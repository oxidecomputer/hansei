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
//! Each find is inspected by its programs (`inspect_future`, as a
//! held value) for its concrete identity, suspend state, continuation
//! and the resource it is parked on — and its own frames are scanned
//! in turn, so a set inside a held future inside a set is reached.
//! What DWARF cannot say is whether an arbitrary struct implements
//! `Future`, so a hand-written combinator is not itself listed — but
//! the scan descends through it by value, and any coroutine inside it
//! is. A held value's inspection says what *it* is parked on; it never
//! says its owner polls it.
//!
//! A task mid-poll is the exception to the walk: its frames are being
//! rewritten, so only the sets they hold are read from them, and
//! nothing else.
//!
//! What a frame's scan looks at is its own storage: a coroutine's
//! locals as its layout lists them for the active state, a plain
//! future's members. What it leaves alone is the chain itself — a
//! find whose identity is a frame of the chain being scanned is that
//! frame, counted there, not a future held beside it — decided by
//! exact identity, never by a member's name.
//!
//! Discovery never follows ordinary pointers: a future reachable only
//! behind an unrecognized `Box`/`Arc` is not found (the dyn wide
//! pointer and a set's node list are the deliberate exceptions).

use super::TaskState;
use super::assess::{AssessmentPass, ContinuationStatus};
use super::bundle::{AwaitChain, Context, TaskList, WaitKind};
use super::chain::{FutureInspection, InspectionMode, NextFuture};
use super::observe::ResourceObservation;
// The by-value types sets and join sets are recognized as; the trailing
// `<` keeps each match on the real generic, not a lookalike suffix. A
// `JoinSet` holds *tasks* rather than futures, so it is walked and
// reported apart from a set of futures; anything built on one
// (omicron's `ParallelTaskSet`, which pairs it with a semaphore) is
// reached by the same scan, since it holds its `JoinSet` by value.
use super::observe::{
    HttpRequestObservation, PoolInfos, PoolPeers, ReadContext, Refusal, ValueKey,
};

use anyhow::{Context as _, Result, anyhow, ensure};
use foldhash::{HashMap, HashSet};
use hansei_bundle::{BundleTypeId, TypeClass, WalkRole};
use proc::Target;
use reify::Value;
use std::fmt;
use std::rc::Rc;

/// Hard bound on one set's child walk. Real sets run to thousands of
/// children (a `buffer_unordered` over a large stream), so the bound is
/// generous; it exists so corrupt memory ends in a report, not a spin,
/// and a walk that hits it keeps the children found up to there.
const MAX_CHILDREN: usize = 65_536;

/// How deep the locals scan descends through nested aggregates. The
/// scan follows no pointers, so the bound is on a type's own nesting,
/// and the deepest a reviewed layout goes is hyper's HTTP/1 connection:
/// fifteen aggregates from a server task's frame, through hyper-util's
/// version-choosing state and the h1 dispatcher's connection, to the
/// socket's io registration.
pub(crate) const MAX_SCAN_DEPTH: usize = 20;

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
    /// Locals the walk did not scan because the coroutine layout
    /// cannot say they are initialized in the frame's state: an async
    /// block's captures once it has been polled, whose slots the body
    /// may have moved out of. Their bytes are there; whether they still
    /// hold a live value is not known, so nothing is read from them.
    /// Not a limit — no bound would have let the walk read them — but
    /// a place the listing may be short.
    pub uncertain: usize,
    /// How many finds the allocator's account of the heap refused; see
    /// [`Walker::taken_back`].
    ///
    /// A refusal drops the find *and* everything the walk would have
    /// reached through it, so the number is places the listing is
    /// short rather than rows removed from it — which is why it is
    /// counted at all: a dropped find otherwise leaves a listing that
    /// covered less looking exactly like a complete one.
    pub refused: usize,
    /// Which of the scan's paths produced the finds; see [`Stats`].
    pub stats: Stats,
    /// The far end of every pooled HTTP client connection a frame the
    /// walk scanned holds a pool of: a pool's idle reaper, or a
    /// connection checked out of one.
    pub pool_peers: PoolPeers,
    /// What those pools keep of how each connection was made, by the
    /// same pointer.
    pub pool_infos: PoolInfos,
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
    /// Values not scanned because the bundle says their storage cannot
    /// be read: a compiler's coroutine environment no reviewed
    /// convention covers. Its bytes are there; which of them hold live
    /// values is not known, and an ordinary enum scan of them would
    /// take dead storage for futures.
    pub unavailable: usize,
}

impl Capped {
    /// Whether anything was capped at all.
    pub fn any(&self) -> bool {
        self.total() > 0
    }

    /// Every place a limit stopped the walk, of any kind.
    pub fn total(&self) -> usize {
        self.deep + self.distant + self.unavailable
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
    /// Finds dropped because they are a frame of the chain they were
    /// scanned out of — the awaitee in its slot, a referent behind an
    /// adapter — and are counted as that frame.
    pub chain_hits: usize,
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
    /// The await-chain frame the set was found in — numbered the way
    /// the listings display frames, #0 the most recently polled — and
    /// the local (the frame member the scan entered through) that
    /// holds it.
    pub frame: usize,
    pub local: String,
    /// How the census reached the frame when it is not one of the
    /// owning task's own; see [`HeldFuture::via`].
    pub via: Option<Via>,
    /// The set's address and full type name.
    pub addr: u64,
    pub ty: BundleTypeId,
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
    /// The await-chain frame the set was found in — numbered the way
    /// the listings display frames, #0 the most recently polled — and
    /// the local (the frame member the scan entered through) that
    /// holds it.
    pub frame: usize,
    pub local: String,
    /// How the census reached the frame when it is not one of the
    /// owning task's own; see [`HeldFuture::via`].
    pub via: Option<Via>,
    /// The set's address and full type name.
    pub addr: u64,
    pub ty: BundleTypeId,
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
    pub future: Option<BundleTypeId>,
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
    /// The raw observation read from the chain's primitive, whatever
    /// the summary made of it: what a listing of one kind of resource
    /// reads its columns from.
    pub observation: Option<ResourceObservation>,
    /// The request a frame of the child's chain keeps, where one does:
    /// what names the request behind the connection a child awaits.
    pub request: Option<HttpRequestObservation>,
    /// How the child's chain ended: at a primitive (which `waiting_on`
    /// then describes), in a terminal state, or without its
    /// continuation established.
    pub continuation: ContinuationStatus,
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
    /// The await-chain frame it was found in — numbered the way the
    /// listings display frames, #0 the most recently polled — and the
    /// local (the frame member the scan entered through) that holds it.
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
    /// The frames of that chain, in the order it ran — the find's own
    /// value first, whatever it delegates to after — so what the find
    /// holds through a pointer (a boxed `Sleep` behind an interval's
    /// tick) is known to be its without walking the chain again.
    pub frames: Vec<ValueKey>,
    /// The concrete future type, dyn-resolved when it had to be.
    pub future: BundleTypeId,
    /// Its suspend state, `Suspend1 — file:line` style.
    pub state: Option<String>,
    /// What its chain bottoms out in, when recognized.
    pub waiting_on: Option<String>,
    /// The same wait as a tally counts it; see [`SetChild::wait`].
    pub wait: Option<WaitKind>,
    /// The raw observation read from the chain's primitive, whatever
    /// the summary made of it: what a listing of one kind of resource
    /// reads its columns from.
    pub observation: Option<ResourceObservation>,
    /// The request a frame of its chain keeps; see [`SetChild::request`].
    pub request: Option<HttpRequestObservation>,
    /// How its chain ended; see [`SetChild::continuation`].
    pub continuation: ContinuationStatus,
}

impl FutureCensus {
    /// A census over finds laid out by hand — what a listing test
    /// builds when no fixture holds the shape it wants. Nothing was
    /// walked, so nothing is spanned: [`Self::locate`] answers no
    /// address, and the walk's own accounts are all zero.
    pub fn from_finds(
        held: Vec<HeldFuture>,
        sets: Vec<FutureSet>,
        join_sets: Vec<JoinSet>,
    ) -> Self {
        FutureCensus {
            sets,
            join_sets,
            held,
            spans: Vec::new(),
            errors: Vec::new(),
            capped: Capped::default(),
            uncertain: 0,
            refused: 0,
            stats: Stats::default(),
            pool_peers: PoolPeers::default(),
            pool_infos: PoolInfos::default(),
        }
    }

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
            if !seen.insert((set.addr, set.ty)) {
                v.push(format!("the set at {:#x} is recorded twice", set.addr));
            }
        }
        let mut seen = HashSet::default();
        for set in &self.join_sets {
            if !seen.insert((set.addr, set.ty)) {
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
        self.errors
            .iter()
            .any(|e| names_address(&format!("{e:#}"), addr))
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
    v: &mut Vec<String>,
) {
    if depth == 0 && (state || waiting_on || wait) {
        v.push(format!("{what} stands on no frames but carries a summary"));
    }
    if wait != waiting_on {
        v.push(format!(
            "{what} counts a wait it does not name, or names one it does not count"
        ));
    }
}

/// The values one frame offers a scan of its storage, each under the
/// name a listing prints for it, and what the frame withheld.
pub(crate) struct FrameLocals<'b> {
    pub(crate) locals: Vec<(&'b str, Value<'b>)>,
    /// The frame's storage is declared unreadable: it offered nothing.
    pub(crate) unavailable: bool,
    /// Locals the layout could not vouch for, withheld and counted.
    pub(crate) uncertain: usize,
}

/// The values one frame offers the scan, each under the name a listing
/// prints for it.
///
/// A coroutine frame offers the locals its layout lists as initialized
/// in the active state — by name, addressed on the state's payload —
/// and withholds the ones the layout cannot vouch for, counted rather
/// than guessed at. A frame that keeps no state, or whose state no
/// layout describes (a hand-written enum), offers every sized member:
/// a generic tuple field is real storage, whatever its name. A frame
/// whose storage the tokio info declares unreadable offers nothing and
/// is counted.
pub(crate) fn frame_locals<'b, T: Target>(
    ctx: &Context<'b, T>,
    frame: &super::bundle::AwaitFrame<'b>,
) -> FrameLocals<'b> {
    let mut out = FrameLocals {
        locals: Vec::new(),
        unavailable: false,
        uncertain: 0,
    };
    if ctx.storage_unavailable(frame.future.ty.id()) {
        out.unavailable = true;
        return out;
    }
    let payload = match &frame.state {
        Some(state) => state.payload,
        None => frame.future,
    };
    let slice = |m: &hansei_bundle::BundleMember<'b>| -> Option<(&'b str, Value<'b>)> {
        let start = m.offset() as usize;
        let end = start + m.ty().size() as usize;
        let bytes = payload.bytes.get(start..end)?;
        Some((
            m.name(),
            Value::new(m.ty(), payload.addr + m.offset(), bytes),
        ))
    };
    let layout = frame
        .state
        .as_ref()
        .and_then(|_| ctx.type_semantics(frame.future.ty.id()))
        .and_then(|record| record.coroutine.as_ref());
    let Some(layout) = layout else {
        // The same positional slicing as the locals display: a
        // hand-written state may alias two names to one slot.
        let mut seen = HashSet::default();
        out.locals = payload
            .ty
            .members()
            .filter(|m| m.ty().size() > 0 && seen.insert((m.name(), m.offset())))
            .filter_map(|m| slice(&m))
            .collect();
        return out;
    };
    // The layout's states are keyed by variant, the frame's state by
    // its display name: decode the key again.
    let Some(Ok(active)) = frame.future.ty.active_variant(frame.future.bytes) else {
        return out;
    };
    let Some(state) = layout
        .states
        .iter()
        .find(|s| ctx.view.str(s.variant) == Some(active.name))
    else {
        return out;
    };
    out.uncertain = state.uncertain_locals.len();
    out.locals = state
        .locals
        .iter()
        .filter_map(|&name| ctx.view.str(name))
        .filter_map(|name| payload.ty.members().find(|m| m.name() == name))
        .filter(|m| m.ty().size() > 0)
        .filter_map(|m| slice(&m))
        .collect();
    out
}

/// What one scan hit is; [`Walker::record`] decides what to do with it.
pub(crate) enum Find<'b> {
    Set(Value<'b>),
    JoinSet(Value<'b>),
    /// A container whose entries are polled with the task's own
    /// context: each entry is scanned as a find of the task.
    Fanout(Value<'b>),
    Future(Value<'b>),
    /// An owned adapter whose referent, by its recorded route, is the
    /// find.
    Adapter(Value<'b>),
    /// A hash table whose buckets could hold a find: each full bucket
    /// is scanned as storage of the value keeping the table.
    Table(Value<'b>),
}

/// Which finds a scan of a chain's frames records.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Scope {
    /// Every find: a parked chain's frames hold what they say.
    All,
    /// Sets alone: a running task's frames ([`Walker::scan_running`]).
    Sets,
}

/// The census walker: the context and task listing it scans over, and
/// its running state.
struct Walker<'a, 'b, T> {
    ctx: &'a Context<'b, T>,
    list: &'a TaskList,
    /// What the walk's reads are held to: the allocator's own account
    /// of what is still handed out, where the target has one to read,
    /// and nothing everywhere else, which is every target whose malloc
    /// is not libumem.
    read: ReadContext<'a>,
    /// The semaphore queues and io registrations the finds' resource
    /// descriptions read, each once for the whole walk.
    pass: AssessmentPass,
    sets: Vec<FutureSet>,
    join_sets: Vec<JoinSet>,
    held: Vec<HeldFuture>,
    spans: Vec<(u64, u64, usize, usize)>,
    errors: Vec<anyhow::Error>,
    capped: Capped,
    uncertain: usize,
    refused: usize,
    stats: Stats,
    pool_peers: PoolPeers,
    pool_infos: PoolInfos,
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

/// Walk every enumerated task's await chain and take the census, with
/// no allocator to corroborate what it finds.
///
/// A task whose stage or chain does not decode contributes nothing —
/// those failures already surface wherever the task itself is asked
/// about — while a *found* set or future whose walk fails is reported.
pub fn census<T: Target>(ctx: &Context<'_, T>, list: &TaskList) -> FutureCensus {
    census_bounded(ctx, list, Bounds::default(), &ReadContext::none())
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

/// [`census`], with the bounds and the read context as arguments.
///
/// `read` carries what the target's own malloc says is still handed
/// out, where there is one to ask. The walk consults it wherever it is
/// about to believe a pointer — the referent a boxed find lies at, a
/// set's next node — and refuses what the allocator has taken back,
/// because those bytes belong to whoever holds the block now and
/// decode into a future that is not there. An empty context is the
/// ordinary case, and the walk is then exactly the walk it was.
pub fn census_bounded<T: Target>(
    ctx: &Context<'_, T>,
    list: &TaskList,
    bounds: Bounds,
    read: &ReadContext<'_>,
) -> FutureCensus {
    let mut walker = Walker {
        ctx,
        list,
        read: *read,
        pass: AssessmentPass::new(),
        sets: Vec::new(),
        join_sets: Vec::new(),
        held: Vec::new(),
        spans: Vec::new(),
        errors: Vec::new(),
        capped: Capped::default(),
        uncertain: 0,
        refused: 0,
        stats: Stats::default(),
        pool_peers: PoolPeers::default(),
        pool_infos: PoolInfos::default(),
        bounds,
        visited: HashSet::default(),
        plans: HashMap::default(),
    };

    for (owner, task) in list.tasks.iter().enumerate() {
        let Ok(Some(inspection)) = ctx.inspect_task(task, read) else {
            continue;
        };
        // A task mid-poll is mutating its frames: its saved state is
        // not read as a chain, and its locals are not scanned for
        // finds that may be half-written — except for the sets they
        // hold ([`Walker::scan_running`]).
        if matches!(inspection.chain.end, super::bundle::ChainEnd::ActivePoll) {
            if let Some(root) = inspection.chain.frames.first() {
                let saved = ctx.inspect_future(root.future, InspectionMode::Held, read);
                walker.scan_running(owner, &saved.chain);
            }
            continue;
        }
        walker.scan_chain(owner, None, &inspection.chain, 0);
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
        uncertain: walker.uncertain,
        refused: walker.refused,
        stats: walker.stats,
        pool_peers: walker.pool_peers,
        pool_infos: walker.pool_infos,
    }
}

/// Whether `report` writes `addr` as an address of its own: `0x10` is
/// not named by a report about `0x100`, nor by one about `0x0x10`'s
/// tail — the digits must stand alone.
pub(crate) fn names_address(report: &str, addr: u64) -> bool {
    let written = format!("{addr:#x}");
    report.match_indices(&written).any(|(at, _)| {
        let before = report[..at].chars().next_back();
        let after = report[at + written.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric())
            && !after.is_some_and(|c| c.is_ascii_hexdigit())
    })
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
    /// Whether the allocator has taken back the memory at `addr`, and
    /// so whether anything decoded from it is a reading of somebody
    /// else's bytes.
    ///
    /// Only `Freed` refuses. `Live` is the ordinary answer and
    /// `Unknown` claims nothing at all — a future on a stack, a target
    /// whose malloc is not libumem, a block in a layer this walk does
    /// not cover — and a silence must never be read as a verdict. Nor
    /// is `Live` a clean bill of health: a block freed and handed
    /// straight back out to somebody else is live, and the stale
    /// pointer at it is as wrong as the refused one. This corroborates
    /// where it can and is quiet where it cannot.
    fn taken_back(&self, addr: u64) -> bool {
        self.read.taken_back(addr)
    }

    /// Scan every frame of `chain` for sets and held futures, recursing
    /// through what it finds. `via` says how the census reached this
    /// chain when it is not a task's own.
    ///
    /// What a frame offers the scan is its own storage
    /// ([`frame_locals`]); what the scan leaves alone is the
    /// chain: a find whose identity is a frame of this chain is that
    /// frame, counted there, told apart by exact identity.
    fn scan_chain(
        &mut self,
        owner: usize,
        via: Option<Via>,
        chain: &AwaitChain<'b>,
        nesting: usize,
    ) {
        self.scan_frames(owner, via, chain, nesting, Scope::All);
    }

    /// Scan a running task's saved state — `chain`, its root read as
    /// though the task were parked — for the sets its frames hold, and
    /// nothing else.
    ///
    /// A set is what its children's wakers name the task by: a child
    /// wakes the set's ready-to-run queue, and the queue wakes whoever
    /// polls the set. That task is running exactly when a child has
    /// just woken it, so a census blind to running tasks loses the
    /// wakers of the busiest sets. The frames a set sits in are ones
    /// the poll re-enters rather than rewrites, and futures-util takes
    /// the child it is polling off the set's list for the length of
    /// that poll, so the nodes the walk reaches are parked ones. What
    /// else the frames hold — a future the poll may be moving, a pool
    /// or table it may be filling — stays unread. A local the frames
    /// withhold is not counted among those the census could not read:
    /// that count warns of the held futures it hides, and a running
    /// task's are not listed in any case.
    fn scan_running(&mut self, owner: usize, chain: &AwaitChain<'b>) {
        self.scan_frames(owner, None, chain, 0, Scope::Sets);
    }

    /// [`Self::scan_chain`], recording the finds `scope` admits.
    fn scan_frames(
        &mut self,
        owner: usize,
        via: Option<Via>,
        chain: &AwaitChain<'b>,
        nesting: usize,
        scope: Scope,
    ) {
        let on_chain: HashSet<ValueKey> = chain.referents().collect();
        for (frame_index, frame) in chain.frames.iter().enumerate() {
            // Recorded display-numbered — #0 the most recently polled
            // frame — the way every listing prints it.
            let display = chain.frames.len() - 1 - frame_index;
            // A frame that is itself a fan-out container — a chain
            // ending at a `StreamMap` the task polls directly — holds
            // its entries the way a local holds a future: they are the
            // task's finds, entered through the member the map keeps
            // them in. Its members are not scanned besides, since that
            // member is the buffer's header and nothing else.
            if self.ctx.recognize(frame.future.ty.id()) == Recognized::Fanout {
                if scope == Scope::Sets {
                    continue;
                }
                let storage = self.ctx.fanout_storage_name().to_string();
                self.record(
                    owner,
                    display,
                    &storage,
                    via,
                    Find::Fanout(frame.future),
                    nesting,
                    &on_chain,
                );
                continue;
            }
            let locals = frame_locals(self.ctx, frame);
            if scope == Scope::All {
                if locals.unavailable {
                    self.capped.unavailable += 1;
                }
                self.uncertain += locals.uncertain;
            }
            for (name, local) in locals.locals {
                // A pool the frame holds names the pooled connections'
                // far ends: a fact beside the finds, read once per value.
                if scope == Scope::All
                    && let Some(pool) = self
                        .ctx
                        .type_semantics(local.ty.id())
                        .and_then(|record| record.pool.as_ref())
                    && self.visited.insert((local.addr, local.ty.id()))
                    && let Err(e) = super::pool::read_pool(
                        self.ctx,
                        &self.read,
                        local,
                        pool,
                        &mut self.pool_peers,
                        &mut self.pool_infos,
                    )
                {
                    self.errors.push(e);
                }
                let mut found = Vec::new();
                scan_value(
                    local,
                    self.ctx,
                    0,
                    self.bounds.scan_depth,
                    Path::default(),
                    &mut found,
                    &mut self.capped,
                    &mut self.plans,
                    &mut self.stats,
                );
                for find in found {
                    if scope == Scope::Sets && !matches!(find, Find::Set(_)) {
                        continue;
                    }
                    self.record(owner, display, name, via, find, nesting, &on_chain);
                }
            }
        }
    }

    /// Record one find and recurse into it. `on_chain` is the identity
    /// of every frame of the chain the find was scanned out of.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        owner: usize,
        frame: usize,
        local: &str,
        via: Option<Via>,
        find: Find<'b>,
        nesting: usize,
        on_chain: &HashSet<ValueKey>,
    ) {
        let value = match &find {
            Find::Set(value)
            | Find::JoinSet(value)
            | Find::Fanout(value)
            | Find::Future(value)
            | Find::Adapter(value)
            | Find::Table(value) => value,
        };
        // Asked before the find is recorded rather than after the
        // listing is built, because the walk goes on *through* what it
        // records: a stale pointer produces the row and then every
        // find under it, and a filter over the finished listing would
        // drop the parent and keep the subtree. Refusing here stops
        // both. Counted per place rather than per address, since two
        // frames pointing at one dead block are two rows missing.
        if self.taken_back(value.addr) {
            self.refused += 1;
            return;
        }
        if !self.visited.insert((value.addr, value.ty.id())) {
            self.stats.dedup_hits += 1;
            return;
        }
        match find {
            Find::Set(value) => self.record_set(owner, frame, local, via, value, nesting),
            Find::JoinSet(value) => self.record_join_set(owner, frame, local, via, value),
            Find::Fanout(value) => {
                self.record_fanout(owner, frame, local, via, value, nesting, on_chain)
            }
            Find::Table(value) => {
                self.record_table(owner, frame, local, via, value, nesting, on_chain)
            }
            // The adapter's referent is the find — under the adapter's
            // slot, so a `Box<F>` local lists `F` where the local is.
            // A route that lands nowhere lists nothing: the adapter is
            // not a future, and what it holds is not established.
            Find::Adapter(value) => match self.ctx.access_referent(value, &self.read) {
                Some(NextFuture::Next { future, .. }) => {
                    self.record(
                        owner,
                        frame,
                        local,
                        via,
                        Find::Future(future),
                        nesting,
                        on_chain,
                    );
                }
                // The referent is what the allocator weighs: a route
                // it refuses is a stale pointer, and the find behind
                // it is not there.
                Some(NextFuture::End(super::bundle::ChainEnd::Error(e))) if refused(&e) => {
                    self.refused += 1;
                }
                _ => {}
            },
            Find::Future(value) => {
                // A frame of the chain itself, found in the slot the
                // chain reached it through: counted as that frame, not
                // as a future held beside it.
                if on_chain.contains(&ValueKey::of(value)) {
                    self.stats.chain_hits += 1;
                    return;
                }
                let place = (value.addr, value.ty.id());
                let held = self
                    .ctx
                    .inspect_future(value, InspectionMode::Held, &self.read);
                // An alias of a chain frame reached through a pointer
                // route — the held chain lands on a frame of the
                // owner's — is on the chain, whatever route led there.
                if held.chain.referents().any(|key| on_chain.contains(&key)) {
                    self.stats.chain_hits += 1;
                    return;
                }
                // The future itself, past the adapters it was held
                // through (behind a box, that is the heap allocation
                // rather than the local's pointer slot). A find that is
                // only its adapter — the route to the future it holds
                // refused by the allocator before any future was
                // reached — is a stale slot: the referent is what the
                // allocator weighs, and the find is not there.
                let (identity, frame_of) = self.identity_frame(&held.chain);
                let adapter = self
                    .ctx
                    .type_semantics(frame_of.future.ty.id())
                    .is_some_and(|record| record.access.is_some());
                if adapter
                    && let super::bundle::ChainEnd::Error(e) = &held.chain.end
                    && refused(e)
                {
                    self.refused += 1;
                    return;
                }
                let (addr, ty) = (frame_of.future.addr, frame_of.future.ty.id());
                // What was recorded is that future, so that is what a
                // later reference to it has to be deduped against —
                // the slot key above is the pointer's, and two
                // pointers to one future have two of those. A find
                // held by value keys the same place twice, which is
                // why only a differing root is looked up.
                if (addr, ty) != place {
                    // The frame held a pointer and the chain followed
                    // it, so this address is the frame's claim rather
                    // than a place the scan was already standing in —
                    // which makes it the one thing here the allocator
                    // can contradict.
                    if self.taken_back(addr) {
                        self.refused += 1;
                        return;
                    }
                    if !self.visited.insert((addr, ty)) {
                        self.stats.dedup_hits += 1;
                        return;
                    }
                }
                let summary = self.summarize(&held, identity);
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
                    frames: held
                        .chain
                        .frames
                        .iter()
                        .map(|f| ValueKey::of(f.future))
                        .collect(),
                    future: summary.future,
                    state: summary.state,
                    waiting_on: summary.waiting_on,
                    wait: summary.wait,
                    observation: summary.observation,
                    request: summary.request,
                    continuation: summary.continuation,
                });
                if nesting < self.bounds.nesting {
                    self.scan_chain(owner, Some(Via::Held(index)), &held.chain, nesting + 1);
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
            ty: value.ty.id(),
            children: Vec::new(),
        };
        // A walk that fails part-way (an unmapped node, the bound)
        // keeps what it found: the children up to the failure are real,
        // and the error says the list is incomplete.
        let mut slots = Vec::new();
        if let Err(e) = self.walk_set(value, &mut slots) {
            self.errors.push(e.context(format!(
                "the FuturesUnordered at {:#x} lists only {} of its children",
                value.addr,
                slots.len()
            )));
        }
        let mut scan = Vec::new();
        for (child_index, (cur, fut, extent)) in slots.into_iter().enumerate() {
            self.spans.push((extent.0, extent.1, index, child_index));
            let (child, chain) = self.set_child(cur, fut);
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

    /// Record one fan-out container: walk its entries, and scan each
    /// as a value the task holds at `local[index]`, so what the entry
    /// is — an owned stream over a box, a future outright — is found
    /// the way it would be in a frame's local. The container itself
    /// is no row: it holds the task's own registrations, not a set's.
    #[allow(clippy::too_many_arguments)]
    fn record_fanout(
        &mut self,
        owner: usize,
        frame: usize,
        local: &str,
        via: Option<Via>,
        value: Value<'b>,
        nesting: usize,
        on_chain: &HashSet<ValueKey>,
    ) {
        let mut entries = Vec::new();
        let visit = &mut |index: usize,
                          _entry: Value<'b>,
                          stream: Value<'b>|
         -> std::result::Result<(), NodeStop> {
            entries.push((index, stream));
            Ok(())
        };
        if let Err(e) = walk_fanout_entries(self.ctx, &self.read, value, MAX_CHILDREN, visit) {
            self.errors.push(anyhow::Error::from(e).context(format!(
                "the StreamMap at {:#x} lists only {} of its entries",
                value.addr,
                entries.len()
            )));
        }
        for (index, stream) in entries {
            let mut found = Vec::new();
            scan_value(
                stream,
                self.ctx,
                0,
                self.bounds.scan_depth,
                Path::default(),
                &mut found,
                &mut self.capped,
                &mut self.plans,
                &mut self.stats,
            );
            let local = format!("{local}[{index}]");
            for find in found {
                self.record(owner, frame, &local, via, find, nesting, on_chain);
            }
        }
    }

    /// Record one hash table: walk its full buckets, and scan each as a
    /// value the task holds at `local[index]`, as a fan-out container's
    /// entries are. The table itself is no row: its buckets are the
    /// storage of the value keeping it, and what one holds is held by
    /// the frame that value is in.
    #[allow(clippy::too_many_arguments)]
    fn record_table(
        &mut self,
        owner: usize,
        frame: usize,
        local: &str,
        via: Option<Via>,
        value: Value<'b>,
        nesting: usize,
        on_chain: &HashSet<ValueKey>,
    ) {
        let Some(table) = self.ctx.scanned_table(value.ty.id()) else {
            return;
        };
        let mut buckets = Vec::new();
        let visit = &mut |index: usize, bucket: Value<'b>| -> std::result::Result<(), NodeStop> {
            buckets.push((index, bucket));
            Ok(())
        };
        match walk_table_buckets(self.ctx, &self.read, value, table, MAX_CHILDREN, visit) {
            Ok(count) if count.full as u64 != count.items => self.errors.push(anyhow!(
                "the hash table at {:#x} counts {} items, and {} of its buckets are full",
                value.addr,
                count.items,
                count.full
            )),
            Ok(_) => {}
            Err(e) => self.errors.push(anyhow::Error::from(e).context(format!(
                "the hash table at {:#x} lists only {} of its entries",
                value.addr,
                buckets.len()
            ))),
        }
        for (index, bucket) in buckets {
            let mut found = Vec::new();
            scan_value(
                bucket,
                self.ctx,
                0,
                self.bounds.scan_depth,
                Path::default(),
                &mut found,
                &mut self.capped,
                &mut self.plans,
                &mut self.stats,
            );
            let local = format!("{local}[{index}]");
            for find in found {
                self.record(owner, frame, &local, via, find, nesting, on_chain);
            }
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
            ty: value.ty.id(),
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
/// What the bundle's facts make of a type the scan meets: one of the
/// two containers it walks by their own contracts, a future it chains
/// rather than descends, or neither. The scan asks about types, never
/// about names or shapes; what it is told comes from the semantic table.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Recognized {
    Set,
    JoinSet,
    /// A container that polls every entry with the polling task's own
    /// context — a `StreamMap` — so its entries are futures the task
    /// holds, listed as its finds rather than as a set's children.
    Fanout,
    Future,
    /// A supported owned pointer adapter that is not itself a future —
    /// a `Box<F>` over a future that is not `Unpin`, the `Box<dyn
    /// Future>` inside a pinned one — whose access binding records the
    /// route to what it holds.
    Adapter,
    /// A hash table the bundle binds, whose bucket type could hold a
    /// find: its buckets are the value's storage, read by the binding.
    Table,
    /// Storage the bundle declares unreadable, with no identity that
    /// would make the value a find: stopped at, never descended into.
    Unavailable,
    Other,
}

/// The source of those facts — the attached [`Context`] in production,
/// a hand-built table in the tests below.
pub(crate) trait Recognize {
    fn recognize(&self, id: BundleTypeId) -> Recognized;
}

impl<T: Target> Recognize for Context<'_, T> {
    fn recognize(&self, id: BundleTypeId) -> Recognized {
        match self.container_kind(id) {
            Some(hansei_bundle::ContainerKind::FuturesUnordered) => Recognized::Set,
            Some(hansei_bundle::ContainerKind::JoinSet) => Recognized::JoinSet,
            Some(hansei_bundle::ContainerKind::StreamMap) => Recognized::Fanout,
            None if self.recognized_future(id) => Recognized::Future,
            None if self.owned_adapter(id) => Recognized::Adapter,
            None if self.scanned_table(id).is_some() => Recognized::Table,
            None if self.storage_unavailable(id) => Recognized::Unavailable,
            None => Recognized::Other,
        }
    }
}

#[derive(Clone)]
pub(crate) enum ScanPlan {
    Set,
    JoinSet,
    /// A container polling its entries with the task's own context:
    /// walked by its contract, each entry a find of the task.
    Fanout,
    /// A future outright: a coroutine env, a known leaf, or a wide
    /// pointer to a future trait object — chained rather than descended
    /// into, so its insides are attributed to it rather than to the
    /// frame holding it.
    Future,
    /// An owned pointer adapter: followed by its recorded route to the
    /// future it holds, which is then the find.
    Adapter,
    /// A hash table: walked by its binding, each full bucket scanned as
    /// storage of the value.
    Table,
    /// Storage the bundle declares unreadable: counted as a place the
    /// scan stopped short, never scanned as the enum it is shaped as.
    Unavailable,
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
/// in order. What the bundle recognizes — a container, a future, an
/// adapter — is the semantic table's answer; everything else is
/// decided by the type's shape, and a plan is a fact of the type
/// alone.
fn scan_plan(value: Value<'_>, facts: &dyn Recognize) -> ScanPlan {
    match facts.recognize(value.ty.id()) {
        Recognized::Set => return ScanPlan::Set,
        Recognized::JoinSet => return ScanPlan::JoinSet,
        Recognized::Fanout => return ScanPlan::Fanout,
        Recognized::Future => return ScanPlan::Future,
        Recognized::Adapter => return ScanPlan::Adapter,
        Recognized::Table => return ScanPlan::Table,
        Recognized::Unavailable => return ScanPlan::Unavailable,
        Recognized::Other => {}
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

/// The steps between the scanned local and the value in hand: whether
/// a struct descent or an active-variant step lies on the way, which
/// is what the per-path find counters in [`Stats`] record.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Path {
    descended: bool,
    variant: bool,
}

/// Find every by-value future inside `value`: the value itself, or one
/// nested in its structs and active enum variants. Ordinary pointers
/// are never followed, so the scan stays inside the frame's own bytes
/// and terminates.
#[expect(clippy::too_many_arguments, reason = "internal recursion")]
pub(crate) fn scan_value<'b>(
    value: Value<'b>,
    facts: &dyn Recognize,
    depth: usize,
    max_depth: usize,
    path: Path,
    found: &mut Vec<Find<'b>>,
    capped: &mut Capped,
    plans: &mut HashMap<BundleTypeId, ScanPlan>,
    stats: &mut Stats,
) {
    if depth > max_depth {
        capped.deep += 1;
        return;
    }
    let plan = match plans.get(&value.ty.id()) {
        Some(plan) => plan.clone(),
        None => {
            let plan = scan_plan(value, facts);
            plans.insert(value.ty.id(), plan.clone());
            plan
        }
    };
    if matches!(
        plan,
        ScanPlan::Set
            | ScanPlan::JoinSet
            | ScanPlan::Fanout
            | ScanPlan::Future
            | ScanPlan::Adapter
            | ScanPlan::Table
    ) {
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
        ScanPlan::Fanout => found.push(Find::Fanout(value)),
        ScanPlan::Future => found.push(Find::Future(value)),
        ScanPlan::Adapter => found.push(Find::Adapter(value)),
        ScanPlan::Table => found.push(Find::Table(value)),
        ScanPlan::Unavailable => capped.unavailable += 1,
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
                    facts,
                    depth + 1,
                    max_depth,
                    path,
                    found,
                    capped,
                    plans,
                    stats,
                );
            }
        }
        ScanPlan::Enum => {
            // The *raw* payload, not the peeled one: peel descends
            // single-sized-member wrappers, and `Some(JoinSet<_>)`
            // peels straight through the JoinSet into its interior —
            // the scan then never sees the name it screens on, and
            // the find silently vanishes. The raw variant struct
            // descends to its members like any other aggregate.
            if let Ok((_, payload)) = value.active_variant_raw() {
                let path = Path {
                    variant: true,
                    ..path
                };
                // The variant struct is the enum's own storage, not
                // another aggregate layer: descending into its members
                // is what costs a level, the way it always did when
                // the payload arrived pre-peeled.
                scan_value(
                    payload, facts, depth, max_depth, path, found, capped, plans, stats,
                );
            }
        }
        ScanPlan::Stop => {}
    }
}

/// Whether an error is the allocator's refusal, wherever in its chain
/// of causes the refusal sits.
fn refused(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<Refusal>().is_some())
}

/// One find's listing row, reduced from its inspection.
struct Summary {
    /// How many frames the chain ran to, which is what lets a count of
    /// futures be told apart from a count of the frames they stand on.
    depth: usize,
    future: BundleTypeId,
    state: Option<String>,
    waiting_on: Option<String>,
    wait: Option<WaitKind>,
    observation: Option<ResourceObservation>,
    request: Option<HttpRequestObservation>,
    continuation: ContinuationStatus,
}

impl<'b, T: Target> Walker<'_, 'b, T> {
    /// The frame a find is listed as: the first of its chain whose type
    /// is not a supported adapter — past the `Pin`, the `Box`, the
    /// reference the value was held through — or the root itself where
    /// every frame is one (a trait object the join could not resolve
    /// is listed as its wide pointer).
    fn identity_frame<'c>(
        &self,
        chain: &'c AwaitChain<'b>,
    ) -> (usize, &'c super::bundle::AwaitFrame<'b>) {
        chain
            .frames
            .iter()
            .enumerate()
            .find(|(_, f)| {
                self.ctx
                    .type_semantics(f.future.ty.id())
                    .is_none_or(|record| record.access.is_none())
            })
            .unwrap_or((0, &chain.frames[0]))
    }

    /// Reduce a future's inspection to one listing row: the identity
    /// frame's type and state, the resource its chain ends in described
    /// under no protocol, and how the chain ended.
    fn summarize(&mut self, inspection: &FutureInspection<'b>, identity: usize) -> Summary {
        let chain = &inspection.chain;
        let frame = &chain.frames[identity];
        let state = frame.state.as_ref().map(|state| {
            let loc = state
                .await_loc
                .map(|(file, line)| format!(" — {file}:{line}"))
                .unwrap_or_default();
            format!("{}{loc}", state.name)
        });
        let target = inspection.primitive.value.as_ref().and_then(|observation| {
            self.ctx
                .observed_target(&mut self.pass, observation, chain, self.list, &self.read)
        });
        Summary {
            depth: chain.frames.len(),
            future: frame.future.ty.id(),
            state,
            waiting_on: target.as_ref().map(|t| t.to_string()),
            wait: target.as_ref().map(|t| t.kind()),
            observation: inspection.primitive.value.clone(),
            request: self.ctx.chain_request(chain, &self.read),
            continuation: ContinuationStatus::of(&chain.end),
        }
    }

    /// One set child as the listing carries it, and its chain for the
    /// scan when the slot holds a future.
    fn set_child(
        &mut self,
        node: u64,
        fut: Option<Value<'b>>,
    ) -> (SetChild, Option<AwaitChain<'b>>) {
        let Some(fut) = fut else {
            return (
                SetChild {
                    node,
                    // A reaped slot holds no future, so it stands on
                    // no frames either.
                    depth: 0,
                    future: None,
                    root: None,
                    state: None,
                    waiting_on: None,
                    wait: None,
                    observation: None,
                    request: None,
                    continuation: ContinuationStatus::Incomplete {
                        reason: super::assess::IncompleteReason::NoRoot,
                        detail: None,
                    },
                },
                None,
            );
        };
        let inspection = self
            .ctx
            .inspect_future(fut, InspectionMode::Held, &self.read);
        // As for a held future: the future itself past its adapters
        // (behind a box, the heap future rather than the slot).
        let (identity, frame) = self.identity_frame(&inspection.chain);
        let root = FutureRoot {
            addr: frame.future.addr,
            ty: frame.future.ty.id(),
        };
        let summary = self.summarize(&inspection, identity);
        (
            SetChild {
                node,
                depth: summary.depth,
                future: Some(summary.future),
                root: Some(root),
                state: summary.state,
                waiting_on: summary.waiting_on,
                wait: summary.wait,
                observation: summary.observation,
                request: summary.request,
                continuation: summary.continuation,
            },
            Some(inspection.chain),
        )
    }
}

/// One walked child slot: the node's address, the resident future
/// (`None` for an empty slot), and the node's extent.
type WalkedSlot<'b> = (u64, Option<Value<'b>>, (u64, u64));

impl<'b, T: Target> Walker<'_, 'b, T> {
    /// Walk one set's intrusive `head_all` → `next_all` node list,
    /// pushing each child slot as it goes, so a caller keeps the prefix
    /// a failing walk found.
    fn walk_set(&self, set: Value<'b>, slots: &mut Vec<WalkedSlot<'b>>) -> Result<()> {
        let ctx = self.ctx;
        let visit = &mut |cur: u64, node: Value<'b>| -> std::result::Result<(), NodeStop> {
            // Task.future: UnsafeCell<Option<Fut>>; `None` is a completed
            // child the set has not reaped.
            let slot = ctx.walk(WalkRole::SetNodeFuture).walk_at(node)?;
            let (variant, payload) = slot
                .active_variant_raw()
                .with_context(|| format!("failed to decode the child slot at {cur:#x}"))?;
            let fut = if variant == "Some" {
                // The `Some` payload's one field is the future itself,
                // read as its own nominal type: its program takes the
                // first step, adapter or coroutine alike. Unpeeled,
                // because a peel takes `Pin<Box<dyn Future>>` to the
                // bare box it wraps, which is no future and has no
                // program to take that step.
                Some(
                    payload
                        .member_raw("__0")
                        .with_context(|| format!("the child slot at {cur:#x} holds no future"))?,
                )
            } else {
                None
            };
            slots.push((cur, fut, (cur, cur + node.ty.size())));
            Ok(())
        };
        walk_set_nodes(ctx, &self.read, set, MAX_CHILDREN, visit).map_err(anyhow::Error::from)
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
        let visit = &mut |addr: u64, entry: Value<'b>| -> std::result::Result<(), NodeStop> {
            let task = join_set_entry_task(ctx, entry)?;
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
            Ok(())
        };
        walk_join_set_entries(ctx, &self.read, set, MAX_CHILDREN, length, visit)
            .map_err(anyhow::Error::from)
    }
}

// ---------------------------------------------------------------------------
// The container node walks
// ---------------------------------------------------------------------------
//
// The two intrusive lists the census and the reference scan both walk,
// node by node: the walk owns the checks every node is held to — the
// pointer mapped, the allocator's word on it, the cycle guard, the
// child cap — and hands each node to its caller, which decides what a
// node is for. The caller keeps whatever prefix a failing walk reached.

/// Why a node walk stopped short of the list's end.
#[derive(Debug)]
pub(crate) enum NodeStop {
    /// A link points off the target's mappings.
    Unmapped { what: &'static str, addr: u64 },
    /// The allocator refuses the node's bytes.
    Refused {
        what: &'static str,
        addr: u64,
        refusal: Refusal,
    },
    /// A link points back at a node already walked.
    Cycle { what: &'static str, addr: u64 },
    /// The list ran past the child cap.
    Capped { unit: &'static str, max: usize },
    /// A read, a recorded walk, or the caller's own visit failed.
    Failed(anyhow::Error),
}

impl fmt::Display for NodeStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unmapped { what, addr } => write!(f, "{what} pointer {addr:#x} is unmapped"),
            Self::Refused {
                what,
                addr,
                refusal: Refusal::Freed { .. },
            } => write!(
                f,
                "{what} pointer {addr:#x} is in memory the allocator has taken back"
            ),
            Self::Refused {
                what,
                addr,
                refusal,
            } => write!(f, "{what} pointer {addr:#x}: {refusal}"),
            Self::Cycle { what, addr } => write!(f, "{what} cycle at {addr:#x}"),
            Self::Capped { unit, max } => write!(f, "the walk stopped at {max} {unit}"),
            Self::Failed(e) => write!(f, "{e:#}"),
        }
    }
}

impl From<NodeStop> for anyhow::Error {
    fn from(stop: NodeStop) -> Self {
        match stop {
            NodeStop::Failed(e) => e,
            other => anyhow!("{other}"),
        }
    }
}

impl From<anyhow::Error> for NodeStop {
    fn from(e: anyhow::Error) -> Self {
        NodeStop::Failed(e)
    }
}

/// The state one intrusive-list walk carries between nodes: what its
/// nodes are called in a diagnostic, the nodes already walked, and how
/// many the caller may take.
struct NodeWalk {
    what: &'static str,
    unit: &'static str,
    max: usize,
    visited: HashSet<u64>,
    count: usize,
}

impl NodeWalk {
    fn new(what: &'static str, unit: &'static str, max: usize) -> Self {
        NodeWalk {
            what,
            unit,
            max,
            visited: HashSet::default(),
            count: 0,
        }
    }

    /// The checks every node is held to before it is read: mapped,
    /// permitted by the allocator, not yet walked, and under the cap.
    fn admit(
        &mut self,
        ctx: &Context<'_, impl Target>,
        read: &ReadContext<'_>,
        addr: u64,
        size: u64,
    ) -> std::result::Result<(), NodeStop> {
        let what = self.what;
        if !ctx.mappings.contains_addr(addr) {
            return Err(NodeStop::Unmapped { what, addr });
        }
        // The same refusal a held find gets, one layer out: the list's
        // own link is what claimed this node, and a node the allocator
        // has taken back is a child that is not there. The walk stops
        // rather than skipping it, because the link to the next node is
        // read out of these very bytes.
        if let Some(refusal) = read.refusal(addr, size) {
            return Err(NodeStop::Refused {
                what,
                addr,
                refusal,
            });
        }
        if !self.visited.insert(addr) {
            return Err(NodeStop::Cycle { what, addr });
        }
        if self.count >= self.max {
            return Err(NodeStop::Capped {
                unit: self.unit,
                max: self.max,
            });
        }
        self.count += 1;
        Ok(())
    }
}

/// Walk a `FuturesUnordered`'s intrusive `head_all` → `next_all` node
/// list, handing each node to `visit` as it is reached.
pub(crate) fn walk_set_nodes<'b, T: Target>(
    ctx: &Context<'b, T>,
    read: &ReadContext<'_>,
    set: Value<'b>,
    max: usize,
    visit: &mut dyn FnMut(u64, Value<'b>) -> std::result::Result<(), NodeStop>,
) -> std::result::Result<(), NodeStop> {
    let head_member = ctx.walk(WalkRole::SetHeadAll).walk_at_with(read, set)?;
    let head: u64 = head_member.parse(ctx.proc).map_err(anyhow::Error::from)?;
    // The node layout is the pointer's target, reached by peeling the
    // atomic shims off the `head_all` word.
    let node_ty = head_member
        .ty
        .pointer_target()
        .ok_or_else(|| anyhow!("head_all does not peel to a pointer"))?;

    let mut walk = NodeWalk::new("set node", "nodes", max);
    let mut cur = head;
    while cur != 0 {
        walk.admit(ctx, read, cur, node_ty.size())?;
        let node = Value::read(ctx.proc, node_ty, cur)
            .with_context(|| format!("failed to read the set node at {cur:#x}"))?;
        visit(cur, node)?;
        cur = ctx.walk(WalkRole::SetNodeNext).read_with(read, node)?;
    }
    Ok(())
}

/// How deep an entry's key is rendered for its heading: a key is a
/// string, an integer or a thin wrapper over one, and a level past
/// the wrapper reads the string it holds.
const KEY_DEPTH: usize = 2;

/// The longest key text a heading takes. A key is a name — a DNS name
/// of seventy characters inside the newtype that wraps it still fits —
/// and what runs past this is a structural rendering of a type no
/// formatter reads as text, which names nothing to a reader.
const KEY_WIDTH: usize = 128;

/// A `StreamMap` entry's key as text for a heading, or `None` where
/// the bundle has no route to it, the read fails, or the value
/// renders on more than one line or wider than a name — an aggregate
/// no heading has room for, which the entry's index then stands in
/// for. Read on demand by the one walker that lists entries, since
/// the others only poll their streams.
pub(crate) fn fanout_key<'b, T: Target>(
    ctx: &Context<'b, T>,
    read: &ReadContext<'_>,
    entry: Value<'b>,
) -> Option<String> {
    let key = ctx
        .walk(WalkRole::StreamMapEntryKey)
        .walk_at_with(read, entry)
        .ok()?;
    let text = format!("{}", key.display_from_target(ctx.proc, KEY_DEPTH));
    let fits = !text.is_empty() && !text.contains('\n') && text.chars().count() <= KEY_WIDTH;
    fits.then_some(text)
}

/// Walk a `StreamMap`'s entries — the elements of its `Vec<(K, V)>`,
/// read through the `Vec`'s own buffer route — handing each entry to
/// `visit` with its index, the `(K, V)` element itself (for
/// [`fanout_key`]) and its stream, and returning how many entries the
/// map holds. The buffer is one allocation, held to the allocator's
/// word as a set's nodes are; past `max` entries the walk stops and
/// says so, the count still being the map's own.
pub(crate) fn walk_fanout_entries<'b, T: Target>(
    ctx: &Context<'b, T>,
    read: &ReadContext<'_>,
    map: Value<'b>,
    max: usize,
    visit: &mut dyn FnMut(usize, Value<'b>, Value<'b>) -> std::result::Result<(), NodeStop>,
) -> std::result::Result<usize, NodeStop> {
    let entries = ctx
        .walk(WalkRole::StreamMapEntries)
        .walk_at_with(read, map)?;
    let elements = entries.elements(ctx.proc).map_err(|e| {
        NodeStop::Failed(anyhow::Error::from(e).context(format!(
            "failed to read the entries of the StreamMap at {:#x}",
            map.addr
        )))
    })?;
    let total = elements.len() as usize;
    if let Some(first) = elements.iter().next() {
        let extent = elements.len() * elements.element_ty().size();
        if !ctx.mappings.contains_addr(first.addr) {
            return Err(NodeStop::Unmapped {
                what: "StreamMap entries",
                addr: first.addr,
            });
        }
        if let Some(refusal) = read.refusal(first.addr, extent) {
            return Err(NodeStop::Refused {
                what: "StreamMap entries",
                addr: first.addr,
                refusal,
            });
        }
    }
    for (index, entry) in elements.iter().enumerate().take(max) {
        let stream = ctx
            .walk(WalkRole::StreamMapEntryStream)
            .walk_at_with(read, entry)?;
        visit(index, entry, stream)?;
    }
    if total > max {
        return Err(NodeStop::Capped {
            unit: "entries",
            max,
        });
    }
    Ok(total)
}

/// What a hash table walk counted: the items the table says it holds,
/// and the full buckets its control bytes mark. The two agree in any
/// table not caught halfway through an insert or a removal.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct TableCount {
    pub(crate) items: u64,
    pub(crate) full: usize,
}

/// Walk a hash table's full buckets — a hashbrown map's or set's, or
/// std's around one — handing each to `visit` in bucket order with its
/// place among the full ones, by the words the type's table binding
/// routes to. A table with no items is known from its count alone: its
/// control pointer names a static group with nothing of the table's
/// below it. Otherwise the buckets and their control bytes are one
/// allocation, the buckets first, held to the allocator's word as a
/// map's entries buffer is; past `max` full buckets the walk stops and
/// says so.
pub(crate) fn walk_table_buckets<'b, T: Target>(
    ctx: &Context<'b, T>,
    read: &ReadContext<'_>,
    map: Value<'b>,
    table: &hansei_bundle::HashTableBinding,
    max: usize,
    visit: &mut dyn FnMut(usize, Value<'b>) -> std::result::Result<(), NodeStop>,
) -> std::result::Result<TableCount, NodeStop> {
    let word = |path: &hansei_bundle::TypedPath, what: &str| -> Result<u64> {
        let landed = super::contract::execute_steps(ctx, read, map, &path.steps)?
            .optional()
            .filter(|landed| landed.ty.id() == path.target)
            .ok_or_else(|| {
                anyhow!(
                    "the hash table's {what} at {:#x} is not where its binding says",
                    map.addr
                )
            })?;
        Ok(landed.parse(ctx.proc)?)
    };
    let items = word(&table.items, "item count")?;
    if items == 0 {
        return Ok(TableCount { items, full: 0 });
    }
    let mask = word(&table.bucket_mask, "bucket mask")?;
    let ctrl = word(&table.ctrl, "control pointer")?;
    let buckets = mask
        .checked_add(1)
        .filter(|buckets| buckets.is_power_of_two())
        .ok_or_else(|| {
            anyhow!(
                "the hash table at {:#x} has a bucket mask {mask:#x}, not a power of two less one",
                map.addr
            )
        })?;
    if items > buckets {
        return Err(NodeStop::Failed(anyhow!(
            "the hash table at {:#x} claims {items} items in {buckets} buckets",
            map.addr
        )));
    }
    let bucket = ctx.view.ty(table.bucket).ok_or_else(|| {
        anyhow!(
            "the tokio info records no bucket type {} for the hash table",
            table.bucket.0
        )
    })?;
    // A zero-sized bucket has no storage for anything to be found in.
    let stride = bucket.size();
    if stride == 0 {
        return Ok(TableCount { items, full: 0 });
    }
    let base = buckets
        .checked_mul(stride)
        .and_then(|span| ctrl.checked_sub(span))
        .ok_or_else(|| {
            anyhow!(
                "the hash table at {:#x} places its buckets below address zero",
                map.addr
            )
        })?;
    for addr in [base, ctrl] {
        if !ctx.mappings.contains_addr(addr) {
            return Err(NodeStop::Unmapped {
                what: "hash table",
                addr,
            });
        }
    }
    if let Some(refusal) = read.refusal(base, ctrl - base + buckets) {
        return Err(NodeStop::Refused {
            what: "hash table",
            addr: base,
            refusal,
        });
    }
    let control = ctx
        .proc
        .read_bytes(ctrl, buckets)
        .with_context(|| format!("failed to read the hash table's control bytes at {ctrl:#x}"))?;
    let mut full = 0;
    for (index, byte) in control.iter().enumerate() {
        if byte & 0x80 != 0 {
            continue;
        }
        if full == max {
            return Err(NodeStop::Capped {
                unit: "buckets",
                max,
            });
        }
        // Bucket `i` ends `i` buckets below the control bytes.
        let addr = ctrl - (index as u64 + 1) * stride;
        let value = Value::read(ctx.proc, bucket, addr)
            .map_err(|e| anyhow!(e).context(format!("failed to read the bucket at {addr:#x}")))?;
        visit(full, value)?;
        full += 1;
    }
    Ok(TableCount { items, full })
}

/// Walk a `JoinSet`'s two entry lists, handing each entry to `visit`
/// as it is reached and leaving the set's own count in `length`.
///
/// A `JoinSet<T>` is an `IdleNotifiedSet<JoinHandle<T>>`: a `length`
/// in the frame beside an `Arc` to a mutex over *two* intrusive
/// lists, one of entries whose task has woken and one of the rest.
/// Which list an entry is in says nothing about the task — a
/// completed task waits in `notified` for its output to be taken —
/// so both are walked and the entries handed over together, in the
/// order the lists hold them. The length is read before the walk and
/// kept either way, so a short list is visible beside its count.
///
/// Every entry's `value` is live by construction: an entry leaves
/// the two lists before its `JoinHandle` is consumed.
pub(crate) fn walk_join_set_entries<'b, T: Target>(
    ctx: &Context<'b, T>,
    read: &ReadContext<'_>,
    set: Value<'b>,
    max: usize,
    length: &mut u64,
    visit: &mut dyn FnMut(u64, Value<'b>) -> std::result::Result<(), NodeStop>,
) -> std::result::Result<(), NodeStop> {
    *length = ctx.walk(WalkRole::JoinSetLength).read_with(read, set)?;
    // The lists live behind an Arc, whose target is the `ArcInner`
    // header the payload follows; `data` is the mutex, and its own
    // `data` the guarded value, however the loom shim spells the lock.
    let lists = ctx
        .walk(WalkRole::JoinSetLists)
        .walk_at_with(read, set)
        .context("failed to read the join set's shared lists")?;

    let mut walk = NodeWalk::new("join set entry", "entries", max);
    for queue in [WalkRole::JoinSetNotifiedHead, WalkRole::JoinSetIdleHead] {
        let Some(head) = ctx.walk(queue).walk_with(read, lists)?.optional() else {
            continue;
        };
        // The recorded steps land on the raw entry pointer inside the
        // NonNull: its target is the layout each entry decodes with.
        let entry_ty = head
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("the {} list head is not pointer-shaped", queue.name()))?;
        let mut cur = Some(head.parse::<u64>(ctx.proc).map_err(anyhow::Error::from)?);
        while let Some(addr) = cur {
            walk.admit(ctx, read, addr, entry_ty.size())?;
            let entry = Value::read(ctx.proc, entry_ty, addr)
                .with_context(|| format!("failed to read the join set entry at {addr:#x}"))?;
            visit(addr, entry)?;
            cur = ctx
                .walk(WalkRole::JoinSetEntryNext)
                .walk_with(read, entry)?
                .optional()
                .map(|ptr| ptr.parse(ctx.proc).map_err(anyhow::Error::from))
                .transpose()?;
        }
    }
    Ok(())
}

/// The task a `JoinSet` entry's handle names.
///
/// ListEntry.value is the joined task's `JoinHandle`, behind a cell
/// and a `ManuallyDrop`. Every wrapper from the cell down to the
/// `Header` pointer holds one value, the handle included, so peeling
/// lands on that pointer — the same word a `JoinHandle` leaf is read
/// through. Asking for a member by name in there would peel first and
/// look afterwards, which is to say look past what it asked for.
pub(crate) fn join_set_entry_task<'b, T: Target>(
    ctx: &Context<'b, T>,
    entry: Value<'b>,
) -> Result<u64> {
    let handle = ctx.walk(WalkRole::JoinSetEntryValue).walk_at(entry)?;
    ensure!(
        handle.ty.pointer_target().is_some(),
        "the join set entry at {:#x} does not peel to a task pointer, but to {}",
        entry.addr,
        handle.ty.name()
    );
    Ok(handle.parse(ctx.proc)?)
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
    use crate::tokio::bundle::TaskStage;

    use crate::heap::umem::UmemHeap;
    use crate::heap::umem::tests::freeing;
    use crate::heap::view::{GateCounts, HeapView};
    use crate::testkit;

    use hansei_bundle::{
        Bundle, BundleMember, BundleType, BundleView, ContainerKind, DiscrValue, TypeDef,
    };

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

    /// Whether the bundle binds `ty` as a container of `kind`.
    fn bound_as(bundle: &Bundle, ty: BundleType<'_>, kind: ContainerKind) -> bool {
        bundle
            .semantics
            .types
            .iter()
            .any(|r| r.ty == ty.id() && r.container.as_ref().is_some_and(|c| c.kind == kind))
    }

    /// The facts a test hands the scan: the fixture bundle's own
    /// container bindings and future identities, plus exactly `futures`
    /// as further recognized futures — a poll table naming types the
    /// bundle's own evidence does not, which the scan takes as proof
    /// however the type is spelled.
    struct Facts {
        containers: HashMap<BundleTypeId, hansei_bundle::ContainerKind>,
        futures: HashSet<BundleTypeId>,
        adapters: HashSet<BundleTypeId>,
        unavailable: HashSet<BundleTypeId>,
    }

    impl Recognize for Facts {
        fn recognize(&self, id: BundleTypeId) -> Recognized {
            match self.containers.get(&id) {
                Some(hansei_bundle::ContainerKind::FuturesUnordered) => Recognized::Set,
                Some(hansei_bundle::ContainerKind::JoinSet) => Recognized::JoinSet,
                Some(hansei_bundle::ContainerKind::StreamMap) => Recognized::Fanout,
                None if self.futures.contains(&id) => Recognized::Future,
                None if self.adapters.contains(&id) => Recognized::Adapter,
                None if self.unavailable.contains(&id) => Recognized::Unavailable,
                None => Recognized::Other,
            }
        }
    }

    fn facts(bundle: &Bundle, ids: impl IntoIterator<Item = BundleTypeId>) -> Facts {
        let mut futures: HashSet<BundleTypeId> = ids.into_iter().collect();
        futures.extend(
            bundle
                .semantics
                .types
                .iter()
                .filter(|r| r.future.is_some() || r.resource.is_some())
                .map(|r| r.ty),
        );
        let adapters = bundle
            .semantics
            .types
            .iter()
            .filter(|r| {
                r.future.is_none()
                    && r.resource.is_none()
                    && r.access
                        .as_ref()
                        .is_some_and(|a| a.kind == hansei_bundle::AccessKind::Owned)
            })
            .map(|r| r.ty)
            .collect();
        Facts {
            containers: bundle
                .semantics
                .types
                .iter()
                .filter_map(|r| Some((r.ty, r.container.as_ref()?.kind)))
                .collect(),
            futures,
            adapters,
            unavailable: HashSet::default(),
        }
    }

    /// A poll table naming exactly `ids`, over the `unordered` fixture's
    /// containers.
    fn poll_table(ids: impl IntoIterator<Item = BundleTypeId>) -> Facts {
        facts(unordered(), ids)
    }

    /// A poll table naming every type there is — so a value screened as
    /// anything other than a future was screened by the order of the
    /// tests in [`scan_plan`], not by what the table knows.
    fn every_type(bundle: &Bundle) -> Facts {
        facts(
            bundle,
            (0..bundle.types.types.len() as u32).map(BundleTypeId),
        )
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
        /// Values abandoned at the depth limit.
        capped: usize,
        /// Values stopped at for unavailable storage.
        unavailable: usize,
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
                Find::Fanout(_) => "fan-out",
                Find::Future(_) => "future",
                Find::Adapter(_) => "adapter",
                Find::Table(_) => "table",
            }
        }

        fn value(&self) -> Value<'b> {
            match *self {
                Find::Set(v)
                | Find::JoinSet(v)
                | Find::Fanout(v)
                | Find::Future(v)
                | Find::Adapter(v)
                | Find::Table(v) => v,
            }
        }
    }

    fn scan<'b>(value: Value<'b>, facts: &dyn Recognize) -> Scanned<'b> {
        scan_from(value, facts, 0, HashMap::default())
    }

    /// A scan started part-way down, and over a memo a previous scan
    /// left behind.
    fn scan_from<'b>(
        value: Value<'b>,
        facts: &dyn Recognize,
        depth: usize,
        mut plans: HashMap<BundleTypeId, ScanPlan>,
    ) -> Scanned<'b> {
        let mut finds = Vec::new();
        let mut capped = Capped::default();
        let mut stats = Stats::default();
        scan_value(
            value,
            facts,
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
            capped: capped.deep,
            unavailable: capped.unavailable,
            plans,
            stats,
        }
    }

    /// Every kind of stop counts toward the total the warning reports,
    /// and any one of them alone makes the listing incomplete.
    #[test]
    fn test_every_cap_counts() {
        let capped = Capped {
            deep: 1,
            distant: 2,
            unavailable: 4,
        };
        assert_eq!(capped.total(), 7);
        assert!(capped.any());
        for one in [
            Capped {
                deep: 1,
                ..Capped::default()
            },
            Capped {
                distant: 1,
                ..Capped::default()
            },
            Capped {
                unavailable: 1,
                ..Capped::default()
            },
        ] {
            assert_eq!(one.total(), 1);
            assert!(one.any());
        }
        assert!(!Capped::default().any());
        assert_eq!(Capped::default().total(), 0);
    }

    /// A coroutine env the bundle declares unreadable — an unreviewed
    /// compiler's, say — is stopped at and counted, not scanned as the
    /// enum it is shaped as: the future its active variant holds is not
    /// found, and the place is one the listing is short.
    #[test]
    fn test_unavailable_storage_is_counted_and_never_scanned_as_an_enum() {
        let bundle = unordered();
        // A coroutine with a tagged suspended state whose awaitee is
        // itself a coroutine: found through the enum scan if anything is.
        let mut suspended = None;
        let ty = find_ty(bundle, |t| {
            if !t.is_coroutine() {
                return false;
            }
            let Some(shape) = t.variant_shape() else {
                return false;
            };
            let Some(discr) = &shape.discr else {
                return false;
            };
            let discr_size = t.related_type(discr.ty).size();
            if discr_size == 0 || discr_size > 8 {
                return false;
            }
            for v in &shape.variants {
                let payload = t.related_type(v.payload.ty);
                if !payload
                    .name()
                    .rsplit("::")
                    .next()
                    .unwrap_or("")
                    .starts_with("Suspend")
                {
                    continue;
                }
                let Some(vals) = &v.discr_values else {
                    continue;
                };
                let [DiscrValue::Value(tag)] = vals.0.as_slice() else {
                    continue;
                };
                let Some(awaitee) = payload.members().find(|m| m.name() == "__awaitee") else {
                    continue;
                };
                if !awaitee.ty().is_coroutine() {
                    continue;
                }
                suspended = Some((discr.offset, discr_size, *tag, awaitee.ty().id()));
                return true;
            }
            false
        });
        let (discr_offset, discr_size, tag, awaitee) =
            suspended.expect("the fixture has a coroutine awaiting a coroutine");
        // As the bundle's own facts have it, the coroutine is a future
        // and is found as one.
        let known = facts(bundle, []);
        let bytes = vec![0u8; ty.size() as usize];
        let value = Value::new(ty, AT, &bytes);
        let scanned = scan(value, &known);
        assert!(
            matches!(scanned.finds.as_slice(), [Find::Future(_)]),
            "{:?}",
            scanned.summary()
        );
        // With its storage unavailable instead, nothing is found — not
        // the coroutine, and not the awaitee the enum scan would have
        // reached — and the stop is counted.
        let mut given = facts(bundle, []);
        given.futures.remove(&ty.id());
        given.unavailable.insert(ty.id());
        assert!(given.futures.contains(&awaitee));
        let scanned = scan(value, &given);
        assert!(scanned.finds.is_empty(), "{:?}", scanned.summary());
        assert_eq!(scanned.unavailable, 1);
        assert_eq!(scanned.capped, 0);
        assert!(matches!(
            scanned.plans.get(&ty.id()),
            Some(ScanPlan::Unavailable)
        ));
        // Unknown to the facts entirely, the same enum is scanned like
        // any other: the awaitee inside its active variant is found.
        // That fall-through is exactly what an unavailable record
        // exists to prevent.
        let mut given = facts(bundle, []);
        given.futures.remove(&ty.id());
        let mut active = bytes.clone();
        let at = discr_offset as usize;
        active[at..at + discr_size as usize]
            .copy_from_slice(&tag.to_le_bytes()[..discr_size as usize]);
        let value = Value::new(ty, AT, &active);
        let scanned = scan(value, &given);
        assert!(
            scanned.finds.iter().any(|f| f.value().ty.id() == awaitee),
            "{:?} (types {:?}, awaitee {:?})",
            scanned.summary(),
            scanned
                .finds
                .iter()
                .map(|f| f.value().ty.name())
                .collect::<Vec<_>>(),
            ty.related_type(awaitee).name()
        );
        // And with the storage unavailable, those same bytes yield
        // nothing either: the active variant is never consulted.
        let scanned = scan(value, &{
            let mut given = facts(bundle, []);
            given.futures.remove(&ty.id());
            given.unavailable.insert(ty.id());
            given
        });
        assert!(scanned.finds.is_empty(), "{:?}", scanned.summary());
        assert_eq!(scanned.unavailable, 1);
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

    /// A pointer to a set: something the scan would certainly have
    /// recorded had it been reached by value.
    fn pointer_to_set(bundle: &Bundle) -> BundleType<'_> {
        find_ty(bundle, |ty| {
            matches!(ty.def(), TypeDef::Pointer { .. })
                && ty
                    .pointer_target()
                    .is_some_and(|t| bound_as(bundle, t, ContainerKind::FuturesUnordered))
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
        // The find came through the variant step — and through the
        // variant struct's member, which the scan descends like any
        // aggregate. It sees the payload *as declared* rather than
        // pre-peeled: peel walks single-sized-member wrappers, and on
        // a `Some(JoinSet<_>)` that descends straight through the
        // JoinSet before the name screen can run — a silent omission
        // the generated corpus caught.
        assert_eq!(scanned.stats.enum_finds, 1, "{:?}", scanned.stats);
        assert_eq!(scanned.stats.descend_finds, 1, "{:?}", scanned.stats);

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

    /// A zero-sized member is not scanned: there is no value there to
    /// read, and a poll table naming its type must not conjure a find
    /// out of nothing.
    #[test]
    fn test_a_zero_sized_member_is_not_scanned() {
        let bundle = unordered();
        let mut zst = None;
        let known = every_type(bundle);
        let ty = find_ty(bundle, |ty| {
            // A plain struct the scan would descend into, not one the
            // bundle's own facts take for a future or a set.
            if !matches!(ty.def(), TypeDef::Struct { .. })
                || known.containers.contains_key(&ty.id())
                || bundle
                    .semantics
                    .types
                    .iter()
                    .any(|r| r.ty == ty.id() && (r.future.is_some() || r.resource.is_some()))
            {
                return false;
            }
            let bytes = vec![0u8; ty.size() as usize];
            if Value::new(ty, AT, &bytes).peel().ty.dyn_pointer().is_some() {
                return false;
            }
            zst = ty.members().find(|m| m.ty().size() == 0);
            zst.is_some()
        });
        let zst = zst.expect("the found struct has a zero-sized member");
        let bytes = vec![0u8; ty.size() as usize];
        let scanned = scan(Value::new(ty, AT, &bytes), &poll_table([zst.ty().id()]));
        assert!(
            scanned.finds.is_empty(),
            "a zero-sized member was scanned: {:?}",
            scanned.summary()
        );
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
        let ty = find_ty(bundle, |t| {
            bound_as(bundle, t, ContainerKind::FuturesUnordered)
        });
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
        let ty = find_ty(bundle, |t| bound_as(bundle, t, ContainerKind::JoinSet));
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
        let census = unordered_census_with(bounds, None);
        assert!(census.errors.is_empty(), "{:?}", census.errors);
        census
    }

    /// [`unordered_census`], with an allocator index to corroborate
    /// against — and without the clean-errors assertion, since a
    /// refused node *is* an error on the census: the list it was in
    /// runs short and the error is what says so.
    fn unordered_census_with(bounds: Bounds, heap: Option<&UmemHeap>) -> FutureCensus {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        // Through the same bridge a session hands the walk: the real
        // adapter, over the real index.
        let gates = GateCounts::default();
        let view = heap.map(|heap| HeapView::new(heap, &snapshot, &gates));
        let read = ReadContext {
            heap: view.as_ref().map(|view| view as &dyn reify::Heap),
        };
        let census = census_bounded(&ctx, &list, bounds, &read);
        // A healthy capture passes both audit classes, bounded or not
        // — and a refusal must not change that. It removes rows, and
        // every invariant is over the rows that are there.
        let violations = census.audit(&list);
        assert!(violations.is_empty(), "{violations:#?}");
        census
    }

    /// Every held find as its identity alone — the local it was found
    /// in and where it lies — which is what a refusal must leave
    /// untouched, and enough to say which row it did touch.
    fn held_rows(census: &FutureCensus) -> Vec<(&str, u64)> {
        census
            .held
            .iter()
            .map(|h| (h.local.as_str(), h.addr))
            .collect()
    }

    /// The same for the sets: each by its own address and the nodes it
    /// listed.
    fn set_rows(census: &FutureCensus) -> Vec<(u64, Vec<u64>)> {
        census
            .sets
            .iter()
            .map(|s| (s.addr, s.children.iter().map(|c| c.node).collect()))
            .collect()
    }

    /// The held find `local` names, of the ungated census.
    fn held_at<'a>(census: &'a FutureCensus, local: &str) -> &'a HeldFuture {
        census
            .held
            .iter()
            .find(|h| h.local == local)
            .unwrap_or_else(|| panic!("the fixture holds a future in `{local}`"))
    }

    /// A find the allocator has taken back is not listed, and neither
    /// is anything the walk would have reached through it.
    ///
    /// That is the difference between corroborating *inside* the walk
    /// and filtering the finished listing: the walk goes on through
    /// what it records, so a filter would drop the row and keep the
    /// subtree hanging under a parent that is no longer there. The
    /// fixture's `nested_hold` is the shape that shows it — a held
    /// future whose own frames hold `inner` — and one refusal is
    /// counted for it, not two, because the second was never reached.
    /// The heap double refuses exactly as the real index does: the
    /// same find, the same subtree gone with it, the same count — so a
    /// scan's refusal behaviour can be asserted where no core carries
    /// allocator metadata.
    /// The census's count of withheld locals is at least what the
    /// tasks' own frames withhold — it scans the chains of what it
    /// finds as well — and walk-shapes withholds some.
    #[test]
    fn test_uncertain_locals_are_summed_over_the_frames() {
        let (bundle, snapshot) = testkit::load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = census(&ctx, &list);
        let mut expected = 0;
        for task in &list.tasks {
            let Ok(Some(inspection)) = ctx.inspect_task(task, &ReadContext::none()) else {
                continue;
            };
            for frame in &inspection.chain.frames {
                expected += frame_locals(&ctx, frame).uncertain;
            }
        }
        assert!(expected > 0);
        assert!(
            census.uncertain >= expected,
            "{} < {expected}",
            census.uncertain
        );
    }

    /// A running task's frames are read for the sets they hold and
    /// nothing else: marked running, the task that polls the fixture's
    /// sets still lists every one of them, with the same nodes and the
    /// finds under them, while the futures its own frames hold, and
    /// the locals they withhold, drop out.
    #[test]
    fn test_a_running_task_still_holds_its_sets() {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let parked = census(&ctx, &list);
        let owner = parked
            .sets
            .iter()
            .find(|set| set.via.is_none() && !set.children.is_empty())
            .expect("the fixture's task holds a set with children")
            .owner;
        let own_held = |census: &FutureCensus| {
            census
                .held
                .iter()
                .filter(|h| h.owner == owner && h.via.is_none())
                .count()
        };
        assert!(
            own_held(&parked) > 0,
            "the owner holds futures beside its sets"
        );

        let mut tasks = list.tasks.clone();
        tasks[owner].state = TaskState(tasks[owner].state.0 | 0b1);
        let list = TaskList::new(tasks);
        assert!(
            matches!(
                ctx.inspect_task(&list.tasks[owner], &ReadContext::none())
                    .unwrap()
                    .expect("the owner still has a root")
                    .chain
                    .end,
                super::super::bundle::ChainEnd::ActivePoll
            ),
            "the owner reads as mid-poll"
        );
        let running = census(&ctx, &list);

        let sets_of = |census: &FutureCensus| -> Vec<(u64, Vec<u64>)> {
            census
                .sets
                .iter()
                .filter(|set| set.owner == owner && set.via.is_none())
                .map(|s| (s.addr, s.children.iter().map(|c| c.node).collect()))
                .collect()
        };
        assert_eq!(sets_of(&running), sets_of(&parked));
        // What the children hold is theirs, not the running frames':
        // it is listed as before.
        let under_children = |census: &FutureCensus| {
            census
                .held
                .iter()
                .filter(|h| h.owner == owner && matches!(h.via, Some(Via::SetChild { .. })))
                .count()
        };
        assert_eq!(under_children(&running), under_children(&parked));
        assert_eq!(own_held(&running), 0, "{:#?}", running.held);
        assert!(running.uncertain <= parked.uncertain);
    }

    #[test]
    fn test_the_heap_double_refuses_like_the_real_index() {
        let full = unordered_census(Bounds::default());
        let stale = held_at(&full, "nested_hold").addr;
        let real = unordered_census_with(Bounds::default(), Some(&freeing(stale..stale + 1)));

        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let double = testkit::heap::FakeHeap::new().freed(stale..stale + 1);
        let faked = census_bounded(
            &ctx,
            &list,
            Bounds::default(),
            &ReadContext::with_heap(&double),
        );
        assert_eq!(held_rows(&faked), held_rows(&real));
        assert_eq!(faked.refused, real.refused);
        assert_eq!(faked.refused, 1);
        assert_eq!(faked.sets.len(), real.sets.len());
        // The refusal is the census's own count, not a renderer gate.
        assert_eq!(double.counts(), (0, 0, 0));
        // And a double that frees nothing the walk touches changes
        // nothing.
        let elsewhere = testkit::heap::FakeHeap::new().freed(1..2);
        let same = census_bounded(
            &ctx,
            &list,
            Bounds::default(),
            &ReadContext::with_heap(&elsewhere),
        );
        assert_eq!(held_rows(&same), held_rows(&full));
        assert_eq!(same.refused, 0);
    }

    #[test]
    fn test_a_find_in_freed_memory_takes_its_subtree_with_it() {
        let full = unordered_census(Bounds::default());
        let stale = held_at(&full, "nested_hold").addr;
        assert_eq!(
            held_at(&full, "inner").via,
            Some(Via::Held(
                full.held
                    .iter()
                    .position(|h| h.local == "nested_hold")
                    .expect("it is listed")
            )),
            "the fixture must reach `inner` through `nested_hold` for this to say anything"
        );

        let heap = freeing(stale..stale + 1);
        let census = unordered_census_with(Bounds::default(), Some(&heap));

        let held = held_rows(&census);
        assert!(
            !held
                .iter()
                .any(|&(local, _)| local == "nested_hold" || local == "inner"),
            "{held:#?}"
        );
        // Everything the refusal was not about is where it was.
        let kept: Vec<(&str, u64)> = held_rows(&full)
            .into_iter()
            .filter(|&(local, _)| local != "nested_hold" && local != "inner")
            .collect();
        assert_eq!(held, kept);
        assert_eq!(set_rows(&census), set_rows(&full));
        assert_eq!(census.refused, 1);
        assert!(census.errors.is_empty(), "{:?}", census.errors);
    }

    /// What a refusal weighs behind a pointer is the referent, not the
    /// slot the pointer was found in.
    ///
    /// A boxed find is recorded at the heap allocation its wide
    /// pointer named, and that address is the frame's *claim* — the
    /// one thing about the find the allocator can contradict. The slot
    /// itself is in the frame, which is live whatever the pointer in
    /// it says.
    #[test]
    fn test_a_boxed_find_is_weighed_where_the_pointer_lands() {
        let full = unordered_census(Bounds::default());
        let boxed = held_at(&full, "boxed");
        let (slot, referent) = (boxed.slot, boxed.addr);
        assert_ne!(slot, referent, "`boxed` must be a find behind a pointer");

        let heap = freeing(referent..referent + 1);
        let census = unordered_census_with(Bounds::default(), Some(&heap));
        assert!(
            !census.held.iter().any(|h| h.local == "boxed"),
            "{:#?}",
            census.held
        );
        assert_eq!(census.refused, 1);

        // The slot is where the scan was already standing rather than
        // an address it followed a pointer to, and an index that
        // freed it refuses the find just the same — through the gate
        // ahead of the chain rather than the one behind it.
        let heap = freeing(slot..slot + 1);
        let census = unordered_census_with(Bounds::default(), Some(&heap));
        assert!(
            !census.held.iter().any(|h| h.local == "boxed"),
            "{:#?}",
            census.held
        );
        assert_eq!(census.refused, 1);
    }

    /// The `delegation-cases` census over the given heap evidence, with
    /// the registry its program wrote down: each case's root and the
    /// child it holds, by the addresses the program itself recorded.
    fn delegation_census(
        heap: Option<&testkit::heap::FakeHeap>,
    ) -> (FutureCensus, Vec<testkit::delegation::Case>) {
        let (bundle, snapshot) = testkit::load_any("delegation-cases");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let read = match heap {
            Some(heap) => ReadContext::with_heap(heap),
            None => ReadContext::none(),
        };
        let census = census_bounded(&ctx, &list, Bounds::default(), &read);
        let cases = testkit::delegation::read_from(&snapshot)
            .expect("the fixture registers its cases")
            .expect("the registry is post-poll ground truth");
        (census, cases)
    }

    fn delegation_case<'a>(
        cases: &'a [testkit::delegation::Case],
        name: &str,
    ) -> &'a testkit::delegation::Case {
        cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("the fixture registers the {name} case"))
    }

    /// A find behind an owned box is listed where the box points —
    /// the box is an adapter, not a future, and what it holds is the
    /// find — and weighed there: an index that has taken the pointee
    /// back refuses the find, and the box's slot lists nothing.
    #[test]
    fn test_a_find_behind_an_owned_box_is_listed_where_the_box_points() {
        let (full, cases) = delegation_census(None);
        let holder = delegation_case(&cases, "holder");
        let held = held_at(&full, "held");
        assert_eq!(held.addr, holder.child);
        let (bundle, _) = testkit::load_any("delegation-cases");
        let future = BundleView::new(&bundle).ty(held.future).unwrap().name();
        assert!(future.contains("{async_block"), "{future}");
        assert_eq!(full.refused, 0);

        let freed = testkit::heap::FakeHeap::new().freed(holder.child..holder.child + 1);
        let (census, _) = delegation_census(Some(&freed));
        assert!(
            !census.held.iter().any(|h| h.local == "held"),
            "{:#?}",
            census.held
        );
        assert_eq!(census.refused, 1);
        assert_eq!(census.uncertain, full.uncertain);
        let kept: Vec<(&str, u64)> = held_rows(&full)
            .into_iter()
            .filter(|&(local, _)| local != "held")
            .collect();
        assert_eq!(held_rows(&census), kept);
    }

    /// A box whose pointer word leads off the map holds nothing the
    /// census can list, and nothing the allocator refused either: the
    /// slot lists nothing and the refusal count is untouched.
    #[test]
    fn test_a_box_pointing_off_the_map_is_neither_listed_nor_refused() {
        const NOWHERE: u64 = 0xdead_beef_0000;
        let (bundle, snapshot) = testkit::load_any("delegation-cases");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let holder = list
            .tasks
            .iter()
            .find(|t| matches!(&t.future, FutureInfo::Known(k) if k.name(ctx.view).contains("delegation_cases::Holder<")))
            .expect("the holder is a task");
        // The pin over the box forwards to the holder itself, whose
        // `held` member is the box's pointer word.
        let root = match ctx.task_root(holder, &ReadContext::none()).unwrap() {
            TaskStage::Running(root) => root,
            other => panic!("the holder is resident: {other:?}"),
        };
        let testkit::delegation::Followed::Static { value: holder, .. } =
            testkit::delegation::follow(&ctx, root).unwrap()
        else {
            panic!("the pin forwards statically");
        };
        let slot = holder.addr + holder.ty.member("held").expect("Holder::held").offset();

        let cut = testkit::corrupt::Corrupt::new(&snapshot).patch(slot, NOWHERE);
        let ctx = Context::new(&cut, BundleView::new(&bundle)).unwrap();
        let census = census_bounded(&ctx, &list, Bounds::default(), &ReadContext::none());
        assert!(
            !census.held.iter().any(|h| h.local == "held"),
            "{:#?}",
            census.held
        );
        assert_eq!(census.refused, 0);
    }

    /// A pinned box in a frame's locals whose pointee is a frame of
    /// that chain — the chain went through a `Pin` reference to the
    /// same block — is that frame, counted there, and not a future
    /// held beside the chain.
    #[test]
    fn test_a_box_aliasing_a_frame_of_its_chain_is_counted_as_that_frame() {
        let (full, cases) = delegation_census(None);
        let alias = delegation_case(&cases, "alias");
        assert!(
            !full
                .held
                .iter()
                .any(|h| h.local == "inner" || h.addr == alias.child),
            "{:#?}",
            full.held
        );
    }

    /// An index that has taken back nothing the census reads changes
    /// nothing about the census — which is the whole of what a healthy
    /// target must see, and what the fixtures and every real target
    /// walked so far actually do see.
    #[test]
    fn test_an_index_with_nothing_to_refuse_changes_nothing() {
        let full = unordered_census(Bounds::default());
        // Free memory the walk never reads: past every address the
        // ungated census recorded.
        let past = full.held.iter().map(|h| h.addr).max().expect("finds") + 0x10_0000;
        let heap = freeing(past..past + 0x1000);
        let census = unordered_census_with(Bounds::default(), Some(&heap));

        assert_eq!(held_rows(&census), held_rows(&full));
        assert_eq!(set_rows(&census), set_rows(&full));
        assert_eq!(census.refused, 0);
        assert_eq!(census.capped, full.capped);
        assert_eq!(census.stats, full.stats);
        assert!(census.errors.is_empty(), "{:?}", census.errors);
    }

    /// A set's node list stops at a node the allocator has taken back,
    /// and the error says so.
    ///
    /// It stops rather than skipping the node: the link to the next
    /// one is read out of the very bytes the refusal is about. The
    /// children found before it are real and are kept, which is what
    /// the walk already does for an unmapped node.
    #[test]
    fn test_a_set_stops_at_a_node_the_allocator_took_back() {
        let full = unordered_census(Bounds::default());
        let set = full
            .sets
            .iter()
            .find(|s| s.children.len() > 1)
            .expect("the fixture drives a set of several children");
        let (owner, first, stale) = (set.addr, set.children[0].node, set.children[1].node);

        let heap = freeing(stale..stale + 1);
        let census = unordered_census_with(Bounds::default(), Some(&heap));

        let gated = census
            .sets
            .iter()
            .find(|s| s.addr == owner)
            .expect("the set itself is still listed");
        assert_eq!(
            gated.children.iter().map(|c| c.node).collect::<Vec<_>>(),
            [first]
        );
        // A refused node is a short list rather than a dropped find,
        // so it is the error that reports it, the way every other
        // short list here is reported.
        assert_eq!(census.refused, 0);
        let reports: Vec<String> = census.errors.iter().map(|e| format!("{e:#}")).collect();
        assert!(
            reports.iter().any(|r| r.contains(&format!("{stale:#x}"))
                && r.contains("taken back")
                && r.contains("lists only 1 of its children")),
            "{reports:#?}"
        );
    }

    /// A set whose children sit behind `dyn Future` boxes names each
    /// child by the future its box holds: the fixture's nested set
    /// holds unpolled `leaf`s that way. Its slot is a
    /// `Pin<Box<dyn Future>>`, and read peeled it would be the bare box
    /// inside the pin, which is no future — every child would stop
    /// there, named by the box and with no continuation.
    #[test]
    fn test_a_set_names_a_boxed_child_by_the_future_it_holds() {
        let census = unordered_census(Bounds::default());
        let nested = census
            .sets
            .iter()
            .find(|s| s.via.is_some())
            .expect("the fixture's first child holds a set");
        assert_eq!(nested.children.len(), 2, "{nested:#?}");
        let (bundle, _) = testkit::load_any("unordered");
        let view = BundleView::new(&bundle);
        for child in &nested.children {
            let future = view.ty(child.future.unwrap()).unwrap().name();
            assert!(future.starts_with("unordered::leaf"), "{future}");
            assert!(
                matches!(child.continuation, ContinuationStatus::Unresumed),
                "{child:#?}"
            );
        }
    }

    /// A join set's entry list stops the same way, at an entry the
    /// allocator has taken back — and for the same reason: the link
    /// to the next entry is in the refused bytes. The set keeps the
    /// length it reads for itself, so the listing shows both numbers
    /// and the error says why they differ.
    #[test]
    fn test_a_join_set_stops_at_an_entry_the_allocator_took_back() {
        let (bundle, snapshot) = testkit::load_any("joinset");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);

        let full = census(&ctx, &list);
        assert!(full.errors.is_empty(), "{:?}", full.errors);
        let set = full
            .join_sets
            .iter()
            .find(|s| !s.children.is_empty())
            .expect("the fixture drives a join set with tasks in it");
        let (owner, stale, length) = (set.addr, set.children[0].entry, set.length);

        let heap = freeing(stale..stale + 1);
        let gates = GateCounts::default();
        let view = HeapView::new(&heap, &snapshot, &gates);
        let census = census_bounded(
            &ctx,
            &list,
            Bounds::default(),
            &ReadContext::with_heap(&view),
        );
        let gated = census
            .join_sets
            .iter()
            .find(|s| s.addr == owner)
            .expect("the join set itself is still listed");
        assert!(
            !gated.children.iter().any(|c| c.entry == stale),
            "{gated:#?}"
        );
        assert_eq!(
            gated.length, length,
            "the set's own count is read either way"
        );
        assert_eq!(census.refused, 0);
        let reports: Vec<String> = census.errors.iter().map(|e| format!("{e:#}")).collect();
        assert!(
            reports
                .iter()
                .any(|r| r.contains(&format!("{stale:#x}")) && r.contains("taken back")),
            "{reports:#?}"
        );
        // A list the walk cut short is still a sound census: the
        // length it disagrees with is excused by the error that names
        // the set.
        let violations = census.audit(&list);
        assert!(violations.is_empty(), "{violations:#?}");
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
        // scanned: the seven futures the driver holds — two of them in
        // its map's buckets, which are the frame's storage and no hop —
        // and the set it drives, whose children are walked (a set's own
        // child list is not a hop) but never scanned.
        let census = unordered_census(nesting(0));
        assert_eq!(census.sets.len(), 1, "{:#?}", census.sets);
        assert_eq!(census.sets[0].children.len(), 3, "{:#?}", census.sets[0]);
        let own: Vec<&str> = census.held.iter().map(|h| h.local.as_str()).collect();
        assert_eq!(
            own,
            [
                "held",
                "boxed",
                "pair",
                "maybe",
                "nested_hold",
                "keyed[0]",
                "keyed[1]"
            ],
            "{:#?}",
            census.held
        );
        assert!(
            census.held.iter().all(|h| h.via.is_none()),
            "{:#?}",
            census.held
        );

        // Seven held futures and three resident set children: ten
        // chains the census reached and declined to scan.
        assert_eq!(
            census.capped,
            Capped {
                deep: 0,
                distant: 10,
                unavailable: 0,
            }
        );
        assert!(census.capped.any());
        assert_eq!(census.capped.total(), 10);
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
                distant: 6,
                unavailable: 0,
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
            read: ReadContext::none(),
            pass: AssessmentPass::new(),
            sets: Vec::new(),
            join_sets: Vec::new(),
            held: Vec::new(),
            spans: Vec::new(),
            errors: Vec::new(),
            capped: Capped::default(),
            uncertain: 0,
            refused: 0,
            stats: Stats::default(),
            pool_peers: PoolPeers::default(),
            pool_infos: PoolInfos::default(),
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
        walker.record(
            0,
            0,
            "held",
            None,
            Find::Future(value),
            0,
            &HashSet::default(),
        );
        assert_eq!(walker.held.len(), 1, "{:#?}", walker.held);
        assert_eq!(walker.stats.dedup_hits, 0);

        walker.record(
            0,
            0,
            "held_again",
            None,
            Find::Future(value),
            0,
            &HashSet::default(),
        );
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
        let chain = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .expect("the owner task is running")
            .chain;
        let frame = &chain.frames[chain.frames.len() - 1 - held.frame];
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
        walker.record(
            0,
            0,
            "boxed",
            None,
            Find::Future(slot),
            0,
            &HashSet::default(),
        );
        assert_eq!(walker.held.len(), 1, "{:#?}", walker.held);
        assert_eq!(walker.stats.dedup_hits, 0);

        // The same wide pointer read out of a different slot: a fresh
        // slot key over the same future behind it.
        let alias = Value::new(m.ty(), AT, bytes);
        walker.record(
            0,
            0,
            "alias",
            None,
            Find::Future(alias),
            0,
            &HashSet::default(),
        );
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
    use super::super::bundle::{FutureInfo, OwnerResolution, Task, TaskKind};

    use anyhow::anyhow;

    /// The type names the hand-laid rows below carry: a future `f`, the
    /// sets `S` and `T`, a join set `J`, and two tasks' futures, each its
    /// position's id.
    const NAMES: [&str; 6] = [
        "f",
        "S",
        "T",
        "J",
        "demo::driver::{async_fn_env#0}",
        "demo::worker::{async_fn_env#0}",
    ];

    /// The id [`names`] gives `name`.
    fn named(name: &str) -> BundleTypeId {
        let at = NAMES.iter().position(|n| *n == name).expect("a named type");
        BundleTypeId(at as u32)
    }

    /// A bundle holding nothing but [`NAMES`], so what reads a row's type
    /// by name can.
    fn names() -> BundleView<'static> {
        static BUNDLE: OnceLock<Bundle> = OnceLock::new();
        BundleView::new(BUNDLE.get_or_init(|| testkit::named_types(&NAMES)))
    }

    /// A list of `n` tasks at distinct addresses, for owners to name.
    fn task_list(n: usize) -> TaskList {
        TaskList::new(
            (0..n)
                .map(|i| Task {
                    addr: TaskAddr(0x100 + i as u64 * 0x40),
                    state: TaskState(0),
                    owner_id: None,
                    task_id: None,
                    spawn_location: None,
                    future: FutureInfo::Unknown { poll_symbol: None },
                    kind: TaskKind::Async,
                    owner: OwnerResolution::Unknown,
                })
                .collect(),
        )
    }

    fn blank() -> FutureCensus {
        FutureCensus {
            sets: Vec::new(),
            join_sets: Vec::new(),
            held: Vec::new(),
            spans: Vec::new(),
            errors: Vec::new(),
            capped: Capped::default(),
            uncertain: 0,
            refused: 0,
            stats: Stats::default(),
            pool_peers: PoolPeers::default(),
            pool_infos: PoolInfos::default(),
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
            frames: Vec::new(),
            future: named("f"),
            state: None,
            waiting_on: None,
            wait: None,
            observation: None,
            request: None,
            continuation: no_chain(),
        }
    }

    /// The continuation of a find laid out by hand: no chain was walked.
    fn no_chain() -> ContinuationStatus {
        ContinuationStatus::Incomplete {
            reason: super::super::assess::IncompleteReason::NoRoot,
            detail: None,
        }
    }

    fn a_child(node: u64, root: u64) -> SetChild {
        SetChild {
            node,
            depth: 1,
            future: Some(named("f")),
            root: Some(FutureRoot {
                addr: root,
                ty: BundleTypeId(0),
            }),
            state: None,
            waiting_on: None,
            wait: None,
            observation: None,
            request: None,
            continuation: no_chain(),
        }
    }

    fn a_set(addr: u64, ty: &str, children: Vec<SetChild>) -> FutureSet {
        FutureSet {
            owner: 0,
            frame: 0,
            local: "set".to_string(),
            via: None,
            addr,
            ty: named(ty),
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
            ty: named("J"),
            length,
            children,
        }
    }

    /// How a `via` is spelled for a reader: the parent's kind and the
    /// address whose listing row prints it — the held future's own
    /// address, a set child's node.
    #[test]
    fn test_describe_names_the_parent_and_its_address() {
        let mut census = blank();
        census.held.push(a_held(0, 0x2000));
        census
            .sets
            .push(a_set(0x3000, "S", vec![a_child(0x4000, 0x4010)]));
        assert_eq!(census.describe(Via::Held(0)), "held future at 0x2000");
        assert_eq!(
            census.describe(Via::SetChild { set: 0, child: 0 }),
            "set child at 0x4000"
        );
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

        // An error about another address that merely begins with this
        // one's digits is no escape hatch.
        census
            .errors
            .push(anyhow!("the set node at 0x50100 is unreadable"));
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

    #[test]
    fn test_a_report_names_an_address_only_whole() {
        assert!(names_address("the node at 0x10 is bent", 0x10));
        assert!(names_address("0x10", 0x10));
        assert!(names_address("nodes at 0x8, 0x10.", 0x10));
        assert!(!names_address("the node at 0x100 is bent", 0x10));
        assert!(!names_address("the node at 0x10a is bent", 0x10));
        assert!(!names_address("the node at 0x0x10 is bent", 0x10));
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
            |held| {
                held.wait = Some(WaitKind::Io {
                    addr: 0x7000,
                    handshake: false,
                })
            },
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
                future: named(name),
                kind: hansei_bundle::FutureKind::AsyncFn,
                decl: None,
                symbol: String::new(),
            }),
            kind: TaskKind::Async,
            owner: OwnerResolution::Unknown,
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
        assert_eq!(
            diff(&expected, names(), &census, &list),
            Vec::<String>::new()
        );
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
        let flagged = diff(&expected, names(), &census, &list);
        assert_eq!(flagged.len(), 1, "{flagged:#?}");
        assert!(flagged[0].contains("no census row"), "{flagged:#?}");

        // An error about another address that merely begins with this
        // one's digits names nothing registered.
        census.errors.push(anyhow!("something failed at 0x10000"));
        assert_eq!(diff(&expected, names(), &census, &list).len(), 1);

        census.errors.push(anyhow!("something failed at 0x1000"));
        assert_eq!(
            diff(&expected, names(), &census, &list),
            Vec::<String>::new()
        );
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
        let flagged = diff(&[], names(), &census, &list);
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
        let flagged = diff(&expected, names(), &census, &list);
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
        assert_eq!(
            diff(&expected, names(), &census, &list),
            Vec::<String>::new()
        );
        let by_referent = [Expectation::Held {
            slot: 0x9000,
            name: "f".to_string(),
        }];
        assert_eq!(diff(&by_referent, names(), &census, &list).len(), 2);
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
        assert_eq!(
            diff(&expected, names(), &census, &list),
            Vec::<String>::new()
        );

        // The same registration against a census that attributed the
        // carried future to the wrong parent — or to no parent — fails.
        census.held[1].via = None;
        let flagged = diff(&expected, names(), &census, &list);
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
        let flagged = diff(&expected, names(), &census, &list);
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
        assert_eq!(diff(&expected, names(), &census, &list).len(), 3);

        // ...and one error per named address excuses each in turn.
        census.errors.push(anyhow!("the set at 0x4000 broke"));
        census.errors.push(anyhow!("the join set at 0x6000 broke"));
        census.errors.push(anyhow!("the frame at 0x1000 broke"));
        assert_eq!(
            diff(&expected, names(), &census, &list),
            Vec::<String>::new()
        );
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
        let flagged = diff(&expected, names(), &census, &list);
        assert_eq!(flagged.len(), 1, "{flagged:#?}");
        assert!(
            flagged[0].contains("1 members against the registered 3"),
            "{flagged:#?}"
        );

        // An error naming the set stands in for the missing members.
        census.errors.push(anyhow!("the walk stopped at 0x6000"));
        assert_eq!(
            diff(&expected, names(), &census, &list),
            Vec::<String>::new()
        );
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
        let flagged = diff(&expected, names(), &census, &list);
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
            diff(std::slice::from_ref(&one), names(), &census, &list),
            Vec::<String>::new()
        );
        let two = [one.clone(), one];
        let flagged = diff(&two, names(), &census, &list);
        assert_eq!(flagged.len(), 1, "{flagged:#?}");
        assert!(
            flagged[0].contains("2 task(s) registered as `demo::worker`, but the listing shows 1"),
            "{flagged:#?}"
        );
    }

    // The problem lists (`testkit::healthy_problems`,
    // `testkit::expect::problems`) are pinned here for the same reason
    // as the diff: the offline suites only ever show them empty, so
    // the reporting side is pinned over hand-built censuses or
    // nowhere.

    /// A clean walk owes a healthy capture nothing.
    #[test]
    fn test_healthy_problems_pass_a_clean_walk() {
        assert_eq!(
            testkit::healthy_problems(&blank(), &task_list(1)),
            Vec::<String>::new()
        );
    }

    /// Each entitlement reports in its own spelling: every census
    /// error, any cap, and every healthy-only audit violation.
    #[test]
    fn test_healthy_problems_report_errors_caps_and_audit_violations() {
        let list = task_list(0);
        let mut census = blank();
        census.errors.push(anyhow!("the walk broke at 0x1000"));
        census.capped.deep = 1;
        // An owner off the list, which the audit flags.
        census.held.push(a_held(0, 0x2000));
        let problems = testkit::healthy_problems(&census, &list);
        assert_eq!(problems.len(), 3, "{problems:#?}");
        assert!(
            problems[0].contains("census error: the walk broke at 0x1000"),
            "{problems:#?}"
        );
        assert!(
            problems[1].contains("the walk hit a hard limit"),
            "{problems:#?}"
        );
        assert!(problems[2].contains("healthy-only audit:"), "{problems:#?}");
    }

    /// The registry ladder reports each missing rung as a problem —
    /// absent, unparseable, empty — and a present registry's problems
    /// are the diff's, verbatim.
    #[test]
    fn test_registry_problems_name_each_missing_rung() {
        use crate::testkit::fake::{FakeTarget, registry};

        let list = task_list(0);
        let census = blank();
        let target = |bytes: Vec<u8>, has_symbol: bool| FakeTarget {
            base: 0x1000,
            bytes,
            has_symbol,
            seam: None,
        };

        let absent = target(registry(&[]), false);
        assert_eq!(
            testkit::expect::problems(&absent, names(), &census, &list),
            ["the capture carries no census registry symbol"]
        );

        let unparseable = target(registry(&[(9, 0, 0, "")]), true);
        let problems = testkit::expect::problems(&unparseable, names(), &census, &list);
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(
            problems[0].contains("the registry does not parse:"),
            "{problems:#?}"
        );

        let empty = target(registry(&[]), true);
        assert_eq!(
            testkit::expect::problems(&empty, names(), &census, &list),
            ["the registry is empty; every registering fixture registers"]
        );

        let registered = target(registry(&[(5, 0, 0, "task_name")]), true);
        let problems = testkit::expect::problems(&registered, names(), &census, &list);
        assert_eq!(
            problems,
            ["1 task(s) registered as `task_name`, but the listing shows 0"]
        );
    }

    /// The `Run` methods report what the shared primitives see. The
    /// suites over healthy pairs only ever show them empty, so a
    /// doctored census is what pins the delegation itself.
    #[test]
    fn test_a_run_reports_problems_through_its_methods() {
        let (bundle, snapshot) = testkit::load_any("simple-await");
        let mut r = testkit::run(&bundle, &snapshot);
        r.census.errors.push(anyhow!("the walk broke at 0xf00d"));
        // A held row the fixture never registered: a fabrication the
        // registry diff must flag.
        r.census.held.push(a_held(0, 0xf00d));
        let healthy = r.healthy_problems();
        assert!(
            healthy
                .iter()
                .any(|p| p.contains("census error: the walk broke at 0xf00d")),
            "{healthy:#?}"
        );
        let registry_problems = r.registry_problems();
        assert!(
            registry_problems
                .iter()
                .any(|p| p.contains("unregistered held find")),
            "{registry_problems:#?}"
        );
    }
}

#[cfg(test)]
mod fanout_tests {
    use super::*;
    use crate::testkit::heap::FakeHeap;
    use crate::testkit::{self, load_any};
    use crate::tokio::bundle::{FutureInfo, Task};

    use proc::snapshot::Snapshot;

    fn mapper_map<'b>(ctx: &Context<'b, Snapshot>, list: &TaskList) -> Value<'b> {
        let task: &Task = list
            .tasks
            .iter()
            .find(
                |t| matches!(&t.future, FutureInfo::Known(k) if k.name(ctx.view).contains("mapper")),
            )
            .expect("the fixture lists the mapper");
        testkit::frame_local(ctx, task, "mapper", "map")
    }

    /// The map's entries are its three streams in order, every one
    /// under the cap; exactly the cap lists them all and stops nothing;
    /// past the cap the walk stops after `max` and says so. The member
    /// the entries are held in is the one the route names.
    #[test]
    fn test_the_map_walk_hands_over_each_entry_up_to_the_cap() {
        let (bundle, snapshot) = load_any("watch-stream");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let map = mapper_map(&ctx, &list);
        let read = ReadContext::none();
        let mut seen: Vec<(usize, String)> = Vec::new();
        let total = walk_fanout_entries(&ctx, &read, map, MAX_CHILDREN, &mut |i, _, v| {
            seen.push((i, v.ty.name().to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(total, 3);
        assert_eq!(seen.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0, 1, 2]);
        assert!(
            seen.iter()
                .all(|(_, n)| n.starts_with("tokio_stream::wrappers::watch::WatchStream<")),
            "{seen:?}"
        );
        let mut n = 0;
        let total = walk_fanout_entries(&ctx, &read, map, 3, &mut |_, _, _| {
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((total, n), (3, 3));
        let mut n = 0;
        let stop = walk_fanout_entries(&ctx, &read, map, 2, &mut |_, _, _| {
            n += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(
                stop,
                NodeStop::Capped {
                    unit: "entries",
                    max: 2
                }
            ),
            "{stop}"
        );
        assert_eq!(n, 2);
        assert_eq!(ctx.fanout_storage_name(), "entries");
    }

    /// The entries buffer is one allocation, held to the allocator's
    /// word before any entry is read: freed, the walk refuses it; a
    /// block shorter than the three entries refuses it as outside its
    /// allocation; a block covering exactly the three admits it.
    #[test]
    fn test_the_map_walk_holds_the_buffer_to_the_allocator() {
        let (bundle, snapshot) = load_any("watch-stream");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let map = mapper_map(&ctx, &list);
        let entries = ctx.walk(WalkRole::StreamMapEntries).walk_at(map).unwrap();
        let elements = entries.elements(ctx.proc).unwrap();
        let base = elements.get(0).addr;
        let stride = elements.element_ty().size();
        assert!(stride > 0 && elements.len() == 3);
        let walk = |heap: &FakeHeap| {
            let mut n = 0;
            let outcome = walk_fanout_entries(
                &ctx,
                &ReadContext::with_heap(heap),
                map,
                MAX_CHILDREN,
                &mut |_, _, _| {
                    n += 1;
                    Ok(())
                },
            );
            (outcome, n)
        };
        let (freed, n) = walk(&FakeHeap::new().freed(base..base + 3 * stride));
        assert!(
            matches!(
                freed,
                Err(NodeStop::Refused {
                    refusal: Refusal::Freed { .. },
                    ..
                })
            ),
            "{freed:?}"
        );
        assert_eq!(n, 0);
        let (short, n) = walk(&FakeHeap::new().live(base..base + 2 * stride));
        assert!(
            matches!(
                short,
                Err(NodeStop::Refused {
                    refusal: Refusal::OutsideAllocation { .. },
                    ..
                })
            ),
            "{short:?}"
        );
        assert_eq!(n, 0);
        let (whole, n) = walk(&FakeHeap::new().live(base..base + 3 * stride));
        assert!(matches!(whole, Ok(3)), "{whole:?}");
        assert_eq!(n, 3);
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;
    use crate::testkit::heap::FakeHeap;
    use crate::testkit::{self, load_any};
    use crate::tokio::bundle::{FutureInfo, Task};
    use crate::tokio::contract;

    use proc::snapshot::Snapshot;

    /// `unordered`'s driver task, and the map it keeps two futures in.
    fn keyed<'b>(ctx: &Context<'b, Snapshot>, list: &'b TaskList) -> (&'b Task, Value<'b>) {
        let task: &Task = list
            .tasks
            .iter()
            .find(
                |t| matches!(&t.future, FutureInfo::Known(k) if k.name(ctx.view).contains("driver")),
            )
            .expect("the fixture lists the driver");
        (task, testkit::frame_local(ctx, task, "driver", "keyed"))
    }

    /// A word of the table, read by its binding's route.
    fn word(ctx: &Context<'_, Snapshot>, map: Value<'_>, path: &hansei_bundle::TypedPath) -> u64 {
        contract::execute_steps(ctx, &ReadContext::none(), map, &path.steps)
            .unwrap()
            .optional()
            .unwrap()
            .parse(ctx.proc)
            .unwrap()
    }

    /// The table's two full buckets are the driver's two futures, each
    /// a `(u32, F)` whose value is the leaf future, handed over in
    /// bucket order; exactly two is under the cap and past it the walk
    /// stops and says so. The map binds because its bucket could hold
    /// a find; one of plain data would not be walked at all.
    #[test]
    fn test_the_table_walk_hands_over_each_full_bucket() {
        let (bundle, snapshot) = load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let (_, map) = keyed(&ctx, &list);
        let table = ctx
            .scanned_table(map.ty.id())
            .expect("the map binds its table");
        let read = ReadContext::none();
        let mut seen: Vec<(usize, u64, String)> = Vec::new();
        let count = walk_table_buckets(&ctx, &read, map, table, MAX_CHILDREN, &mut |i, b| {
            seen.push((i, b.addr, b.ty.name().to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(count, TableCount { items: 2, full: 2 });
        assert_eq!(seen.iter().map(|(i, ..)| *i).collect::<Vec<_>>(), [0, 1]);
        assert!(
            seen.iter()
                .all(|(.., name)| name == "(u32, unordered::leaf::{async_fn_env#0})"),
            "{seen:?}"
        );
        // In bucket order, which puts each lower than the last: bucket
        // `i` ends `i` buckets below the control bytes.
        assert!(seen[0].1 > seen[1].1, "{seen:?}");
        let mut n = 0;
        let stop = walk_table_buckets(&ctx, &read, map, table, 1, &mut |_, _| {
            n += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(
                stop,
                NodeStop::Capped {
                    unit: "buckets",
                    max: 1
                }
            ),
            "{stop}"
        );
        assert_eq!(n, 1);
    }

    /// The buckets and their control bytes are one allocation, held to
    /// the allocator's word before any bucket is read: freed, the walk
    /// refuses it; a block ending short of the last control byte refuses
    /// it as outside its allocation; one holding the buckets and every
    /// control byte admits it.
    #[test]
    fn test_the_table_walk_holds_the_table_to_the_allocator() {
        let (bundle, snapshot) = load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let (_, map) = keyed(&ctx, &list);
        let table = ctx
            .scanned_table(map.ty.id())
            .expect("the map binds its table");
        let ctrl = word(&ctx, map, &table.ctrl);
        let buckets = word(&ctx, map, &table.bucket_mask) + 1;
        let stride = ctx.view.ty(table.bucket).unwrap().size();
        let base = ctrl - buckets * stride;
        let walk = |heap: &FakeHeap| {
            let mut n = 0;
            let outcome = walk_table_buckets(
                &ctx,
                &ReadContext::with_heap(heap),
                map,
                table,
                MAX_CHILDREN,
                &mut |_, _| {
                    n += 1;
                    Ok(())
                },
            );
            (outcome, n)
        };
        let (freed, n) = walk(&FakeHeap::new().freed(base..ctrl + buckets));
        assert!(
            matches!(
                freed,
                Err(NodeStop::Refused {
                    refusal: Refusal::Freed { .. },
                    ..
                })
            ),
            "{freed:?}"
        );
        assert_eq!(n, 0);
        let (short, n) = walk(&FakeHeap::new().live(base..ctrl + buckets - 1));
        assert!(
            matches!(
                short,
                Err(NodeStop::Refused {
                    refusal: Refusal::OutsideAllocation { .. },
                    ..
                })
            ),
            "{short:?}"
        );
        assert_eq!(n, 0);
        let (whole, n) = walk(&FakeHeap::new().live(base..ctrl + buckets));
        assert!(
            matches!(whole, Ok(TableCount { items: 2, full: 2 })),
            "{whole:?}"
        );
        assert_eq!(n, 2);
    }

    /// The census finds what the map holds as the driver's own, at the
    /// map's local and the entry's place among the full buckets.
    #[test]
    fn test_the_census_finds_the_futures_a_map_holds() {
        let (bundle, snapshot) = load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = census(&ctx, &list);
        let mut locals: Vec<&str> = census
            .held
            .iter()
            .map(|h| h.local.as_str())
            .filter(|local| local.starts_with("keyed"))
            .collect();
        locals.sort();
        assert_eq!(locals, ["keyed[0]", "keyed[1]"], "{:?}", census.errors);
        assert!(census.errors.is_empty(), "{:?}", census.errors);
    }

    /// A map whose item count its full buckets do not bear out — a core
    /// taken halfway through an insert — is reported, and what its full
    /// buckets hold is still found: the control bytes are what say
    /// where the entries are, and the count is only checked against
    /// them.
    #[test]
    fn test_a_table_whose_count_disagrees_is_reported() {
        let (bundle, snapshot) = load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let (_, map) = keyed(&ctx, &list);
        let table = ctx
            .scanned_table(map.ty.id())
            .expect("the map binds its table");
        let items = contract::execute_steps(&ctx, &ReadContext::none(), map, &table.items.steps)
            .unwrap()
            .optional()
            .unwrap();
        let cut = testkit::corrupt::Corrupt::new(&snapshot).patch(items.addr, 3);
        let ctx = Context::new(&cut, hansei_bundle::BundleView::new(&bundle)).unwrap();
        let census = census(&ctx, &list);
        let reports: Vec<String> = census.errors.iter().map(|e| format!("{e:#}")).collect();
        assert!(
            reports
                .iter()
                .any(|r| r.contains(&format!("{:#x} counts 3 items, and 2", map.addr))),
            "{reports:#?}"
        );
        let keyed = census
            .held
            .iter()
            .filter(|h| h.local.starts_with("keyed"))
            .count();
        assert_eq!(keyed, 2, "{:#?}", census.held);
    }

    /// A table holds at most one item per bucket: a count past the
    /// bucket count is no table's, and the walk refuses it before it
    /// reads a bucket; a count of every bucket is a full table, walked.
    #[test]
    fn test_the_table_walk_refuses_more_items_than_buckets() {
        let (bundle, snapshot) = load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let (_, map) = keyed(&ctx, &list);
        let table = ctx
            .scanned_table(map.ty.id())
            .expect("the map binds its table");
        let buckets = word(&ctx, map, &table.bucket_mask) + 1;
        let items = contract::execute_steps(&ctx, &ReadContext::none(), map, &table.items.steps)
            .unwrap()
            .optional()
            .unwrap();
        let walk = |count: u64| {
            let cut = testkit::corrupt::Corrupt::new(&snapshot).patch(items.addr, count);
            let ctx = Context::new(&cut, hansei_bundle::BundleView::new(&bundle)).unwrap();
            let map = Value::read(ctx.proc, map.ty, map.addr).unwrap();
            let mut n = 0;
            let outcome = walk_table_buckets(
                &ctx,
                &ReadContext::none(),
                map,
                table,
                MAX_CHILDREN,
                &mut |_, _| {
                    n += 1;
                    Ok(())
                },
            )
            .map_err(|stop| stop.to_string());
            (outcome, n)
        };
        let (over, n) = walk(buckets + 1);
        let over = over.unwrap_err();
        assert!(
            over.contains(&format!(
                "claims {} items in {buckets} buckets",
                buckets + 1
            )),
            "{over}"
        );
        assert_eq!(n, 0);
        let (full, n) = walk(buckets);
        assert_eq!(
            full,
            Ok(TableCount {
                items: buckets,
                full: 2
            })
        );
        assert_eq!(n, 2);
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The reachability index: every heap allocation the value walk can reach
//! from the futures the census enumerates, with the path that reached it.
//!
//! Where the census scans frames *by value* for futures, this walk follows
//! pointers: plain pointers (which cover `Box`, `Arc` → `ArcInner`,
//! `NonNull`, references), slice and string buffers through their `Slice`/
//! `Str` display programs, and trait objects through the vtable join. Each
//! dereference target becomes one record — `(start..end, type, the step
//! that reached it)` — and a query that lands inside an extent is answered
//! with the full path from a task's own frames down to it.
//!
//! What the walk deliberately does not do:
//!
//! - **By-value interiors are not recorded.** A member of a recorded extent
//!   is found at answer time by offset math against the recorded type.
//! - **Pointers into task allocations are not followed.** A `JoinHandle`'s
//!   or a `Waker`'s pointer lands in another task's allocation, which the
//!   task-extent join already claims; following it would attribute one
//!   task's insides to whichever other task holds a handle to it.
//! - **Unions (so `MaybeUninit`) and inactive enum variants are not
//!   descended**, for the census's reason: their bytes are dead storage,
//!   and a pointer misread out of them would record garbage. This is also
//!   why a `BTreeMap`'s node contents stay unreached: the node arrays are
//!   `MaybeUninit`. The node allocations themselves are reached.
//! - **First path wins.** A shared `Arc` dedups on `(address, type)`; the
//!   recorded path is the first one the walk took, which is stable because
//!   roots are walked in task order.
//!
//! A miss is therefore a lower bound, the same contract the census states:
//! "not reached" never means "not owned", and [`ReachIndex::capped`] says
//! when raising a bound could find more.

use super::bundle::{Context, TaskExtents, TaskList, TaskStage};
use super::census::{FutureCensus, is_own_local};
use super::model::AwaitChain;

use hansei_bundle::{BundleType, BundleTypeId, DisplayNode, TypeClass};
use proc::Target;
use reify::Value;

use foldhash::{HashMap, HashSet};

use std::fmt::Write as _;

/// How deep the walk descends by default: one level per member, element,
/// or dereference, the way the renderer counts depth. The register that
/// motivated this index sat sixteen levels into its task's future graph,
/// so the default is generous rather than render-sized.
const MAX_REACH_DEPTH: usize = 64;

/// How many extents the index records before declaring itself incomplete.
const MAX_REACH_RECORDS: usize = 1 << 20;

/// How many elements of one sequence the walk descends into. The buffer's
/// whole extent is recorded regardless; this bounds only the search for
/// pointers *inside* the elements.
const MAX_SEQ_ELEMENTS: u64 = 4096;

/// Where the walk's hard limits sit, as values rather than the constants:
/// a caller told the walk stopped can move the limit that stopped it and
/// ask again.
#[derive(Debug, Clone, Copy)]
pub struct ReachBounds {
    /// Depth of one walk, counted per member, element and dereference.
    pub depth: usize,
    /// Total extents recorded across the index.
    pub max_records: usize,
    /// Elements of one sequence descended into.
    pub max_elements: u64,
}

impl Default for ReachBounds {
    fn default() -> Self {
        ReachBounds {
            depth: MAX_REACH_DEPTH,
            max_records: MAX_REACH_RECORDS,
            max_elements: MAX_SEQ_ELEMENTS,
        }
    }
}

/// Honesty counters: each is a place the walk stopped short of what more
/// budget would have reached.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReachCapped {
    /// Subtrees cut off at [`ReachBounds::depth`].
    pub deep: usize,
    /// Sequences whose tail elements were not descended into — the
    /// element bound, or a buffer the target served short.
    pub elements: usize,
    /// The record cap was hit and the index is incomplete from there on.
    pub records: bool,
}

impl ReachCapped {
    /// Whether any limit cut the walk short — the "raising a bound could
    /// find more" signal a miss should carry.
    pub fn any(&self) -> bool {
        self.deep > 0 || self.elements > 0 || self.records
    }
}

/// Walk accounting, for the audit trail and the tests that pin behavior.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReachStats {
    /// Chains walked as roots.
    pub roots: usize,
    /// Pointer targets already recorded under an earlier path.
    pub dedup_hits: usize,
    /// Pointer targets inside a task allocation, left to the extent join.
    pub task_hits: usize,
    /// Edges that degraded: an unreadable target, an invalid sequence
    /// header, a vtable that resolved to nothing.
    pub degraded: usize,
}

/// What one recorded extent holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentKind {
    /// One value of the record's type at `start`.
    Value,
    /// A contiguous buffer of the record's (element) type, `stride` bytes
    /// apart — a `Vec`'s or slice's allocation.
    Buffer {
        /// Bytes between successive elements.
        stride: u64,
    },
    /// The UTF-8 bytes of a string-shaped value; the record's type is the
    /// owner (`String`, `&str`), not the bytes'.
    Bytes,
}

/// One chain the walk rooted at: the task that owns it and how it was
/// reached when it is not the task's own (`held #N`, `set #S child #C`).
#[derive(Debug)]
pub struct ReachRoot {
    /// Index into the walked [`TaskList`].
    pub owner: usize,
    /// How the chain was reached; empty for the task's own chain.
    pub via: String,
}

/// One dereference target the walk recorded.
#[derive(Debug)]
pub struct ReachRecord {
    pub start: u64,
    pub end: u64,
    /// The type `start` holds — the element type for a
    /// [`ExtentKind::Buffer`], the owning string type for
    /// [`ExtentKind::Bytes`].
    pub ty: BundleTypeId,
    pub kind: ExtentKind,
    /// Index into [`ReachIndex`]'s roots.
    root: u32,
    /// The record whose walk found this one; `None` when it was reached
    /// straight from the root chain's own bytes.
    parent: Option<u32>,
    /// The member path from the parent record (or from the root's frame
    /// local, spelled `#<frame> <local>…`) to the value that pointed here.
    step: String,
}

/// One containing extent, answered for an address: the record, the offset
/// into it, the root it was reached from, and the steps between.
#[derive(Debug)]
pub struct ReachHit<'i> {
    pub record: &'i ReachRecord,
    /// The queried address's offset into the record.
    pub offset: u64,
    pub root: &'i ReachRoot,
    /// The step strings from the root to the record, in walk order. The
    /// first names a frame and local (`#2 conn`); the rest are member
    /// paths, one per dereference on the way.
    pub path: Vec<&'i str>,
}

/// The finished index; build one with [`reach_index`].
#[derive(Debug)]
pub struct ReachIndex {
    roots: Vec<ReachRoot>,
    records: Vec<ReachRecord>,
    /// Record indices sorted by `(start, end)`, for [`ReachIndex::locate`].
    by_start: Vec<u32>,
    /// The longest recorded extent, bounding locate's backward scan.
    max_len: u64,
    /// The bounds the walk ran under, for spelling "raise the knob".
    pub bounds: ReachBounds,
    pub capped: ReachCapped,
    pub stats: ReachStats,
}

impl ReachIndex {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Every recorded extent, in discovery order.
    pub fn records(&self) -> impl Iterator<Item = &ReachRecord> {
        self.records.iter()
    }

    /// The path from the root to `record`, outermost step first.
    fn path_to<'i>(&'i self, record: &'i ReachRecord) -> Vec<&'i str> {
        let mut steps = vec![record.step.as_str()];
        let mut cur = record.parent;
        while let Some(index) = cur {
            let parent = &self.records[index as usize];
            steps.push(parent.step.as_str());
            cur = parent.parent;
        }
        steps.reverse();
        steps
    }

    /// The most specific recorded extent containing `addr`: the smallest,
    /// and the earliest-recorded among equals — extents overlap only when
    /// two pointers alias into one allocation.
    pub fn locate(&self, addr: u64) -> Option<ReachHit<'_>> {
        let candidates = self
            .by_start
            .partition_point(|&index| self.records[index as usize].start <= addr);
        let mut best: Option<u32> = None;
        for &index in self.by_start[..candidates].iter().rev() {
            let record = &self.records[index as usize];
            // Sorted by start: once even the longest extent starting here
            // could not reach `addr`, no earlier start can either.
            if record.start.saturating_add(self.max_len) <= addr {
                break;
            }
            if record.end <= addr {
                continue;
            }
            best = match best {
                None => Some(index),
                Some(prev) => {
                    let p = &self.records[prev as usize];
                    let smaller = (record.end - record.start, index);
                    if smaller < (p.end - p.start, prev) {
                        Some(index)
                    } else {
                        Some(prev)
                    }
                }
            };
        }
        let record = &self.records[best? as usize];
        Some(ReachHit {
            record,
            offset: addr - record.start,
            root: &self.roots[record.root as usize],
            path: self.path_to(record),
        })
    }
}

/// Build the index: walk every chain the census enumerates — each running
/// task's own, each held future's, each set child's — recording every
/// dereference target. Order is task order, then the census's own held and
/// set-child order, which is what makes first-path-wins stable.
pub fn reach_index<T: Target>(
    ctx: &Context<'_, T>,
    list: &TaskList,
    census: &FutureCensus,
    extents: &TaskExtents,
    bounds: ReachBounds,
) -> ReachIndex {
    let mut walker = Walker::new(ctx.proc, extents, bounds);

    for (owner, task) in list.tasks.iter().enumerate() {
        let Ok(TaskStage::Running(root)) = ctx.task_stage(task) else {
            continue;
        };
        let chain = ctx.await_chain(root);
        walker.walk_chain(owner, String::new(), &chain);
    }
    // Held futures and set children are mostly reached from the task
    // chains above already (a held future's storage is a frame local or
    // sits behind a pointer the walk followed), so most of their edges
    // land as dedup hits — but each re-rooted chain starts a fresh depth
    // budget, which is what carries a deep target's coverage past the
    // depth its own task's walk ran out at.
    for (index, held) in census.held.iter().enumerate() {
        let Some(ty) = ctx.view.ty(held.ty) else {
            continue;
        };
        let Ok(root) = Value::read(ctx.proc, ty, held.addr) else {
            continue;
        };
        let chain = ctx.await_chain(root);
        walker.walk_chain(held.owner, format!("held #{index}"), &chain);
    }
    for (set_index, set) in census.sets.iter().enumerate() {
        for (child_index, child) in set.children.iter().enumerate() {
            let Some(root) = &child.root else {
                continue;
            };
            let Some(ty) = ctx.view.ty(root.ty) else {
                continue;
            };
            let Ok(value) = Value::read(ctx.proc, ty, root.addr) else {
                continue;
            };
            let chain = ctx.await_chain(value);
            walker.walk_chain(
                set.owner,
                format!("set #{set_index} child #{child_index}"),
                &chain,
            );
        }
    }
    walker.finish()
}

/// What the walk does at a value of one type — decided once per type and
/// remembered, the census [`ScanPlan`](super::census) precedent: the walk
/// visits millions of values but only thousands of distinct types.
#[derive(Clone)]
enum Route<'b> {
    /// A string-shaped value: record its byte buffer.
    Str,
    /// A sequence: record its buffer, walk its elements.
    Slice,
    /// A trait object: follow through the vtable join.
    Dyn,
    /// A pointer to a sized target: follow it.
    Pointer(BundleType<'b>),
    /// A struct: recurse into the sized members that can reach an edge —
    /// members whose types provably hold none are pruned here, so a tree
    /// of scalars costs one route lookup instead of a walk.
    Members(std::rc::Rc<Vec<MemberStep<'b>>>),
    /// A Rust enum whose variants can reach an edge: recurse into the
    /// active variant's payload.
    Enum,
    /// An inline array of edge-bearing elements.
    Array { element: BundleType<'b>, count: u64 },
    /// Nothing here can dereference anything.
    Stop,
}

/// One precomputed struct-member descent.
struct MemberStep<'b> {
    ty: BundleType<'b>,
    offset: u64,
    size: u64,
    name: &'b str,
}

/// The walk's running state.
struct Walker<'a, 'b, T> {
    proc: &'b T,
    extents: &'a TaskExtents,
    bounds: ReachBounds,
    roots: Vec<ReachRoot>,
    records: Vec<ReachRecord>,
    /// Every dereference target, by `(address, type id)`: permanent, so a
    /// shared allocation is recorded under its first path only.
    visited: HashSet<(u64, BundleTypeId)>,
    /// [`Route`] per type.
    routes: HashMap<BundleTypeId, Route<'b>>,
    /// Whether a type can transitively reach a dereference, for the
    /// route pruning. Computed over by-value structure only — pointers
    /// answer without recursing — so it terminates on any sized type
    /// graph.
    edges: HashMap<BundleTypeId, bool>,
    /// reify-side memos: resolved display nodes per type, the dyn join
    /// per vtable address.
    cache: reify::WalkCache<'b>,
    capped: ReachCapped,
    stats: ReachStats,
}

impl<'a, 'b, T: Target> Walker<'a, 'b, T> {
    fn new(proc: &'b T, extents: &'a TaskExtents, bounds: ReachBounds) -> Self {
        Walker {
            proc,
            extents,
            bounds,
            roots: Vec::new(),
            records: Vec::new(),
            visited: HashSet::default(),
            routes: HashMap::default(),
            edges: HashMap::default(),
            cache: reify::WalkCache::new(),
            capped: ReachCapped::default(),
            stats: ReachStats::default(),
        }
    }

    /// The memoized [`Route`] for `ty`.
    fn route(&mut self, ty: BundleType<'b>) -> Route<'b> {
        if let Some(route) = self.routes.get(&ty.id()) {
            return route.clone();
        }
        let route = self.compute_route(ty);
        self.routes.insert(ty.id(), route.clone());
        route
    }

    fn compute_route(&mut self, ty: BundleType<'b>) -> Route<'b> {
        match ty.debug_format() {
            Some(DisplayNode::Str { .. }) => return Route::Str,
            Some(DisplayNode::Slice { .. }) => return Route::Slice,
            Some(DisplayNode::DynPointer { .. }) => return Route::Dyn,
            _ => {}
        }
        match ty.classify() {
            TypeClass::Pointer { target } if target.size() > 0 => Route::Pointer(target),
            TypeClass::Struct => {
                let members: Vec<MemberStep<'b>> = ty
                    .members()
                    .filter(|m| m.ty().size() > 0)
                    .filter(|m| self.has_edges(m.ty()))
                    .map(|m| MemberStep {
                        ty: m.ty(),
                        offset: m.offset(),
                        size: m.ty().size(),
                        name: m.name(),
                    })
                    .collect();
                match members.is_empty() {
                    true => Route::Stop,
                    false => Route::Members(std::rc::Rc::new(members)),
                }
            }
            TypeClass::RustEnum if self.has_edges(ty) => Route::Enum,
            TypeClass::Array { element, count }
                if element.size() > 0 && self.has_edges(element) =>
            {
                Route::Array { element, count }
            }
            // Unions are the same storage read as different types, at
            // most one of them live; scalars hold no edges.
            _ => Route::Stop,
        }
    }

    /// Whether walking a value of `ty` could ever dereference something.
    /// Recurses over by-value structure only — a pointer answers `true`
    /// without following — with an in-progress entry answering `false`,
    /// which is the fixpoint for a pure by-value cycle: one that holds a
    /// pointer anywhere answers `true` before the cycle closes.
    fn has_edges(&mut self, ty: BundleType<'b>) -> bool {
        let id = ty.id();
        if let Some(&edges) = self.edges.get(&id) {
            return edges;
        }
        self.edges.insert(id, false);
        let edges = match ty.debug_format() {
            Some(
                DisplayNode::Str { .. }
                | DisplayNode::Slice { .. }
                | DisplayNode::DynPointer { .. },
            ) => true,
            _ => match ty.classify() {
                TypeClass::Pointer { target } => target.size() > 0,
                TypeClass::Struct => {
                    let members: Vec<BundleType<'b>> = ty
                        .members()
                        .map(|m| m.ty())
                        .filter(|t| t.size() > 0)
                        .collect();
                    members.into_iter().any(|t| self.has_edges(t))
                }
                TypeClass::RustEnum => match ty.variant_shape() {
                    Some(shape) => {
                        let payloads: Vec<BundleType<'b>> = shape
                            .variants
                            .iter()
                            .map(|v| ty.related_type(v.payload.ty))
                            .filter(|t| t.size() > 0)
                            .collect();
                        payloads.into_iter().any(|t| self.has_edges(t))
                    }
                    None => false,
                },
                TypeClass::Array { element, .. } => element.size() > 0 && self.has_edges(element),
                _ => false,
            },
        };
        self.edges.insert(id, edges);
        edges
    }

    /// Register a chain as a root and walk every frame's own locals, the
    /// member filter the census scan uses: `__…` slots and the frame's
    /// inner future are the next frame, walked as itself.
    fn walk_chain(&mut self, owner: usize, via: String, chain: &AwaitChain<'b>) {
        let root = self.begin_root(owner, via);
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
                let Some(bytes) = payload.bytes.get(start..start + m.ty().size() as usize) else {
                    continue;
                };
                let local = Value::new(m.ty(), payload.addr + m.offset(), bytes);
                let mut path = format!("#{frame_index} {}", m.name());
                self.walk_value(local, 0, root, None, &mut path);
            }
        }
    }

    fn begin_root(&mut self, owner: usize, via: String) -> u32 {
        let index = self.roots.len() as u32;
        self.roots.push(ReachRoot { owner, via });
        self.stats.roots += 1;
        index
    }

    /// Walk one value by its type's [`Route`]: string, slice and
    /// trait-object shapes go through their display programs — which
    /// replace structural descent, as they do in the renderer — and
    /// everything else structurally.
    fn walk_value(
        &mut self,
        value: Value<'b>,
        depth: usize,
        root: u32,
        parent: Option<u32>,
        path: &mut String,
    ) {
        if self.capped.records {
            return;
        }
        if depth >= self.bounds.depth {
            self.capped.deep += 1;
            return;
        }
        if (value.bytes.len() as u64) < value.ty.size() {
            return;
        }
        match self.route(value.ty) {
            Route::Stop => {}
            Route::Str => self.walk_str(value, root, parent, path),
            Route::Slice => self.walk_slice(value, depth, root, parent, path),
            Route::Dyn => self.walk_dyn(value, depth, root, parent, path),
            Route::Pointer(target) => {
                let Some(&word) = value.bytes.first_chunk::<8>() else {
                    return;
                };
                let addr = u64::from_le_bytes(word);
                if addr == 0 {
                    return;
                }
                self.follow(addr, target, depth, root, parent, path);
            }
            Route::Members(members) => {
                for m in members.iter() {
                    let start = m.offset as usize;
                    let Some(bytes) = value.bytes.get(start..start + m.size as usize) else {
                        continue;
                    };
                    let child = Value::new(m.ty, value.addr + m.offset, bytes);
                    let len = path.len();
                    push_member(path, m.name);
                    self.walk_value(child, depth + 1, root, parent, path);
                    path.truncate(len);
                }
            }
            Route::Enum => {
                // The raw payload, as the census scans it: only the active
                // variant's bytes are live values, and the variant struct
                // is the enum's own storage — descending into its members
                // is what costs a level.
                if let Ok((_, payload)) = value.active_variant_raw() {
                    self.walk_value(payload, depth, root, parent, path);
                }
            }
            Route::Array { element, count } => {
                let walked = count.min(self.bounds.max_elements);
                if walked < count {
                    self.capped.elements += 1;
                }
                for index in 0..walked {
                    let start = (index * element.size()) as usize;
                    let Some(bytes) = value.bytes.get(start..start + element.size() as usize)
                    else {
                        continue;
                    };
                    let child = Value::new(element, value.addr + index * element.size(), bytes);
                    let len = path.len();
                    let _ = write!(path, "[{index}]");
                    self.walk_value(child, depth + 1, root, parent, path);
                    path.truncate(len);
                }
            }
        }
    }

    /// Follow one pointer edge: record the target and walk its bytes.
    fn follow(
        &mut self,
        addr: u64,
        target: BundleType<'b>,
        depth: usize,
        root: u32,
        parent: Option<u32>,
        path: &str,
    ) {
        if self.extents.locate(addr).is_some() {
            self.stats.task_hits += 1;
            return;
        }
        if !self.visited.insert((addr, target.id())) {
            self.stats.dedup_hits += 1;
            return;
        }
        let Ok(bytes) = self.proc.read_bytes(addr, target.size()) else {
            self.stats.degraded += 1;
            return;
        };
        let Some(record) = self.record(
            addr,
            addr + target.size(),
            target.id(),
            ExtentKind::Value,
            root,
            parent,
            path,
        ) else {
            return;
        };
        let pointee = Value::new(target, addr, bytes);
        let mut sub = String::new();
        self.walk_value(pointee, depth + 1, root, Some(record), &mut sub);
    }

    /// Record a string-shaped value's byte buffer. Nothing to recurse
    /// into: the bytes are the point.
    fn walk_str(&mut self, value: Value<'b>, root: u32, parent: Option<u32>, path: &str) {
        let Ok((base, bytes, claimed)) = value.utf8_buffer_with(self.proc, &mut self.cache) else {
            self.stats.degraded += 1;
            return;
        };
        if bytes.is_empty() {
            if claimed.is_some() {
                self.stats.degraded += 1;
            }
            return;
        }
        if self.extents.locate(base).is_some() {
            self.stats.task_hits += 1;
            return;
        }
        if !self.visited.insert((base, value.ty.id())) {
            self.stats.dedup_hits += 1;
            return;
        }
        if claimed.is_some() {
            self.capped.elements += 1;
        }
        self.record(
            base,
            base + bytes.len() as u64,
            value.ty.id(),
            ExtentKind::Bytes,
            root,
            parent,
            path,
        );
    }

    /// Record a sequence's buffer and walk its elements for pointers.
    fn walk_slice(
        &mut self,
        value: Value<'b>,
        depth: usize,
        root: u32,
        parent: Option<u32>,
        path: &str,
    ) {
        let Ok(elements) = value.elements_with(self.proc, &mut self.cache) else {
            self.stats.degraded += 1;
            return;
        };
        let element = elements.element_ty();
        if elements.is_empty() || element.size() == 0 {
            return;
        }
        let base = elements.get(0).addr;
        if self.extents.locate(base).is_some() {
            self.stats.task_hits += 1;
            return;
        }
        if !self.visited.insert((base, element.id())) {
            self.stats.dedup_hits += 1;
            return;
        }
        let count = elements.len();
        let Some(record) = self.record(
            base,
            base + count * element.size(),
            element.id(),
            ExtentKind::Buffer {
                stride: element.size(),
            },
            root,
            parent,
            path,
        ) else {
            return;
        };
        let walked = count.min(self.bounds.max_elements);
        if walked < count || elements.truncated().is_some() {
            self.capped.elements += 1;
        }
        // The buffer extent stands whatever the elements hold; the
        // per-element descent only hunts for further edges, so a buffer
        // of edge-free elements (a `Vec<u16>`, a byte buffer) skips it.
        if !self.has_edges(element) {
            return;
        }
        for index in 0..walked {
            let mut sub = format!("[{index}]");
            self.walk_value(elements.get(index), depth + 1, root, Some(record), &mut sub);
        }
    }

    /// Follow a trait-object wide pointer through the vtable join. The
    /// concrete type comes from the vtable's function symbols; an
    /// unresolved or disagreeing vtable follows nothing rather than
    /// guessing.
    fn walk_dyn(
        &mut self,
        value: Value<'b>,
        depth: usize,
        root: u32,
        parent: Option<u32>,
        path: &str,
    ) {
        let Some((concrete, addr)) = value.dyn_pointee_with(self.proc, &mut self.cache) else {
            self.stats.degraded += 1;
            return;
        };
        self.follow(addr, concrete, depth, root, parent, path);
    }

    /// Append one record, or trip the cap and record nothing more.
    #[expect(clippy::too_many_arguments, reason = "internal builder")]
    fn record(
        &mut self,
        start: u64,
        end: u64,
        ty: BundleTypeId,
        kind: ExtentKind,
        root: u32,
        parent: Option<u32>,
        step: &str,
    ) -> Option<u32> {
        if self.records.len() >= self.bounds.max_records {
            self.capped.records = true;
            return None;
        }
        let index = self.records.len() as u32;
        self.records.push(ReachRecord {
            start,
            end,
            ty,
            kind,
            root,
            parent,
            step: step.to_string(),
        });
        Some(index)
    }

    fn finish(self) -> ReachIndex {
        let mut by_start: Vec<u32> = (0..self.records.len() as u32).collect();
        by_start.sort_unstable_by_key(|&index| {
            let record = &self.records[index as usize];
            (record.start, record.end, index)
        });
        let max_len = self
            .records
            .iter()
            .map(|record| record.end - record.start)
            .max()
            .unwrap_or(0);
        ReachIndex {
            roots: self.roots,
            records: self.records,
            by_start,
            max_len,
            bounds: self.bounds,
            capped: self.capped,
            stats: self.stats,
        }
    }
}

/// Append one member step: `a` then `.b`, so a path reads `a.b[3].c`.
fn push_member(path: &mut String, name: &str) {
    if !path.is_empty() {
        path.push('.');
    }
    path.push_str(name);
}

#[cfg(test)]
mod tests {
    use super::{ExtentKind, ReachBounds, ReachIndex, Walker};
    use crate::tokio::bundle::TaskExtents;

    use hansei_bundle::{Bundle, BundleView, DisplayNode, TypeDef};
    use reify::Value;
    use reify::testhelper::{
        BIG, FAT_PTR, FakeMem, MSG, NODE, NODE_PTR, POINT, PTR, STRING, U32, VEC, VTABLE_ARRAY,
        node_bytes, sel, test_bundle, u32s, u64s,
    };

    /// Walk one root local against `mem` under `bounds`, the way a chain
    /// frame's local is walked, and return the finished index.
    fn walk(
        bundle: &Bundle,
        mem: &FakeMem,
        spans: Vec<(u64, u64, usize)>,
        bounds: ReachBounds,
        roots: &[(hansei_bundle::BundleTypeId, u64, &str)],
    ) -> ReachIndex {
        let view = BundleView::new(bundle);
        let extents = TaskExtents { spans };
        let mut walker = Walker::new(mem, &extents, bounds);
        for &(ty, addr, local) in roots {
            let root = walker.begin_root(0, String::new());
            let value = Value::read(mem, view.ty(ty).unwrap(), addr).expect("root value reads");
            let mut path = format!("#0 {local}");
            walker.walk_value(value, 0, root, None, &mut path);
        }
        walker.finish()
    }

    fn defaults() -> ReachBounds {
        ReachBounds::default()
    }

    /// A pointer chain records one extent per hop, each hop's step naming
    /// the member that pointed there, and a landing inside a later hop
    /// answers with the whole path. The root's own bytes are frame-local,
    /// not an extent.
    #[test]
    fn test_a_pointer_chain_records_each_hop_with_its_path() {
        let b = test_bundle();
        let mem = FakeMem::new()
            .at(0x1000, node_bytes(1, 0x2000))
            .at(0x2000, node_bytes(2, 0x3000))
            .at(0x3000, node_bytes(3, 0));
        let index = walk(&b, &mem, vec![], defaults(), &[(NODE, 0x1000, "n")]);

        assert_eq!(index.len(), 2);
        let hit = index.locate(0x3004).expect("the second hop is indexed");
        assert_eq!(hit.record.ty, NODE);
        assert_eq!(hit.record.kind, ExtentKind::Value);
        assert_eq!((hit.record.start, hit.record.end), (0x3000, 0x3010));
        assert_eq!(hit.offset, 4);
        assert_eq!(hit.path, ["#0 n.next", "next"]);
        assert_eq!((hit.root.owner, hit.root.via.as_str()), (0, ""));
        assert!(index.locate(0x1004).is_none(), "the root is not an extent");
        assert!(!index.capped.any());
    }

    /// A target two paths reach is recorded once, under the first path —
    /// which is what keeps shared `Arc`s one row and the walk stable.
    #[test]
    fn test_a_shared_target_keeps_its_first_path() {
        let b = test_bundle();
        let mem = FakeMem::new()
            .at(0x1000, node_bytes(1, 0x3000))
            .at(0x2000, node_bytes(2, 0x3000))
            .at(0x3000, node_bytes(3, 0));
        let index = walk(
            &b,
            &mem,
            vec![],
            defaults(),
            &[(NODE, 0x1000, "a"), (NODE, 0x2000, "b")],
        );

        assert_eq!(index.len(), 1);
        assert_eq!(index.stats.dedup_hits, 1);
        let hit = index.locate(0x3000).unwrap();
        assert_eq!(hit.path, ["#0 a.next"]);
    }

    /// A cycle terminates: the back edge lands on a visited target and
    /// dedups rather than recursing.
    #[test]
    fn test_a_cycle_terminates() {
        let b = test_bundle();
        let mem = FakeMem::new()
            .at(0x1000, node_bytes(1, 0x2000))
            .at(0x2000, node_bytes(2, 0x1000));
        let index = walk(&b, &mem, vec![], defaults(), &[(NODE, 0x1000, "n")]);

        // 0x2000 from the root, 0x1000 from 0x2000 (the root's own bytes
        // were never a dereference target), then the back edge dedups.
        assert_eq!(index.len(), 2);
        assert_eq!(index.stats.dedup_hits, 1);
    }

    /// A `Vec` records its buffer as one extent — element type, stride —
    /// and an address inside any element refines against it.
    #[test]
    fn test_a_vec_records_its_buffer() {
        let b = test_bundle();
        let mem = FakeMem::new()
            .at(0x1000, u64s(&[0x2000, 3, 4]))
            .at(0x2000, u32s(&[7, 8, 9]));
        let index = walk(&b, &mem, vec![], defaults(), &[(VEC, 0x1000, "v")]);

        assert_eq!(index.len(), 1);
        let hit = index.locate(0x2005).unwrap();
        assert_eq!((hit.record.start, hit.record.end), (0x2000, 0x200c));
        assert_eq!(hit.record.ty, U32);
        assert_eq!(hit.record.kind, ExtentKind::Buffer { stride: 4 });
        assert_eq!(hit.path, ["#0 v"]);
        assert!(index.locate(0x200c).is_none(), "the end is exclusive");
    }

    /// Elements are walked for pointers of their own: a buffer of
    /// pointers records the buffer and one extent per pointee, each
    /// pointee's step naming its element.
    #[test]
    fn test_a_buffer_of_pointers_walks_its_elements() {
        let b = slice_of_node_pointers();
        let mem = FakeMem::new()
            .at(0x1000, u64s(&[0x2000, 2, 2]))
            .at(0x2000, u64s(&[0x4000, 0x5000]))
            .at(0x4000, node_bytes(4, 0))
            .at(0x5000, node_bytes(5, 0));
        let index = walk(&b, &mem, vec![], defaults(), &[(VEC, 0x1000, "v")]);

        assert_eq!(index.len(), 3);
        let buffer = index.locate(0x2008).unwrap();
        assert_eq!(buffer.record.kind, ExtentKind::Buffer { stride: 8 });
        assert_eq!(buffer.record.ty, NODE_PTR);
        let first = index.locate(0x4000).unwrap();
        assert_eq!(first.record.ty, NODE);
        assert_eq!(first.path, ["#0 v", "[0]"]);
        let second = index.locate(0x5000).unwrap();
        assert_eq!(second.path, ["#0 v", "[1]"]);
    }

    /// A `String` records its byte buffer, typed as the owner.
    #[test]
    fn test_a_string_records_its_bytes() {
        let b = test_bundle();
        let mem = FakeMem::new()
            .at(0x1000, u64s(&[0x2000, 5, 8]))
            .at(0x2000, b"hello".to_vec());
        let index = walk(&b, &mem, vec![], defaults(), &[(STRING, 0x1000, "s")]);

        assert_eq!(index.len(), 1);
        let hit = index.locate(0x2004).unwrap();
        assert_eq!((hit.record.start, hit.record.end), (0x2000, 0x2005));
        assert_eq!(hit.record.ty, STRING);
        assert_eq!(hit.record.kind, ExtentKind::Bytes);
    }

    /// A trait object follows the vtable join: the concrete type its
    /// function symbols agree on is recorded at the data pointer.
    #[test]
    fn test_a_dyn_pointer_follows_the_vtable_join() {
        let mut b = test_bundle();
        let TypeDef::Array { count, .. } = &mut b.types.types[VTABLE_ARRAY.0 as usize] else {
            panic!("vtable is not an array");
        };
        *count = 4;
        b.validate().expect("expanded vtable must validate");
        let mem = FakeMem::new()
            .at(0x1234, u32s(&[1, 2]))
            .at(0x3000, u64s(&[0, 8, 8, 0x4000]))
            .at(0x1000, u64s(&[0x1234, 0x3000]))
            .symbol(0x4000, "<Point as app::Trait>::run");
        let index = walk(&b, &mem, vec![], defaults(), &[(FAT_PTR, 0x1000, "d")]);

        assert_eq!(index.len(), 1);
        let hit = index.locate(0x1234).unwrap();
        assert_eq!(hit.record.ty, POINT);
        assert_eq!((hit.record.start, hit.record.end), (0x1234, 0x123c));
        assert_eq!(hit.path, ["#0 d"]);
    }

    /// A pointer into a task allocation is not followed: that ground is
    /// the extent join's, and claiming it here would attribute one task's
    /// insides to whoever holds a handle to it.
    #[test]
    fn test_a_pointer_into_a_task_allocation_is_left_to_the_extent_join() {
        let b = test_bundle();
        let mem = FakeMem::new().at(0x1000, node_bytes(1, 0x2050));
        let index = walk(
            &b,
            &mem,
            vec![(0x2000, 0x2100, 0)],
            defaults(),
            &[(NODE, 0x1000, "n")],
        );

        assert!(index.is_empty());
        assert_eq!(index.stats.task_hits, 1);
    }

    /// The depth bound cuts the walk and says so; what was recorded
    /// before the cut still answers.
    #[test]
    fn test_the_depth_bound_stops_and_counts() {
        let b = test_bundle();
        let mem = FakeMem::new()
            .at(0x1000, node_bytes(1, 0x2000))
            .at(0x2000, node_bytes(2, 0x3000))
            .at(0x3000, node_bytes(3, 0));
        let bounds = ReachBounds {
            depth: 2,
            ..defaults()
        };
        let index = walk(&b, &mem, vec![], bounds, &[(NODE, 0x1000, "n")]);

        assert_eq!(index.len(), 1);
        assert!(index.capped.deep > 0);
        assert!(index.capped.any());
        assert!(index.locate(0x2000).is_some());
        assert!(index.locate(0x3000).is_none());
    }

    /// An unreadable target degrades that edge and keeps walking.
    #[test]
    fn test_an_unreadable_target_degrades() {
        let b = test_bundle();
        let mem = FakeMem::new().at(0x1000, node_bytes(1, 0xdead_0000));
        let index = walk(&b, &mem, vec![], defaults(), &[(NODE, 0x1000, "n")]);

        assert!(index.is_empty());
        assert_eq!(index.stats.degraded, 1);
    }

    /// Only the active variant's payload is walked: the same bytes under
    /// an inactive pointer-bearing variant are dead storage, and the walk
    /// must not read through them.
    #[test]
    fn test_inactive_variants_are_not_walked() {
        let mut b = test_bundle();
        let TypeDef::Enum { shape, .. } = &mut b.types.types[MSG.0 as usize] else {
            panic!("Msg is not an enum");
        };
        shape.variants[1].payload.ty = NODE_PTR;
        b.validate().expect("modified enum bundle must validate");

        // Tag 1 (`B`, now a `*Node`): the pointer is live and followed.
        let live = FakeMem::new()
            .at(0x1000, msg_bytes(1, 0x2000))
            .at(0x2000, node_bytes(2, 0));
        let index = walk(&b, &live, vec![], defaults(), &[(MSG, 0x1000, "m")]);
        assert_eq!(index.len(), 1);
        assert_eq!(index.locate(0x2000).unwrap().record.ty, NODE);

        // Tag 0 (`A`, a `Point` over the same storage): the word that
        // would be `B`'s pointer is dead, and following it would read
        // 0x2000 — which this memory panics on.
        let dead = FakeMem::new()
            .at(0x1000, msg_bytes(0, 0x2000))
            .panic_on_unmapped();
        let index = walk(&b, &dead, vec![], defaults(), &[(MSG, 0x1000, "m")]);
        assert!(index.is_empty());
    }

    /// `locate` answers with the most specific containing extent when two
    /// pointers alias into one allocation.
    #[test]
    fn test_locate_prefers_the_smallest_containing_extent() {
        let mut b = test_bundle();
        let TypeDef::Pointer { target, .. } = &mut b.types.types[PTR.0 as usize] else {
            panic!("PTR is not a pointer");
        };
        *target = BIG;
        b.validate().expect("retargeted pointer must validate");

        let mem = FakeMem::new()
            .at(0x1000, u64s(&[0x20000]))
            .at(0x2000, node_bytes(1, 0x20010))
            .at(0x20000, vec![0u8; 0x10004]);
        let index = walk(
            &b,
            &mem,
            vec![],
            defaults(),
            &[(PTR, 0x1000, "big"), (NODE, 0x2000, "n")],
        );

        // Both extents recorded: BIG at 0x20000..0x30004, and a Node
        // inside it at 0x20010..0x20020.
        assert_eq!(index.len(), 2);
        let inside = index.locate(0x20014).unwrap();
        assert_eq!(inside.record.ty, NODE);
        let outside = index.locate(0x21000).unwrap();
        assert_eq!(outside.record.ty, BIG);
        assert_eq!(outside.path, ["#0 big"]);
    }

    /// The element bound stops the descent into a long buffer's tail —
    /// the buffer extent itself is still whole — and says so.
    #[test]
    fn test_the_element_bound_cuts_the_descent_and_counts() {
        let b = slice_of_node_pointers();
        let mem = FakeMem::new()
            .at(0x1000, u64s(&[0x2000, 3, 3]))
            .at(0x2000, u64s(&[0x4000, 0x5000, 0x6000]))
            .at(0x4000, node_bytes(4, 0))
            .at(0x5000, node_bytes(5, 0))
            .at(0x6000, node_bytes(6, 0));
        let bounds = ReachBounds {
            max_elements: 2,
            ..defaults()
        };
        let index = walk(&b, &mem, vec![], bounds, &[(VEC, 0x1000, "v")]);

        // The whole buffer, plus the first two pointees only.
        assert_eq!(index.len(), 3);
        assert_eq!(index.capped.elements, 1);
        assert_eq!(
            (
                index.locate(0x2000).unwrap().record.start,
                index.locate(0x2000).unwrap().record.end
            ),
            (0x2000, 0x2018)
        );
        let second = index.locate(0x5000).unwrap();
        assert_eq!(second.path, ["#0 v", "[1]"]);
        assert!(index.locate(0x6000).is_none());
    }

    /// Bytes for a [`MSG`] value: the tag byte and the 8-byte payload
    /// word at offset 8.
    fn msg_bytes(tag: u8, payload: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes[0] = tag;
        bytes[8..].copy_from_slice(&payload.to_le_bytes());
        bytes
    }

    /// The fixture bundle with `VEC`'s slice program retargeted to `*Node`
    /// elements, so a buffer's elements carry edges of their own.
    fn slice_of_node_pointers() -> Bundle {
        let mut b = test_bundle();
        b.types.debug_formats.insert(
            VEC,
            DisplayNode::Slice {
                pointer: sel(&[0]),
                length: sel(&[1]),
                capacity: Some(sel(&[2])),
                element: NODE_PTR,
            },
        );
        b.validate().expect("retargeted slice must validate");
        b
    }
}

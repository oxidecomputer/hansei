// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The waker sweep: every clone of a task's waker, found by the pair
//! it is stored as rather than by the type that stores it.
//!
//! A future that returned `Pending` left a clone of its task's waker
//! somewhere — a wheel entry, an io waiter, a channel's slot, a
//! `Notify`'s node, a oneshot's `Inner` — and that clone is two machine
//! words: the `RawWaker`'s `vtable`, which for a tokio task is the
//! address of one copy of tokio's `WAKER_VTABLE` static, and its
//! `data`, the task's `Header`. A `FuturesUnordered` child's waker is
//! the same shape with futures-util's per-set vtable and the child's
//! node as its data. Neither word depends on what holds the pair, so
//! one scan of every readable mapping finds every parked waker there is
//! to find, and the registries and readers that name a slot by its type
//! become enrichment rather than discovery.
//!
//! The sweep finds and classifies; it names nothing. A hit is admitted
//! when its data word names a listed task or set child and the memory
//! it sits in is memory the program still owns — a task's own
//! allocation, a census find, a live allocator buffer, the data
//! segment, or (on a target with no allocator index to ask) anonymous
//! memory. A hit in freed memory, on an lwp stack, or whose companion
//! word is unmapped is counted and never admitted: a stale pair is the
//! one thing a waker join must not believe. What holds an admitted hit,
//! and so what the task is parked on, is the attributor's business.

use super::bundle::{Context, TaskExtents, TaskList};
use super::census::FutureCensus;
use crate::heap::umem::{Liveness, UmemHeap};

use foldhash::{HashMap, HashSet};
use proc::{LwpInfo, Mappings, Target};

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// How much of a mapping one scan chunk covers. A pair straddling a
/// chunk edge is seen by the chunk that starts before it, since chunks
/// overlap by one pair's width and a hit is deduplicated by address.
const CHUNK: u64 = 64 << 20;

/// The overlap between consecutive chunks: one `RawWaker`.
const OVERLAP: u64 = 16;

/// Whose vtable a pattern is.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum VtableKind {
    /// One copy of tokio's task `WAKER_VTABLE`.
    Task,
    /// A `futures_util` `FuturesUnordered` child vtable: one per
    /// monomorphized `Task<F>`.
    Set,
}

/// Who a hit's data word names.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Owner {
    /// A listed task, by its header and its index in the list.
    Task { header: u64, index: usize },
    /// A set child the census lists, by set and child index.
    Child { set: usize, child: usize },
}

/// Where a hit sits. The order is the classification order: the first
/// class that claims the address wins.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Class {
    /// Inside a listed task's own allocation.
    TaskExtent,
    /// Inside a census find: a held future's storage or a set child's
    /// node.
    Find,
    /// In an allocator buffer still handed out.
    UmemLive,
    /// In an allocator buffer taken back: a stale pair.
    UmemFreed,
    /// On an lwp's stack or alternate signal stack: a transient.
    LwpStack,
    /// In a file-backed writable mapping: a static.
    DataSegment,
    /// Anonymous memory the allocator index does not account for, or
    /// any memory on a target with no index.
    Anon,
    /// The data word points at nothing mapped: not a waker anyone can
    /// wake.
    UnmappedCompanion,
}

impl Class {
    pub const ALL: [Class; 8] = [
        Class::TaskExtent,
        Class::Find,
        Class::UmemLive,
        Class::UmemFreed,
        Class::LwpStack,
        Class::DataSegment,
        Class::Anon,
        Class::UnmappedCompanion,
    ];

    /// The class as `info` names it.
    pub fn name(self) -> &'static str {
        match self {
            Class::TaskExtent => "task extent",
            Class::Find => "find",
            Class::UmemLive => "umem live",
            Class::UmemFreed => "umem freed",
            Class::LwpStack => "lwp stack",
            Class::DataSegment => "data segment",
            Class::Anon => "anon",
            Class::UnmappedCompanion => "unmapped companion",
        }
    }
}

/// One aligned occurrence of a known vtable address with its
/// companion word read.
#[derive(Clone, Debug)]
pub struct Hit {
    /// The `RawWaker`'s address: the slot.
    pub slot: u64,
    /// The vtable word, and whose it is.
    pub vtable: u64,
    pub kind: VtableKind,
    /// The companion word.
    pub data: u64,
    /// Who the data word names, when it names something listed.
    pub owner: Option<Owner>,
    pub class: Class,
    /// Whether the sweep believes the hit: an owner, in memory the
    /// program owns.
    pub admitted: bool,
}

/// What the sweep did and what it found, for `info`.
#[derive(Clone, Debug, Default)]
pub struct SweepStats {
    pub bytes: u64,
    pub chunks: usize,
    pub elapsed: Duration,
    /// Copies of tokio's static the symtab named.
    pub task_vtables: usize,
    /// Set vtables the data mappings held.
    pub set_vtables: usize,
    pub task_hits: usize,
    pub set_hits: usize,
    pub by_class: BTreeMap<Class, usize>,
    pub admitted: usize,
    /// Distinct data words of task-pattern hits with a mapped
    /// companion that name no listed task.
    pub unlisted: usize,
    /// Why the sweep admitted nothing, where it could not run at all.
    pub absent: Option<String>,
}

/// Every waker slot in the target, indexed by who it wakes.
#[derive(Debug, Default)]
pub struct WakerSlots {
    /// Every pattern swept for, sorted by address.
    pub vtables: Vec<(u64, VtableKind)>,
    /// Every hit, admitted or not, sorted by slot address.
    pub hits: Vec<Hit>,
    pub stats: SweepStats,
    by_task: HashMap<u64, Vec<usize>>,
    by_child: HashMap<(usize, usize), Vec<usize>>,
}

impl WakerSlots {
    /// The admitted hits whose data word is the task header at `addr`,
    /// in slot order.
    pub fn slots_of(&self, addr: u64) -> impl Iterator<Item = &Hit> {
        self.by_task
            .get(&addr)
            .into_iter()
            .flatten()
            .map(|&i| &self.hits[i])
    }

    /// The admitted hits whose data word is the node of set child
    /// `(set, child)`, in slot order.
    pub fn slots_of_child(&self, set: usize, child: usize) -> impl Iterator<Item = &Hit> {
        self.by_child
            .get(&(set, child))
            .into_iter()
            .flatten()
            .map(|&i| &self.hits[i])
    }

    /// The admitted hit at exactly `slot`, if any.
    pub fn hit_at(&self, slot: u64) -> Option<&Hit> {
        let at = self.hits.partition_point(|h| h.slot < slot);
        self.hits.get(at).filter(|h| h.slot == slot && h.admitted)
    }

    /// Cross-check the registries against the sweep: every waker a
    /// harvest decoded as a task's must be an admitted hit naming the
    /// same task, since both read the same bytes. One line per
    /// violation; empty is clean. A sweep that could not run checks
    /// nothing and says so once.
    pub fn audit<'a>(&self, registered: impl Iterator<Item = (&'a str, u64, u64)>) -> Vec<String> {
        if let Some(absent) = &self.stats.absent {
            return vec![format!("waker sweep did not run: {absent}")];
        }
        let mut out = Vec::new();
        for (what, slot, task) in registered {
            match self.hit_at(slot) {
                Some(hit) if matches!(hit.owner, Some(Owner::Task { header, .. }) if header == task) =>
                    {}
                Some(hit) => out.push(format!(
                    "{what} at {slot:#x} names the task at {task:#x}, but the sweep's hit there \
                     names {:?}",
                    hit.owner
                )),
                None => out.push(format!(
                    "{what} at {slot:#x} holds the task at {task:#x}'s waker, but the sweep \
                     admitted no hit there"
                )),
            }
        }
        out
    }

    /// A population of hits laid out by hand, indexed the way the sweep
    /// indexes its own — for a test over a shape no fixture holds.
    pub fn from_hits(mut hits: Vec<Hit>) -> WakerSlots {
        hits.sort_by_key(|h| h.slot);
        let mut slots = WakerSlots {
            hits,
            ..WakerSlots::default()
        };
        slots.index();
        slots
    }

    fn index(&mut self) {
        for (i, hit) in self.hits.iter().enumerate() {
            if !hit.admitted {
                continue;
            }
            match hit.owner {
                Some(Owner::Task { header, .. }) => self.by_task.entry(header).or_default().push(i),
                Some(Owner::Child { set, child }) => {
                    self.by_child.entry((set, child)).or_default().push(i)
                }
                None => {}
            }
        }
        for class in Class::ALL {
            self.stats.by_class.entry(class).or_default();
        }
        for hit in &self.hits {
            *self.stats.by_class.entry(hit.class).or_default() += 1;
            match hit.kind {
                VtableKind::Task => self.stats.task_hits += 1,
                VtableKind::Set => self.stats.set_hits += 1,
            }
        }
        self.stats.admitted = self.hits.iter().filter(|h| h.admitted).count();
        self.stats.unlisted = self
            .hits
            .iter()
            .filter(|h| {
                h.kind == VtableKind::Task
                    && h.owner.is_none()
                    && h.class != Class::UnmappedCompanion
            })
            .map(|h| h.data)
            .collect::<HashSet<_>>()
            .len();
    }
}

/// What the sweep classifies against: the session's account of who
/// owns which memory.
pub struct Territory<'a> {
    pub list: &'a TaskList,
    pub extents: &'a TaskExtents,
    pub census: &'a FutureCensus,
    pub heap: Option<&'a UmemHeap>,
    pub lwps: &'a [LwpInfo],
}

/// The two word offsets of a `RawWaker`, from the bundle's layout.
#[derive(Copy, Clone, Debug)]
pub struct PairLayout {
    pub data: u64,
    pub vtable: u64,
    pub size: u64,
}

impl PairLayout {
    /// The slot a match of the vtable word at `at` belongs to.
    fn slot_of(&self, at: u64) -> Option<u64> {
        at.checked_sub(self.vtable)
    }
}

impl<'b, T: Target> Context<'b, T> {
    /// Sweep every readable mapping for waker pairs and classify each
    /// against `territory`. Never fails: a target whose symtab names no
    /// copy of the task vtable, or whose bundle has no `RawWaker`
    /// layout, yields an empty index whose stats say why.
    pub fn sweep_wakers(&self, territory: &Territory<'_>) -> WakerSlots {
        let started = Instant::now();
        let mut slots = WakerSlots::default();
        let layout = match self.raw_waker_layout() {
            Some(layout) => layout,
            None => {
                slots.stats.absent = Some("the tokio info has no RawWaker layout".to_string());
                return slots;
            }
        };
        let task_vtables = match self.task_waker_vtables() {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => {
                slots.stats.absent =
                    Some("the symtab names no copy of tokio's WAKER_VTABLE".to_string());
                return slots;
            }
            Err(e) => {
                slots.stats.absent = Some(format!("{e:#}"));
                return slots;
            }
        };
        let set_vtables = self.set_waker_vtables();
        slots.stats.task_vtables = task_vtables.len();
        slots.stats.set_vtables = set_vtables.len();
        slots.vtables = task_vtables
            .iter()
            .map(|&v| (v, VtableKind::Task))
            .chain(set_vtables.iter().map(|&v| (v, VtableKind::Set)))
            .collect();
        slots.vtables.sort_unstable();
        slots.vtables.dedup_by_key(|(addr, _)| *addr);

        let patterns: Vec<[u8; 8]> = slots.vtables.iter().map(|(v, _)| v.to_le_bytes()).collect();
        let matcher = matcher(&patterns);

        // Every readable run, in chunks.
        let mut chunks: Vec<(u64, u64)> = Vec::new();
        let mut bytes = 0u64;
        for (addr, len) in self.readable_runs(|_| true) {
            bytes += len;
            let mut start = addr;
            // Saturating: a live target maps the top of the address
            // space too, and a run there has no room past its end.
            let end = addr.saturating_add(len);
            while start < end {
                let stop = start.saturating_add(CHUNK).min(end);
                let with_overlap = stop.saturating_add(OVERLAP).min(end);
                chunks.push((start, with_overlap - start));
                start = stop;
            }
        }
        slots.stats.bytes = bytes;
        slots.stats.chunks = chunks.len();

        // The scan, chunks handed out to scoped workers.
        let next = AtomicUsize::new(0);
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(chunks.len().max(1));
        let proc = self.proc;
        let raw: Vec<(u64, u64, VtableKind)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    let (next, chunks, matcher, slots, layout) =
                        (&next, &chunks, &matcher, &slots, layout);
                    scope.spawn(move || {
                        let mut found = Vec::new();
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some(&(addr, len)) = chunks.get(i) else {
                                break;
                            };
                            let Ok(bytes) = proc.read_bytes(addr, len) else {
                                continue;
                            };
                            for (start, pattern) in aligned_matches(matcher, bytes) {
                                let Some(slot) = layout.slot_of(addr + start) else {
                                    continue;
                                };
                                let (vtable, kind) = slots.vtables[pattern];
                                found.push((slot, vtable, kind));
                            }
                        }
                        found
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("a sweep worker panicked"))
                .collect()
        });
        let mut raw = raw;
        raw.sort_unstable();
        raw.dedup();

        // Companions, owners, classes.
        let headers: HashMap<u64, usize> = territory
            .list
            .tasks
            .iter()
            .enumerate()
            .map(|(i, t)| (t.addr.0, i))
            .collect();
        let held_spans = held_spans(self, territory.census);
        let mut hits = Vec::with_capacity(raw.len());
        for (slot, vtable, kind) in raw {
            let Some(data_at) = slot.checked_add(layout.data) else {
                continue;
            };
            let Ok(data) = self.proc.read_u64(data_at) else {
                continue;
            };
            let mapped = self.mappings.contains_addr(data);
            let owner = match kind {
                VtableKind::Task => headers.get(&data).map(|&index| Owner::Task {
                    header: data,
                    index,
                }),
                VtableKind::Set => territory
                    .census
                    .locate(data)
                    .filter(|&(_, _, offset)| offset == 0)
                    .map(|(set, child, _)| Owner::Child { set, child }),
            };
            let class = if !mapped {
                Class::UnmappedCompanion
            } else {
                classify(slot, territory, &held_spans, &self.mappings)
            };
            let admitted = owner.is_some()
                && match class {
                    Class::TaskExtent | Class::Find | Class::UmemLive | Class::DataSegment => true,
                    Class::Anon => territory.heap.is_none(),
                    Class::UmemFreed | Class::LwpStack | Class::UnmappedCompanion => false,
                };
            hits.push(Hit {
                slot,
                vtable,
                kind,
                data,
                owner,
                class,
                admitted,
            });
        }
        slots.hits = hits;
        slots.index();
        slots.stats.elapsed = started.elapsed();
        slots
    }

    /// The offsets of a `RawWaker`'s two words, from the walk contract's
    /// `RawWaker.data`/`RawWaker.vtable` bindings over the bundle's own
    /// type. `None` where either is unbound.
    pub fn raw_waker_layout(&self) -> Option<PairLayout> {
        let ty = self
            .view
            .find_by_name("core::task::wake::RawWaker")
            .next()?;
        let data = self
            .walk(hansei_bundle::WalkRole::WakerData)
            .member_offset(ty)?;
        let vtable = self
            .walk(hansei_bundle::WalkRole::WakerVtable)
            .member_offset(ty)?;
        Some(PairLayout {
            data,
            vtable,
            size: ty.size(),
        })
    }

    /// Every `futures_util` `FuturesUnordered` child vtable in the
    /// target: a `RawWakerVTable` record in a file-backed, non-executable
    /// mapping whose four entries are the set's `clone_arc_raw`,
    /// `wake_arc_raw`, `wake_by_ref_arc_raw` and `drop_arc_raw`
    /// monomorphizations, by the bundle's member offsets. Empty on a
    /// target with no set, or whose symtab names no such functions.
    pub fn set_waker_vtables(&self) -> Vec<u64> {
        const PREFIX: &str = "futures_util::stream::futures_unordered::task::waker_ref::";
        let Ok(symbols) = self.proc.symbols() else {
            return Vec::new();
        };
        let mut sets: [HashSet<u64>; 4] = Default::default();
        for symbol in &symbols {
            // Every mangling keeps the path's identifiers verbatim, so
            // the ones that can match are found before demangling any.
            if !symbol.name.contains("waker_ref") {
                continue;
            }
            let name = format!("{:#}", rustc_demangle::demangle(&symbol.name));
            let Some(rest) = name.strip_prefix(PREFIX) else {
                continue;
            };
            let which = if rest.starts_with("clone_arc_raw::<") {
                0
            } else if rest.starts_with("wake_arc_raw::<") {
                1
            } else if rest.starts_with("wake_by_ref_arc_raw::<") {
                2
            } else if rest.starts_with("drop_arc_raw::<") {
                3
            } else {
                continue;
            };
            sets[which].insert(symbol.st_value);
        }
        if sets[0].is_empty() {
            return Vec::new();
        }
        let Some(offsets) = self.raw_waker_vtable_layout() else {
            return Vec::new();
        };
        let patterns: Vec<[u8; 8]> = sets[0].iter().map(|v| v.to_le_bytes()).collect();
        let matcher = matcher(&patterns);
        let mut found = Vec::new();
        // File-backed, non-executable: the data and read-only data
        // segments, where a vtable static lives.
        let runs = self.readable_runs(|m| !m.flags.is_exec() && !m.flags.is_anon());
        for (addr, len) in runs {
            let Ok(bytes) = self.proc.read_bytes(addr, len) else {
                continue;
            };
            for (start, _) in aligned_matches(&matcher, bytes) {
                let at = addr + start;
                let Some(base) = at.checked_sub(offsets[0]) else {
                    continue;
                };
                let word = |off: u64| self.proc.read_u64(base + off).ok();
                let agrees = (1..4).all(|i| word(offsets[i]).is_some_and(|w| sets[i].contains(&w)));
                if agrees {
                    found.push(base);
                }
            }
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    /// The readable stretches of the target inside the mappings `keep`
    /// admits, as `(addr, len)`: a core's are found page by page in its
    /// mappings, a snapshot's are exactly the runs its capture read,
    /// clipped to the admitted mappings.
    fn readable_runs(&self, keep: impl Fn(&proc::LoadedObjectWithPath) -> bool) -> Vec<(u64, u64)> {
        let mappings = self
            .mappings
            .as_slice()
            .iter()
            .filter(|m| m.flags.is_read() && keep(m));
        match self.proc.captured_runs() {
            Some(runs) => {
                let mut out = Vec::new();
                for mapping in mappings {
                    let range = mapping.range();
                    for run in &runs {
                        let start = run.start.max(range.start);
                        let end = run.end.min(range.end);
                        if start < end {
                            out.push((start, end - start));
                        }
                    }
                }
                out.sort_unstable();
                out
            }
            None => mappings
                .flat_map(|m| {
                    proc::readable_runs(m.vaddr, m.size, |a, max| self.proc.readable_len(a, max))
                })
                .collect(),
        }
    }

    /// The offsets of `RawWakerVTable`'s `clone`, `wake`, `wake_by_ref`
    /// and `drop`, by name, from the bundle's infra type.
    fn raw_waker_vtable_layout(&self) -> Option<[u64; 4]> {
        let ty = self.view.ty(self.view.bundle().infra.raw_waker_vtable)?;
        let offset = |name: &str| ty.members().find(|m| m.name() == name).map(|m| m.offset());
        Some([
            offset("clone")?,
            offset("wake")?,
            offset("wake_by_ref")?,
            offset("drop")?,
        ])
    }
}

/// A matcher over fixed eight-byte words: leftmost-first, which is what
/// lets the vectorized prefilter run, and no overlap handling of its
/// own — [`aligned_matches`] resumes one byte past each match, so a
/// word match cannot hide an aligned one under it.
fn matcher(patterns: &[[u8; 8]]) -> aho_corasick::AhoCorasick {
    aho_corasick::AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostFirst)
        .build(patterns)
        .expect("fixed 8-byte patterns build")
}

/// Every eight-aligned match of `matcher` in `bytes`, as `(offset,
/// pattern index)`. A match at an unaligned offset is no word and is
/// skipped, and the search resumes one byte past every match rather
/// than past its end, so an aligned word overlapping an unaligned
/// match is still seen.
fn aligned_matches(matcher: &aho_corasick::AhoCorasick, bytes: &[u8]) -> Vec<(u64, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(m) = matcher.find(&bytes[pos..]) else {
            break;
        };
        let at = pos + m.start();
        if at.is_multiple_of(8) {
            out.push((at as u64, m.pattern().as_usize()));
        }
        pos = at + 1;
    }
    out
}

/// The held finds' storage, `(start, end, index)` sorted by start, for
/// the classification's containment test.
fn held_spans<T: Target>(ctx: &Context<'_, T>, census: &FutureCensus) -> Vec<(u64, u64, usize)> {
    let mut spans: Vec<(u64, u64, usize)> = census
        .held
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            let size = ctx.view.ty(h.ty)?.size();
            (size > 0).then_some((h.addr, h.addr + size, i))
        })
        .collect();
    spans.sort_unstable();
    spans
}

/// Where `slot` sits, first claim wins.
fn classify(
    slot: u64,
    territory: &Territory<'_>,
    held_spans: &[(u64, u64, usize)],
    mappings: &Mappings,
) -> Class {
    if territory.extents.locate(slot).is_some() {
        return Class::TaskExtent;
    }
    if territory.census.locate(slot).is_some() {
        return Class::Find;
    }
    let at = held_spans.partition_point(|&(start, _, _)| start <= slot);
    if let Some(&(_, end, _)) = at.checked_sub(1).and_then(|i| held_spans.get(i))
        && slot < end
    {
        return Class::Find;
    }
    if let Some(heap) = territory.heap {
        match heap.locate(slot) {
            Liveness::Live { .. } => return Class::UmemLive,
            Liveness::Freed { .. } => return Class::UmemFreed,
            Liveness::Unknown => {}
        }
    }
    if territory
        .lwps
        .iter()
        .any(|lwp| lwp.stack_range.contains(&slot) || lwp.altstack.contains(&slot))
    {
        return Class::LwpStack;
    }
    match mappings.get(slot) {
        Some(mapping) if mapping.is_data() => Class::DataSegment,
        _ => Class::Anon,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, load_any};
    use crate::tokio::bundle::Task;

    fn hit(slot: u64, owner: Option<Owner>, class: Class, admitted: bool) -> Hit {
        Hit {
            slot,
            vtable: 0xf000,
            kind: match owner {
                Some(Owner::Child { .. }) => VtableKind::Set,
                _ => VtableKind::Task,
            },
            data: match owner {
                Some(Owner::Task { header, .. }) => header,
                Some(Owner::Child { .. }) => 0xc000,
                None => 0xdead,
            },
            owner,
            class,
            admitted,
        }
    }

    fn task(header: u64) -> Option<Owner> {
        Some(Owner::Task { header, index: 0 })
    }

    /// The index answers by owner and by slot over admitted hits only,
    /// and the stats count every hit by class and kind, the unlisted
    /// data words distinct.
    #[test]
    fn test_the_index_serves_admitted_hits_by_owner_and_slot() {
        let slots = WakerSlots::from_hits(vec![
            hit(0x3000, task(0x1000), Class::TaskExtent, true),
            hit(0x2000, task(0x1000), Class::UmemLive, true),
            hit(0x4000, task(0x1000), Class::UmemFreed, false),
            hit(
                0x5000,
                Some(Owner::Child { set: 0, child: 2 }),
                Class::Find,
                true,
            ),
            hit(0x6000, None, Class::Anon, false),
            hit(0x7000, None, Class::Anon, false),
            hit(0x8000, None, Class::UnmappedCompanion, false),
        ]);
        let of: Vec<u64> = slots.slots_of(0x1000).map(|h| h.slot).collect();
        assert_eq!(of, [0x2000, 0x3000], "sorted, the freed one left out");
        assert_eq!(
            slots
                .slots_of_child(0, 2)
                .map(|h| h.slot)
                .collect::<Vec<_>>(),
            [0x5000]
        );
        assert!(slots.slots_of(0x9999).next().is_none());
        assert_eq!(slots.hit_at(0x3000).map(|h| h.slot), Some(0x3000));
        assert!(slots.hit_at(0x4000).is_none(), "not admitted");
        assert!(slots.hit_at(0x3008).is_none());
        let stats = &slots.stats;
        assert_eq!((stats.task_hits, stats.set_hits), (6, 1));
        assert_eq!(stats.admitted, 3);
        // Two unlisted task hits share one data word; the unmapped one
        // is no header at all.
        assert_eq!(stats.unlisted, 1);
        assert_eq!(stats.by_class[&Class::Anon], 2);
        assert_eq!(stats.by_class[&Class::LwpStack], 0);
    }

    /// The audit holds every registered waker to an admitted hit naming
    /// the same task: a missing hit and a hit naming another task are
    /// each one line, a sweep that did not run is one line for all.
    #[test]
    fn test_the_audit_names_each_disagreement() {
        let slots = WakerSlots::from_hits(vec![
            hit(0x3000, task(0x1000), Class::TaskExtent, true),
            hit(0x4000, task(0x1000), Class::UmemFreed, false),
            hit(0x5000, task(0x2000), Class::UmemLive, true),
        ]);
        let registered = [
            ("wheel entry", 0x3000, 0x1000),
            ("io waiter", 0x4000, 0x1000),
            ("trailer", 0x5000, 0x1000),
        ];
        let lines = slots.audit(registered.iter().copied());
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert!(lines[0].contains("io waiter at 0x4000") && lines[0].contains("no hit"));
        assert!(lines[1].contains("trailer at 0x5000") && lines[1].contains("names"));
        let mut absent = WakerSlots::default();
        absent.stats.absent = Some("no vtable".to_string());
        let lines = absent.audit(registered.iter().copied());
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("did not run"));
    }

    /// Classification order: a task's own allocation before a find
    /// before the allocator's word before the stacks before the mapping
    /// kind — and admission per class, an anon hit admitted only where
    /// no allocator index could have answered for it.
    #[test]
    fn test_classification_order_and_admission() {
        use crate::tokio::bundle::{TaskExtents, TaskList};
        use crate::tokio::census::FutureCensus;
        use proc::{LoadedObjectWithPath, LwpInfo, MapFlags, Mappings, Regs, Timespec};

        let list = TaskList::new(Vec::<Task>::new());
        let extents = TaskExtents {
            spans: vec![(0x1000, 0x1100, 0)],
        };
        let census = FutureCensus::from_finds(Vec::new(), Vec::new(), Vec::new());
        let lwp = LwpInfo {
            tid: 1,
            regs: Regs::default(),
            stack_range: 0x7000..0x8000,
            altstack: 0x9000..0x9100,
            tstamp: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        };
        let mapping = |vaddr, flags| LoadedObjectWithPath {
            path: Some("/bin/x".to_string()),
            vaddr,
            size: 0x1000,
            flags: MapFlags(flags),
        };
        // Readable and writable (`MA_READ | MA_WRITE`), file-backed:
        // the data segment. The anonymous bit would make it heap.
        let mappings: Mappings = [mapping(0xa000, 0x04 | 0x02)].into_iter().collect();
        let territory = Territory {
            list: &list,
            extents: &extents,
            census: &census,
            heap: None,
            lwps: std::slice::from_ref(&lwp),
        };
        let classify = |slot| classify(slot, &territory, &[(0x2000, 0x2100, 0)], &mappings);
        assert_eq!(classify(0x1080), Class::TaskExtent);
        assert_eq!(classify(0x2080), Class::Find);
        assert_eq!(classify(0x2100), Class::Anon, "the find's end is out");
        assert_eq!(classify(0x7800), Class::LwpStack);
        assert_eq!(classify(0x9080), Class::LwpStack);
        assert_eq!(classify(0xa080), Class::DataSegment);
        assert_eq!(classify(0xb000), Class::Anon);
    }

    /// Over a real pair: every waker the wheel harvest decoded is an
    /// admitted hit naming the same task, the sleeper's slot lies in its
    /// own extent, and the audit over the registries is clean.
    #[test]
    fn test_the_sweep_finds_the_registries_wakers() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        e.discover(&ctx, &[]);
        let extents = ctx.task_extents(&e.list);
        let census = testkit::census(&ctx, &e.list);
        let lwps = snapshot.lwps().unwrap();
        let slots = ctx.sweep_wakers(&Territory {
            list: &e.list,
            extents: &extents,
            census: &census,
            heap: None,
            lwps: &lwps,
        });
        assert!(slots.stats.absent.is_none(), "{:?}", slots.stats.absent);
        assert_eq!(slots.stats.task_vtables, 1);
        assert!(slots.stats.bytes > 0);
        let sleeper = e
            .list
            .tasks
            .iter()
            .find(|t| matches!(&t.future, crate::tokio::bundle::FutureInfo::Known(k) if k.display_name.contains("sleeper")))
            .expect("the sleeper");
        let entry = e
            .registries
            .timers_of(sleeper.addr.0)
            .next()
            .expect("the sleeper's wheel entry");
        let at = entry.waker_at.expect("the harvest kept the pair's address");
        let hit = slots
            .hit_at(at)
            .expect("the sweep found the wheel entry's waker");
        assert_eq!(hit.class, Class::TaskExtent, "{hit:?}");
        assert!(matches!(hit.owner, Some(Owner::Task { header, .. }) if header == sleeper.addr.0));
        assert!(slots.slots_of(sleeper.addr.0).any(|h| h.slot == at));
        let registered = e
            .registries
            .timers
            .iter()
            .filter_map(|t| Some(("wheel entry", t.waker_at?, t.task?)));
        assert_eq!(slots.audit(registered), Vec::<String>::new());
    }
}

#[cfg(test)]
mod planted_tests {
    //! Tests over a target no capture holds: a fixture pair with memory
    //! planted beside it, or with its symtab taken away.

    use super::*;
    use crate::testkit::{self, load_any};

    use hansei_bundle::BundleView;
    use proc::snapshot::Snapshot;
    use proc::{LoadedObjectWithPath, LwpInfo, MapFlags, Regs, SymbolBuf};

    use std::ops::Range;

    /// Where the planted mapping sits: high, and in no fixture.
    const BASE: u64 = 0x5f00_0000_0000;
    const SIZE: u64 = 0x1000;
    /// A second planted mapping, anonymous: heap-shaped memory, where
    /// a record shaped like a vtable is not one.
    const ANON: u64 = 0x5f00_0001_0000;

    /// A snapshot with one writable file-backed mapping planted beside
    /// it, holding whatever bytes a test lays down, and four function
    /// symbols named as futures-util's set-waker entries.
    struct Planted<'a> {
        inner: &'a Snapshot,
        bytes: Vec<u8>,
        anon: Vec<u8>,
        symbols: Vec<SymbolBuf>,
    }

    fn symbol(name: &str, at: u64) -> SymbolBuf {
        SymbolBuf {
            name: name.to_string(),
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 1,
            st_value: at,
            st_size: 16,
        }
    }

    const PREFIX: &str = "futures_util::stream::futures_unordered::task::waker_ref::";
    const TASK: &str = "<futures_util::stream::futures_unordered::task::Task<planted::Fut>>";
    const CLONE: u64 = BASE + 0x10;
    const WAKE: u64 = BASE + 0x20;
    const WAKE_BY_REF: u64 = BASE + 0x30;
    const DROP: u64 = BASE + 0x40;
    const DECOY: u64 = BASE + 0x50;
    /// The genuine record and a decoy whose drop entry is wrong.
    const VTABLE: u64 = BASE + 0x100;
    const BAD_VTABLE: u64 = BASE + 0x140;
    /// Three pairs: owned, unowned (a node's interior), and on the decoy.
    const OWNED: u64 = BASE + 0x200;
    const UNOWNED: u64 = BASE + 0x220;
    const ON_DECOY: u64 = BASE + 0x240;

    impl<'a> Planted<'a> {
        fn new(inner: &'a Snapshot) -> Self {
            Planted {
                inner,
                bytes: vec![0; SIZE as usize],
                anon: vec![0; SIZE as usize],
                symbols: vec![
                    symbol(&format!("{PREFIX}clone_arc_raw::{TASK}"), CLONE),
                    symbol(&format!("{PREFIX}wake_arc_raw::{TASK}"), WAKE),
                    symbol(&format!("{PREFIX}wake_by_ref_arc_raw::{TASK}"), WAKE_BY_REF),
                    symbol(&format!("{PREFIX}drop_arc_raw::{TASK}"), DROP),
                    symbol(&format!("{PREFIX}will_wake::{TASK}"), DECOY),
                ],
            }
        }

        fn word(&mut self, at: u64, value: u64) {
            let (buf, base) = if at >= ANON {
                (&mut self.anon, ANON)
            } else {
                (&mut self.bytes, BASE)
            };
            let off = (at - base) as usize;
            buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }

        fn range(&self) -> Range<u64> {
            BASE..BASE + SIZE
        }

        fn anon_range(&self) -> Range<u64> {
            ANON..ANON + SIZE
        }
    }

    impl proc::Target for Planted<'_> {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            for (range, buf) in [(self.range(), &self.bytes), (self.anon_range(), &self.anon)] {
                if range.contains(&addr) && addr + len <= range.end {
                    let off = (addr - range.start) as usize;
                    return Ok(&buf[off..off + len as usize]);
                }
            }
            self.inner.read_bytes(addr, len)
        }

        fn readable_len(&self, addr: u64, max: u64) -> u64 {
            for range in [self.range(), self.anon_range()] {
                if range.contains(&addr) {
                    return (range.end - addr).min(max);
                }
            }
            self.inner.readable_len(addr, max)
        }

        fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
            self.inner.lookup_symbol_by_addr(addr)
        }

        fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
            self.inner.lookup_symbol_by_name(name)
        }

        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            let mut symbols = self.inner.symbols()?;
            symbols.extend(self.symbols.iter().cloned());
            Ok(symbols)
        }

        fn object_symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            self.inner.object_symbols()
        }

        fn mappings(&self) -> proc::Result<proc::Mappings> {
            let planted = LoadedObjectWithPath {
                path: Some("/planted/libset.so".to_string()),
                vaddr: BASE,
                size: SIZE,
                // Readable and writable, file-backed: a data segment.
                flags: MapFlags(0x04 | 0x02),
            };
            let anon = LoadedObjectWithPath {
                path: None,
                vaddr: ANON,
                size: SIZE,
                // Readable, writable and anonymous: heap-shaped.
                flags: MapFlags(0x04 | 0x02 | 0x40),
            };
            Ok(self
                .inner
                .mappings()?
                .as_slice()
                .iter()
                .cloned()
                .chain([planted, anon])
                .collect())
        }

        fn captured_runs(&self) -> Option<Vec<Range<u64>>> {
            let mut runs = self.inner.captured_runs()?;
            runs.push(self.range());
            runs.push(self.anon_range());
            Some(runs)
        }

        fn lwps(&self) -> proc::Result<Vec<LwpInfo>> {
            self.inner.lwps()
        }

        fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> proc::Result<Option<u64>> {
            self.inner.tls_var_addr(regs, sym)
        }
    }

    /// A set vtable is a record whose four entries are the four set
    /// functions in the bundle's order, found in a file-backed data
    /// mapping; a record with a wrong entry is not one, and neither is
    /// a genuine-looking record in anonymous memory. A pair on the
    /// genuine vtable naming a set child's node is that child's slot,
    /// admitted in the data segment; one naming the node's interior
    /// names nothing; one on the decoy is no hit at all.
    #[test]
    fn test_set_vtables_are_found_by_their_entries_and_name_set_children() {
        let (bundle, snapshot) = load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = testkit::census(&ctx, &list);
        let extents = ctx.task_extents(&list);
        let lwps = snapshot.lwps().unwrap();
        let node = census.sets[0].children[0].node;
        let (set, child, _) = census.locate(node).expect("a listed child node");

        let mut planted = Planted::new(&snapshot);
        let layout = ctx.raw_waker_layout().expect("the RawWaker layout");
        let offsets = ctx.raw_waker_vtable_layout().expect("the vtable layout");
        for (record, drop) in [(VTABLE, DROP), (BAD_VTABLE, DECOY), (ANON + 0x100, DROP)] {
            planted.word(record + offsets[0], CLONE);
            planted.word(record + offsets[1], WAKE);
            planted.word(record + offsets[2], WAKE_BY_REF);
            planted.word(record + offsets[3], drop);
        }
        for (pair, vtable, data) in [
            (OWNED, VTABLE, node),
            (UNOWNED, VTABLE, node + 8),
            (ON_DECOY, BAD_VTABLE, node),
        ] {
            planted.word(pair + layout.vtable, vtable);
            planted.word(pair + layout.data, data);
        }

        let pctx = Context::new(&planted, BundleView::new(&bundle)).unwrap();
        assert_eq!(pctx.set_waker_vtables(), vec![VTABLE]);
        let slots = pctx.sweep_wakers(&Territory {
            list: &list,
            extents: &extents,
            census: &census,
            heap: None,
            lwps: &lwps,
        });
        assert_eq!(slots.stats.set_vtables, 1, "{:?}", slots.stats);
        assert!(slots.vtables.contains(&(VTABLE, VtableKind::Set)));
        let owned = slots.hit_at(OWNED).expect("the owned pair is admitted");
        assert_eq!(owned.owner, Some(Owner::Child { set, child }));
        assert_eq!(
            (owned.kind, owned.class),
            (VtableKind::Set, Class::DataSegment)
        );
        assert!(slots.slots_of_child(set, child).any(|h| h.slot == OWNED));
        let unowned = slots
            .hits
            .iter()
            .find(|h| h.slot == UNOWNED)
            .expect("the unowned pair is a hit");
        assert_eq!(unowned.owner, None);
        assert!(!unowned.admitted);
        assert!(slots.hits.iter().all(|h| h.slot != ON_DECOY));
        assert!(slots.stats.set_hits >= 2);
    }

    /// A snapshot whose symtab has no copy of tokio's static: the sweep
    /// admits nothing and says why, and the audit says it did not run.
    struct Nameless<'a>(&'a Snapshot);

    impl proc::Target for Nameless<'_> {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            self.0.read_bytes(addr, len)
        }
        fn readable_len(&self, addr: u64, max: u64) -> u64 {
            self.0.readable_len(addr, max)
        }
        fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
            self.0.lookup_symbol_by_addr(addr)
        }
        fn lookup_symbol_by_name(&self, _name: &str) -> Option<SymbolBuf> {
            None
        }
        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            self.0.symbols()
        }
        fn object_symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            Ok(Vec::new())
        }
        fn mappings(&self) -> proc::Result<proc::Mappings> {
            self.0.mappings()
        }
        fn captured_runs(&self) -> Option<Vec<Range<u64>>> {
            self.0.captured_runs()
        }
        fn lwps(&self) -> proc::Result<Vec<LwpInfo>> {
            self.0.lwps()
        }
        fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> proc::Result<Option<u64>> {
            self.0.tls_var_addr(regs, sym)
        }
    }

    #[test]
    fn test_no_copy_of_the_static_means_an_absent_sweep() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = testkit::census(&ctx, &list);
        let extents = ctx.task_extents(&list);
        let lwps = snapshot.lwps().unwrap();
        let nameless = Nameless(&snapshot);
        let nctx = Context::new(&nameless, BundleView::new(&bundle)).unwrap();
        assert_eq!(nctx.task_waker_vtables().unwrap(), Vec::<u64>::new());
        let slots = nctx.sweep_wakers(&Territory {
            list: &list,
            extents: &extents,
            census: &census,
            heap: None,
            lwps: &lwps,
        });
        assert_eq!(
            slots.stats.absent.as_deref(),
            Some("the symtab names no copy of tokio's WAKER_VTABLE")
        );
        assert!(slots.hits.is_empty() && slots.vtables.is_empty());
        assert_eq!(slots.stats.bytes, 0);
        let lines = slots.audit(std::iter::once(("wheel entry", 0x10, 0x20)));
        assert!(lines[0].contains("did not run"), "{lines:?}");
    }

    /// The held finds' spans are exactly the finds' storage, sorted:
    /// each find's address to its type's size.
    #[test]
    fn test_held_spans_are_the_finds_storage() {
        let (bundle, snapshot) = load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = testkit::census(&ctx, &list);
        let mut expected: Vec<(u64, u64, usize)> = census
            .held
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let size = ctx.view.ty(h.ty).unwrap().size();
                (h.addr, h.addr + size, i)
            })
            .collect();
        expected.sort_unstable();
        assert!(!expected.is_empty());
        assert!(expected.iter().all(|(start, end, _)| end > start));
        assert_eq!(held_spans(&ctx, &census), expected);
    }

    /// The recorder hands a sweep the runs of the snapshot it wraps.
    #[test]
    fn test_the_recorder_passes_the_captured_runs_through() {
        use proc::Target as _;
        let (_, snapshot) = load_any("sleep-join");
        let recorder = proc::snapshot::Recorder::new(&snapshot);
        let runs = recorder.captured_runs().expect("a snapshot's runs");
        assert!(!runs.is_empty());
        assert_eq!(runs, snapshot.captured_runs().unwrap());
        assert_eq!(runs, snapshot.segments().collect::<Vec<_>>());
    }
}

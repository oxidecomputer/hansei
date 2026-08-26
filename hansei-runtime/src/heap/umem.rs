// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What libumem says about an address: the allocation containing it,
//! and whether that allocation is live.
//!
//! libumem is the userland port of the kernel slab allocator, and
//! postmortem debuggability is one of its design goals: every buffer it
//! hands out is accounted for in metadata the core carries, which is
//! what mdb's `::whatis` and `::walk umem` read. This walks the same
//! metadata to answer the one question no amount of DWARF can — "is
//! this pointer's target still allocated?" — because the type of a
//! stale pointer says nothing about whether the bytes under it still
//! belong to what wrote them.
//!
//! The shape of the walk, per cache:
//!
//! - `umem_ready` gates everything; `umem_null_cache` anchors a
//!   circular list of every `umem_cache_t`.
//! - Each cache anchors a circular list of `umem_slab_t` at its own
//!   `cache_nullslab`. A slab's buffers tile it exactly: `slab_chunks`
//!   chunks of `cache_chunksize` bytes from `slab_base`.
//! - The chunks on the slab's freelist (`slab_head`, chained through
//!   `bc_next`) are free; the rest are allocated. `slab_refcnt` counts
//!   the allocated ones independently, so the two must agree — which is
//!   the cross-check that catches both a misread layout and a core
//!   caught mid-`malloc`.
//!
//! What this deliberately does not cover, and so errs toward [`Live`]
//! on (never toward wrongly [`Freed`]):
//!
//! - **The magazine and per-thread layers.** A buffer freed into a
//!   per-CPU magazine, a depot magazine, or a `UMF_PTC` cache's
//!   per-thread cache is free, but the slab layer above still counts it
//!   allocated. mdb subtracts them; this does not yet, so such a buffer
//!   reads `Live`.
//! - **The oversize and memalign vmem arenas.** Allocations too large
//!   for any cache come from `umem_oversize` and are in no slab at all,
//!   so nothing here covers them and they answer [`Liveness::Unknown`].
//!
//! Every step validates before it believes, and a violation declines —
//! the slab, the cache, or the whole index, whichever the violation
//! scopes to. An index that declines part of the target says so in its
//! [`Stats`], because a walk that quietly covered less than it claims
//! would turn a missing verdict into a wrong one.
//!
//! [`Live`]: Liveness::Live
//! [`Freed`]: Liveness::Freed

use proc::Target;

use std::ops::Range;

/// The object whose symbols name the allocator's own state. umem is
/// per-process opt-in — a program links it or preloads it — so a target
/// without this object mapped has no index to build, which is the
/// ordinary case and not a failure.
const LIBUMEM: &str = "libumem.so.1";

/// `umem_ready`'s value once the allocator is fully initialized
/// (`UMEM_READY` in `umem_impl.h`). Anything else — mid-init, or an
/// init that failed — means the metadata below is not yet meaningful.
const UMEM_READY: u32 = 3;

/// `UMF_HASH`: the cache keeps its bufctls outside the buffers, in a
/// hash table, rather than embedded at `cache_bufctl` inside them.
/// Which of the two a cache uses is the one layout difference the
/// freelist walk has to care about.
const UMF_HASH: u32 = 0x200;

/// How many caches the list may hold before the walk calls it corrupt.
/// A real target has a few dozen.
const MAX_CACHES: usize = 4096;

/// How many slabs one cache may hold. A gigabyte of 8-byte allocations
/// is under 300k slabs, so this bounds a cycle rather than a target.
const MAX_SLABS_PER_CACHE: usize = 1 << 21;

/// How many chunks one slab may tile into.
const MAX_CHUNKS_PER_SLAB: u64 = 1 << 20;

/// How many buckets a cache's hash table may have.
const MAX_HASH_BUCKETS: u64 = 1 << 24;

/// How many decline notes are kept. Enough to say what went wrong
/// without hoarding one line per slab of a torn core.
const MAX_NOTES: usize = 32;

/// Where one layout epoch puts the fields the walk reads.
///
/// Offsets are pinned from `umem_impl.h` rather than derived, the way
/// this workspace pins tokio's: the structures are C, so a member's
/// place is the compiler's arithmetic over the declarations, and the
/// only honest source is the header of the release being read. Should a
/// future libumem move one, it gets its own entry here and the walk
/// picks between them the way it picks between nothing today — by
/// believing whichever one's invariants hold.
#[derive(Debug, Clone, Copy)]
struct Layout {
    /// What to call this epoch in a decline note.
    name: &'static str,
    cache_name: u64,
    cache_bufsize: u64,
    cache_flags: u64,
    cache_next: u64,
    cache_prev: u64,
    cache_chunksize: u64,
    cache_slabsize: u64,
    cache_bufctl: u64,
    cache_hash_mask: u64,
    cache_nullslab: u64,
    cache_hash_table: u64,
    slab_cache: u64,
    slab_base: u64,
    slab_next: u64,
    slab_prev: u64,
    slab_head: u64,
    slab_refcnt: u64,
    slab_chunks: u64,
    slab_size: u64,
    bufctl_next: u64,
    bufctl_addr: u64,
}

/// The layout every illumos libumem has had: `umem_impl.h` has not
/// moved one of these members since the allocator was written.
const LP64: Layout = Layout {
    name: "lp64",
    cache_name: 88,
    cache_bufsize: 120,
    cache_flags: 180,
    cache_next: 192,
    cache_prev: 200,
    cache_chunksize: 256,
    cache_slabsize: 264,
    cache_bufctl: 272,
    cache_hash_mask: 336,
    cache_nullslab: 352,
    cache_hash_table: 416,
    slab_cache: 0,
    slab_base: 8,
    slab_next: 16,
    slab_prev: 24,
    slab_head: 32,
    slab_refcnt: 40,
    slab_chunks: 48,
    slab_size: 56,
    bufctl_next: 0,
    bufctl_addr: 8,
};

/// Every layout the walk knows, tried in order.
const LAYOUTS: &[Layout] = &[LP64];

/// What the allocator says about an address.
///
/// There is no verdict for "not in the heap": an address no walked slab
/// covers is [`Unknown`](Liveness::Unknown), because the walk covers
/// only what it understands — the slab layer of a live umem — and the
/// oversize arenas, another allocator's memory, a stack and a mapping
/// that was never heap are all equally outside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    /// The address is inside an allocated buffer.
    Live {
        /// The buffer's exact bounds — what a pointer claiming to own
        /// this allocation must fit inside. Not the chunk's: a cache
        /// whose buffer is shorter than its stride keeps the slack
        /// past the buffer's end for itself.
        buffer: Range<u64>,
        /// Index into [`UmemHeap::caches`].
        cache: usize,
    },
    /// The address is inside a buffer on its slab's freelist: freed,
    /// and not since handed back out.
    Freed { buffer: Range<u64>, cache: usize },
    /// No walked buffer covers the address, and nothing is claimed
    /// about it.
    Unknown,
}

/// What the allocator knows about one address as an *allocation*:
/// whether its block is still handed out, how big the allocation in it
/// is, and how far into it the address falls.
///
/// This is the slab walk's reading joined to the malloc shim's: the
/// walk finds the block, and the header libumem wrote at that block's
/// base says what the program asked for and where the pointer it was
/// given starts. Either half can be missing — freeing scrubs the
/// header, and an oversize allocation is in no walked slab — so each
/// field says which reading it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    /// Whether the allocator still considers the block handed out.
    ///
    /// The two verdicts are not equally strong. `false` is corroborated
    /// twice — the block is on its slab's freelist *and* its malloc
    /// header has been scrubbed — while `true` says only that the
    /// allocator has not taken the block back, which a buffer parked in
    /// a magazine also satisfies until that layer is walked.
    pub live: bool,
    /// How big the allocation is, and whose number that is.
    pub size: Size,
    /// How far past the pointer the program was given the address sits
    /// — or past the block's base, where no header survives to say
    /// where that pointer was. Zero means the address *is* the
    /// allocation rather than a pointer into one.
    pub offset: u64,
}

/// How big an allocation is, by whichever reading was available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    /// What the program asked for, from the malloc header: exact, and
    /// the caller's own number rather than the allocator's arithmetic.
    Requested(u64),
    /// The block's own size, for an allocation whose header is gone.
    /// Freeing scrubs it, so a freed allocation is always measured this
    /// way, and the block is all there is left to measure.
    Block(u64),
}

/// One cache the walk believed, as its own accounting.
#[derive(Debug, Clone)]
pub struct Cache {
    /// Where the `umem_cache_t` is, for a hand check under mdb.
    pub addr: u64,
    pub name: String,
    /// The object size the cache serves.
    pub bufsize: u64,
    /// Bytes from one chunk to the next: `bufsize` rounded up, plus
    /// whatever debugging features are on.
    pub chunksize: u64,
    pub slabsize: u64,
    pub flags: u32,
    pub slabs: usize,
    /// Slabs dropped by a failed invariant, whose chunks are in no
    /// verdict at all.
    pub slabs_declined: usize,
    pub live: u64,
    pub freed: u64,
    /// How far into a buffer a raw cache's embedded bufctl sits — the
    /// one cache property the freelist walk needs and nobody else does.
    bufctl: u64,
}

impl Cache {
    /// Whether bufctls live in a hash table outside the buffers.
    pub fn hashed(&self) -> bool {
        self.flags & UMF_HASH != 0
    }
}

/// Honesty counters: every place the walk covered less than the target
/// holds, so an incomplete index can say so rather than read as a
/// complete one.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Which layout the index was built with.
    pub layout: &'static str,
    /// Caches walked and believed.
    pub caches: usize,
    /// Caches dropped whole by a failed invariant.
    pub caches_declined: usize,
    pub slabs: usize,
    pub slabs_declined: usize,
    pub live_chunks: u64,
    pub freed_chunks: u64,
    /// Bytes in live chunks, chunk stride rather than requested size.
    pub live_bytes: u64,
    /// Slabs dropped because another slab already claimed their
    /// address range — an overlap is two readings of the same memory,
    /// so neither is believed.
    pub overlaps: usize,
    /// Whether the magazine, depot and per-thread layers were
    /// subtracted. False here: a buffer parked in one reads `Live`.
    pub magazines_walked: bool,
    /// Whether the oversize and memalign vmem arenas were walked.
    /// False here: allocations from them answer `Unknown`.
    pub oversize_walked: bool,
    /// Why the declines above happened, capped at [`MAX_NOTES`].
    pub notes: Vec<String>,
}

impl Stats {
    /// Whether anything was declined — the "this index covers less than
    /// the target" signal a verdict-consuming answer should carry.
    pub fn incomplete(&self) -> bool {
        self.caches_declined > 0 || self.slabs_declined > 0 || self.overlaps > 0
    }
}

/// One slab's chunks, as the tiling plus which of them are free.
///
/// The index is slabs rather than chunks on purpose: a real target has
/// millions of chunks and tens of thousands of slabs, and a slab knows
/// its chunks by arithmetic. A bit per chunk is the whole difference
/// between the two answers.
#[derive(Debug)]
struct Slab {
    base: u64,
    chunksize: u64,
    chunks: u32,
    cache: u32,
    /// Bit `i` set means chunk `i` is on the freelist. Empty for a slab
    /// with nothing free, which is most of a busy target's.
    free: Vec<u64>,
}

impl Slab {
    fn end(&self) -> u64 {
        self.base + self.chunks as u64 * self.chunksize
    }

    fn is_free(&self, chunk: u32) -> bool {
        let word = chunk as usize / 64;
        self.free
            .get(word)
            .is_some_and(|w| w >> (chunk % 64) & 1 == 1)
    }

    fn freed(&self) -> u64 {
        self.free.iter().map(|w| w.count_ones() as u64).sum()
    }
}

/// libumem's own account of which of the target's allocations are live.
#[derive(Debug)]
pub struct UmemHeap {
    caches: Vec<Cache>,
    /// Sorted by base and non-overlapping, so an address finds its slab
    /// by binary search.
    slabs: Vec<Slab>,
    stats: Stats,
}

impl UmemHeap {
    /// Read the target's umem metadata, or `None` when there is nothing
    /// to read: no libumem mapped, an allocator not yet initialized, or
    /// metadata that fails its own invariants.
    ///
    /// `None` is silent and ordinary. umem is per-process opt-in, so a
    /// target without it simply has no allocator corroboration to offer
    /// and everything reading this must behave exactly as it would have
    /// without one.
    pub fn build<T: Target>(target: &T) -> Option<UmemHeap> {
        LAYOUTS
            .iter()
            .find_map(|layout| Walk::new(target, *layout).run())
    }

    /// What the allocator says about `addr`.
    pub fn locate(&self, addr: u64) -> Liveness {
        let Some(slab) = self.slab_at(addr) else {
            return Liveness::Unknown;
        };
        let index = ((addr - slab.base) / slab.chunksize) as u32;
        let start = slab.base + index as u64 * slab.chunksize;
        let cache = slab.cache as usize;
        // A chunk is the stride from one buffer to the next, and a
        // cache whose buffer is shorter than that pads the difference —
        // where a raw cache parks the bufctl of a free buffer, among
        // other things. That slack is the allocator's own memory, so an
        // address in it is in no allocation, the way one between two
        // slabs is.
        let buffer = start..start + self.caches[cache].bufsize;
        if !buffer.contains(&addr) {
            return Liveness::Unknown;
        }
        match slab.is_free(index) {
            true => Liveness::Freed { buffer, cache },
            false => Liveness::Live { buffer, cache },
        }
    }

    /// What the allocator says about the *allocation* at `addr`, which
    /// is what a consumer answering a human wants: the block's own
    /// account of itself rather than which cache it came from.
    ///
    /// `None` means nothing is known — no walked slab covers the
    /// address and no malloc header precedes it — which is a silence to
    /// pass on rather than an answer of "unknown".
    pub fn allocation<T: Target>(&self, target: &T, addr: u64) -> Option<Allocation> {
        let (live, block) = match self.locate(addr) {
            Liveness::Live { buffer, .. } => (true, buffer),
            Liveness::Freed { buffer, .. } => (false, buffer),
            // In no walked slab: the oversize and memalign arenas are
            // outside this walk, and the header the shim wrote is then
            // the only account of the allocation there is. It speaks
            // for the pointer it precedes and for no other address, so
            // this answers for such an allocation's own pointer and
            // stays silent about an address inside one.
            Liveness::Unknown => {
                let tag = malloc_tag(target, addr)?;
                let header = addr - tag.base;
                return Some(Allocation {
                    // A header that still decodes has not been through
                    // `free`, which overwrites the word it decodes
                    // from.
                    live: true,
                    size: Size::Requested(tag.total.checked_sub(header)?),
                    offset: 0,
                });
            }
        };
        let size = block.end - block.start;
        Some(
            match header(target, block.start, size).filter(|&(ptr, _)| addr >= ptr) {
                Some((ptr, requested)) => Allocation {
                    live,
                    size: Size::Requested(requested),
                    offset: addr - ptr,
                },
                // No header to read, or an address inside one: a header
                // is libumem's own memory rather than the program's, so
                // an address in it has no pointer to be an offset from
                // and is measured against the block like any other.
                None => Allocation {
                    live,
                    size: Size::Block(size),
                    offset: addr - block.start,
                },
            },
        )
    }

    fn slab_at(&self, addr: u64) -> Option<&Slab> {
        let above = self.slabs.partition_point(|s| s.base <= addr);
        self.slabs
            .get(above.checked_sub(1)?)
            .filter(|s| addr < s.end())
    }

    /// The caches the walk believed, in the order the cache list holds
    /// them. A [`Liveness`] names one by its index here.
    pub fn caches(&self) -> &[Cache] {
        &self.caches
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Every allocated buffer, in address order: the set mdb's `::walk
    /// umem` enumerates, which is what an enumeration differential
    /// against it diffs.
    pub fn live_buffers(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.buffers(false)
    }

    /// Every buffer found on a slab's freelist, in address order. This
    /// is a subset of what mdb calls freed, which also counts the
    /// magazine layer this walk does not read.
    pub fn freed_buffers(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.buffers(true)
    }

    fn buffers(&self, free: bool) -> impl Iterator<Item = Range<u64>> + '_ {
        self.slabs.iter().flat_map(move |slab| {
            let bufsize = self.caches[slab.cache as usize].bufsize;
            (0..slab.chunks).filter_map(move |i| {
                let start = slab.base + i as u64 * slab.chunksize;
                (slab.is_free(i) == free).then(|| start..start + bufsize)
            })
        })
    }

    /// Self-consistency invariants, checked over the finished index
    /// rather than during the walk that built it: live chunks never
    /// overlap, and every cache's counts add up to its slabs'.
    ///
    /// Cheap enough to run on every real-core session that asks for a
    /// verdict, and what turns a walker bug or a torn core into a
    /// reported violation instead of a confident wrong answer.
    pub fn violations(&self) -> Vec<String> {
        let mut out = Vec::new();
        for pair in self.slabs.windows(2) {
            if pair[0].end() > pair[1].base {
                out.push(format!(
                    "slabs at {:#x} and {:#x} overlap",
                    pair[0].base, pair[1].base
                ));
            }
        }
        let mut live = vec![0u64; self.caches.len()];
        let mut freed = vec![0u64; self.caches.len()];
        for slab in &self.slabs {
            for i in 0..slab.chunks {
                match slab.is_free(i) {
                    true => freed[slab.cache as usize] += 1,
                    false => live[slab.cache as usize] += 1,
                }
            }
        }
        for (i, cache) in self.caches.iter().enumerate() {
            if (cache.live, cache.freed) != (live[i], freed[i]) {
                out.push(format!(
                    "{} counted {} live / {} freed, its slabs hold {} / {}",
                    cache.name, cache.live, cache.freed, live[i], freed[i]
                ));
            }
        }
        out
    }
}

/// One walk of the metadata, under one candidate [`Layout`].
struct Walk<'t, T> {
    target: &'t T,
    layout: Layout,
    caches: Vec<Cache>,
    slabs: Vec<Slab>,
    stats: Stats,
}

impl<'t, T: Target> Walk<'t, T> {
    fn new(target: &'t T, layout: Layout) -> Self {
        Walk {
            target,
            layout,
            caches: Vec::new(),
            slabs: Vec::new(),
            stats: Stats {
                layout: layout.name,
                ..Stats::default()
            },
        }
    }

    fn run(mut self) -> Option<UmemHeap> {
        let ready = self.symbol("umem_ready")?;
        if self.target.read_u32(ready).ok()? != UMEM_READY {
            return None;
        }
        let anchor = self.symbol("umem_null_cache")?;
        self.walk_caches(anchor)?;

        self.slabs.sort_unstable_by_key(|s| s.base);
        self.drop_overlaps();
        Some(UmemHeap {
            caches: self.caches,
            slabs: self.slabs,
            stats: self.stats,
        })
    }

    /// The address of one of libumem's own globals. They are private to
    /// the library, so the lookup names the object that defines them
    /// rather than the executable.
    fn symbol(&self, name: &str) -> Option<u64> {
        self.target
            .lookup_symbol_by_name(&format!("{LIBUMEM}`{name}"))
            .map(|s| s.st_value)
    }

    /// Walk the circular cache list anchored at `umem_null_cache`.
    ///
    /// A violation here is the whole index's: the list is how every
    /// cache is found, so a walk that cannot trust it has no population
    /// to be partly right about.
    fn walk_caches(&mut self, anchor: u64) -> Option<()> {
        let mut addr = self.read(anchor + self.layout.cache_next)?;
        let mut prev = anchor;
        let mut seen = 0;
        while addr != anchor {
            seen += 1;
            if seen > MAX_CACHES {
                return None;
            }
            // The list is doubly linked, so each step has a witness:
            // an entry whose `cache_prev` is not where we came from is
            // a misread pointer or a corrupt list, and either way the
            // rest of the walk is guesswork.
            if self.read(addr + self.layout.cache_prev)? != prev {
                return None;
            }
            self.walk_cache(addr);
            prev = addr;
            addr = self.read(addr + self.layout.cache_next)?;
        }
        (self.stats.caches > 0).then_some(())
    }

    /// One cache: its geometry, then its slabs. A cache that fails an
    /// invariant is dropped whole — its slabs with it — and counted, so
    /// the rest of the target is still answered for.
    fn walk_cache(&mut self, addr: u64) {
        let Some(mut cache) = self.read_cache(addr) else {
            self.decline_cache(addr, "unreadable or implausible geometry");
            return;
        };
        let index = self.caches.len() as u32;
        let first = self.slabs.len();
        if self.walk_slabs(addr, &mut cache, index).is_none() {
            self.slabs.truncate(first);
            self.decline_cache(addr, "its slab list did not walk");
            return;
        }
        if cache.hashed() && !self.hash_agrees(addr, &cache, &self.slabs[first..]) {
            self.slabs.truncate(first);
            self.decline_cache(addr, "its hash table disagrees with its slabs");
            return;
        }
        self.stats.caches += 1;
        self.stats.slabs += cache.slabs;
        self.stats.live_chunks += cache.live;
        self.stats.freed_chunks += cache.freed;
        self.stats.live_bytes += cache.live * cache.chunksize;
        self.caches.push(cache);
    }

    /// A cache's properties, believed only if they describe a tiling
    /// that could exist: a buffer fits its chunk, a chunk fits its
    /// slab, and neither is zero.
    fn read_cache(&self, addr: u64) -> Option<Cache> {
        let bufsize = self.read(addr + self.layout.cache_bufsize)?;
        let chunksize = self.read(addr + self.layout.cache_chunksize)?;
        let slabsize = self.read(addr + self.layout.cache_slabsize)?;
        let flags = self.target.read_u32(addr + self.layout.cache_flags).ok()?;
        if bufsize == 0 || bufsize > chunksize || chunksize > slabsize {
            return None;
        }
        // The embedded bufctl a non-hashed cache's freelist is chained
        // through has to be inside the buffer it belongs to.
        let bufctl = self.read(addr + self.layout.cache_bufctl)?;
        if flags & UMF_HASH == 0 && bufctl >= chunksize {
            return None;
        }
        Some(Cache {
            addr,
            name: self.read_name(addr + self.layout.cache_name)?,
            bufsize,
            chunksize,
            slabsize,
            flags,
            slabs: 0,
            slabs_declined: 0,
            live: 0,
            freed: 0,
            bufctl,
        })
    }

    /// Walk one cache's circular slab list, anchored at its own
    /// `cache_nullslab`. `None` means the list itself is unwalkable;
    /// individual slabs decline on their own without ending the walk.
    fn walk_slabs(&mut self, cache_addr: u64, cache: &mut Cache, index: u32) -> Option<()> {
        let anchor = cache_addr + self.layout.cache_nullslab;
        let mut addr = self.read(anchor + self.layout.slab_next)?;
        let mut prev = anchor;
        let mut seen = 0;
        while addr != anchor {
            seen += 1;
            if seen > MAX_SLABS_PER_CACHE {
                return None;
            }
            if self.read(addr + self.layout.slab_prev)? != prev {
                return None;
            }
            match self.read_slab(addr, cache_addr, cache, index) {
                Some(slab) => {
                    let freed = slab.freed();
                    cache.slabs += 1;
                    cache.live += slab.chunks as u64 - freed;
                    cache.freed += freed;
                    self.slabs.push(slab);
                }
                None => {
                    cache.slabs_declined += 1;
                    self.stats.slabs_declined += 1;
                    self.note(format!("{}: slab {addr:#x} declined", cache.name));
                }
            }
            prev = addr;
            addr = self.read(addr + self.layout.slab_next)?;
        }
        Some(())
    }

    /// One slab, and which of its chunks are free.
    ///
    /// Two independently-derived numbers have to agree here — the
    /// slab's own `slab_refcnt` and the length of its freelist — which
    /// is the strongest check in the walk: a misread layout, a stale
    /// pointer followed into someone else's memory, and a core caught
    /// part-way through a `malloc` all show up as a disagreement.
    fn read_slab(&self, addr: u64, cache_addr: u64, cache: &Cache, index: u32) -> Option<Slab> {
        let slab = self.target.read_bytes(addr, self.layout.slab_size).ok()?;
        let at = |off: u64| {
            let off = off as usize;
            u64::from_le_bytes(slab[off..off + 8].try_into().unwrap())
        };
        // The back-pointer is the anchor: a slab that does not name the
        // cache we reached it from is not this cache's to account for.
        if at(self.layout.slab_cache) != cache_addr {
            return None;
        }
        let base = at(self.layout.slab_base);
        let chunks = at(self.layout.slab_chunks);
        let refcnt = at(self.layout.slab_refcnt);
        if chunks == 0 || chunks > MAX_CHUNKS_PER_SLAB || refcnt > chunks {
            return None;
        }
        // The chunks have to tile the slab they claim to be in.
        let span = chunks.checked_mul(cache.chunksize)?;
        if span > cache.slabsize || base.checked_add(span).is_none() {
            return None;
        }

        let mut free = vec![0u64; (chunks as usize).div_ceil(64)];
        let mut bufctl = at(self.layout.slab_head);
        let mut freed = 0;
        while bufctl != 0 {
            freed += 1;
            if freed > chunks {
                return None;
            }
            let buf = match cache.hashed() {
                true => self.read(bufctl + self.layout.bufctl_addr)?,
                // A raw cache chains through a bufctl embedded in the
                // buffer itself, at a distance the cache records.
                false => bufctl.checked_sub(cache.bufctl)?,
            };
            // A free buffer has to be one of this slab's chunks, on a
            // chunk boundary.
            let offset = buf.checked_sub(base)?;
            if offset >= span || offset % cache.chunksize != 0 {
                return None;
            }
            let chunk = offset / cache.chunksize;
            if free[chunk as usize / 64] >> (chunk % 64) & 1 == 1 {
                // The same chunk twice is a looped freelist.
                return None;
            }
            free[chunk as usize / 64] |= 1 << (chunk % 64);
            bufctl = self.read(bufctl + self.layout.bufctl_next)?;
        }
        // The cross-check.
        if freed != chunks - refcnt {
            return None;
        }
        if freed == 0 {
            free.clear();
        }
        Some(Slab {
            base,
            chunksize: cache.chunksize,
            chunks: chunks as u32,
            cache: index,
            free,
        })
    }

    /// Whether a hashed cache's hash table describes the same allocated
    /// set its slabs do.
    ///
    /// For a `UMF_HASH` cache the allocated buffers are exactly the
    /// entries of this table, derived from bufctls the slab walk never
    /// read — so agreeing with the freelist arithmetic is a second,
    /// independent reading of the same population.
    fn hash_agrees(&self, cache_addr: u64, cache: &Cache, slabs: &[Slab]) -> bool {
        let (Some(table), Some(mask)) = (
            self.read(cache_addr + self.layout.cache_hash_table),
            self.read(cache_addr + self.layout.cache_hash_mask),
        ) else {
            return false;
        };
        let buckets = mask + 1;
        if table == 0 || buckets > MAX_HASH_BUCKETS || !buckets.is_power_of_two() {
            return false;
        }
        // The cache's slabs by address, so each entry finds its own by
        // bisection. Scanning them instead is quadratic in a cache
        // whose chunk fills a slab — a real target has tens of
        // thousands of those, one buffer each.
        let mut spans: Vec<(u64, u64)> = slabs.iter().map(|s| (s.base, s.end())).collect();
        spans.sort_unstable();

        let mut entries = 0u64;
        for bucket in 0..buckets {
            let Some(mut bufctl) = self.read(table + bucket * 8) else {
                return false;
            };
            while bufctl != 0 {
                entries += 1;
                if entries > cache.live {
                    return false;
                }
                let (Some(buf), Some(next)) = (
                    self.read(bufctl + self.layout.bufctl_addr),
                    self.read(bufctl + self.layout.bufctl_next),
                ) else {
                    return false;
                };
                // Every allocated buffer must be a chunk of one of this
                // cache's own slabs.
                let above = spans.partition_point(|&(base, _)| base <= buf);
                let found = above.checked_sub(1).is_some_and(|i| {
                    let (base, end) = spans[i];
                    buf < end && (buf - base) % cache.chunksize == 0
                });
                if !found {
                    return false;
                }
                bufctl = next;
            }
        }
        entries == cache.live
    }

    /// Drop any slab whose chunks overlap one already accepted. Two
    /// readings of the same memory cannot both be right, and which is
    /// wrong is exactly what the walk cannot tell.
    fn drop_overlaps(&mut self) {
        let mut end = 0;
        let mut overlaps = 0;
        self.slabs.retain(|slab| {
            if slab.base < end {
                overlaps += 1;
                return false;
            }
            end = slab.end();
            true
        });
        if overlaps > 0 {
            self.stats.overlaps = overlaps;
            self.note(format!("{overlaps} overlapping slab(s) dropped"));
            // The per-cache counts described a population that included
            // them, so they no longer describe this one.
            self.recount();
        }
    }

    /// Rebuild the per-cache counts from the slabs actually kept.
    fn recount(&mut self) {
        for cache in &mut self.caches {
            cache.slabs = 0;
            cache.live = 0;
            cache.freed = 0;
        }
        for slab in &self.slabs {
            let freed: u64 = slab.free.iter().map(|w| w.count_ones() as u64).sum();
            let cache = &mut self.caches[slab.cache as usize];
            cache.slabs += 1;
            cache.live += slab.chunks as u64 - freed;
            cache.freed += freed;
        }
        self.stats.slabs = self.slabs.len();
        self.stats.live_chunks = self.caches.iter().map(|c| c.live).sum();
        self.stats.freed_chunks = self.caches.iter().map(|c| c.freed).sum();
        self.stats.live_bytes = self.caches.iter().map(|c| c.live * c.chunksize).sum();
    }

    fn decline_cache(&mut self, addr: u64, why: &str) {
        self.stats.caches_declined += 1;
        self.note(format!("cache {addr:#x}: {why}"));
    }

    fn note(&mut self, note: String) {
        if self.stats.notes.len() < MAX_NOTES {
            self.stats.notes.push(note);
        }
    }

    fn read(&self, addr: u64) -> Option<u64> {
        self.target.read_u64(addr).ok()
    }

    /// A `char[32]` cache name, up to its NUL.
    fn read_name(&self, addr: u64) -> Option<String> {
        let bytes = self.target.read_bytes(addr, 32).ok()?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }
}

/// libumem's malloc tag magics (`umem_impl.h`), each recognizable in
/// the encoded status word and each naming a header size.
pub(crate) const MALLOC_MAGIC: u32 = 0x3a10c000;
const MALLOC_SECOND_MAGIC: u32 = 0x16ba7000;
const MALLOC_OVERSIZE_MAGIC: u32 = 0x06e47000;
const MEMALIGN_MAGIC: u32 = 0x3e3a1000;

/// Which of libumem's malloc headers precedes a pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagKind {
    /// An 8-byte header, for an allocation with no alignment demands
    /// beyond 8.
    Malloc,
    /// A 16-byte header, which is what 16-byte alignment costs on LP64.
    /// The first of the two words is left as it was found, so only the
    /// second is a tag.
    Second,
    /// Two tags, the second carrying the high word of a size that did
    /// not fit the 32-bit field — over 4 GiB, which is the only thing
    /// that puts an allocation here.
    Oversize,
    /// Two tags of its own, written by `memalign` rather than `malloc`.
    /// The alignment is paid for inside the arena's own segment rather
    /// than by moving the pointer away from its tags, so the pointer's
    /// allocation still begins immediately before them.
    Memalign,
}

/// libumem's own record of what a pointer is: the header its `malloc`
/// shim writes immediately before every pointer it returns.
///
/// This corroborates a pointer without walking anything — the magic has
/// to be one of four values and the size has to fit the chunk holding
/// it — which is a cheap second opinion beside [`UmemHeap::locate`],
/// and the only one available for an allocation from an arena the walk
/// does not cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MallocTag {
    pub kind: TagKind,
    /// The whole allocation, tags included, as the tag records it —
    /// what was handed to the allocator beneath the shim rather than
    /// what the caller asked for.
    pub total: u64,
    /// Where the allocation starts, which is where its first tag does:
    /// every spelling puts its tags immediately before the pointer it
    /// hands out, so this is 8 or 16 bytes below it.
    pub base: u64,
}

/// Read the malloc header immediately before `ptr`, if one is there.
///
/// `None` means the bytes are not a header: `ptr` is not a `malloc`
/// pointer, or not a pointer at all.
pub fn malloc_tag<T: Target>(target: &T, ptr: u64) -> Option<MallocTag> {
    let low = ptr.checked_sub(8)?;
    let size = target.read_u32(low).ok()?;
    let status = target.read_u32(low + 4).ok()?;
    // A size the 32-bit field cannot hold rides in a second tag ahead
    // of the first, and which magic that tag carries is what tells the
    // two spellings that use one apart: `malloc` marks its high word
    // with the ordinary magic, `memalign` repeats its own.
    let wide = |magic: u32| {
        let base = ptr.checked_sub(16)?;
        let high = target.read_u32(base).ok()?;
        let status = target.read_u32(base + 4).ok()?;
        (status.wrapping_add(high) == magic).then_some((base, (high as u64) << 32 | size as u64))
    };
    // The status is the magic with the size subtracted out, so that a
    // free of the wrong size cannot pass for a valid header.
    let (kind, base, total) = match status.wrapping_add(size) {
        MALLOC_MAGIC => (TagKind::Malloc, low, size as u64),
        // The word ahead of this one is whatever the buffer held
        // before: `malloc` steps over it rather than writing it, so
        // only the allocation's start follows from it being there.
        MALLOC_SECOND_MAGIC => (TagKind::Second, ptr.checked_sub(16)?, size as u64),
        MALLOC_OVERSIZE_MAGIC => {
            let (base, total) = wide(MALLOC_MAGIC)?;
            (TagKind::Oversize, base, total)
        }
        MEMALIGN_MAGIC => {
            let (base, total) = wide(MEMALIGN_MAGIC)?;
            (TagKind::Memalign, base, total)
        }
        _ => return None,
    };
    Some(MallocTag { kind, total, base })
}

/// The pointer libumem handed out of the block based at `base`, and
/// the size the program asked for, read from the malloc header at that
/// base rather than from before some address inside the block. That is
/// what turns the tag from a check on a pointer into an answer about
/// any address the block contains.
///
/// The shim's headers are 8 or 16 bytes and each records the whole
/// allocation, header included, so the one this block carries is the
/// one whose own base is this block's — which tells the two spellings
/// apart without knowing in advance which the allocation used. A header
/// claiming more than the block holds is not this block's either.
///
/// `None` means no header is there: `free` scrubs the word one decodes
/// from, and an allocation that never went through the shim never had
/// one.
fn header<T: Target>(target: &T, base: u64, block: u64) -> Option<(u64, u64)> {
    [8, 16].into_iter().find_map(|header| {
        let tag = malloc_tag(target, base + header)?;
        let requested = tag.total.checked_sub(header)?;
        (tag.base == base && tag.total <= block).then_some((base + header, requested))
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use proc::{Regs, SymbolBuf};

    use std::collections::BTreeMap;

    /// A target holding one run of bytes, with libumem's globals
    /// resolving into it — everything the walk reads and nothing else.
    pub(crate) struct Fake {
        base: u64,
        bytes: Vec<u8>,
        symbols: BTreeMap<String, u64>,
        /// An address range that reads as unmapped, however much of the
        /// run it covers: a page the core did not dump.
        hole: Range<u64>,
    }

    impl Fake {
        pub(crate) fn new(base: u64, len: usize) -> Self {
            Fake {
                base,
                bytes: vec![0; len],
                symbols: BTreeMap::new(),
                hole: 0..0,
            }
        }

        pub(crate) fn put_u64(&mut self, addr: u64, value: u64) {
            let at = (addr - self.base) as usize;
            self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }

        pub(crate) fn put_u32(&mut self, addr: u64, value: u32) {
            let at = (addr - self.base) as usize;
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn put_str(&mut self, addr: u64, s: &str) {
            let at = (addr - self.base) as usize;
            self.bytes[at..at + s.len()].copy_from_slice(s.as_bytes());
        }

        fn symbol(&mut self, name: &str, addr: u64) {
            self.symbols.insert(format!("{LIBUMEM}`{name}"), addr);
        }
    }

    impl Target for Fake {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            let end = addr + len;
            if addr < self.hole.end && end > self.hole.start {
                return Err(proc::Error::unmapped(addr, len));
            }
            let start = addr
                .checked_sub(self.base)
                .filter(|&s| s + len <= self.bytes.len() as u64)
                .ok_or_else(|| proc::Error::unmapped(addr, len))?;
            Ok(&self.bytes[start as usize..(start + len) as usize])
        }

        fn lookup_symbol_by_addr(&self, _: u64) -> Option<SymbolBuf> {
            None
        }

        fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
            let &addr = self.symbols.get(name)?;
            Some(SymbolBuf {
                name: name.to_string(),
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: addr,
                st_size: 8,
            })
        }

        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            Ok(Vec::new())
        }

        fn mappings(&self) -> proc::Result<proc::Mappings> {
            unimplemented!("the umem walk never asks")
        }

        fn lwps(&self) -> proc::Result<Vec<proc::LwpInfo>> {
            unimplemented!("the umem walk never asks")
        }

        fn tls_var_addr(&self, _: &Regs, _: &SymbolBuf) -> proc::Result<Option<u64>> {
            unimplemented!("the umem walk never asks")
        }
    }

    const BASE: u64 = 0x1000_0000;
    const READY: u64 = BASE;
    const ANCHOR: u64 = BASE + 0x100;
    /// Where the caches are laid, one every 0x400 bytes.
    const CACHES: u64 = BASE + 0x1000;
    /// Where the slabs are laid, one every 0x100 bytes.
    const SLABS: u64 = BASE + 0x4000;
    /// Where hashed caches' external bufctls are laid, 24 bytes each.
    const BUFCTLS: u64 = BASE + 0x8000;
    /// Where the buffers themselves are, one slab's worth every 0x1000.
    pub(crate) const BUFFERS: u64 = BASE + 0x10_0000;

    /// A hashed cache's `cache_hash_mask`: four buckets, so a walk
    /// that reads the wrong number of them comes up short.
    const HASH_MASK: u64 = 3;

    /// One slab to lay: which chunks are free, in freelist order.
    pub(crate) struct SlabSpec {
        pub(crate) base: u64,
        pub(crate) chunks: u64,
        pub(crate) free: Vec<u64>,
    }

    /// A target with `umem_ready` set and an empty cache list, ready
    /// for caches to be laid into.
    pub(crate) fn fake() -> Fake {
        let mut f = Fake::new(BASE, 0x20_0000);
        f.symbol("umem_ready", READY);
        f.symbol("umem_null_cache", ANCHOR);
        f.put_u32(READY, UMEM_READY);
        f.put_u64(ANCHOR + LP64.cache_next, ANCHOR);
        f.put_u64(ANCHOR + LP64.cache_prev, ANCHOR);
        f
    }

    /// Lay a cache and its slabs, and splice it into the list between
    /// the anchor and whatever is already there.
    ///
    /// Free chunks are chained the way the cache's flags say: through a
    /// bufctl embedded at `bufsize` into the buffer for a raw cache, or
    /// through external bufctls for a hashed one — which also get a
    /// hash table holding every allocated buffer.
    pub(crate) fn cache(
        f: &mut Fake,
        index: u64,
        name: &str,
        chunksize: u64,
        flags: u32,
        slabs: &[SlabSpec],
    ) {
        let addr = CACHES + index * 0x400;
        // Big enough to hold the largest slab laid below, the way a
        // real cache's is chosen to fit its chunks -- and exactly the
        // size of one chunk where a chunk is bigger than a page, which
        // is what every large cache on a real target looks like.
        let slabsize = slabs
            .iter()
            .map(|s| s.chunks * chunksize)
            .max()
            .unwrap_or(0x1000)
            .max(0x1000)
            .max(chunksize);
        f.put_str(addr + LP64.cache_name, name);
        // Buffer and chunk are the same size unless a debugging
        // feature widened the chunk; the small caches of a real target
        // are all this way.
        f.put_u64(addr + LP64.cache_bufsize, chunksize);
        f.put_u64(addr + LP64.cache_chunksize, chunksize);
        f.put_u64(addr + LP64.cache_slabsize, slabsize);
        // A hashed cache's bufctls are outside its buffers, so the
        // distance is meaningless there and libumem leaves it zero.
        let bufctl = match flags & UMF_HASH != 0 {
            true => 0,
            false => chunksize - 8,
        };
        f.put_u64(addr + LP64.cache_bufctl, bufctl);
        f.put_u32(addr + LP64.cache_flags, flags);

        // Splice in: anchor -> this -> whatever the anchor named.
        let next = f.read_u64(ANCHOR + LP64.cache_next).unwrap();
        f.put_u64(ANCHOR + LP64.cache_next, addr);
        f.put_u64(addr + LP64.cache_prev, ANCHOR);
        f.put_u64(addr + LP64.cache_next, next);
        f.put_u64(next + LP64.cache_prev, addr);

        let nullslab = addr + LP64.cache_nullslab;
        f.put_u64(nullslab + LP64.slab_cache, addr);
        f.put_u64(nullslab + LP64.slab_next, nullslab);
        f.put_u64(nullslab + LP64.slab_prev, nullslab);

        let mut allocated = Vec::new();
        let mut bufctls = 0;
        for (i, spec) in slabs.iter().enumerate() {
            let slab = SLABS + (index * 16 + i as u64) * 0x100;
            f.put_u64(slab + LP64.slab_cache, addr);
            f.put_u64(slab + LP64.slab_base, spec.base);
            f.put_u64(slab + LP64.slab_chunks, spec.chunks);
            f.put_u64(
                slab + LP64.slab_refcnt,
                spec.chunks - spec.free.len() as u64,
            );

            // The freelist, in the order given.
            let mut head = 0;
            for &chunk in spec.free.iter().rev() {
                let buf = spec.base + chunk * chunksize;
                let bufctl = match flags & UMF_HASH != 0 {
                    true => {
                        let bc = BUFCTLS + bufctls * 24;
                        bufctls += 1;
                        f.put_u64(bc + LP64.bufctl_addr, buf);
                        bc
                    }
                    false => buf + chunksize - 8,
                };
                f.put_u64(bufctl + LP64.bufctl_next, head);
                head = bufctl;
            }
            f.put_u64(slab + LP64.slab_head, head);
            allocated.extend(
                (0..spec.chunks)
                    .filter(|c| !spec.free.contains(c))
                    .map(|c| spec.base + c * chunksize),
            );

            // Append to the slab list.
            let last = f.read_u64(nullslab + LP64.slab_prev).unwrap();
            f.put_u64(last + LP64.slab_next, slab);
            f.put_u64(slab + LP64.slab_prev, last);
            f.put_u64(slab + LP64.slab_next, nullslab);
            f.put_u64(nullslab + LP64.slab_prev, slab);
        }

        if flags & UMF_HASH != 0 {
            // Every allocated buffer's bufctl, spread over four
            // buckets: the walk checks membership and count rather
            // than the hash function, but a table it reads only part
            // of must not add up.
            let table = BUFCTLS + 0x4000;
            let mask = HASH_MASK;
            f.put_u64(addr + LP64.cache_hash_table, table);
            f.put_u64(addr + LP64.cache_hash_mask, mask);
            let mut heads = vec![0u64; (mask + 1) as usize];
            for (i, buf) in allocated.iter().enumerate() {
                let bc = BUFCTLS + 0x2000 + i as u64 * 24;
                let bucket = (i as u64 & mask) as usize;
                f.put_u64(bc + LP64.bufctl_addr, *buf);
                f.put_u64(bc + LP64.bufctl_next, heads[bucket]);
                heads[bucket] = bc;
            }
            for (bucket, head) in heads.into_iter().enumerate() {
                f.put_u64(table + bucket as u64 * 8, head);
            }
        }
    }

    /// The ordinary case: two raw caches, some chunks free.
    fn two_caches() -> Fake {
        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_64",
            64,
            0,
            &[
                SlabSpec {
                    base: BUFFERS,
                    chunks: 8,
                    free: vec![1, 5],
                },
                SlabSpec {
                    base: BUFFERS + 0x1000,
                    chunks: 8,
                    free: vec![],
                },
            ],
        );
        cache(
            &mut f,
            1,
            "umem_alloc_128",
            128,
            0,
            &[SlabSpec {
                base: BUFFERS + 0x2000,
                chunks: 4,
                free: vec![3],
            }],
        );
        f
    }

    #[test]
    fn test_a_target_without_libumem_has_no_index() {
        let mut f = fake();
        f.symbols.clear();
        assert!(UmemHeap::build(&f).is_none());
    }

    #[test]
    fn test_an_allocator_not_yet_ready_is_not_read() {
        let mut f = two_caches();
        f.put_u32(READY, 2);
        assert!(UmemHeap::build(&f).is_none());
    }

    #[test]
    fn test_an_empty_cache_list_is_no_index() {
        let f = fake();
        assert!(UmemHeap::build(&f).is_none());
    }

    #[test]
    fn test_every_chunk_gets_the_verdict_its_freelist_says() {
        let heap = UmemHeap::build(&two_caches()).expect("the walk built an index");
        assert!(heap.violations().is_empty(), "{:?}", heap.violations());

        let stats = heap.stats();
        assert_eq!((stats.caches, stats.caches_declined), (2, 0));
        assert_eq!((stats.slabs, stats.slabs_declined), (3, 0));
        assert_eq!((stats.live_chunks, stats.freed_chunks), (17, 3));
        // Chunk stride, per cache, over the live chunks: 14 of 64 and
        // 3 of 128.
        assert_eq!(stats.live_bytes, 14 * 64 + 3 * 128);
        assert!(!stats.incomplete());

        // A freed chunk, an allocated one, and an address inside each
        // rather than at its base.
        let cache = |name: &str| {
            heap.caches()
                .iter()
                .position(|c| c.name == name)
                .expect("the cache is in the index")
        };
        let alloc_64 = cache("umem_alloc_64");
        assert_eq!(
            heap.locate(BUFFERS + 64),
            Liveness::Freed {
                buffer: BUFFERS + 64..BUFFERS + 128,
                cache: alloc_64,
            }
        );
        assert_eq!(
            heap.locate(BUFFERS + 64 + 63),
            Liveness::Freed {
                buffer: BUFFERS + 64..BUFFERS + 128,
                cache: alloc_64,
            }
        );
        assert_eq!(
            heap.locate(BUFFERS + 130),
            Liveness::Live {
                buffer: BUFFERS + 128..BUFFERS + 192,
                cache: alloc_64,
            }
        );
        assert_eq!(
            heap.locate(BUFFERS + 0x2000 + 3 * 128),
            Liveness::Freed {
                buffer: BUFFERS + 0x2000 + 384..BUFFERS + 0x2000 + 512,
                cache: cache("umem_alloc_128"),
            }
        );

        // Past the last chunk of a slab is the slab's own metadata and
        // colouring, which no chunk covers and nothing claims.
        assert_eq!(heap.locate(BUFFERS + 8 * 64), Liveness::Unknown);
        assert_eq!(heap.locate(BUFFERS - 1), Liveness::Unknown);
        assert_eq!(heap.locate(0), Liveness::Unknown);

        // What an enumeration differential diffs: every chunk of one
        // liveness, in address order, spelled exactly -- bounds and
        // all. A chunk off by one, or one whose end does not follow
        // from its start, is the whole failure a differential exists
        // to catch, so nothing here is asserted by count alone.
        let chunk = |start: u64, size: u64| start..start + size;
        let freed: Vec<Range<u64>> = heap.freed_buffers().collect();
        assert_eq!(
            freed,
            [
                chunk(BUFFERS + 64, 64),
                chunk(BUFFERS + 5 * 64, 64),
                chunk(BUFFERS + 0x2000 + 3 * 128, 128),
            ]
        );
        let live: Vec<Range<u64>> = heap.live_buffers().collect();
        let want: Vec<Range<u64>> = (0..8)
            .filter(|i| ![1, 5].contains(i))
            .map(|i| chunk(BUFFERS + i * 64, 64))
            .chain((0..8).map(|i| chunk(BUFFERS + 0x1000 + i * 64, 64)))
            .chain((0..3).map(|i| chunk(BUFFERS + 0x2000 + i * 128, 128)))
            .collect();
        assert_eq!(live, want);
    }

    /// A cache whose buffer is shorter than its stride: the slack past
    /// each buffer's end is the allocator's own — a raw cache keeps the
    /// bufctl of a free buffer there — so no allocation covers it, and
    /// an address in it is as much a miss as one between two slabs.
    /// umem's own caches are all this shape (`umem_bufctl_cache` serves
    /// 24 bytes on a 32-byte stride), which is where an answer of "in a
    /// chunk" rather than "in a buffer" would first be wrong.
    #[test]
    fn test_the_slack_past_a_buffers_end_is_no_allocation() {
        let mut f = two_caches();
        let cache = CACHES;
        f.put_u64(cache + LP64.cache_bufsize, 48);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        let alloc_64 = heap
            .caches()
            .iter()
            .position(|c| c.addr == cache)
            .expect("the cache is in the index");

        assert_eq!(
            heap.locate(BUFFERS + 47),
            Liveness::Live {
                buffer: BUFFERS..BUFFERS + 48,
                cache: alloc_64,
            }
        );
        assert_eq!(heap.locate(BUFFERS + 48), Liveness::Unknown);
        assert_eq!(heap.locate(BUFFERS + 63), Liveness::Unknown);
        // The next chunk along starts a buffer of its own, which the
        // slack before it is no part of.
        assert_eq!(
            heap.locate(BUFFERS + 64),
            Liveness::Freed {
                buffer: BUFFERS + 64..BUFFERS + 112,
                cache: alloc_64,
            }
        );

        // What an enumeration yields is the buffer too, so a
        // differential against another reader compares like with like.
        assert_eq!(heap.live_buffers().next(), Some(BUFFERS..BUFFERS + 48));
        // The accounting still counts chunks and the stride they cost:
        // the slack is footprint the cache paid for, whoever owns it.
        assert_eq!(heap.stats().live_bytes, 14 * 64 + 3 * 128);
    }

    #[test]
    fn test_a_hashed_cache_is_checked_against_its_hash_table() {
        // Eight chunks over four buckets, so a table read short by a
        // bucket is a table that has lost entries. The slab is
        // *coloured* -- its buffers start a little way into it, as a
        // real slab's do -- so that every offset the walk computes has
        // to be taken from the slab's own base rather than from
        // anything that happens to be chunk-aligned.
        const COLOUR: u64 = 16;
        const SLAB_BASE: u64 = BUFFERS + COLOUR;
        const CHUNKS: u64 = 8;
        let hashed = || {
            let mut f = fake();
            cache(
                &mut f,
                0,
                "umem_alloc_4096",
                4096,
                UMF_HASH,
                &[SlabSpec {
                    base: SLAB_BASE,
                    chunks: CHUNKS,
                    free: vec![2],
                }],
            );
            f
        };
        let heap = UmemHeap::build(&hashed()).expect("the walk built an index");
        assert_eq!(heap.stats().live_chunks, 7);
        assert!(heap.caches()[0].hashed());
        assert!(matches!(
            heap.locate(SLAB_BASE + 2 * 4096),
            Liveness::Freed { .. }
        ));
        assert!(matches!(heap.locate(SLAB_BASE), Liveness::Live { .. }));

        // A table naming a buffer that is in no slab of this cache is a
        // second reading that disagrees with the first, so neither is
        // believed and the cache is declined whole. The address one
        // past the last chunk is the one worth naming: it is where the
        // slab stops, it is chunk-aligned from the base, and only the
        // bound itself excludes it.
        for buf in [BUFFERS + 0x9000, SLAB_BASE + CHUNKS * 4096] {
            let mut f = hashed();
            f.put_u64(BUFCTLS + 0x2000 + LP64.bufctl_addr, buf);
            assert!(
                UmemHeap::build(&f).is_none(),
                "the only cache should have declined for {buf:#x}"
            );
        }

        // So does a table the walk reads only part of: half the
        // buckets is half the entries, and the count no longer adds
        // up. A mask that is not one less than a power of two is not a
        // mask at all and is refused on its own account -- including
        // the one that names *more* buckets than the table has, where
        // the empty tail leaves the count adding up perfectly well.
        for mask in [HASH_MASK / 2, HASH_MASK - 1, HASH_MASK + 1] {
            let mut f = hashed();
            f.put_u64(CACHES + LP64.cache_hash_mask, mask);
            assert!(UmemHeap::build(&f).is_none(), "mask {mask}");
        }
    }

    #[test]
    fn test_a_slab_whose_freelist_and_refcnt_disagree_is_declined() {
        let mut f = two_caches();
        // Two chunks are on the freelist; claim all eight are in use.
        f.put_u64(SLABS + LP64.slab_refcnt, 8);
        let heap = UmemHeap::build(&f).expect("the other slabs still walk");

        assert_eq!(heap.stats().slabs_declined, 1);
        assert!(heap.stats().incomplete());
        assert!(heap.stats().notes.iter().any(|n| n.contains("declined")));
        // A declined slab's chunks are in no verdict at all: silence,
        // not a guess either way.
        assert_eq!(heap.locate(BUFFERS + 64), Liveness::Unknown);
        assert_eq!(heap.locate(BUFFERS + 128), Liveness::Unknown);
        // Its cache keeps the slabs that did walk.
        let cache = &heap.caches()[heap
            .caches()
            .iter()
            .position(|c| c.name == "umem_alloc_64")
            .unwrap()];
        assert_eq!((cache.slabs, cache.slabs_declined), (1, 1));
        assert!(heap.violations().is_empty(), "{:?}", heap.violations());
    }

    #[test]
    fn test_a_slab_that_names_another_cache_is_declined() {
        let mut f = two_caches();
        f.put_u64(SLABS + LP64.slab_cache, CACHES + 0x400);
        let heap = UmemHeap::build(&f).expect("the other slabs still walk");
        assert_eq!(heap.stats().slabs_declined, 1);
        assert_eq!(heap.locate(BUFFERS + 128), Liveness::Unknown);
    }

    #[test]
    fn test_a_free_buffer_off_its_chunk_boundary_declines_the_slab() {
        let mut f = two_caches();
        // Move the first freelist entry's buffer a byte off its chunk.
        f.put_u64(SLABS + LP64.slab_head, BUFFERS + 64 + 1 + 64 - 8);
        let heap = UmemHeap::build(&f).expect("the other slabs still walk");
        assert_eq!(heap.stats().slabs_declined, 1);
    }

    #[test]
    fn test_a_looping_freelist_declines_the_slab() {
        let mut f = two_caches();
        // Chunk 1's bufctl points back at itself.
        let bufctl = BUFFERS + 64 + 64 - 8;
        f.put_u64(bufctl + LP64.bufctl_next, bufctl);
        let heap = UmemHeap::build(&f).expect("the other slabs still walk");
        assert_eq!(heap.stats().slabs_declined, 1);
    }

    /// A freelist that names one chunk twice and is *the right length
    /// anyway*: the refcnt cross-check is satisfied and every entry is
    /// on a chunk boundary, so only noticing the repeat declines it. A
    /// walk that missed it would hand back a free set with a chunk
    /// missing from it and no sign anything went wrong.
    ///
    /// It takes a hashed cache to build: a raw cache's bufctl address
    /// *is* its buffer's, so no two entries can name one chunk.
    #[test]
    fn test_a_freelist_that_repeats_a_chunk_is_declined() {
        let mut f = two_caches();
        cache(
            &mut f,
            2,
            "umem_alloc_4096",
            4096,
            UMF_HASH,
            &[SlabSpec {
                base: BUFFERS + 0x4000,
                chunks: 8,
                free: vec![1, 2, 3],
            }],
        );
        // The freelist is laid tail first, so its last entry is the
        // first bufctl; point that at chunk 2's buffer as well.
        f.put_u64(BUFCTLS + LP64.bufctl_addr, BUFFERS + 0x4000 + 2 * 4096);

        let heap = UmemHeap::build(&f).expect("the raw caches still walk");
        let stats = heap.stats();
        assert_eq!(stats.slabs_declined, 1);
        // With no slab left, the cache's hash table describes a
        // population its slabs do not, so it goes too.
        assert_eq!(stats.caches_declined, 1);
        assert!(heap.caches().iter().all(|c| c.name != "umem_alloc_4096"));
    }

    /// The freelist bounds every walk reads from it: an entry outside
    /// the slab's own chunks, and one so far out that believing it
    /// would index past the bitmap.
    #[test]
    fn test_a_free_buffer_outside_the_slab_declines_it() {
        for buf in [BUFFERS + 8 * 64, BUFFERS + 0x8000] {
            let mut f = two_caches();
            f.put_u64(SLABS + LP64.slab_head, buf + 64 - 8);
            let heap = UmemHeap::build(&f).expect("the other slabs still walk");
            assert_eq!(heap.stats().slabs_declined, 1, "buffer at {buf:#x}");
        }
    }

    /// A slab with nothing allocated in it -- a fresh one, or one
    /// about to be destroyed. Every chunk is free and the walk must
    /// say so rather than treating a full freelist as a corrupt one.
    #[test]
    fn test_a_wholly_free_slab_is_all_freed_chunks() {
        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_64",
            64,
            0,
            &[SlabSpec {
                base: BUFFERS,
                chunks: 4,
                free: vec![0, 1, 2, 3],
            }],
        );
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert_eq!(
            (heap.stats().live_chunks, heap.stats().freed_chunks),
            (0, 4)
        );
        assert_eq!(heap.stats().live_bytes, 0);
        for i in 0..4 {
            assert!(matches!(
                heap.locate(BUFFERS + i * 64),
                Liveness::Freed { .. }
            ));
        }
    }

    /// Every geometry a slab cannot have.
    ///
    /// Each case is staged on the fixture's second slab, which has
    /// nothing on its freelist, and moves the refcnt along with the
    /// chunk count where one implies the other — so exactly the guard
    /// named is the one with anything to say. A case that several
    /// guards would catch says nothing about any of them.
    #[test]
    fn test_impossible_slab_geometry_is_declined() {
        // The second slab of umem_alloc_64: eight chunks, all in use.
        const SLAB: u64 = SLABS + 0x100;
        let cases: [(&str, &[(u64, u64)]); 5] = [
            (
                "no chunks at all",
                &[(LP64.slab_chunks, 0), (LP64.slab_refcnt, 0)],
            ),
            (
                "more allocated than there are chunks",
                &[(LP64.slab_refcnt, 9)],
            ),
            (
                "chunks past the end of the slab",
                &[(LP64.slab_chunks, 65), (LP64.slab_refcnt, 65)],
            ),
            ("a base that overflows", &[(LP64.slab_base, u64::MAX - 8)]),
            (
                "more chunks than any slab may hold",
                &[
                    (LP64.slab_chunks, MAX_CHUNKS_PER_SLAB + 1),
                    (LP64.slab_refcnt, MAX_CHUNKS_PER_SLAB + 1),
                ],
            ),
        ];
        for (why, writes) in cases {
            let mut f = two_caches();
            // The last case is about the walk's own bound rather than
            // the cache's, so its slab is given room the cache would
            // otherwise deny it.
            if why.contains("any slab") {
                f.put_u64(CACHES + LP64.cache_slabsize, 1 << 27);
            }
            for &(field, value) in writes {
                f.put_u64(SLAB + field, value);
            }
            let heap = UmemHeap::build(&f).expect("the other slabs still walk");
            assert_eq!(heap.stats().slabs_declined, 1, "{why}");
        }

        // And the boundary itself: a slab of exactly as many chunks as
        // the bound allows is walked, not declined. It gets a fixture
        // of its own, since a slab this size covers every address the
        // others would have used.
        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_64",
            64,
            0,
            &[SlabSpec {
                base: BUFFERS,
                chunks: 1,
                free: vec![],
            }],
        );
        f.put_u64(CACHES + LP64.cache_slabsize, 1 << 27);
        f.put_u64(SLABS + LP64.slab_chunks, MAX_CHUNKS_PER_SLAB);
        f.put_u64(SLABS + LP64.slab_refcnt, MAX_CHUNKS_PER_SLAB);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert_eq!(heap.stats().slabs_declined, 0);
        assert_eq!(heap.stats().live_chunks, MAX_CHUNKS_PER_SLAB);
    }

    #[test]
    fn test_a_cache_that_serves_nothing_is_declined() {
        let mut f = two_caches();
        f.put_u64(CACHES + LP64.cache_bufsize, 0);
        let heap = UmemHeap::build(&f).expect("the other cache still walks");
        assert_eq!(heap.stats().caches_declined, 1);
    }

    /// A raw cache whose embedded bufctl would sit outside the buffer
    /// it belongs to describes a layout that cannot exist. A hashed
    /// cache keeps its bufctls elsewhere, so the same value there is
    /// ordinary -- libumem leaves it zero -- and must not decline.
    #[test]
    fn test_the_bufctl_distance_is_checked_only_where_it_is_used() {
        let mut f = two_caches();
        f.put_u64(CACHES + LP64.cache_bufctl, 64);
        let heap = UmemHeap::build(&f).expect("the other cache still walks");
        assert_eq!(heap.stats().caches_declined, 1);

        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_4096",
            4096,
            UMF_HASH,
            &[SlabSpec {
                base: BUFFERS,
                chunks: 2,
                free: vec![1],
            }],
        );
        f.put_u64(CACHES + LP64.cache_bufctl, 1 << 20);
        let heap = UmemHeap::build(&f).expect("a hashed cache does not use it");
        assert_eq!(heap.stats().caches_declined, 0);
        assert_eq!(heap.stats().live_chunks, 1);
    }

    #[test]
    fn test_a_cache_with_impossible_geometry_is_declined() {
        let mut f = two_caches();
        // A buffer bigger than the chunk that must hold it.
        f.put_u64(CACHES + LP64.cache_bufsize, 4096);
        let heap = UmemHeap::build(&f).expect("the other cache still walks");
        assert_eq!(heap.stats().caches_declined, 1);
        assert_eq!(heap.caches().len(), 1);
        assert_eq!(heap.caches()[0].name, "umem_alloc_128");
        // Nothing of the declined cache survives into a verdict.
        assert_eq!(heap.locate(BUFFERS + 128), Liveness::Unknown);
    }

    #[test]
    fn test_a_cache_list_that_does_not_link_back_is_refused() {
        let mut f = two_caches();
        // The list runs anchor -> alloc_128 -> alloc_64 -> anchor; make
        // the second entry's back-pointer skip the first.
        f.put_u64(CACHES + LP64.cache_prev, ANCHOR);
        assert!(UmemHeap::build(&f).is_none());
    }

    #[test]
    fn test_a_cache_list_cycle_is_bounded_and_refused() {
        let mut f = fake();
        // A cache whose next is itself, with a consistent back-pointer:
        // the walk has to bound the list rather than trust it to end.
        let addr = CACHES;
        f.put_u64(ANCHOR + LP64.cache_next, addr);
        f.put_u64(addr + LP64.cache_prev, ANCHOR);
        f.put_u64(addr + LP64.cache_next, addr);
        assert!(UmemHeap::build(&f).is_none());
    }

    /// A cache list that closes on itself *behind* the anchor: every
    /// back-pointer inverts its forward one, so nothing local is wrong
    /// and only counting the walk ends it.
    #[test]
    fn test_a_cache_list_that_never_reaches_the_anchor_is_bounded() {
        let mut f = two_caches();
        let (first, second) = (CACHES + 0x400, CACHES);
        // anchor -> first -> second -> first -> second -> ...
        f.put_u64(second + LP64.cache_next, first);
        f.put_u64(first + LP64.cache_prev, second);
        assert!(UmemHeap::build(&f).is_none());
    }

    /// The same for a cache's slab list. Nothing here says how long a
    /// real one is, so the walk carries its own bound; a list that
    /// closes behind the nullslab is the only thing that reaches it.
    #[test]
    fn test_a_slab_list_that_never_reaches_the_anchor_is_bounded() {
        let mut f = two_caches();
        let (first, second) = (SLABS, SLABS + 0x100);
        f.put_u64(second + LP64.slab_next, first);
        f.put_u64(first + LP64.slab_prev, second);
        let heap = UmemHeap::build(&f).expect("the other cache still walks");
        // The cache the runaway list belongs to is declined whole; the
        // one after it is untouched.
        assert_eq!(heap.stats().caches_declined, 1);
        assert_eq!(heap.caches().len(), 1);
        assert_eq!(heap.caches()[0].name, "umem_alloc_128");
    }

    /// A torn core can fail an invariant on every slab it has, and a
    /// note per slab would bury the answer in its own diagnostics. The
    /// cap holds; what it drops is counted all the same, which is why
    /// the counters and not the notes are what a consumer reads.
    #[test]
    fn test_the_decline_notes_are_capped() {
        let f = fake();
        let mut walk = Walk::new(&f, LP64);
        for i in 0..MAX_NOTES * 2 {
            walk.note(format!("note {i}"));
        }
        assert_eq!(walk.stats.notes.len(), MAX_NOTES);
        // The first are kept, not the last: what went wrong first is
        // what explains the rest.
        assert_eq!(walk.stats.notes[0], "note 0");
        assert_eq!(
            walk.stats.notes[MAX_NOTES - 1],
            format!("note {}", MAX_NOTES - 1)
        );
    }

    /// The self-check earns its keep only if it can fail, and the walk
    /// is built not to produce either failure -- so both are staged
    /// here by hand, over an index the walk would never hand back.
    #[test]
    fn test_the_self_check_catches_what_the_walk_should_never_produce() {
        let slab = |base: u64, chunks: u32, free: Vec<u64>| Slab {
            base,
            chunksize: 64,
            chunks,
            cache: 0,
            free,
        };
        let cache = Cache {
            addr: CACHES,
            name: "umem_alloc_64".to_string(),
            bufsize: 64,
            chunksize: 64,
            slabsize: 0x1000,
            flags: 0,
            slabs: 2,
            slabs_declined: 0,
            live: 8,
            freed: 0,
            bufctl: 56,
        };
        let sound = UmemHeap {
            caches: vec![cache.clone()],
            slabs: vec![slab(BUFFERS, 4, vec![]), slab(BUFFERS + 0x1000, 4, vec![])],
            stats: Stats::default(),
        };
        assert!(sound.violations().is_empty());

        // Two slabs claiming the same memory: neither reading can be
        // trusted, and which is wrong is what nothing here can tell.
        let overlapping = UmemHeap {
            slabs: vec![slab(BUFFERS, 4, vec![]), slab(BUFFERS + 128, 4, vec![])],
            ..UmemHeap {
                caches: vec![cache.clone()],
                slabs: Vec::new(),
                stats: Stats::default(),
            }
        };
        let found = overlapping.violations();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("overlap"), "{found:?}");

        // Slabs that touch exactly are not an overlap: a chunk ends
        // where the next begins.
        let abutting = UmemHeap {
            caches: vec![cache.clone()],
            slabs: vec![slab(BUFFERS, 4, vec![]), slab(BUFFERS + 256, 4, vec![])],
            stats: Stats::default(),
        };
        assert!(abutting.violations().is_empty());

        // A cache whose totals do not add up to its own slabs'.
        let miscounted = UmemHeap {
            caches: vec![Cache { live: 7, ..cache }],
            slabs: vec![slab(BUFFERS, 4, vec![]), slab(BUFFERS + 0x1000, 4, vec![])],
            stats: Stats::default(),
        };
        let found = miscounted.violations();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("umem_alloc_64"), "{found:?}");
    }

    #[test]
    fn test_unreadable_metadata_declines_rather_than_panics() {
        let mut f = two_caches();
        f.hole = SLABS..SLABS + 0x100;
        let heap = UmemHeap::build(&f).expect("the other cache still walks");
        assert!(heap.stats().incomplete());
        assert_eq!(heap.locate(BUFFERS + 128), Liveness::Unknown);

        // A hole over the cache list itself takes the whole index.
        let mut f = two_caches();
        f.hole = CACHES..CACHES + 0x400;
        assert!(UmemHeap::build(&f).is_none());
    }

    #[test]
    fn test_overlapping_slabs_are_dropped_and_counted() {
        let mut f = two_caches();
        // The second slab of umem_alloc_64 now tiles chunks the first
        // slab already claims, starting one chunk into it.
        f.put_u64(SLABS + 0x100 + LP64.slab_base, BUFFERS + 64);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert_eq!(heap.stats().overlaps, 1);
        assert!(heap.stats().incomplete());
        assert!(heap.violations().is_empty(), "{:?}", heap.violations());
        // The counts describe what is left, not what was walked --
        // the byte total with them, since it is derived from the
        // counts a second time rather than carried along with them.
        let alloc_64 = heap
            .caches()
            .iter()
            .find(|c| c.name == "umem_alloc_64")
            .unwrap();
        assert_eq!((alloc_64.slabs, alloc_64.live, alloc_64.freed), (1, 6, 2));
        assert_eq!(heap.stats().live_chunks, 6 + 3);
        assert_eq!(heap.stats().live_bytes, 6 * 64 + 3 * 128);
    }

    /// Write the tag libumem's malloc shim would have written before
    /// the pointer it handed out at `ptr`, recording `total` bytes —
    /// the whole allocation, its tags included.
    pub(crate) fn tag(f: &mut Fake, ptr: u64, magic: u32, total: u64) {
        f.put_u32(ptr - 8, total as u32);
        f.put_u32(ptr - 4, magic.wrapping_sub(total as u32));
    }

    /// Write the second tag the two wide spellings carry ahead of the
    /// first, holding the high word of a size the field could not.
    fn high_tag(f: &mut Fake, ptr: u64, magic: u32, total: u64) {
        let high = (total >> 32) as u32;
        f.put_u32(ptr - 16, high);
        f.put_u32(ptr - 12, magic.wrapping_sub(high));
    }

    /// An allocation is the block the walk found joined to the header
    /// its base carries: the header says what the program asked for and
    /// where the pointer it was given starts, so an address inside the
    /// block is an offset from *that* pointer rather than from the
    /// block. Where no header survives — which is every freed block,
    /// `free` having scrubbed it — the block itself is the answer.
    #[test]
    fn test_an_allocation_joins_the_block_to_its_header() {
        let mut f = two_caches();
        // Two live chunks of the 64-byte cache, one carrying each of
        // the header spellings, both for a 40-byte request.
        tag(&mut f, BUFFERS + 8, MALLOC_MAGIC, 48);
        tag(&mut f, BUFFERS + 128 + 16, MALLOC_SECOND_MAGIC, 56);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        let at = |addr| heap.allocation(&f, addr);
        let live = |size, offset| {
            Some(Allocation {
                live: true,
                size,
                offset,
            })
        };

        // The pointer the program was given is the allocation itself,
        // and an address past it is that far into it -- not into the
        // block, which starts 8 bytes lower.
        assert_eq!(at(BUFFERS + 8), live(Size::Requested(40), 0));
        assert_eq!(at(BUFFERS + 8 + 24), live(Size::Requested(40), 24));
        // The 16-byte spelling is found the same way, so the offset is
        // taken from 16 bytes into the block rather than from 8.
        assert_eq!(at(BUFFERS + 128 + 16), live(Size::Requested(40), 0));
        assert_eq!(at(BUFFERS + 128 + 24), live(Size::Requested(40), 8));

        // An address inside the header is in libumem's own memory,
        // which is no offset into the program's allocation at all.
        assert_eq!(at(BUFFERS + 4), live(Size::Block(64), 4));

        // A live block whose header was never written, and the freed
        // chunks, whose headers `free` scrubbed: the block is all
        // there is to measure, and the offset counts from its base.
        assert_eq!(at(BUFFERS + 192), live(Size::Block(64), 0));
        assert_eq!(
            at(BUFFERS + 64),
            Some(Allocation {
                live: false,
                size: Size::Block(64),
                offset: 0,
            })
        );
        assert_eq!(
            at(BUFFERS + 64 + 16),
            Some(Allocation {
                live: false,
                size: Size::Block(64),
                offset: 16,
            })
        );
    }

    /// A header is believed only where it is this block's own: one
    /// recording a different base, one claiming more than the block
    /// holds, and a `memalign` redirect that names no base at all are
    /// each declined on their own, leaving the block to answer.
    #[test]
    fn test_a_header_that_is_not_the_blocks_own_is_declined() {
        // One question of every staging: the address a believed
        // 8-byte header makes the allocation itself, which a declined
        // one leaves 8 bytes into the block.
        let block = Some(Allocation {
            live: true,
            size: Size::Block(64),
            offset: 8,
        });
        let staged = |write: &dyn Fn(&mut Fake)| {
            let mut f = two_caches();
            write(&mut f);
            let heap = UmemHeap::build(&f).expect("the walk built an index");
            heap.allocation(&f, BUFFERS + 8)
        };

        // Staged where it is the only thing wrong: the same header,
        // believed when it names this block and declined when it does
        // not.
        assert_eq!(
            staged(&|f| tag(f, BUFFERS + 8, MALLOC_MAGIC, 48)),
            Some(Allocation {
                live: true,
                size: Size::Requested(40),
                offset: 0,
            })
        );
        // 16 bytes in, the 8-byte spelling records the block as
        // starting 8 bytes late -- the discrimination that keeps one
        // spelling from passing for the other.
        assert_eq!(staged(&|f| tag(f, BUFFERS + 16, MALLOC_MAGIC, 48)), block);
        // A 64-byte block cannot hold a 200-byte allocation.
        assert_eq!(staged(&|f| tag(f, BUFFERS + 8, MALLOC_MAGIC, 200)), block);
    }

    /// An allocation from an arena the walk does not cover — oversize,
    /// memalign — is in no slab, and its header is then the only
    /// account of it there is. It answers for the pointer it precedes
    /// and for nothing else: no header, no answer, rather than a
    /// confident "unknown".
    #[test]
    fn test_an_allocation_outside_every_slab_answers_from_its_header() {
        const OUTSIDE: u64 = BASE + 0xE000;
        let mut f = two_caches();
        assert_eq!(
            UmemHeap::build(&f)
                .expect("the walk built an index")
                .locate(OUTSIDE),
            Liveness::Unknown,
            "the address the header must answer for alone is in a slab"
        );

        tag(&mut f, OUTSIDE, MALLOC_SECOND_MAGIC, 100);
        // An oversize allocation, whose size needs a second tag to
        // hold it -- being over 4 GiB is the only way to be here.
        let huge = 5 * 1024 * 1024 * 1024u64 + 16;
        tag(&mut f, OUTSIDE + 0x400, MALLOC_OVERSIZE_MAGIC, huge);
        high_tag(&mut f, OUTSIDE + 0x400, MALLOC_MAGIC, huge);
        // A `memalign` allocation, which is the whole of what this
        // arena is for and every one of tokio's task cells.
        tag(&mut f, OUTSIDE + 0x800, MEMALIGN_MAGIC, 1168);
        high_tag(&mut f, OUTSIDE + 0x800, MEMALIGN_MAGIC, 1168);

        let heap = UmemHeap::build(&f).expect("the walk built an index");
        let at = |addr| heap.allocation(&f, addr);
        let live = |size| {
            Some(Allocation {
                live: true,
                size: Size::Requested(size),
                offset: 0,
            })
        };
        assert_eq!(at(OUTSIDE), live(100 - 16));
        assert_eq!(at(OUTSIDE + 0x400), live(huge - 16));
        assert_eq!(at(OUTSIDE + 0x800), live(1168 - 16));
        // The tags speak for the pointer they precede; an address
        // inside the allocation has nothing in front of it to read.
        assert_eq!(at(OUTSIDE + 8), None);
        assert_eq!(at(OUTSIDE + 0xc00), None);
    }

    /// The tag libumem's malloc shim writes before every pointer it
    /// hands out, in each of its four spellings — and the base each
    /// one implies, which every spelling puts 8 or 16 bytes below the
    /// pointer rather than anywhere the tag has to name.
    #[test]
    fn test_the_malloc_tag_decodes_each_header() {
        let mut f = Fake::new(BASE, 0x1000);
        let ptr = BASE + 0x100;
        // The one-tag spellings: a size that fits the field, and no
        // word ahead of it that has to say anything.
        for (magic, total, kind, base) in [
            (MALLOC_MAGIC, 15, TagKind::Malloc, ptr - 8),
            (MALLOC_SECOND_MAGIC, 144, TagKind::Second, ptr - 16),
        ] {
            tag(&mut f, ptr, magic, total);
            assert_eq!(malloc_tag(&f, ptr), Some(MallocTag { kind, total, base }));
        }

        // The two-tag spellings: the size spans both words, and the
        // magic on the high one is what says which spelling wrote it.
        let huge = 5 * 1024 * 1024 * 1024u64 + 16;
        for (magic, high, total, kind) in [
            (MALLOC_OVERSIZE_MAGIC, MALLOC_MAGIC, huge, TagKind::Oversize),
            (MEMALIGN_MAGIC, MEMALIGN_MAGIC, 1168, TagKind::Memalign),
        ] {
            tag(&mut f, ptr, magic, total);
            high_tag(&mut f, ptr, high, total);
            assert_eq!(
                malloc_tag(&f, ptr),
                Some(MallocTag {
                    kind,
                    total,
                    base: ptr - 16,
                })
            );
            // A high word that does not corroborate the low one is no
            // header: the two are written together or not at all, so
            // one of them alone is bytes that happen to look like one.
            high_tag(&mut f, ptr, magic.wrapping_add(1), total);
            assert_eq!(malloc_tag(&f, ptr), None);
        }

        // The status word is the magic *minus the size*, so a header
        // whose size was overwritten no longer decodes -- which is the
        // point of encoding it that way.
        tag(&mut f, ptr, MALLOC_MAGIC, 15);
        f.put_u32(ptr - 8, 16);
        assert_eq!(malloc_tag(&f, ptr), None);
        f.put_u32(ptr - 4, 0);
        assert_eq!(malloc_tag(&f, ptr), None);
        assert_eq!(malloc_tag(&f, 0), None);
        assert_eq!(malloc_tag(&f, BASE + 0x9000), None);
    }
}

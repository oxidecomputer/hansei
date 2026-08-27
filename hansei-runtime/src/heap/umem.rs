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
//! The slab layer is not the whole allocator, though, and taking it
//! for the whole one is how almost everything free reads live: a free
//! travels only as far as the nearest layer that will keep it.
//!
//! - **The magazine layer.** A buffer freed into the magazine loaded
//!   on a CPU, into the one loaded before it, or into a full magazine
//!   in the depot is free — while the slab holding it goes on counting
//!   it allocated. On nexus that is 208,615 buffers against the 679 the
//!   slab layer calls free.
//! - **The threads' own caches.** A `UMF_PTC` cache's buffers can also
//!   be held per thread, in a list rooted in each thread's `ulwp_t` and
//!   chained through the first word of each buffer — the one layer no
//!   cache structure records, and so the one found by walking threads.
//! - **The arenas `malloc` allocates out of.** What is too big for the
//!   largest size class comes from the `umem_oversize` arena, and what
//!   is aligned more strictly than a cache promises from
//!   `umem_memalign` — every tokio task cell among them. Neither is in
//!   any slab, so only the arena's own segment list answers for them,
//!   and a freed one has somewhere to be freed *to*.
//!
//! What is left errs toward [`Live`], never toward wrongly [`Freed`]: a
//! buffer freed and handed straight back out is somebody else's live
//! allocation, and a layer that declined leaves its buffers reading the
//! way they read before it was walked at all.
//!
//! Every step validates before it believes, and a violation declines —
//! the slab, a cache's parked set, an arena, the cache, or the whole
//! index, whichever the violation scopes to. An index that declines
//! part of the target says so in its [`Stats`], because a walk that
//! quietly covered less than it claims would turn a missing verdict
//! into a wrong one.
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

/// `UMF_NOMAGAZINE`: the cache has no magazine layer, so every free
/// goes straight to a slab and there is nothing beneath it to walk.
const UMF_NOMAGAZINE: u32 = 0x20;

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

/// How many per-CPU caches one cache's `cache_cpu[]` may hold. A real
/// target sizes it to the machine's CPU count.
const MAX_CPUS: u64 = 1 << 12;

/// How many rounds one magazine may hold. libumem's largest magazine
/// type takes 143.
const MAX_ROUNDS: i32 = 1 << 12;

/// How many magazines the depot's full list may chain, before the walk
/// calls the list looped rather than long.
const MAX_MAGAZINES: u64 = 1 << 22;

/// How many buffers one thread's per-thread cache may chain. Bounded by
/// `umem_ptc_size` in the target (a megabyte by default, so a hundred
/// thousand of the smallest buffers); this bounds a cycle.
const MAX_PTC_BUFFERS: usize = 1 << 20;

/// `NTMEMBASE`: how many roots a thread's `tmem_t` holds, one per size
/// class libumem caches per-thread. The array is `{ size_t tm_size;
/// void *tm_roots[NTMEMBASE]; }`, so the first root sits one word in.
const NTMEMBASE: u64 = 16;

/// `UMF_PTC`: the cache's buffers may also be held in a thread's own
/// cache, which is the layer no per-cache structure records.
const UMF_PTC: u32 = 0x800;

/// How many segments one arena's list may hold.
const MAX_SEGS: usize = 1 << 22;

/// `vs_type` values (`sys/vmem.h`): what a segment in an arena's list
/// is. A span describes memory the arena imported and contains the
/// other two; a rotor is a marker rather than memory.
const VMEM_ALLOC: u8 = 0x01;
const VMEM_FREE: u8 = 0x02;
const VMEM_SPAN: u8 = 0x10;

/// The two arenas libumem's `malloc` shim allocates straight out of,
/// with the global naming each: everything too big for the largest
/// cache comes from the first, and everything whose alignment a cache
/// cannot promise from the second. Each is named here as the arena's
/// own `vm_name` spells it, which is what the walk checks it against
/// before believing a pointer read out of a static.
const MALLOC_ARENAS: &[(&str, &str)] = &[
    ("umem_oversize_arena", "umem_oversize"),
    ("umem_memalign_arena", "umem_memalign"),
];

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
    cache_cpu_mask: u64,
    cache_magtype: u64,
    cache_full: u64,
    cache_cpu: u64,
    /// `sizeof (umem_cpu_cache_t)`: the stride of the `cache_cpu[]`
    /// array, which is padded to a cache line.
    cpu_cache: u64,
    cc_loaded: u64,
    cc_ploaded: u64,
    cc_rounds: u64,
    cc_prounds: u64,
    cc_magsize: u64,
    ml_list: u64,
    ml_total: u64,
    mag_next: u64,
    mag_round: u64,
    mt_magsize: u64,
    vm_name: u64,
    vm_seg0: u64,
    vs_start: u64,
    vs_end: u64,
    vs_anext: u64,
    vs_aprev: u64,
    vs_type: u64,
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
    cache_cpu_mask: 224,
    cache_magtype: 448,
    cache_full: 456,
    cache_cpu: 536,
    cpu_cache: 64,
    cc_loaded: 32,
    cc_ploaded: 40,
    cc_rounds: 48,
    cc_prounds: 52,
    cc_magsize: 56,
    ml_list: 0,
    ml_total: 8,
    mag_next: 0,
    mag_round: 8,
    mt_magsize: 0,
    vm_name: 0,
    vm_seg0: 184,
    vs_start: 0,
    vs_end: 8,
    vs_anext: 32,
    vs_aprev: 40,
    vs_type: 48,
};

/// Every layout the walk knows, tried in order.
const LAYOUTS: &[Layout] = &[LP64];

/// What the allocator says about an address.
///
/// There is no verdict for "not in the heap": an address nothing the
/// walk covers holds is [`Unknown`](Liveness::Unknown), because another
/// allocator's memory, a stack and a mapping that was never heap are
/// all equally outside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    /// The address is inside an allocation still handed out.
    Live {
        /// The allocation's exact bounds — what a pointer claiming to
        /// own it must fit inside. For a cache buffer that is the
        /// buffer rather than the chunk: a cache whose buffer is
        /// shorter than its stride keeps the slack past the buffer's
        /// end for itself.
        buffer: Range<u64>,
        /// Which layer of the allocator answered.
        source: Source,
    },
    /// The address is inside an allocation the allocator has taken
    /// back: a buffer on its slab's freelist or held by a layer below
    /// it, or a segment its arena has marked free.
    Freed { buffer: Range<u64>, source: Source },
    /// Nothing the walk covers holds the address, and nothing is
    /// claimed about it.
    Unknown,
}

/// Which of the allocator's two ways of serving an allocation this one
/// came from, and where the walk's account of it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A buffer of a slab of the cache at this index into
    /// [`UmemHeap::caches`].
    Cache(usize),
    /// A segment of the arena at this index into
    /// [`UmemHeap::arenas`] — an allocation too big for any cache, or
    /// aligned more strictly than one can promise.
    Arena(usize),
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
    /// twice — the allocator holds the block, on a slab's freelist or
    /// in a magazine, *and* its malloc header has been scrubbed —
    /// while `true` says only that the allocator has not taken the
    /// block back, which a block handed straight back out to somebody
    /// else also satisfies.
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
    /// Buffers handed out to the program: the chunks the slab layer
    /// counts allocated, less the ones a layer below it holds.
    pub live: u64,
    /// Buffers on a slab's freelist.
    pub freed: u64,
    /// Buffers the slab layer counts allocated but the magazine, depot
    /// or per-thread layer holds — free, and the reason those two
    /// numbers alone do not add up to the cache's own `BUFTOTL`.
    pub parked: u64,
    /// Whether the layers below the slab were read for this cache. A
    /// cache whose magazine layer declined counts none of its buffers
    /// parked, so they read live, which is what they did before this
    /// layer was walked at all.
    pub parked_walked: bool,
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
    /// Buffers handed out to the program.
    pub live_chunks: u64,
    /// Buffers on a slab's freelist.
    pub freed_chunks: u64,
    /// Buffers the magazine, depot or per-thread layer holds. Free,
    /// and counted apart because the slab layer calls them allocated:
    /// the two readings disagreeing is the layer's whole point.
    pub parked_chunks: u64,
    /// Bytes in live chunks, chunk stride rather than requested size.
    pub live_bytes: u64,
    /// Slabs dropped because another slab already claimed their
    /// address range — an overlap is two readings of the same memory,
    /// so neither is believed.
    pub overlaps: usize,
    /// Whether the per-CPU magazines and the depot were read. False
    /// only where a target's caches have no magazine layer at all.
    pub magazines_walked: bool,
    /// Whether the threads' own caches were read.
    pub ptc_walked: bool,
    /// Caches whose parked set was declined by a failed invariant.
    /// Their buffers read live, which is what every buffer did before
    /// these layers were walked.
    pub caches_parked_declined: usize,
    /// Whether the oversize and memalign vmem arenas were walked.
    pub oversize_walked: bool,
    /// Arenas walked and believed.
    pub arenas: usize,
    /// Allocations still handed out by a walked arena, and the bytes
    /// in them.
    pub arena_live: u64,
    pub arena_live_bytes: u64,
    /// Segments a walked arena has marked free.
    pub arena_freed: u64,
    /// Why the declines above happened, capped at [`MAX_NOTES`].
    pub notes: Vec<String>,
}

impl Stats {
    /// Whether anything was declined — the "this index covers less than
    /// the target" signal a verdict-consuming answer should carry.
    pub fn incomplete(&self) -> bool {
        self.caches_declined > 0
            || self.slabs_declined > 0
            || self.overlaps > 0
            || self.caches_parked_declined > 0
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
    /// Bit `i` set means a layer below the slab holds chunk `i`: a
    /// magazine, the depot, or a thread's own cache.
    ///
    /// Its own bitmap rather than another way of setting a freelist
    /// bit, because the two say different things and one of them is
    /// load-bearing: the freelist bits are what the freelist length
    /// cross-check is derived from, and a parked buffer is allocated as
    /// far as its slab is concerned. Answering `locate` from a bitmap
    /// rather than from a search over every parked buffer in the target
    /// is what keeps the verdict as cheap as it was before this layer
    /// existed — it runs on every pointer the renderer follows.
    parked: Vec<u64>,
}

impl Slab {
    fn end(&self) -> u64 {
        self.base + self.chunks as u64 * self.chunksize
    }

    fn is_free(&self, chunk: u32) -> bool {
        bit(&self.free, chunk)
    }

    /// Whether a layer below the slab holds the chunk. Free, the same
    /// as [`is_free`](Slab::is_free) — the slab is simply not the layer
    /// that knows it.
    fn is_parked(&self, chunk: u32) -> bool {
        bit(&self.parked, chunk)
    }

    /// Whether the allocator holds the chunk, by either reading.
    fn is_held(&self, chunk: u32) -> bool {
        self.is_free(chunk) || self.is_parked(chunk)
    }

    fn freed(&self) -> u64 {
        self.free.iter().map(|w| w.count_ones() as u64).sum()
    }

    /// Where the chunk holding `addr` starts.
    fn base_of(&self, addr: u64) -> u64 {
        self.base + (addr - self.base) / self.chunksize * self.chunksize
    }
}

/// Bit `chunk` of a bitmap that may be empty, meaning no bit is set.
fn bit(map: &[u64], chunk: u32) -> bool {
    map.get(chunk as usize / 64)
        .is_some_and(|word| word >> (chunk % 64) & 1 == 1)
}

/// The slab holding `addr`, by binary search over a set sorted by base
/// and known not to overlap.
fn slab_at(slabs: &[Slab], addr: u64) -> Option<&Slab> {
    slabs.get(slab_index(slabs, addr)?)
}

/// Where that slab is, for a caller that has to write to it.
fn slab_index(slabs: &[Slab], addr: u64) -> Option<usize> {
    let above = slabs.partition_point(|s| s.base <= addr);
    let at = above.checked_sub(1)?;
    (addr < slabs[at].end()).then_some(at)
}

/// One vmem arena the malloc shim allocates straight out of, as its own
/// accounting.
///
/// Two of these serve allocations no cache can: one for what is too big
/// for the largest size class, one for what is aligned more strictly
/// than a cache promises. Their memory is in no slab, which is why the
/// slab walk alone answers nothing about a 12 MB buffer or a tokio task
/// cell.
#[derive(Debug, Clone)]
pub struct Arena {
    /// Where the `vmem_t` is, for a hand check under mdb.
    pub addr: u64,
    pub name: String,
    /// Segments believed, allocated and free together.
    pub segs: usize,
    pub live: u64,
    pub freed: u64,
    /// Bytes in the allocated segments.
    pub live_bytes: u64,
}

/// One allocated or free extent of an arena. The spans an arena
/// imported are not kept: a span contains these rather than being one,
/// so keeping it would cover every address twice.
#[derive(Debug)]
struct Seg {
    start: u64,
    end: u64,
    arena: u32,
    live: bool,
}

/// libumem's own account of which of the target's allocations are live.
#[derive(Debug)]
pub struct UmemHeap {
    caches: Vec<Cache>,
    /// Sorted by base and non-overlapping, so an address finds its slab
    /// by binary search.
    slabs: Vec<Slab>,
    /// Buffers the slab layer counts allocated and a layer below it
    /// holds: per-CPU magazines, the depot's full magazines, the
    /// threads' own caches. Sorted, so a chunk asks in one search.
    parked: Vec<u64>,
    arenas: Vec<Arena>,
    /// Sorted by start and non-overlapping, the way `slabs` is.
    segs: Vec<Seg>,
    /// What `segs` spans, first start to last end: what an address has
    /// to be inside for a search of them to be worth making.
    arena_span: Range<u64>,
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
    ///
    /// The slab layer answers first and alone: a slab covering the
    /// address settles it, including when the answer is that the
    /// address is in the slab's own slack rather than in a buffer. Only
    /// an address no slab holds is the arenas' to answer for, which is
    /// the order the allocator itself serves them in.
    pub fn locate(&self, addr: u64) -> Liveness {
        let Some(slab) = slab_at(&self.slabs, addr) else {
            return self.locate_in_arena(addr);
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
        let source = Source::Cache(cache);
        // Free on the slab's own freelist, or held by one of the layers
        // beneath it. The two are the same verdict: the allocator has
        // the buffer either way, and which of its pockets it is in is a
        // fact about libumem rather than about the allocation.
        match slab.is_held(index) {
            true => Liveness::Freed { buffer, source },
            false => Liveness::Live { buffer, source },
        }
    }

    /// What an arena says about an address no slab covers.
    fn locate_in_arena(&self, addr: u64) -> Liveness {
        // Most addresses the renderer follows are in neither arena --
        // a stack, a static, a mapping that was never heap -- and the
        // span the arenas imported answers for all of them at once,
        // before any search.
        if !self.arena_span.contains(&addr) {
            return Liveness::Unknown;
        }
        let above = self.segs.partition_point(|s| s.start <= addr);
        let Some(seg) = above
            .checked_sub(1)
            .map(|i| &self.segs[i])
            .filter(|s| addr < s.end)
        else {
            return Liveness::Unknown;
        };
        let buffer = seg.start..seg.end;
        let source = Source::Arena(seg.arena as usize);
        match seg.live {
            true => Liveness::Live { buffer, source },
            false => Liveness::Freed { buffer, source },
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

    /// Every allocation an arena still has handed out, and every extent
    /// it has taken back, in address order: the two sets mdb's `::walk
    /// vmem_alloc` and `::walk vmem_free` enumerate over the same
    /// arenas.
    pub fn arena_extents(&self, live: bool) -> impl Iterator<Item = Range<u64>> + '_ {
        self.segs
            .iter()
            .filter(move |seg| seg.live == live)
            .map(|seg| seg.start..seg.end)
    }

    /// The caches the walk believed, in the order the cache list holds
    /// them. A [`Source::Cache`] names one by its index here.
    pub fn caches(&self) -> &[Cache] {
        &self.caches
    }

    /// The arenas the walk believed. A [`Source::Arena`] names one by
    /// its index here.
    pub fn arenas(&self) -> &[Arena] {
        &self.arenas
    }

    /// What to call whichever layer answered, for a line a human reads.
    pub fn source_name(&self, source: Source) -> &str {
        match source {
            Source::Cache(i) => &self.caches[i].name,
            Source::Arena(i) => &self.arenas[i].name,
        }
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Every buffer still handed out to the program, in address order:
    /// the set mdb's `::walk umem` enumerates, which is what an
    /// enumeration differential against it diffs. Cache buffers only —
    /// an arena's allocations are in no cache and in neither of these.
    pub fn live_buffers(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.buffers(true)
    }

    /// Every buffer the allocator has taken back, in address order: on
    /// a slab's freelist, or held by the magazine, depot or per-thread
    /// layer. This is what mdb's `::walk freemem` enumerates, and the
    /// two partition a cache.
    pub fn freed_buffers(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.buffers(false)
    }

    fn buffers(&self, live: bool) -> impl Iterator<Item = Range<u64>> + '_ {
        self.slabs.iter().flat_map(move |slab| {
            let bufsize = self.caches[slab.cache as usize].bufsize;
            (0..slab.chunks).filter_map(move |i| {
                let start = slab.base + i as u64 * slab.chunksize;
                (slab.is_held(i) != live).then(|| start..start + bufsize)
            })
        })
    }

    /// Self-consistency invariants, checked over the finished index
    /// rather than during the walk that built it: nothing the walk
    /// covers overlaps anything else it covers, and every cache's and
    /// arena's counts add up to what the index actually holds.
    ///
    /// The slab layer's arithmetic is checked on its own terms rather
    /// than loosened to accommodate the layers below it: a parked
    /// buffer is allocated as far as its slab is concerned, so the
    /// slab-derived count has to match `live + parked` exactly. That
    /// keeps phase-1's freelist cross-check — two independently derived
    /// numbers agreeing — worth exactly what it was worth.
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
            if (cache.live + cache.parked, cache.freed) != (live[i], freed[i]) {
                out.push(format!(
                    "{} counted {} live / {} parked / {} freed, its slabs hold {} / {}",
                    cache.name, cache.live, cache.parked, cache.freed, live[i], freed[i]
                ));
            }
        }
        out.extend(self.parked_violations());
        out.extend(self.arena_violations());
        out
    }

    /// What the parked set has to satisfy on its own terms, none of
    /// which the slab arithmetic above would catch: a buffer two
    /// magazines both claim is counted twice and freed once, and a
    /// round that is not a buffer at all is a misread layout.
    ///
    /// The set is kept twice over — as the addresses the walk found,
    /// and as a bit on the slab holding each — so this checks the two
    /// against each other as well, the way every other reading here is
    /// checked against a second one.
    fn parked_violations(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut counted = vec![0u64; self.caches.len()];
        for pair in self.parked.windows(2) {
            if pair[0] >= pair[1] {
                out.push(format!("{:#x} is parked twice", pair[0]));
            }
        }
        for &addr in &self.parked {
            let Some(slab) = slab_at(&self.slabs, addr).filter(|s| addr == s.base_of(addr)) else {
                out.push(format!("parked {addr:#x} is no walked buffer"));
                continue;
            };
            let index = ((addr - slab.base) / slab.chunksize) as u32;
            if slab.is_free(index) {
                out.push(format!("parked {addr:#x} is also on its slab's freelist"));
            }
            if !slab.is_parked(index) {
                out.push(format!("parked {addr:#x} is not marked on its slab"));
            }
            counted[slab.cache as usize] += 1;
        }
        let marked: u64 = self
            .slabs
            .iter()
            .map(|slab| {
                slab.parked
                    .iter()
                    .map(|w| w.count_ones() as u64)
                    .sum::<u64>()
            })
            .sum();
        if marked != self.parked.len() as u64 {
            out.push(format!(
                "{} buffer(s) are parked, {marked} are marked on a slab",
                self.parked.len()
            ));
        }
        for (i, cache) in self.caches.iter().enumerate() {
            if cache.parked != counted[i] {
                out.push(format!(
                    "{} counted {} parked, the index holds {}",
                    cache.name, cache.parked, counted[i]
                ));
            }
        }
        out
    }

    /// What an arena's segments have to satisfy: they tile no memory
    /// twice, and they are memory no cache also claims. A cache's slabs
    /// and these arenas are carved from the same heap, so an address
    /// both layers answer for means one of the two readings is wrong.
    fn arena_violations(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut counted = vec![(0u64, 0u64); self.arenas.len()];
        for pair in self.segs.windows(2) {
            if pair[0].end > pair[1].start {
                out.push(format!(
                    "segments at {:#x} and {:#x} overlap",
                    pair[0].start, pair[1].start
                ));
            }
        }
        for seg in &self.segs {
            if slab_at(&self.slabs, seg.start).is_some() {
                out.push(format!(
                    "the segment at {:#x} is inside a walked slab",
                    seg.start
                ));
            }
            let counts = &mut counted[seg.arena as usize];
            match seg.live {
                true => counts.0 += 1,
                false => counts.1 += 1,
            }
        }
        for (i, arena) in self.arenas.iter().enumerate() {
            if (arena.live, arena.freed) != counted[i] {
                out.push(format!(
                    "{} counted {} live / {} freed, the index holds {} / {}",
                    arena.name, arena.live, arena.freed, counted[i].0, counted[i].1
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
    /// Buffers the layers below the slab hold, as `(cache, buffer)`
    /// pairs kept until the slabs are sorted: what a round is has to be
    /// checked against the slab that holds it, and that check wants the
    /// finished set rather than the one this cache had when the round
    /// was read.
    parked: Vec<(u32, u64)>,
    /// Caches whose parked set failed an invariant, and whose buffers
    /// therefore read live.
    parked_declined: Vec<u32>,
    arenas: Vec<Arena>,
    segs: Vec<Seg>,
    stats: Stats,
}

impl<'t, T: Target> Walk<'t, T> {
    fn new(target: &'t T, layout: Layout) -> Self {
        Walk {
            target,
            layout,
            caches: Vec::new(),
            slabs: Vec::new(),
            parked: Vec::new(),
            parked_declined: Vec::new(),
            arenas: Vec::new(),
            segs: Vec::new(),
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
        // The per-CPU and depot layers are read with the cache that
        // owns them; a cache that declined its own is counted, not this
        // flag, which says the build read that layer at all.
        self.stats.magazines_walked = true;

        self.slabs.sort_unstable_by_key(|s| s.base);
        self.drop_overlaps();
        // The threads' caches hold buffers no per-cache structure
        // records, so they are found by walking threads rather than
        // caches — which needs the slabs sorted, because the only thing
        // that says which cache such a buffer belongs to is the slab
        // holding it.
        self.walk_ptc();
        let parked = self.fold_parked();
        self.walk_arenas();
        self.segs.sort_unstable_by_key(|s| s.start);
        let arena_span = match (self.segs.first(), self.segs.last()) {
            (Some(first), Some(last)) => first.start..last.end,
            _ => 0..0,
        };
        Some(UmemHeap {
            caches: self.caches,
            slabs: self.slabs,
            parked,
            arenas: self.arenas,
            segs: self.segs,
            arena_span,
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
        // The layers below the slab decline on their own: a cache whose
        // magazines cannot be read is still a cache whose slabs were,
        // and its buffers then read live — which is what every buffer
        // read before these layers were walked at all.
        let mut parked = Vec::new();
        match self.walk_magazines(addr, &cache, index, &mut parked) {
            Some(()) => {
                cache.parked_walked = true;
                self.parked.append(&mut parked);
            }
            None => {
                self.parked_declined.push(index);
                self.stats.caches_parked_declined += 1;
                self.note(format!("{}: its magazine layer declined", cache.name));
            }
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
            parked: 0,
            parked_walked: false,
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
            parked: Vec::new(),
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

    /// The buffers this cache's per-CPU magazines and depot hold.
    ///
    /// A buffer here is free — the program handed it back — but the
    /// slab layer above still counts it allocated, because a free
    /// travels no further than the magazine it lands in until that
    /// magazine fills. The disagreement is the point: without this
    /// layer the freed set is only the remainder that made it all the
    /// way down to a slab, which on a busy target is almost none of it.
    fn walk_magazines(
        &self,
        cache_addr: u64,
        cache: &Cache,
        index: u32,
        out: &mut Vec<(u32, u64)>,
    ) -> Option<()> {
        let magsize = self.magazine_size(cache_addr, cache)?;
        // A cache whose magazine layer is off holds nothing here, which
        // is not the same as holding something unreadable.
        if magsize == 0 {
            return Some(());
        }
        self.walk_depot(cache_addr, cache, magsize, index, out)?;
        self.walk_cpu_caches(cache_addr, cache, index, out)
    }

    /// How many rounds a full magazine of this cache holds, or zero for
    /// a cache with no magazine layer.
    ///
    /// CPU zero's copy is authoritative wherever it is set — it is what
    /// the allocator itself reads — and the magazine type the cache
    /// points at answers for a cache that has never loaded one there.
    fn magazine_size(&self, cache_addr: u64, cache: &Cache) -> Option<i32> {
        let cpu = cache_addr + self.layout.cache_cpu;
        match self.read_i32(cpu + self.layout.cc_magsize)? {
            size @ 1..=MAX_ROUNDS => return Some(size),
            0 => {}
            _ => return None,
        }
        if cache.flags & UMF_NOMAGAZINE != 0 {
            return Some(0);
        }
        let magtype = self.read(cache_addr + self.layout.cache_magtype)?;
        if magtype == 0 {
            return Some(0);
        }
        let magsize = self.read_i32(magtype + self.layout.mt_magsize)?;
        (0..=MAX_ROUNDS).contains(&magsize).then_some(magsize)
    }

    /// The depot's full magazines, each holding a whole magazine of
    /// rounds. The empty list is not walked: an empty magazine holds no
    /// buffer, by definition.
    fn walk_depot(
        &self,
        cache_addr: u64,
        cache: &Cache,
        magsize: i32,
        index: u32,
        out: &mut Vec<(u32, u64)>,
    ) -> Option<()> {
        let depot = cache_addr + self.layout.cache_full;
        let head = self.read(depot + self.layout.ml_list)?;
        let total = self.read(depot + self.layout.ml_total)?;
        if total > MAX_MAGAZINES {
            return None;
        }
        let mut mag = head;
        let mut seen = 0;
        while mag != 0 {
            seen += 1;
            if seen > total {
                return None;
            }
            self.read_rounds(mag, magsize, cache, index, out)?;
            mag = self.read(mag + self.layout.mag_next)?;
            if mag == head {
                break;
            }
        }
        // The depot counts its own magazines, so walking them is a
        // second reading that has to come out at the same number.
        (seen == total).then_some(())
    }

    /// The magazines the CPUs hold: the one loaded and the one before
    /// it, on each of the per-CPU caches this cache was sized for.
    fn walk_cpu_caches(
        &self,
        cache_addr: u64,
        cache: &Cache,
        index: u32,
        out: &mut Vec<(u32, u64)>,
    ) -> Option<()> {
        let mask = self
            .target
            .read_u32(cache_addr + self.layout.cache_cpu_mask)
            .ok()?;
        let cpus = mask as u64 + 1;
        if !cpus.is_power_of_two() || cpus > MAX_CPUS {
            return None;
        }
        for cpu in 0..cpus {
            let cpu = cache_addr + self.layout.cache_cpu + cpu * self.layout.cpu_cache;
            let magsize = self.read_i32(cpu + self.layout.cc_magsize)?;
            for (rounds, loaded) in [
                (self.layout.cc_rounds, self.layout.cc_loaded),
                (self.layout.cc_prounds, self.layout.cc_ploaded),
            ] {
                // A CPU with no magazine loaded records minus one
                // rather than zero, so the count is signed and its
                // sentinel is the common case rather than an edge: most
                // CPUs of a real target never allocated from this cache
                // at all.
                let rounds = self.read_i32(cpu + rounds)?;
                if rounds <= 0 {
                    continue;
                }
                if rounds > magsize {
                    return None;
                }
                let mag = self.read(cpu + loaded)?;
                if mag == 0 {
                    return None;
                }
                self.read_rounds(mag, rounds, cache, index, out)?;
            }
        }
        Some(())
    }

    /// The rounds one magazine holds: the first `rounds` of its array,
    /// the slots past them being the ones it has handed out.
    fn read_rounds(
        &self,
        mag: u64,
        rounds: i32,
        cache: &Cache,
        index: u32,
        out: &mut Vec<(u32, u64)>,
    ) -> Option<()> {
        for round in 0..rounds as u64 {
            let buf = self.read(mag + self.layout.mag_round + round * 8)?;
            if buf == 0 {
                return None;
            }
            out.push((index, buf));
        }
        // The layers below the slabs cannot hold more buffers than the
        // slabs above them call allocated, and a walk that believes
        // they do is following a list that loops.
        (out.len() as u64 <= cache.live).then_some(())
    }

    /// The buffers the threads' own caches hold.
    ///
    /// libumem caches the smallest size classes per thread as well, in
    /// a list rooted in each thread's `ulwp_t` rather than in anything
    /// a cache knows about — so this is the one layer found by walking
    /// threads. A buffer here is as free as one in a magazine, and as
    /// allocated as one to the slab holding it.
    fn walk_ptc(&mut self) {
        let before = self.parked.len();
        match self.walk_thread_caches() {
            Some(()) => self.stats.ptc_walked = true,
            None => {
                // Part of a layer is not the layer: what was collected
                // before it went wrong accounts for the threads walked
                // so far and for no others, and a freed set that stops
                // partway through is a guess about the rest.
                self.parked.truncate(before);
                self.note("the threads' own caches did not walk".to_string());
            }
        }
    }

    fn walk_thread_caches(&mut self) -> Option<()> {
        // A libumem too old to cache per-thread has neither the switch
        // nor the layer, and one whose switch is off has the roots and
        // never puts anything in them: both are nothing to walk rather
        // than something unreadable.
        let Some(enabled) = self.symbol("umem_ptc_enabled") else {
            self.stats.ptc_walked = true;
            return Some(());
        };
        if self.target.read_u32(enabled).ok()? == 0 {
            return Some(());
        }
        let tmem = self.read(self.symbol("umem_tmem_off")?)?;
        // By thread pointer rather than by LWP: a cache belongs to the
        // thread, and a core can name one thread from two LWP records —
        // nexus has such a pair — which would walk its lists twice and
        // count every buffer in them twice over.
        let mut threads: Vec<u64> = self
            .target
            .lwps()
            .ok()?
            .iter()
            .map(|lwp| lwp.regs.fsbase)
            .collect();
        threads.sort_unstable();
        threads.dedup();
        for ulwp in threads {
            // The thread pointer holds the address of the thread's own
            // `ulwp_t`, whose first member points back at it — the one
            // check that says this is a thread rather than a number.
            if ulwp == 0 || self.read(ulwp)? != ulwp {
                return None;
            }
            for root in 0..NTMEMBASE {
                // A `tmem_t` is a size followed by its roots, one per
                // size class cached this way.
                self.walk_ptc_root(ulwp + tmem + 8 + root * 8)?;
            }
        }
        Some(())
    }

    /// One root of one thread's cache: a list of buffers chained
    /// through the first word of each.
    fn walk_ptc_root(&mut self, head: u64) -> Option<()> {
        let mut buf = self.read(head)?;
        let mut cache = None;
        let mut seen = 0;
        while buf != 0 {
            seen += 1;
            if seen > MAX_PTC_BUFFERS {
                return None;
            }
            let index = slab_at(&self.slabs, buf)?.cache;
            // One root holds one size class, and the cache serving it
            // has to be one libumem caches this way at all.
            if *cache.get_or_insert(index) != index
                || self.caches[index as usize].flags & UMF_PTC == 0
            {
                return None;
            }
            self.parked.push((index, buf));
            buf = self.read(buf)?;
        }
        Some(())
    }

    /// Fold the parked candidates into the index, believing one cache's
    /// set only whole.
    ///
    /// Every entry has to be a buffer of that cache the slab layer
    /// calls allocated, and no buffer may be in two pockets at once. A
    /// set with one entry that is not is a reading of that layer that
    /// went wrong somewhere, and keeping the rest of it would be
    /// keeping a freed set that is partly a guess — where dropping it
    /// leaves those buffers reading live, which is what every buffer
    /// read before this layer was walked at all.
    fn fold_parked(&mut self) -> Vec<u64> {
        let parked = std::mem::take(&mut self.parked);
        let mut sorted = parked;
        sorted.sort_unstable();
        let mut kept = Vec::with_capacity(sorted.len());
        let mut at = 0;
        while at < sorted.len() {
            let cache = sorted[at].0;
            let group = &sorted[at..][..sorted[at..].partition_point(|&(c, _)| c == cache)];
            at += group.len();
            if self.parked_declined.contains(&cache) {
                continue;
            }
            if let Some((stray, why)) = self.stray_parked(cache, group) {
                self.caches[cache as usize].parked_walked = false;
                self.parked_declined.push(cache);
                self.stats.caches_parked_declined += 1;
                let name = self.caches[cache as usize].name.clone();
                self.note(format!("{name}: parked {stray:#x} {why}"));
                continue;
            }
            self.caches[cache as usize].parked = group.len() as u64;
            for &(_, buf) in group {
                // Beside the freelist bit, never in place of it: what
                // the slab believes about the buffer has not changed,
                // and the cross-check derived from it must go on
                // meaning what it meant.
                let slab = slab_index(&self.slabs, buf).expect("the group is this cache's buffers");
                let chunk = ((buf - self.slabs[slab].base) / self.slabs[slab].chunksize) as u32;
                let slab = &mut self.slabs[slab];
                if slab.parked.is_empty() {
                    slab.parked = vec![0; (slab.chunks as usize).div_ceil(64)];
                }
                slab.parked[chunk as usize / 64] |= 1 << (chunk % 64);
            }
            kept.extend(group.iter().map(|&(_, buf)| buf));
        }
        // The slab layer counted a parked buffer allocated, which is
        // what it is to the slab and not what it is to the program.
        for cache in &mut self.caches {
            cache.live -= cache.parked;
        }
        self.stats.parked_chunks = kept.len() as u64;
        self.stats.live_chunks = self.caches.iter().map(|c| c.live).sum();
        self.stats.live_bytes = self.caches.iter().map(|c| c.live * c.chunksize).sum();
        kept.sort_unstable();
        kept
    }

    /// The first entry of one cache's parked set that is not a buffer
    /// of that cache the slab layer counts allocated, or that two of
    /// its pockets both claim, with what is wrong with it — and `None`
    /// where the whole set is sound.
    fn stray_parked(&self, cache: u32, group: &[(u32, u64)]) -> Option<(u64, &'static str)> {
        if let Some(pair) = group.windows(2).find(|pair| pair[0].1 == pair[1].1) {
            return Some((pair[0].1, "is held twice"));
        }
        group.iter().find_map(|&(_, buf)| {
            let Some(slab) = slab_at(&self.slabs, buf) else {
                return Some((buf, "is in no walked slab"));
            };
            if slab.cache != cache {
                return Some((buf, "belongs to another cache"));
            }
            if slab.base_of(buf) != buf {
                return Some((buf, "is not a buffer's base"));
            }
            let chunk = ((buf - slab.base) / slab.chunksize) as u32;
            slab.is_free(chunk)
                .then_some((buf, "is also on its slab's freelist"))
        })
    }

    /// The two arenas the malloc shim allocates straight out of.
    ///
    /// Everything too big for the largest cache, and everything aligned
    /// more strictly than a cache promises, is in no slab at all: it is
    /// a segment of one of these. This is what lets an address inside a
    /// twelve-megabyte buffer — or inside a tokio task cell, which is
    /// memaligned — be answered for at all, and what gives a freed
    /// allocation of that kind anywhere to be freed *to*.
    fn walk_arenas(&mut self) {
        let mut walked = true;
        for &(symbol, name) in MALLOC_ARENAS {
            let first = self.segs.len();
            let index = self.arenas.len() as u32;
            match self.walk_arena(symbol, name, index) {
                Some(arena) => self.arenas.push(arena),
                None => {
                    self.segs.truncate(first);
                    self.note(format!("the {name} arena did not walk"));
                    walked = false;
                }
            }
        }
        self.stats.oversize_walked = walked;
        self.stats.arenas = self.arenas.len();
        self.stats.arena_live = self.arenas.iter().map(|a| a.live).sum();
        self.stats.arena_freed = self.arenas.iter().map(|a| a.freed).sum();
        self.stats.arena_live_bytes = self.arenas.iter().map(|a| a.live_bytes).sum();
    }

    /// One arena's segments, from the anchor its own `vm_seg0` is.
    fn walk_arena(&mut self, symbol: &str, name: &str, index: u32) -> Option<Arena> {
        let arena = self.read(self.symbol(symbol)?)?;
        if arena == 0 {
            return None;
        }
        // A static holding a pointer is worth what the thing it points
        // at says it is: an arena names itself, and one that does not
        // carry the name this static was supposed to name is not it.
        if self.read_name(arena + self.layout.vm_name)? != name {
            return None;
        }
        let mut out = Arena {
            addr: arena,
            name: name.to_string(),
            segs: 0,
            live: 0,
            freed: 0,
            live_bytes: 0,
        };
        let anchor = arena + self.layout.vm_seg0;
        let mut addr = self.read(anchor + self.layout.vs_anext)?;
        let mut prev = anchor;
        let mut seen = 0;
        // What the arena imported. The segments below tile it in
        // address order, and a span is not an extent of its own: it
        // contains them, so believing it as one would cover every
        // address in it twice.
        let mut span = 0..0;
        let mut last = 0;
        while addr != anchor {
            seen += 1;
            if seen > MAX_SEGS {
                return None;
            }
            if self.read(addr + self.layout.vs_aprev)? != prev {
                return None;
            }
            let start = self.read(addr + self.layout.vs_start)?;
            let end = self.read(addr + self.layout.vs_end)?;
            match self.target.read_u8(addr + self.layout.vs_type).ok()? {
                VMEM_SPAN => {
                    if start >= end {
                        return None;
                    }
                    span = start..end;
                    last = start;
                }
                kind @ (VMEM_ALLOC | VMEM_FREE) => {
                    if start >= end || start < last || end > span.end {
                        return None;
                    }
                    last = end;
                    let live = kind == VMEM_ALLOC;
                    out.segs += 1;
                    match live {
                        true => {
                            out.live += 1;
                            out.live_bytes += end - start;
                        }
                        false => out.freed += 1,
                    }
                    self.segs.push(Seg {
                        start,
                        end,
                        arena: index,
                        live,
                    });
                }
                // The rotor, which marks a place in the list rather
                // than describing memory.
                _ => {}
            }
            prev = addr;
            addr = self.read(addr + self.layout.vs_anext)?;
        }
        Some(out)
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

    /// A signed count, of which libumem has several: a magazine's
    /// rounds are minus one where there is no magazine.
    fn read_i32(&self, addr: u64) -> Option<i32> {
        self.target.read_u32(addr).ok().map(|word| word as i32)
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
        /// What the target's LWPs are, for the one layer found by
        /// walking threads rather than caches.
        lwps: Vec<proc::LwpInfo>,
    }

    impl Fake {
        pub(crate) fn new(base: u64, len: usize) -> Self {
            Fake {
                base,
                bytes: vec![0; len],
                symbols: BTreeMap::new(),
                hole: 0..0,
                lwps: Vec::new(),
            }
        }

        fn put_u8(&mut self, addr: u64, value: u8) {
            self.bytes[(addr - self.base) as usize] = value;
        }

        /// A thread, the way a core names one: a thread pointer in an
        /// LWP's registers, and the self-pointer libc keeps at the
        /// start of the `ulwp_t` it points at.
        fn thread(&mut self, tid: u32, ulwp: u64) {
            self.put_u64(ulwp, ulwp);
            self.lwps.push(proc::LwpInfo {
                tid,
                regs: Regs {
                    fsbase: ulwp,
                    ..Regs::default()
                },
                stack_range: 0..0,
                altstack: 0..0,
                tstamp: proc::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            });
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
            Ok(self.lwps.clone())
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

    /// Where magazines are laid, one every 0x200 bytes.
    const MAGS: u64 = BASE + 0x18000;
    /// Where the `vmem_t`s are laid, one every 0x400 bytes — only the
    /// first 216 of a real one is anything this walk reads.
    const ARENAS: u64 = BASE + 0x1c000;
    /// Where the statics naming them are, 8 bytes each.
    const ARENA_PTRS: u64 = BASE + 0x200;
    /// Where arena segments are laid, one every 0x40 bytes.
    const SEGS: u64 = BASE + 0x1d000;
    /// Where the arenas' own memory is: nothing any slab covers, which
    /// is what makes it an arena's to answer for.
    const OVERSIZE: u64 = BASE + 0x18_0000;
    /// Where the threads' `ulwp_t`s are, one every 0x200 bytes.
    const THREADS: u64 = BASE + 0x1e000;
    /// What `umem_tmem_off` says: how far into a `ulwp_t` its `tmem_t`
    /// begins. Its roots start one word past that, after the size.
    const TMEM_OFF: u64 = 0x100;

    /// A hashed cache's `cache_hash_mask`: four buckets, so a walk
    /// that reads the wrong number of them comes up short.
    const HASH_MASK: u64 = 3;

    /// What one cache's layers below the slab hold.
    #[derive(Default)]
    struct Magazines {
        /// How many rounds a full magazine of this cache holds.
        magsize: i32,
        /// The rounds of each CPU's loaded and previously loaded
        /// magazines. A CPU with no magazine loaded gets an empty list,
        /// which is written as libumem writes it: minus one rounds.
        cpus: Vec<(Vec<u64>, Vec<u64>)>,
        /// The rounds of each full magazine in the depot.
        depot: Vec<Vec<u64>>,
    }

    /// One segment of an arena's list.
    struct SegSpec {
        start: u64,
        end: u64,
        kind: u8,
    }

    /// Lay a magazine holding `rounds`, and answer where it is.
    fn magazine(f: &mut Fake, index: u64, rounds: &[u64]) -> u64 {
        let mag = MAGS + index * 0x200;
        for (i, &buf) in rounds.iter().enumerate() {
            f.put_u64(mag + LP64.mag_round + i as u64 * 8, buf);
        }
        mag
    }

    /// Give a cache the magazine layer described: one per-CPU cache per
    /// entry of `cpus`, and the depot's full list.
    fn magazines(f: &mut Fake, index: u64, spec: &Magazines) {
        let addr = CACHES + index * 0x400;
        let mut mags = index * 16;
        let mut lay = |f: &mut Fake, rounds: &[u64]| {
            mags += 1;
            magazine(f, mags, rounds)
        };
        f.put_u32(
            addr + LP64.cache_cpu_mask,
            spec.cpus.len().max(1) as u32 - 1,
        );
        for (i, (loaded, previous)) in spec.cpus.iter().enumerate() {
            let cpu = addr + LP64.cache_cpu + i as u64 * LP64.cpu_cache;
            f.put_u32(cpu + LP64.cc_magsize, spec.magsize as u32);
            for (rounds, at, mag) in [
                (loaded, LP64.cc_rounds, LP64.cc_loaded),
                (previous, LP64.cc_prounds, LP64.cc_ploaded),
            ] {
                match rounds.is_empty() {
                    // No magazine loaded at all, which is not the same
                    // as one with nothing in it.
                    true => f.put_u32(cpu + at, -1i32 as u32),
                    false => {
                        f.put_u32(cpu + at, rounds.len() as u32);
                        let held = lay(f, rounds);
                        f.put_u64(cpu + mag, held);
                    }
                }
            }
        }
        let depot = addr + LP64.cache_full;
        f.put_u64(depot + LP64.ml_total, spec.depot.len() as u64);
        let mut head = 0;
        for rounds in spec.depot.iter().rev() {
            let mag = lay(f, rounds);
            f.put_u64(mag + LP64.mag_next, head);
            head = mag;
        }
        f.put_u64(depot + LP64.ml_list, head);
    }

    /// Give the fake the per-thread caching libumem does when it is
    /// turned on: the switch, the offset of a thread's roots, and a
    /// thread holding the buffers listed in the root named.
    fn per_thread(f: &mut Fake, tid: u32, held: &[(u64, &[u64])]) {
        let ulwp = THREADS + tid as u64 * 0x200;
        f.symbol("umem_ptc_enabled", BASE + 0x300);
        f.put_u32(BASE + 0x300, 1);
        f.symbol("umem_tmem_off", BASE + 0x308);
        f.put_u64(BASE + 0x308, TMEM_OFF);
        f.thread(tid, ulwp);
        // The size the roots follow, given a value that would pass for
        // a buffer if anything ever read it as a root: a walk off by
        // one word parks that buffer as well as the magazine holding
        // it, and the set is refused for holding it twice.
        f.put_u64(ulwp + TMEM_OFF, BUFFERS);
        for &(root, buffers) in held {
            let mut next = 0;
            for &buf in buffers.iter().rev() {
                f.put_u64(buf, next);
                next = buf;
            }
            f.put_u64(ulwp + TMEM_OFF + 8 + root * 8, next);
        }
    }

    /// Lay an arena and its segment list, and the static naming it.
    fn arena(f: &mut Fake, index: u64, symbol: &str, name: &str, segs: &[SegSpec]) {
        let arena = ARENAS + index * 0x400;
        f.symbol(symbol, ARENA_PTRS + index * 8);
        f.put_u64(ARENA_PTRS + index * 8, arena);
        f.put_str(arena + LP64.vm_name, name);
        let anchor = arena + LP64.vm_seg0;
        let mut prev = anchor;
        for (i, spec) in segs.iter().enumerate() {
            let seg = SEGS + (index * 64 + i as u64) * 0x40;
            f.put_u64(seg + LP64.vs_start, spec.start);
            f.put_u64(seg + LP64.vs_end, spec.end);
            f.put_u8(seg + LP64.vs_type, spec.kind);
            f.put_u64(prev + LP64.vs_anext, seg);
            f.put_u64(seg + LP64.vs_aprev, prev);
            prev = seg;
        }
        f.put_u64(prev + LP64.vs_anext, anchor);
        f.put_u64(anchor + LP64.vs_aprev, prev);
    }

    /// The two arenas a real target always has, with one allocation
    /// each: one still handed out, one the arena has taken back.
    fn arenas(f: &mut Fake) {
        arena(
            f,
            0,
            "umem_oversize_arena",
            "umem_oversize",
            &[
                SegSpec {
                    start: OVERSIZE,
                    end: OVERSIZE + 0x4000,
                    kind: VMEM_SPAN,
                },
                SegSpec {
                    start: OVERSIZE,
                    end: OVERSIZE + 0x2000,
                    kind: VMEM_ALLOC,
                },
                SegSpec {
                    start: OVERSIZE + 0x2000,
                    end: OVERSIZE + 0x4000,
                    kind: VMEM_FREE,
                },
            ],
        );
        arena(
            f,
            1,
            "umem_memalign_arena",
            "umem_memalign",
            &[
                SegSpec {
                    start: OVERSIZE + 0x4000,
                    end: OVERSIZE + 0x5000,
                    kind: VMEM_SPAN,
                },
                SegSpec {
                    start: OVERSIZE + 0x4000,
                    end: OVERSIZE + 0x4400,
                    kind: VMEM_ALLOC,
                },
                // With a gap between it and the next: an arena's
                // segments need not abut, and the hole between two of
                // them is the memory the arena has not handed out and
                // has not been asked to account for either.
                SegSpec {
                    start: OVERSIZE + 0x4800,
                    end: OVERSIZE + 0x4c00,
                    kind: VMEM_ALLOC,
                },
            ],
        );
    }

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

    /// An index answering [`Liveness::Freed`] for exactly `block` and
    /// [`Liveness::Unknown`] everywhere else, built without a walk.
    ///
    /// Everything else here lays metadata at addresses of its own
    /// choosing and reads it back, which is what a test of the *walk*
    /// wants. A test of a **consumer** cannot: the values it gates are
    /// wherever its own fixture put them — a captured snapshot's heap,
    /// megabytes from anything a fake target could hold — and no walk
    /// can be made to answer for those. So this states the verdicts
    /// directly, as one arena's free segments, and what it answers
    /// still comes out of [`UmemHeap::locate`] rather than out of a
    /// stand-in for it.
    pub(crate) fn freeing(block: Range<u64>) -> UmemHeap {
        let segs = vec![Seg {
            start: block.start,
            end: block.end,
            arena: 0,
            live: false,
        }];
        let span = block;
        UmemHeap {
            caches: Vec::new(),
            slabs: Vec::new(),
            parked: Vec::new(),
            arenas: vec![Arena {
                addr: 0,
                name: "umem_oversize".to_string(),
                segs: segs.len(),
                live: 0,
                freed: segs.len() as u64,
                live_bytes: 0,
            }],
            segs,
            arena_span: span,
            stats: Stats::default(),
        }
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
                source: Source::Cache(alloc_64),
            }
        );
        assert_eq!(
            heap.locate(BUFFERS + 64 + 63),
            Liveness::Freed {
                buffer: BUFFERS + 64..BUFFERS + 128,
                source: Source::Cache(alloc_64),
            }
        );
        assert_eq!(
            heap.locate(BUFFERS + 130),
            Liveness::Live {
                buffer: BUFFERS + 128..BUFFERS + 192,
                source: Source::Cache(alloc_64),
            }
        );
        assert_eq!(
            heap.locate(BUFFERS + 0x2000 + 3 * 128),
            Liveness::Freed {
                buffer: BUFFERS + 0x2000 + 384..BUFFERS + 0x2000 + 512,
                source: Source::Cache(cache("umem_alloc_128")),
            }
        );

        // Which layer answered, by name: what the audit prints beside a
        // verdict, and the only thing that says which of the two the
        // index holds it came from.
        assert_eq!(heap.source_name(Source::Cache(alloc_64)), "umem_alloc_64");

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
                source: Source::Cache(alloc_64),
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
                source: Source::Cache(alloc_64),
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

    /// An index staged by hand rather than walked: the caches and slabs
    /// given, and nothing beneath them.
    fn staged(caches: Vec<Cache>, slabs: Vec<Slab>) -> UmemHeap {
        UmemHeap {
            caches,
            slabs,
            parked: Vec::new(),
            arenas: Vec::new(),
            segs: Vec::new(),
            arena_span: 0..0,
            stats: Stats::default(),
        }
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
            parked: Vec::new(),
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
            parked: 0,
            parked_walked: true,
            bufctl: 56,
        };
        let sound = staged(
            vec![cache.clone()],
            vec![slab(BUFFERS, 4, vec![]), slab(BUFFERS + 0x1000, 4, vec![])],
        );
        assert!(sound.violations().is_empty());

        // Two slabs claiming the same memory: neither reading can be
        // trusted, and which is wrong is what nothing here can tell.
        let overlapping = staged(
            vec![cache.clone()],
            vec![slab(BUFFERS, 4, vec![]), slab(BUFFERS + 128, 4, vec![])],
        );
        let found = overlapping.violations();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("overlap"), "{found:?}");

        // Slabs that touch exactly are not an overlap: a chunk ends
        // where the next begins.
        let abutting = staged(
            vec![cache.clone()],
            vec![slab(BUFFERS, 4, vec![]), slab(BUFFERS + 256, 4, vec![])],
        );
        assert!(abutting.violations().is_empty());

        // A cache whose totals do not add up to its own slabs'.
        let miscounted = staged(
            vec![Cache { live: 7, ..cache }],
            vec![slab(BUFFERS, 4, vec![]), slab(BUFFERS + 0x1000, 4, vec![])],
        );
        let found = miscounted.violations();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("umem_alloc_64"), "{found:?}");
    }

    /// The ordinary shape of a busy target: a cache whose magazine
    /// layer holds most of what is free, and one buffer that made it
    /// all the way down to a slab's freelist.
    fn magazined() -> Fake {
        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_64",
            64,
            0,
            &[SlabSpec {
                base: BUFFERS,
                chunks: 8,
                free: vec![7],
            }],
        );
        magazines(
            &mut f,
            0,
            &Magazines {
                magsize: 3,
                cpus: vec![
                    (vec![BUFFERS], Vec::new()),
                    (Vec::new(), vec![BUFFERS + 64]),
                ],
                depot: vec![vec![BUFFERS + 128, BUFFERS + 192, BUFFERS + 256]],
            },
        );
        f
    }

    /// A buffer a magazine holds is free, whatever its slab says.
    ///
    /// The slab layer counts it allocated — a free travels no further
    /// than the magazine it lands in — so the two readings disagree by
    /// construction, and the verdict is the lower layer's.
    #[test]
    fn test_a_buffer_a_magazine_holds_is_freed() {
        let heap = UmemHeap::build(&magazined()).expect("the walk built an index");
        assert!(heap.violations().is_empty(), "{:?}", heap.violations());

        let stats = heap.stats();
        assert!(stats.magazines_walked && !stats.incomplete());
        assert_eq!(
            (stats.live_chunks, stats.freed_chunks, stats.parked_chunks),
            (2, 1, 5)
        );
        // The bytes follow the live count rather than the slab's, so a
        // parked buffer is not counted as memory in use either.
        assert_eq!(stats.live_bytes, 2 * 64);
        let cache = &heap.caches()[0];
        assert_eq!((cache.live, cache.freed, cache.parked), (2, 1, 5));
        assert!(cache.parked_walked);

        // Loaded, previously loaded, and in the depot: each is freed,
        // and each still names the buffer it is a round of.
        for held in [BUFFERS, BUFFERS + 64, BUFFERS + 128, BUFFERS + 256] {
            assert_eq!(
                heap.locate(held),
                Liveness::Freed {
                    buffer: held..held + 64,
                    source: Source::Cache(0),
                },
                "{held:#x}",
            );
        }
        assert_eq!(
            heap.locate(BUFFERS + 320),
            Liveness::Live {
                buffer: BUFFERS + 320..BUFFERS + 384,
                source: Source::Cache(0),
            }
        );

        // What the enumeration differential diffs: the two sets
        // partition the cache, with the magazine layer counted on the
        // freed side where mdb's own walkers count it.
        let live: Vec<u64> = heap.live_buffers().map(|b| b.start).collect();
        assert_eq!(live, [BUFFERS + 320, BUFFERS + 384]);
        let freed: Vec<u64> = heap.freed_buffers().map(|b| b.start).collect();
        assert_eq!(
            freed,
            [
                BUFFERS,
                BUFFERS + 64,
                BUFFERS + 128,
                BUFFERS + 192,
                BUFFERS + 256,
                BUFFERS + 448,
            ]
        );
    }

    /// A CPU that has no magazine loaded records minus one rounds, and
    /// whatever the pointer beside it held last. Reading that pointer
    /// because the count looked unsigned is the mistake this pins:
    /// most CPUs of a real target are in exactly this state.
    #[test]
    fn test_a_cpu_with_no_magazine_loaded_is_not_read() {
        let mut f = magazined();
        let cpu = CACHES + LP64.cache_cpu + LP64.cpu_cache;
        f.put_u64(cpu + LP64.cc_loaded, BUFFERS + 0x10_0000);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(!heap.stats().incomplete());
        assert_eq!(heap.stats().parked_chunks, 5);
    }

    /// The depot counts its own magazines, so a list that walks to a
    /// different number is a list this walk is not reading right.
    #[test]
    fn test_a_depot_that_miscounts_its_magazines_declines_the_layer() {
        let mut f = magazined();
        f.put_u64(CACHES + LP64.cache_full + LP64.ml_total, 2);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        let stats = heap.stats();
        assert_eq!(stats.caches_parked_declined, 1);
        assert!(stats.incomplete());
        // Declining the layer leaves its buffers reading live, which is
        // what they read before the layer was walked at all -- never
        // the other way round.
        assert_eq!((stats.live_chunks, stats.parked_chunks), (7, 0));
        assert!(!heap.caches()[0].parked_walked);
        assert!(matches!(heap.locate(BUFFERS), Liveness::Live { .. }));
        assert!(heap.violations().is_empty(), "{:?}", heap.violations());
    }

    /// A magazine cannot hold more rounds than its own size, and a
    /// count that says it does is a count read from the wrong place.
    #[test]
    fn test_more_rounds_than_a_magazine_holds_declines_the_layer() {
        let mut f = magazined();
        f.put_u32(CACHES + LP64.cache_cpu + LP64.cc_rounds, 4);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert_eq!(heap.stats().caches_parked_declined, 1);
        assert_eq!(heap.stats().parked_chunks, 0);
    }

    /// A round has to be a buffer of the cache whose magazine holds it,
    /// on its own boundary -- the check that catches a layout read one
    /// member out, where every round lands somewhere plausible.
    #[test]
    fn test_a_round_that_is_not_a_buffer_declines_the_layer() {
        let mut f = magazined();
        let mag = MAGS + 0x200;
        f.put_u64(mag + LP64.mag_round, BUFFERS + 8);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert_eq!(heap.stats().caches_parked_declined, 1);
        assert!(
            heap.stats()
                .notes
                .iter()
                .any(|note| note.contains("is not a buffer's base")),
            "{:?}",
            heap.stats().notes
        );
    }

    /// No buffer is in two pockets at once, so a set that says one is
    /// has read one of the two pockets wrong.
    #[test]
    fn test_a_buffer_two_magazines_both_hold_is_refused() {
        let mut f = magazined();
        f.put_u64(MAGS + 2 * 0x200 + LP64.mag_round, BUFFERS);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert_eq!(heap.stats().caches_parked_declined, 1);
        assert!(
            heap.stats()
                .notes
                .iter()
                .any(|note| note.contains("is held twice")),
            "{:?}",
            heap.stats().notes
        );
    }

    /// A buffer on its slab's freelist is not also in a magazine: the
    /// slab layer gets it only once the magazine gives it back.
    #[test]
    fn test_a_parked_buffer_on_its_slabs_freelist_is_refused() {
        let mut f = magazined();
        f.put_u64(MAGS + 0x200 + LP64.mag_round, BUFFERS + 448);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert_eq!(heap.stats().caches_parked_declined, 1);
        assert!(
            heap.stats()
                .notes
                .iter()
                .any(|note| note.contains("freelist")),
            "{:?}",
            heap.stats().notes
        );
    }

    /// A cache whose CPUs have never loaded a magazine keeps nothing in
    /// their own copies of the size, and the magazine type it points at
    /// is what says how big a full magazine is — which is the only
    /// thing that says how many rounds the depot's hold.
    fn depot_only() -> (Fake, u64) {
        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_64",
            64,
            0,
            &[SlabSpec {
                base: BUFFERS,
                chunks: 8,
                free: vec![7],
            }],
        );
        magazines(
            &mut f,
            0,
            &Magazines {
                magsize: 0,
                cpus: vec![(Vec::new(), Vec::new())],
                depot: vec![vec![BUFFERS, BUFFERS + 64, BUFFERS + 128]],
            },
        );
        let magtype = MAGS + 0x1000;
        f.put_u64(CACHES + LP64.cache_magtype, magtype);
        f.put_u32(magtype + LP64.mt_magsize, 3);
        (f, magtype)
    }

    #[test]
    fn test_a_cache_that_never_loaded_a_magazine_asks_its_magazine_type() {
        let (f, _) = depot_only();
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(!heap.stats().incomplete());
        assert_eq!(heap.stats().parked_chunks, 3);
        assert!(heap.violations().is_empty(), "{:?}", heap.violations());

        // A cache whose magazine layer is turned off holds nothing
        // there whatever its depot looks like, and that is nothing to
        // walk rather than something unreadable.
        let (mut f, _) = depot_only();
        f.put_u32(CACHES + LP64.cache_flags, UMF_NOMAGAZINE);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(!heap.stats().incomplete());
        assert_eq!(heap.stats().parked_chunks, 0);

        // And one whose type says a magazine holds a number of rounds
        // no magazine could is a type read from the wrong place.
        let (mut f, magtype) = depot_only();
        f.put_u32(magtype + LP64.mt_magsize, MAX_ROUNDS as u32 + 1);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert_eq!(heap.stats().caches_parked_declined, 1);
    }

    /// The depot's list may end by looping back to its own head rather
    /// than at a null, and both are the whole list once.
    #[test]
    fn test_a_depot_list_that_loops_back_to_its_head_ends_there() {
        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_64",
            64,
            0,
            &[SlabSpec {
                base: BUFFERS,
                chunks: 8,
                free: vec![7],
            }],
        );
        magazines(
            &mut f,
            0,
            &Magazines {
                magsize: 3,
                cpus: vec![(Vec::new(), Vec::new())],
                depot: vec![
                    vec![BUFFERS, BUFFERS + 64, BUFFERS + 128],
                    vec![BUFFERS + 192, BUFFERS + 256, BUFFERS + 320],
                ],
            },
        );
        // The list the builder laid ends at a null; libumem's ends by
        // coming back to its own head, and both are the whole list
        // once round.
        let depot = CACHES + LP64.cache_full;
        let head = f.read_u64(depot + LP64.ml_list).unwrap();
        let second = f.read_u64(head + LP64.mag_next).unwrap();
        f.put_u64(second + LP64.mag_next, head);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(!heap.stats().incomplete());
        assert_eq!(heap.stats().parked_chunks, 6);
    }

    /// A depot that claims more magazines than a target could hold, and
    /// one whose list is longer than it claims: the first is bounded
    /// before the walk starts, the second while it runs.
    #[test]
    fn test_an_implausible_depot_declines_the_layer() {
        for (member, value) in [(LP64.ml_total, MAX_MAGAZINES + 1), (LP64.ml_total, 0)] {
            let mut f = magazined();
            f.put_u64(CACHES + LP64.cache_full + member, value);
            let heap = UmemHeap::build(&f).expect("the slab layer still walks");
            assert_eq!(heap.stats().caches_parked_declined, 1, "{value}");
            assert_eq!(heap.stats().parked_chunks, 0);
        }
    }

    /// A CPU cache array is sized to a mask, so its count is a power of
    /// two; anything else is a number read from the wrong place.
    #[test]
    fn test_an_implausible_cpu_count_declines_the_layer() {
        for mask in [2u32, MAX_CPUS as u32] {
            let mut f = magazined();
            f.put_u32(CACHES + LP64.cache_cpu_mask, mask);
            let heap = UmemHeap::build(&f).expect("the slab layer still walks");
            assert_eq!(heap.stats().caches_parked_declined, 1, "{mask}");
        }
    }

    /// A magazine as full as its own size is the ordinary case, not the
    /// one over it: the check is on more rounds than fit, not on as
    /// many as fit.
    #[test]
    fn test_a_magazine_filled_to_its_size_is_walked() {
        let mut f = magazined();
        let loaded = magazine(&mut f, 9, &[BUFFERS, BUFFERS + 320, BUFFERS + 384]);
        let cpu = CACHES + LP64.cache_cpu;
        f.put_u32(cpu + LP64.cc_rounds, 3);
        f.put_u64(cpu + LP64.cc_loaded, loaded);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(!heap.stats().incomplete());
        assert_eq!(heap.stats().parked_chunks, 7);
    }

    /// The layer no cache records: a buffer a thread is holding for
    /// itself, found by walking threads rather than caches.
    #[test]
    fn test_a_buffer_a_thread_holds_is_freed() {
        let mut f = magazined();
        // The cache has to be one libumem caches per-thread at all.
        f.put_u32(CACHES + LP64.cache_flags, UMF_PTC);
        per_thread(&mut f, 1, &[(4, &[BUFFERS + 320, BUFFERS + 384])]);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(heap.violations().is_empty(), "{:?}", heap.violations());
        assert!(heap.stats().ptc_walked && !heap.stats().incomplete());
        assert_eq!(
            (heap.stats().live_chunks, heap.stats().parked_chunks),
            (0, 7)
        );
        assert!(matches!(heap.locate(BUFFERS + 320), Liveness::Freed { .. }));
    }

    /// A thread's roots are a size followed by the roots themselves, so
    /// reading them one word early reads the size as a buffer. The
    /// fixture puts a plausible buffer address there for exactly that:
    /// a walk off by one word parks a buffer twice and refuses the set.
    #[test]
    fn test_a_threads_roots_begin_past_the_size_before_them() {
        let mut f = magazined();
        f.put_u32(CACHES + LP64.cache_flags, UMF_PTC);
        per_thread(&mut f, 1, &[(4, &[BUFFERS + 320])]);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(!heap.stats().incomplete());
        assert_eq!(heap.stats().parked_chunks, 6);
    }

    /// A thread pointer that does not point at a thread is a number,
    /// and the layer it would have been read through declines.
    #[test]
    fn test_a_thread_pointer_that_names_no_thread_declines_the_layer() {
        let mut f = magazined();
        f.put_u32(CACHES + LP64.cache_flags, UMF_PTC);
        per_thread(&mut f, 1, &[(4, &[BUFFERS + 320])]);
        f.put_u64(THREADS + 0x200, 0);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert!(!heap.stats().ptc_walked);
        assert_eq!(heap.stats().parked_chunks, 5);
    }

    /// A cache libumem does not cache per thread has no per-thread list
    /// to be in, so a root holding one of its buffers is a root read
    /// from the wrong place.
    #[test]
    fn test_a_thread_holding_a_buffer_of_a_cache_it_cannot_cache_declines() {
        let mut f = magazined();
        per_thread(&mut f, 1, &[(4, &[BUFFERS + 320])]);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert!(!heap.stats().ptc_walked);
        assert_eq!(heap.stats().parked_chunks, 5);
    }

    /// A list that never ends is bounded rather than followed, however
    /// long a thread's cache is allowed to be.
    #[test]
    fn test_a_thread_cache_that_loops_is_bounded_and_refused() {
        let mut f = magazined();
        f.put_u32(CACHES + LP64.cache_flags, UMF_PTC);
        per_thread(&mut f, 1, &[(4, &[BUFFERS + 320, BUFFERS + 384])]);
        // The second buffer points back at the first.
        f.put_u64(BUFFERS + 384, BUFFERS + 320);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert!(!heap.stats().ptc_walked);
        assert_eq!(heap.stats().parked_chunks, 5);
    }

    /// A core can name one thread from two LWP records, and nexus has
    /// such a pair. Walking its lists twice would count every buffer in
    /// them twice -- and then refuse the whole set for holding a buffer
    /// twice, which is how this was found.
    #[test]
    fn test_a_thread_two_lwps_name_is_walked_once() {
        let mut f = magazined();
        f.put_u32(CACHES + LP64.cache_flags, UMF_PTC);
        per_thread(&mut f, 1, &[(4, &[BUFFERS + 320])]);
        let ulwp = THREADS + 0x200;
        f.thread(9, ulwp);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(!heap.stats().incomplete());
        assert_eq!(heap.stats().parked_chunks, 6);
    }

    /// One root holds one size class, because the root a buffer goes
    /// back to is chosen by the cache that served it. A root holding
    /// two is a root address read from the wrong offset.
    #[test]
    fn test_a_root_holding_two_size_classes_declines_the_layer() {
        let mut f = fake();
        for (index, name, chunk, base) in [
            (0, "umem_alloc_64", 64u64, BUFFERS),
            (1, "umem_alloc_128", 128u64, BUFFERS + 0x2000),
        ] {
            cache(
                &mut f,
                index,
                name,
                chunk,
                UMF_PTC,
                &[SlabSpec {
                    base,
                    chunks: 4,
                    free: Vec::new(),
                }],
            );
        }
        per_thread(&mut f, 1, &[(4, &[BUFFERS, BUFFERS + 0x2000])]);
        let heap = UmemHeap::build(&f).expect("the slab layer still walks");
        assert!(!heap.stats().ptc_walked);
        assert_eq!(heap.stats().parked_chunks, 0);
        assert!(matches!(heap.locate(BUFFERS), Liveness::Live { .. }));
    }

    /// An allocation no cache served: too big for the largest size
    /// class, or aligned more strictly than one can promise. It is in
    /// no slab at all, so only the arena it came from can answer -- and
    /// a freed one has somewhere to be freed *to*, which is what the
    /// large size classes lacked before.
    #[test]
    fn test_an_arena_answers_for_an_allocation_no_cache_served() {
        let mut f = two_caches();
        arenas(&mut f);
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(heap.violations().is_empty(), "{:?}", heap.violations());
        assert!(heap.stats().oversize_walked);
        assert_eq!(heap.stats().arenas, 2);
        // Each arena's own count of what it holds, which is what the
        // audit's table prints and the only number in it that says how
        // much of an arena's list was believed.
        let segs: Vec<usize> = heap.arenas().iter().map(|a| a.segs).collect();
        assert_eq!(segs, [2, 2]);
        assert_eq!((heap.stats().arena_live, heap.stats().arena_freed), (3, 1));
        assert_eq!(heap.stats().arena_live_bytes, 0x2000 + 0x400 + 0x400);

        let oversize = heap
            .arenas()
            .iter()
            .position(|a| a.name == "umem_oversize")
            .expect("the arena is in the index");
        assert_eq!(heap.source_name(Source::Arena(oversize)), "umem_oversize");
        // An address inside the allocation, not only its base: an
        // arena's segment is the whole extent, so anything in it is
        // answered for.
        assert_eq!(
            heap.locate(OVERSIZE + 0x100),
            Liveness::Live {
                buffer: OVERSIZE..OVERSIZE + 0x2000,
                source: Source::Arena(oversize),
            }
        );
        assert_eq!(
            heap.locate(OVERSIZE + 0x2000),
            Liveness::Freed {
                buffer: OVERSIZE + 0x2000..OVERSIZE + 0x4000,
                source: Source::Arena(oversize),
            }
        );
        // The byte past an allocation's end is not in it, and neither
        // is the hole after it -- the one place an off-by-one in the
        // segment search would show.
        assert_eq!(heap.locate(OVERSIZE + 0x4400), Liveness::Unknown);
        assert_eq!(heap.locate(OVERSIZE + 0x4700), Liveness::Unknown);
        // And past everything the arena imported.
        assert_eq!(heap.locate(OVERSIZE + 0x5000), Liveness::Unknown);
        assert_eq!(
            heap.locate(OVERSIZE + 0x4000),
            Liveness::Live {
                buffer: OVERSIZE + 0x4000..OVERSIZE + 0x4400,
                source: Source::Arena(1 - oversize),
            }
        );

        // The cache buffers are the slab layer's, and the arenas add
        // nothing to what an enumeration differential compares against
        // mdb's cache walkers: an arena has no buffers to enumerate.
        assert_eq!(heap.live_buffers().count(), 17);

        // What the differential against its *arena* walkers compares,
        // spelled the same way: every extent of one liveness, in
        // address order, bounds and all.
        let extents = |live: bool| heap.arena_extents(live).collect::<Vec<_>>();
        assert_eq!(
            extents(true),
            [
                OVERSIZE..OVERSIZE + 0x2000,
                OVERSIZE + 0x4000..OVERSIZE + 0x4400,
                OVERSIZE + 0x4800..OVERSIZE + 0x4c00,
            ]
        );
        assert_eq!(extents(false), [OVERSIZE + 0x2000..OVERSIZE + 0x4000]);
    }

    /// A static holding a pointer is worth what the thing it points at
    /// says it is.
    #[test]
    fn test_an_arena_that_does_not_name_itself_is_refused() {
        let mut f = two_caches();
        arenas(&mut f);
        f.put_str(ARENAS + LP64.vm_name, "umem_internal");
        let heap = UmemHeap::build(&f).expect("the caches still walk");
        assert!(!heap.stats().oversize_walked);
        assert_eq!(heap.stats().arenas, 1);
        assert_eq!(heap.locate(OVERSIZE + 0x100), Liveness::Unknown);
    }

    /// Segments tile the span they are in, in address order. One that
    /// reaches past it, or back over the one before it, is a list this
    /// walk is not reading right -- and the whole arena declines,
    /// because which of the two readings is wrong is what nothing here
    /// can tell.
    #[test]
    fn test_a_segment_outside_its_span_declines_the_arena() {
        for (member, value) in [
            (LP64.vs_end, OVERSIZE + 0x5000),
            (LP64.vs_start, OVERSIZE - 0x1000),
        ] {
            let mut f = two_caches();
            arenas(&mut f);
            f.put_u64(SEGS + 0x40 + member, value);
            let heap = UmemHeap::build(&f).expect("the caches still walk");
            assert_eq!(heap.stats().arenas, 1, "{member} {value:#x}");
            assert_eq!(heap.locate(OVERSIZE + 0x100), Liveness::Unknown);
        }
    }

    /// A span is not an allocation: it is what the arena imported, and
    /// the segments inside it are what it handed out. Believing it as
    /// an extent of its own would answer for every address in it twice.
    #[test]
    fn test_a_span_is_not_an_allocation() {
        let mut f = two_caches();
        arena(
            &mut f,
            0,
            "umem_oversize_arena",
            "umem_oversize",
            &[SegSpec {
                start: OVERSIZE,
                end: OVERSIZE + 0x4000,
                kind: VMEM_SPAN,
            }],
        );
        arena(
            &mut f,
            1,
            "umem_memalign_arena",
            "umem_memalign",
            &[SegSpec {
                start: OVERSIZE + 0x4000,
                end: OVERSIZE + 0x5000,
                kind: VMEM_SPAN,
            }],
        );
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        assert!(heap.stats().oversize_walked);
        assert_eq!((heap.stats().arena_live, heap.stats().arena_freed), (0, 0));
        assert_eq!(heap.locate(OVERSIZE), Liveness::Unknown);
    }

    /// The malloc header of an arena allocation is read at the segment
    /// the arena kept, which is what lets an address *inside* a
    /// memaligned allocation -- every tokio task cell is one -- answer
    /// for the allocation containing it rather than for nothing.
    #[test]
    fn test_an_arena_allocation_answers_from_the_header_at_its_base() {
        let mut f = two_caches();
        arenas(&mut f);
        // What `memalign` writes: two tags of its own, and a pointer
        // sixteen bytes above the segment the arena handed out.
        let ptr = OVERSIZE + 16;
        tag(&mut f, ptr, MEMALIGN_MAGIC, 0x1800);
        high_tag(&mut f, ptr, MEMALIGN_MAGIC, 0x1800);
        let heap = UmemHeap::build(&f).expect("the walk built an index");

        assert_eq!(
            heap.allocation(&f, ptr + 0x40),
            Some(Allocation {
                live: true,
                size: Size::Requested(0x1800 - 16),
                offset: 0x40,
            })
        );
        // The freed segment beside it has no header left to read, so
        // the segment is all there is to measure.
        assert_eq!(
            heap.allocation(&f, OVERSIZE + 0x2000),
            Some(Allocation {
                live: false,
                size: Size::Block(0x2000),
                offset: 0,
            })
        );
    }

    /// The other half of the self-check, staged the same way: what the
    /// layers below and beside the slab have to satisfy, none of which
    /// the slab arithmetic above would notice.
    #[test]
    fn test_the_self_check_catches_a_parked_or_arena_reading_that_cannot_be() {
        let cache = Cache {
            addr: CACHES,
            name: "umem_alloc_64".to_string(),
            bufsize: 64,
            chunksize: 64,
            slabsize: 0x1000,
            flags: 0,
            slabs: 1,
            slabs_declined: 0,
            live: 3,
            freed: 0,
            parked: 1,
            parked_walked: true,
            bufctl: 56,
        };
        // The parked buffer is the second chunk, marked on the slab
        // the way the walk marks it -- the bit beside the freelist's,
        // never one of the freelist's own.
        let slab = || Slab {
            base: BUFFERS,
            chunksize: 64,
            chunks: 4,
            cache: 0,
            free: Vec::new(),
            parked: vec![0b10],
        };
        let arena = Arena {
            addr: ARENAS,
            name: "umem_oversize".to_string(),
            segs: 1,
            live: 1,
            freed: 0,
            live_bytes: 0x1000,
        };
        let seg = |start: u64, live: bool| Seg {
            start,
            end: start + 0x1000,
            arena: 0,
            live,
        };
        let heap = |parked: Vec<u64>, segs: Vec<Seg>| UmemHeap {
            caches: vec![cache.clone()],
            slabs: vec![slab()],
            parked,
            arenas: vec![arena.clone()],
            segs,
            arena_span: OVERSIZE..OVERSIZE + 0x2000,
            stats: Stats::default(),
        };

        let sound = heap(vec![BUFFERS + 64], vec![seg(OVERSIZE, true)]);
        assert!(sound.violations().is_empty(), "{:?}", sound.violations());

        // Each of these is a reading the walk refuses to produce, and
        // the message says which: a parked buffer that is no buffer,
        // one two pockets both hold, a count that does not match what
        // the index holds, and an arena segment inside a slab -- two
        // layers answering for the same memory, where the walk answers
        // from the more specific one and would be answering wrong.
        for (parked, segs, expected) in [
            (
                vec![BUFFERS + 8],
                vec![seg(OVERSIZE, true)],
                "no walked buffer",
            ),
            (
                vec![BUFFERS + 64, BUFFERS + 64],
                vec![seg(OVERSIZE, true)],
                "parked twice",
            ),
            (Vec::new(), vec![seg(OVERSIZE, true)], "counted 1 parked"),
            (
                vec![BUFFERS + 64],
                vec![seg(BUFFERS, true)],
                "inside a walked slab",
            ),
            (
                vec![BUFFERS + 64],
                vec![seg(OVERSIZE, true), seg(OVERSIZE + 8, false)],
                "overlap",
            ),
            (
                vec![BUFFERS + 64],
                vec![seg(OVERSIZE, false)],
                "counted 1 live",
            ),
            // The parked set is kept twice over; the two readings have
            // to say the same thing about the same buffer.
            (
                vec![BUFFERS + 128],
                vec![seg(OVERSIZE, true)],
                "not marked on its slab",
            ),
        ] {
            let found = heap(parked, segs).violations();
            assert!(
                found.iter().any(|v| v.contains(expected)),
                "{expected}: {found:?}"
            );
        }
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

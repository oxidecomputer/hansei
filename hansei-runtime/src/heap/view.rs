// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The allocator index as the renderer sees it.
//!
//! reify does the dereferencing that turns an address into a printed
//! value, and it is where a stale pointer becomes fiction a human reads
//! — but it cannot name [`UmemHeap`], because this crate depends on
//! reify rather than the other way round. So reify declares the shape of
//! the question ([`reify::Heap`]) and this answers it: the index, the
//! target its malloc headers are read through, and the tally of what the
//! corroboration refused.

use crate::heap::umem::{Liveness, UmemHeap};

use proc::Target;

use std::sync::atomic::{AtomicU64, Ordering};

/// How often each corroboration refused something the bytes alone would
/// have allowed, over the life of a session.
///
/// A gate that fires is invisible by design — the whole point is that
/// the fiction is *not* printed — so the tally is the only account of
/// what it did. Relaxed ordering throughout: these are counters read
/// after the fact by a human, not a synchronization channel.
#[derive(Debug, Default)]
pub struct GateCounts {
    freed: AtomicU64,
    clipped: AtomicU64,
    base_mismatch: AtomicU64,
}

impl GateCounts {
    /// Pointers into freed memory left as addresses.
    pub fn freed(&self) -> u64 {
        self.freed.load(Ordering::Relaxed)
    }

    /// Sequences cut to the allocation holding their buffer.
    pub fn clipped(&self) -> u64 {
        self.clipped.load(Ordering::Relaxed)
    }

    /// Owning buffers that did not start where their allocation does.
    /// Counted only — nothing declines on this yet.
    pub fn base_mismatch(&self) -> u64 {
        self.base_mismatch.load(Ordering::Relaxed)
    }
}

/// [`UmemHeap`] joined to the target its malloc headers are read
/// through and to the tally the gates count into.
///
/// Borrows all three rather than owning them, so a session can hand one
/// out per render from state it keeps itself — the tally in particular
/// has to outlive any single render for a session's total to mean
/// anything.
pub struct HeapView<'a, T> {
    heap: &'a UmemHeap,
    target: &'a T,
    gates: &'a GateCounts,
}

impl<'a, T: Target> HeapView<'a, T> {
    /// The index this view reads, borrowed for as long as the index
    /// itself lives rather than for as long as the view does — a view
    /// is a temporary a session hands out per render, and the index it
    /// names outlives every one of them.
    pub fn heap(&self) -> &'a UmemHeap {
        self.heap
    }

    pub fn new(heap: &'a UmemHeap, target: &'a T, gates: &'a GateCounts) -> Self {
        HeapView {
            heap,
            target,
            gates,
        }
    }
}

impl<T: Target> reify::Heap for HeapView<'_, T> {
    fn locate(&self, addr: u64) -> reify::Liveness {
        match self.heap.locate(addr) {
            Liveness::Live { buffer, .. } => reify::Liveness::Live { block: buffer },
            Liveness::Freed { .. } => reify::Liveness::Freed,
            Liveness::Unknown => reify::Liveness::Unknown,
        }
    }

    fn owns(&self, addr: u64) -> Option<bool> {
        // Through `allocation` rather than the malloc tag directly, so
        // this and `whatis` cannot disagree about where an allocation
        // starts: a zero offset is exactly what that answer calls "the
        // address *is* the allocation".
        Some(self.heap.allocation(self.target, addr)?.offset == 0)
    }

    fn note(&self, gate: reify::Gate) {
        let counter = match gate {
            reify::Gate::Freed => &self.gates.freed,
            reify::Gate::Clipped => &self.gates.clipped,
            reify::Gate::BaseMismatch => &self.gates.base_mismatch,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::heap::umem::MALLOC_MAGIC;
    use crate::heap::umem::tests::{BUFFERS, Fake, SlabSpec, cache, fake, tag};

    use reify::{Gate, Heap as _};

    const CHUNK: u64 = 64;

    /// A target with one cache of four 64-byte buffers, the first two
    /// handed out and the last two on the freelist, and a malloc header
    /// ahead of the first buffer's pointer.
    fn target() -> (Fake, u64) {
        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_64",
            CHUNK,
            0,
            &[SlabSpec {
                base: BUFFERS,
                chunks: 4,
                free: vec![2, 3],
            }],
        );
        // What the malloc shim hands out of the first buffer: eight
        // bytes past its base, with the tag it wrote in between.
        let ptr = BUFFERS + 8;
        tag(&mut f, ptr, MALLOC_MAGIC, 24);
        (f, ptr)
    }

    /// The three verdicts the renderer asks for, mapped from the ones
    /// the walk keeps. A cache the walk believed answers `Live` for a
    /// buffer still handed out and `Freed` for one on the freelist,
    /// with the block's own bounds on the live one — which is the
    /// extent a claimed sequence is then held to.
    #[test]
    fn test_the_view_answers_the_renderer_for_each_verdict() {
        let (f, _) = target();
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        let gates = GateCounts::default();
        let view = HeapView::new(&heap, &f, &gates);

        assert_eq!(
            view.locate(BUFFERS),
            reify::Liveness::Live {
                block: BUFFERS..BUFFERS + CHUNK
            }
        );
        // An address inside the second buffer, not its base: still the
        // buffer that holds it, so a sequence starting there is bounded
        // by that buffer's end rather than the slab's.
        assert_eq!(
            view.locate(BUFFERS + CHUNK + 8),
            reify::Liveness::Live {
                block: BUFFERS + CHUNK..BUFFERS + 2 * CHUNK
            }
        );
        assert_eq!(view.locate(BUFFERS + 2 * CHUNK), reify::Liveness::Freed);
        // Past every slab the walk covers, nothing is claimed at all —
        // which is what a render with no verdict behaves on.
        assert_eq!(view.locate(BUFFERS + 0x10_0000), reify::Liveness::Unknown);
    }

    /// Whether an address starts its allocation, which is what the
    /// base-match gate weighs: an address past the handed-out pointer
    /// owns nothing.
    #[test]
    fn test_the_view_says_which_address_owns_its_allocation() {
        let (f, ptr) = target();
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        let gates = GateCounts::default();
        let view = HeapView::new(&heap, &f, &gates);

        assert_eq!(view.owns(ptr), Some(true));
        assert_eq!(view.owns(ptr + 8), Some(false));
        // The block's base is inside the header rather than past it, so
        // there is no handed-out pointer to measure it from and it is
        // measured against the block — where it is the start. "Starts
        // its allocation" is the claim, not "is the malloc pointer".
        assert_eq!(view.owns(BUFFERS), Some(true));
        // Outside the heap the question has no answer, rather than the
        // answer "no" — a caller must not read a silence as evidence.
        assert_eq!(view.owns(BUFFERS + 0x10_0000), None);
    }

    /// Each gate counts into its own tally and no other, so the numbers
    /// a session reports say which corroboration refused what.
    #[test]
    fn test_each_gate_counts_into_its_own_tally() {
        let (f, _) = target();
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        let gates = GateCounts::default();
        let view = HeapView::new(&heap, &f, &gates);

        assert_eq!(
            (gates.freed(), gates.clipped(), gates.base_mismatch()),
            (0, 0, 0)
        );
        view.note(Gate::Freed);
        view.note(Gate::Freed);
        view.note(Gate::Clipped);
        view.note(Gate::BaseMismatch);
        assert_eq!(
            (gates.freed(), gates.clipped(), gates.base_mismatch()),
            (2, 1, 1)
        );
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A stand-in for a target's allocator, for the scans and walks that
//! read through a [`reify::Heap`].
//!
//! Describe the blocks that should exist and what the allocator thinks
//! of each; an address in no described block is
//! [`Unknown`](reify::Liveness::Unknown), which is what most of a
//! target is. The real bridge, [`HeapView`](crate::heap::view::HeapView)
//! over a [`UmemHeap`](crate::heap::umem::UmemHeap), stays covered by
//! the umem synthetic-target tests; this double exists so a scan's
//! bounds, refusals and counts can be asserted on every platform, with
//! answers chosen rather than recovered.

use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct FakeHeap {
    blocks: Vec<Block>,
    freed: AtomicU64,
    clipped: AtomicU64,
    base_mismatch: AtomicU64,
}

struct Block {
    range: Range<u64>,
    /// The address the program was handed for this block: its base
    /// unless a malloc header sits ahead of it.
    user: u64,
    live: bool,
}

impl FakeHeap {
    pub fn new() -> Self {
        Self::default()
    }

    /// A live block over `range`, handed out at its base.
    pub fn live(self, range: Range<u64>) -> Self {
        let user = range.start;
        self.block(range, user, true)
    }

    /// A live block whose pointer is `user` rather than its base.
    pub fn live_at(self, range: Range<u64>, user: u64) -> Self {
        self.block(range, user, true)
    }

    /// A block the allocator has taken back.
    pub fn freed(self, range: Range<u64>) -> Self {
        let user = range.start;
        self.block(range, user, false)
    }

    fn block(mut self, range: Range<u64>, user: u64, live: bool) -> Self {
        assert!(range.start < range.end, "a block has extent");
        self.blocks.push(Block { range, user, live });
        self
    }

    /// How often each gate fired, in declaration order: freed targets
    /// refused, sequences cut, owning buffers off base.
    pub fn counts(&self) -> (u64, u64, u64) {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        (
            load(&self.freed),
            load(&self.clipped),
            load(&self.base_mismatch),
        )
    }

    fn at(&self, addr: u64) -> Option<&Block> {
        self.blocks.iter().find(|b| b.range.contains(&addr))
    }
}

impl reify::Heap for FakeHeap {
    fn locate(&self, addr: u64) -> reify::Liveness {
        match self.at(addr) {
            None => reify::Liveness::Unknown,
            Some(block) if block.live => reify::Liveness::Live {
                block: block.range.clone(),
            },
            Some(_) => reify::Liveness::Freed,
        }
    }

    fn owns(&self, addr: u64) -> Option<bool> {
        Some(self.at(addr)?.user == addr)
    }

    fn note(&self, gate: reify::Gate) {
        let counter = match gate {
            reify::Gate::Freed => &self.freed,
            reify::Gate::Clipped => &self.clipped,
            reify::Gate::BaseMismatch => &self.base_mismatch,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reify::{Gate, Heap, Liveness};

    #[test]
    fn test_the_double_answers_each_verdict_and_counts_each_gate() {
        let heap = FakeHeap::new()
            .live(0x1000..0x1040)
            .live_at(0x2000..0x2040, 0x2008)
            .freed(0x3000..0x3040);
        assert_eq!(
            heap.locate(0x1010),
            Liveness::Live {
                block: 0x1000..0x1040
            }
        );
        assert_eq!(heap.locate(0x3000), Liveness::Freed);
        assert_eq!(heap.locate(0x4000), Liveness::Unknown);
        assert_eq!(heap.owns(0x1000), Some(true));
        assert_eq!(heap.owns(0x1008), Some(false));
        assert_eq!(heap.owns(0x2008), Some(true));
        assert_eq!(heap.owns(0x2000), Some(false));
        assert_eq!(heap.owns(0x4000), None);
        heap.note(Gate::Freed);
        heap.note(Gate::Clipped);
        heap.note(Gate::Clipped);
        heap.note(Gate::BaseMismatch);
        assert_eq!(heap.counts(), (1, 2, 1));
    }
}

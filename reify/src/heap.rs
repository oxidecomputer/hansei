// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the target's own allocator says about the memory the renderer is
//! about to read.
//!
//! Every value printed from a core is bytes read through a pointer that
//! something else wrote, and nothing in a type says whether the memory it
//! names is still the value it claims to be: a slot left behind in a
//! coroutine frame, a queue node freed while a live pointer still names
//! it, a length word out of reused memory. The allocator knows, and its
//! metadata is in the core.
//!
//! This is the *shape* of that knowledge, not the reading of it: reify
//! cannot name the walker that produces it, because the crate that owns
//! the walker depends on reify rather than the other way round. A caller
//! that has one hands it in ([`crate::DisplayValue::heap`]); a caller
//! that has none — a target whose allocator keeps no readable metadata,
//! which is most of them — hands in nothing, and every gate below is
//! inert.

use std::ops::Range;

/// What the allocator says about one address.
///
/// [`Unknown`](Liveness::Unknown) is the answer for everything the
/// allocator does not account for — a stack, a static, an arena the
/// walker does not read — and it means "behave as though there were no
/// allocator to ask", never "suspicious".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    /// The address is inside a block the allocator still considers
    /// handed out, whose bounds are `block`. What a claimed extent is
    /// held to: a sequence starting here cannot run past `block.end`
    /// and still be the allocation it says it is.
    Live { block: Range<u64> },
    /// The address is inside a block the allocator has taken back. The
    /// bytes are whatever the last owner left; nothing there is a value.
    Freed,
    /// Nothing is claimed about the address.
    Unknown,
}

/// One corroboration refusing something the bytes alone would have
/// allowed. Counted rather than reported per occurrence: a session's
/// tally is what says whether a gate is worth what it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// A pointer into freed memory, left as an address instead of
    /// expanded into the value behind it.
    Freed,
    /// A sequence whose claimed extent runs past the allocation holding
    /// its buffer, cut to what fits.
    Clipped,
    /// A buffer that owns its whole allocation and does not start at
    /// one. Counted only — a mismatch is evidence about a pointer, and
    /// what to do about it is not decided yet.
    BaseMismatch,
}

/// The target's allocator metadata, as much of it as the renderer asks.
///
/// `Sync` because a render pass fans a large collection out across
/// worker threads, all reading through the one index.
pub trait Heap: Sync {
    /// What the allocator says about `addr`.
    fn locate(&self, addr: u64) -> Liveness;

    /// Whether `addr` is where its allocation starts — the pointer the
    /// program was handed, or the block's own base where no header
    /// survives to name one — rather than an address inside one.
    /// `None` where the allocator accounts for neither.
    fn owns(&self, addr: u64) -> Option<bool>;

    /// Record that a gate fired.
    fn note(&self, gate: Gate);
}

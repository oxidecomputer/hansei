// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a read over target memory is corroborated against.
//!
//! Every route that dereferences a pointer on behalf of discovery or
//! semantic interpretation takes a [`ReadContext`] explicitly: the
//! allocator's account of the heap, where the target has one, so a
//! referent the allocator has taken back is refused before it is read
//! and a live block bounds what may be read out of it. The recorded
//! walk contract's own accessors pass an empty context — they read
//! what the runtime's structures point at, and their corroboration is
//! the census's — so no caller inherits the renderer's implicit
//! peeling or an unstated heap by accident.

use hansei_bundle::BundleTypeId;

/// A value's identity for observation caches and diagnostics: where it
/// is and which nominal type it was read as. The type is part of the
/// key because one address read as two types is two observations, and
/// two library copies can give one layout two ids.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ValueKey {
    pub addr: u64,
    pub ty: BundleTypeId,
}

/// The evidence a read is held to.
#[derive(Copy, Clone, Default)]
pub struct ReadContext<'a> {
    /// The allocator's account of what is handed out, where the target
    /// has one to consult. `None` claims nothing: every read is then
    /// bounded only by the target's own mappings.
    pub heap: Option<&'a dyn reify::Heap>,
}

impl<'a> ReadContext<'a> {
    /// No allocator evidence: reads are uncorroborated.
    pub const fn none() -> Self {
        ReadContext { heap: None }
    }

    /// Reads corroborated against `heap`.
    pub fn with_heap(heap: &'a dyn reify::Heap) -> Self {
        ReadContext { heap: Some(heap) }
    }

    /// Whether the allocator has taken back the block at `addr`. Only a
    /// `Freed` answer refuses; `Live` is the ordinary answer and
    /// `Unknown` claims nothing.
    pub fn taken_back(&self, addr: u64) -> bool {
        self.heap
            .is_some_and(|heap| matches!(heap.locate(addr), reify::Liveness::Freed))
    }

    /// Why a typed read of `size` bytes at `addr` cannot be believed,
    /// or `None` when the allocator permits it: the block is freed, or
    /// the typed range runs past the live block holding its start. An
    /// `Unknown` block permits the read but corroborates nothing.
    pub fn refusal(&self, addr: u64, size: u64) -> Option<String> {
        let heap = self.heap?;
        match heap.locate(addr) {
            reify::Liveness::Freed => Some(format!(
                "the allocator has taken back the memory at {addr:#x}"
            )),
            reify::Liveness::Live { block } => {
                let end = addr.checked_add(size)?;
                (end > block.end).then(|| {
                    format!(
                        "{size} bytes at {addr:#x} run past the allocation holding it \
                         ({:#x}..{:#x})",
                        block.start, block.end
                    )
                })
            }
            reify::Liveness::Unknown => None,
        }
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Allocator corroboration: what the target's own malloc says about an
//! address, read out of its metadata rather than inferred from the
//! bytes at it.
//!
//! Nothing here is tokio's, which is why it sits beside [`crate::tokio`]
//! rather than inside it: a pointer either lands in an allocation the
//! allocator still considers live or it does not, whatever the value
//! walk believed it pointed at.

pub mod umem;
pub mod view;

use crate::heap::umem::UmemHeap;

use anyhow::{Result, anyhow};
use proc::Target;
use proc::snapshot::RecordedHeapEvidence;

/// The allocator evidence a session or capture reads under, prepared
/// once before anything is gated by it, under the policy the target
/// records about itself.
///
/// A target that records nothing — a core — is simply asked, and
/// `None` means only that allocator evidence is unavailable: no
/// libumem mapped, an allocator not yet initialized, metadata that
/// failed its own invariants, or a read the target refused; the walk
/// does not say which, and nothing downstream may treat the answer as
/// "no allocator". A snapshot records what its capture did. One that
/// recorded no index is not asked at all, since the reads that would
/// rebuild one were never captured and a partial answer over whatever
/// happens to be there would gate the replay differently from the
/// capture. One that recorded an index has every read the walk needs,
/// so failing to rebuild it is an incomplete capture — an error, never
/// a quiet fall back to reading ungated.
pub fn prepare<T: Target>(target: &T) -> Result<Option<UmemHeap>> {
    match target.recorded_heap_evidence() {
        None => Ok(UmemHeap::build(target)),
        Some(RecordedHeapEvidence::Unavailable) => Ok(None),
        Some(RecordedHeapEvidence::Available) => {
            UmemHeap::build(target).map(Some).ok_or_else(|| {
                anyhow!(
                    "the snapshot records an allocator index its replay cannot rebuild; \
                 the capture is incomplete"
                )
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::umem::tests::{BUFFERS, SlabSpec, cache, fake};
    use crate::testkit;

    use proc::snapshot::Recorder;

    /// A target that records nothing about the question is asked, and
    /// the walk's answer stands: an index where umem's metadata is
    /// readable, and nothing where it is not.
    #[test]
    fn test_a_target_recording_no_policy_is_asked() {
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
                free: vec![2, 3],
            }],
        );
        assert_eq!(f.recorded_heap_evidence(), None);
        assert!(prepare(&f).unwrap().is_some());
    }

    /// A snapshot that recorded no index is not asked at all: the reads
    /// that would rebuild one were never captured, so not one read is
    /// made before the neutral answer.
    #[test]
    fn test_a_snapshot_recording_no_index_is_not_asked() {
        // Recorded here rather than read off a set, so the policy is
        // the one under test whichever kind of target the run reads.
        let (_, fixture) = testkit::load(testkit::set_or_any("linux"), "simple-await");
        let snapshot = Recorder::new(&fixture)
            .snapshot(RecordedHeapEvidence::Unavailable)
            .unwrap();
        assert_eq!(snapshot.heap_evidence(), RecordedHeapEvidence::Unavailable);
        let recorder = Recorder::new(&snapshot);
        assert!(prepare(&recorder).unwrap().is_none());
        assert_eq!(recorder.charged().entries, 0);
    }

    /// A snapshot that claims an index its reads cannot rebuild is an
    /// incomplete capture, refused outright — never a quiet fall back
    /// to reading ungated.
    #[test]
    fn test_a_claimed_index_that_cannot_be_rebuilt_is_refused() {
        let (_, snapshot) = testkit::load(testkit::set_or_any("linux"), "simple-await");
        let claimed = Recorder::new(&snapshot)
            .snapshot(RecordedHeapEvidence::Available)
            .unwrap();
        let err = prepare(&claimed).expect_err("the claim is not honored");
        assert_eq!(
            err.to_string(),
            "the snapshot records an allocator index its replay cannot rebuild; \
             the capture is incomplete"
        );
    }
}

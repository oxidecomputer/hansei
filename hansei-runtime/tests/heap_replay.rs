// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Allocator evidence over cores and through a recording: the illumos
//! cores are taken under libumem, so the walk builds an index from
//! them, a capture recorded through the recorder records that it did,
//! and a replay rebuilds the same index from the recorded reads and
//! gates the same population. The Linux cores carry none, which is what
//! the runtime's heap double exists for.

use hansei_runtime::heap;
use hansei_runtime::testkit::corrupt::Corrupt;
use hansei_runtime::testkit::{self, PROGRAMS, fixture_sets};
use hansei_runtime::tokio::bundle::Context;
use hansei_runtime::tokio::census::FutureCensus;

use hansei_bundle::BundleView;
use proc::RecordedHeapEvidence;
use proc::Target;
use proc::snapshot::Recorder;

/// The gated population a census settled on, as the addresses of its
/// finds and what it refused — what a replay has to reproduce exactly.
fn population(census: &FutureCensus) -> (Vec<u64>, Vec<u64>, Vec<u64>, usize) {
    (
        census.held.iter().map(|h| h.addr).collect(),
        census.sets.iter().map(|s| s.addr).collect(),
        census.join_sets.iter().map(|s| s.addr).collect(),
        census.refused,
    )
}

/// Every illumos core yields an index, and every Linux core none.
/// Neither set stands for the other: the positive coverage is the
/// illumos set's alone.
#[test]
fn test_each_set_reads_the_allocator_evidence_its_system_has() {
    for set in fixture_sets() {
        for program in PROGRAMS {
            let (bundle, core) = testkit::load(set, program);
            let run = testkit::run(&bundle, &core);
            assert_eq!(run.heap.is_some(), *set == "illumos", "[{set}] {program}");
            if let Some(index) = &run.heap {
                let stats = index.stats();
                assert!(
                    stats.caches > 0 && stats.slabs > 0,
                    "[{set}] {program}: {stats:?}"
                );
            }
        }
    }
}

/// The tasks a run listed, by their headers.
fn tasks<T: Target>(run: &testkit::Run<'_, T>) -> Vec<u64> {
    run.list.tasks.iter().map(|t| t.addr.0).collect()
}

/// A capture of an umem-bearing core through the recorder builds the
/// index through it, records `Available`, and replays to the same
/// gated population: the same finds, the same refusals, the same task
/// list. That is the whole claim the label makes.
#[test]
fn test_a_recapture_replays_the_same_gated_population() {
    // The illumos cores are the ones under libumem; a run that does not
    // read that set has no index to capture.
    if !testkit::reads("illumos") {
        return;
    }
    for program in PROGRAMS {
        let (bundle, core) = testkit::load("illumos", program);
        let first = testkit::run(&bundle, &core);
        let index = first
            .heap
            .as_ref()
            .expect("the illumos core carries an index");

        let recorder = Recorder::new(&core);
        let ctx = Context::new(&recorder, BundleView::new(&bundle)).unwrap();
        let mut e = testkit::enumerate(&ctx, &recorder);
        assert!(
            e.heap.is_some(),
            "{program}: the index rebuilds through the recorder"
        );
        e.discover(&ctx, &[]);
        let census = e.with_read(&recorder, |read| testkit::census_with(&ctx, &e.list, read));
        assert_eq!(population(&census), population(&first.census), "{program}");
        let recaptured = recorder
            .snapshot(RecordedHeapEvidence::Available)
            .expect("the recorder assembles a snapshot");

        let replay = testkit::run(&bundle, &recaptured);
        let rebuilt = replay
            .heap
            .as_ref()
            .expect("the recapture rebuilds its index");
        assert_eq!(rebuilt.stats().slabs, index.stats().slabs, "{program}");
        assert_eq!(
            population(&replay.census),
            population(&first.census),
            "{program}"
        );
        assert_eq!(tasks(&replay), tasks(&first), "{program}");
    }
}

/// A capture that claims an index whose metadata cannot be read is an
/// incomplete capture: the attach refuses it outright rather than
/// reading the pair ungated, and says which claim it could not honor.
/// The capture is recorded here, from the fixture, so it claims the
/// index the fixture's own walk built — a fresh core records no claim
/// of its own to deny.
#[test]
fn test_a_claimed_index_whose_metadata_is_denied_does_not_attach() {
    // Only an illumos capture maps libumem.
    if !testkit::reads("illumos") {
        return;
    }
    let (bundle, fixture) = testkit::load("illumos", "simple-await");
    let captured = testkit::record(&bundle, &fixture);
    assert_eq!(
        captured.recorded_heap_evidence(),
        Some(RecordedHeapEvidence::Available),
        "the fixture's walk builds an index"
    );
    let ready = captured
        .lookup_symbol_by_name("libumem.so.1`umem_ready")
        .expect("the capture recorded umem's own symbols")
        .st_value;
    let denied = Corrupt::new(&captured).deny(ready..ready + 4);
    let ctx = Context::new(&denied, BundleView::new(&bundle)).unwrap();
    let err = match testkit::try_enumerate(&ctx, &denied) {
        Ok(_) => panic!("the claim is not honored"),
        Err(e) => e,
    };
    assert!(
        format!("{err:#}").contains("records an allocator index its replay cannot rebuild"),
        "{err:#}"
    );
    let err = heap::prepare(&denied).expect_err("the walk cannot rebuild");
    assert!(
        format!("{err:#}").contains("the capture is incomplete"),
        "{err:#}"
    );
}

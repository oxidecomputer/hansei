// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The churn-capture oracle: what a capture taken at an arbitrary
//! instant of a churning workload must still satisfy, over one
//! snapshot pair.
//!
//! Opt-in, like the genfix oracle: `HANSEI_CHURN_PAIR=<prefix>` names
//! a pair as `<prefix>.tinfo` / `<prefix>.snapshot` (the churn loop,
//! `test-programs/genfix/churn.sh`, passes what it just captured), and
//! without it the test skips with a message.
//!
//! The oracle is safety only. The workload completes and respawns
//! futures continuously and the capture is not synchronized to
//! anything, so nothing about the *content* of the listing can be
//! asserted — no registry diff (churn programs register nothing), no
//! error- or cap-freeness, no healthy-only audit. What must hold over
//! any instant whatsoever: the pipeline neither panics nor loops
//! (iteration caps bound the walks; a hang fails in the harness), the
//! census obeys its construction rules (the total audit, run inside
//! `testkit::census`, which also holds every error to naming an
//! address), and the walk stays deterministic — a pair that captured
//! cleanly must replay cleanly. The shared outcome list is printed per
//! run for the loop's coverage summary, so a batch shows which shapes
//! its arbitrary instants actually caught mid-flight.

use hansei_bundle::Bundle;
use hansei_runtime::testkit;
use proc::snapshot::Snapshot;

#[test]
fn test_churn_capture_walks_safely() {
    let Ok(prefix) = std::env::var("HANSEI_CHURN_PAIR") else {
        eprintln!("HANSEI_CHURN_PAIR is not set; nothing to check (churn.sh sets it)");
        return;
    };

    let bundle = Bundle::load(format!("{prefix}.tinfo").as_ref()).expect("the bundle loads");
    let snapshot =
        Snapshot::load(format!("{prefix}.snapshot").as_ref()).expect("the snapshot loads");
    // The capture-time pipeline ran to completion to produce this pair,
    // and a snapshot replays the same bytes, so discovery succeeding
    // here is part of the determinism claim — a panic in the pipeline
    // is a real finding, not a flaky capture. The total audit runs
    // (and panics) inside it. Nothing beyond that is asked: a
    // mid-flight capture is entitled to errors and caps, so the
    // healthy and registry problem lists are deliberately not called.
    let r = testkit::run(&bundle, &snapshot);

    testkit::print_outcomes(&r.census);
    println!(
        "churn: {} tasks, {} held, {} sets, {} join sets, {} errors, capped: {:?}",
        r.list.tasks.len(),
        r.census.held.len(),
        r.census.sets.len(),
        r.census.join_sets.len(),
        r.census.errors.len(),
        r.census.capped,
    );
}

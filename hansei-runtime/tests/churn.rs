// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The churn-capture oracle: what a core taken at an arbitrary instant
//! of a churning workload must still satisfy.
//!
//! Opt-in, like the genfix oracle: `HANSEI_CHURN_CORE` names the core,
//! `HANSEI_CHURN_BINARY` the build A it was taken of, and
//! `HANSEI_CHURN_TINFO` the bundle extracted from that program's build
//! B (the churn loop, `test-programs/genfix/churn.sh`, passes what it
//! just took), and without them the test skips with a message.
//!
//! The oracle is safety only. The workload completes and respawns
//! futures continuously and the core is not synchronized to anything,
//! so nothing about the *content* of the listing can be asserted — no
//! registry diff (churn programs register nothing), no error- or
//! cap-freeness, no healthy-only audit. What must hold over any
//! instant whatsoever: the pipeline neither panics nor loops
//! (iteration caps bound the walks; a hang fails in the loop's
//! timeout), the census obeys its construction rules (the total
//! audit, run inside `testkit::census`, which also holds every error
//! to naming an address), and the walk is deterministic — run twice
//! over the same core, it gives the same result. The shared outcome
//! list is printed per run for the loop's coverage summary, so a batch
//! shows which shapes its arbitrary instants actually caught
//! mid-flight.

use hansei_bundle::Bundle;
use hansei_runtime::testkit;
use proc::{CoreFiles, Proc, Target};

use std::fmt::Write as _;
use std::path::PathBuf;

/// What one run of the pipeline found, in the order it found it: the
/// tasks, the census's finds, its errors and caps. The census's maps
/// are left out, since their debug order is a hasher's.
fn found<T: Target>(r: &testkit::Run<'_, T>) -> String {
    let mut out = String::new();
    for t in &r.list.tasks {
        writeln!(out, "task {:#x} {:?}", t.addr.0, t.future).unwrap();
    }
    for h in &r.census.held {
        writeln!(
            out,
            "held {:?} {} {:#x} {:#x} {:?} {} {}",
            h.future, h.local, h.slot, h.addr, h.via, h.owner, h.frame
        )
        .unwrap();
    }
    for s in &r.census.sets {
        writeln!(out, "set {s:?}").unwrap();
    }
    for s in &r.census.join_sets {
        writeln!(out, "join set {s:?}").unwrap();
    }
    for e in &r.census.errors {
        writeln!(out, "error {e:#}").unwrap();
    }
    writeln!(
        out,
        "capped {:?} uncertain {} refused {}",
        r.census.capped, r.census.uncertain, r.census.refused
    )
    .unwrap();
    out
}

#[test]
fn test_churn_capture_walks_safely() {
    let var = |name| std::env::var_os(name).map(PathBuf::from);
    let (Some(core), Some(binary), Some(tinfo)) = (
        var("HANSEI_CHURN_CORE"),
        var("HANSEI_CHURN_BINARY"),
        var("HANSEI_CHURN_TINFO"),
    ) else {
        eprintln!(
            "HANSEI_CHURN_CORE, HANSEI_CHURN_BINARY and HANSEI_CHURN_TINFO are not set; \
             nothing to check (churn.sh sets them)"
        );
        return;
    };

    let bundle = Bundle::load(&tinfo).expect("the bundle loads");
    let files = CoreFiles {
        binary: Some(&binary),
        sysroot: None,
    };
    let proc = Proc::open_core_with(&core, files).expect("the core opens");
    // A panic in the pipeline is a real finding, not a flaky capture:
    // the core is fixed once taken. The total audit runs (and panics)
    // inside it. Nothing beyond that is asked: a mid-flight core is
    // entitled to errors and caps, so the healthy and registry problem
    // lists are deliberately not called.
    let r = testkit::run(&bundle, &proc);

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

    let again = testkit::run(&bundle, &proc);
    assert_eq!(
        found(&again),
        found(&r),
        "two runs over the same core found different things"
    );
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The generated-fixture oracle: everything a healthy capture of a
//! genfix program must satisfy, over a fresh core of it.
//!
//! Opt-in, like the matrix: `HANSEI_GENFIX_CAPTURE=<dir>` captures
//! `gen-soak` — whatever `src/bin/gen-soak.rs` holds, which the soak
//! loop has just written — into that directory the way every fixture
//! is captured (both builds, build A parked at its readiness marker
//! and cored, the bundle extracted from build B), and without it the
//! test skips with a message. The soak loop
//! (`test-programs/genfix/soak.sh`) runs this once per seed; a failure
//! here after a clean recapture is a failing seed, and its generated
//! source becomes a quarantined fixture. The core is read as it is:
//! the oracle diffs against the program's own registry, not a golden,
//! so nothing needs renaming.
//!
//! The oracle is the registry diff plus everything a *healthy* capture
//! is entitled to: the pipeline's total audit (inside
//! `testkit::census`), the healthy-only audit, no errors, no caps, and
//! a registry that parses and is non-empty. Every problem is collected
//! before failing, so a bad seed reports its whole story at once. The
//! shared outcome list is printed per run (`testkit::print_outcomes`)
//! for the soak's coverage summary — the generated corpus's version of
//! the checked-in corpus's "sometimes" test.

use hansei_runtime::testkit;

use std::path::PathBuf;

#[test]
fn test_generated_capture_matches_its_registry() {
    let Some(dir) = std::env::var_os("HANSEI_GENFIX_CAPTURE").map(PathBuf::from) else {
        eprintln!("HANSEI_GENFIX_CAPTURE is not set; nothing to check (soak.sh sets it)");
        return;
    };

    let (bundle, core) = testkit::cores::capture_now(&dir, "gen-soak");
    // The total audit runs (and panics) inside the pipeline.
    let r = testkit::run(&bundle, &core);
    let (list, census) = (&r.list, &r.census);

    testkit::print_outcomes(census);

    // A healthy capture walks cleanly — an error or a cap on a program
    // built to park quietly is a finding in itself — and matches its
    // registry both ways.
    let mut problems = r.healthy_problems();
    problems.extend(r.registry_problems());

    // Triage happens far from the failing host, so a failure carries
    // the whole population the diff judged, not just its verdicts.
    if !problems.is_empty() {
        let name = |id| r.ctx.view.ty(id).map_or("<unknown>", |ty| ty.name());
        for (i, t) in list.tasks.iter().enumerate() {
            let name = match &t.future {
                hansei_runtime::tokio::bundle::FutureInfo::Known(k) => k.name(r.ctx.view),
                other => &format!("{other:?}"),
            };
            println!("task {i}: `{name}` header at {:#x}", t.addr.0);
        }
        for h in &census.held {
            println!(
                "held: `{}` local `{}` slot {:#x} addr {:#x} via {:?} owner {} frame {}",
                name(h.future),
                h.local,
                h.slot,
                h.addr,
                h.via,
                h.owner,
                h.frame
            );
        }
        for s in &census.sets {
            println!(
                "set: `{}` local `{}` addr {:#x} children {} via {:?}",
                name(s.ty),
                s.local,
                s.addr,
                s.children.len(),
                s.via
            );
        }
        for s in &census.join_sets {
            println!(
                "join set: `{}` local `{}` addr {:#x} members {} via {:?}",
                name(s.ty),
                s.local,
                s.addr,
                s.children.len(),
                s.via
            );
        }
    }
    assert!(
        problems.is_empty(),
        "the generated capture in {} fails its oracle:\n{problems:#?}",
        dir.display()
    );
}

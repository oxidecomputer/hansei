// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The generated-fixture oracle: everything a healthy capture of a
//! genfix program must satisfy, over one snapshot pair.
//!
//! Opt-in, like the matrix: `HANSEI_GENFIX_PAIR=<prefix>` names a pair
//! as `<prefix>.bundle` / `<prefix>.snapshot` (the soak loop passes
//! what `capture-snapshots.sh` just wrote), and without it the test
//! skips with a message. The soak loop (`test-programs/genfix/soak.sh`)
//! runs this once per seed; a failure here after a clean recapture is
//! a failing seed, and its generated source becomes a quarantined
//! fixture.
//!
//! The oracle is the registry diff plus everything a *healthy* capture
//! is entitled to: the pipeline's total audit (inside
//! `testkit::census`), the healthy-only audit, no errors, no caps, and
//! a registry that parses and is non-empty. Every problem is collected
//! before failing, so a bad seed reports its whole story at once. The
//! shared outcome list (`testkit::outcomes`) is printed per run for
//! the soak's coverage summary — the generated corpus's version of the
//! checked-in corpus's "sometimes" test.

use hansei_bundle::Bundle;
use hansei_runtime::testkit;
use proc::snapshot::Snapshot;

#[test]
fn test_generated_pair_matches_its_registry() {
    let Ok(prefix) = std::env::var("HANSEI_GENFIX_PAIR") else {
        eprintln!("HANSEI_GENFIX_PAIR is not set; nothing to check (soak.sh sets it)");
        return;
    };

    let bundle = Bundle::load(format!("{prefix}.bundle").as_ref()).expect("the bundle loads");
    let snapshot =
        Snapshot::load(format!("{prefix}.snapshot").as_ref()).expect("the snapshot loads");
    let ctx = testkit::context(&bundle, &snapshot);
    let list = testkit::tasks(&ctx, &snapshot);
    // Runs the total audit subset; violations panic in there.
    let census = testkit::census(&ctx, &list);

    for (name, hit) in testkit::outcomes(&census) {
        println!("genfix outcome: {name} = {hit}");
    }

    let mut problems: Vec<String> = Vec::new();
    // A healthy capture walks cleanly: an error or a cap on a program
    // built to park quietly is a finding in itself.
    problems.extend(census.errors.iter().map(|e| format!("census error: {e:#}")));
    if census.capped.any() {
        problems.push(format!("the walk hit a hard limit: {:?}", census.capped));
    }
    problems.extend(
        census
            .audit(&list)
            .into_iter()
            .map(|v| format!("healthy-only audit: {v}")),
    );

    match testkit::expect::read_from(&snapshot) {
        None => problems.push("the capture carries no census registry symbol".into()),
        Some(Err(e)) => problems.push(format!("the registry does not parse: {e:#}")),
        Some(Ok(expected)) => {
            if expected.is_empty() {
                problems.push("the registry is empty; every genfix program registers".into());
            }
            problems.extend(testkit::expect::diff(&expected, &census, &list));
        }
    }

    // Triage happens far from the failing host, so a failure carries
    // the whole population the diff judged, not just its verdicts.
    if !problems.is_empty() {
        for (i, t) in list.tasks.iter().enumerate() {
            let name = match &t.future {
                hansei_runtime::tokio::bundle::FutureInfo::Known(k) => k.display_name.as_str(),
                other => &format!("{other:?}"),
            };
            println!("task {i}: `{name}` header at {:#x}", t.addr.0);
        }
        for h in &census.held {
            println!(
                "held: `{}` local `{}` slot {:#x} addr {:#x} via {:?} owner {} frame {}",
                h.future, h.local, h.slot, h.addr, h.via, h.owner, h.frame
            );
        }
        for s in &census.sets {
            println!(
                "set: `{}` local `{}` addr {:#x} children {} via {:?}",
                s.ty,
                s.local,
                s.addr,
                s.children.len(),
                s.via
            );
        }
        for s in &census.join_sets {
            println!(
                "join set: `{}` local `{}` addr {:#x} members {} via {:?}",
                s.ty,
                s.local,
                s.addr,
                s.children.len(),
                s.via
            );
        }
    }
    assert!(
        problems.is_empty(),
        "the generated pair at {prefix} fails its oracle:\n{problems:#?}"
    );
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The walk contract against real bundles: every fixture pair's bundle
//! must carry a clean recorded report, the spellings that bind on the
//! primary tokio/toolchain must stay the ones we think bind, and a
//! bundle missing a recorded binding must be loud, not a silent
//! structural decline.

use hansei_bundle::{Bundle, BundleView, WalkOutcome, WalkRole};
use hansei_runtime::tokio::contract::{Class, verify_walk_contract};

use std::path::{Path, PathBuf};

/// Every program `capture-snapshots.sh` captures a fixture pair for
/// (kept in sync with `two_binary.rs`, which checks the pairs against
/// the sources).
const PROGRAMS: &[&str] = &[
    "simple-await",
    "nested-await",
    "dyn-future",
    "futurelock",
    "sleep-join",
    "channels",
];

fn fixture_bundle(program: &str) -> Bundle {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{program}.bundle"));
    Bundle::load(&path).expect("fixture bundle loads; regenerate with capture-snapshots.sh")
}

/// Every fixture bundle records a clean walk contract: nothing broken,
/// and the required roles in particular all bound. The fixtures are the
/// primary cell, so a binder edit that no longer matches them fails
/// here first — the macOS-runnable half of "a new tokio produces a loud
/// diff" (the other half is the matrix suite, where binding runs
/// against every cell's DWARF).
#[test]
fn test_contract_is_clean_on_every_fixture() {
    for program in PROGRAMS {
        let bundle = fixture_bundle(program);
        let view = BundleView::new(&bundle);
        let report = verify_walk_contract(&view);
        assert!(report.is_clean(), "{program}:\n{report}");

        for entry in &report.entries {
            if entry.class == Class::Required {
                assert!(
                    matches!(entry.outcome, WalkOutcome::Bound { .. }),
                    "{program}: required path {} did not bind:\n{report}",
                    entry.name
                );
            }
        }
    }
}

/// Which spelling the binder recorded on the primary cell, pinned per
/// role. A regenerated fixture that silently flips one — the walk
/// starts taking a fallback route, or a versioned row selects a
/// different family — fails here as a reviewable diff rather than an
/// invisible behavior change.
#[test]
fn test_primary_cell_recorded_spellings() {
    for program in PROGRAMS {
        let bundle = fixture_bundle(program);
        let view = BundleView::new(&bundle);
        let report = verify_walk_contract(&view);

        // The pinned toolchain spells the field `filename: NonNull<str>`,
        // so the wrapper-explicit spelling binds; the bare-`filename` and
        // pre-rename `file` spellings stay declared as fallbacks.
        let entry = report.entry("Location.file").expect("in table");
        if let WalkOutcome::Bound {
            spelling,
            spellings,
            ..
        } = entry.outcome
        {
            assert_eq!(spelling, 0, "{program}: Location.file:\n{report}");
            assert_eq!(spellings, 3, "{program}: Location.file:\n{report}");
        }

        // The primary tokio (1.52.x) keeps the deadline behind the
        // 1.49 flavor enum: the versioned row must record the V1_49
        // family's spelling.
        let entry = report.entry("Sleep.deadline").expect("in table");
        if let WalkOutcome::Bound { note, .. } = &entry.outcome {
            let note = note.as_deref().unwrap_or("");
            assert!(
                note.contains("family v1_49"),
                "{program}: Sleep.deadline note {note:?}:\n{report}"
            );
        }

        // The driver-lock row collapsed to one explicit spelling when
        // the implicit-peel alternatives died with the old interpreter.
        let entry = report.entry("parker::Inner.driver_lock").expect("in table");
        if let WalkOutcome::Bound { spellings, .. } = entry.outcome {
            assert_eq!(spellings, 1, "{program}:\n{report}");
        }
    }
}

/// A primitive the target does not use is an expected absence — noted,
/// never breakage. `simple-await` uses no `FuturesUnordered`, and its
/// report stays clean.
#[test]
fn test_unused_leaf_is_absent_not_broken() {
    let bundle = fixture_bundle("simple-await");
    let view = BundleView::new(&bundle);
    let report = verify_walk_contract(&view);
    let entry = report.entry("FuturesUnordered.head_all").expect("in table");
    assert!(
        matches!(entry.outcome, WalkOutcome::Absent { .. }),
        "{:?}",
        entry.outcome
    );
    assert!(report.is_clean());
}

/// A bundle that records no binding for a role — one produced before
/// the role existed, or doctored — is loud and refuses a strict attach,
/// not a silent structural decline.
#[test]
fn test_a_missing_binding_is_loud() {
    let mut bundle = fixture_bundle("simple-await");
    bundle
        .walks
        .entries
        .remove(&WalkRole::HeaderState)
        .expect("the fixture records the role");

    let view = BundleView::new(&bundle);
    let report = verify_walk_contract(&view);
    let entry = report.entry("Header.state").expect("in table");
    assert!(
        matches!(entry.outcome, WalkOutcome::Broken { .. }),
        "{:?}",
        entry.outcome
    );
    assert!(!report.is_clean());
    let text = report.to_string();
    assert!(text.contains("BROKEN  Header.state"), "{text}");
    assert!(text.contains("no walk binding"), "{text}");
}

/// The fixtures are built `--cfg tokio_unstable`, so the
/// instrumentation member exists and its capability-conditional role
/// binds — extraction classified it, and the record says so.
#[test]
fn test_instrumentation_binds_on_the_unstable_fixture() {
    let bundle = fixture_bundle("simple-await");
    assert_eq!(bundle.meta.tokio_unstable, Some(true));
    let view = BundleView::new(&bundle);
    let report = verify_walk_contract(&view);
    let entry = report
        .entry("Vtable.spawn_location_offset")
        .expect("in table");
    assert!(
        matches!(entry.outcome, WalkOutcome::Bound { .. }),
        "{:?}",
        entry.outcome
    );
}

/// Every fixture records the statics the walk resolves through the
/// target's symtab; their absence would mean `--allow-missing-infra`
/// extraction, which no walkable bundle comes from.
#[test]
fn test_statics_are_recorded() {
    for program in PROGRAMS {
        let bundle = fixture_bundle(program);
        let view = BundleView::new(&bundle);
        let report = verify_walk_contract(&view);
        for name in ["statics.tls_context_key", "statics.task_waker_vtable"] {
            let entry = report.entry(name).expect(name);
            assert!(
                matches!(entry.outcome, WalkOutcome::Bound { .. }),
                "{program}: {name}: {:?}",
                entry.outcome
            );
        }
    }
}

/// The stage decode was bound over every task cell the bundle binds,
/// and the recorded note says how many that was — the count is what
/// makes "it verified" mean something.
#[test]
fn test_cell_rows_record_the_cell_count() {
    let bundle = fixture_bundle("simple-await");
    let view = BundleView::new(&bundle);
    let report = verify_walk_contract(&view);
    let entry = report.entry("Cell.stage").expect("in table");
    let WalkOutcome::Bound {
        note: Some(note), ..
    } = &entry.outcome
    else {
        panic!("{:?}", entry.outcome);
    };
    assert!(note.contains("cells"), "{note}");
}

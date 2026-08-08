// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The walk contract against real bundles: every fixture pair's bundle
//! must verify clean, the alternative spellings that bind on the
//! primary tokio/toolchain must stay the ones we think bind, and a
//! layout the table cannot navigate must be loud, not a silent
//! structural decline.

use exegesis::bundle::{Bundle, BundleView};
use hansei_types::tokio::contract::{
    self, Class, InfraRoot, Nav, Outcome, Root, Terminal, WalkPath, verify_walk_contract,
};

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

/// The whole table resolves against every fixture bundle: nothing is
/// broken, and the required paths in particular all bind. This is the
/// macOS-runnable half of "a new tokio produces a loud diff" — the
/// fixtures are the primary cell, so a table edit that no longer
/// matches them fails here first.
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
                    matches!(entry.outcome, Outcome::Resolved { .. }),
                    "{program}: required path {} did not resolve:\n{report}",
                    entry.name
                );
            }
        }
    }
}

/// Which alternative spelling binds on the primary cell, pinned per
/// path. A regenerated fixture that silently flips one — the walk
/// starts taking a fallback route — fails here as a reviewable diff
/// rather than an invisible behavior change.
#[test]
fn test_primary_cell_alternative_bindings() {
    // (path name, 0-based alternative expected wherever it resolves)
    let expected = [
        // std spells the field `filename` on the pinned toolchain.
        ("Location.file", 0),
        // The parkers' `Shared` holds only the driver lock, so the
        // member peels past it: the driver-less spelling binds.
        ("parker::Inner.driver_lock", 1),
        // This tokio's `entry` is already the `runtime::Timer` enum,
        // so the active-variant route binds, not the flat member.
        ("Sleep.deadline", 1),
    ];
    for program in PROGRAMS {
        let bundle = fixture_bundle(program);
        let view = BundleView::new(&bundle);
        let report = verify_walk_contract(&view);
        for (name, want) in expected {
            let entry = report.entry(name).expect(name);
            if let Outcome::Resolved { alternative, .. } = entry.outcome {
                assert_eq!(
                    alternative, want,
                    "{program}: {name} bound a different alternative:\n{report}"
                );
            }
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
        matches!(entry.outcome, Outcome::Absent { .. }),
        "{:?}",
        entry.outcome
    );
    assert!(report.is_clean());
}

/// A navigation the layout cannot satisfy is loud and self-describing:
/// the report names the missing member and what the type actually has,
/// the way `--explain-format` does for detectors.
#[test]
fn test_a_moved_layout_is_loud() {
    let bundle = fixture_bundle("simple-await");
    let view = BundleView::new(&bundle);

    let moved = WalkPath {
        name: "Header.gone",
        root: Root::Infra(InfraRoot::Header),
        alts: &[&[Nav::Member("owned_by_a_future_tokio")]],
        terminal: Terminal::Any,
        class: Class::Required,
    };
    let Outcome::Broken { errors } = moved.check(&view) else {
        panic!(
            "a missing member must be Broken, not {:?}",
            moved.check(&view)
        );
    };
    let text = errors.join("; ");
    assert!(text.contains("no member owned_by_a_future_tokio"), "{text}");
    assert!(text.contains("has: "), "{text}");

    // A wrong terminal shape is breakage too, not a bind: the path
    // navigates but does not land on what the walk would then read.
    let misshapen = WalkPath {
        name: "Header.state_as_pointer",
        root: Root::Infra(InfraRoot::Header),
        alts: &[&[Nav::Member("state")]],
        terminal: Terminal::Pointer,
        class: Class::Required,
    };
    assert!(
        matches!(misshapen.check(&view), Outcome::Broken { .. }),
        "{:?}",
        misshapen.check(&view)
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
                matches!(entry.outcome, Outcome::Resolved { .. }),
                "{program}: {name}: {:?}",
                entry.outcome
            );
        }
    }
}

/// The stage decode is checked over every task cell the bundle binds,
/// and the report says how many that was — the count is what makes "it
/// verified" mean something.
#[test]
fn test_cell_family_is_checked_per_cell() {
    let bundle = fixture_bundle("simple-await");
    let view = BundleView::new(&bundle);
    let report = verify_walk_contract(&view);
    let entry = report.entry(contract::CELL_STAGE.name).expect("in table");
    let Outcome::Resolved {
        note: Some(note), ..
    } = &entry.outcome
    else {
        panic!("{:?}", entry.outcome);
    };
    assert!(note.contains("cells"), "{note}");
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The fixtures `hansei`'s acceptance suite runs against: both
//! compilations of its programs, and a bundle extracted from each
//! program's build B.
//!
//! They are here rather than in the suite so the step that builds the
//! fixtures ahead of the suites (`examples/build_fixtures.rs`) can make
//! them too. Inside the suite, the first test to want them builds and
//! extracts all of them while every other test waits.

use super::{EXTRACTIONS, parallel_at};

use testrun::fixture::{Matrix, Recipe, build_a, build_b, test_programs_dir};

use std::fs;
use std::path::PathBuf;

/// The programs the acceptance suite runs: the testkit's
/// ([`super::PROGRAMS`]) and five that only it reads.
pub const PROGRAMS: &[&str] = &[
    "simple-await",
    "nested-await",
    "dyn-future",
    "futurelock",
    "many-tasks",
    "sleep-join",
    "unordered",
    "joinset",
    "ct-runtime",
    "local-set",
    "local-set-timer",
    "local-set-io",
    "foreign-runtime",
    "blocking-pool",
    "delegation-cases",
    "spin-poll",
    "ct-spin",
    "stale-local",
    "enum-reprs",
    "armed-select",
    "watch-stream",
    "http-conns",
    "two-releases",
    "tls-conns",
];

pub struct Fixtures {
    /// Build A: the binaries that run (and are cored).
    pub bin_a: PathBuf,
    /// Build B: the same programs carrying DWARF, which the bundles
    /// below were extracted from and which `--debug-info` takes.
    pub bin_b: PathBuf,
    /// Bundles extracted from build B, one per program.
    pub bundles: PathBuf,
}

impl Fixtures {
    pub fn program(&self, program: &str) -> PathBuf {
        self.bin_a.join(program)
    }

    pub fn debug_binary(&self, program: &str) -> PathBuf {
        self.bin_b.join(program)
    }

    pub fn bundle(&self, program: &str) -> PathBuf {
        self.bundles.join(format!("{program}.tinfo"))
    }
}

/// Build both compilations of every program under `recipe`, the
/// suite's matrix cell, and extract every program's bundle, once per
/// test-suite run.
pub fn fixtures(recipe: &Recipe) -> Fixtures {
    // Both compilations, once per run and each held to its recipe:
    // build B is the standard fixture build the extraction goldens
    // share, build A one of its own without debug info.
    let bin_a = build_a(recipe, PROGRAMS);
    let bin_b = build_b(recipe, PROGRAMS);
    let bundles = test_programs_dir()
        .join("fixtures/accept")
        .join(recipe.cell());
    fs::create_dir_all(&bundles).expect("failed to create the bundle dir");

    // Once per run rather than once per process. Under nextest every
    // test is its own process, so without this each of them would
    // re-extract every bundle while the others read the bundles being
    // written.
    //
    // The bundles stamp apart from the builds because they are made
    // from different things, which only matters to a run reusing what
    // an earlier one left behind (`testrun::REUSE`): a change to the
    // extraction side must re-extract without recompiling the
    // fixtures, and — the case that makes it necessary rather than
    // tidy — a `cargo mutants` sweep of hansei-bundle mutates what the
    // bundles are written by, so those must be rebuilt per mutant while
    // the compilations need not be.
    testrun::once_per_run(
        &bundles.join(".bundles"),
        || extracted_from(recipe),
        || {
            parallel_at(EXTRACTIONS, PROGRAMS, |program| {
                let opts = exegesis::extract::ExtractOptions {
                    extract_args: format!("acceptance-suite extraction of {program}"),
                    ..Default::default()
                };
                let (bundle, _stats) = exegesis::extract::extract_file(&bin_b.join(program), &opts)
                    .unwrap_or_else(|e| panic!("extraction of {program} failed: {e}"));
                bundle
                    .save(&bundles.join(format!("{program}.tinfo")))
                    .expect("failed to write the bundle");
            });
        },
    );

    Fixtures {
        bin_a,
        bin_b,
        bundles,
    }
}

/// What a cell's bundles are extracted from, for a run reusing what an
/// earlier one left behind (`testrun::REUSE`): build B of every
/// program, and the code that reads and writes the bundles.
fn extracted_from(recipe: &Recipe) -> String {
    let dir = test_programs_dir();
    let root = dir.join("..");
    let matrix = Matrix::read(&dir);
    let mut inputs = testrun::Inputs::new();
    for program in PROGRAMS {
        inputs.text(&recipe.inputs(&dir, &matrix, program));
    }
    inputs
        .tree(&root.join("exegesis/src"), ".rs")
        .tree(&root.join("hansei-bundle/src"), ".rs")
        .file(&root.join("Cargo.lock"));
    inputs.finish()
}

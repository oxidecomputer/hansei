// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Build the fixture programs the suites build, ahead of them.
//!
//! The suites build the fixture programs themselves, once per run,
//! inside whichever test first needs them, while every other test
//! needing them waits on the build's lock. On a cold machine that wait
//! can outlast a per-test timeout meant to catch a hang, so CI runs
//! this first: the suite then starts with every fixture target dir
//! warm, and its own builds find nothing left to compile.
//!
//! It builds through the same calls the suites make, so it builds what
//! they build: the primary cell's build B, which the extraction goldens
//! and the bundle-only tests read everywhere; both compilations of
//! every program in each set this system cores; and on Linux the packed
//! split-debuginfo build the extraction goldens compare against.
//!
//! Usage: `cargo run -p hansei-runtime --example build_fixtures`

use hansei_runtime::testkit::PROGRAMS;
use hansei_runtime::testkit::cores::{CAPTURED, recipe};
use testrun::fixture::{Matrix, build_a, build_b};

/// The program the extraction goldens compare a packed split build of
/// against its unsplit build (`exegesis/tests/golden.rs`).
#[cfg(target_os = "linux")]
const DWP_PROGRAM: &str = "select-combinator";

fn main() {
    build_b(&Matrix::load().primary_recipe(), PROGRAMS);
    for set in CAPTURED {
        let recipe = recipe(set);
        build_a(&recipe, PROGRAMS);
        build_b(&recipe, PROGRAMS);
    }
    #[cfg(target_os = "linux")]
    testrun::fixture::build_dwp(DWP_PROGRAM);
}

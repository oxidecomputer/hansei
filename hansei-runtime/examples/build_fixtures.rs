// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Build the fixture programs the suites build, and make what the
//! suites make from them, ahead of the suites.
//!
//! The suites do this work themselves, once per run, inside whichever
//! test first needs each piece, while every other test needing it
//! waits on its lock — holding a test slot that nothing else can use
//! meanwhile. On a cold machine that wait can outlast a per-test
//! timeout meant to catch a hang, and on a machine with few CPUs it is
//! much of the suite's time. So CI runs this first, under the run name
//! the suite then runs under (`testrun::RUN`), and the suite finds
//! every piece already done.
//!
//! It does the work through the same calls the suites make, so it does
//! what they do:
//!
//! - build B of every fixture program in the primary cell, which the
//!   extraction goldens and the bundle-only tests read everywhere, and
//!   which `proc`'s and `unwind`'s suites run;
//! - both compilations of every program in each set this system cores,
//!   and each set's cores;
//! - the acceptance suite's two compilations and its bundles, on a
//!   system it runs on;
//! - on Linux, the packed split-debuginfo build the extraction goldens
//!   compare against;
//! - the bundle of every program's own build B, and of every program in
//!   every set whose cores are there to read.
//!
//! A set this system does not core is read from cores another system
//! took, which may arrive after the build: run this again once they
//! have, and it extracts their bundles, the rest being done.
//!
//! Usage: `cargo run -p hansei-runtime --example build_fixtures`

use hansei_runtime::testkit::cores::{self, CAPTURED, recipe};
use hansei_runtime::testkit::{self, PROGRAMS, accept, parallel};
use testrun::fixture::{Matrix, all_programs, build_a, build_b};

/// The program the extraction goldens compare a packed split build of
/// against its unsplit build (`exegesis/tests/golden.rs`).
#[cfg(target_os = "linux")]
const DWP_PROGRAM: &str = "select-combinator";

/// Whether the acceptance suite runs here: it reads ELF cores it takes
/// itself, so it compiles on no other system.
const ACCEPTANCE: bool = cfg!(any(target_os = "linux", target_os = "illumos"));

fn main() {
    let primary = Matrix::load().primary_recipe();
    let all = all_programs();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    build_b(&primary, &all);
    for set in CAPTURED {
        let recipe = recipe(set);
        build_a(&recipe, PROGRAMS);
        build_b(&recipe, PROGRAMS);
    }
    if ACCEPTANCE {
        build_a(&primary, accept::PROGRAMS);
    }
    #[cfg(target_os = "linux")]
    testrun::fixture::build_dwp(DWP_PROGRAM);

    // Coring a program is mostly waiting, on its marker and on gcore,
    // and extraction mostly computing, so the two go side by side.
    let dir = cores::dir();
    std::thread::scope(|scope| {
        scope.spawn(|| parallel(CAPTURED, |set| cores::take(&dir, set)));
        if ACCEPTANCE {
            accept::fixtures(&primary);
        }
        parallel(PROGRAMS, |program| {
            testkit::bundle_path(program);
        });
    });

    let pairs: Vec<(&str, &str)> = cores::sets(&dir)
        .into_iter()
        .filter(|set| dir.join(set).is_dir())
        .flat_map(|set| PROGRAMS.iter().map(move |&program| (set, program)))
        .collect();
    parallel(&pairs, |&(set, program)| {
        cores::bundle_path(set, program, &cores::capture(&dir, set, program));
    });
}

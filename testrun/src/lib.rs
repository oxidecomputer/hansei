// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Doing a fixture build once per *test-suite run*, when the run is
//! more than one process.
//!
//! Test scaffolding only: nothing depends on this crate outside a
//! `[dev-dependencies]`, so it is compiled for test binaries and never
//! linked into anything hansei ships. It is a crate of its own because
//! the suites that need it — `exegesis`'s extraction goldens and
//! `hansei`'s acceptance suite — are in different crates, and
//! `#[cfg(test)]` would not reach either: that cfg is set only while a
//! crate compiles its own unit tests, and an integration test links the
//! library built without it.
//!
//! `cargo test` runs a suite in a single process, so a `OnceLock` was
//! all it took to build a fixture once however many tests read it.
//! `cargo nextest run` gives every test its own process, and there that
//! same code builds once per *test*: the acceptance suite's two
//! compilations and a bundle per program, thirty-two times over, each
//! run writing over a fixture the others are reading.
//!
//! nextest names the run it is executing in `NEXTEST_RUN_ID`, which is
//! the missing piece. The first process to take the lock does the work
//! and stamps it with the run's name; the rest block, wake to find
//! their own run's stamp, and skip. A run still rebuilds everything it
//! reads — the anti-staleness the fixture suites depend on, since a
//! stale binary reads as line-number drift and has been blessed into a
//! golden as if it were the truth — because the next run is named
//! differently.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// Run `work` once per test-suite run, guarded by `stamp` and a lock
/// file beside it.
///
/// Under `cargo test` there is no run to name, so `work` runs the way it
/// always has: once per process, which there is once per run.
///
/// A panic in `work` releases the lock without stamping, so the next
/// process runs it again and fails the same way — better than reporting
/// a fixture that was never built.
pub fn once_per_run(stamp: &Path, work: impl FnOnce()) {
    let Ok(run) = std::env::var("NEXTEST_RUN_ID") else {
        work();
        return;
    };
    let dir = stamp.parent().expect("the stamp path names a directory");
    fs::create_dir_all(dir).expect("failed to create the fixture stamp directory");

    let lock = PathBuf::from(format!("{}.lock", stamp.display()));
    let lock = File::create(&lock).expect("failed to open the fixture lock");
    lock.lock().expect("failed to take the fixture lock");

    if fs::read_to_string(stamp).is_ok_and(|stamped| stamped == run) {
        return;
    }
    work();
    fs::write(stamp, &run).expect("failed to write the fixture stamp");
}

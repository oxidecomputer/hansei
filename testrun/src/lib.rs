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
//!
//! # Reusing fixtures across runs
//!
//! Rebuilding every run is a blunt spelling of rebuilding when the
//! inputs moved, and one caller cannot afford it: a `cargo mutants`
//! sweep is one nextest run per mutant, and it reuses a single scratch
//! copy of the tree per parallel job — so the fixtures are still there
//! from the last mutant, and only the run's name says otherwise.
//!
//! So a caller also passes a digest of what its fixtures are built
//! *from*, and setting [`REUSE`] stamps with that instead of the run
//! id. Fixture sources the sweep never touches then digest the same
//! from one mutant to the next and the work is skipped, while an edit
//! to any input reads as a different stamp and rebuilds — the same
//! anti-staleness, keyed on the thing it was always a proxy for.
//! Nothing sets it by default: a human's run rebuilds, as before.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// Set this to stamp fixture work with the digest of its inputs rather
/// than with the run it was built in, reusing what an earlier run left
/// behind. See the module docs; sweeps set it, people do not.
pub const REUSE: &str = "HANSEI_REUSE_FIXTURES";

/// Run `work` once per test-suite run, guarded by `stamp` and a lock
/// file beside it.
///
/// `inputs` is the digest of everything the work is built from, used in
/// place of the run when [`REUSE`] is set — see the module docs. It is
/// a closure because computing it reads files, which is wasted on the
/// runs that stamp with the run id.
///
/// Under `cargo test` there is no run to name, so `work` runs the way it
/// always has: once per process, which there is once per run.
///
/// A panic in `work` releases the lock without stamping, so the next
/// process runs it again and fails the same way — better than reporting
/// a fixture that was never built.
pub fn once_per_run(stamp: &Path, inputs: impl FnOnce() -> String, work: impl FnOnce()) {
    let reuse = std::env::var_os(REUSE).is_some();
    let value = stamp_value(std::env::var("NEXTEST_RUN_ID").ok(), reuse, inputs);
    once_stamped(stamp, value, work);
}

/// [`once_per_run`], once the run has decided what to call itself:
/// `None` is nothing to compare against, so the work simply runs.
fn once_stamped(stamp: &Path, value: Option<String>, work: impl FnOnce()) {
    let Some(value) = value else {
        work();
        return;
    };
    let dir = stamp.parent().expect("the stamp path names a directory");
    fs::create_dir_all(dir).expect("failed to create the fixture stamp directory");

    let lock = PathBuf::from(format!("{}.lock", stamp.display()));
    let lock = File::create(&lock).expect("failed to open the fixture lock");
    lock.lock().expect("failed to take the fixture lock");

    if fs::read_to_string(stamp).is_ok_and(|stamped| stamped == value) {
        return;
    }
    work();
    fs::write(stamp, &value).expect("failed to write the fixture stamp");
}

/// What this run stamps its fixture work with, or `None` when there is
/// nothing to compare against and the work simply runs.
///
/// Reuse wins over the run id where both are available: a sweep asking
/// for it has said that its runs are the same run for this purpose.
fn stamp_value(
    run: Option<String>,
    reuse: bool,
    inputs: impl FnOnce() -> String,
) -> Option<String> {
    match (reuse, run) {
        (true, _) => Some(inputs()),
        (false, run) => run,
    }
}

/// The digest of what a fixture build depends on: files by content,
/// plus whatever else the caller knows about the build that is not in
/// a file — the cell's flags, which of two compilations this is.
///
/// Every input is fed in with its own length, so no two different
/// input lists can hash the same by running together.
#[derive(Default)]
pub struct Inputs(blake3::Hasher);

impl Inputs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Some text the caller knows: a flag, a version, a name.
    pub fn text(&mut self, text: &str) -> &mut Self {
        self.0.update(&(text.len() as u64).to_le_bytes());
        self.0.update(text.as_bytes());
        self
    }

    /// One file, by content. A file that is not there is an input too —
    /// it hashes as its absence, so creating it later reads as a
    /// change.
    pub fn file(&mut self, path: &Path) -> &mut Self {
        match fs::read(path) {
            Ok(bytes) => {
                self.0.update(&(bytes.len() as u64).to_le_bytes());
                self.0.update(&bytes);
            }
            Err(_) => {
                self.0.update(&u64::MAX.to_le_bytes());
            }
        }
        self
    }

    /// Every file under `dir` whose name ends in `ext`, recursively, in
    /// a fixed order — so the digest is the tree's content and not the
    /// order the filesystem happened to list it in. The names are fed
    /// in as well: a renamed file is a changed input.
    pub fn tree(&mut self, dir: &Path, ext: &str) -> &mut Self {
        let mut found = Vec::new();
        collect(dir, ext, &mut found);
        found.sort();
        for path in found {
            self.text(&path.to_string_lossy());
            self.file(&path);
        }
        self
    }

    /// The digest so far, as the hex a stamp file holds.
    pub fn finish(&self) -> String {
        self.0.finalize().to_hex().to_string()
    }
}

/// Every `ext` file at or under `dir`. A directory that cannot be read
/// contributes nothing, which the caller's other inputs will usually
/// notice; this is a digest, not a build system.
fn collect(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, ext, out);
        } else if path.to_string_lossy().ends_with(ext) {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which name the work is stamped with, in each of the four states
    /// the two knobs make. The digest is only computed where it is
    /// used, so the closure here panics everywhere else.
    #[test]
    fn test_reuse_stamps_with_the_inputs_and_nothing_else_does() {
        let run = || Some("run-42".to_string());
        let digest = || "digest".to_string();
        let never = || panic!("the inputs were digested without reuse asked for");

        // A sweep's runs are all one run for this purpose, whether or
        // not the runner named them.
        assert_eq!(stamp_value(run(), true, digest), Some("digest".into()));
        assert_eq!(stamp_value(None, true, digest), Some("digest".into()));

        // Without it, the run is the stamp, and a run with no name is
        // one process doing the work itself.
        assert_eq!(stamp_value(run(), false, never), Some("run-42".into()));
        assert_eq!(stamp_value(None, false, never), None);
    }

    /// A digest is of the inputs, so anything that moves moves it —
    /// including a rename, which leaves every byte where it was.
    #[test]
    fn test_a_digest_follows_its_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("bin")).unwrap();
        fs::write(src.join("lib.rs"), "fn main() {}").unwrap();
        fs::write(src.join("bin/one.rs"), "// one").unwrap();

        let of = |ext: &str, flag: &str| {
            let mut inputs = Inputs::new();
            inputs.text(flag).tree(&src, ext);
            inputs.finish()
        };
        let base = of(".rs", "--stable");

        // The same inputs, twice: a stamp that moved on its own would
        // rebuild every time and reuse nothing.
        assert_eq!(base, of(".rs", "--stable"));

        // What the caller knows, and what is in the tree.
        assert_ne!(base, of(".rs", "--unstable"));
        fs::write(src.join("bin/one.rs"), "// two").unwrap();
        let edited = of(".rs", "--stable");
        assert_ne!(base, edited);

        // A rename, with every byte where it was.
        fs::rename(src.join("bin/one.rs"), src.join("bin/two.rs")).unwrap();
        assert_ne!(edited, of(".rs", "--stable"));

        // And a file the filter does not name is not an input.
        fs::write(src.join("bin/notes.txt"), "ignored").unwrap();
        assert_eq!(of(".rs", "--stable"), of(".rs", "--stable"));
    }

    /// A file that is not there yet is an input: the fixture sources
    /// grow a program, or a lockfile is written, and the stamp moves.
    #[test]
    fn test_a_missing_file_is_an_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.lock");
        let of = || {
            let mut inputs = Inputs::new();
            inputs.file(&path);
            inputs.finish()
        };
        let absent = of();
        fs::write(&path, "").unwrap();
        assert_ne!(absent, of(), "an empty file read as no file at all");
    }

    /// The work runs once for a stamp and is skipped after, a different
    /// stamp runs it again, and an unstamped call always runs — the
    /// whole point, with the run id and the digest both spelled as
    /// stamps by now.
    #[test]
    fn test_work_runs_once_per_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let stamp = dir.path().join("sub").join(".fixtures");
        let runs = std::cell::Cell::new(0);
        let once = |value: Option<&str>| {
            once_stamped(&stamp, value.map(str::to_string), || {
                runs.set(runs.get() + 1)
            });
        };
        once(Some("a"));
        once(Some("a"));
        once(Some("b"));
        once(Some("b"));
        assert_eq!(runs.get(), 2, "a stamp already on disk did the work again");
        once(None);
        once(None);
        assert_eq!(
            runs.get(),
            4,
            "an unstamped run skipped work nobody claimed"
        );
    }

    /// Work that panicked left no stamp, so the next process does it
    /// again and fails the same way — rather than reporting a fixture
    /// that was never built.
    #[test]
    fn test_failed_work_is_not_stamped() {
        let dir = tempfile::tempdir().unwrap();
        let stamp = dir.path().join(".fixtures");
        let value = Some("a".to_string());
        let panicked = std::panic::catch_unwind(|| {
            once_stamped(&stamp, value.clone(), || panic!("the build failed"));
        });
        assert!(panicked.is_err());
        assert!(!stamp.exists(), "a failed build stamped itself as done");

        let mut runs = 0;
        once_stamped(&stamp, value, || runs += 1);
        assert_eq!(runs, 1);
    }
}

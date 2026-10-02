// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Fresh cores of the fixture programs, read in place of the checked-in
//! snapshots when [`CORES`] names a directory to keep them in.
//!
//! A system that can core a process takes its own sets there, once per
//! run: both compilations of every program built
//! ([`testrun::fixture::build_a`], [`build_b`]), build A driven to its
//! readiness marker ([`Parked`]), `gcore`d, and the core kept beside
//! copies of the two builds and — for a Linux core, which carries no
//! library text — the libraries it maps, at their recorded paths under
//! the set's `sysroot/`. What a set's directory holds is everything
//! reading it needs, so a system that cannot core (macOS) reads a set
//! copied from the host that took it, and extracts the bundle from the
//! copied build B with its own exegesis.
//!
//! ```text
//! $HANSEI_CORES/<set>/<program>/core        the core of build A
//! $HANSEI_CORES/<set>/<program>/<program>   build A, the binary that ran
//! $HANSEI_CORES/<set>/<program>/debug/<program>  build B
//! $HANSEI_CORES/<set>/<program>/capture     what both were built from
//! $HANSEI_CORES/<set>/sysroot/…             a Linux set's libraries
//! ```
//!
//! Dot-named entries (`.stamps`, `.bundles`) are this host's own
//! bookkeeping and never need copying.
//!
//! [`build_b`]: testrun::fixture::build_b

use super::{FIXTURE_SETS, PROGRAMS};

use hansei_bundle::Bundle;
use proc::{CoreFiles, Proc, Target};
use testrun::fixture::{Matrix, Recipe, test_programs_dir};

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;

/// Name a directory here and every fixture-reading test reads fresh
/// cores from it instead of the checked-in snapshots, capturing the
/// sets this system takes into it first.
pub const CORES: &str = "HANSEI_CORES";

/// The directory [`CORES`] names, when this run reads cores.
pub fn dir() -> Option<PathBuf> {
    std::env::var_os(CORES)
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
}

/// The sets this system captures: its own, and on Linux the floor
/// tokio's set beside it. None anywhere else, macOS included.
pub const CAPTURED: &[&str] = if cfg!(target_os = "linux") {
    &["linux", "linux-floor"]
} else if cfg!(target_os = "illumos") {
    &["illumos"]
} else {
    &[]
};

/// The sets a run reads cores of: on a system that captures, its own
/// and any other already in [`dir`]; elsewhere every set, each of which
/// must be there.
pub fn sets(dir: &Path) -> Vec<&'static str> {
    FIXTURE_SETS
        .iter()
        .copied()
        .filter(|set| CAPTURED.is_empty() || CAPTURED.contains(set) || dir.join(set).is_dir())
        .collect()
}

/// The recipe a set's programs are built with: the primary cell, or the
/// floor tokio's for the floor set.
pub fn recipe(set: &str) -> Recipe {
    Matrix::load().capture_recipe(set)
}

/// One program's capture, as a reader finds it.
pub struct Capture {
    /// The core of build A.
    pub core: PathBuf,
    /// Build A, the binary that ran: what a Linux core is opened with.
    pub binary: PathBuf,
    /// Build B, which the bundle is extracted from.
    pub debug: PathBuf,
    /// Where a Linux core's libraries are, at their recorded paths.
    pub sysroot: Option<PathBuf>,
}

impl Capture {
    /// Open the core through the production reader, its executable and
    /// libraries read from the copies beside it.
    pub fn open(&self) -> Proc {
        let files = CoreFiles {
            binary: Some(&self.binary),
            sysroot: self.sysroot.as_deref(),
        };
        Proc::open_core_with(&self.core, files)
            .unwrap_or_else(|e| panic!("failed to open {}: {e}", self.core.display()))
    }
}

/// `program`'s capture in `set`, taken first if this system captures
/// the set and this run has not yet. Panics, with the one message
/// saying how to get them, when the cores are not there to read.
pub fn capture(dir: &Path, set: &str, program: &str) -> Capture {
    assert!(
        PROGRAMS.contains(&program),
        "{program} is not a fixture program"
    );
    if CAPTURED.contains(&set) {
        take(dir, set);
    }
    locate(dir, set, program)
}

/// The record a capture keeps of what its builds were built from, which
/// a reader holds the tree it runs in to.
fn record(set: &str, program: &str) -> String {
    let dir = test_programs_dir();
    let matrix = Matrix::read(&dir);
    matrix
        .capture_recipe(set)
        .capture_record(&dir, &matrix, set, program)
}

fn locate(dir: &Path, set: &str, program: &str) -> Capture {
    let at = dir.join(set).join(program);
    let capture = Capture {
        core: at.join("core"),
        binary: at.join(program),
        debug: at.join("debug").join(program),
        sysroot: set
            .starts_with("linux")
            .then(|| dir.join(set).join("sysroot")),
    };
    let complete = [&capture.core, &capture.binary, &capture.debug]
        .iter()
        .all(|path| path.is_file());
    if !complete {
        missing(dir, set, program);
    }
    let recorded = fs::read_to_string(at.join("capture")).unwrap_or_default();
    assert!(
        recorded == record(set, program),
        "{CORES}={}: the {set} capture of {program} was built from other \
         fixture sources than this tree's; take it again from this tree",
        dir.display()
    );
    capture
}

/// The one failure every test reading a missing core reports, so that
/// any other failure among them stands out.
fn missing(dir: &Path, set: &str, program: &str) -> ! {
    panic!(
        "{CORES}={} holds no {set} capture of {program}: a system that \
         cannot core reads the cores a capturing host took, so copy that \
         host's {CORES} directory here (check-all.sh's local leg does)",
        dir.display()
    )
}

/// Capture every program of `set` this run has not, once per run.
fn take(dir: &Path, set: &str) {
    let recipe = recipe(set);
    let stamps = dir.join(".stamps").join(set);
    testrun::once_per_run_each(
        &stamps,
        PROGRAMS,
        |program| record(set, program),
        |stale| {
            let bin_a = testrun::fixture::build_a(&recipe, PROGRAMS);
            let bin_b = testrun::fixture::build_b(&recipe, PROGRAMS);
            for &program in stale {
                take_one(dir, set, program, &bin_a, &bin_b);
            }
        },
    );
}

/// Core one program and lay the capture out beside it. Everything is
/// assembled in a scratch dir and renamed into place whole, so a reader
/// finds the previous capture or this one and never half of each.
fn take_one(dir: &Path, set: &str, program: &str, bin_a: &Path, bin_b: &Path) {
    let set_dir = dir.join(set);
    fs::create_dir_all(&set_dir).expect("failed to create the set's core dir");
    let scratch = tempfile::tempdir_in(&set_dir).expect("failed to create a scratch dir");
    let at = scratch.path();

    let parked = Parked::spawn(&bin_a.join(program), program);
    let core = gcore(parked.pid(), at);
    drop(parked);
    fs::rename(&core, at.join("core")).expect("failed to name the core");

    fs::create_dir_all(at.join("debug")).expect("failed to create the debug dir");
    place(&bin_a.join(program), &at.join(program));
    place(&bin_b.join(program), &at.join("debug").join(program));
    fs::write(at.join("capture"), record(set, program)).expect("failed to write the record");

    if set.starts_with("linux") {
        let proc = Proc::open_core_with(
            &at.join("core"),
            CoreFiles {
                binary: Some(&at.join(program)),
                sysroot: None,
            },
        )
        .expect("failed to open the fresh core");
        sysroot(&proc, &set_dir.join("sysroot"));
    }

    let dest = set_dir.join(program);
    let old = set_dir.join(format!(".old-{program}"));
    let _ = fs::remove_dir_all(&old);
    if dest.exists() {
        fs::rename(&dest, &old).expect("failed to move the previous capture aside");
    }
    fs::rename(at, &dest).expect("failed to move the capture into place");
    let _ = fs::remove_dir_all(&old);
}

/// Copy every library `proc` maps into `sysroot` at its recorded path,
/// replacing by rename so a reader of an earlier copy keeps its file.
/// The executable is left out: it is read from the copy of build A.
fn sysroot(proc: &Proc, sysroot: &Path) {
    let exec = proc.exec_name().expect("the core names its executable");
    let mappings = proc.mappings().expect("the core lists its mappings");
    let mut files: Vec<&str> = mappings
        .iter()
        .filter_map(|m| m.path.as_deref())
        .filter(|path| Path::new(path) != exec && Path::new(path).is_file())
        .collect();
    files.sort_unstable();
    files.dedup();
    for file in files {
        let to = sysroot.join(file.trim_start_matches('/'));
        fs::create_dir_all(to.parent().unwrap()).expect("failed to create a sysroot dir");
        let tmp = to.with_extension(format!("tmp{}", std::process::id()));
        fs::copy(file, &tmp).unwrap_or_else(|e| panic!("failed to copy {file}: {e}"));
        fs::rename(&tmp, &to).expect("failed to install a sysroot library");
    }
}

/// Put a copy of `from` at `to`: a hard link where the two share a
/// filesystem, which costs nothing and keeps the bytes the core was
/// taken from even when `regen.sh` later installs a new build by
/// rename; a copy where they do not.
fn place(from: &Path, to: &Path) {
    if fs::hard_link(from, to).is_err() {
        fs::copy(from, to).unwrap_or_else(|e| panic!("failed to copy {}: {e}", from.display()));
    }
}

/// The bundle extracted from `capture`'s build B by the exegesis under
/// test, once per run, and written to a file under `dir` whose path is
/// returned.
pub fn bundle_path(dir: &Path, set: &str, program: &str, capture: &Capture) -> PathBuf {
    let bundles = dir.join(".bundles").join(set);
    let path = bundles.join(format!("{program}.tinfo"));
    testrun::once_per_run_each(
        &dir.join(".stamps").join(format!("bundles-{set}")),
        &[program],
        |_| {
            let root = test_programs_dir().join("..");
            let mut inputs = testrun::Inputs::new();
            inputs
                .file(&capture.debug)
                .tree(&root.join("exegesis/src"), ".rs")
                .tree(&root.join("hansei-bundle/src"), ".rs")
                .file(&root.join("Cargo.lock"));
            inputs.finish()
        },
        |_| {
            let opts = exegesis::extract::ExtractOptions {
                extract_args: format!("testkit extraction of {set}/{program}"),
                ..Default::default()
            };
            let (bundle, _stats) = exegesis::extract::extract_file(&capture.debug, &opts)
                .unwrap_or_else(|e| panic!("extraction of {set}/{program} failed: {e}"));
            fs::create_dir_all(&bundles).expect("failed to create the bundle dir");
            let tmp = path.with_extension(format!("tmp{}", std::process::id()));
            bundle.save(&tmp).expect("failed to write the bundle");
            fs::rename(&tmp, &path).expect("failed to install the bundle");
        },
    );
    path
}

/// Load `program`'s bundle and open its core, from `set` in `dir`.
pub fn load(dir: &Path, set: &str, program: &str) -> (Bundle, Proc) {
    let capture = capture(dir, set, program);
    let bundle = Bundle::load(&bundle_path(dir, set, program, &capture))
        .unwrap_or_else(|e| panic!("the {set}/{program} bundle loads: {e}"));
    (bundle, capture.open())
}

/// The stdout line a fixture prints once the state under inspection is
/// stable.
pub fn marker(program: &str) -> &'static str {
    match program {
        // Deadlocked for good once the background task drops the lock
        // (RFD 609: the handoff goes to the never-again-polled future1).
        "futurelock" => "background task: done (dropping lock)",
        _ => "READY",
    }
}

/// A fixture program from build A, running at its parked steady state.
pub struct Parked {
    child: Child,
}

impl Parked {
    /// Launch `binary`, the build of `program`, and block on its stdout
    /// until the readiness marker: from that line on, the state under
    /// inspection is stable. There are no timing sleeps anywhere.
    pub fn spawn(binary: &Path, program: &str) -> Self {
        let marker = marker(program);
        let mut child = Command::new(binary)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to launch {}: {e}", binary.display()));
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next() {
                Some(Ok(line)) if line == marker => break,
                Some(Ok(_)) => continue,
                Some(Err(e)) => panic!("failed to read {program} stdout: {e}"),
                None => panic!("{program} exited before reaching its steady state"),
            }
        }
        // Keep draining stdout so the child can never block on a full
        // pipe.
        thread::spawn(move || lines.for_each(drop));
        Self { child }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Parked {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Take a core of the parked process into `dir`, returning its path.
pub fn gcore(pid: u32, dir: &Path) -> PathBuf {
    let prefix = dir.join("core");
    let out = Command::new("gcore")
        .arg("-o")
        .arg(&prefix)
        .arg(pid.to_string())
        .output()
        .expect("failed to run gcore");
    assert!(
        out.status.success(),
        "gcore of {pid} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let core = dir.join(format!("core.{pid}"));
    assert!(core.exists(), "gcore left no {}", core.display());
    core
}

/// The `--binary` flags an attach to `core` needs, if any.
///
/// A Linux core carries no symbol table, so hansei requires the
/// executable to be named; an illumos core carries its own and warns if
/// one is passed. A core taken here is of a program still sitting where
/// it ran, so the path the core recorded is the right answer — which is
/// the whole reason the flag can be filled in rather than threaded
/// through every caller.
pub fn binary_args(core: &Path) -> Vec<PathBuf> {
    let proc = Proc::open_core(core).expect("failed to open the core");
    match proc.needs_binary() {
        false => Vec::new(),
        true => vec![proc.exec_name().expect("the core names no executable")],
    }
}

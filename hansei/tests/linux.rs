//! The end-to-end suite on Linux: bundle, core, and the three commands
//! that read one through the other.
//!
//! This is the whole pipeline in one place — extraction from DWARF,
//! `AT_PHDR` and the load bias, the ELF thread-local that finds the
//! runtime, the task walk, and reify's rendering of a frame's locals —
//! run against a core the kernel's own loader laid out. The illumos
//! suite (`tests/illumos.rs`) does the same against a live process
//! there; between them the two platforms' targets are held to the same
//! output.
//!
//! The target is `test-programs`' `core-tokio`, which parks two tasks at
//! known await points, prints `READY`, and aborts. gdb runs it and takes
//! the core with `gcore`; see `proc/tests/linux.rs` for why the core
//! comes from gdb and not from `core_pattern`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The fixture, and what it parks. Keep in step with
/// `test-programs/src/bin/core-tokio.rs`.
const PROGRAM: &str = "core-tokio";
const PARKED_TASK: &str = "core_tokio::parked_task::{async_fn_env#0}";
const RECEIVING_TASK: &str = "core_tokio::receiving_task::{async_fn_env#0}";
/// `MARKER` in the fixture, as hansei prints it: decimal, not hex.
const MARKER: u64 = 0x0123_4567_89ab_cdef;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

/// Build the fixture, extract a bundle from it, and dump a core of it —
/// once for the whole suite.
fn target() -> &'static (tempfile::TempDir, PathBuf, PathBuf) {
    static TARGET: OnceLock<(tempfile::TempDir, PathBuf, PathBuf)> = OnceLock::new();
    TARGET.get_or_init(|| {
        let test_programs = workspace_root().join("test-programs");
        let status = Command::new(test_programs.join("regen.sh"))
            .arg(PROGRAM)
            .status()
            .expect("failed to run regen.sh");
        assert!(
            status.success(),
            "regen.sh failed; is the pinned toolchain installed?"
        );
        let fixture = test_programs.join("fixtures/bin").join(PROGRAM);

        let dir = tempfile::tempdir().expect("failed to create a tempdir");
        let bundle_path = dir.path().join("bundle");
        let core = dir.path().join("core");

        // The bundle comes from the same binary the core is taken from.
        // The two-binary case — a bundle from a second compilation — is
        // what the offline suite in hansei-types covers.
        let (bundle, _stats) = exegesis::extract::extract_file(
            &fixture,
            &exegesis::extract::ExtractOptions {
                include_types: Vec::new(),
                allow_missing_infra: false,
                extract_args: "hansei linux suite".to_string(),
            },
        )
        .expect("failed to extract a bundle from the fixture");
        bundle
            .save(&bundle_path)
            .expect("failed to write the bundle");

        let out = Command::new("gdb")
            .args(["-batch", "-nx", "-ex", "run", "-ex"])
            .arg(format!("gcore {}", core.display()))
            .args(["-ex", "kill", "--args"])
            .arg(&fixture)
            .env("MALLOC_ARENA_MAX", "1")
            .output()
            .unwrap_or_else(|e| panic!("failed to run gdb ({e}); it has to be on PATH"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("READY"),
            "the fixture never reached its steady state:\n{stdout}"
        );
        assert!(
            core.exists(),
            "gdb wrote no core:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );

        (dir, bundle_path, core)
    })
}

/// Run hansei against the fixture, and hand back what it printed.
fn hansei(args: &[&str]) -> String {
    let (_dir, bundle, core) = target();
    let out = Command::new(env!("CARGO_BIN_EXE_hansei"))
        .args(args)
        .arg("--bundle")
        .arg(bundle)
        .arg("--core")
        .arg(core)
        .output()
        .expect("failed to run hansei");
    assert!(
        out.status.success(),
        "hansei {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The command fails, and says why.
fn hansei_err(args: &[&str]) -> String {
    let (_dir, bundle, core) = target();
    let out = Command::new(env!("CARGO_BIN_EXE_hansei"))
        .args(args)
        .arg("--bundle")
        .arg(bundle)
        .arg("--core")
        .arg(core)
        .output()
        .expect("failed to run hansei");
    assert!(
        !out.status.success(),
        "hansei {args:?} unexpectedly succeeded:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Both parked tasks are found, named and located. That the command
/// runs at all means the bundle's symbol fingerprint resolved in the
/// target without `--force`, and that the runtime was found through the
/// thread-local the bundle names.
#[test]
fn test_tasks_lists_what_the_fixture_parked() {
    let out = hansei(&["tasks"]);
    assert!(out.contains("TASK"), "{out}");
    assert!(out.contains(PARKED_TASK), "{out}");
    assert!(out.contains(RECEIVING_TASK), "{out}");
    assert!(out.contains("2 tasks"), "{out}");

    // Both are parked at an await point, so neither is running.
    for line in out.lines().filter(|l| l.contains("async_fn_env")) {
        assert!(line.contains("idle"), "{line}");
    }
    // Spawn sites come from the bundle's line table.
    assert!(out.contains("core-tokio.rs:"), "{out}");
}

/// The await chain of a parked task, down to the locals reify renders
/// out of the core's memory.
#[test]
fn test_task_trace_reads_the_frame_locals() {
    let id = task_id(PARKED_TASK);
    let out = hansei(&["task-trace", "--task-id", &id, "-v"]);

    assert!(out.contains(PARKED_TASK), "{out}");
    assert!(out.contains("locals:"), "{out}");
    // A plain integer, a BTreeMap and a Vec, all read back through the
    // core: the fixture's own values, not just their names.
    assert!(out.contains(&format!("marker: {MARKER}")), "{out}");
    assert!(out.contains("counts:"), "{out}");
    for entry in ["1: 10", "2: 20", "3: 30"] {
        assert!(out.contains(entry), "{entry} missing from {out}");
    }
    assert!(out.contains("values:"), "{out}");
    // The await point it is parked on, by source line.
    assert!(out.contains("core-tokio.rs:"), "{out}");
}

/// The dependency graph runs and finds nothing wrong, which is the
/// right answer for two independently parked tasks.
#[test]
fn test_graph_reports_no_futurelock() {
    let out = hansei(&["graph"]);
    assert!(out.contains("WAITING ON"), "{out}");
    assert!(out.contains("no futurelock detected"), "{out}");
}

/// The two illumos-only paths say so rather than misbehaving.
#[test]
fn test_unsupported_paths_explain_themselves() {
    let err = hansei_err(&["tasks", "--heuristic-discovery"]);
    assert!(
        err.contains("fast-TSD") && err.contains("--heuristic-discovery"),
        "{err}"
    );

    // `--pid` is in the interface everywhere; only illumos honours it.
    let out = Command::new(env!("CARGO_BIN_EXE_hansei"))
        .args(["tasks", "--pid", "1", "--bundle"])
        .arg(&target().1)
        .output()
        .expect("failed to run hansei");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("not supported on this platform"), "{err}");
    assert!(err.contains("--core"), "{err}");
}

/// The task id hansei assigned to a future, read out of `tasks`.
fn task_id(future: &str) -> String {
    let out = hansei(&["tasks"]);
    out.lines()
        .find(|l| l.contains(future))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("no task row for {future}:\n{out}"))
        .to_string()
}

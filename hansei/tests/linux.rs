//! The end-to-end suite on Linux: bundle, core, and the three commands
//! that read one through the other.
//!
//! This is the whole pipeline in one place — extraction from DWARF,
//! `AT_PHDR` and the load bias, the ELF thread-local that finds the
//! runtime, the task walk, and reify's rendering of a frame's locals —
//! run against a core the kernel's own loader laid out. The illumos
//! suite (`tests/illumos.rs`) does the same against a core taken there;
//! between them the two platforms' targets are held to the same output.
//!
//! The target is `test-programs`' `core-tokio`, which parks two tasks at
//! known await points, prints `READY`, and aborts. gdb runs it and takes
//! the core with `gcore`; see `proc/tests/linux.rs` for why the core
//! comes from gdb and not from `core_pattern`.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

/// Ask an attached session one command — hansei takes them on stdin,
/// not as arguments — and hand back what it printed.
fn hansei(command: &str) -> String {
    let out = ask(command);
    assert!(
        out.status.success(),
        "hansei {command:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Ask a command that must be refused, and hand back the complaint.
fn hansei_err(command: &str) -> String {
    let out = ask(command);
    assert!(
        !out.status.success(),
        "hansei {command:?} was expected to fail:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn ask(command: &str) -> std::process::Output {
    let (_dir, bundle, core) = target();
    let mut child = Command::new(env!("CARGO_BIN_EXE_hansei"))
        .arg("--bundle")
        .arg(bundle)
        .arg("--core")
        .arg(core)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run hansei");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(command.as_bytes())
        .expect("failed to send the command");
    child.wait_with_output().expect("failed to wait for hansei")
}

/// Both parked tasks are found, named and located. That the command
/// runs at all means the bundle's symbol fingerprint resolved in the
/// target without `--force`, and that the runtime was found through the
/// thread-local the bundle names.
#[test]
fn test_tasks_lists_what_the_fixture_parked() {
    let out = hansei("tasks");
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
    let out = hansei(&format!("trace {id} -v"));

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
    let out = hansei("graph");
    assert!(out.contains("WAITING ON"), "{out}");
    assert!(out.contains("no futurelock detected"), "{out}");
}

/// Every thread the runtime runs on, from both sides: the scheduler's
/// own view of the worker (its index and the core it holds) and the
/// stack the unwinder walks out of the core.
#[test]
fn test_threads_shows_workers_and_stacks() {
    let out = hansei("threads");

    // The fixture's runtime has two workers, plus the thread blocked in
    // `block_on`, which holds a runtime context without running the
    // worker loop.
    assert_eq!(out.matches("LWP ").count(), 3, "{out}");
    assert!(out.contains("worker 0"), "{out}");
    assert!(out.contains("worker 1"), "{out}");
    assert!(out.contains("not in the scheduler's run loop"), "{out}");

    // The worker core, read through the bundle's layout: values, not
    // just field names.
    assert!(out.contains("multi_thread::worker::Core"), "{out}");
    assert!(out.contains("is_searching: false"), "{out}");
    // And the stacks, which is what needs the target's unwind info.
    assert!(out.contains("stack:"), "{out}");
    assert!(out.contains("core_tokio::main"), "{out}");
}

/// The scheduler state the workers share, read out of the target
/// through the bundle rather than through a mirror of tokio's structs.
#[test]
fn test_shared_state_reads_the_scheduler() {
    let out = hansei("shared-state");
    assert!(out.contains("multi_thread::worker::Shared"), "{out}");
    assert!(out.contains("owned:"), "{out}");
    assert!(out.contains("inject:"), "{out}");
    // The runtime the fixture builds, in its own numbers.
    assert!(out.contains("num_workers: 2"), "{out}");
}

/// The drivers hanging off the same runtime handle.
#[test]
fn test_drivers_reads_the_driver_handle() {
    let out = hansei("drivers");
    assert!(out.contains("runtime::driver::Handle"), "{out}");
    assert!(out.contains("io:"), "{out}");
    assert!(out.contains("time:"), "{out}");
}

/// A type's recorded layout, for the future `trace` walks: the
/// coroutine's states, the await point each was suspended at, and the
/// locals held across it.
#[test]
fn test_type_prints_a_recorded_layout() {
    let out = hansei(&format!("type {PARKED_TASK}"));
    assert!(out.starts_with("enum "), "{out}");
    assert!(out.contains("discriminant"), "{out}");
    assert!(out.contains("Unresumed"), "{out}");
    assert!(out.contains("Suspend0"), "{out}");
    // The await point rustc recorded for the suspend state.
    assert!(out.contains("core-tokio.rs:"), "{out}");

    // The state's payload holds the locals the trace renders.
    let out = hansei(&format!("type {PARKED_TASK}::Suspend0"));
    assert!(out.starts_with("struct "), "{out}");
    for local in ["marker", "counts", "values"] {
        assert!(out.contains(local), "{local} missing from {out}");
    }
}

/// Substring search over the same type names, which is how a name long
/// enough to need `type` is found in the first place.
#[test]
fn test_find_types_lists_matching_names() {
    let out = hansei("find-types core_tokio::");
    assert!(out.contains(PARKED_TASK), "{out}");
    assert!(out.contains(RECEIVING_TASK), "{out}");
    assert!(out.trim_end().ends_with(" types"), "{out}");

    // A needle nothing matches is an empty listing, not a failure.
    let out = hansei("find-types no_such_crate::");
    assert!(out.contains("0 types"), "{out}");
}

/// A command answers to any leading substring that fits it and no
/// other, which is what a prompt is for. A prefix that fits several
/// names them rather than picking one.
#[test]
fn test_a_unique_prefix_names_a_command() {
    assert!(hansei("i").contains("symbols resolved:"));
    assert!(hansei("dr -d 1").contains("runtime::driver::Handle"));
    assert!(hansei("thr -f 0").contains("LWP "));
    // `snapshot` is not in a default build, so nothing else starts
    // with an `s`.
    assert!(hansei("s").contains("multi_thread::worker::Shared"));

    let err = hansei_err("t");
    for candidate in ["tasks", "threads", "trace", "type"] {
        assert!(err.contains(candidate), "{candidate} missing from {err}");
    }
}

/// The task id hansei assigned to a future, read out of `tasks`.
fn task_id(future: &str) -> String {
    let out = hansei("tasks");
    out.lines()
        .find(|l| l.contains(future))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("no task row for {future}:\n{out}"))
        .to_string()
}

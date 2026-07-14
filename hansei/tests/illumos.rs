// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The illumos integration suite (plan §11.4).
//!
//! Everything here runs on-box against freshly built two-binary fixture
//! pairs: `test-programs/regen.sh` compiles the fixture programs twice
//! with the pinned recipe into separate target dirs, bundles are
//! extracted from build B, and the processes and cores under inspection
//! come from build A. Each program is driven to a deterministic parked
//! steady state by blocking on its stdout readiness marker — there are
//! no timing sleeps anywhere. Cores are taken fresh into a tempdir and
//! removed with it.
//!
//! Run via `tests/illumos/run.sh`, or on-box with
//! `cargo test -p hansei --features illumos-integration -- --ignored`.

#![cfg(feature = "illumos-integration")]

use exegesis::extract::{ExtractOptions, extract_file};

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::thread;

const PROGRAMS: &[&str] = &[
    "simple-await",
    "nested-await",
    "dyn-future",
    "futurelock",
    "many-tasks",
];

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

struct Fixtures {
    /// Build A: the binaries that run (and are cored).
    bin_a: PathBuf,
    /// Build B: a separate compilation of the same sources, which feeds
    /// the extractor — the two-binary constraint (§2).
    bin_b: PathBuf,
    /// Bundles extracted from build B, one per program.
    bundles: PathBuf,
}

impl Fixtures {
    fn program(&self, program: &str) -> PathBuf {
        self.bin_a.join(program)
    }

    fn debug_binary(&self, program: &str) -> PathBuf {
        self.bin_b.join(program)
    }

    fn bundle(&self, program: &str) -> PathBuf {
        self.bundles.join(format!("{program}.bundle"))
    }
}

/// Build both fixture compilations and extract every program's bundle,
/// once per test-suite run.
fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let test_programs = workspace_root().join("test-programs");
        let fixture_dir = test_programs.join("fixtures");
        for (bin, target) in [("bin-a", "target-a"), ("bin-b", "target-b")] {
            let status = Command::new(test_programs.join("regen.sh"))
                .args(PROGRAMS)
                .env("REGEN_BIN_DIR", fixture_dir.join(bin))
                .env("REGEN_TARGET_DIR", fixture_dir.join(target))
                .status()
                .expect("failed to run regen.sh");
            assert!(
                status.success(),
                "regen.sh failed; is the pinned toolchain installed?"
            );
        }

        let bundles = fixture_dir.join("integration");
        fs::create_dir_all(&bundles).expect("failed to create the bundle dir");
        for program in PROGRAMS {
            let opts = ExtractOptions {
                extract_args: format!("illumos integration extraction of {program}"),
                ..Default::default()
            };
            let (bundle, _stats) = extract_file(&fixture_dir.join("bin-b").join(program), &opts)
                .unwrap_or_else(|e| panic!("extraction of {program} failed: {e}"));
            bundle
                .save(&bundles.join(format!("{program}.bundle")))
                .expect("failed to write the bundle");
        }

        Fixtures {
            bin_a: fixture_dir.join("bin-a"),
            bin_b: fixture_dir.join("bin-b"),
            bundles,
        }
    })
}

/// A fixture program from build A, running at its parked steady state.
struct Parked {
    child: Child,
}

impl Parked {
    /// Launch the program and block on its stdout until the readiness
    /// marker: from that line on, the state under inspection is stable.
    fn spawn(program: &str) -> Self {
        let marker = match program {
            // Deadlocked for good once the background task drops the
            // lock (RFD 609: the handoff goes to the never-again-polled
            // future1).
            "futurelock" => "background task: done (dropping lock)",
            _ => "READY",
        };
        let path = fixtures().program(program);
        let mut child = Command::new(&path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to launch {}: {e}", path.display()));
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

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Parked {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Take a core of the parked process; it lives in the caller's tempdir
/// and is cleaned up with it.
fn gcore(pid: u32, dir: &Path) -> PathBuf {
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

/// A target for the hansei CLI: the same assertions run against a fresh
/// core and against the still-live process.
enum Source {
    Core(PathBuf),
    Live(u32),
}

impl Source {
    fn args(&self) -> Vec<String> {
        match self {
            Source::Core(path) => vec!["--core".into(), path.to_str().unwrap().into()],
            // Live attach stops the process while reading (-w
            // acknowledges that).
            Source::Live(pid) => vec!["--pid".into(), pid.to_string(), "-w".into()],
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            Source::Core(_) => "core",
            Source::Live(_) => "live",
        }
    }
}

/// Drive a program to its steady state and run `check` against a fresh
/// core of it, then against the live process.
fn for_each_source(program: &str, check: impl Fn(&Source)) {
    let parked = Parked::spawn(program);
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core = gcore(parked.pid(), dir.path());
    check(&Source::Core(core));
    check(&Source::Live(parked.pid()));
}

fn hansei(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hansei"))
        .args(args)
        .output()
        .expect("failed to run hansei")
}

/// Run hansei expecting success and no warnings, returning stdout.
fn hansei_ok(args: &[&str]) -> String {
    let out = hansei(args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "hansei {args:?} failed:\n{stderr}\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(stderr.is_empty(), "hansei {args:?} warned:\n{stderr}");
    String::from_utf8(out.stdout).expect("hansei output is UTF-8")
}

#[derive(Debug)]
struct TaskRow {
    id: String,
    state: String,
    future: String,
    spawned: String,
    defined: String,
}

/// Cells are padded with runs of two or more spaces; values themselves
/// contain at most single spaces.
fn split_columns(line: &str) -> Vec<&str> {
    line.split("  ")
        .map(str::trim)
        .filter(|cell| !cell.is_empty())
        .collect()
}

/// Run `hansei tasks` and parse the listing.
fn list_tasks(bundle: &Path, source: &Source) -> Vec<TaskRow> {
    let mut args = vec!["tasks", "--bundle", bundle.to_str().unwrap()];
    let source_args = source.args();
    args.extend(source_args.iter().map(String::as_str));
    let out = hansei_ok(&args);

    let mut lines = out.lines();
    let header = lines.next().expect("tasks output has a header");
    assert_eq!(
        split_columns(header),
        ["TASK", "STATE", "FUTURE", "SPAWNED AT", "DEFINED AT"],
        "unexpected tasks header"
    );

    let mut rows = Vec::new();
    for line in &mut lines {
        if line.is_empty() {
            break;
        }
        let cells = split_columns(line);
        assert_eq!(cells.len(), 5, "unexpected tasks row {line:?}");
        rows.push(TaskRow {
            id: cells[0].to_string(),
            state: cells[1].to_string(),
            future: cells[2].to_string(),
            spawned: cells[3].to_string(),
            defined: cells[4].to_string(),
        });
    }

    let footer = lines.next().expect("tasks output has a count footer");
    assert_eq!(
        footer,
        format!("{} tasks", rows.len()),
        "footer disagrees with the row count"
    );
    rows
}

/// The listed task with the given future type, of which there must be
/// exactly one.
fn task_with_future<'a>(rows: &'a [TaskRow], future: &str) -> &'a TaskRow {
    let mut matches = rows.iter().filter(|row| row.future == future);
    let row = matches
        .next()
        .unwrap_or_else(|| panic!("no task with future {future}: {rows:#?}"));
    assert!(
        matches.next().is_none(),
        "more than one task with future {future}: {rows:#?}"
    );
    row
}

/// Run `hansei task-trace --task-id` and return its output.
fn trace(bundle: &Path, source: &Source, task_id: &str, verbose: bool) -> String {
    let mut args = vec![
        "task-trace",
        "--bundle",
        bundle.to_str().unwrap(),
        "--task-id",
        task_id,
    ];
    if verbose {
        args.push("--verbose");
    }
    let source_args = source.args();
    args.extend(source_args.iter().map(String::as_str));
    hansei_ok(&args)
}

/// Assert every named local appears in a verbose trace. Values are live
/// memory (addresses and the like) and deliberately not asserted; the
/// exact per-frame local sets are pinned by the offline two-binary
/// tests (§11.3).
fn assert_locals(verbose_trace: &str, names: &[&str]) {
    for name in names {
        assert!(
            verbose_trace.contains(&format!("\n       {name}: ")),
            "local {name} missing from trace:\n{verbose_trace}"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance tests: exact await-chain goldens (§11.4 item 3)
// ---------------------------------------------------------------------------

/// One spawned async fn parked on a leaked oneshot: the baseline listing
/// and two-frame chain, against a core and the live process.
#[test]
#[ignore = "illumos integration suite; run via tests/illumos/run.sh"]
fn test_simple_await_acceptance() {
    let bundle = fixtures().bundle("simple-await");
    for_each_source("simple-await", |source| {
        let rows = list_tasks(&bundle, source);
        assert_eq!(rows.len(), 1, "({}) {rows:#?}", source.describe());
        let task = task_with_future(&rows, "simple_await::work::{async_fn_env#0}");
        assert_eq!(task.state, "idle", "({})", source.describe());
        assert_eq!(task.spawned, "test-programs/src/bin/simple-await.rs:32:21");
        assert_eq!(task.defined, "simple-await.rs:14");

        let expected = format!(
            "\
Task {id}: simple_await::work::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/simple-await.rs:32:21
Defined at: simple-await.rs:14

  0: simple_await::work::{{async_fn_env#0}}
     state Suspend1 — simple-await.rs:18
  1: tokio::sync::oneshot::Receiver<u32>
",
            id = task.id
        );
        assert_eq!(
            trace(&bundle, source, &task.id, false),
            expected,
            "({})",
            source.describe()
        );

        let verbose = trace(&bundle, source, &task.id, true);
        assert_locals(&verbose, &["count", "first", "ready", "park"]);
    });
}

/// async fn awaiting async fn awaiting a leaf: the exact three-deep
/// chain, every await point mapped to its source line.
#[test]
#[ignore = "illumos integration suite; run via tests/illumos/run.sh"]
fn test_nested_await_acceptance() {
    let bundle = fixtures().bundle("nested-await");
    for_each_source("nested-await", |source| {
        let rows = list_tasks(&bundle, source);
        assert_eq!(rows.len(), 1, "({}) {rows:#?}", source.describe());
        let task = task_with_future(&rows, "nested_await::outer::{async_fn_env#0}");
        assert_eq!(task.state, "idle", "({})", source.describe());
        assert_eq!(task.spawned, "test-programs/src/bin/nested-await.rs:30:21");
        assert_eq!(task.defined, "nested-await.rs:16");

        let expected = format!(
            "\
Task {id}: nested_await::outer::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/nested-await.rs:30:21
Defined at: nested-await.rs:16

  0: nested_await::outer::{{async_fn_env#0}}
     state Suspend0 — nested-await.rs:18
  1: nested_await::middle::{{async_fn_env#0}}
     state Suspend0 — nested-await.rs:12
  2: nested_await::leaf::{{async_fn_env#0}}
     state Suspend0 — nested-await.rs:8
  3: tokio::sync::oneshot::Receiver<u32>
",
            id = task.id
        );
        assert_eq!(
            trace(&bundle, source, &task.id, false),
            expected,
            "({})",
            source.describe()
        );
    });
}

/// A `Pin<Box<dyn Future>>` awaitee: the concrete type is reachable only
/// through the vtable in target memory joined against the bundle's
/// dyn-future table (the [dyn] frame). The JoinSet member is its own
/// task.
#[test]
#[ignore = "illumos integration suite; run via tests/illumos/run.sh"]
fn test_dyn_future_acceptance() {
    let bundle = fixtures().bundle("dyn-future");
    for_each_source("dyn-future", |source| {
        let rows = list_tasks(&bundle, source);
        assert_eq!(rows.len(), 2, "({}) {rows:#?}", source.describe());

        let driver = task_with_future(&rows, "dyn_future::driver::{async_fn_env#0}");
        assert_eq!(driver.state, "idle", "({})", source.describe());
        assert_eq!(driver.spawned, "test-programs/src/bin/dyn-future.rs:44:21");
        assert_eq!(driver.defined, "dyn-future.rs:22");
        let expected = format!(
            "\
Task {id}: dyn_future::driver::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/dyn-future.rs:44:21
Defined at: dyn-future.rs:22

  0: dyn_future::driver::{{async_fn_env#0}}
     state Suspend0 — dyn-future.rs:29
  1: dyn_future::boxed_leaf::{{async_fn_env#0}} [dyn]
     state Suspend0 — dyn-future.rs:11
  2: tokio::sync::oneshot::Receiver<u32>
",
            id = driver.id
        );
        assert_eq!(
            trace(&bundle, source, &driver.id, false),
            expected,
            "({})",
            source.describe()
        );

        let member = task_with_future(&rows, "dyn_future::set_member::{async_fn_env#0}");
        assert_eq!(member.state, "idle", "({})", source.describe());
        assert_eq!(member.spawned, "test-programs/src/bin/dyn-future.rs:26:9");
        assert_eq!(member.defined, "dyn-future.rs:14");
        let expected = format!(
            "\
Task {id}: dyn_future::set_member::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/dyn-future.rs:26:9
Defined at: dyn-future.rs:14

  0: dyn_future::set_member::{{async_fn_env#0}}
     state Suspend0 — dyn-future.rs:15
  1: tokio::sync::oneshot::Receiver<u32>
",
            id = member.id
        );
        assert_eq!(
            trace(&bundle, source, &member.id, false),
            expected,
            "({})",
            source.describe()
        );
    });
}

/// The RFD 609 futurelock acceptance test (§10, §11.4): the surviving
/// task is suspended in the select! arm while still holding `future1`
/// (visible in its locals), blocked down the Mutex lock/acquire chain on
/// the semaphore leaf — found fully automatically.
#[test]
#[ignore = "illumos integration suite; run via tests/illumos/run.sh"]
fn test_futurelock_acceptance() {
    let bundle = fixtures().bundle("futurelock");
    for_each_source("futurelock", |source| {
        let rows = list_tasks(&bundle, source);
        // The background task completed and left OwnedTasks; only the
        // deadlocked main task remains.
        assert_eq!(rows.len(), 1, "({}) {rows:#?}", source.describe());
        let task = task_with_future(
            &rows,
            "futurelock::main::{async_block#0}::{async_block_env#0}",
        );
        assert_eq!(task.state, "idle", "({})", source.describe());
        assert_eq!(task.spawned, "test-programs/src/bin/futurelock.rs:13:17");
        assert_eq!(task.defined, "futurelock.rs:13");

        let expected = format!(
            "\
Task {id}: futurelock::main::{{async_block#0}}::{{async_block_env#0}} (idle)
Spawned at: test-programs/src/bin/futurelock.rs:13:17
Defined at: futurelock.rs:13

  0: futurelock::main::{{async_block#0}}::{{async_block_env#0}}
     state Suspend1 — futurelock.rs:23
  1: futurelock::do_stuff::{{async_fn_env#0}}
     state Suspend1 — futurelock.rs:60
  2: futurelock::do_async_thing::{{async_fn_env#0}}
     state Suspend0 — futurelock.rs:68
  3: tokio::sync::mutex::{{impl#10}}::lock::{{async_fn_env#0}}<()>
     state Suspend0 — src/sync/mutex.rs:455
  4: tokio::sync::mutex::{{impl#10}}::lock::{{async_fn#0}}::{{async_block_env#0}}<()>
     state Suspend0 — src/sync/mutex.rs:436
  5: tokio::sync::mutex::{{impl#10}}::acquire::{{async_fn_env#0}}<()>
     state Suspend1 — src/sync/mutex.rs:658
  6: tokio::sync::batch_semaphore::Acquire
",
            id = task.id
        );
        assert_eq!(
            trace(&bundle, source, &task.id, false),
            expected,
            "({})",
            source.describe()
        );

        // The boxed, never-again-polled future1 is still held across
        // do_stuff's suspension — the futurelock signature.
        let verbose = trace(&bundle, source, &task.id, true);
        assert_locals(&verbose, &["lock", "future1", "disabled", "label"]);
    });
}

/// Thirty-two identical parked tasks: enough to give the OwnedTasks
/// shards more than one task each, so the listing exercises the
/// intrusive-list walk beyond the shard heads.
#[test]
#[ignore = "illumos integration suite; run via tests/illumos/run.sh"]
fn test_many_tasks_acceptance() {
    let bundle = fixtures().bundle("many-tasks");
    for_each_source("many-tasks", |source| {
        let rows = list_tasks(&bundle, source);
        assert_eq!(rows.len(), 32, "({}) {rows:#?}", source.describe());
        for row in &rows {
            assert_eq!(row.state, "idle", "({}) {row:#?}", source.describe());
            assert_eq!(row.future, "many_tasks::park_task::{async_fn_env#0}");
            assert_eq!(row.spawned, "test-programs/src/bin/many-tasks.rs:25:13");
            assert_eq!(row.defined, "many-tasks.rs:9");
        }
        let ids: HashSet<&str> = rows.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(ids.len(), rows.len(), "task ids are unique");

        let task = &rows[0];
        let expected = format!(
            "\
Task {id}: many_tasks::park_task::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/many-tasks.rs:25:13
Defined at: many-tasks.rs:9

  0: many_tasks::park_task::{{async_fn_env#0}}
     state Suspend0 — many-tasks.rs:11
  1: tokio::sync::oneshot::Receiver<u32>
",
            id = task.id
        );
        assert_eq!(
            trace(&bundle, source, &task.id, false),
            expected,
            "({})",
            source.describe()
        );
    });
}

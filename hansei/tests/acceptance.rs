// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The acceptance suite: hansei driven end to end against a core of a
//! fixture program, on whatever system is running the tests.
//!
//! Everything here runs against freshly built two-binary fixture pairs:
//! `test-programs/regen.sh` compiles the fixture programs twice with the
//! pinned recipe into separate target dirs, bundles are extracted from
//! build B, and the cores under inspection come from build A. Joining
//! B's layouts against A's memory by mangled symbol name is the
//! two-binary constraint the whole design rests on. Each program is
//! driven to a deterministic parked steady state by blocking on its
//! stdout readiness marker — there are no timing sleeps anywhere. Cores
//! are taken fresh into a tempdir and removed with it.
//!
//! None of it is platform-specific. `gcore(1)` takes a core of a running
//! process under the same spelling on both systems, and hansei reads
//! either format, so the same goldens hold on illumos — where the core
//! comes back through libproc — and on Linux, where it is read from the
//! file. What a system has to provide is the pinned toolchain and the
//! right to core a process it owns; on Linux that means a
//! `kernel.yama.ptrace_scope` permissive enough to attach.

use exegesis::bundle::{Bundle, BundleView};
use exegesis::extract::{ExtractOptions, extract_file};
use hansei_types::tokio::bundle::Context as BundleContext;
use proc::Proc;

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
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
    "sleep-join",
];

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

struct Fixtures {
    /// Build A: the binaries that run (and are cored).
    bin_a: PathBuf,
    /// Bundles extracted from build B, one per program.
    bundles: PathBuf,
}

impl Fixtures {
    fn program(&self, program: &str) -> PathBuf {
        self.bin_a.join(program)
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
                extract_args: format!("acceptance-suite extraction of {program}"),
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

/// Drive a program to its steady state and run `check` against a fresh
/// core of it.
fn with_core(program: &str, check: impl Fn(&Path)) {
    let parked = Parked::spawn(program);
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core = gcore(parked.pid(), dir.path());
    check(&core);
}

/// Attach a session to `core` through `bundle` and ask it one command.
/// hansei reads commands from stdin, so the command is written there
/// rather than passed as an argument.
fn hansei(bundle: &Path, core: &Path, command: &str) -> Output {
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

/// Run hansei expecting success and no warnings, returning stdout.
fn hansei_ok(bundle: &Path, core: &Path, command: &str) -> String {
    let out = hansei(bundle, core, command);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "hansei {command:?} failed:\n{stderr}\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(stderr.is_empty(), "hansei {command:?} warned:\n{stderr}");
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

/// Run the `tasks` command and parse the listing.
fn list_tasks(bundle: &Path, core: &Path) -> Vec<TaskRow> {
    let out = hansei_ok(bundle, core, "tasks");

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

/// Run the `trace` command and return its output.
fn trace(bundle: &Path, core: &Path, task_id: &str, verbose: bool) -> String {
    trace_opts(bundle, core, task_id, verbose, false)
}

/// Like [`trace`], but also toggles `--ugly` (the raw structural view, with
/// every type's custom formatter suppressed).
fn trace_opts(bundle: &Path, core: &Path, task_id: &str, verbose: bool, ugly: bool) -> String {
    let mut command = format!("trace {task_id}");
    if verbose {
        command.push_str(" --verbose");
    }
    if ugly {
        command.push_str(" --ugly");
    }
    hansei_ok(bundle, core, &command)
}

/// Mask the run-varying values a trace can carry — heap addresses and
/// timer deadlines — so goldens compare exactly.
fn normalize(trace: &str) -> String {
    let addrs = regex::Regex::new(r"0x[0-9a-f]+").unwrap();
    let deadlines = regex::Regex::new(r"deadline \d+\.\d{3}s").unwrap();
    let masked = addrs.replace_all(trace, "0xADDR");
    deadlines.replace_all(&masked, "deadline TS").into_owned()
}

fn assert_locals(verbose_trace: &str, names: &[&str]) {
    for name in names {
        let prefix = format!("{name}:");
        assert!(
            verbose_trace
                .lines()
                .any(|line| line.trim_start().starts_with(&prefix)),
            "local {name} missing from trace:\n{verbose_trace}"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance tests: exact await-chain goldens (§11.4 item 3)
// ---------------------------------------------------------------------------

/// One spawned async fn parked on a leaked oneshot: the baseline listing
/// and two-frame chain.
#[test]
fn test_simple_await_acceptance() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 1, "{rows:#?}");
        let task = task_with_future(&rows, "simple_await::work::{async_fn_env#0}");
        assert_eq!(task.state, "idle");
        assert_eq!(task.spawned, "test-programs/src/bin/simple-await.rs:67:21");
        assert_eq!(task.defined, "simple-await.rs:16");

        let expected = format!(
            "\
Task {id}: simple_await::work::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/simple-await.rs:67:21
Defined at: simple-await.rs:16

  0  async fn      simple_await::work::{{async_fn_env#0}}
     state         Suspend1 — simple-await.rs:34
     awaits:
     └─* 1  future        tokio::sync::oneshot::Receiver<u32>
",
            id = task.id
        );
        assert_eq!(trace(&bundle, core, &task.id, false), expected);

        let verbose = trace(&bundle, core, &task.id, true);
        assert_locals(&verbose, &["count", "first", "ready", "park"]);
    });
}

/// The locals are read out of the target, not merely named: the
/// fixture's own numbers come back through the bundle's layouts, and the
/// containers among them — a `BTreeMap`, a `Vec`, a boxed slice and a
/// borrowed one — are walked into the target's memory to reach their
/// elements.
#[test]
fn test_local_values_come_back_from_the_target() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "simple_await::work::{async_fn_env#0}");
        let verbose = trace(&bundle, core, &task.id, true);

        // Scalars, including one the task computed after its first
        // await rather than one it was handed.
        assert!(verbose.contains("count: 3"), "{verbose}");
        assert!(verbose.contains("first: 41"), "{verbose}");

        // The map's entries, in key order.
        for entry in ["1: 10", "2: 20", "3: 30"] {
            assert!(verbose.contains(entry), "{entry} missing from {verbose}");
        }

        // `values`, `boxed` and `slice` hold 3, 2 and 3 elements; every
        // one of them is read through a pointer into the target.
        for element in ["5,", "8,", "13,", "21,", "34,"] {
            assert!(
                verbose.contains(element),
                "element {element} missing from {verbose}"
            );
        }
    });
}

/// `--ugly` suppresses every type's custom formatter and falls back to the
/// raw structural view. The simple-await task keeps a spread of
/// custom-formatted locals live across its park — an IP address, a borrowed
/// `&str`, an owned `String` — each of which reads as its decoded value
/// normally and as its underlying representation under `--ugly`.
#[test]
fn test_ugly_locals_acceptance() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "simple_await::work::{async_fn_env#0}");
        // Normal verbose rendering: each local reads as its decoded value,
        // through its own formatter.
        let pretty = trace_opts(&bundle, core, &task.id, true, false);
        assert!(pretty.contains("ipv4: 192.0.2.1"), "{pretty}");
        assert!(pretty.contains(r#"borrowed: "borrowed\ntext""#), "{pretty}");
        assert!(pretty.contains(r#"owned: "owned\ttext""#), "{pretty}");

        // --ugly: the very same locals render through their structure, and the
        // formatted forms are gone entirely.
        let ugly = trace_opts(&bundle, core, &task.id, true, true);
        assert!(
            !ugly.contains("192.0.2.1"),
            "--ugly still formatted the IP:\n{ugly}"
        );
        assert!(
            !ugly.contains(r#""borrowed\ntext""#),
            "--ugly still formatted the &str:\n{ugly}"
        );
        assert!(
            ugly.contains("core::net::ip_addr::Ipv4Addr {"),
            "--ugly IP is not structural:\n{ugly}"
        );
        assert!(
            ugly.contains("&str {") && ugly.contains("length: 13"),
            "--ugly &str is not structural:\n{ugly}"
        );
        assert!(
            ugly.contains("alloc::string::String {"),
            "--ugly String is not structural:\n{ugly}"
        );
    });
}

/// async fn awaiting async fn awaiting a leaf: the exact three-deep
/// chain, every await point mapped to its source line.
#[test]
fn test_nested_await_acceptance() {
    let bundle = fixtures().bundle("nested-await");
    with_core("nested-await", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 1, "{rows:#?}");
        let task = task_with_future(&rows, "nested_await::outer::{async_fn_env#0}");
        assert_eq!(task.state, "idle");
        assert_eq!(task.spawned, "test-programs/src/bin/nested-await.rs:32:21");
        assert_eq!(task.defined, "nested-await.rs:16");

        let expected = format!(
            "\
Task {id}: nested_await::outer::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/nested-await.rs:32:21
Defined at: nested-await.rs:16

  0  async fn      nested_await::outer::{{async_fn_env#0}}
     state         Suspend0 — nested-await.rs:18
     awaits:
     └─  1  async fn      nested_await::middle::{{async_fn_env#0}}
         state            Suspend0 — nested-await.rs:12
         awaits:
         └─  2  async fn      nested_await::leaf::{{async_fn_env#0}}
             state            Suspend0 — nested-await.rs:8
             awaits:
             └─* 3  future        tokio::sync::oneshot::Receiver<u32>
",
            id = task.id
        );
        assert_eq!(trace(&bundle, core, &task.id, false), expected);
    });
}

/// A `Pin<Box<dyn Future>>` awaitee: the concrete type is reachable only
/// through the vtable in target memory joined against the bundle's
/// dyn-future table (the [dyn] frame). The JoinSet member is its own
/// task.
#[test]
fn test_dyn_future_acceptance() {
    let bundle = fixtures().bundle("dyn-future");
    with_core("dyn-future", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 2, "{rows:#?}");

        let driver = task_with_future(&rows, "dyn_future::driver::{async_fn_env#0}");
        assert_eq!(driver.state, "idle");
        assert_eq!(driver.spawned, "test-programs/src/bin/dyn-future.rs:46:21");
        assert_eq!(driver.defined, "dyn-future.rs:22");
        let expected = format!(
            "\
Task {id}: dyn_future::driver::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/dyn-future.rs:46:21
Defined at: dyn-future.rs:22

  0  async fn      dyn_future::driver::{{async_fn_env#0}}
     state         Suspend0 — dyn-future.rs:29
     awaits:
     └─  1  async fn      dyn_future::boxed_leaf::{{async_fn_env#0}} [dyn]
         state            Suspend0 — dyn-future.rs:11
         awaits:
         └─* 2  future        tokio::sync::oneshot::Receiver<u32>
",
            id = driver.id
        );
        assert_eq!(trace(&bundle, core, &driver.id, false), expected);

        let member = task_with_future(&rows, "dyn_future::set_member::{async_fn_env#0}");
        assert_eq!(member.state, "idle");
        assert_eq!(member.spawned, "test-programs/src/bin/dyn-future.rs:26:9");
        assert_eq!(member.defined, "dyn-future.rs:14");
        let expected = format!(
            "\
Task {id}: dyn_future::set_member::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/dyn-future.rs:26:9
Defined at: dyn-future.rs:14

  0  async fn      dyn_future::set_member::{{async_fn_env#0}}
     state         Suspend0 — dyn-future.rs:15
     awaits:
     └─* 1  future        tokio::sync::oneshot::Receiver<u32>
",
            id = member.id
        );
        assert_eq!(trace(&bundle, core, &member.id, false), expected);
    });
}

/// The RFD 609 futurelock acceptance test (§10, §11.4): the surviving
/// task is suspended in the select! arm while still holding `future1`
/// (visible in its locals), blocked down the Mutex lock/acquire chain on
/// the semaphore leaf — found fully automatically.
#[test]
fn test_futurelock_acceptance() {
    let bundle = fixtures().bundle("futurelock");
    with_core("futurelock", |core| {
        let rows = list_tasks(&bundle, core);
        // The background task completed and left OwnedTasks; only the
        // deadlocked main task remains.
        assert_eq!(rows.len(), 1, "{rows:#?}");
        let task = task_with_future(
            &rows,
            "futurelock::main::{async_block#0}::{async_block_env#0}",
        );
        assert_eq!(task.state, "idle");
        assert_eq!(task.spawned, "test-programs/src/bin/futurelock.rs:15:17");
        assert_eq!(task.defined, "futurelock.rs:15");

        let expected = format!(
            "\
Task {id}: futurelock::main::{{async_block#0}}::{{async_block_env#0}} (idle)
Spawned at: test-programs/src/bin/futurelock.rs:15:17
Defined at: futurelock.rs:15

  0  async block   futurelock::main::{{async_block#0}}::{{async_block_env#0}}
     state         Suspend1 — futurelock.rs:25
     awaits:
     └─  1  async fn      futurelock::do_stuff::{{async_fn_env#0}}
         state            Suspend1 — futurelock.rs:64
         awaits:
         └─  2  async fn      futurelock::do_async_thing::{{async_fn_env#0}}
             state            Suspend0 — futurelock.rs:72
             awaits:
             └─  3  async fn      tokio::sync::mutex::{{impl#10}}::lock::{{async_fn_env#0}}<()>
                 state            Suspend0 — src/sync/mutex.rs:455
                 awaits:
                 └─  4  async block   tokio::sync::mutex::{{impl#10}}::lock::{{async_fn#0}}::{{async_block_env#0}}<()>
                     state            Suspend0 — src/sync/mutex.rs:436
                     awaits:
                     └─  5  async fn      tokio::sync::mutex::{{impl#10}}::acquire::{{async_fn_env#0}}<()>
                         state            Suspend1 — src/sync/mutex.rs:658
                         awaits:
                         └─* 6  future        tokio::sync::batch_semaphore::Acquire
                             waiting on a tokio::sync::Mutex (semaphore 0xADDR): 1 permit requested, 0 available; wake queue: task {id}
",
            id = task.id
        );
        assert_eq!(normalize(&trace(&bundle, core, &task.id, false)), expected);

        // The boxed, never-again-polled future1 is still held across
        // do_stuff's suspension — the futurelock signature.
        let verbose = trace(&bundle, core, &task.id, true);
        assert_locals(&verbose, &["lock", "future1", "disabled", "label"]);
    });
}

/// Thirty-two identical parked tasks: enough to give the OwnedTasks
/// shards more than one task each, so the listing exercises the
/// intrusive-list walk beyond the shard heads.
#[test]
fn test_many_tasks_acceptance() {
    let bundle = fixtures().bundle("many-tasks");
    with_core("many-tasks", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 32, "{rows:#?}");
        for row in &rows {
            assert_eq!(row.state, "idle", "{row:#?}");
            assert_eq!(row.future, "many_tasks::park_task::{async_fn_env#0}");
            assert_eq!(row.spawned, "test-programs/src/bin/many-tasks.rs:27:13");
            assert_eq!(row.defined, "many-tasks.rs:9");
        }
        let ids: HashSet<&str> = rows.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(ids.len(), rows.len(), "task ids are unique");

        let task = &rows[0];
        let expected = format!(
            "\
Task {id}: many_tasks::park_task::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/many-tasks.rs:27:13
Defined at: many-tasks.rs:9

  0  async fn      many_tasks::park_task::{{async_fn_env#0}}
     state         Suspend0 — many-tasks.rs:11
     awaits:
     └─* 1  future        tokio::sync::oneshot::Receiver<u32>
",
            id = task.id
        );
        assert_eq!(trace(&bundle, core, &task.id, false), expected);
    });
}

/// The leaf-future knowledge base (§3.6): a task parked on the timer
/// reports its deadline, and a task awaiting a JoinHandle reports which
/// task it waits for — the dependency edge, joined across the two
/// binaries by nothing but the leaf's type name.
#[test]
fn test_sleep_join_acceptance() {
    let bundle = fixtures().bundle("sleep-join");
    with_core("sleep-join", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 2, "{rows:#?}");
        let sleeper = task_with_future(&rows, "sleep_join::sleeper::{async_fn_env#0}");
        let joiner = task_with_future(&rows, "sleep_join::joiner::{async_fn_env#0}");
        assert_eq!(sleeper.state, "idle");
        assert_eq!(joiner.state, "idle");

        let expected = format!(
            "\
Task {id}: sleep_join::sleeper::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/sleep-join.rs:28:22
Defined at: sleep-join.rs:9

  0  async fn      sleep_join::sleeper::{{async_fn_env#0}}
     state         Suspend0 — sleep-join.rs:11
     awaits:
     └─* 1  future        tokio::time::sleep::Sleep
         waiting on the timer: deadline TS on the target's monotonic clock
",
            id = sleeper.id
        );
        assert_eq!(
            normalize(&trace(&bundle, core, &sleeper.id, false)),
            expected
        );

        let expected = format!(
            "\
Task {id}: sleep_join::joiner::{{async_fn_env#0}} (idle)
Spawned at: test-programs/src/bin/sleep-join.rs:29:23
Defined at: sleep-join.rs:15

  0  async fn      sleep_join::joiner::{{async_fn_env#0}}
     state         Suspend0 — sleep-join.rs:17
     awaits:
     └─* 1  future        tokio::runtime::task::join::JoinHandle<u32>
         waiting on task {sleeper_id} (JoinHandle)
",
            id = joiner.id,
            sleeper_id = sleeper.id
        );
        assert_eq!(trace(&bundle, core, &joiner.id, false), expected);
    });
}

// ---------------------------------------------------------------------------
// Dependency graph and futurelock diagnosis (§3.6, §10)
// ---------------------------------------------------------------------------

/// Run the `graph` command and return its output.
fn graph(bundle: &Path, core: &Path) -> String {
    hansei_ok(bundle, core, "graph")
}

/// Format rows the way the graph table does: two-space separated
/// columns, each padded to its widest cell.
fn graph_table(rows: &[[&str; 3]]) -> String {
    let mut widths = [0usize; 2];
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()) {
            *w = (*w).max(cell.len());
        }
    }
    rows.iter()
        .map(|[task, state, target]| {
            format!(
                "{task:<w0$}  {state:<w1$}  {target}\n",
                w0 = widths[0],
                w1 = widths[1]
            )
        })
        .collect()
}

/// The RFD 609 diagnosis, fully automatic: the contended Mutex's wake
/// queue resolves to the blocked task itself, and the abandoned
/// `future1` is found in do_stuff's locals holding the granted permit
/// it can never release.
#[test]
fn test_futurelock_graph() {
    let bundle = fixtures().bundle("futurelock");
    with_core("futurelock", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(
            &rows,
            "futurelock::main::{async_block#0}::{async_block_env#0}",
        );
        let id = task.id.as_str();

        let wait = format!(
            "a tokio::sync::Mutex (semaphore 0xADDR): 1 permit requested, \
             0 available; wake queue: task {id}"
        );
        let mut expected = graph_table(&[["TASK", "STATE", "WAITING ON"], [id, "idle", &wait]]);
        expected.push_str(&format!(
            "\nfuturelock: task {id} holds 1 granted permit of a tokio::sync::Mutex \
             (semaphore 0xADDR) in a future it stopped polling:\n  \
             `future1` (futurelock::do_async_thing::{{async_fn_env#0}})\n  \
             held across futurelock::do_stuff::{{async_fn_env#0}} state Suspend1 \
             — futurelock.rs:64\n  \
             blocked behind it: task {id}\n"
        ));
        assert_eq!(normalize(&graph(&bundle, core)), expected);
    });
}

/// Wait edges without a diagnosis: the joiner's JoinHandle edge points
/// at the sleeper, the sleeper waits on the timer, and a healthy
/// runtime reports no futurelock.
#[test]
fn test_sleep_join_graph() {
    let bundle = fixtures().bundle("sleep-join");
    with_core("sleep-join", |core| {
        let rows = list_tasks(&bundle, core);
        let sleeper = task_with_future(&rows, "sleep_join::sleeper::{async_fn_env#0}");
        let joiner = task_with_future(&rows, "sleep_join::joiner::{async_fn_env#0}");

        let join_edge = format!("task {} (JoinHandle)", sleeper.id);
        let mut expected = graph_table(&[
            ["TASK", "STATE", "WAITING ON"],
            [
                &sleeper.id,
                "idle",
                "the timer: deadline TS on the target's monotonic clock",
            ],
            [&joiner.id, "idle", &join_edge],
        ]);
        expected.push_str("\nno futurelock detected\n");
        assert_eq!(normalize(&graph(&bundle, core)), expected);
    });
}

// ---------------------------------------------------------------------------
// Runtime state and bundle layouts
// ---------------------------------------------------------------------------

/// The runtime as its own threads hold it: each worker's index and the
/// `Core` it is carrying, plus the stack the unwinder walks out of the
/// core. Worker counts follow the box's CPU count, so what is asserted
/// is the shape of a worker, not how many there are.
#[test]
fn test_threads_shows_workers_and_stacks() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "threads");
        assert!(out.contains("LWP "), "{out}");
        assert!(out.contains("worker 0"), "{out}");
        assert!(out.contains("multi_thread::worker::Core"), "{out}");
        assert!(out.contains("is_searching:"), "{out}");
        // The blocking thread holds a runtime context without running
        // the worker loop.
        assert!(out.contains("not in the scheduler's run loop"), "{out}");
        assert!(out.contains("stack:"), "{out}");
        assert!(out.contains("simple_await::main"), "{out}");
    });
}

/// The scheduler state and the drivers, both read out of the target
/// through the bundle's layouts rather than a mirror of tokio's structs.
#[test]
fn test_shared_state_and_drivers() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let shared = hansei_ok(&bundle, core, "shared-state");
        assert!(shared.contains("multi_thread::worker::Shared"), "{shared}");
        assert!(shared.contains("owned:"), "{shared}");
        assert!(shared.contains("inject:"), "{shared}");
        assert!(shared.contains("num_workers:"), "{shared}");

        let drivers = hansei_ok(&bundle, core, "drivers");
        assert!(drivers.contains("runtime::driver::Handle"), "{drivers}");
        assert!(drivers.contains("io:"), "{drivers}");
        assert!(drivers.contains("time:"), "{drivers}");
    });
}

/// The layouts behind those readings: the parked task's coroutine
/// states, the await point recorded for each, and the substring search
/// that finds the name in the first place.
#[test]
fn test_type_and_find_types() {
    let bundle = fixtures().bundle("simple-await");
    let future = "simple_await::work::{async_fn_env#0}";
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, &format!("type {future}"));
        assert!(out.starts_with("enum "), "{out}");
        assert!(out.contains("discriminant"), "{out}");
        assert!(out.contains("Unresumed"), "{out}");
        // The state the task is parked in, at the await point rustc
        // recorded for it — the same line the trace prints.
        assert!(out.contains("Suspend1"), "{out}");
        assert!(out.contains("simple-await.rs:34"), "{out}");

        // The locals held across that await.
        let out = hansei_ok(&bundle, core, &format!("type {future}::Suspend1"));
        assert!(out.starts_with("struct "), "{out}");
        for local in ["count", "first", "ready", "park"] {
            assert!(out.contains(local), "{local} missing from {out}");
        }

        let out = hansei_ok(&bundle, core, "find-types simple_await::");
        assert!(out.contains(future), "{out}");
        assert!(out.trim_end().ends_with(" types"), "{out}");
    });
}

/// A command answers to any leading substring that fits it and no
/// other, which is what a prompt is for. A prefix that fits several
/// names them rather than picking one.
#[test]
fn test_a_unique_prefix_names_a_command() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        assert!(hansei_ok(&bundle, core, "i").contains("symbols resolved:"));
        assert!(hansei_ok(&bundle, core, "dr -d 1").contains("runtime::driver::Handle"));
        assert!(hansei_ok(&bundle, core, "thr -f 0").contains("LWP "));
        // `snapshot` is not in a default build, so nothing else starts
        // with an `s`.
        assert!(hansei_ok(&bundle, core, "s").contains("multi_thread::worker::Shared"));

        let out = hansei(&bundle, core, "t");
        assert!(
            !out.status.success(),
            "an ambiguous prefix must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        for candidate in ["tasks", "threads", "trace", "type"] {
            assert!(err.contains(candidate), "{candidate} missing from {err}");
        }
    });
}

// ---------------------------------------------------------------------------
// Symbol match-rate tests
// ---------------------------------------------------------------------------

/// A same-recipe pair fingerprints at exactly 100%.
#[test]
fn test_fingerprint_complete_on_matched_pair() {
    let parked = Parked::spawn("simple-await");
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core = gcore(parked.pid(), dir.path());

    let proc = Proc::open_core(&core).expect("failed to open the core");
    let bundle = Bundle::load(&fixtures().bundle("simple-await")).expect("bundle loads");
    let view = BundleView::new(&bundle);
    let ctx = BundleContext::new(&proc, view).expect("context");

    let fp = ctx.validate_fingerprint();
    assert!(fp.total > 0, "the bundle carries a fingerprint");
    assert!(
        fp.is_complete(),
        "expected a 100% symbol match on a same-recipe pair, got {}/{}; missing: {:#?}",
        fp.matched,
        fp.total,
        fp.missing
    );
}

/// A bundle from a different program shares tokio-internal
/// instantiations with the target but misses its program-specific ones:
/// the fingerprint lands strictly between zero and complete, and the
/// default <100% policy refuses it with a pointed diagnostic.
#[test]
fn test_mismatched_bundle_refused() {
    let parked = Parked::spawn("simple-await");
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core = gcore(parked.pid(), dir.path());
    let wrong_bundle = fixtures().bundle("futurelock");

    let out = hansei(&wrong_bundle, &core, "tasks");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a mismatched bundle must be refused, but hansei succeeded:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains("does not match this binary"),
        "diagnostic does not name the mismatch:\n{stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "diagnostic does not mention the override:\n{stderr}"
    );

    // The mismatch is partial, not total: different programs share the
    // tokio-internal task instantiations.
    let proc = Proc::open_core(&core).expect("failed to open the core");
    let bundle = Bundle::load(&wrong_bundle).expect("bundle loads");
    let view = BundleView::new(&bundle);
    let ctx = BundleContext::new(&proc, view).expect("context");
    let fp = ctx.validate_fingerprint();
    assert!(fp.matched > 0, "no symbols matched at all");
    assert!(fp.matched < fp.total, "{}/{}", fp.matched, fp.total);
}

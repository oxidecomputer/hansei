// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The acceptance suite: hansei driven end to end against a core of a
//! fixture program, on whatever system is running the tests.
//!
//! Everything here runs against freshly built two-binary fixture pairs:
//! `test-programs/regen.sh` compiles the fixture programs twice into
//! separate target dirs, bundles are extracted from build B, and the
//! cores under inspection come from build A — which carries **no debug
//! info**, the shape of a production binary a core actually comes
//! from, so the join is proven against a target whose only
//! self-description is its symbol table. Joining B's layouts against
//! A's memory by mangled symbol name is the two-binary constraint the
//! whole design rests on. Build B is not a compilation of its own: it
//! is the standard fixture build, the same dirs the extraction goldens
//! use, so on a host that runs both suites the debug graph is compiled
//! once. The constraint only needs the *cored* binary to come from a
//! different compilation than the bundle, and build A still does. Each program is driven to a deterministic
//! parked steady state by blocking on its stdout readiness marker —
//! there are no timing sleeps anywhere. Cores are taken fresh into a
//! tempdir and removed with it.
//!
//! By default the pair is the primary matrix cell — the checked-in
//! lock's tokio on the pinned toolchain, `--cfg tokio_unstable` on.
//! `HANSEI_CELL=rust-<toolchain>-tokio-<version>-{unstable,stable}`
//! (the fixture-dir spelling `regen.sh` uses) runs the whole suite
//! against that cell instead, which is the behavioral half of the
//! version matrix: the goldens hold semantic facts — states decode,
//! chains reach their known leaves, counts match what the fixture
//! spawned — that no bundle-only check can prove. What a cell cannot
//! record adapts ([`spawned`]: a no-unstable build has no spawn
//! locations), and what varies per cell is masked ([`normalize`]:
//! tokio's own source lines move between versions).
//!
//! Nothing here is specific to *either* of the two systems it runs on.
//! `gcore(1)` takes a core of a running process under the same spelling
//! on both, and hansei reads either format, so the same goldens hold on
//! illumos — where the core comes back through libproc — and on Linux,
//! where it is read from the file. What a system has to provide is the
//! pinned toolchain and the right to core a process it owns; on Linux
//! that means a `kernel.yama.ptrace_scope` permissive enough to attach.
//!
//! Those two are the whole of it, so the suite compiles nowhere else.
//! What it asks of a system is a core of an ELF target, and the only
//! core formats hansei knows are the ELF ones these two write; macOS
//! spells `gcore` the same way but hands back a Mach-O core of a Mach-O
//! binary, which nothing downstream can read. The portable coverage of
//! the same analysis is `hansei-runtime/tests/two_binary.rs`, which
//! replays captured snapshots instead of coring anything.

#![cfg(any(target_os = "linux", target_os = "illumos"))]

use exegesis::extract::{ExtractOptions, extract_file};
use hansei_bundle::{Bundle, BundleView};
use hansei_runtime::testkit::matrix::Matrix;
use hansei_runtime::tokio::bundle::Context as BundleContext;
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

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

/// What this cell's fixture binaries are compiled from, for a run
/// reusing what an earlier one left behind (`testrun::REUSE`): the
/// programs and the crate they call into, the manifests and lockfiles
/// pinning what they link, the script that builds them and the manifest
/// naming the cells, and the cell's own flags.
fn compiled_from(cell: &Cell) -> String {
    let dir = workspace_root().join("test-programs");
    let mut inputs = testrun::Inputs::new();
    inputs
        .text(&cell.flags.join(" "))
        .text(&PROGRAMS.join(" "))
        .tree(&dir.join("src"), ".rs")
        .tree(&dir.join("locks"), ".lock")
        .file(&dir.join("Cargo.toml"))
        .file(&dir.join("Cargo.lock"))
        .file(&dir.join("matrix.toml"))
        .file(&dir.join("regen.sh"))
        .file(&dir.join("capture-snapshots.sh"));
    let matrix = Matrix::read(&dir);
    let mut recipe = matrix.primary_recipe();
    recipe.unstable = cell.unstable;
    for pair in cell.flags.windows(2) {
        match pair[0].as_str() {
            "--tokio" => recipe.tokio.clone_from(&pair[1]),
            "--toolchain" => recipe.toolchain.clone_from(&pair[1]),
            _ => {}
        }
    }
    for program in PROGRAMS {
        inputs
            .text(&recipe.inputs(&dir, &matrix, program))
            .text(&recipe.target_recipe().inputs(&dir, &matrix, program));
    }
    inputs.finish()
}

/// What this cell's bundles are extracted from: the binaries above, and
/// the code that reads and writes them.
fn extracted_from(cell: &Cell) -> String {
    let root = workspace_root();
    let mut inputs = testrun::Inputs::new();
    inputs
        .text(&compiled_from(cell))
        .tree(&root.join("exegesis/src"), ".rs")
        .tree(&root.join("hansei-bundle/src"), ".rs")
        .file(&root.join("Cargo.lock"));
    inputs.finish()
}

/// The matrix cell the suite is running against.
struct Cell {
    /// The fixture-dir name, `None` for the primary cell.
    name: Option<String>,
    /// Whether this is the primary cell, named or not: `regen.sh`
    /// builds that one in the everyday dirs whatever it was asked for
    /// by, so where its binaries land is decided by what it *is*,
    /// not by whether `HANSEI_CELL` spelled it out.
    primary: bool,
    /// `--tokio`/`--toolchain`/`--no-unstable` for `regen.sh`; empty
    /// for the primary cell, whose defaults are exactly that recipe.
    flags: Vec<String>,
    /// Whether the cell builds with `--cfg tokio_unstable`.
    unstable: bool,
    /// The (toolchain, cfg) pair key: cells of one pair share target
    /// dirs, so switching tokio versions re-resolves only tokio.
    pair: String,
}

fn cell() -> &'static Cell {
    static CELL: OnceLock<Cell> = OnceLock::new();
    CELL.get_or_init(|| {
        let Ok(name) = std::env::var("HANSEI_CELL") else {
            return Cell {
                name: None,
                primary: true,
                flags: Vec::new(),
                unstable: true,
                pair: String::new(),
            };
        };
        let parse = || {
            let rest = name.strip_prefix("rust-")?;
            let (toolchain, rest) = rest.split_once("-tokio-")?;
            let (tokio, cfg) = rest.rsplit_once('-')?;
            let unstable = match cfg {
                "unstable" => true,
                "stable" => false,
                _ => return None,
            };
            Some((toolchain.to_owned(), tokio.to_owned(), unstable))
        };
        let Some((toolchain, tokio, unstable)) = parse() else {
            panic!(
                "HANSEI_CELL={name} is not rust-<toolchain>-tokio-<version>-{{unstable,stable}}"
            );
        };
        let m = Matrix::load();
        let primary = unstable && tokio == m.primary.tokio && toolchain == m.primary.toolchain;
        let mut flags = vec![
            "--tokio".to_owned(),
            tokio,
            "--toolchain".to_owned(),
            toolchain.clone(),
        ];
        if !unstable {
            flags.push("--no-unstable".to_owned());
        }
        let cfg = if unstable { "unstable" } else { "stable" };
        Cell {
            pair: format!("rust-{toolchain}-{cfg}"),
            name: Some(name),
            primary,
            flags,
            unstable,
        }
    })
}

/// The `spawned at` value `task` reports: the recorded location under
/// tokio_unstable instrumentation, no line at all without.
fn spawned(loc: &str) -> String {
    if cell().unstable {
        loc.to_owned()
    } else {
        String::new()
    }
}

struct Fixtures {
    /// Build A: the binaries that run (and are cored).
    bin_a: PathBuf,
    /// Build B: the same programs carrying DWARF, which the bundles
    /// below were extracted from and which `--debug-info` takes.
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
        self.bundles.join(format!("{program}.tinfo"))
    }
}

/// Build both fixture compilations and extract every program's bundle,
/// once per test-suite run.
fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let cell = cell();
        let test_programs = workspace_root().join("test-programs");
        let fixture_dir = test_programs.join("fixtures");
        // Build A's dirs: the primary cell keeps the classic ones (the
        // same capture-snapshots.sh uses); a matrix cell gets its own
        // bin dir, with target dirs shared per (toolchain, cfg) pair
        // the way regen.sh shares its cell target dirs.
        let (base, target_a) = match &cell.name {
            None => (fixture_dir.clone(), fixture_dir.join("target-a")),
            Some(name) => (
                fixture_dir.join("accept").join(name),
                fixture_dir
                    .join("accept-target")
                    .join(format!("{}-a", cell.pair)),
            ),
        };
        // Build B lands wherever regen.sh lands the cell: the everyday
        // bin dir for the primary cell, named or not, and a per-cell
        // dir for every other. Deciding this by the name alone would
        // send the named primary cell to a dir regen.sh never writes.
        let bin_b = match &cell.name {
            Some(name) if !cell.primary => fixture_dir.join("bin").join(name),
            _ => fixture_dir.join("bin"),
        };
        let bundles = base.join("integration");
        fs::create_dir_all(&bundles).expect("failed to create the bundle dir");

        // Once per run rather than once per process. Under nextest every
        // test is its own process, so without this each of them would
        // run both compilations and re-extract every bundle — while the
        // others read the bundles being written.
        //
        // The two halves stamp separately because they are built from
        // different things, which only matters to a run reusing what an
        // earlier one left behind (`testrun::REUSE`): a change to the
        // extraction side must re-extract without recompiling the
        // fixtures, and — the case that makes it necessary rather than
        // tidy — a `cargo mutants` sweep of hansei-bundle mutates what
        // the bundles are written by, so those must be rebuilt per
        // mutant while these compilations need not be.
        testrun::once_per_run(
            &base.join(".fixtures"),
            || compiled_from(cell),
            || {
                // Build A runs and is cored, so it is built the way a
                // production binary is — no debug info, as a compilation of its
                // own rather than a stripped copy of B.
                let status = Command::new(test_programs.join("regen.sh"))
                    .arg("--no-debug-info")
                    .args(&cell.flags)
                    .args(PROGRAMS)
                    .env("REGEN_BIN_DIR", base.join("bin-a"))
                    .env("REGEN_TARGET_DIR", &target_a)
                    .status()
                    .expect("failed to run regen.sh");
                assert!(
                    status.success(),
                    "regen.sh failed; is the cell's toolchain installed?"
                );
                // Build B is the standard fixture build in regen.sh's own dirs
                // — an incremental no-op on a host whose extraction goldens
                // already built this cell.
                let status = Command::new(test_programs.join("regen.sh"))
                    .args(&cell.flags)
                    .args(PROGRAMS)
                    .status()
                    .expect("failed to run regen.sh");
                assert!(
                    status.success(),
                    "regen.sh failed; is the cell's toolchain installed?"
                );
            },
        );
        testrun::once_per_run(
            &bundles.join(".bundles"),
            || extracted_from(cell),
            || {
                for program in PROGRAMS {
                    let opts = ExtractOptions {
                        extract_args: format!("acceptance-suite extraction of {program}"),
                        ..Default::default()
                    };
                    let (bundle, _stats) = extract_file(&bin_b.join(program), &opts)
                        .unwrap_or_else(|e| panic!("extraction of {program} failed: {e}"));
                    bundle
                        .save(&bundles.join(format!("{program}.tinfo")))
                        .expect("failed to write the bundle");
                }
            },
        );

        Fixtures {
            bin_a: base.join("bin-a"),
            bin_b,
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

/// The `--binary` flags an attach to `core` needs, if any.
///
/// A Linux core carries no symbol table, so hansei requires the
/// executable to be named; an illumos core carries its own and warns if
/// one is passed. Every core in this suite is of a program still sitting
/// where it was, so the path the core recorded is the right answer —
/// which is the whole reason the flag can be filled in here rather than
/// threaded through every caller.
fn binary_args(core: &Path) -> Vec<PathBuf> {
    let proc = Proc::open_core(core).expect("failed to open the core");
    match proc.needs_binary() {
        false => Vec::new(),
        true => vec![proc.exec_name().expect("the core names no executable")],
    }
}

/// Attach a session to `core` through `bundle` and ask it one command.
/// hansei reads commands from stdin, so the command is written there
/// rather than passed as an argument.
fn hansei(bundle: &Path, core: &Path, command: &str) -> Output {
    hansei_with(bundle, core, &[], command)
}

/// [`hansei`], with session flags — what shapes the attach itself, and
/// so cannot be asked for once a session is up.
fn hansei_with(bundle: &Path, core: &Path, flags: &[&str], command: &str) -> Output {
    hansei_from(("--tokio-info", bundle), core, flags, command)
}

/// [`hansei_with`], saying where the session's types come from: a
/// tokio-info file behind `--tokio-info`, or a debug build behind
/// `--debug-info` for the session to extract one from at launch.
fn hansei_from(types: (&str, &Path), core: &Path, flags: &[&str], command: &str) -> Output {
    let (types_flag, types_path) = types;
    let mut child = Command::new(env!("CARGO_BIN_EXE_hansei"))
        .arg(types_flag)
        .arg(types_path)
        .arg("--core")
        .arg(core)
        .args(flags)
        .args(
            binary_args(core)
                .iter()
                .flat_map(|p| ["--binary".as_ref(), p.as_os_str()]),
        )
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

/// Ask through `--exec` rather than stdin, one flag per element.
///
/// A command the session would refuse is written to stdin regardless,
/// so a run that succeeds is also proof that `--exec` is what was read.
fn hansei_exec(bundle: &Path, core: &Path, exec: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hansei"));
    command
        .arg("--tokio-info")
        .arg(bundle)
        .arg("--core")
        .arg(core);
    for binary in binary_args(core) {
        command.arg("--binary").arg(binary);
    }
    for commands in exec {
        command.arg("--exec").arg(commands);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run hansei");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(b"trace 99999\n")
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
    /// The group tag — which runtime or local set owns the task, as
    /// `runtimes` names it — printed only when the population holds
    /// more than one group, so empty on most fixtures.
    owner: String,
    /// How many futures the task holds in its own frames beside its
    /// await chain, `0` when it holds none.
    futures: String,
    /// How many sets it drives and how many tasks and futures they
    /// hold, `0` when it drives none.
    sets: String,
    /// The two source locations, empty when the target did not record
    /// one — `task` prints no line for a missing anchor.
    spawned: String,
    defined: String,
    /// The await site the task is suspended behind, empty when no frame
    /// on its chain is at one — a task never polled has none, and
    /// `task` prints no line for it.
    awaiting: String,
    /// The thread the task is on, `<none>` where it is on none.
    thread: String,
    /// What follows `awaiting on:` — the cell, or a verified target
    /// with its reading — empty under a bare label, and for a task
    /// waiting on nothing nameable, which gets no line either.
    waiting: String,
    /// The lines under `awaiting on`: the stop's members and the items
    /// the current await reaches.
    wait_lines: Vec<String>,
    /// The lines under `will wake`: the items an await that has
    /// returned installed, empty for a task that prints no such label.
    wake_lines: Vec<String>,
}

/// Run `task` under every task — `tasks --exec task` — and parse what
/// it prints: each task's table row as the exec heading, then a `task
/// <id>` line and one `<label>: <value>` line per field. The fields
/// `task` always prints — state, thread, type, the two census counts —
/// must be there for every task; the anchors and the wait print only
/// where the target has them, so those may come back empty.
fn list_tasks(bundle: &Path, core: &Path) -> Vec<TaskRow> {
    let out = hansei_ok(bundle, core, "tasks --exec task");

    let mut rows: Vec<TaskRow> = Vec::new();
    let mut lines = out.lines().peekable();
    while let Some(line) = lines.next() {
        if let Some(rest) = line.strip_prefix("[Executed against ") {
            let plural = if rows.len() == 1 { "" } else { "s" };
            assert_eq!(
                rest,
                format!("{} task{plural}, 0 failed]", rows.len()),
                "the exec summary disagrees with the task count"
            );
            assert!(
                lines.next().is_none(),
                "output after the exec summary: {out}"
            );
            break;
        }
        // The exec heading — the task's table row — opens each run;
        // the `task` line under it opens the fields.
        let Some(id) = line.strip_prefix("task ") else {
            continue;
        };
        assert!(!id.contains(' '), "unexpected task line {line:?}");
        let mut row = TaskRow {
            id: id.to_string(),
            state: String::new(),
            future: String::new(),
            owner: String::new(),
            futures: String::new(),
            sets: String::new(),
            spawned: String::new(),
            defined: String::new(),
            awaiting: String::new(),
            thread: String::new(),
            waiting: String::new(),
            wait_lines: Vec::new(),
            wake_lines: Vec::new(),
        };
        // Which label the detail lines are under: `awaiting on` or
        // `will wake`, the two that carry any.
        let mut under: Option<&str> = None;
        while let Some(line) = lines.peek() {
            if line.is_empty() || line.starts_with("[Executed against ") {
                break;
            }
            let line = lines.next().expect("peeked");
            // A field sits four columns in; anything deeper is detail
            // under the field above it (a member, an item, a wheel
            // entry), not a field.
            let field_line = line
                .strip_prefix("    ")
                .unwrap_or_else(|| panic!("unexpected task line {line:?}"));
            if let Some(detail) = field_line.strip_prefix("    ") {
                match under {
                    Some("awaiting on") => row.wait_lines.push(detail.to_string()),
                    Some("will wake") => row.wake_lines.push(detail.to_string()),
                    _ => panic!("detail under no wait label {line:?}"),
                }
                continue;
            }
            // A bare `awaiting on:` stands over the lines that list the
            // wait whole, and `will wake:` is only ever bare; every
            // other field carries its value.
            let (label, value) = match field_line.strip_suffix(':') {
                Some(label @ ("awaiting on" | "will wake")) => (label, ""),
                _ => field_line
                    .split_once(": ")
                    .unwrap_or_else(|| panic!("unexpected task line {line:?}")),
            };
            under = matches!(label, "awaiting on" | "will wake").then_some(label);
            let field = match label {
                "state" => &mut row.state,
                "thread" => &mut row.thread,
                "owner" => &mut row.owner,
                "type" => &mut row.future,
                "awaiting at" => &mut row.awaiting,
                "awaiting on" => &mut row.waiting,
                "spawned at" => &mut row.spawned,
                "type defined at" => &mut row.defined,
                "held futures" => &mut row.futures,
                "join sets" => &mut row.sets,
                // `will wake` carries no value of its own.
                "will wake" => {
                    assert!(row.wake_lines.is_empty(), "repeated task field {line:?}");
                    assert!(
                        !row.waiting.is_empty() || !row.wait_lines.is_empty(),
                        "will wake before awaiting on {line:?}"
                    );
                    continue;
                }
                _ => panic!("unexpected task field {line:?}"),
            };
            assert!(
                field.is_empty() && (label != "awaiting on" || row.wait_lines.is_empty()),
                "repeated task field {line:?}"
            );
            *field = value.to_string();
        }
        for (label, value) in [
            ("state", &row.state),
            ("thread", &row.thread),
            ("type", &row.future),
            ("held futures", &row.futures),
            ("join sets", &row.sets),
        ] {
            assert!(!value.is_empty(), "task {} has no {label} line", row.id);
        }
        rows.push(row);
    }
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

/// The bare `tasks` is a table: a header, one row per task, and the
/// count footer — the block form is `-v`'s. `--limit` is the only
/// truncation, and cutting the list earns the footer that counts
/// what was left out.
#[test]
fn test_tasks_lists_a_table_row_per_task() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "tasks");
        let mut lines = out.lines();
        let header = lines.next().expect("the listing has a header");
        assert!(header.starts_with("ID"), "{out}");
        for column in ["STATE", "FUT", "AWAITING AT", "WAITING ON", "TYPE"] {
            assert!(header.contains(column), "{out}");
        }
        let rest: Vec<&str> = lines.collect();
        let (footer, rows) = rest.split_last().expect("the listing has a footer");
        assert_eq!(*footer, format!("[{} task]", rows.len()), "{out}");
        assert!(rows[0].contains("async fn simple_await::work"), "{out}");

        // A limit of zero prints no table at all — a header over
        // nothing would read as data missing — and the footer carries
        // both numbers.
        let out = hansei_ok(&bundle, core, "tasks --limit 0");
        assert_eq!(out, "[1 task, 0 shown]\n", "{out}");
    });
}

/// Run the `trace` command and return its output.
fn trace(bundle: &Path, core: &Path, task_id: &str, verbose: bool) -> String {
    trace_opts(bundle, core, task_id, verbose, false)
}

/// Like [`trace`], but under `config ugly on` (the raw structural view,
/// with every type's custom formatter suppressed).
fn trace_opts(bundle: &Path, core: &Path, task_id: &str, verbose: bool, ugly: bool) -> String {
    let mut command = format!("trace {task_id}");
    if verbose {
        command.push_str(" --verbose");
    }
    if ugly {
        command = format!("config ugly on; {command}");
    }
    hansei_ok(bundle, core, &command)
}

/// Mask the run-varying values a trace can carry — heap addresses and
/// timer deadlines — so goldens compare exactly.
/// Mask what a live target varies between runs: addresses, and a timer
/// deadline.
///
/// A deadline is masked whole, trailing clock clause included, because
/// which of its two spellings appears is a property of the system the
/// suite is running on rather than of hansei: a deadline is reported
/// relative to the moment the target stopped where the lwps stamp one
/// (illumos) and as an absolute point on the monotonic clock where they
/// do not (a Linux core). Both spellings are pinned deterministically by
/// `hansei-runtime`' `test_timer_deadline_spellings`.
///
/// An await site inside tokio's own sources is masked down to its file
/// (`tokio/src/sync/mutex.rs:LINE`): the version in the path and the
/// line number are the cell's tokio, not hansei's output, and one
/// golden serves every cell. The fixture's own `src/bin/…` sites stay
/// exact — those the golden owns.
///
/// The instrumentation leaf's type is masked the same way: tokio 1.50
/// rewrote `async_trace_leaf` from a hand-written `Trace` future into
/// an async fn, so which spelling a chain's leaf local carries is the
/// cell's tokio version.
fn normalize(trace: &str) -> String {
    let addrs = regex::Regex::new(r"0x[0-9a-f]+").unwrap();
    mask(&addrs.replace_all(trace, "0xADDR"))
}

/// The half of [`normalize`] that stands for no identity, so nothing is
/// lost by spelling every occurrence alike: a deadline, a source line
/// inside tokio's own tree, the leaf type an instrumented trace ends on.
fn mask(out: &str) -> String {
    let deadlines =
        regex::Regex::new(r"deadline \+?\d+\.\d{3}s( on the target's monotonic clock)?").unwrap();
    let overdue = regex::Regex::new(r"overdue by \d+\.\d{3}s").unwrap();
    let tokio_sites = regex::Regex::new(r"tokio-\d+\.\d+\.\d+(/[^ :]+):\d+").unwrap();
    let trace_leaf =
        regex::Regex::new(r"(async fn |future )?tokio::trace::async_trace_leaf(::\S+)?").unwrap();
    // A waker slot in memory no type reaches is admitted only where
    // the target carries no allocator index (a Linux core); an index
    // classifies the same bytes, and drops the stale ones. Whether the
    // line exists is the target's call, so it is not pinned.
    let unknown_slot =
        regex::Regex::new(r"(?m)^\s*unknown (0x[0-9a-f]+|ADDR\d+): [^\n]*\n").unwrap();
    let masked = deadlines.replace_all(out, "deadline TS");
    let masked = overdue.replace_all(&masked, "overdue by TS");
    let masked = tokio_sites.replace_all(&masked, "tokio$1:LINE");
    let masked = unknown_slot.replace_all(&masked, "");
    trace_leaf
        .replace_all(&masked, "tokio::trace::async_trace_leaf::TY")
        .into_owned()
}

/// The run-varying values in a command's output, and the stable names
/// they take in a golden.
///
/// [`normalize`] spells every address `0xADDR` and leaves task ids
/// alone, which is why a test that wants to hold output whole has to
/// rebuild it around the ids the run handed out. That masking also
/// costs the agreement between two values, and the agreement is what a
/// graph is read for: that the wake queue names the blocked task is the
/// futurelock diagnosis. So each distinct value takes a distinct symbol
/// here instead. A task the test named carries that name (`#joiner`);
/// anything else is numbered in the order it is first seen (`#t1`,
/// `ADDR1`), which a fixture parked deterministically hands out the
/// same way every run.
///
/// What this buys over `format!`-ing the expectation around the run's
/// own ids is a golden that holds for every cell: a task id is a small
/// decimal under `tokio_unstable` and the Header address where the
/// target records none, and neither reaches the golden.
#[derive(Default)]
struct Symbols {
    named: Vec<(String, String)>,
    columns: bool,
}

impl Symbols {
    fn new() -> Self {
        Self::default()
    }

    /// Give the task with id `id` the name it carries in the golden.
    fn task(mut self, id: &str, name: &str) -> Self {
        self.named.push((id.to_owned(), format!("#{name}")));
        self
    }

    /// Re-flow a fixed-width table by its header row — what `runtimes`
    /// prints — around the symbols replacing its addresses.
    fn columns(mut self) -> Self {
        self.columns = true;
        self
    }

    /// Number the lwps in first-seen order.
    ///
    /// Distinct symbols rather than one masking: whether the thread a
    /// runtime runs on is the thread its local set is pinned to is
    /// something the page reports, and `foreign-runtime` is a fixture
    /// where it is not.
    fn lwps(&self, out: &str) -> String {
        let lwp = regex::Regex::new(r"\blwp (?<id>\d+)\b").unwrap();
        let mut seen: Vec<String> = Vec::new();
        lwp.replace_all(out, |caps: &regex::Captures<'_>| {
            let id = caps["id"].to_owned();
            let at = seen.iter().position(|s| *s == id).unwrap_or_else(|| {
                seen.push(id);
                seen.len() - 1
            });
            format!("lwp L{}", at + 1)
        })
        .into_owned()
    }

    /// Rewrite `out` into the form a golden holds.
    ///
    /// One `seen` serves both passes: the table and the prose under it
    /// name the same tasks, and a symbol minted once per pass would let
    /// a golden claim an agreement between them the run never had.
    fn apply(&self, out: &str) -> String {
        let mut seen = Vec::new();
        let out = drop_spawn_line(out);
        // Before any substitution, while the padding is still the one
        // hansei laid down and so still says where the columns are.
        let out = match self.columns {
            true => split_columns(&out),
            false => out,
        };
        let out = self.addresses(&out);
        let out = self.lwps(&out);
        let out = mask(&out);
        let out = self.table(&mut seen, &out);
        let out = self.references(&mut seen, &out);
        match self.columns {
            true => rejoin_columns(&out),
            false => out,
        }
    }

    /// The symbol for a task id: the name it was given, or the next
    /// number, minted on first sight.
    fn task_symbol(&self, seen: &mut Vec<(String, String)>, id: &str) -> String {
        if let Some((_, sym)) = self.named.iter().find(|(known, _)| known == id) {
            return sym.clone();
        }
        if let Some((_, sym)) = seen.iter().find(|(known, _)| known == id) {
            return sym.clone();
        }
        let sym = format!("#t{}", seen.len() + 1);
        seen.push((id.to_owned(), sym.clone()));
        sym
    }

    /// Number the addresses in first-seen order, so two mentions of one
    /// address stay one symbol and two addresses stay two.
    fn addresses(&self, out: &str) -> String {
        let hex = regex::Regex::new(r"0x[0-9a-f]+").unwrap();
        let mut seen: Vec<String> = Vec::new();
        hex.replace_all(out, |caps: &regex::Captures<'_>| {
            let addr = caps[0].to_owned();
            let at = seen.iter().position(|a| *a == addr).unwrap_or_else(|| {
                seen.push(addr);
                seen.len() - 1
            });
            format!("ADDR{}", at + 1)
        })
        .into_owned()
    }

    /// Rewrite the ids in the graph table's first column, and re-flow
    /// the columns around them.
    ///
    /// hansei pads TASK and STATE to their widest cell, so the table's
    /// whitespace records how wide a task id happened to be — one digit
    /// under `tokio_unstable`, a whole address without it — and a
    /// golden that kept it would need a copy per cell. The columns are
    /// recomputed here instead. What hansei's own padding does is not
    /// left uncovered by that: the unit tests in `hansei/src/graph.rs`
    /// pin it over constructed ids, portably and without a core.
    fn table(&self, seen: &mut Vec<(String, String)>, out: &str) -> String {
        let lines: Vec<&str> = out.lines().collect();
        let Some(head) = lines.iter().position(|l| l.starts_with("TASK")) else {
            return out.to_owned();
        };
        // The header is padded to the same widths as every row and
        // holds no wide characters, so where its labels start is where
        // every row's columns start.
        let column = |needle: &str| {
            lines[head]
                .find(needle)
                .map(|byte| lines[head][..byte].chars().count())
        };
        let (Some(state), Some(target)) = (column("STATE"), column("WAITING ON")) else {
            return out.to_owned();
        };
        let end = lines[head..]
            .iter()
            .position(|l| l.trim().is_empty())
            .map_or(lines.len(), |n| head + n);

        // Columns are sliced by character, not byte: a nested row's
        // branch is drawn with box-drawing characters, as the table
        // itself counts.
        let cell = |line: &[char], from: usize, to: usize| -> String {
            let to = to.min(line.len());
            match from >= to {
                true => String::new(),
                false => line[from..to]
                    .iter()
                    .collect::<String>()
                    .trim_end()
                    .to_owned(),
            }
        };

        let mut rows: Vec<[String; 3]> = Vec::new();
        for line in &lines[head..end] {
            let chars: Vec<char> = line.chars().collect();
            let task = cell(&chars, 0, state);
            rows.push([
                self.row_task(seen, &task),
                cell(&chars, state, target),
                cell(&chars, target, chars.len()),
            ]);
        }

        let mut widths = [0usize; 2];
        for row in &rows {
            for (w, cell) in widths.iter_mut().zip(row) {
                *w = (*w).max(cell.chars().count());
            }
        }
        let mut table = String::new();
        for line in &lines[..head] {
            table.push_str(line);
            table.push('\n');
        }
        for [task, state, target] in &rows {
            table.push_str(&format!(
                "{task:<w0$}  {state:<w1$}  {target}\n",
                w0 = widths[0],
                w1 = widths[1]
            ));
        }
        for line in &lines[end..] {
            table.push_str(line);
            table.push('\n');
        }
        table
    }

    /// A TASK cell: the id, under whatever branch draws it and beside
    /// whatever the row says about it.
    fn row_task(&self, seen: &mut Vec<(String, String)>, cell: &str) -> String {
        let row = regex::Regex::new(r"^(?<pre>[├└]─ )?(?<id>[^ ]+)(?<post>.*)$").unwrap();
        let Some(caps) = row.captures(cell) else {
            return cell.to_owned();
        };
        if &caps["id"] == "TASK" {
            return cell.to_owned();
        }
        format!(
            "{}{}{}",
            caps.name("pre").map_or("", |m| m.as_str()),
            self.task_symbol(seen, &caps["id"]),
            caps.name("post").map_or("", |m| m.as_str()),
        )
    }

    /// Every other mention of a task: the header a trace opens with,
    /// and the `task <id>` prose names one by anywhere else.
    ///
    /// Matched in those positions rather than by the digits alone: a
    /// task id is only a number, and a run whose blocked task is task
    /// 64 must not rewrite `futurelock.rs:64` along with it.
    fn references(&self, seen: &mut Vec<(String, String)>, out: &str) -> String {
        let reference = regex::Regex::new(r"\b(?<word>[Tt]ask) (?<id>\d+)\b").unwrap();
        reference
            .replace_all(out, |caps: &regex::Captures<'_>| {
                let symbol = self.task_symbol(seen, &caps["id"]);
                format!("{} {symbol}", &caps["word"])
            })
            .into_owned()
    }
}

/// The character standing in for a column boundary between
/// [`split_columns`] and [`rejoin_columns`], so the substitutions in
/// between see ordinary text.
const COLUMN: char = '\u{1}';

/// Mark the column boundaries of a fixed-width table by its header
/// row's label offsets.
///
/// The header is padded to the same widths as every row and holds no
/// wide characters, so where its labels start — the first character
/// after a two-space run — is where every row's columns start. This is
/// how `runtimes` is re-flowed; the graph table has its own pass in
/// [`Symbols::table`], whose first column needs symbol substitution.
fn split_columns(out: &str) -> String {
    let lines: Vec<&str> = out.lines().collect();
    let Some(header) = lines.first() else {
        return out.to_owned();
    };
    let mut cuts: Vec<usize> = Vec::new();
    let mut spaces = 2;
    for (i, c) in header.chars().enumerate() {
        if c == ' ' {
            spaces += 1;
            continue;
        }
        if spaces >= 2 {
            cuts.push(i);
        }
        spaces = 0;
    }

    let mut text = String::new();
    for line in &lines {
        // The bracketed footer under a listing is not a row: it counts
        // the rows, and passes through whole.
        if line.starts_with('[') {
            text.push_str(line);
            text.push('\n');
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        for (at, &from) in cuts.iter().enumerate() {
            if at > 0 {
                text.push(COLUMN);
            }
            let to = cuts.get(at + 1).copied().unwrap_or(chars.len());
            let cell: String = chars[from.min(chars.len())..to.min(chars.len())]
                .iter()
                .collect();
            text.push_str(cell.trim_end());
        }
        text.push('\n');
    }
    text
}

/// Pad the marked columns to their widest cell again, now that what
/// they hold is symbols rather than the run's own addresses.
fn rejoin_columns(out: &str) -> String {
    let rows: Vec<Vec<&str>> = out
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split(COLUMN).collect())
        .collect();
    // The bracketed footer is not a row and sets no column's width.
    let is_footer = |row: &Vec<&str>| row.len() == 1 && row[0].starts_with('[');
    let mut widths = vec![0usize; rows.iter().map(Vec::len).max().unwrap_or(0)];
    for row in rows.iter().filter(|row| !is_footer(row)) {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut text = String::new();
    for row in &rows {
        let last = row.len() - 1;
        for (at, cell) in row.iter().enumerate() {
            text.push_str(cell);
            if at != last {
                let pad = widths[at] - cell.chars().count();
                text.extend(std::iter::repeat_n(' ', pad + 2));
            }
        }
        text.push('\n');
    }
    text
}

/// Drop the `Spawned at` line, wherever a command prints one. See
/// [`spawn_line`] for why a golden does not hold it.
fn drop_spawn_line(out: &str) -> String {
    out.lines()
        .filter(|line| {
            !line.starts_with("Spawned at: ") && !line.trim_start().starts_with("spawned at: ")
        })
        .fold(String::new(), |mut text, line| {
            text.push_str(line);
            text.push('\n');
            text
        })
}

/// The `task` selection's `spawned at` line, which a target carries
/// only under `tokio_unstable` instrumentation.
///
/// Held out of a golden rather than in it: whether the line is there at
/// all is the cell's, not hansei's, and one golden serves every cell.
/// What it says where it is there is [`assert_spawned_at`]'s to check.
fn spawn_line(loc: &str) -> Option<String> {
    cell().unstable.then(|| format!("spawned at: {loc}"))
}

/// Assert a `task` selection records `loc` as the spawn site — or
/// records no site at all, on a cell whose target could not.
fn assert_spawned_at(trace: &str, loc: &str) {
    let line = trace
        .lines()
        .map(str::trim_start)
        .find(|line| line.starts_with("spawned at: "))
        .map(str::to_owned);
    assert_eq!(line, spawn_line(loc), "in:\n{trace}");
}

/// Compare `actual` against the checked-in golden of that name, under
/// `hansei/tests/golden/`.
///
/// Re-bless with `INSTA_UPDATE=always`, which writes the goldens in
/// place under a plain `cargo test` — as every golden in the tree is
/// blessed, and the only shape that serves this suite: it runs nowhere
/// but the hosts that can core a process, so a golden is always blessed
/// over ssh and reviewed here afterwards. A plain run
/// leaves a rejected golden beside its file as `.snap.new` instead of
/// overwriting it.
///
/// File snapshots rather than inline ones for the same reason: applying
/// an inline snapshot rewrites the source, and needs the `cargo-insta`
/// binary on every host to do it.
fn golden(name: &str, actual: &str) {
    insta::with_settings!({
        snapshot_path => "golden",
        prepend_module_to_snapshot => false,
    }, {
        insta::assert_snapshot!(name, actual);
    });
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

/// `info` against a real core: the process identity out of the core's
/// own notes, a live capture's signal answer, and the counts the
/// listings go and look at.
#[test]
fn test_info_acceptance() {
    let program = "simple-await";
    let bundle = fixtures().bundle(program);
    with_core(program, |core| {
        let process = hansei_ok(&bundle, core, "info");
        assert!(process.contains("pid:"), "{process}");
        assert!(process.contains("ppid:"), "{process}");
        assert!(process.contains("psargs:"), "{process}");
        if cfg!(target_os = "linux") {
            assert!(
                process.contains("argv: not recorded in a Linux core"),
                "{process}"
            );
            assert!(
                process.contains("environment: not recorded in a Linux core"),
                "{process}"
            );
        } else {
            // An illumos psinfo records the model and start time, and
            // its argv/envp pointers resolve in the dump.
            assert!(process.contains("model:  LP64"), "{process}");
            assert!(process.contains("start:  "), "{process}");
            assert!(process.contains("argv:"), "{process}");
            assert!(process.contains("environment:"), "{process}");
        }

        // gcore stops the process rather than crashing it, so no
        // signal is recorded.
        assert!(process.contains("signal: none recorded"), "{process}");

        // What was attached.
        assert!(process.contains("symbols resolved: "), "{process}");
    });
}

/// A session opens on a debug build directly, extracting at launch,
/// and answers exactly what the tokio-info file extracted from that
/// same build answers — but for the one line that says which way in it
/// was.
///
/// The equivalence is the point: `--debug-info` is meant to save the
/// operator a file, not to be a second, lesser way of reading a target.
#[test]
fn test_a_session_can_extract_from_debug_info() {
    let program = "simple-await";
    let bundle = fixtures().bundle(program);
    let debug_binary = fixtures().debug_binary(program);
    // Enough of the session to exercise the whole attach: the summary,
    // the task listing and the census's finds, and the wait graph.
    let command = "info\ntasks --exec children\ngraph\n";
    with_core(program, |core| {
        let from_bundle = hansei_ok(&bundle, core, command);
        let out = hansei_from(("--debug-info", &debug_binary), core, &[], command);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "extracting session failed:\n{stderr}\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(stderr.is_empty(), "extracting session warned:\n{stderr}");
        let from_binary = String::from_utf8(out.stdout).expect("hansei output is UTF-8");

        assert!(
            from_binary.contains(&format!(
                "tokio info: extracted from {}",
                debug_binary.display()
            )),
            "the summary should name what it extracted from:\n{from_binary}"
        );
        assert!(
            from_bundle.contains(&format!("tokio info: {}", bundle.display())),
            "the summary should name the tokio-info file it read:\n{from_bundle}"
        );
        let strip_source = |out: &str| {
            out.lines()
                .map(|line| match line.starts_with("tokio info: ") {
                    true => "tokio info: <source>",
                    false => line,
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip_source(&from_binary), strip_source(&from_bundle));
    });
}

/// `save-tokio-info` persists what a `--debug-info` session extracted
/// at launch: the file it writes opens a later session that answers
/// exactly what the extracting one did. A session that read a
/// tokio-info file refuses — the file it would save already exists.
#[test]
fn test_save_tokio_info_persists_the_extraction() {
    let program = "simple-await";
    let bundle = fixtures().bundle(program);
    let debug_binary = fixtures().debug_binary(program);
    let command = "info\ntasks --exec children\n";
    with_core(program, |core| {
        let dir = tempfile::tempdir().expect("failed to create a tempdir");
        let saved = dir.path().join("saved.tinfo");
        let save = format!("save-tokio-info {}\n", saved.display());

        let out = hansei_from(
            ("--debug-info", &debug_binary),
            core,
            &[],
            &format!("{command}{save}"),
        );
        assert!(
            out.status.success(),
            "saving session failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        let extracting = String::from_utf8(out.stdout).expect("hansei output is UTF-8");
        assert!(
            extracting.contains(&format!("wrote {}", saved.display())),
            "the save should say where it wrote:\n{extracting}"
        );

        // The saved file answers as the extracting session did, but
        // for the summary line that says which way in it was.
        let from_saved = hansei_ok(&saved, core, command);
        let strip = |out: &str| {
            out.lines()
                .filter(|line| !line.starts_with("wrote "))
                .map(|line| match line.starts_with("tokio info: ") {
                    true => "tokio info: <source>",
                    false => line,
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip(&from_saved), strip(&extracting));

        let out = hansei(&bundle, core, &save);
        assert!(
            !out.status.success(),
            "a --tokio-info session accepted save-tokio-info"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("nothing to save"), "{stderr}");
    });
}

// ---------------------------------------------------------------------------
// Acceptance tests: exact await-chain goldens
// ---------------------------------------------------------------------------

/// One spawned async fn parked on a leaked oneshot: the baseline listing
/// and two-frame chain.
#[test]
fn test_simple_await_acceptance() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 1, "{rows:#?}");
        let task = task_with_future(&rows, "async fn simple_await::work");
        assert_eq!(task.state, "idle");
        assert_eq!(task.spawned, spawned("src/bin/simple-await.rs:89:21"));
        assert_eq!(task.defined, "src/bin/simple-await.rs:21");

        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", task.id)),
            "src/bin/simple-await.rs:89:21",
        );
        golden(
            "simple-await-trace",
            &Symbols::new().task(&task.id, "work").apply(&out),
        );

        // Exactly these, against a bundle extracted a moment ago: the
        // extractor drops what rustc lists in a state that is not that
        // state's own, and whether it dropped the right things is a
        // question about `simple-await.rs` that only the source
        // answers. Every name here is bound between lines 23 and 48
        // and read again at 52..67, so each has to survive both awaits;
        // `first` is bound *by* the line-49 await. The arguments
        // `ready` and `park` are gone by line 51 — one consumed by
        // `send()`, the other moved into the awaitee — and the offsets
        // they left behind are not this state's to report.
        //
        // Asserted in full rather than by presence, because the way
        // this breaks under a new toolchain is a live local quietly
        // going missing, which no count in `--stats` would show.
        let verbose = trace(&bundle, core, &task.id, true);
        assert_eq!(
            locals_listed(&verbose),
            [
                "count",
                "labels",
                "values",
                "boxed",
                "slice",
                "ipv4",
                "ipv6",
                "borrowed",
                "owned",
                "c_owned",
                "c_borrowed",
                "glyph",
                "ports",
                "seen",
                "first"
            ],
            "in:\n{verbose}"
        );
    });
}

/// The names under a verbose trace's first `locals:`, in the order the
/// state lists them. Entries sit one indent in; anything deeper is the
/// value of the entry above it.
fn locals_listed(verbose_trace: &str) -> Vec<&str> {
    let indent = |line: &str| line.len() - line.trim_start().len();
    let mut lines = verbose_trace
        .lines()
        .skip_while(|line| line.trim() != "locals:");
    let depth = match lines.next() {
        Some(header) => indent(header),
        None => panic!("no locals in:\n{verbose_trace}"),
    };

    let mut names = Vec::new();
    let mut entries = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if indent(line) <= depth {
            break;
        }
        if indent(line) == *entries.get_or_insert(indent(line)) {
            names.push(line.trim_start().split(':').next().unwrap_or_default());
        }
    }
    names
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
        let task = task_with_future(&rows, "async fn simple_await::work");
        let verbose = trace(&bundle, core, &task.id, true);

        // Scalars, including one the task computed after its first
        // await rather than one it was handed.
        assert!(verbose.contains("count: u32 = 3"), "{verbose}");
        assert!(verbose.contains("first: u32 = 41"), "{verbose}");

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

/// `config ugly on` suppresses every type's custom formatter and falls back to the
/// raw structural view. The simple-await task keeps a spread of
/// custom-formatted locals live across its park — an IP address, a borrowed
/// `&str`, an owned `String` — each of which reads as its decoded value
/// normally and as its underlying representation under `config ugly on`.
#[test]
fn test_ugly_locals_acceptance() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async fn simple_await::work");
        // Normal verbose rendering: each local reads as its decoded value,
        // through its own formatter.
        let pretty = trace_opts(&bundle, core, &task.id, true, false);
        assert!(
            pretty.contains("ipv4: core::net::ip_addr::Ipv4Addr = 192.0.2.1"),
            "{pretty}"
        );
        assert!(
            pretty.contains(r#"borrowed: &str = "borrowed\ntext""#),
            "{pretty}"
        );
        assert!(
            pretty.contains(r#"owned: alloc::string::String = "owned\ttext""#),
            "{pretty}"
        );
        // The char is the code point, not its low byte (`-`).
        assert!(pretty.contains("glyph: char = '中'"), "{pretty}");

        // The raw view: the very same locals render through their structure, and the
        // formatted forms are gone entirely.
        let ugly = trace_opts(&bundle, core, &task.id, true, true);
        assert!(
            !ugly.contains("192.0.2.1"),
            "the raw view still formatted the IP:\n{ugly}"
        );
        assert!(
            !ugly.contains(r#""borrowed\ntext""#),
            "the raw view still formatted the &str:\n{ugly}"
        );
        assert!(
            ugly.contains("core::net::ip_addr::Ipv4Addr {"),
            "the raw-view IP is not structural:\n{ugly}"
        );
        assert!(
            ugly.contains("&str {") && ugly.contains("length: 13"),
            "the raw-view &str is not structural:\n{ugly}"
        );
        assert!(
            ugly.contains("alloc::string::String {"),
            "the raw-view String is not structural:\n{ugly}"
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
        let task = task_with_future(&rows, "async fn nested_await::outer");
        assert_eq!(task.state, "idle");
        assert_eq!(task.spawned, spawned("src/bin/nested-await.rs:37:21"));
        assert_eq!(task.defined, "src/bin/nested-await.rs:20");

        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", task.id)),
            "src/bin/nested-await.rs:37:21",
        );
        golden(
            "nested-await-trace",
            &Symbols::new().task(&task.id, "outer").apply(&out),
        );
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
        assert_eq!(rows.len(), 3, "{rows:#?}");

        let driver = task_with_future(&rows, "async fn dyn_future::driver");
        assert_eq!(driver.state, "idle");
        assert_eq!(driver.spawned, spawned("src/bin/dyn-future.rs:57:21"));
        assert_eq!(driver.defined, "src/bin/dyn-future.rs:24");
        let out = trace(&bundle, core, &driver.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", driver.id)),
            "src/bin/dyn-future.rs:57:21",
        );
        golden(
            "dyn-future-driver-trace",
            &Symbols::new().task(&driver.id, "driver").apply(&out),
        );

        let member = task_with_future(&rows, "async fn dyn_future::set_member");
        assert_eq!(member.state, "idle");
        assert_eq!(member.spawned, spawned("src/bin/dyn-future.rs:32:9"));
        assert_eq!(member.defined, "src/bin/dyn-future.rs:19");
        let out = trace(&bundle, core, &member.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", member.id)),
            "src/bin/dyn-future.rs:32:9",
        );
        golden(
            "dyn-future-member-trace",
            &Symbols::new().task(&member.id, "member").apply(&out),
        );

        // The holder's `Arc<dyn Aligned>` erases a 64-aligned value, which
        // std places at the first 64-byte boundary past the `ArcInner`
        // refcounts, not right after them: the render has to round the
        // header by the vtable's align word to read `7` rather than
        // padding. Frame #0 is the oneshot the holder awaits; #1 is the
        // async fn whose local it is.
        let holder = task_with_future(&rows, "async fn dyn_future::hold_aligned");
        let printed = hansei_ok(
            &bundle,
            core,
            &format!("task {}; frame 1; print aligned", holder.id),
        );
        assert!(
            printed.contains("concrete type: dyn_future::Padded"),
            "{printed}"
        );
        assert!(printed.contains("value: 7"), "{printed}");
        assert!(printed.contains("align: 64"), "{printed}");
    });
}

/// The RFD 609 futurelock acceptance test: the surviving
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
        let task = task_with_future(&rows, "async block futurelock::main::{async_block#0}");
        assert_eq!(task.state, "idle");
        assert_eq!(task.spawned, spawned("src/bin/futurelock.rs:20:17"));
        assert_eq!(task.defined, "src/bin/futurelock.rs:20");

        // The chain the diagnosis is built on, six frames from the
        // async block down to the semaphore. The wake queue at the
        // bottom names #blocked, which the header at the top is: the
        // task is waiting for a lock it holds itself, spelled once
        // rather than masked into two anonymous ids.
        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", task.id)),
            "src/bin/futurelock.rs:20:17",
        );
        golden(
            "futurelock-trace",
            &Symbols::new().task(&task.id, "blocked").apply(&out),
        );

        // The boxed, never-again-polled future1 is still held across
        // do_stuff's suspension — the futurelock signature.
        let verbose = trace(&bundle, core, &task.id, true);
        assert_locals(&verbose, &["lock", "future1", "disabled", "label"]);

        // The contended Mutex renders its wait queue among the locals, and
        // the parked waiter's waker resolves to the task it would wake —
        // this task itself, the futurelock shape in the value dump. A depth
        // generous enough to reach the waiter row is asked for explicitly.
        let deep = hansei_ok(
            &bundle,
            core,
            &format!("config depth 12; trace {} --verbose", task.id),
        );
        assert!(
            deep.contains(&format!(
                "waker: core::option::Option<core::task::wake::Waker> = Some(task {})",
                task.id
            )),
            "{deep}"
        );
    });
}

/// `print` renders a local of the cursor frame: the semaphore the
/// trace names, reached as the `semaphore` local of the task's leaf
/// frame, decodes through its own formatter to the same contended
/// state the wait line reported — one permit outstanding, none
/// available, not closed.
#[test]
fn test_print_renders_a_local_through_its_formatter() {
    let bundle = fixtures().bundle("futurelock");
    with_core("futurelock", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async block futurelock::main::{async_block#0}");
        let out = trace(&bundle, core, &task.id, false);
        assert!(out.contains("semaphore 0x"), "{out}");

        // The name, through the semaphore's own formatter: the permit
        // word decodes in place.
        let printed = hansei_ok(&bundle, core, &format!("task {}; print semaphore", task.id));
        assert!(
            printed.contains("tokio::sync::batch_semaphore::Semaphore"),
            "{printed}"
        );
        assert!(printed.contains("closed=false"), "{printed}");
        assert!(printed.contains("permits=0"), "{printed}");

        // `config ugly on` falls back to the raw structural view: the
        // decoded permit word is gone and the underlying members show
        // as themselves.
        let ugly = hansei_ok(
            &bundle,
            core,
            &format!("config ugly on; task {}; print semaphore", task.id),
        );
        assert!(!ugly.contains("closed=false"), "{ugly}");
        assert!(ugly.contains("permits"), "{ugly}");

        // An address is not a local: the refusal points at `whatis`.
        let addr = regex::Regex::new(r"semaphore (0x[0-9a-f]+)")
            .unwrap()
            .captures(&out)
            .unwrap_or_else(|| panic!("no semaphore address in {out}"))[1]
            .to_string();
        let refused = hansei(&bundle, core, &format!("task {}; print {addr}", task.id));
        assert!(!refused.status.success());
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(stderr.contains("whatis"), "{stderr}");
    });
}

/// Enums whose tag constants DWARF spells narrower than the tag: a
/// `-1` on a `#[repr(i32)]` enum arrives as one `0xff` byte and has
/// to select on the tag's `0xffff_ffff`. Rendered from the core, each
/// held value names its variant; a constant left at the form's width
/// matches nothing, and the enum falls back to its name over raw
/// bytes instead.
#[test]
fn test_enum_reprs_acceptance() {
    let bundle = fixtures().bundle("enum-reprs");
    with_core("enum-reprs", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async fn enum_reprs::hold");
        let verbose = trace(&bundle, core, &task.id, true);
        for local in [
            "signed32: enum_reprs::Signed32 = Below(1)",
            "signed64: enum_reprs::Signed64 = Below(2)",
            "unsigned32: enum_reprs::Unsigned32 = Byte(3)",
            "level: enum_reprs::Level = Below",
        ] {
            assert!(verbose.contains(local), "{local} missing from {verbose}");
        }
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
            assert_eq!(row.future, "async fn many_tasks::park_task");
            assert_eq!(row.spawned, spawned("src/bin/many-tasks.rs:31:13"));
            assert_eq!(row.defined, "src/bin/many-tasks.rs:13");
        }
        let ids: HashSet<&str> = rows.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(ids.len(), rows.len(), "task ids are unique");

        // Whichever of the thirty-two is listed first: they are spawned
        // from one line of one async fn, so the chain a golden holds is
        // every task's, and the id that would have told them apart is
        // the one thing symbolized out of it.
        let task = &rows[0];
        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", task.id)),
            "src/bin/many-tasks.rs:31:13",
        );
        golden(
            "many-tasks-trace",
            &Symbols::new().task(&task.id, "park").apply(&out),
        );
    });
}

/// The leaf-future knowledge base: a task parked on the timer
/// reports its deadline, and a task awaiting a JoinHandle reports which
/// task it waits for — the dependency edge, joined across the two
/// binaries by nothing but the leaf's type name.
#[test]
fn test_sleep_join_acceptance() {
    let bundle = fixtures().bundle("sleep-join");
    with_core("sleep-join", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 2, "{rows:#?}");
        let sleeper = task_with_future(&rows, "async fn sleep_join::sleeper");
        let joiner = task_with_future(&rows, "async fn sleep_join::joiner");
        assert_eq!(sleeper.state, "idle");
        assert_eq!(joiner.state, "idle");

        // Both traces name both tasks, so both symbols are given to
        // both: the joiner's leaf names the sleeper, and that the id it
        // names is the sleeper's own row is the dependency edge.
        let symbols = || {
            Symbols::new()
                .task(&sleeper.id, "sleeper")
                .task(&joiner.id, "joiner")
        };

        let out = trace(&bundle, core, &sleeper.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", sleeper.id)),
            "src/bin/sleep-join.rs:34:22",
        );
        golden("sleep-join-sleeper-trace", &symbols().apply(&out));

        let out = trace(&bundle, core, &joiner.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", joiner.id)),
            "src/bin/sleep-join.rs:35:23",
        );
        golden("sleep-join-joiner-trace", &symbols().apply(&out));
    });
}

/// A current_thread runtime: discovery crosses the `CurrentThread`
/// variant and everything downstream — listing, tracing, the timer and
/// semaphore leaf readers — runs unchanged. Only the two spawned tasks
/// are listed: the `block_on` root future lives on the caller's stack,
/// not in `OwnedTasks`, the same as on multi_thread.
#[test]
fn test_ct_runtime_acceptance() {
    let bundle = fixtures().bundle("ct-runtime");
    with_core("ct-runtime", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 2, "{rows:#?}");
        let sleeper = task_with_future(&rows, "async fn ct_runtime::sleeper");
        let acquirer = task_with_future(&rows, "async fn ct_runtime::acquirer");
        assert_eq!(sleeper.state, "idle");
        assert_eq!(acquirer.state, "idle");

        let out = trace(&bundle, core, &sleeper.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", sleeper.id)),
            "src/bin/ct-runtime.rs:37:24",
        );
        golden(
            "ct-runtime-sleeper-trace",
            &Symbols::new().task(&sleeper.id, "sleeper").apply(&out),
        );

        // The acquirer bottoms out in the semaphore leaf; the frames
        // between are tokio's own and shift with the cell's version.
        let out = normalize(&trace(&bundle, core, &acquirer.id, false));
        assert!(
            out.contains("tokio::sync::batch_semaphore::Acquire"),
            "{out}"
        );
        assert!(
            out.contains(
                "waiting on a tokio::sync::Semaphore (semaphore 0xADDR): \
                 1 permit requested, 0 available"
            ),
            "{out}"
        );

        // The block_on thread is the CT scheduler's one worker: the
        // threads listing names it as such, with what it is doing read
        // from where its core and driver are rather than from the
        // parker array it does not have.
        let out = hansei_ok(&bundle, core, "threads --exec thread");
        assert!(
            out.contains("block_on thread of its current_thread runtime"),
            "{out}"
        );
        assert!(!out.contains("not in the scheduler's run loop"), "{out}");

        // And the census's thread section classifies it the same way.
        let out = hansei_ok(&bundle, core, "census --threads");
        assert!(out.contains("  block_on thread  in driver"), "{out}");
    });
}

#[test]
fn test_delegation_cases_acceptance() {
    let bundle = fixtures().bundle("delegation-cases");
    with_core("delegation-cases", |core| {
        let binary = fixtures().program("delegation-cases");
        let proc = Proc::open_core_with_binary(
            core,
            cfg!(target_os = "linux").then_some(binary.as_path()),
        )
        .unwrap();
        let cases = hansei_runtime::testkit::delegation::read_from(&proc)
            .expect("registry symbol")
            .unwrap();
        assert_eq!(cases.len(), 12);
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 12, "{rows:#?}");
        assert!(rows.iter().all(|row| row.state == "idle"), "{rows:#?}");
    });
}

/// A `LocalSet` on a current_thread runtime: its two tasks live in the
/// set's own list, which the ordinary spawned task's JoinHandle edge
/// bootstraps — the whole set from one member. They merge into the flat
/// listing tagged with the set (and the lwp it is pinned to, joined
/// through the runtime context's thread id), the joined local task is
/// simply listed with no unlisted caveat, and `info` names the set with
/// the route that found it. The TLS route finds nothing here on
/// purpose: a parked core reads the `CURRENT` anchor empty.
#[test]
fn test_local_set_acceptance() {
    let bundle = fixtures().bundle("local-set");
    with_core("local-set", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 3, "{rows:#?}");
        let joiner = task_with_future(&rows, "async fn local_set::joiner");
        let sleeper = task_with_future(&rows, "async fn local_set::local_sleeper");
        let acquirer = task_with_future(&rows, "async fn local_set::local_acquirer");

        // Groups: the scheduler task carries the runtime's tag, the two
        // local tasks the set's, with the owner lwp joined on.
        let rt_tag = regex::Regex::new(r"^runtime 0 @ 0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&joiner.owner), "{rows:#?}");
        let set_tag = regex::Regex::new(r"^local set 0 @ 0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
        assert!(set_tag.is_match(&sleeper.owner), "{rows:#?}");
        assert_eq!(sleeper.owner, acquirer.owner, "{rows:#?}");

        // The join edge names the local task with no "not in the
        // scheduler's owned tasks" caveat: it is simply listed now.
        let out = trace(&bundle, core, &joiner.id, false);
        assert!(
            out.contains(&format!("waiting on task {}\n", sleeper.id)),
            "{out}"
        );

        // The local tasks read like any listed task: the sleeper's
        // timer leaf decodes, and the acquirer's semaphore names its
        // queued waker as the task it would wake.
        let out = normalize(&trace(&bundle, core, &sleeper.id, false));
        assert!(out.contains("tokio::time::sleep::Sleep"), "{out}");
        assert!(out.contains("waiting on timer (deadline TS"), "{out}");
        let out = normalize(&trace(&bundle, core, &acquirer.id, false));
        assert!(
            out.contains(&format!("wake queue: task {}", acquirer.id)),
            "{out}"
        );

        // The set is not a runtime and has no row in the listing; the
        // golden pins the row of the runtime it shares a thread with,
        // counting that runtime's own tasks and not the set's.
        let out = hansei_ok(&bundle, core, "runtimes");
        golden("local-set-runtimes", &Symbols::new().columns().apply(&out));
    });
}

/// The blocking pool's cells as rows against a real core: the claimed
/// cell running on a nameable lwp — the poll-symbol stack join, which
/// no snapshot can exercise — the queued cell behind it, and each
/// waiter's join edge pointing at a listed row rather than the old
/// "no task list carries those" caveat.
#[test]
fn test_blocking_pool_acceptance() {
    let bundle = fixtures().bundle("blocking-pool");
    with_core("blocking-pool", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 5, "{rows:#?}");
        // The detached cell: its handle is gone, so this row exists
        // only because the queue walk read the pool's VecDeque.
        let detached = task_with_future(
            &rows,
            "future tokio::runtime::blocking::task::BlockingTask<\
             blocking_pool::main::{async_block#0}::{closure_env#2}>",
        );
        assert_eq!(detached.state, "blocking (queued)", "{rows:#?}");
        let running = task_with_future(
            &rows,
            "future tokio::runtime::blocking::task::BlockingTask<\
             blocking_pool::main::{async_block#0}::{closure_env#0}>",
        );
        let queued = task_with_future(
            &rows,
            "future tokio::runtime::blocking::task::BlockingTask<\
             blocking_pool::main::{async_block#0}::{closure_env#1}>",
        );
        assert_eq!(running.state, "blocking", "{rows:#?}");
        assert!(running.thread.parse::<u32>().is_ok(), "{rows:#?}");
        assert_eq!(queued.state, "blocking (queued)", "{rows:#?}");
        assert_eq!(queued.thread, "<none>", "{rows:#?}");
        // A blocking cell waits on a pool thread, not on a future, so
        // `task` prints no wait line for it.
        assert_eq!(running.waiting, "", "{rows:#?}");
        // The pool's thread is inside the running closure, which is
        // itself parked on a channel receive — through the primitives an
        // idle pool thread parks in. The task machinery between the
        // closure and the pool's loop is what says it is running.
        let threads = hansei_ok(&bundle, core, "threads");
        let row = threads
            .lines()
            .find(|line| line.split_whitespace().next() == Some(running.thread.as_str()))
            .unwrap_or_else(|| panic!("no row for lwp {}: {threads}", running.thread));
        assert!(row.contains("blocking, running"), "{threads}");

        // The join edges point at listed rows, plainly named: the
        // verified join is the wait line, with the trailer slot under
        // it.
        let a = task_with_future(&rows, "async fn blocking_pool::running_waiter");
        assert_eq!(a.waiting, format!("task {}", running.id), "{rows:#?}");
        assert_eq!(a.wait_lines, ["waker: its trailer"], "{rows:#?}");
        let b = task_with_future(&rows, "async fn blocking_pool::queued_waiter");
        assert_eq!(b.waiting, format!("task {}", queued.id), "{rows:#?}");
        assert_eq!(b.wait_lines, ["waker: its trailer"], "{rows:#?}");
    });
}

/// The wheel harvest against a real core: a `LocalSet` whose members
/// nothing outside it points at — both handles dropped at spawn, the
/// semaphore one of them waits on nobody else's — so every route that
/// starts from an enumerated task comes back empty. The runtime's own
/// timer wheel names the sleeper, and the whole set follows: both
/// members listed under the set's tag, the semaphore waiter included,
/// with `info` naming the route that found it.
#[test]
fn test_local_set_timer_acceptance() {
    let bundle = fixtures().bundle("local-set-timer");
    with_core("local-set-timer", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 3, "{rows:#?}");
        let spawned = task_with_future(&rows, "async fn local_set_timer::sleeper");
        let sleeper = task_with_future(&rows, "async fn local_set_timer::local_sleeper");
        let acquirer = task_with_future(&rows, "async fn local_set_timer::local_acquirer");

        // The spawned task keeps its runtime's tag — its own entry is in
        // the same wheel, and being listed is what keeps it out of the
        // harvest's candidates.
        let rt_tag = regex::Regex::new(r"^runtime 0 @ 0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&spawned.owner), "{rows:#?}");
        let set_tag = regex::Regex::new(r"^local set 0 @ 0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
        assert!(set_tag.is_match(&sleeper.owner), "{rows:#?}");
        assert_eq!(sleeper.owner, acquirer.owner, "{rows:#?}");

        // Both members read like any listed task — including the one no
        // route ever named, which the set brought with it.
        let out = normalize(&trace(&bundle, core, &sleeper.id, false));
        assert!(out.contains("waiting on timer (deadline TS"), "{out}");
        let out = normalize(&trace(&bundle, core, &acquirer.id, false));
        assert!(
            out.contains(&format!("wake queue: task {}", acquirer.id)),
            "{out}"
        );

        // The set has no row in the listing; the golden pins the row
        // of the runtime it was found through, with the set's tasks
        // counted apart from it.
        let out = hansei_ok(&bundle, core, "runtimes");
        golden(
            "local-set-timer-runtimes",
            &Symbols::new().columns().apply(&out),
        );
    });
}

/// The io harvest against a real core: a `LocalSet` in the same
/// position as the wheel fixture's, except that nothing here parks on
/// time, so the wheel comes back empty too. Each member is parked on a
/// socket of its own — one per waker site a registration has — and the
/// driver's registration list names them, so all three are listed under
/// the set's tag with `info` naming the route.
#[test]
fn test_local_set_io_acceptance() {
    let bundle = fixtures().bundle("local-set-io");
    with_core("local-set-io", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 5, "{rows:#?}");
        let spawned = task_with_future(&rows, "async fn local_set_io::reader");
        let members = ["local_reader", "local_watcher", "local_writer"]
            .map(|name| task_with_future(&rows, &format!("async fn local_set_io::{name}")));
        let gated = task_with_future(&rows, "async fn local_set_io::local_gated_reader");

        // The spawned task keeps its runtime's tag — its own waker is on
        // a registration the harvest walks, and being listed is what
        // keeps it out of the candidates.
        let rt_tag = regex::Regex::new(r"^runtime 0 @ 0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&spawned.owner), "{rows:#?}");
        let set_tag = regex::Regex::new(r"^local set 0 @ 0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
        for member in members.iter().chain([&gated]) {
            assert!(set_tag.is_match(&member.owner), "{rows:#?}");
            assert_eq!(member.owner, members[0].owner, "{rows:#?}");
        }

        // Every member reads like any listed task: the awaited chain
        // resolves down to the io leaf each of them parked at.
        for member in &members {
            let out = normalize(&trace(&bundle, core, &member.id, false));
            assert!(out.contains("tokio::net::unix"), "{out}");
        }
        // The gated reader parked on nothing: no registration names it,
        // so only the set's own list brought it in, and its chain ends
        // at the fixture's own reader rather than at a socket.
        let out = normalize(&trace(&bundle, core, &gated.id, false));
        assert!(out.contains("Read<local_set_io::Gated>"), "{out}");
        assert!(!out.contains("io fd"), "{out}");

        // The set has no row in the listing; the golden pins the row
        // of the runtime it was found through, with the set's tasks
        // counted apart from it.
        let out = hansei_ok(&bundle, core, "runtimes");
        golden(
            "local-set-io-runtimes",
            &Symbols::new().columns().apply(&out),
        );
    });
}

/// A runtime no thread is inside, against a real core. Its `block_on`
/// has returned, so the TLS anchor finds only the main runtime and
/// everything the second one owns is unlisted; the one `JoinHandle` the
/// main runtime's task parks on leads to a task of it, and that task's
/// cell leads to the runtime. Admitting it is also what puts its
/// drivers in reach, which is the only way the set inside it — one
/// member, parked on a timer in that runtime's own wheel — is ever
/// named.
#[test]
fn test_foreign_runtime_acceptance() {
    let bundle = fixtures().bundle("foreign-runtime");
    with_core("foreign-runtime", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 4, "{rows:#?}");
        let joiner = task_with_future(&rows, "async fn foreign_runtime::joiner");
        let joined = task_with_future(&rows, "async fn foreign_runtime::joined");
        let detached = task_with_future(&rows, "async fn foreign_runtime::detached");
        let sleeper = task_with_future(&rows, "async fn foreign_runtime::local_sleeper");

        let rt_tag = regex::Regex::new(r"^runtime 0 @ 0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&joiner.owner), "{rows:#?}");
        // Both of the hidden runtime's tasks carry its tag: the one the
        // joiner named, and the one nothing outside its list points at.
        let hidden_tag =
            regex::Regex::new(r"^runtime 1 @ 0x[0-9a-f]+ \(current_thread, no thread inside it\)$")
                .unwrap();
        for task in [joined, detached] {
            assert!(hidden_tag.is_match(&task.owner), "{rows:#?}");
        }
        let set_tag = regex::Regex::new(r"^local set 0 @ 0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
        assert!(set_tag.is_match(&sleeper.owner), "{rows:#?}");

        // The join edge reads like any other now that its target is
        // listed, rather than naming a runtime the session cannot show.
        let out = normalize(&trace(&bundle, core, &joiner.id, false));
        assert!(
            out.contains(&format!("waiting on task {}\n", joined.id)),
            "{out}"
        );
        assert!(!out.contains("does not list"), "{out}");

        // `runtimes` names the hidden runtime and the route to it, with
        // no thread inside it, beside the runtime that is run — and
        // neither row counts the set's task, which belongs to the set
        // that harvesting the hidden runtime's wheel found.
        let out = hansei_ok(&bundle, core, "runtimes");
        golden(
            "foreign-runtime-runtimes",
            &Symbols::new().columns().apply(&out),
        );
    });
}

/// A task cored mid-poll — spinning in a synchronous section of its
/// poll — gets its native continuation joined onto the trace under
/// `-n`: the committed chain stops at the yield the fixture long
/// since moved past, and the section above it names the spin frame
/// the poll is actually in — unnumbered, most recent first.
#[test]
fn test_spin_poll_acceptance() {
    let bundle = fixtures().bundle("spin-poll");
    with_core("spin-poll", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 1, "{rows:#?}");
        let task = task_with_future(&rows, "async fn spin_poll::spinner");

        // The listing corroborates the worker's claim, and names the
        // lwp the joined section must attribute the poll to.
        assert_eq!(task.state, "running", "{rows:#?}");
        let lwp = &task.thread;
        assert!(
            lwp.parse::<u32>().is_ok(),
            "the spinner is not running on a worker: {rows:#?}"
        );

        // Not [`hansei_ok`]: tracing a running task warns that its
        // state may be torn, and that warning is part of the assertion.
        let out = hansei(&bundle, core, &format!("trace {} -n", task.id));
        assert!(
            out.status.success(),
            "hansei trace failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            format!(
                "warning: task {} is running on lwp {lwp}; its state may be torn\n",
                task.id
            ),
        );
        let out = String::from_utf8(out.stdout).expect("hansei output is UTF-8");

        // The join, never the refusal: the section opens on the claimed
        // lwp.
        assert!(out.contains(&format!("mid-poll on lwp {lwp}")), "{out}");
        assert!(!out.contains("mid-poll, but"), "{out}");

        // The section sits above the chain: the heading comes before
        // the first numbered frame.
        let heading = out.find("mid-poll on lwp").expect("the heading prints");
        let first_frame = out.find("\n#0").expect("the chain prints");
        assert!(heading < first_frame, "{out}");

        // At least one native row, and it is the synchronous frame the
        // fixture parked its pc in.
        let grind = out
            .lines()
            .find(|line| line.trim_end().ends_with("spin_poll::grind"))
            .unwrap_or_else(|| panic!("no row names the spin frame:\n{out}"));
        assert!(grind.starts_with("0x"), "{out}");
        assert!(grind.contains("  spin_poll::grind"), "{out}");

        // The chain's rows alone carry numbers — the native rows have
        // none — counting 0.. from the most recent frame down to the
        // root with no reset or gap.
        let numbers: Vec<usize> = out
            .lines()
            .filter_map(|line| line.strip_prefix('#'))
            .map(|row| {
                let number = row.split_whitespace().next().unwrap_or_default();
                number
                    .parse()
                    .unwrap_or_else(|_| panic!("unnumbered frame row #{row}\nin:\n{out}"))
            })
            .collect();
        assert_eq!(numbers, (0..numbers.len()).collect::<Vec<_>>(), "{out}");

        // The provenance footer is gone: the section ends at its rows.
        assert!(!out.contains("scheduler frames above it omitted"), "{out}");

        // Without --native the section is elided whole: the chain is
        // the root alone, since a mid-poll task's saved state may be
        // mid-mutation, and the end says so — no native heading, no
        // lwp, and no refusal spelling either.
        let bare = hansei(&bundle, core, &format!("trace {}", task.id));
        assert!(
            bare.status.success(),
            "hansei trace failed:\n{}",
            String::from_utf8_lossy(&bare.stderr)
        );
        let bare = String::from_utf8(bare.stdout).expect("hansei output is UTF-8");
        assert!(
            bare.contains("the task is mid-poll: its saved state below the root is not read"),
            "{bare}"
        );
        assert!(!bare.contains("mid-poll on lwp"), "{bare}");
        assert!(!bare.contains(" native "), "{bare}");
        assert_eq!(bare.matches("\n#").count(), 1, "{bare}");

        // The chain carries no register block of its own — that moved
        // to `regs` — which answers for this task because selecting a
        // running task selects the lwp polling it: frame-0 state,
        // annotated from the recorded joins — the stack pointer lands
        // in a recorded thread stack, named the way `pmap` names one.
        assert!(!out.contains("registers:"), "{out}");
        let out = hansei_ok(&bundle, core, &format!("task {} ; regs", task.id));
        assert!(out.contains("registers:"), "{out}");
        let rsp = regex::Regex::new(r"(?m)^  rsp  0x[0-9a-f]{16}  — \[ stack tid=\d+ \]$").unwrap();
        assert!(rsp.is_match(&out), "{out}");
    });
}

/// The same mid-poll shape on a current_thread runtime, where the
/// thread polling the spinner is the `block_on` thread. Its scheduler
/// core is checked in with its driver for the whole poll, exactly as
/// it is while the root future is polled, so the state is told apart
/// by the thread-local task id: the thread is polling the task, and
/// nothing prints the root future.
#[test]
fn test_ct_spin_acceptance() {
    let bundle = fixtures().bundle("ct-spin");
    with_core("ct-spin", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 2, "{rows:#?}");
        let task = task_with_future(&rows, "async fn ct_spin::spinner");
        assert_eq!(task.state, "running", "{rows:#?}");

        // The task the spinner spawned before it began to spin can
        // never run: on this flavor a spawned task is polled only when
        // the running one yields, and the spinner never does. Its root
        // is `Unresumed` — no instruction of its body has executed —
        // so it is suspended behind no await, and the listing must not
        // present the line its body opens on as one.
        let dormant = task_with_future(&rows, "async fn ct_spin::dormant");
        assert_eq!(dormant.state, "queued", "{rows:#?}");
        assert_eq!(dormant.awaiting, "", "{rows:#?}");
        let out = hansei_ok(&bundle, core, "tasks");
        let row = out
            .lines()
            .find(|line| line.contains("async fn ct_spin::dormant"))
            .unwrap_or_else(|| panic!("no row for the dormant task: {out}"));
        assert!(!row.contains("ct-spin.rs"), "{out}");
        // And grouping by await site files it in the empty bucket,
        // not under its body's opening line.
        let out = hansei_ok(&bundle, core, "tasks --group awaiting");
        let bucket = out
            .lines()
            .find(|line| line.contains("<empty>"))
            .unwrap_or_else(|| panic!("no empty bucket in the grouping: {out}"));
        assert!(bucket.contains(&dormant.id), "{out}");
        let lwp = &task.thread;
        assert!(
            lwp.parse::<u32>().is_ok(),
            "the spinner is not running on the block_on thread: {rows:#?}"
        );

        // The thread block: the heading's claim and the block_on line
        // agree on the task, and the root future is named nowhere.
        let out = hansei_ok(&bundle, core, "threads --exec thread");
        assert!(
            out.contains(&format!("lwp {lwp}  polling task {}", task.id)),
            "{out}"
        );
        assert!(
            out.contains("block_on thread of its current_thread runtime"),
            "{out}"
        );
        assert!(
            out.contains(&format!("\n    polling task {}\n", task.id)),
            "{out}"
        );
        assert!(!out.contains("block_on future"), "{out}");
        assert!(!out.contains("between polls"), "{out}");

        // And the census puts it in the polling row, with the task
        // named beside the lwp, not the root-future row.
        let out = hansei_ok(&bundle, core, "census --threads");
        assert!(out.contains("  block_on thread  polling  "), "{out}");
        assert!(out.contains(&format!("{lwp} (task {})", task.id)), "{out}");
        assert!(!out.contains("polling block_on"), "{out}");
    });
}

/// `regs` under a cursor on a task no thread is polling: an idle task
/// has no trap state anywhere to show, and the refusal says whose
/// fault that is — the task's, not the reader's.
#[test]
fn test_regs_refuses_a_task_off_every_thread() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async fn simple_await::work");
        let out = hansei_ok(&bundle, core, &format!("task {} ; regs", task.id));
        assert!(
            out.contains("registers not available, task is not on a thread"),
            "{out}"
        );
    });
}

/// `trace -v` labels a pointer into another task's allocation with that
/// task's id, and `whatis` says what a raw address is — and the two
/// agree: the labelled Header pointer inside the joiner's JoinHandle
/// resolves back to the sleeper.
#[test]
fn test_whatis_acceptance() {
    let bundle = fixtures().bundle("sleep-join");
    with_core("sleep-join", |core| {
        let rows = list_tasks(&bundle, core);
        let sleeper = task_with_future(&rows, "async fn sleep_join::sleeper");
        let joiner = task_with_future(&rows, "async fn sleep_join::joiner");

        let verbose = trace(&bundle, core, &joiner.id, true);
        let labelled = regex::Regex::new(r"(0x[0-9a-f]+) \(task (\d+)\)")
            .unwrap()
            .captures(&verbose)
            .unwrap_or_else(|| panic!("no labelled pointer in:\n{verbose}"));
        assert_eq!(&labelled[2], sleeper.id.as_str(), "{verbose}");

        let header = &labelled[1];
        let out = hansei_ok(&bundle, core, &format!("whatis {header}"));
        assert!(
            out.contains(&format!(
                "Task {}: async fn sleep_join::sleeper\n",
                sleeper.id
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "    At: offset 0x0 in the task's allocation (header {header})"
            )),
            "{out}"
        );
        assert!(out.contains("    State: idle"), "{out}");

        // An interior address resolves to the same task with its offset.
        let interior = u64::from_str_radix(header.trim_start_matches("0x"), 16).unwrap() + 0x10;
        let out = hansei_ok(&bundle, core, &format!("whatis {interior:#x}"));
        assert!(out.contains(&format!("Task {}: ", sleeper.id)), "{out}");
        assert!(
            out.contains("    At: offset 0x10 in the task's allocation"),
            "{out}"
        );

        // An address outside every allocation is a miss, not an error.
        let out = hansei_ok(&bundle, core, "whatis 0x10");
        assert_eq!(
            out,
            "no task's allocation and no future the census found contains 0x10\n"
        );

        // The 0x prefix is mandatory: a bare number is a parse error,
        // which fails a scripted session.
        let out = hansei(&bundle, core, "whatis 42");
        assert!(
            !out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    });
}

/// The sub-executor census: a `FuturesUnordered`'s children are futures,
/// not tasks — `children` lists them under the task that polls the
/// set, `trace -v` labels their queued wakers with that task, and
/// `whatis` resolves a child node address to it.
#[test]
fn test_futures_acceptance() {
    let bundle = fixtures().bundle("unordered");
    with_core("unordered", |core| {
        let rows = list_tasks(&bundle, core);
        let driver = task_with_future(&rows, "async fn unordered::driver");

        // Seven held futures, two of them in a map's buckets, and one
        // set holding three children — the driver's own finds, counted
        // apart from what the census went on to find inside them.
        // `task` carries both counts, and says `0` for a task the
        // census found nothing for rather than staying silent;
        // `children` lists what each counted, under its own row, at the
        // margin — under the task's scope it prints no heading of its
        // own.
        assert_eq!(driver.futures, "7", "{rows:?}");
        assert_eq!(driver.sets, "1 (3 futures)", "{rows:?}");
        for row in rows.iter().filter(|row| row.id != driver.id) {
            assert_eq!(row.futures, "0", "{row:?}");
            assert_eq!(row.sets, "0", "{row:?}");
        }
        let block = hansei_ok(&bundle, core, &format!("task {}", driver.id));
        assert!(
            block.ends_with("\n    held futures: 7\n    join sets: 1 (3 futures)\n"),
            "{block}"
        );
        let futures = hansei_ok(&bundle, core, &format!("task {} children", driver.id));
        assert!(futures.starts_with("held futures: 7\n    "), "{futures}");
        assert!(
            futures.contains("\njoin sets: 1 (3 futures)\n    - "),
            "{futures}"
        );
        assert!(
            futures.contains(
                "futures_util::stream::futures_unordered::FuturesUnordered\
                 <unordered::set_member> at 0x"
            ),
            "{futures}"
        );
        // The set's own row says the same, spelled for one set rather
        // than for the block's total.
        assert!(futures.contains("`): 3 children in flight"), "{futures}");
        // Set-child rows sit one indent step deeper than the set's own
        // bulleted row.
        let child =
            regex::Regex::new(r"\n        (0x[0-9a-f]+)  async fn unordered::set_member").unwrap();
        let nodes: Vec<String> = child
            .captures_iter(&futures)
            .map(|c| c[1].to_string())
            .collect();
        assert_eq!(nodes.len(), 3, "{futures}");

        // The held futures — a bare coroutine and a dyn-boxed one, the
        // census's other two detections — are listed off the driver's
        // spine, never yet polled, and so are the two the scan reached
        // only by descending into a tuple and into an enum, and the one
        // carrying a future of its own.
        // The driver is frame 2 of its own chain: its `next()` reaches
        // the set, which is the leaf.
        for local in ["held", "boxed", "pair", "maybe", "nested_hold"] {
            assert!(
                futures.contains(&format!("\n    (frame 2, `{local}`)")),
                "{futures}"
            );
        }
        assert!(
            futures.contains("async fn unordered::set_member  Unresumed"),
            "{futures}"
        );

        // What the census found inside what it found is listed under
        // it, not beside it: each set child holds a future of its own,
        // one indent step deeper than the child, and one of them holds
        // a whole set of its own, whose children are deeper again and
        // named by the futures their boxes hold. The tree is the
        // census's attribution, drawn.
        let held_row = r"held \(frame 1, `held`\): 0x[0-9a-f]+  async fn unordered::leaf";
        let under_child =
            regex::Regex::new(&format!(r"\n            {held_row}  Unresumed")).unwrap();
        assert_eq!(under_child.find_iter(&futures).count(), 3, "{futures}");
        assert!(
            futures.contains(
                "\n            - futures_util::stream::futures_unordered::FuturesUnordered\
                 <Pin<Box<(dyn Future<Output=u32> + Send)>>> at 0x"
            ),
            "{futures}"
        );
        assert!(
            futures.contains("(frame 1, `inner`): 2 children in flight"),
            "{futures}"
        );
        let under_set = regex::Regex::new(
            r"\n                0x[0-9a-f]+  async fn unordered::leaf  Unresumed",
        )
        .unwrap();
        assert_eq!(under_set.find_iter(&futures).count(), 2, "{futures}");

        // The same nesting without a set in it: a future the driver
        // holds carries one, so its row sits one step under the row
        // that holds it, inside the `held futures` block. No `held`
        // mark there — the heading is already the word.
        let carried_row = r"\(frame 0, `inner`\): 0x[0-9a-f]+  async fn unordered::leaf";
        let under_held =
            regex::Regex::new(&format!(r"\n        {carried_row}  Unresumed")).unwrap();
        assert_eq!(under_held.find_iter(&futures).count(), 1, "{futures}");

        // Every one of those finds is the driver's: any other task
        // lists nothing under its zeros.
        for row in rows.iter().filter(|row| row.id != driver.id) {
            let other = hansei_ok(&bundle, core, &format!("task {} children", row.id));
            assert_eq!(other, "held futures: 0\njoin sets: 0\n");
            let block = hansei_ok(&bundle, core, &format!("task {}", row.id));
            assert!(
                block.ends_with("\n    held futures: 0\n    join sets: 0\n"),
                "{block}"
            );
        }

        // The children park in the shared Notify; rendering the driver's
        // own `set` local deep enough reaches that wait queue, whose
        // wakers carry the set's node addresses — named as the polling
        // task rather than left as raw pointers.
        let verbose = hansei_ok(
            &bundle,
            core,
            &format!("config depth 12; trace {} --verbose", driver.id),
        );
        assert!(
            verbose.contains(&format!("task {} via FuturesUnordered", driver.id)),
            "{verbose}"
        );

        // A child node address names the child future and the task that
        // polls the set holding it. The node is its own heap
        // allocation, so no task's allocation claims it and the block
        // naming the set is the only thing that says whose it is.
        let out = hansei_ok(&bundle, core, &format!("whatis {}", nodes[0]));
        assert!(
            out.contains(&format!(
                "Future {}: async fn unordered::set_member",
                nodes[0]
            )),
            "{out}"
        );
        assert!(
            out.contains("    At: offset 0x0 in a FuturesUnordered child node"),
            "{out}"
        );
        assert!(
            out.contains(&format!("    Polled by: task {} — ", driver.id)),
            "{out}"
        );

        // The set's own address says what the set is, and — since it
        // sits in a frame local of the driver's own allocation — says
        // the driver holds it, outermost answer first.
        let set = regex::Regex::new(r"FuturesUnordered<[^>]+> at (0x[0-9a-f]+)")
            .unwrap()
            .captures(&futures)
            .map(|c| c[1].to_string())
            .expect("the set row prints an address");
        let out = hansei_ok(&bundle, core, &format!("whatis {set}"));
        let task_block = out
            .find(&format!("Task {}: ", driver.id))
            .unwrap_or_else(|| panic!("the set's holder is not reported:\n{out}"));
        let set_block = out
            .find(&format!("Set {set}: "))
            .unwrap_or_else(|| panic!("the set itself is not reported:\n{out}"));
        assert!(task_block < set_block, "{out}");
        assert!(out.contains("    Children: 3 in flight"), "{out}");
        assert!(
            out.contains(&format!("    Driven by: task {} — ", driver.id)),
            "{out}"
        );

        // A child node address is also traceable on its own: `trace`
        // re-roots at the resident future and renders its chain, headed
        // by the set that owns the node and the task that polls the set.
        let out = hansei_ok(&bundle, core, &format!("trace {}", nodes[0]));
        assert!(
            out.contains(&format!(
                "future {}: async fn unordered::set_member",
                nodes[0]
            )),
            "{out}"
        );
        assert!(
            out.contains("Child of: futures_util::stream::futures_unordered::FuturesUnordered"),
            "{out}"
        );
        assert!(
            out.contains(&format!("polled by task {}", driver.id)),
            "{out}"
        );
        assert!(
            out.contains("  async fn      unordered::set_member"),
            "{out}"
        );

        // And so is a held future, by the address its row prints.
        let held = regex::Regex::new(r"\n    \(frame 2, `held`\): (0x[0-9a-f]+)")
            .unwrap()
            .captures(&futures)
            .map(|c| c[1].to_string())
            .expect("the held row prints an address");
        let out = hansei_ok(&bundle, core, &format!("trace {held}"));
        assert!(
            out.contains(&format!(
                "Held by: task {} — async fn unordered::driver (frame 2, `held`)",
                driver.id
            )),
            "{out}"
        );

        // That future is held by value in a frame, so it lives inside
        // the driver's own allocation and one address belongs to both:
        // `whatis` answers with the task and then the future, rather
        // than stopping at whichever it found first.
        let out = hansei_ok(&bundle, core, &format!("whatis {held}"));
        let task_block = out
            .find(&format!("Task {}: async fn unordered::driver", driver.id))
            .unwrap_or_else(|| panic!("the task holding the future is not reported:\n{out}"));
        assert!(out.contains("in the task's allocation (header 0x"), "{out}");
        assert!(out.contains("    At: offset 0x0 in the future"), "{out}");
        let future_block = out
            .find(&format!("Future {held}: async fn unordered::set_member"))
            .unwrap_or_else(|| panic!("the held future itself is not reported:\n{out}"));
        assert!(task_block < future_block, "{out}");
        assert!(
            out.contains(&format!(
                "    Held by: task {} — async fn unordered::driver (frame 2, `held`)",
                driver.id
            )),
            "{out}"
        );
    });
}

/// `--search-depth` is how deep the census descends into one frame
/// local, and the only bound of the walk a session can move.
///
/// Told not to descend at all, the scan still finds what a frame holds
/// outright — a coroutine local, a boxed one — and misses the two the
/// fixture nests inside a tuple and an `Option`. That listing is
/// shorter than the target, which is exactly the incompleteness no
/// error reports, so the run says on stderr where it stopped and which
/// flag moves it. Raised past what the fixture needs, the same session
/// is the default's answer to the byte.
#[test]
fn test_search_depth_acceptance() {
    let bundle = fixtures().bundle("unordered");
    with_core("unordered", |core| {
        let full = hansei_ok(&bundle, core, "tasks --exec children");

        let shallow = hansei_with(
            &bundle,
            core,
            &["--search-depth", "0"],
            "tasks --exec children",
        );
        let warned = String::from_utf8_lossy(&shallow.stderr);
        let listed = String::from_utf8_lossy(&shallow.stdout);
        assert!(shallow.status.success(), "{warned}");
        assert!(
            warned.contains("the scan stopped at its depth limit in "),
            "{warned}"
        );
        assert!(warned.contains("--search-depth"), "{warned}");

        // What the driver holds outright is still found and still
        // counted; what it holds nested is neither.
        assert!(listed.contains("\nheld futures: 3\n"), "{listed}");
        for local in ["held", "boxed", "nested_hold"] {
            assert!(
                listed.contains(&format!("\n    (frame 2, `{local}`)")),
                "{listed}"
            );
        }
        for local in ["pair", "maybe"] {
            assert!(
                !listed.contains(&format!("(frame 2, `{local}`)")),
                "{listed}"
            );
            assert!(full.contains(&format!("(frame 2, `{local}`)")), "{full}");
        }
        // A set is a local in its own right, so its children are
        // walked as ever: the depth limit is a bound on one value's
        // insides, not on how far the census goes.
        assert!(listed.contains("3 children in flight"), "{listed}");

        // And it moves the other way: past what this target needs, the
        // walk is the unbounded one, warning and all.
        let deep = hansei_with(
            &bundle,
            core,
            &["--search-depth", "64"],
            "tasks --exec children",
        );
        let quiet = String::from_utf8_lossy(&deep.stderr);
        assert!(quiet.is_empty(), "{quiet}");
        assert_eq!(String::from_utf8_lossy(&deep.stdout), full);
    });
}

/// A `JoinSet` holds tasks rather than futures: `children` lists
/// them under the task that drives the set, by the ids each has a row
/// of its own under — and no futures count moves, because a spawned task
/// is on its own await chain rather than off anybody's.
///
/// One of them has no row to name, being a member of the second set
/// that ran to completion and was never joined: a task off the
/// runtime's owned list, which only the set still holds.
#[test]
fn test_join_set_acceptance() {
    let bundle = fixtures().bundle("joinset");
    with_core("joinset", |core| {
        let rows = list_tasks(&bundle, core);
        let driver = task_with_future(&rows, "async fn joinset::driver");

        // Two sets of three members each — tasks, counted apart from
        // the futures a set of futures would hold — and nothing held in
        // the driver's own frames.
        assert_eq!(driver.sets, "2 (6 tasks)", "{rows:?}");
        assert_eq!(driver.futures, "0", "{rows:?}");
        for row in rows.iter().filter(|row| row.id != driver.id) {
            assert_eq!(row.sets, "0", "{row:?}");
        }

        let futures = hansei_ok(&bundle, core, &format!("task {} children", driver.id));
        assert!(
            futures.contains("\njoin sets: 2 (6 tasks)\n    - "),
            "{futures}"
        );
        assert!(
            futures.contains("tokio::task::join_set::JoinSet<u32> at 0x"),
            "{futures}"
        );
        assert!(futures.contains("`): 3 tasks\n"), "{futures}");

        // Every member is named by the id its own row carries, so the
        // set reads as an edge into the listing rather than as a
        // population beside it.
        let member = regex::Regex::new(r"\n        task (\d+)  async fn joinset::member").unwrap();
        let ids: Vec<String> = member
            .captures_iter(&futures)
            .map(|c| c[1].to_string())
            .collect();
        assert_eq!(ids.len(), 5, "{futures}");
        for id in &ids {
            assert!(rows.iter().any(|row| &row.id == id), "{rows:?}");
            let traced = hansei_ok(&bundle, core, &format!("trace {id}"));
            assert!(traced.contains("async fn      joinset::member"), "{traced}");
        }

        // Except the member of the unjoined set that has run to
        // completion. It has left the runtime's owned list, so the
        // listing has no row for it and nothing but this set's entry
        // names it — which the row says outright rather than naming a
        // future it cannot reach.
        let done = regex::Regex::new(r"\n        task (\d+)  <complete, awaiting join>")
            .unwrap()
            .captures(&futures)
            .unwrap_or_else(|| panic!("no completed member: {futures}"))[1]
            .to_string();
        assert!(!ids.contains(&done), "{futures}");
        assert!(!rows.iter().any(|row| row.id == done), "{rows:?}");

        // The same edge is what the wait graph nests on. Nothing about
        // the driver's own wait names these tasks — it is parked in
        // `join_next`, not on any one member's `JoinHandle` — so the
        // set is the only thing that says the driver is waiting for
        // them.
        let graph = graph(&bundle, core);
        assert!(
            graph.contains(&format!("\n{} ", driver.id)),
            "the driver is not at the margin: {graph}"
        );
        for id in &ids {
            assert!(
                graph.contains(&format!("─ {id} [in the JoinSet above]")),
                "{id} is not nested under the driver: {graph}"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Dependency graph and futurelock diagnosis
// ---------------------------------------------------------------------------

/// Run the `graph` command and return its output.
fn graph(bundle: &Path, core: &Path) -> String {
    hansei_ok(bundle, core, "graph")
}

/// The RFD 609 diagnosis, fully automatic: the contended Mutex's wake
/// queue resolves to the blocked task itself, and the abandoned
/// `future1` is found in do_stuff's locals holding the granted permit
/// it can never release.
///
/// The golden is read for the agreements running through it. The lock's
/// holder is the blocked task itself, so the graph's one edge closes
/// straight back on its own row — `#blocked` in the wake queue, on the
/// `← cycle` row and in the diagnosis is the self-deadlock shape, drawn
/// — and the semaphore the row names is the one the diagnosis names,
/// which is `ADDR1` in both places rather than two maskings that could
/// have hidden two different locks.
#[test]
fn test_futurelock_graph() {
    let bundle = fixtures().bundle("futurelock");
    with_core("futurelock", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async block futurelock::main::{async_block#0}");
        let symbols = Symbols::new().task(&task.id, "blocked");
        golden("futurelock-graph", &symbols.apply(&graph(&bundle, core)));
    });
}

/// The resource-centric view of the same diagnosis the graph draws:
/// one block for the contended Mutex, its holder named from the
/// futurelock analysis, the blocked task and the wake queue agreeing on
/// who waits. The semaphore address in the block heading is the same
/// spelling trace prints, and the argument `sync 0x…` takes back — the
/// selected block is byte-identical to the listing's one block.
#[test]
fn test_sync_lists_the_contended_semaphore() {
    let bundle = fixtures().bundle("futurelock");
    with_core("futurelock", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async block futurelock::main::{async_block#0}");
        let out = hansei_ok(&bundle, core, "sync");
        golden(
            "futurelock-sync",
            &Symbols::new().task(&task.id, "blocked").apply(&out),
        );

        let addr = regex::Regex::new(r"semaphore (0x[0-9a-f]+)")
            .unwrap()
            .captures(&out)
            .unwrap_or_else(|| panic!("no semaphore address in {out}"))[1]
            .to_string();
        // The listing may append join and set blocks after the
        // semaphore's; the selected block is byte-identical to the
        // listing's first.
        let one = hansei_ok(&bundle, core, &format!("sync {addr}"));
        assert!(out.starts_with(&one), "sync {addr}: {one}\nlisting: {out}");

        // An address the analysis never decoded — no semaphore, no
        // set, no task's allocation, no frame holding it by value —
        // is refused rather than answered with silence.
        let miss = hansei(&bundle, core, "sync 0x10");
        assert!(!miss.status.success());
        assert!(
            String::from_utf8_lossy(&miss.stderr).contains("no decoded resource at 0x10"),
            "{}",
            String::from_utf8_lossy(&miss.stderr)
        );
    });
}

/// A target with no relations prints nothing at all: the analysis
/// reads only the edges it knows how to read, and an empty answer is
/// "none found here". A joined task is a relation now — sleep-join's
/// sleeper earns a block in the bare listing — and so is the oneshot
/// simple-await's one task parks on, so the empty answer belongs to
/// the families a fixture has none of, and the no-contention claim to
/// the semaphore family alone.
#[test]
fn test_sync_prints_nothing_without_contention() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        for kinds in ["semaphore", "join", "set", "mpsc,watch,notify"] {
            let out = hansei_ok(&bundle, core, &format!("sync --kind {kinds}"));
            assert_eq!(out, "", "simple-await has no {kinds}");
        }
        // The one relation it has: the oneshot its task waits on, one
        // block and nothing else.
        let out = hansei_ok(&bundle, core, "sync");
        assert!(out.starts_with("oneshot 0x"), "{out}");
        assert!(
            out.contains(": nothing sent, sender alive\n    rx: task "),
            "{out}"
        );
        assert_eq!(out.matches("\n\n").count(), 0, "{out}");
    });
    let bundle = fixtures().bundle("sleep-join");
    with_core("sleep-join", |core| {
        let out = hansei_ok(&bundle, core, "sync --kind semaphore");
        assert_eq!(out, "", "sleep-join contends on no semaphore");
        let joins = hansei_ok(&bundle, core, "sync");
        assert!(joins.contains("Waited by: task "), "{joins}");
    });
}

/// Wait edges without a diagnosis: the joiner's JoinHandle edge points
/// at the sleeper, the sleeper waits on the timer, and a healthy
/// runtime reports no futurelock.
///
/// The joiner is waiting for the sleeper, so the sleeper's row hangs
/// under it rather than standing beside it, and the sleeper's own wait
/// — the timer — is what the chain ends on. Nothing follows the table:
/// a target with no futurelock says nothing about futurelocks.
#[test]
fn test_sleep_join_graph() {
    let bundle = fixtures().bundle("sleep-join");
    with_core("sleep-join", |core| {
        let rows = list_tasks(&bundle, core);
        let sleeper = task_with_future(&rows, "async fn sleep_join::sleeper");
        let joiner = task_with_future(&rows, "async fn sleep_join::joiner");

        let symbols = Symbols::new()
            .task(&joiner.id, "joiner")
            .task(&sleeper.id, "sleeper");
        golden("sleep-join-graph", &symbols.apply(&graph(&bundle, core)));
    });
}

// ---------------------------------------------------------------------------
// Runtime state and bundle layouts
// ---------------------------------------------------------------------------

/// The runtime as its own threads hold it: each worker's index and the
/// `Core` it is carrying. Worker counts follow the box's CPU count, so
/// what is asserted is the shape of a worker, not how many there are.
#[test]
fn test_threads_shows_workers() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "threads --exec thread");
        // Each thread's block opens under its table row, and every
        // line under a block's heading sits four columns in.
        let claim = regex::Regex::new(
            r"(?m)^lwp \d+  (polling no task|polling task \d+|last polled task \d+)",
        )
        .unwrap();
        assert!(claim.is_match(&out), "{out}");
        for line in out
            .lines()
            .filter(|l| l.starts_with("    ") || l.starts_with("lwp "))
        {
            assert!(
                line.starts_with("lwp ") || line.starts_with("    "),
                "{line}"
            );
        }
        assert!(out.contains("\n    worker 0\n"), "{out}");
        // The thread's own tokio context prints ahead of the scheduler
        // state.
        assert!(out.contains("\n    thread_id: "), "{out}");
        assert!(out.contains("\n    budget: "), "{out}");
        assert!(out.contains("multi_thread::worker::Core"), "{out}");
        assert!(out.contains("is_searching:"), "{out}");
        // The blocking thread holds a runtime context without running
        // the worker loop.
        assert!(
            out.contains("\n    not in the scheduler's run loop\n"),
            "{out}"
        );
        // The stack is `trace`'s under the thread cursor, not the
        // block's.
        assert!(!out.contains("stack:"), "{out}");
    });
}

/// The bare `threads` is a table over every lwp — runtime workers,
/// the threads that merely entered, and the ones holding no runtime
/// at all — one row each, and `thread` prints a block for each.
#[test]
fn test_threads_lists_a_table_row_per_lwp() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "threads");
        let mut lines = out.lines();
        let header = lines.next().expect("the listing has a header");
        assert!(header.starts_with("LWP"), "{out}");
        for column in ["NAME", "ROLE", "TASK", "FRAME 0"] {
            assert!(header.contains(column), "{out}");
        }
        let mut rows: Vec<&str> = lines.collect();
        // The table closes with its count; one row per block `thread`
        // prints under it, so the two listings cover the same
        // population.
        let footer = rows.pop().expect("the listing has a footer");
        assert_eq!(footer, format!("[{} threads]", rows.len()), "{out}");
        let blocks = hansei_ok(&bundle, core, "threads --exec thread");
        let heading = regex::Regex::new(r"(?m)^lwp \d+  ").unwrap();
        assert_eq!(rows.len(), heading.find_iter(&blocks).count(), "{blocks}");
        // A worker's row names its place in the run loop; the main
        // thread entered the runtime without running its loop.
        assert!(rows.iter().any(|r| r.contains("worker 0,")), "{out}");
        assert!(rows.iter().any(|r| r.contains("entered runtime")), "{out}");
    });
}

/// `thread N` prints one thread's block — the same block `threads
/// --exec thread` prints under that thread's row — and an lwp the
/// listing does not hold is an error naming the ones it does. The
/// listing itself takes no lwp ids, and says which command does.
#[test]
fn test_thread_selects_one_lwp() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let full = hansei_ok(&bundle, core, "threads --exec thread");
        // The first block: from its `lwp` heading to the blank line
        // before the next thread's row.
        let start = full.find("\nlwp ").expect("the loop prints a block") + 1;
        let end = full[start..]
            .find("\n\n")
            .map_or(full.len(), |i| start + i + 1);
        let first = &full[start..end];
        let tid = first
            .strip_prefix("lwp ")
            .and_then(|rest| rest.split_whitespace().next())
            .expect("the block heading names its lwp");

        let one = hansei_ok(&bundle, core, &format!("thread {tid}"));
        assert_eq!(one, first, "the lwp selects its block alone");

        // An lwp no runtime runs on is an error, which fails a
        // scripted session.
        let out = hansei(&bundle, core, "thread 999999");
        assert!(
            !out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("no lwp 999999 ("), "{stderr}");

        // The listing refuses an lwp id, naming the selector.
        let out = hansei(&bundle, core, &format!("threads {tid}"));
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(&format!("`thread {tid}`")), "{stderr}");
    });
}

/// Registers print only where they are earned or asked for: a healthy
/// capture's thread blocks carry none, `regs` under each thread prints
/// an annotated block, and the stack registers attribute to the
/// thread they were read from.
#[test]
fn test_threads_registers_annotate_on_request() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let plain = hansei_ok(&bundle, core, "threads --exec thread");
        assert!(!plain.contains("registers:"), "{plain}");

        let out = hansei_ok(&bundle, core, "threads --exec regs");
        let blocks = out.matches("registers:\n").count();
        assert!(blocks > 0, "{out}");
        // Each block's rsp is that thread's own. The claim names a
        // thread rather than being first-person, so what says it is
        // the loop's own heading: the tid on the rsp line must be the
        // one the heading above it names, in every block.
        let heading = regex::Regex::new(r"(?m)^thread (\d+)$").unwrap();
        let rsp =
            regex::Regex::new(r"(?m)^  rsp  0x[0-9a-f]{16}  — \[ stack tid=(\d+) \]$").unwrap();
        let headings: Vec<&str> = heading
            .captures_iter(&out)
            .map(|c| c.get(1).unwrap().as_str())
            .collect();
        let claimed: Vec<&str> = rsp
            .captures_iter(&out)
            .map(|c| c.get(1).unwrap().as_str())
            .collect();
        assert_eq!(headings.len(), blocks, "{out}");
        assert_eq!(claimed, headings, "{out}");
    });
}

/// `runtime` selects by listed index and by handle address, prints
/// the one runtime unnamed on a target holding one, and refuses a
/// runtime the target does not hold with a count rather than
/// printing the runtimes that were found.
#[test]
fn test_runtime_selects_by_index_and_address() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "runtime 0");
        assert!(out.starts_with("runtime 0 @ 0x"), "{out}");
        assert!(out.contains("\n    flavor: multi_thread\n"), "{out}");
        // The two halves open on their own line, the rendered value
        // set under the label the way `thread` sets its fields.
        assert!(
            out.contains("\n    drivers:\n      tokio::runtime::driver::Handle {"),
            "{out}"
        );
        assert!(
            out.contains(
                "\n    shared:\n      tokio::runtime::scheduler::multi_thread::worker::Shared {"
            ),
            "{out}"
        );

        let unnamed = hansei_ok(&bundle, core, "runtime");
        assert_eq!(out, unnamed, "the one runtime needs no name");

        let listed = hansei_ok(&bundle, core, "runtimes");
        let addr = regex::Regex::new(r"\b(0x[0-9a-f]+)\b")
            .unwrap()
            .captures(&listed)
            .expect("the listing prints a handle address")[1]
            .to_string();
        let by_addr = hansei_ok(&bundle, core, &format!("runtime {addr}"));
        assert_eq!(out, by_addr, "the listed handle address selects it");

        let out = hansei(&bundle, core, "runtime 3");
        assert!(!out.status.success(), "an absent index was shown anyway");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("no runtime 3 (1 runtime)"), "{stderr}");

        // Naming a runtime to the listing is refused with the
        // selector's spelling.
        let out = hansei(&bundle, core, "runtimes 0");
        assert!(!out.status.success(), "the listing took a runtime name");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("`runtime 0` prints that one runtime"),
            "{stderr}"
        );
    });
}

/// Several runtimes are each their own block, opened by the name the
/// listing gives them — and with more than one, the unnamed form
/// refuses rather than guessing.
#[test]
fn test_several_runtimes_are_each_their_own_block() {
    let bundle = fixtures().bundle("foreign-runtime");
    with_core("foreign-runtime", |core| {
        let zero = hansei_ok(&bundle, core, "runtime 0");
        assert!(zero.starts_with("runtime 0 @ 0x"), "{zero}");
        assert!(zero.contains("\n    flavor: current_thread\n"), "{zero}");
        assert!(!zero.contains("\nruntime 1 @"), "{zero}");

        // The hidden runtime: no thread inside it, and the route that
        // found it in place of one.
        let one = hansei_ok(&bundle, core, "runtime 1");
        assert!(one.starts_with("runtime 1 @ 0x"), "{one}");
        assert!(one.contains("\n    threads: none inside it\n"), "{one}");
        assert!(
            one.contains("\n    found via: a JoinHandle scanned in an enumerated task's storage\n"),
            "{one}"
        );

        let out = hansei(&bundle, core, "runtime");
        assert!(!out.status.success(), "an unnamed runtime was guessed at");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("2 runtimes; name one"), "{stderr}");
    });
}

/// `--runtime` past the end is refused with the list of what there is:
/// a reader who guessed wrong wants the runtimes, not a bare refusal.
#[test]
fn test_runtime_selection_past_the_end_is_refused() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_with(&bundle, core, &["--runtime", "7"], "info");
        assert!(!out.status.success(), "an absent runtime index attached");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--runtime 7: the target has 1 runtime(s)"),
            "{stderr}"
        );
    });
}

/// A script's blank lines and `#` comments are skipped, not executed:
/// an annotated stored script runs clean.
#[test]
fn test_scripts_may_hold_comments_and_blank_lines() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "# a note\n\ninfo");
        assert!(out.contains("symbols resolved:"), "{out}");
    });
}

/// The census counts the same target every other listing walks: the
/// threads by what their parkers say — including the one asleep in the
/// driver on the whole runtime's behalf — the tasks by state and by
/// what each waits on, and the futures on their await chains.
#[test]
fn test_census_counts_the_target() {
    let bundle = fixtures().bundle("sleep-join");
    with_core("sleep-join", |core| {
        let out = hansei_ok(&bundle, core, "census");

        // The section names the one runtime the target holds, the way
        // `runtimes` lists it.
        let inside =
            regex::Regex::new(r"Threads: \d+ lwps, \d+ in runtime 0 @ 0x[0-9a-f]+\n").unwrap();
        assert!(inside.is_match(&out), "{out}");
        let driver =
            regex::Regex::new(r"\n    1  0   worker           in driver        \d+\n").unwrap();
        assert!(driver.is_match(&out), "{out}");
        // The `block_on` thread is in the runtime without running the
        // worker loop, as `threads` says of it too — and it is counted
        // apart from the pool's own threads, which the runtime's two
        // workers are otherwise counted among. The pool's row cannot
        // say which lwps are its; the caller's can, since every thread
        // that entered is the caller's.
        let entered =
            regex::Regex::new(r"\n    1  0   entered runtime  block_on caller  \d+\n").unwrap();
        assert!(entered.is_match(&out), "{out}");
        assert!(
            out.contains("\n    0  0   blocking pool    0 idle, 0 busy   —\n"),
            "{out}"
        );

        // The task total is the task listing's, and the two waits are
        // the two leaves the graph names: the sleeper on the timer, the
        // joiner on the sleeper — each hanging off the future type
        // whose task waits that way rather than tallied on its own.
        let rows = list_tasks(&bundle, core);
        let owned = regex::Regex::new(&format!(
            r"Tasks: {} owned by runtime 0 @ 0x[0-9a-f]+\n",
            rows.len()
        ))
        .unwrap();
        assert!(owned.is_match(&out), "{out}");
        assert!(
            out.contains("COUNT  STATE\n    2  idle\n[2 tasks]\n"),
            "{out}"
        );
        assert!(
            out.contains("    1  async fn sleep_join::sleeper\n       └─ 1  timer\n"),
            "{out}"
        );
        assert!(
            out.contains("    1  async fn sleep_join::joiner\n       └─ 1  task\n"),
            "{out}"
        );

        // Two two-frame chains — each an async fn over its leaf — and
        // nothing at all off them. Two futures in flight, standing on
        // four frames: the heading counts the futures and the frames
        // apart, so a chain that grows deeper does not read as more
        // things running.
        assert!(
            out.contains(
                "Futures: 2 in flight, on 4 await-chain frames, up to 2 deep\n\
                 \n\
                 COUNT  HELD IN\n    \
                 2  task (its own await chain)\n    \
                 0  frame (off any await chain)\n    \
                 0  set (0 FuturesUnordered)\n\
                 [2 futures]\n"
            ),
            "{out}"
        );
    });
}

/// A census narrowed to sections prints those sections and no others,
/// and the ones it does print are the same rows the whole page carries.
#[test]
fn test_census_prints_only_the_sections_named() {
    let bundle = fixtures().bundle("sleep-join");
    with_core("sleep-join", |core| {
        let threads = hansei_ok(&bundle, core, "census --threads");
        assert!(threads.starts_with("Threads: "), "{threads}");
        assert!(!threads.contains("Tasks: "), "{threads}");
        assert!(!threads.contains("Futures: "), "{threads}");

        // Two sections at once, by their short flags: one page with one
        // blank line in it, and neither section short of what the whole
        // census prints for it.
        let both = hansei_ok(&bundle, core, "census -tf");
        assert!(both.starts_with("Tasks: 2 owned by runtime 0 @"), "{both}");
        assert!(!both.contains("Threads: "), "{both}");
        assert!(both.contains("\n\nFutures: 2 in flight, "), "{both}");

        // The tasks section alone still says what each task waits on,
        // which is the dependency analysis rather than the listing: a
        // section can want work another section also wants, and asking
        // for one of them is asking for the work.
        let tasks = hansei_ok(&bundle, core, "census -t");
        assert!(
            tasks.starts_with("Tasks: 2 owned by runtime 0 @"),
            "{tasks}"
        );
        assert!(!tasks.contains("Threads: "), "{tasks}");
        assert!(!tasks.contains("Futures: "), "{tasks}");
        assert!(
            tasks.contains("    1  async fn sleep_join::sleeper\n       └─ 1  timer\n"),
            "{tasks}"
        );
    });
}

/// What a set holds is counted apart from what a frame holds, with the
/// same split `children` lists: five children in flight across
/// the two sets, and eleven futures held in frames beside them.
///
/// The census counts a find wherever the scan reached it, so nesting
/// moves nothing between the two populations — a future held inside a
/// set child is held in a frame like any other.
#[test]
fn test_census_counts_a_set_and_what_is_held_beside_it() {
    let bundle = fixtures().bundle("unordered");
    with_core("unordered", |core| {
        let out = hansei_ok(&bundle, core, "census");
        assert!(
            out.contains(
                "   11  frame (off any await chain)\n    \
                 5  set (2 FuturesUnordered)\n"
            ),
            "{out}"
        );
        // The leaves are what the nesting added: one per set child, two
        // the driver holds inside a tuple and an enum, two more in its
        // map's buckets, the nested set's own two children, and the one
        // carried by the future the driver holds for it — none of them
        // ever polled.
        assert!(
            out.contains("   10  async fn unordered::leaf\n       └─ 10  — (unresumed)\n"),
            "{out}"
        );
        // What all five of them are — the set's children and the two
        // held beside them are the same async fn, the boxed one named
        // through the dyn join rather than by its pointer — and, under
        // it, what those five chains reach. The children park in the
        // shared Notify, the resource their chains end in under its
        // rule; the two held beside them were never polled, which is
        // what leaves the Notify branch at three of the five.
        assert!(
            out.contains(
                "    5  async fn unordered::set_member\n       \
                 ├─ 3  notify rx\n       \
                 └─ 2  — (unresumed)\n"
            ),
            "{out}"
        );
    });
}

/// The scheduler state and the drivers, both read out of the target
/// through the bundle's layouts rather than a mirror of tokio's structs.
#[test]
fn test_shared_state_and_drivers() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "runtime");
        assert!(out.contains("multi_thread::worker::Shared"), "{out}");
        assert!(out.contains("owned:"), "{out}");
        assert!(out.contains("inject:"), "{out}");
        assert!(out.contains("num_workers:"), "{out}");

        assert!(out.contains("runtime::driver::Handle"), "{out}");
        assert!(out.contains("io:"), "{out}");
        assert!(out.contains("time:"), "{out}");
        // The block's own worker count is the scheduler's own.
        assert!(out.contains("\n    workers: 2\n"), "{out}");
        assert!(out.contains("num_workers: 2"), "{out}");
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
        assert!(out.contains("src/bin/simple-await.rs:51"), "{out}");

        // The locals held across that await — and only those. The
        // arguments rustc also lists here belong to `Unresumed`, whose
        // offsets they still carry, so they are not part of this state.
        let out = hansei_ok(&bundle, core, &format!("type {future}::Suspend1"));
        assert!(out.starts_with("struct "), "{out}");
        for local in ["count", "first", "owned", "labels"] {
            assert!(out.contains(local), "{local} missing from {out}");
        }
        for gone in ["ready", "park"] {
            assert!(!out.contains(gone), "{gone} still in {out}");
        }

        // The states that do own them keep them, and this is the whole
        // of the rule: the same two names, dead at one await and live
        // at the other. `Unresumed` holds the arguments as passed;
        // `Suspend0` is the await on line 32, before `ready.send(())`
        // on 33 and before `park` moves into the awaitee on 34, so both
        // are still live there and rustc has relocated them off the
        // argument offsets. Asserting only their absence from Suspend1
        // would pass just as well for an extractor that dropped every
        // copy it found.
        for state in ["Unresumed", "Suspend0"] {
            let out = hansei_ok(&bundle, core, &format!("type {future}::{state}"));
            for arg in ["ready", "park"] {
                assert!(out.contains(arg), "{arg} missing from {state}:\n{out}");
            }
        }

        let out = hansei_ok(&bundle, core, "find-types simple_await::");
        assert!(out.contains(future), "{out}");
        assert!(out.trim_end().ends_with(" types]"), "{out}");
    });
}

/// A member line names its type and stops there, so reading a nested
/// layout otherwise means asking again for every name it mentions.
/// `-r` asks once, and opens each type under the line that named it.
#[test]
fn test_type_recursive_nests_what_the_layout_names() {
    let bundle = fixtures().bundle("simple-await");
    let future = "simple_await::work::{async_fn_env#0}";
    with_core("simple-await", |core| {
        let shallow = hansei_ok(&bundle, core, &format!("type {future}"));
        let deep = hansei_ok(&bundle, core, &format!("type -r -d 99 {future}"));

        // The same target described either way; only what hangs off it
        // differs, so the two agree down to the first member line.
        assert_eq!(deep.lines().next(), shallow.lines().next(), "{deep}");

        // Nothing but the recursion reaches a coroutine state's locals
        // — the enum above names only its variants — nor, past those,
        // the channel the task is parked on. Each arrives under the
        // line that named it rather than in a listing of its own.
        assert!(!shallow.contains("oneshot::Receiver"), "{shallow}");
        nested_under(&deep, "owned", "alloc::string::String");
        nested_under(&deep, "data", "tokio::sync::oneshot::Inner<u32>");

        // Crossing a pointer starts a frame of its own, so what it
        // addresses is named again on a line of its own.
        assert!(
            deep.contains("→ struct alloc::sync::ArcInner<tokio::sync::oneshot::Inner<u32>>"),
            "{deep}"
        );

        // A `labels` local is a BTreeMap, whose internal nodes hold a
        // leaf node of the same type: the walk stops rather than nest
        // for ever.
        assert!(deep.contains("(described above)"), "{deep}");

        // Base types are left to the lines that name them: `count  u32`
        // says everything a definition of `u32` would.
        assert!(!deep.contains("base u32"), "{deep}");

        // Followed all the way there is nothing left over to mark, and
        // `-d` is what leaves some: a bound rendering is shorter, and
        // says on which lines it stopped short.
        assert!(!deep.contains(" …"), "{deep}");
        let bounded = hansei_ok(&bundle, core, &format!("type -r -d 1 {future}"));
        assert!(bounded.contains(" …"), "{bounded}");
        assert!(
            bounded.lines().count() < deep.lines().count(),
            "-d 1 is no shorter than -d 99:\n{bounded}"
        );

        // A depth with nothing to bound is a mistake worth naming, not
        // a silent no-op.
        let out = hansei(&bundle, core, &format!("type -d 2 {future}"));
        assert!(!out.status.success(), "{bounded}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("--recursive"), "{stderr}");
    });
}

/// Assert that a member line naming `member` at type `ty` is followed
/// by that type's own layout, indented under it.
fn nested_under(out: &str, member: &str, ty: &str) {
    let indent = |line: &str| line.len() - line.trim_start().len();
    let mut lines = out.lines();
    while let Some(line) = lines.next() {
        let mut fields = line.split_whitespace();
        let names_it = fields.next().is_some_and(|f| f.starts_with('+'))
            && fields.next() == Some(member)
            && fields.next() == Some(ty);
        if names_it && lines.next().is_some_and(|next| indent(next) > indent(line)) {
            return;
        }
    }
    panic!("nothing is nested under a `{member}` member of {ty}:\n{out}");
}

/// The allocator index, on whichever kind of target this host makes.
///
/// umem is per-process opt-in, so which branch runs is the system's
/// choice rather than the test's: an illumos process here has libumem
/// mapped and the walk has real metadata to read, while a Linux one
/// runs on glibc's malloc and there is nothing to read at all. Both are
/// the same requirement — the session attaches, builds, and answers,
/// saying what it cannot claim rather than failing or guessing.
#[test]
fn test_the_allocator_index_answers_for_what_it_can_read() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "umem-audit");
        if out.contains("no umem metadata in this target") {
            // Nothing to corroborate with, and the session carries on
            // — `whatis` included, which says nothing about an
            // allocation rather than saying it does not know.
            let out = hansei_ok(&bundle, core, "umem-audit 0x1000 ; tasks");
            assert!(out.contains("no umem metadata in this target"), "{out}");
            assert!(out.contains("\n[1 task]\n"), "{out}");
            let out = hansei_ok(&bundle, core, "whatis 0x1000");
            assert!(!out.contains("Status:"), "{out}");
            return;
        }

        // A real index: caches with buffers in them, every invariant it
        // claims about itself holding, and every layer of the
        // allocator read -- the magazines and the depot, the threads'
        // own caches, and the two arenas `malloc` allocates out of,
        // which are the layers a walk of the slabs alone would miss.
        assert!(out.contains("umem_alloc_"), "{out}");
        assert!(out.contains("self-check: clean"), "{out}");
        assert!(!out.contains("declined:"), "{out}");
        assert!(!out.contains("not walked:"), "{out}");
        assert!(out.contains("umem_oversize"), "{out}");
        assert!(out.contains("umem_memalign"), "{out}");
        let live = regex::Regex::new(r"live: (\d+) chunk")
            .unwrap()
            .captures(&out)
            .unwrap_or_else(|| panic!("no live chunk count in {out}"))[1]
            .parse::<u64>()
            .unwrap();
        assert!(live > 0, "{out}");

        // And a verdict on an address it named itself: the enumeration
        // and the lookup are separate walks of the same metadata, so
        // one has to agree with the other.
        let dump = hansei_ok(&bundle, core, "umem-audit --dump live");
        assert_eq!(dump.lines().count() as u64, live, "the dump is the count");
        let chunk = dump.lines().next().expect("a live chunk").to_string();
        let out = hansei_ok(&bundle, core, &format!("umem-audit {chunk}"));
        assert!(out.contains(&format!("{chunk}: live, in umem_")), "{out}");

        // The same of the arenas, whose allocations are in no cache and
        // so in neither set above: what the table counts is what the
        // dump lists, and an address it named is one the lookup places
        // in the arena that named it.
        let arenas = regex::Regex::new(r"(?m)^(umem_(?:oversize|memalign)) +\d+ +(\d+) ")
            .unwrap()
            .captures_iter(&out)
            .map(|row| row[2].parse::<usize>().unwrap())
            .sum::<usize>();
        let dump = hansei_ok(&bundle, core, "umem-audit --dump arena-live");
        assert_eq!(dump.lines().count(), arenas, "the dump is the count");
        if let Some(extent) = dump.lines().next() {
            let out = hansei_ok(&bundle, core, &format!("umem-audit {extent}"));
            assert!(out.contains(&format!("{extent}: live, in umem_")), "{out}");
        }

        // And what `whatis` makes of the same address: the verdict in
        // the allocation's own terms, with no allocator vocabulary in
        // it at all -- which is the whole point of the block, and what
        // would go wrong first if a verdict were wrong.
        let out = hansei_ok(&bundle, core, &format!("whatis {chunk}"));
        assert!(out.starts_with("Status: live\nSize:   "), "{out}");
        assert!(!out.contains("umem"), "{out}");

        // The render gates are attached to what a value-printing
        // command actually prints, and their tally is where a gate that
        // fired says so. A healthy fixture gives them nothing to refuse,
        // which is the assertion: the corroboration is on, and it
        // changes nothing about a target whose pointers are all good.
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async fn simple_await::work");
        let out = hansei_ok(&bundle, core, &format!("trace {} -v ; umem-audit", task.id));
        // Every container the task holds still renders whole: no read
        // was refused and no extent cut anywhere in the chain, which is
        // what the tally then says in numbers.
        assert!(
            out.contains(r#"owned: alloc::string::String = "owned\ttext""#),
            "{out}"
        );
        assert!(!out.contains("past its allocation"), "{out}");
        assert!(!out.contains("<freed"), "{out}");
        assert!(
            out.contains(
                "gates: 0 pointer(s) into freed memory, 0 sequence(s) cut to \
                 their allocation"
            ),
            "{out}"
        );
    });
}

/// The render gates, on a target that gives them something to refuse.
///
/// Every other fixture here is healthy, so the corroboration declines
/// nothing when the suite runs and a gate wired to nothing would pass
/// every one of those tests. `stale-local` parks a task holding the
/// addresses of two blocks it has handed back, a thin pointer's and a
/// boxed future's, which are exactly the pointers the renderer must
/// not follow — on a target whose allocator is libumem. On glibc there
/// is no allocator to ask, and the same frame renders the way it always
/// did, which is the other half of the claim.
#[test]
fn test_a_stale_pointer_is_not_expanded_into_what_the_bytes_say() {
    let bundle = fixtures().bundle("stale-local");
    with_core("stale-local", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async fn stale_local::holder");
        let out = hansei_ok(&bundle, core, &format!("trace {} -v ; umem-audit", task.id));
        assert!(out.contains("stale"), "{out}");
        if out.contains("no umem metadata in this target") {
            assert!(!out.contains("<freed"), "{out}");
            return;
        }
        // The block is free wherever the allocator is keeping it — a
        // per-CPU magazine, most likely, since a free reaches a slab's
        // freelist only when that magazine fills.
        assert!(out.contains("-> <freed>"), "{out}");
        // Two refusals, one per stale pointer. The boxed future's is a
        // wide pointer whose concrete type the renderer recovers from
        // the vtable's function symbols, joined against the bundle's
        // dyn-future table; with the type in hand it reads the value at
        // the far end, and that read is the gate's to refuse like the
        // thin pointer's. The census never follows the wide pointer at
        // all, below.
        assert!(
            out.contains("gates: 2 pointer(s) into freed memory"),
            "{out}"
        );
        assert!(out.contains("self-check: clean"), "{out}");
    });
}

/// The census's half of the same claim, on the same target.
///
/// `stale-local` also parks holding the wide pointer of a boxed future
/// whose block it has handed back — a raw `*mut dyn Future`, which is
/// nobody's to follow: the census follows a pointer only by a
/// contract, a set's node list or a supported adapter's recorded
/// route, and a raw pointer has neither. So the future behind it is
/// never read, on either allocator: nothing is listed, and nothing is
/// refused, since the walk never stood at the far end.
#[test]
fn test_a_stale_future_is_not_counted_as_one_in_flight() {
    let bundle = fixtures().bundle("stale-local");
    with_core("stale-local", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async fn stale_local::holder");
        let out = hansei(&bundle, core, &format!("task {} children", task.id));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}\n{stdout}");

        // The count `tasks` prints and the listing `children` prints
        // are the same census, so both say none.
        assert_eq!(task.futures, "0", "{rows:?}");
        assert!(stdout.starts_with("held futures: 0\n"), "{stdout}");
        assert!(stderr.is_empty(), "{stderr}");
    });
}

/// `--exec` asks from the command line what a pipeline would ask on
/// stdin, and the session exits with its answer.
#[test]
fn test_exec_asks_from_the_command_line() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        // Two commands in one flag, and a second flag after it: both
        // spellings of "more than one question".
        let out = hansei_exec(&bundle, core, &["info ; config depth 1; runtime", "tasks"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "--exec failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("symbols resolved:"), "{stdout}");
        assert!(stdout.contains("runtime::driver::Handle"), "{stdout}");
        assert!(stdout.contains("\n[1 task]\n"), "{stdout}");

        // A failure is fatal, as it is in a script.
        let out = hansei_exec(&bundle, core, &["trace 99999"]);
        assert!(!out.status.success(), "{stdout}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("no task 99999 ("), "{stderr}");
    });
}

/// A line can hold several commands, separated by `;`: they are asked
/// of the one attached target in order, and a failure part-way through
/// stops the rest rather than carrying on past a question that could
/// not be answered.
#[test]
fn test_a_line_can_hold_several_commands() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "info ; runtime");
        assert!(out.contains("symbols resolved:"), "{out}");
        assert!(out.contains("runtime::driver::Handle"), "{out}");

        let out = hansei(&bundle, core, "info ; trace 99999 ; runtime");
        assert!(
            !out.status.success(),
            "a failing command must end the line:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        // The first command answered, the third never ran, and the
        // complaint names the one in between.
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("symbols resolved:"), "{stdout}");
        assert!(!stdout.contains("runtime::driver::Handle"), "{stdout}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("in `trace 99999`"), "{stderr}");
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
        // The prefix names the command; its arguments are never
        // inferred. `regs` sits beside `runtime` and `runtimes`, so
        // `r` fits all three, `ru` the two runtime commands, and only
        // the full words name one.
        assert!(hansei_ok(&bundle, core, "runtimes").contains("multi_thread"));
        assert!(hansei_ok(&bundle, core, "runtime").contains("runtime::driver::Handle"));
        let out = hansei(&bundle, core, "r");
        assert!(
            !out.status.success(),
            "a prefix of three commands must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        for candidate in ["regs", "runtime", "runtimes"] {
            assert!(err.contains(candidate), "{candidate} missing from {err}");
        }
        let out = hansei(&bundle, core, "ru");
        assert!(
            !out.status.success(),
            "a prefix of two commands must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );

        // The singular selectors sit beside their plurals, so every
        // proper prefix of `threads` fits `thread` too: only the full
        // word names the listing now, and `thr` is refused naming
        // both.
        assert!(hansei_ok(&bundle, core, "threads").contains("LWP"));
        let out = hansei(&bundle, core, "thr -f 0");
        assert!(
            !out.status.success(),
            "a prefix of two commands must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        for candidate in ["thread", "threads"] {
            assert!(err.contains(candidate), "{candidate} missing from {err}");
        }

        let out = hansei(&bundle, core, "t");
        assert!(
            !out.status.success(),
            "an ambiguous prefix must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        for candidate in ["task", "tasks", "thread", "threads", "trace", "type"] {
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

/// Run hansei against `core` with exactly the `--binary` given, past
/// the helper that would otherwise fill one in.
fn hansei_with_binary(bundle: &Path, core: &Path, binary: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hansei"));
    command
        .arg("--tokio-info")
        .arg(bundle)
        .arg("--core")
        .arg(core);
    if let Some(binary) = binary {
        command.arg("--binary").arg(binary);
    }
    command
        .arg("--exec")
        .arg("info")
        .output()
        .expect("failed to run hansei")
}

/// A Linux core carries no symbol table, so the executable it was taken
/// from is a required third input rather than a convenience. An illumos
/// core carries its own symbols, and says so rather than taking a flag
/// it would not use.
#[test]
fn test_binary_required_for_a_linux_core() {
    with_core("simple-await", |core| {
        let bundle = fixtures().bundle("simple-await");
        let out = hansei_with_binary(&bundle, core, None);
        let stderr = String::from_utf8_lossy(&out.stderr);

        if !Proc::open_core(core).expect("core opens").needs_binary() {
            assert!(
                out.status.success(),
                "a core carrying its own symbols needs no --binary:\n{stderr}"
            );
            return;
        }

        assert!(
            !out.status.success(),
            "a Linux core without --binary must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            stderr.contains("--binary is required"),
            "diagnostic does not name the missing input:\n{stderr}"
        );
        // The failure this replaces blamed the tokio info for a missing
        // file, which sent the reader after the wrong thing entirely.
        assert!(
            !stderr.contains("does not match this binary"),
            "a missing executable must not read as a tokio-info mismatch:\n{stderr}"
        );
    });
}

/// The debug build the tokio info came from resolves every symbol name
/// and shares none of the addresses, so the fingerprint cannot see the
/// substitution — the build id is what catches it.
#[test]
fn test_wrong_binary_refused_by_build_id() {
    with_core("simple-await", |core| {
        if !Proc::open_core(core).expect("core opens").needs_binary() {
            return;
        }
        let bundle = fixtures().bundle("simple-await");
        // A different fixture: a real binary, so it opens and parses,
        // and its build id is necessarily another one.
        let wrong = fixtures().program("futurelock");

        let out = hansei_with_binary(&bundle, core, Some(&wrong));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "the wrong executable must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            stderr.contains("is not the binary this core was taken from"),
            "diagnostic does not name the mismatch:\n{stderr}"
        );
        assert!(
            stderr.contains("--force"),
            "diagnostic does not mention the override:\n{stderr}"
        );

        // `--force` downgrades it, as it does the fingerprint.
        let mut forced = Command::new(env!("CARGO_BIN_EXE_hansei"));
        let out = forced
            .arg("--tokio-info")
            .arg(&bundle)
            .arg("--core")
            .arg(core)
            .arg("--binary")
            .arg(&wrong)
            .arg("--force")
            .arg("--exec")
            .arg("info")
            .output()
            .expect("failed to run hansei");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("output may be wrong"),
            "--force must warn rather than refuse:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
}

/// The connection listing over the fixture that holds connections: the
/// four clients — two idle in their pools, two awaiting a parked GET's
/// response — and the five servers: two idle, two running the parked
/// handler, and one still choosing its version. One row names a peer:
/// the idle client whose pool keeps a timer, and so a reaper the census
/// reaches the pool through, is named by its pool key's authority, the
/// listener's loopback address. No other row names a peer or a server:
/// hyper keeps neither on either side, a pool with no reaper is reached
/// by nothing, and the fixture's service is its own closure, which no
/// reviewed convention says stores them (dropshot's does). The idle
/// servers have
/// armed their header-read timers, whose deadlines are masked whole —
/// their form is the system's — and whose waits beside the phase only
/// an illumos core, which records when the process stopped, can put a
/// length to. Grouping by phase files the nine under four buckets, and
/// a filter on the role keeps the servers.
///
/// The two clients awaiting a response name the task that sent their
/// request, and no other row names a caller.
///
/// The rows are compared without their task cell, with the caller's id
/// masked, and in sorted order. Every connection is parked by the
/// time the core is taken — that is what `READY` waits for — but the
/// ids tokio hands the parked request's tasks are not the fixture's to
/// order: its
/// connection task is spawned by hyper-util's client inside
/// `client.request()` on the requester's worker, the server's by the
/// accept loop on the other, and the client's pool spawns background
/// tasks of its own between them, so the same capture assigns the ids
/// in either order.
#[test]
fn test_http_conns_connections_acceptance() {
    let bundle = fixtures().bundle("http-conns");
    with_core("http-conns", |core| {
        let out = hansei_ok(&bundle, core, "connections");
        assert!(out.ends_with("[9 connections]\n"), "{out}");
        // The listener's port is the kernel's to pick, so the URL the
        // reqwest requester sent, and the key each client's pool keeps
        // its connection under, are compared with it masked.
        let port = regex::Regex::new(r"127\.0\.0\.1:\d+").unwrap();
        // The idle server's deadline — relative where the core records
        // when the process stopped, else on the monotonic clock — and
        // its wait, which only the former can give.
        let deadline =
            regex::Regex::new(r"\+\d+\.\d{3}s|\d+\.\d{3}s on the target's monotonic clock")
                .unwrap();
        let waited = regex::Regex::new(r"idle \((\d+ms|\d+\.\d{3}s)\)").unwrap();
        assert_eq!(
            waited.find_iter(&out).count(),
            2 * usize::from(cfg!(target_os = "illumos")),
            "{out}"
        );
        let lines: Vec<Vec<&str>> = out
            .lines()
            .skip(1)
            .take(9)
            .map(|line| line.split_whitespace().collect())
            .collect();
        // A caller is a task, one per request in flight, and never one
        // that drives a connection.
        let drivers: Vec<&str> = lines.iter().map(|cells| cells[0]).collect();
        let mut callers: Vec<&str> = lines
            .iter()
            .map(|cells| cells[1])
            .filter(|&caller| caller != "—")
            .collect();
        for caller in &callers {
            assert!(caller.parse::<u64>().is_ok(), "{caller}: {out}");
            assert!(!drivers.contains(caller), "{caller}: {out}");
        }
        callers.sort_unstable();
        callers.dedup();
        assert_eq!(callers.len(), 2, "{out}");
        let mut rows: Vec<String> = lines
            .iter()
            .map(|cells| {
                let caller = if cells[1] == "—" { "—" } else { "CALLER" };
                let row = std::iter::once(caller)
                    .chain(cells[2..].iter().copied())
                    .collect::<Vec<&str>>()
                    .join(" ");
                let row = port.replace_all(&row, "127.0.0.1:PORT");
                let row = deadline.replace_all(&row, "DEADLINE");
                waited.replace_all(&row, "idle").into_owned()
            })
            .collect();
        rows.sort();
        assert_eq!(
            rows,
            [
                "CALLER http1 client awaiting response — — 127.0.0.1:PORT — GET http://127.0.0.1:PORT/park",
                "CALLER http1 client awaiting response — — 127.0.0.1:PORT — GET —",
                "— http1 client idle — — 127.0.0.1:PORT — — —",
                "— http1 client idle — — — — — —",
                "— http1 server handling request — — — — GET /park",
                "— http1 server handling request — — — — GET /park",
                "— http1 server idle DEADLINE — — — — —",
                "— http1 server idle DEADLINE — — — — —",
                "— http1 server negotiating — — — — — —",
            ],
            "{out}"
        );
        let grouped = hansei_ok(&bundle, core, "connections --group phase");
        for bucket in [
            "4  idle",
            "2  awaiting response",
            "2  handling request",
            "1  negotiating",
        ] {
            assert!(grouped.contains(bucket), "{grouped}");
        }
        let servers = hansei_ok(&bundle, core, "connections --with role server");
        assert!(servers.ends_with("[5 connections]\n"), "{servers}");
        assert!(!servers.contains("client"), "{servers}");
        // The request reaches a filter, on either side of the exchange.
        let parked = hansei_ok(&bundle, core, "connections --with request park");
        assert!(parked.ends_with("[3 connections]\n"), "{parked}");
    });
}

/// The connection listing over the fixture that holds TLS and TCP
/// connections: every socket a task parks reading or writing is a row,
/// once however many of its reads and writes are pending. The TLS
/// clients reading directly and through a split's halves, the servers
/// reading directly and through a boxed `BufStream`, all established;
/// the client that sent its close_notify, closing; and the TCP client
/// reading and writing through owned halves and the server reading its
/// bare stream, open. No row names a peer — the fixture has no
/// sprockets stream, the one this listing reads a peer from. The
/// HTTP/1 pair over TLS is two rows of their own, idle between
/// exchanges, each keyed by its socket as the listing reaches it
/// through the dispatcher's stream. The two handshakes in progress are
/// rows too, handshaking,
/// and each task driving one waits on its socket as handshaking, not
/// as a read — both for the peer's first flight. Every connection
/// through TLS has nothing queued to send, but the client whose writes
/// filled its socket: the records its connection kept, unwritten, are
/// its `SENDQ`, the one row a filter on it keeps, and the words its
/// read's wait carries. The tasks parked on anything but a socket are
/// no rows. Grouping by protocol files the twelve under three buckets,
/// and a filter on it keeps the TCP pair.
#[test]
fn test_tls_conns_connections_acceptance() {
    let bundle = fixtures().bundle("tls-conns");
    with_core("tls-conns", |core| {
        let out = hansei_ok(&bundle, core, "connections");
        assert!(out.ends_with("[12 connections]\n"), "{out}");
        // How much the socket took before it refused is the kernel's
        // to say: a nonzero `SENDQ` reads as `N`.
        let mut rows: Vec<String> = out
            .lines()
            .skip(1)
            .take(12)
            .map(|line| {
                let mut cells: Vec<&str> = line.split_whitespace().skip(1).collect();
                if cells[5].parse::<u64>().is_ok_and(|queued| queued > 0) {
                    cells[5] = "N";
                }
                cells.join(" ")
            })
            .collect();
        rows.sort();
        assert_eq!(
            rows,
            [
                "— http1/tls client idle — 0 — — — —",
                "— http1/tls server idle — 0 — — — —",
                "— tcp — open — — — — — —",
                "— tcp — open — — — — — —",
                "— tls client closing — 0 — — — —",
                "— tls client established — 0 — — — —",
                "— tls client established — 0 — — — —",
                "— tls client established — N — — — —",
                "— tls client handshaking — 0 — — — —",
                "— tls server established — 0 — — — —",
                "— tls server established — 0 — — — —",
                "— tls server handshaking — 0 — — — —",
            ],
            "{out}"
        );
        let grouped = hansei_ok(&bundle, core, "connections --group proto");
        for bucket in ["8  tls", "2  tcp", "2  http1/tls"] {
            assert!(grouped.contains(bucket), "{grouped}");
        }
        let queued = hansei_ok(&bundle, core, "connections --with sendq >0");
        assert!(queued.ends_with("[1 connection]\n"), "{queued}");
        let tasks = list_tasks(&bundle, core);
        let unflushed = task_with_future(&tasks, "async fn tls_conns::unflushed_client");
        let block = hansei_ok(&bundle, core, &format!("task {}", unflushed.id));
        let unsent = regex::Regex::new(r"(?m)^        tls: client, TLSv1_3, established, .* written, [1-9][0-9]* unsent \([0-9]+ bytes\)$")
            .unwrap();
        assert!(unsent.is_match(&block), "{block}");
        for side in ["client", "server"] {
            let task = task_with_future(&tasks, &format!("async fn tls_conns::handshaking_{side}"));
            assert!(
                task.waiting.starts_with("handshaking fd ")
                    && task.waiting.ends_with(" (readable)"),
                "{task:?}"
            );
        }
        let tcp = hansei_ok(&bundle, core, "connections --with proto tcp");
        assert!(tcp.ends_with("[2 connections]\n"), "{tcp}");
        assert!(!tcp.contains(" tls "), "{tcp}");
    });
}

/// The waker slots over the fixture built for them. The selector's
/// `select!` parks its waker in four places the registries do not all
/// reach, and the merged `WAITING ON` cell names every one by what
/// holds it: the oneshot's receiver slot, the channel's receiver slot,
/// the watch's `Notify` node and the wheel entry. The holder's cell is
/// its oneshot alone, while the `Notified` it keeps unpolled is the one
/// find nothing arms; the waiter's `Notify` keeps its reader's
/// spelling; the driver's own waker sits in the set's ready queue,
/// named by the type holding it. Both audits run clean.
#[test]
fn test_armed_select_acceptance() {
    let bundle = fixtures().bundle("armed-select");
    with_core("armed-select", |core| {
        let rows = list_tasks(&bundle, core);
        let selector = task_with_future(&rows, "async fn armed_select::selector");
        // A real core holds the watch's `Shared`, so its `Notified` is
        // the watch's, where a snapshot could only say `notify`. Each
        // slot carries its primitive's words: the one sender kept in
        // `main` and the bound of four, the leaked oneshot sender, the
        // watch never sent to. The set's cell is its lines, which
        // stand under a bare wait label.
        assert_eq!(selector.waiting, "", "{selector:?}");
        let listed = selector.wait_lines.join("\n");
        for word in [
            "mpsc rx 0x",
            "1 sender, capacity 4, 0 unread",
            "watch rx 0x",
            "version 0, 1 sender, 1 receiver",
            "oneshot rx 0x",
            " (nothing sent, sender alive)",
            "timer (deadline ",
        ] {
            assert!(listed.contains(word), "{selector:?}");
        }
        // The slot and the leaf reader share one bucket per primitive.
        let grouped = hansei_ok(&bundle, core, "tasks --group waiting-on");
        assert!(
            grouped.contains("mpsc rx, oneshot rx, timer, watch rx"),
            "{grouped}"
        );
        // One block per `select!` branch under the wait, each a
        // borrow of the frame's own local, placed in the frame and
        // local holding it, its arm as the line of this task's code
        // it is reached at, the verdict naming the primitive with
        // what the channel reads. The task is idle, so no branch
        // carries an `armed` line: every enabled branch of a pending
        // `select!` on an idle task is armed by construction. The
        // sleep's slot is the wheel entry the registry decoded, on a
        // `waker` line; its arm binds nothing, so it has no arm line
        // and says where tokio writes `Sleep`'s poll instead.
        let block = hansei_ok(&bundle, core, &format!("task {}", selector.id));
        // The branches sit under one `select!:` heading, which is
        // what makes them branches, placed in the frame holding the
        // `select!` at the line it is written on.
        let select = regex::Regex::new(
            r"(?m)^    awaiting on:\n        select!:\n            held in: frame 1\n            awaiting at: [^\n]*armed-select\.rs:49\n            branch 0",
        )
        .unwrap();
        assert!(select.is_match(&block), "{block}");
        let detail = regex::Regex::new(
            r"(?m)^            branch [0-2] \(borrowed\): [^\n]+\n                held in: frame 1 `(once|recv|changed)`\n(                declared at: [^\n]*armed-select\.rs:33\n)?                awaiting at: [^\n]*armed-select\.rs:5[0-2]\n                awaiting on: (mpsc rx|watch rx|oneshot rx) 0x[0-9a-f]+ \([^)]*\)$",
        )
        .unwrap();
        assert_eq!(detail.find_iter(&block).count(), 3, "{block}");
        // Where the frame declares the local follows `held in:` — for
        // `once`, an argument, the `fn`'s own line. `recv` and `changed`
        // are declared and then pinned, and `tokio::pin!` pins by
        // shadowing: two `let`s of one name at two lines, and nothing
        // says which the member is, so neither gets a line.
        let declared = regex::Regex::new(
            r"(?m)^                held in: frame 1 `once`\n                declared at: [^\n]*armed-select\.rs:33$",
        )
        .unwrap();
        assert!(declared.is_match(&block), "{block}");
        assert_eq!(block.matches("declared at:").count(), 1, "{block}");
        // Each primitive stands on a line of its own and carries its
        // whole reading.
        let words = regex::Regex::new(
            r"(?m)^                awaiting on: .*(1 sender, capacity 4, 0 unread|version 0, 1 sender, 1 receiver|nothing sent, sender alive)\)$",
        )
        .unwrap();
        assert_eq!(words.find_iter(&block).count(), 3, "{block}");
        let sleep = regex::Regex::new(
            r"(?m)^            branch 3 \(borrowed\): tokio::time::sleep::Sleep\n                held in: frame 1 `sleep`\n                awaiting on: timer \(deadline [^\n]*\n                type defined at: tokio-[0-9.]+/src/time/sleep\.rs:[0-9]+\n                waker: timer @ 0x[0-9a-f]+$",
        )
        .unwrap();
        assert!(sleep.is_match(&block), "{block}");
        // The oneshot's `poll` is where tokio writes it; a slot named
        // on its branch's `awaiting on` line is not named again.
        assert!(
            block.contains("\n                type defined at: tokio-1.")
                && block.contains("/src/sync/oneshot.rs:"),
            "{block}"
        );
        assert_eq!(block.matches("oneshot rx 0x").count(), 1, "{block}");
        assert!(!block.contains("armed:"), "{block}");
        assert!(!block.contains("location:"), "{block}");
        assert!(!block.contains("will wake:"), "{block}");

        // The holder's leaf is the receiver itself: a verified wait,
        // printed by its reader on the wait line; the one slot agrees
        // with it and adds nothing under it.
        let holder = task_with_future(&rows, "async fn armed_select::holder");
        assert!(holder.waiting.starts_with("oneshot rx 0x"), "{holder:?}");
        assert!(
            holder.waiting.ends_with(" (nothing sent, sender alive)"),
            "{holder:?}"
        );
        assert!(holder.wait_lines.is_empty(), "{holder:?}");
        assert!(holder.wake_lines.is_empty(), "{holder:?}");
        let waiter = task_with_future(&rows, "async fn armed_select::waiter");
        // The waiter's leaf reader walked the list: its state word and
        // the one node it found, on the line that names the primitive.
        assert!(waiter.waiting.starts_with("notify rx 0x"), "{waiter:?}");
        assert!(
            waiter.waiting.ends_with(" (waiting, 1 queued)"),
            "{waiter:?}"
        );
        assert!(waiter.wait_lines.is_empty(), "{waiter:?}");
        let driver = task_with_future(&rows, "async fn armed_select::driver");
        assert_eq!(driver.waiting, "", "{driver:?}");
        // A slot no table names has no primitive to await: the item is
        // the container the census found it in — the set of futures
        // the driver polls, in its own frame — and the slot is the
        // type holding it at its address.
        let [heading, held, site, waker] = driver.wait_lines.as_slice() else {
            panic!("{driver:?}");
        };
        assert!(heading.starts_with("set 0x"), "{driver:?}");
        assert!(heading.ends_with(" in flight)"), "{driver:?}");
        assert_eq!(held, "    held in: frame 0", "{driver:?}");
        assert!(
            site.starts_with("    type defined at: futures-util-"),
            "{driver:?}"
        );
        assert!(waker.starts_with("    waker: "), "{driver:?}");
        assert!(waker.contains("AtomicWaker @ 0x"), "{driver:?}");
        assert!(driver.wake_lines.is_empty(), "{driver:?}");

        // The older field names still select the same cell.
        let by_alias = hansei_ok(&bundle, core, "tasks --with waker 'oneshot rx'");
        assert!(by_alias.contains("armed_select::holder"), "{by_alias}");
        assert!(by_alias.contains("armed_select::selector"), "{by_alias}");
        assert!(!by_alias.contains("armed_select::waiter"), "{by_alias}");
        let by_slots = hansei_ok(&bundle, core, "tasks --with slots 'oneshot rx'");
        assert_eq!(by_alias, by_slots);

        // The finds: the unpolled `Notified` is the one held future
        // nothing arms; the selector's branches are all armed, the
        // oneshot `Receiver` through the slot reached from it.
        let unarmed = hansei_ok(&bundle, core, "futures --with armed no --with kind local");
        assert!(unarmed.contains("`notified`"), "{unarmed}");
        assert!(
            unarmed.contains("future tokio::sync::notify::Notified"),
            "{unarmed}"
        );
        assert!(unarmed.contains("unarmed: notify rx"), "{unarmed}");
        assert!(!unarmed.contains("`once`"), "{unarmed}");
        // The unpolled `Notified` describes its `Notify` by the state
        // word alone: the list is walked only for a verified wait. The
        // cell names the kind; the reading is the block's.
        let notified = regex::Regex::new(r"(?m)^(0x[0-9a-f]+) +\d+ +frame 1, `notified` ").unwrap();
        let block = hansei_ok(
            &bundle,
            core,
            &format!("future {}", &notified.captures(&unarmed).unwrap()[1]),
        );
        assert!(
            block.contains("\n    awaiting on: unarmed: notify rx 0x"),
            "{block}"
        );
        assert!(block.contains(" (waiting)\n"), "{block}");
        assert!(!block.contains("queued)"), "{block}");
        // Its holder is idle, so the block carries no `armed` line:
        // the `unarmed:` prefix on the wait already says it.
        assert!(!block.contains("\n    armed:"), "{block}");
        let armed = hansei_ok(&bundle, core, "futures --with armed yes");
        for local in ["`once`", "`recv`", "`changed`", "`sleep`"] {
            assert!(armed.contains(local), "{armed}");
        }
        let once =
            regex::Regex::new(r"(?m)^(0x[0-9a-f]+) +\d+ +frame 1, `once` .* oneshot rx +yes ")
                .unwrap();
        assert!(once.is_match(&armed), "{armed}");
        let block = hansei_ok(
            &bundle,
            core,
            &format!("future {}", &once.captures(&armed).unwrap()[1]),
        );
        // One slot is the wait: its account is the wait line, with
        // nothing under it, and the idle holder means no `armed` line.
        assert!(
            block.contains("\n    awaiting on: oneshot rx 0x"),
            "{block}"
        );
        assert!(block.contains(" (nothing sent, sender alive)\n"), "{block}");
        assert!(!block.contains("waker 0:"), "{block}");
        assert!(!block.contains("\n    armed:"), "{block}");

        // The channels as resources: one block per oneshot a slot
        // names — the selector's, the holder's, the ticker's, and the
        // two the set's children park on with the set's wakers, owned
        // by the child — each with the leaked sender alive; the mpsc
        // and the watch under `channels`, with the selector on the
        // receiving side.
        let oneshots = hansei_ok(&bundle, core, "sync --kind oneshot");
        assert_eq!(oneshots.matches("oneshot 0x").count(), 5, "{oneshots}");
        assert_eq!(
            oneshots.matches(": nothing sent, sender alive\n").count(),
            5,
            "{oneshots}"
        );
        assert!(
            oneshots.contains(&format!("\n    rx: task {}\n", selector.id)),
            "{oneshots}"
        );
        assert!(
            oneshots.contains(&format!("\n    rx: task {}\n", holder.id)),
            "{oneshots}"
        );
        let child = regex::Regex::new(&format!(
            r"(?m)^    rx: child [01] of the set at 0x[0-9a-f]+ \(polled by task {}\)$",
            driver.id
        ))
        .unwrap();
        assert_eq!(child.find_iter(&oneshots).count(), 2, "{oneshots}");
        assert!(!oneshots.contains("tx:"), "{oneshots}");
        let channels = hansei_ok(&bundle, core, "channels");
        assert!(channels.contains(&oneshots), "{channels}");
        let mpsc = regex::Regex::new(&format!(
            r"(?m)^mpsc 0x[0-9a-f]+: 1 sender, capacity 4, 0 unread\n    rx: task {}$",
            selector.id
        ))
        .unwrap();
        assert!(mpsc.is_match(&channels), "{channels}");
        let watch = regex::Regex::new(&format!(
            r"(?m)^watch 0x[0-9a-f]+: version 0, 1 sender, 1 receiver\n    rx: task {}$",
            selector.id
        ))
        .unwrap();
        assert!(watch.is_match(&channels), "{channels}");
        assert_eq!(
            hansei_ok(&bundle, core, "sync --kind oneshot,mpsc,watch"),
            channels
        );

        // The interval tasks. The ticker's tick branch — the pinned
        // local its select borrows — reads the timer through the
        // closure, the interval and its box, and is armed by the
        // wheel entry inside the `Sleep` the box holds; no timer line
        // stands on its own under the wait.
        let ticker = task_with_future(&rows, "async fn armed_select::ticker");
        assert_eq!(ticker.waiting, "", "{ticker:?}");
        let block = hansei_ok(&bundle, core, &format!("task {}", ticker.id));
        let tick = regex::Regex::new(
            r"(?m)^            branch 1 \(borrowed\): async fn tokio::time::interval::Interval::tick\n                held in: frame 1 `tick`\n                awaiting on: timer \(deadline [^\n]*(\n                type defined at: [^\n]*)?\n                waker: timer @ 0x[0-9a-f]+$",
        )
        .unwrap();
        assert!(tick.is_match(&block), "{block}");
        assert_eq!(block.matches("timer @ 0x").count(), 1, "{block}");
        assert!(!block.contains("PollFn"), "{block}");
        // The pacer's bare tick: the task's own chain runs the same
        // route to the `Sleep`, a verified timer wait whose one slot
        // is the wheel entry that arms it, as a bare `sleep`'s is; the
        // spare interval's tick it holds unpolled reaches nothing and
        // nothing arms it, its `Sleep` never registered.
        let pacer = task_with_future(&rows, "async fn armed_select::pacer");
        // The deadline is the target's to give, on the wait line; the
        // entry holding the waker is the slot's, under it.
        assert!(pacer.waiting.starts_with("timer (deadline "), "{pacer:?}");
        let [waker] = pacer.wait_lines.as_slice() else {
            panic!("{pacer:?}");
        };
        assert!(waker.starts_with("waker: timer @ 0x"), "{pacer:?}");
        assert!(!waker.contains("deadline"), "{pacer:?}");
        assert!(pacer.wake_lines.is_empty(), "{pacer:?}");
        // The chain, leaf up: the `Sleep`, the box, the closure's
        // `PollFn`, the tick, the task.
        let trace = hansei_ok(&bundle, core, &format!("trace {} -n", pacer.id));
        for frame in [
            r"(?m)^#0 +future +tokio::time::sleep::Sleep$",
            r"(?m)^#1 +future +Pin<Box<tokio::time::sleep::Sleep>>$",
            r"(?m)^#2 +future +core::future::poll_fn::PollFn<tokio::time::interval::Interval::tick::\{async_fn#0\}::\{closure_env#0\}>$",
            r"(?m)^#3 +async fn +tokio::time::interval::Interval::tick$",
            r"(?m)^#4 +async fn +armed_select::pacer$",
        ] {
            assert!(
                regex::Regex::new(frame).unwrap().is_match(&trace),
                "{frame}: {trace}"
            );
        }
        let unarmed = hansei_ok(&bundle, core, "futures --with armed no --with kind local");
        assert!(unarmed.contains("`spare_tick`"), "{unarmed}");
        assert!(unarmed.contains("`spare`"), "{unarmed}");
        assert!(!unarmed.contains("`tick`"), "{unarmed}");
        assert!(!unarmed.contains("`interval`"), "{unarmed}");

        // The forever task: a `select!` every enabled branch of which
        // is never ready is never ready itself, and the verdict is the
        // cell — no slot anywhere, so it is unarmed — with the two
        // branches listed under it, each borrowed from the frame, and
        // the disabled third named by its type alone. The pinned block
        // and the pinned `Ready` are the finds the census lists for
        // it; the bare `Pending` is zero-sized and no find.
        let forever = task_with_future(&rows, "async fn armed_select::forever");
        assert_eq!(forever.waiting, "unarmed: never ready", "{forever:?}");
        let block = hansei_ok(&bundle, core, &format!("task {}", forever.id));
        for line in [
            // Each branch is named in full, generic arguments and
            // all: one line stands for one branch, so what the arm is
            // over is what tells it from its neighbour.
            // Each branch is placed at the line its arm is written on
            // — the disabled one too, whose arm is where its `if
            // false` is — and none carries an `armed` line, the task
            // being idle. The `select!` itself is placed in the frame
            // holding it, at the line it is written on.
            r"(?m)^    awaiting on: unarmed: never ready\n        select!:\n            held in: frame 1\n            awaiting at: [^\n]*armed-select\.rs:169\n            branch 0 \(borrowed\): core::future::pending::Pending<u32>\n                awaiting at: [^\n]*armed-select\.rs:170\n                awaiting on: never ready$",
            r"(?m)^            branch 1 \(borrowed\): async block armed_select::forever::\{async_fn#0\}\n                held in: frame 1 `wrapped`\n                awaiting at: [^\n]*armed-select\.rs:171\n                awaiting on: never ready$",
            r"(?m)^            branch 2: core::future::ready::Ready<u32>: disabled\n                awaiting at: [^\n]*armed-select\.rs:172$",
        ] {
            assert!(
                regex::Regex::new(line).unwrap().is_match(&block),
                "{line}: {block}"
            );
        }
        assert!(!block.contains("PollFn"), "{block}");
        let grouped = hansei_ok(&bundle, core, "tasks --group waiting-on");
        let bucket =
            regex::Regex::new(&format!(r"(?m)^ +1 +unarmed: never ready +{}$", forever.id))
                .unwrap();
        assert!(bucket.is_match(&grouped), "{grouped}");
        let census = hansei_ok(&bundle, core, "census");
        assert!(census.contains("never ready"), "{census}");
        assert!(unarmed.contains("`wrapped`"), "{unarmed}");
        assert!(unarmed.contains("`at_once`"), "{unarmed}");
        assert!(!unarmed.contains("`bare`"), "{unarmed}");

        // Both cross-checks run clean under `--audit`.
        let audited = hansei_with(&bundle, core, &["--audit"], "info");
        let stderr = String::from_utf8_lossy(&audited.stderr);
        assert!(stderr.contains("waker audit: clean"), "{stderr}");
        assert!(stderr.contains("attribution audit: clean"), "{stderr}");
        let info = String::from_utf8_lossy(&audited.stdout);
        assert!(info.contains("; 0 stale\n"), "{info}");
    });
}

/// One crate linked at two releases: the keeper's boxes print through
/// to each release's own `Receiver`, told apart by the listener type
/// the release keeps; each waiter's chain crosses a pin of the same
/// eight bytes as the other's to its own release's `Recv`, and stops
/// on that release's own member; and `find-types` names each release
/// beside its id.
#[test]
fn test_two_releases_acceptance() {
    let bundle = fixtures().bundle("two-releases");
    with_core("two-releases", |core| {
        let rows = list_tasks(&bundle, core);
        assert_eq!(rows.len(), 3, "{rows:#?}");
        let keeper = task_with_future(&rows, "async fn two_releases::keeper");
        let print = |member: &str| {
            hansei_ok(
                &bundle,
                core,
                &format!("task {}; frame 1; print {member}", keeper.id),
            )
        };
        let old = print("old_box");
        assert!(old.contains("-> async_channel::Receiver<u32> {"), "{old}");
        assert!(
            old.contains("listener: core::option::Option<event_listener::EventListener> {"),
            "{old}"
        );
        let new = print("new_box");
        assert!(new.contains("-> async_channel::Receiver<u32> {"), "{new}");
        assert!(
            new.contains("listener: core::option::Option<event_listener::EventListener<()>> {"),
            "{new}"
        );
        // The option and the sender of each release read through to the
        // same channel state, three strong holders each: the box, the
        // option's box and the sender.
        for member in ["old_some", "new_some"] {
            let printed = print(member);
            assert!(
                printed.contains(" = Some(0x")
                    && printed.contains("-> async_channel::Receiver<u32> {"),
                "{printed}"
            );
        }
        for member in ["old_tx", "new_tx"] {
            let printed = print(member);
            assert!(printed.contains("strong: 3,"), "{printed}");
            assert!(
                printed.contains("data: async_channel::Channel<u32> {"),
                "{printed}"
            );
        }

        let old_waiter = task_with_future(&rows, "async fn two_releases::old_waiter");
        let block = hansei_ok(&bundle, core, &format!("task {}", old_waiter.id));
        assert!(
            block.contains("        listener: event_listener::EventListener\n"),
            "{block}"
        );
        let new_waiter = task_with_future(&rows, "async fn two_releases::new_waiter");
        let block = hansei_ok(&bundle, core, &format!("task {}", new_waiter.id));
        assert!(
            block.contains(
                "        _inner: event_listener_strategy::FutureWrapper<async_channel::RecvInner<u32>>\n"
            ),
            "{block}"
        );

        let found = hansei_ok(&bundle, core, "find-types async_channel::Receiver<u32>");
        let both = regex::Regex::new(
            r"(?m)^async_channel::Receiver<u32>  \(2 definitions: type \d+, async-channel 2\.5\.0; type \d+, async-channel 1\.9\.0\)$",
        )
        .unwrap();
        assert!(both.is_match(&found), "{found}");
    });
}

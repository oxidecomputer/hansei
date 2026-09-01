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
use hansei_runtime::tokio::bundle::Context as BundleContext;
use proc::{Proc, Target};

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
    "spin-poll",
    "stale-local",
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
        .file(&dir.join("regen.sh"));
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
            flags,
            unstable,
        }
    })
}

/// The `Spawned at` value a listing reports: the recorded location
/// under tokio_unstable instrumentation, the `-` gap marker without.
fn spawned(loc: &str) -> String {
    if cell().unstable {
        loc.to_owned()
    } else {
        "-".to_owned()
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
        let bin_b = match &cell.name {
            None => fixture_dir.join("bin"),
            Some(name) => fixture_dir.join("bin").join(name),
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
    /// The two source locations, `-` when the target did not record one.
    spawned: String,
    defined: String,
    /// The wait, spelled as the table's cell — `—` for a task waiting
    /// on nothing nameable.
    waiting: String,
    /// The waker slots, `<empty>` where nothing is armed.
    waker: String,
}

/// Run `tasks -v` and parse the block listing: a `Task <id>: <future>`
/// header per task, then one indented `<label>: <value>` line per
/// attribute, then a blank line. Every block carries every attribute, so
/// a field left empty here is a row the listing failed to print.
fn list_tasks(bundle: &Path, core: &Path) -> Vec<TaskRow> {
    let out = hansei_ok(bundle, core, "tasks -v");

    let mut lines = out.lines().peekable();
    let mut rows: Vec<TaskRow> = Vec::new();
    while let Some(line) = lines.peek() {
        let Some(header) = line.strip_prefix("Task ") else {
            break;
        };
        // The id holds no `: `, so the first one separates it from a
        // future name that may well hold more (`<ambiguous: a | b>`).
        let (id, future) = header
            .split_once(": ")
            .unwrap_or_else(|| panic!("unexpected tasks header {line:?}"));
        let mut row = TaskRow {
            id: id.to_string(),
            state: String::new(),
            future: future.to_string(),
            owner: String::new(),
            futures: String::new(),
            sets: String::new(),
            spawned: String::new(),
            defined: String::new(),
            waiting: String::new(),
            waker: String::new(),
        };
        lines.next();

        for line in &mut lines {
            if line.is_empty() {
                break;
            }
            let attr = line
                .strip_prefix("    ")
                .unwrap_or_else(|| panic!("unexpected tasks line {line:?}"));
            // A deeper-indented line is registry detail under the wait
            // row (a wheel entry, an io slot), not an attribute.
            if attr.starts_with(' ') {
                continue;
            }
            let (label, value) = attr
                .split_once(": ")
                .unwrap_or_else(|| panic!("unexpected tasks line {line:?}"));
            let field = match label {
                "State" => &mut row.state,
                "Owner" => &mut row.owner,
                "Held futures" => &mut row.futures,
                "Join sets" => &mut row.sets,
                "Spawned at" => &mut row.spawned,
                "Defined at" => &mut row.defined,
                "Waiting on" => &mut row.waiting,
                "Waker" => &mut row.waker,
                _ => panic!("unexpected tasks attribute {line:?}"),
            };
            assert!(field.is_empty(), "repeated tasks attribute {line:?}");
            *field = value.to_string();
        }
        // Every attribute except the group tag, which only a
        // multi-group population prints.
        for (label, value) in [
            ("State", &row.state),
            ("Held futures", &row.futures),
            ("Join sets", &row.sets),
            ("Spawned at", &row.spawned),
            ("Defined at", &row.defined),
            ("Waiting on", &row.waiting),
            ("Waker", &row.waker),
        ] {
            assert!(!value.is_empty(), "task {} has no {label} row", row.id);
        }
        rows.push(row);
    }

    let footer = lines.next().expect("tasks output has a count footer");
    let plural = if rows.len() == 1 { "" } else { "s" };
    assert_eq!(
        footer,
        format!("{} task{plural}", rows.len()),
        "footer disagrees with the task count"
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
        for column in ["STATE", "AWAITING AT", "WAITING ON", "FUTURE"] {
            assert!(header.contains(column), "{out}");
        }
        let rest: Vec<&str> = lines.collect();
        let (footer, rows) = rest.split_last().expect("the listing has a footer");
        assert_eq!(*footer, format!("{} task", rows.len()), "{out}");
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
    let masked = deadlines.replace_all(out, "deadline TS");
    let masked = overdue.replace_all(&masked, "overdue by TS");
    let masked = tokio_sites.replace_all(&masked, "tokio$1:LINE");
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
    let mut widths = vec![0usize; rows.iter().map(Vec::len).max().unwrap_or(0)];
    for row in &rows {
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
        .filter(|line| !line.starts_with("Spawned at: "))
        .fold(String::new(), |mut text, line| {
            text.push_str(line);
            text.push('\n');
            text
        })
}

/// The `task` selection's `Spawned at` line, which a target carries
/// only under `tokio_unstable` instrumentation.
///
/// Held out of a golden rather than in it: whether the line is there at
/// all is the cell's, not hansei's, and one golden serves every cell.
/// What it says where it is there is [`assert_spawned_at`]'s to check.
fn spawn_line(loc: &str) -> Option<String> {
    cell().unstable.then(|| format!("Spawned at: {loc}"))
}

/// Assert a `task` selection records `loc` as the spawn site — or
/// records no site at all, on a cell whose target could not.
fn assert_spawned_at(trace: &str, loc: &str) {
    let line = trace
        .lines()
        .find(|line| line.starts_with("Spawned at: "))
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

/// The `info` sections against a real core: the process identity out
/// of the core's own notes, the fd table where the system records one,
/// a live capture's signal answer, and the objects survey naming the
/// executable with its symbols and CFI on hand.
#[test]
fn test_info_sections_acceptance() {
    let program = "simple-await";
    let bundle = fixtures().bundle(program);
    with_core(program, |core| {
        let process = hansei_ok(&bundle, core, "info process");
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

        // gcore stops the process rather than crashing it, so the
        // signal section says a live capture outright.
        let signal = hansei_ok(&bundle, core, "info signal");
        assert!(
            signal.contains("signal: none recorded (a live capture, not a crash)"),
            "{signal}"
        );

        let fds = hansei_ok(&bundle, core, "info fds");
        if cfg!(target_os = "linux") {
            assert!(fds.contains("fds: not recorded in a Linux core"), "{fds}");
        } else {
            assert!(fds.contains("fds recorded"), "{fds}");
            // The fixture keeps the standard streams open; fd 0 leads
            // the table.
            assert!(fds.lines().any(|l| l.starts_with("0  ")), "{fds}");
        }

        // The executable row: named, with symbols on hand (the core's
        // own tables on illumos, the --binary the suite supplies on
        // Linux) and its CFI parsed.
        let objects = hansei_ok(&bundle, core, "info objects");
        let exec = objects
            .lines()
            .find(|l| l.contains(program))
            .unwrap_or_else(|| panic!("no row names the executable:\n{objects}"));
        assert!(exec.contains("yes"), "{objects}");

        // The summary carries the new identity lines on both systems.
        let summary = hansei_ok(&bundle, core, "info");
        assert!(summary.contains("pid: "), "{summary}");
        assert!(summary.contains("argv: "), "{summary}");
        assert!(summary.contains("objects: "), "{summary}");
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
    // the task listing off the census, and the wait graph.
    let command = "info\ntasks --futures\ngraph\n";
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
    let command = "info\ntasks --futures\n";
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
        assert_eq!(task.spawned, spawned("src/bin/simple-await.rs:75:21"));
        assert_eq!(task.defined, "src/bin/simple-await.rs:17");

        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", task.id)),
            "src/bin/simple-await.rs:75:21",
        );
        golden(
            "simple-await-trace",
            &Symbols::new().task(&task.id, "work").apply(&out),
        );

        // Exactly these, against a bundle extracted a moment ago: the
        // extractor drops what rustc lists in a state that is not that
        // state's own, and whether it dropped the right things is a
        // question about `simple-await.rs` that only the source
        // answers. Every name here is bound between lines 18 and 37
        // and read again at 40..52, so each has to survive both awaits;
        // `first` is bound *by* the line-38 await. The arguments
        // `ready` and `park` are gone by line 39 — one consumed by
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
        assert_eq!(task.spawned, spawned("src/bin/nested-await.rs:33:21"));
        assert_eq!(task.defined, "src/bin/nested-await.rs:16");

        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", task.id)),
            "src/bin/nested-await.rs:33:21",
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
        assert_eq!(rows.len(), 2, "{rows:#?}");

        let driver = task_with_future(&rows, "async fn dyn_future::driver");
        assert_eq!(driver.state, "idle");
        assert_eq!(driver.spawned, spawned("src/bin/dyn-future.rs:53:21"));
        assert_eq!(driver.defined, "src/bin/dyn-future.rs:24");
        let out = trace(&bundle, core, &driver.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", driver.id)),
            "src/bin/dyn-future.rs:53:21",
        );
        golden(
            "dyn-future-driver-trace",
            &Symbols::new().task(&driver.id, "driver").apply(&out),
        );

        let member = task_with_future(&rows, "async fn dyn_future::set_member");
        assert_eq!(member.state, "idle");
        assert_eq!(member.spawned, spawned("src/bin/dyn-future.rs:28:9"));
        assert_eq!(member.defined, "src/bin/dyn-future.rs:15");
        let out = trace(&bundle, core, &member.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", member.id)),
            "src/bin/dyn-future.rs:28:9",
        );
        golden(
            "dyn-future-member-trace",
            &Symbols::new().task(&member.id, "member").apply(&out),
        );
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
        assert_eq!(task.spawned, spawned("src/bin/futurelock.rs:16:17"));
        assert_eq!(task.defined, "src/bin/futurelock.rs:16");

        // The chain the diagnosis is built on, six frames from the
        // async block down to the semaphore. The wake queue at the
        // bottom names #blocked, which the header at the top is: the
        // task is waiting for a lock it holds itself, spelled once
        // rather than masked into two anonymous ids.
        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", task.id)),
            "src/bin/futurelock.rs:16:17",
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
                "waker: core::option::Option<core::task::wake::Waker>::Some(task {})",
                task.id
            )),
            "{deep}"
        );
    });
}

/// `print` renders memory at an address as a named type: the semaphore
/// address the trace names, pasted back with the type's name, decodes
/// to the same contended state the wait line reported — one permit
/// outstanding, none available, not closed.
#[test]
fn test_print_renders_an_address_as_a_type() {
    let bundle = fixtures().bundle("futurelock");
    with_core("futurelock", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async block futurelock::main::{async_block#0}");
        let out = trace(&bundle, core, &task.id, false);
        let addr = regex::Regex::new(r"semaphore (0x[0-9a-f]+)")
            .unwrap()
            .captures(&out)
            .unwrap_or_else(|| panic!("no semaphore address in {out}"))[1]
            .to_string();

        // The name path, through the semaphore's own formatter: the
        // permit word decodes in place.
        let printed = hansei_ok(
            &bundle,
            core,
            &format!("print {addr} tokio::sync::batch_semaphore::Semaphore"),
        );
        assert!(
            printed.contains("tokio::sync::batch_semaphore::Semaphore"),
            "{printed}"
        );
        assert!(printed.contains("closed=false"), "{printed}");
        assert!(printed.contains("permits=0"), "{printed}");

        // `config ugly on` falls back to the raw structural view: the decoded
        // permit word is gone and the underlying members show as
        // themselves.
        let ugly = hansei_ok(
            &bundle,
            core,
            &format!("config ugly on; print {addr} tokio::sync::batch_semaphore::Semaphore"),
        );
        assert!(!ugly.contains("closed=false"), "{ugly}");
        assert!(ugly.contains("permits"), "{ugly}");

        // A type the bundle does not record is refused with the way to
        // find one that it does.
        let missing = hansei(&bundle, core, &format!("print {addr} no::such::Type"));
        assert!(!missing.status.success());
        assert!(
            String::from_utf8_lossy(&missing.stderr).contains("find-types"),
            "{}",
            String::from_utf8_lossy(&missing.stderr)
        );
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
            assert_eq!(row.spawned, spawned("src/bin/many-tasks.rs:27:13"));
            assert_eq!(row.defined, "src/bin/many-tasks.rs:9");
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
            "src/bin/many-tasks.rs:27:13",
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
            "src/bin/sleep-join.rs:30:22",
        );
        golden("sleep-join-sleeper-trace", &symbols().apply(&out));

        let out = trace(&bundle, core, &joiner.id, false);
        assert_spawned_at(
            &hansei_ok(&bundle, core, &format!("task {}", joiner.id)),
            "src/bin/sleep-join.rs:31:23",
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
            "src/bin/ct-runtime.rs:33:24",
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
        let out = hansei_ok(&bundle, core, "threads -v");
        assert!(
            out.contains("block_on thread of its current_thread runtime"),
            "{out}"
        );
        assert!(!out.contains("not in the scheduler's run loop"), "{out}");

        // And the census's thread section classifies it the same way.
        let out = hansei_ok(&bundle, core, "census --threads");
        assert!(out.contains("1 in the scheduler's run loop"), "{out}");
        assert!(out.contains("block_on thread, lwp"), "{out}");
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
        let rt_tag = regex::Regex::new(r"^runtime 0 @0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&joiner.owner), "{rows:#?}");
        let set_tag = regex::Regex::new(r"^local set 0 @0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
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

        // The listing names the set, its owner thread, its population,
        // and the route that found it — beside the runtime it shares
        // that thread with, which the golden holds too rather than
        // leaving the page's other row unread.
        let out = hansei_ok(&bundle, core, "runtimes -l");
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
        let on_lwp = regex::Regex::new(r"^blocking \(running on lwp \d+\)$").unwrap();
        assert!(on_lwp.is_match(&running.state), "{rows:#?}");
        assert_eq!(queued.state, "blocking (queued)", "{rows:#?}");
        assert_eq!(running.waiting, "—", "{rows:#?}");

        // The join edges point at listed rows, plainly spelled.
        let a = task_with_future(&rows, "async fn blocking_pool::running_waiter");
        assert_eq!(a.waiting, format!("task {}", running.id), "{rows:#?}");
        let b = task_with_future(&rows, "async fn blocking_pool::queued_waiter");
        assert_eq!(b.waiting, format!("task {}", queued.id), "{rows:#?}");
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
        let rt_tag = regex::Regex::new(r"^runtime 0 @0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&spawned.owner), "{rows:#?}");
        let set_tag = regex::Regex::new(r"^local set 0 @0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
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

        // The listing names the route, which is the whole point of
        // the fixture.
        let out = hansei_ok(&bundle, core, "runtimes -l");
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
        assert_eq!(rows.len(), 4, "{rows:#?}");
        let spawned = task_with_future(&rows, "async fn local_set_io::reader");
        let members = ["local_reader", "local_watcher", "local_writer"]
            .map(|name| task_with_future(&rows, &format!("async fn local_set_io::{name}")));

        // The spawned task keeps its runtime's tag — its own waker is on
        // a registration the harvest walks, and being listed is what
        // keeps it out of the candidates.
        let rt_tag = regex::Regex::new(r"^runtime 0 @0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&spawned.owner), "{rows:#?}");
        let set_tag = regex::Regex::new(r"^local set 0 @0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
        for member in &members {
            assert!(set_tag.is_match(&member.owner), "{rows:#?}");
            assert_eq!(member.owner, members[0].owner, "{rows:#?}");
        }

        // Every member reads like any listed task: the awaited chain
        // resolves down to the io leaf each of them parked at.
        for member in &members {
            let out = normalize(&trace(&bundle, core, &member.id, false));
            assert!(out.contains("tokio::net::unix"), "{out}");
        }

        // The listing names the route, which is the whole point of
        // the fixture.
        let out = hansei_ok(&bundle, core, "runtimes -l");
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

        let rt_tag = regex::Regex::new(r"^runtime 0 @0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&joiner.owner), "{rows:#?}");
        // Both of the hidden runtime's tasks carry its tag: the one the
        // joiner named, and the one nothing outside its list points at.
        let hidden_tag =
            regex::Regex::new(r"^runtime 1 @0x[0-9a-f]+ \(current_thread, no thread inside it\)$")
                .unwrap();
        for task in [joined, detached] {
            assert!(hidden_tag.is_match(&task.owner), "{rows:#?}");
        }
        let set_tag = regex::Regex::new(r"^local set 0 @0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
        assert!(set_tag.is_match(&sleeper.owner), "{rows:#?}");

        // The join edge reads like any other now that its target is
        // listed, rather than naming a runtime the session cannot show.
        let out = normalize(&trace(&bundle, core, &joiner.id, false));
        assert!(
            out.contains(&format!("waiting on task {}\n", joined.id)),
            "{out}"
        );
        assert!(!out.contains("does not list"), "{out}");

        // `runtimes` names the runtime and the route to it, and the set
        // that harvesting *its* wheel found. `info` counts them and
        // leaves the naming to the listing.
        // Both rows at once, and the lwps told apart: the set found in
        // the hidden runtime's wheel is pinned to a thread of its own,
        // not the one the main runtime runs on — which two maskings of
        // `lwp \d+` could not have said either way.
        let out = hansei_ok(&bundle, core, "runtimes -l");
        golden(
            "foreign-runtime-runtimes",
            &Symbols::new().columns().apply(&out),
        );

        let info = hansei_ok(&bundle, core, "info");
        assert!(
            info.contains("2 runtimes, 1 local set (see `runtimes --list`)"),
            "{info}"
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
        let lwp = task
            .state
            .strip_prefix("running (lwp ")
            .and_then(|state| state.strip_suffix(')'))
            .unwrap_or_else(|| panic!("the spinner is not running on a worker: {rows:#?}"));

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

        // Without --native the section is elided whole: the chain ends
        // at its last committed frame, no mid-poll heading and no
        // refusal spelling either.
        let bare = hansei(&bundle, core, &format!("trace {}", task.id));
        assert!(
            bare.status.success(),
            "hansei trace failed:\n{}",
            String::from_utf8_lossy(&bare.stderr)
        );
        let bare = String::from_utf8(bare.stdout).expect("hansei output is UTF-8");
        assert!(!bare.contains("mid-poll"), "{bare}");
        assert!(!bare.contains(" native "), "{bare}");

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
/// not tasks — `tasks --futures` lists them under the task that polls
/// the set, `trace -v` labels their queued wakers with that task, and
/// `whatis` resolves a child node address to it.
#[test]
fn test_futures_acceptance() {
    let bundle = fixtures().bundle("unordered");
    with_core("unordered", |core| {
        let rows = list_tasks(&bundle, core);
        let driver = task_with_future(&rows, "async fn unordered::driver");

        // Five held futures, and one set holding three children — the
        // driver's own finds, counted apart from what the census went
        // on to find inside them. The plain listing carries both
        // counts, and says `0` for a task the census found nothing for
        // rather than staying silent; `--futures` lists what each
        // counted, under its own row.
        assert_eq!(driver.futures, "5", "{rows:?}");
        assert_eq!(driver.sets, "1 (3 futures)", "{rows:?}");
        for row in rows.iter().filter(|row| row.id != driver.id) {
            assert_eq!(row.futures, "0", "{row:?}");
            assert_eq!(row.sets, "0", "{row:?}");
        }
        let futures = hansei_ok(&bundle, core, "tasks --futures");
        assert!(
            futures.contains(&format!("Task {}: ", driver.id)),
            "{futures}"
        );
        assert!(
            futures.contains("    Held futures: 5\n        "),
            "{futures}"
        );
        assert!(
            futures.contains("    Join sets: 1 (3 futures)\n        - "),
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
            regex::Regex::new(r"\n            (0x[0-9a-f]+)  async fn unordered::set_member")
                .unwrap();
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
        for local in ["held", "boxed", "pair", "maybe", "nested_hold"] {
            assert!(
                futures.contains(&format!("\n        (frame 1, `{local}`)")),
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
        // a whole set of its own, whose children are deeper again. The
        // tree is the census's attribution, drawn.
        let held_row = r"held \(frame 1, `held`\): 0x[0-9a-f]+  async fn unordered::leaf";
        let under_child =
            regex::Regex::new(&format!(r"\n                {held_row}  Unresumed")).unwrap();
        assert_eq!(under_child.find_iter(&futures).count(), 3, "{futures}");
        assert!(
            futures.contains(
                "\n                - futures_util::stream::futures_unordered::FuturesUnordered\
                 <unordered::leaf> at 0x"
            ),
            "{futures}"
        );
        assert!(
            futures.contains("(frame 1, `inner`): 2 children in flight"),
            "{futures}"
        );
        let under_set = regex::Regex::new(
            r"\n                    0x[0-9a-f]+  async fn unordered::leaf  Unresumed",
        )
        .unwrap();
        assert_eq!(under_set.find_iter(&futures).count(), 2, "{futures}");

        // The same nesting without a set in it: a future the driver
        // holds carries one, so its row sits one step under the row
        // that holds it, inside the `Held futures` block. No `held`
        // mark there — the heading is already the word.
        let carried_row = r"\(frame 0, `inner`\): 0x[0-9a-f]+  async fn unordered::leaf";
        let under_held =
            regex::Regex::new(&format!(r"\n            {carried_row}  Unresumed")).unwrap();
        assert_eq!(under_held.find_iter(&futures).count(), 1, "{futures}");

        // Narrowing to the driver shows its block alone, with the same
        // finds under it: every one of them is the driver's.
        let narrowed = hansei_ok(&bundle, core, &format!("tasks -f --with id {}", driver.id));
        assert!(
            narrowed.starts_with(&format!("Task {}: ", driver.id)),
            "{narrowed}"
        );
        assert!(narrowed.ends_with("\n1 task\n"), "{narrowed}");
        assert!(narrowed.contains("3 children in flight"), "{narrowed}");
        assert!(
            narrowed.contains("    Join sets: 1 (3 futures)\n"),
            "{narrowed}"
        );
        for row in rows.iter().filter(|row| row.id != driver.id) {
            assert!(
                !narrowed.contains(&format!("Task {}: ", row.id)),
                "{narrowed}"
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
        let held = regex::Regex::new(r"\n        \(frame 1, `held`\): (0x[0-9a-f]+)")
            .unwrap()
            .captures(&futures)
            .map(|c| c[1].to_string())
            .expect("the held row prints an address");
        let out = hansei_ok(&bundle, core, &format!("trace {held}"));
        assert!(
            out.contains(&format!(
                "Held by: task {} — async fn unordered::driver (frame 1, `held`)",
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
                "    Held by: task {} — async fn unordered::driver (frame 1, `held`)",
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
        let full = hansei_ok(&bundle, core, "tasks --futures");

        let shallow = hansei_with(&bundle, core, &["--search-depth", "0"], "tasks --futures");
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
        assert!(listed.contains("    Held futures: 3\n"), "{listed}");
        for local in ["held", "boxed", "nested_hold"] {
            assert!(
                listed.contains(&format!("\n        (frame 1, `{local}`)")),
                "{listed}"
            );
        }
        for local in ["pair", "maybe"] {
            assert!(
                !listed.contains(&format!("(frame 1, `{local}`)")),
                "{listed}"
            );
            assert!(full.contains(&format!("(frame 1, `{local}`)")), "{full}");
        }
        // A set is a local in its own right, so its children are
        // walked as ever: the depth limit is a bound on one value's
        // insides, not on how far the census goes.
        assert!(listed.contains("3 children in flight"), "{listed}");

        // And it moves the other way: past what this target needs, the
        // walk is the unbounded one, warning and all.
        let deep = hansei_with(&bundle, core, &["--search-depth", "64"], "tasks --futures");
        let quiet = String::from_utf8_lossy(&deep.stderr);
        assert!(quiet.is_empty(), "{quiet}");
        assert_eq!(String::from_utf8_lossy(&deep.stdout), full);
    });
}

/// A `JoinSet` holds tasks rather than futures: `tasks --futures` lists
/// them under the task that drives the set, by the ids each has a block
/// of its own under — and no futures count moves, because a spawned task
/// is on its own await chain rather than off anybody's.
///
/// One of them has no block to name, being a member of the second set
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

        let futures = hansei_ok(&bundle, core, "tasks --futures");
        assert!(
            futures.contains("    Join sets: 2 (6 tasks)\n        - "),
            "{futures}"
        );
        assert!(
            futures.contains("tokio::task::join_set::JoinSet<u32> at 0x"),
            "{futures}"
        );
        assert!(futures.contains("`): 3 tasks\n"), "{futures}");

        // Every member is named by the id its own block carries, so the
        // set reads as an edge into the listing rather than as a
        // population beside it.
        let member =
            regex::Regex::new(r"\n            task (\d+)  async fn joinset::member").unwrap();
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
        // listing has no block for it and nothing but this set's entry
        // names it — which the row says outright rather than naming a
        // future it cannot reach.
        let done = regex::Regex::new(r"\n            task (\d+)  <complete, awaiting join>")
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
/// sleeper earns a block in the bare listing — so the empty answer
/// belongs to a fixture nothing joins, and the no-contention claim to
/// the semaphore family alone.
#[test]
fn test_sync_prints_nothing_without_contention() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "sync");
        assert_eq!(out, "", "simple-await relates on nothing");
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
/// `Core` it is carrying, plus the stack the unwinder walks out of the
/// core. Worker counts follow the box's CPU count, so what is asserted
/// is the shape of a worker, not how many there are.
#[test]
fn test_threads_shows_workers_and_stacks() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "threads -v");
        // The listing opens with the first lwp's block, and the blank
        // lines fall between blocks — not ahead of them, and not
        // nowhere.
        assert!(out.starts_with("lwp "), "{out}");
        assert!(out.contains("\n\nlwp "), "{out}");
        // The heading claims what each thread is polling, in one of
        // the claim's three spellings.
        let claim =
            regex::Regex::new(r"lwp \d+  (polling no task|polling task \d+|last polled task \d+)")
                .unwrap();
        assert!(claim.is_match(&out), "{out}");
        assert!(out.contains("worker 0"), "{out}");
        // The thread's own tokio context prints ahead of the scheduler
        // state.
        assert!(out.contains("thread_id"), "{out}");
        assert!(out.contains("budget"), "{out}");
        assert!(out.contains("multi_thread::worker::Core"), "{out}");
        assert!(out.contains("is_searching:"), "{out}");
        // The blocking thread holds a runtime context without running
        // the worker loop.
        assert!(out.contains("not in the scheduler's run loop"), "{out}");
        assert!(out.contains("stack:"), "{out}");
        assert!(out.contains("simple_await::main"), "{out}");
    });
}

/// The bare `threads` is a table over every lwp — runtime workers,
/// the threads that merely entered, and the ones holding no runtime
/// at all — one row each, with the block form under -v.
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
        let rows: Vec<&str> = lines.collect();
        // One row per block the -v form prints: the two listings
        // cover the same population.
        let blocks = hansei_ok(&bundle, core, "threads -v");
        assert_eq!(rows.len(), blocks.split("\n\n").count(), "{out}");
        // A worker's row names its place in the run loop; the main
        // thread entered the runtime without running its loop.
        assert!(rows.iter().any(|r| r.contains("worker 0,")), "{out}");
        assert!(rows.iter().any(|r| r.contains("entered runtime")), "{out}");
    });
}

/// `threads` narrows to one thread when its lwp is named: that block
/// alone is printed, and an lwp the listing does not hold is an error
/// naming the ones it does.
#[test]
fn test_threads_selects_one_lwp() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let full = hansei_ok(&bundle, core, "threads -v");
        let first = full.split("\n\n").next().expect("the listing has a block");
        let tid = first
            .strip_prefix("lwp ")
            .and_then(|rest| rest.split_whitespace().next())
            .expect("the block heading names its lwp");

        let one = hansei_ok(&bundle, core, &format!("threads {tid}"));
        assert_eq!(one, format!("{first}\n"), "the lwp selects its block alone");

        // More than one lwp selects each named block, in listing
        // order.
        let mut blocks = full.split("\n\n");
        let (first, second) = (blocks.next().unwrap(), blocks.next().unwrap());
        let second_tid = second
            .strip_prefix("lwp ")
            .and_then(|rest| rest.split_whitespace().next())
            .expect("the second block heading names its lwp");
        let two = hansei_ok(&bundle, core, &format!("threads {tid} {second_tid}"));
        assert_eq!(
            two,
            format!("{first}\n\n{second}\n"),
            "two lwps select their blocks"
        );

        // An lwp no runtime runs on is an error, which fails a
        // scripted session.
        let out = hansei(&bundle, core, "threads 999999");
        assert!(
            !out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("no lwp 999999 ("), "{stderr}");
    });
}

/// Registers print only where they are asked for or earned: a healthy
/// capture's listing carries none, `--registers` puts an annotated
/// block in every selected thread's block, and the stack registers
/// attribute to the thread they were read from.
#[test]
fn test_threads_registers_annotate_on_request() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let plain = hansei_ok(&bundle, core, "threads -v");
        assert!(!plain.contains("registers:"), "{plain}");

        let out = hansei_ok(&bundle, core, "threads --registers");
        let blocks = out.split("\n\n").count();
        assert_eq!(out.matches("  registers:\n").count(), blocks, "{out}");
        // Each block's rsp is that thread's own. The claim names a
        // thread rather than being first-person, so what says it is
        // the block's own lwp: the tid on the rsp line must be the
        // one in the heading above it, in every block.
        let heading = regex::Regex::new(r"(?m)^lwp (\d+)\b").unwrap();
        let rsp =
            regex::Regex::new(r"(?m)^    rsp  0x[0-9a-f]{16}  — \[ stack tid=(\d+) \]$").unwrap();
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

/// `runtimes` selects by listed index and by handle address, and earns
/// headings only from an ambiguity they resolve: one runtime and one
/// section print the value alone.
#[test]
fn test_runtimes_selects_by_index_and_address() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        let out = hansei_ok(&bundle, core, "runtimes -D");
        assert!(out.contains("runtime::driver::Handle"), "{out}");
        assert!(!out.contains("drivers:"), "{out}");
        assert!(!out.contains("(multi_thread):"), "{out}");

        let by_index = hansei_ok(&bundle, core, "runtimes 0 -D");
        assert_eq!(out, by_index, "index 0 selects the one runtime");

        let listed = hansei_ok(&bundle, core, "runtimes -l");
        let addr = regex::Regex::new(r"@(0x[0-9a-f]+)")
            .unwrap()
            .captures(&listed)
            .expect("the listing prints a handle address")[1]
            .to_string();
        let by_addr = hansei_ok(&bundle, core, &format!("runtimes {addr} -D"));
        assert_eq!(out, by_addr, "the listed handle address selects it");

        // Two sections is an ambiguity, and earns each its heading.
        let whole = hansei_ok(&bundle, core, "runtimes");
        assert!(whole.contains("drivers:\n"), "{whole}");
        assert!(whole.contains("\n\nshared:\n"), "{whole}");

        // A runtime the target does not hold is refused with a count,
        // rather than printing the runtimes that were found.
        let out = hansei(&bundle, core, "runtimes 0 3 -D");
        assert!(!out.status.success(), "an absent index was shown anyway");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("no runtime 3 (1 runtime)"), "{stderr}");
    });
}

/// Several runtimes are an ambiguity too: each gets a heading naming
/// it, with a blank line between one runtime's output and the next —
/// and naming some of them shows those alone.
#[test]
fn test_several_runtimes_are_told_apart_by_headings() {
    let bundle = fixtures().bundle("foreign-runtime");
    with_core("foreign-runtime", |core| {
        let out = hansei_ok(&bundle, core, "runtimes -D");
        assert_eq!(out.matches(" (current_thread):\n").count(), 2, "{out}");
        assert!(out.contains("\n\nruntime 1 @"), "{out}");

        // One of the two named is one of the two shown, and with no
        // ambiguity left it prints without a heading at all.
        let one = hansei_ok(&bundle, core, "runtimes 1 -D");
        assert_eq!(one.matches(" (current_thread):\n").count(), 0, "{one}");
        assert!(!one.contains("runtime 1 @"), "{one}");

        // Naming both is naming none: the same two blocks, in listing
        // order however the two were written.
        let both = hansei_ok(&bundle, core, "runtimes 1 0 -D");
        assert_eq!(out, both, "naming every runtime shows every runtime");
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

        assert!(out.contains(" in the scheduler's run loop"), "{out}");
        assert!(out.contains("1 parked in the io driver"), "{out}");
        // The section names the one runtime the target holds, the way
        // `runtimes` lists it.
        let inside =
            regex::Regex::new(r"Threads: \d+ lwps, \d+ in runtime 0 @0x[0-9a-f]+\n").unwrap();
        assert!(inside.is_match(&out), "{out}");
        // The `block_on` thread is in the runtime without running the
        // worker loop, as `threads` says of it too — and it is counted
        // apart from the pool's own threads, which the runtime's two
        // workers are otherwise counted among.
        assert!(out.contains(", outside the run loop\n"), "{out}");
        assert!(out.contains(" in the blocking pool ("), "{out}");
        assert!(
            out.contains("1 that entered the runtime another way (a block_on caller)"),
            "{out}"
        );

        // The task total is the task listing's, and the two waits are
        // the two leaves the graph names: the sleeper on the timer, the
        // joiner on the sleeper — each hanging off the future type
        // whose task waits that way rather than tallied on its own.
        let rows = list_tasks(&bundle, core);
        let owned = regex::Regex::new(&format!(
            r"Tasks: {} owned by runtime 0 @0x[0-9a-f]+\n",
            rows.len()
        ))
        .unwrap();
        assert!(owned.is_match(&out), "{out}");
        assert!(out.contains("    State: 2 idle\n"), "{out}");
        assert!(
            out.contains(
                "        1  async fn sleep_join::sleeper\n           \
                 └─ 1  a timer\n"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "        1  async fn sleep_join::joiner\n           \
                 └─ 1  another task (JoinHandle)\n"
            ),
            "{out}"
        );

        // Two two-frame chains — each an async fn over its leaf — and
        // nothing at all off them. Two futures in flight, standing on
        // four frames: the heading counts the futures and the frames
        // apart, so a chain that grows deeper does not read as more
        // things running.
        assert!(
            out.contains(
                "Futures: 2 in flight, on 4 await-chain frames (up to 2 deep)\n    \
                 Location:\n        \
                 2  polled as tasks\n        \
                 0  held in frames, off any await chain\n        \
                 0  in 0 FuturesUnordered\n"
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
            tasks.contains(
                "        1  async fn sleep_join::sleeper\n           \
                 └─ 1  a timer\n"
            ),
            "{tasks}"
        );
    });
}

/// What a set holds is counted apart from what a frame holds, with the
/// same split `tasks --futures` lists: five children in flight across
/// the two sets, and nine futures held in frames beside them.
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
                "        9  held in frames, off any await chain\n        \
                 5  in 2 FuturesUnordered\n"
            ),
            "{out}"
        );
        // The leaves are what the nesting added: one per set child, two
        // the driver holds inside a tuple and an enum, the nested set's
        // own two children, and the one carried by the future the
        // driver holds for it.
        assert!(
            out.contains("        8  async fn unordered::leaf\n"),
            "{out}"
        );
        // What all five of them are — the set's children and the two
        // held beside them are the same async fn, the boxed one named
        // through the dyn join rather than by its pointer — and, under
        // it, what those five chains reach. The children park in the
        // shared Notify, which is no primitive hansei decodes into a
        // wait target, so the branch names the leaf their chains
        // reached rather than counting them as something it could not
        // identify; the two held beside them reach elsewhere, which is
        // what leaves this branch at three of the five.
        assert!(
            out.contains(
                "        5  async fn unordered::set_member\n           \
                 ├─ 3  future tokio::sync::notify::Notified\n"
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
        let shared = hansei_ok(&bundle, core, "runtimes -s");
        assert!(shared.contains("multi_thread::worker::Shared"), "{shared}");
        assert!(shared.contains("owned:"), "{shared}");
        assert!(shared.contains("inject:"), "{shared}");
        assert!(shared.contains("num_workers:"), "{shared}");

        let drivers = hansei_ok(&bundle, core, "runtimes -D");
        assert!(drivers.contains("runtime::driver::Handle"), "{drivers}");
        assert!(drivers.contains("io:"), "{drivers}");
        assert!(drivers.contains("time:"), "{drivers}");

        // Both views exist to show the runtime's insides, so the bundle's
        // elisions never apply to them: however deep the sweep goes, no
        // subtree may come back `<elided>` — a regression here means a new
        // elided row leaked into runtime introspection.
        for command in [
            "config depth 64; runtimes -s",
            "config depth 64; runtimes -D",
        ] {
            let deep = hansei_ok(&bundle, core, command);
            assert!(!deep.contains("<elided>"), "`{command}`: {deep}");
        }
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
        assert!(out.contains("src/bin/simple-await.rs:40"), "{out}");

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
        assert!(out.trim_end().ends_with(" types"), "{out}");
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

/// `vtables` answers from the tokio info what the target's own memory
/// cannot be asked: which vtables implement a trait, how wide each is,
/// and — the question a crashed indirect call raises — whether the slot
/// it went through has an entry at all.
///
/// What the suite's two compilations allow is what is pinned here. The
/// addresses come from build B and build A is what ran, so whether the
/// two placed a vtable alike is the linker's business rather than this
/// test's: the row's verification mark is deliberately left alone, and
/// the pair, the slot count and the slot lines — none of which depend
/// on that — are what is asserted.
///
/// Whether the words are there to read at all follows from those same
/// two builds. B's address lands where it lands in A: inside a mapping,
/// where it reads back as somebody else's bytes, or in a hole between
/// two segments, where it reads back as nothing — which of the two is
/// the linker's business again, and differs by platform because the
/// layouts do. What each slot line *says* is therefore asserted only
/// where the words were served.
#[test]
fn test_vtables_acceptance() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        // Naming no substring is a count, not a dump: a real target
        // instantiates tens of thousands.
        let all = hansei_ok(&bundle, core, "vtables");
        assert!(all.contains("name a substring"), "{all}");
        assert!(!all.contains("slots"), "{all}");

        // Every Rust program with a `main` instantiates this pair —
        // `lang_start` boxes the closure it calls `main` through — so
        // it is the one entry a fixture can be sure of. Six words: the
        // drop-glue/size/align header, then the three call shims `Fn`
        // carries with its supertraits.
        let anchor = "std::rt::lang_start::{closure_env#0}<()>";
        // The needle is a regex, so the anchor's braces and parens are
        // escaped to match themselves.
        let out = hansei_ok(
            &bundle,
            core,
            &format!("vtables -v {}", regex::escape(anchor)),
        );
        assert!(out.contains("core::ops::function::Fn<()>\n"), "{out}");
        assert!(out.contains(&format!("6 slots  {anchor}")), "{out}");
        // Nothing about this pair is vacant, so nothing says it is.
        assert!(!out.contains("no entry recorded"), "{out}");
        let count = out.trim_end().lines().last().unwrap_or_default();
        assert!(
            count.ends_with(" vtable") || count.ends_with(" vtables"),
            "{out}"
        );

        // Everything below turns on whether the recorded addresses are
        // this target's, and this suite's pair cannot settle that in
        // advance: build A runs and build B carries the DWARF, so where
        // B's addresses land in A is the linker's business and comes
        // out differently on each system. So the listing is asked, and
        // what is pinned is that every other answer agrees with it.
        if out.contains("note: the tokio info is from a different build") {
            // Another build's addresses are shown as nothing at all —
            // no column, and no slots even though `-v` asked for them.
            assert!(!out.contains("0x"), "{out}");
            assert!(!out.contains("slot 0"), "{out}");
            let none = hansei_ok(&bundle, core, "vtables no::such::trait");
            assert!(none.trim_end().ends_with("0 vtables"), "{none}");
            return;
        }

        for slot in 0..6 {
            assert!(out.contains(&format!("slot {slot}  ")), "{out}");
        }
        if !out.contains("(unreadable)") {
            assert!(out.contains("drop glue"), "{out}");
            assert!(out.contains("align: "), "{out}");
        }

        // The row's address is the recorded one moved by the load bias
        // the core itself reports — so a session that never applied it
        // prints an address below where the executable even starts.
        // This core says where the executable landed, so no row may
        // fall back to a link-time address.
        assert!(!out.contains("(link-time)"), "{out}");
        let bias = Proc::open_core(core)
            .expect("failed to open the core")
            .exec_bias()
            .expect("the core says where the executable landed");
        let row = out
            .lines()
            .find(|l| l.contains(" slots  "))
            .expect("the listing has a row");
        let hex = row
            .trim_start()
            .split_whitespace()
            .next()
            .and_then(|cell| cell.strip_prefix("0x"))
            .expect("the row opens with an address");
        let printed = u64::from_str_radix(hex, 16).expect("the address is hex");
        assert!(printed >= bias, "{printed:#x} is below the bias {bias:#x}");

        // `whatis` reads the same table backwards, and the two commands
        // agree about the same address. The listing's mark is what says
        // whether the words there bear the entry out, and it is exactly
        // where they do not that `whatis` declines to name the pair: the
        // question there is about an arbitrary address rather than about
        // this table, so a contradicted entry is a false lead and not an
        // answer.
        let named = hansei_ok(&bundle, core, &format!("whatis {printed:#x}"));
        match row.contains("(unverified)") {
            true => assert!(!named.contains("Implements:"), "{named}"),
            false => {
                assert!(named.contains(&format!("Vtable {printed:#x}")), "{named}");
                assert!(named.contains(&format!("erases {anchor}")), "{named}");
                assert!(
                    named.contains("    Implements: core::ops::function::Fn<()>\n"),
                    "{named}"
                );
            }
        }

        // A needle nothing matches is an empty answer, not a failure.
        let none = hansei_ok(&bundle, core, "vtables no::such::trait");
        assert_eq!(none.trim(), "0 vtables");
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
            assert!(out.contains("\n1 task\n"), "{out}");
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
/// address of a block it has handed back, which is exactly one pointer
/// the renderer must not follow — on a target whose allocator is
/// libumem. On glibc there is no allocator to ask, and the same frame
/// renders the way it always did, which is the other half of the claim.
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
        // One refusal, not two, though the frame holds two stale
        // pointers: the boxed future's is a wide pointer, which the
        // renderer prints as its vtable's own account of itself —
        // concrete type, size, drop glue, all of it read from rodata
        // — rather than by expanding the value at the far end. There
        // is nothing there for a gate to refuse. What follows that
        // pointer is the census, below.
        assert!(
            out.contains("gates: 1 pointer(s) into freed memory"),
            "{out}"
        );
        assert!(out.contains("self-check: clean"), "{out}");
    });
}

/// The census's half of the same claim, on the same target.
///
/// `stale-local` also parks holding the wide pointer of a boxed future
/// whose block it has handed back. That pointer is one the census's
/// discovery *follows* — unlike the plain one above, which only the
/// renderer reads — so without corroboration the future behind it is
/// listed as one in flight, in a listing that then reads as complete.
/// Where there is an allocator to ask it must be refused and the run
/// must say so; on glibc there is nothing to ask, and it is listed like
/// any other held future.
#[test]
fn test_a_stale_future_is_not_counted_as_one_in_flight() {
    let bundle = fixtures().bundle("stale-local");
    with_core("stale-local", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(&rows, "async fn stale_local::holder");
        let out = hansei(&bundle, core, "tasks --futures");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}\n{stdout}");

        if hansei_ok(&bundle, core, "umem-audit").contains("no umem metadata in this target") {
            assert_eq!(task.futures, "1", "{rows:?}");
            assert!(stdout.contains("Held futures: 1"), "{stdout}");
            assert!(stderr.is_empty(), "{stderr}");
            return;
        }
        // The count in the plain listing and the block under
        // `--futures` are the same census, so both have to say none —
        // a refusal that removed the row and left the count would be
        // worse than not refusing at all.
        assert_eq!(task.futures, "0", "{rows:?}");
        assert!(stdout.contains("Held futures: 0"), "{stdout}");
        assert!(
            stderr.contains(
                "the allocator has taken back the memory 1 find(s) lay in; \
                 they and anything they held are not listed"
            ),
            "{stderr}"
        );
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
        let out = hansei_exec(
            &bundle,
            core,
            &["info ; config depth 1; runtimes -D", "tasks"],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "--exec failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("symbols resolved:"), "{stdout}");
        assert!(stdout.contains("runtime::driver::Handle"), "{stdout}");
        assert!(stdout.contains("\n1 task\n"), "{stdout}");

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
        let out = hansei_ok(&bundle, core, "info ; runtimes -D");
        assert!(out.contains("symbols resolved:"), "{out}");
        assert!(out.contains("runtime::driver::Handle"), "{out}");

        let out = hansei(&bundle, core, "info ; trace 99999 ; runtimes -D");
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
        // inferred. `regs` sits beside `runtimes`, so `r` fits both
        // and only `ru` and longer are runtimes' alone.
        assert!(
            hansei_ok(&bundle, core, "config depth 1; runtime -D")
                .contains("runtime::driver::Handle")
        );
        assert!(hansei_ok(&bundle, core, "ru -s").contains("multi_thread::worker::Shared"));
        assert!(hansei_ok(&bundle, core, "runtimes -l").contains("multi_thread"));
        let out = hansei(&bundle, core, "r -s");
        assert!(
            !out.status.success(),
            "a prefix of two commands must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        for candidate in ["regs", "runtimes"] {
            assert!(err.contains(candidate), "{candidate} missing from {err}");
        }

        // The singular selectors sit beside their plurals, so every
        // proper prefix of `threads` fits `thread` too: only the full
        // word names the listing now, and `thr` is refused naming
        // both.
        assert!(hansei_ok(&bundle, core, "threads -f 0").contains("lwp "));
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

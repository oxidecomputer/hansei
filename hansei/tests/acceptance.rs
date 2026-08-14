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
];

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
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

/// The trace header's `Spawned at` line — present, with its trailing
/// newline, only when the target records spawn locations at all.
fn spawned_at(loc: &str) -> String {
    if cell().unstable {
        format!("Spawned at: {loc}\n")
    } else {
        String::new()
    }
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
        let bin_b = match &cell.name {
            None => fixture_dir.join("bin"),
            Some(name) => fixture_dir.join("bin").join(name),
        };

        let bundles = base.join("integration");
        fs::create_dir_all(&bundles).expect("failed to create the bundle dir");
        for program in PROGRAMS {
            let opts = ExtractOptions {
                extract_args: format!("acceptance-suite extraction of {program}"),
                ..Default::default()
            };
            let (bundle, _stats) = extract_file(&bin_b.join(program), &opts)
                .unwrap_or_else(|e| panic!("extraction of {program} failed: {e}"));
            bundle
                .save(&bundles.join(format!("{program}.bundle")))
                .expect("failed to write the bundle");
        }

        Fixtures {
            bin_a: base.join("bin-a"),
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

/// The `--program` flags an attach to `core` needs, if any.
///
/// A Linux core carries no symbol table, so hansei requires the
/// executable to be named; an illumos core carries its own and warns if
/// one is passed. Every core in this suite is of a program still sitting
/// where it was, so the path the core recorded is the right answer —
/// which is the whole reason the flag can be filled in here rather than
/// threaded through every caller.
fn program_args(core: &Path) -> Vec<PathBuf> {
    let proc = Proc::open_core(core).expect("failed to open the core");
    match proc.needs_program() {
        false => Vec::new(),
        true => vec![proc.exec_name().expect("the core names no executable")],
    }
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
        .args(
            program_args(core)
                .iter()
                .flat_map(|p| ["--program".as_ref(), p.as_os_str()]),
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
    command.arg("--bundle").arg(bundle).arg("--core").arg(core);
    for program in program_args(core) {
        command.arg("--program").arg(program);
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
}

/// Run the `tasks` command and parse the listing: a `Task <id>: <future>`
/// header per task, then one indented `<label>: <value>` line per
/// attribute, then a blank line. Every block carries every attribute, so
/// a field left empty here is a row the listing failed to print.
fn list_tasks(bundle: &Path, core: &Path) -> Vec<TaskRow> {
    let out = hansei_ok(bundle, core, "tasks");

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
        };
        lines.next();

        for line in &mut lines {
            if line.is_empty() {
                break;
            }
            let attr = line
                .strip_prefix("    ")
                .unwrap_or_else(|| panic!("unexpected tasks line {line:?}"));
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
        regex::Regex::new(r"deadline -?\d+\.\d{3}s( on the target's monotonic clock)?").unwrap();
    let tokio_sites = regex::Regex::new(r"tokio-\d+\.\d+\.\d+(/[^ :]+):\d+").unwrap();
    let trace_leaf = regex::Regex::new(r"tokio::trace::async_trace_leaf::\S+").unwrap();
    let masked = deadlines.replace_all(out, "deadline TS");
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
/// `@1`), which a fixture parked deterministically hands out the same
/// way every run.
///
/// What this buys over `format!`-ing the expectation around the run's
/// own ids is a golden that holds for every cell: a task id is a small
/// decimal under `tokio_unstable` and the Header address where the
/// target records none, and neither reaches the golden.
#[derive(Default)]
struct Symbols {
    named: Vec<(String, String)>,
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

    /// Rewrite `out` into the form a golden holds.
    ///
    /// One `seen` serves both passes: the table and the prose under it
    /// name the same tasks, and a symbol minted once per pass would let
    /// a golden claim an agreement between them the run never had.
    fn apply(&self, out: &str) -> String {
        let mut seen = Vec::new();
        let out = drop_spawn_line(out);
        let out = self.addresses(&out);
        let out = mask(&out);
        let out = self.table(&mut seen, &out);
        self.references(&mut seen, &out)
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
            format!("@{}", at + 1)
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

/// The trace header's `Spawned at` line, which a target carries only
/// under `tokio_unstable` instrumentation.
///
/// Held out of a golden rather than in it: whether the line is there at
/// all is the cell's, not hansei's, and one golden serves every cell.
/// What it says where it is there is [`assert_spawned_at`]'s to check.
fn spawn_line(loc: &str) -> Option<String> {
    cell().unstable.then(|| format!("Spawned at: {loc}"))
}

/// Assert a trace header records `loc` as the spawn site — or records
/// no site at all, on a cell whose target could not.
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
/// place under a plain `cargo test` — the same shape as `EXEGESIS_BLESS`
/// and `HANSEI_MATRIX_BLESS`, and the only shape that serves this suite:
/// it runs nowhere but the hosts that can core a process, so a golden is
/// always blessed over ssh and reviewed here afterwards. A plain run
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
        let task = task_with_future(&rows, "simple_await::work::{async_fn_env#0}");
        assert_eq!(task.state, "idle");
        assert_eq!(task.spawned, spawned("src/bin/simple-await.rs:67:21"));
        assert_eq!(task.defined, "src/bin/simple-await.rs:16");

        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(&out, "src/bin/simple-await.rs:67:21");
        golden(
            "simple-await-trace",
            &Symbols::new().task(&task.id, "work").apply(&out),
        );

        // Exactly these, against a bundle extracted a moment ago: the
        // extractor drops what rustc lists in a state that is not that
        // state's own, and whether it dropped the right things is a
        // question about `simple-await.rs` that only the source
        // answers. Every name here is bound between lines 17 and 31
        // and read again at 35..45, so each has to survive both awaits;
        // `first` is bound *by* the line-32 await. The arguments
        // `ready` and `park` are gone by line 34 — one consumed by
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
                "count", "labels", "values", "boxed", "slice", "ipv4", "ipv6", "borrowed", "owned",
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
        assert_eq!(task.spawned, spawned("src/bin/nested-await.rs:32:21"));
        assert_eq!(task.defined, "src/bin/nested-await.rs:16");

        let out = trace(&bundle, core, &task.id, false);
        assert_spawned_at(&out, "src/bin/nested-await.rs:32:21");
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

        let driver = task_with_future(&rows, "dyn_future::driver::{async_fn_env#0}");
        assert_eq!(driver.state, "idle");
        assert_eq!(driver.spawned, spawned("src/bin/dyn-future.rs:46:21"));
        assert_eq!(driver.defined, "src/bin/dyn-future.rs:22");
        let expected = format!(
            "\
Task {id}: dyn_future::driver::{{async_fn_env#0}} (idle)
{spawned}Defined at: src/bin/dyn-future.rs:22

  0  async fn      dyn_future::driver::{{async_fn_env#0}}
     suspends:
     ▸ Suspend0  src/bin/dyn-future.rs:29  1 local
       └─  1  async fn      dyn_future::boxed_leaf::{{async_fn_env#0}} [dyn]
          suspends:
          ▸ Suspend0  src/bin/dyn-future.rs:11
            └─* 2  future        tokio::sync::oneshot::Receiver<u32>
       Suspend1  src/bin/dyn-future.rs:30  2 locals  tokio::task::join_set::{{impl#1}}::join_next::{{async_fn_env#0}}<u32>
",
            id = driver.id,
            spawned = spawned_at("src/bin/dyn-future.rs:46:21")
        );
        assert_eq!(trace(&bundle, core, &driver.id, false), expected);

        let member = task_with_future(&rows, "dyn_future::set_member::{async_fn_env#0}");
        assert_eq!(member.state, "idle");
        assert_eq!(member.spawned, spawned("src/bin/dyn-future.rs:26:9"));
        assert_eq!(member.defined, "src/bin/dyn-future.rs:14");
        let expected = format!(
            "\
Task {id}: dyn_future::set_member::{{async_fn_env#0}} (idle)
{spawned}Defined at: src/bin/dyn-future.rs:14

  0  async fn      dyn_future::set_member::{{async_fn_env#0}}
     suspends:
     ▸ Suspend0  src/bin/dyn-future.rs:15
       └─* 1  future        tokio::sync::oneshot::Receiver<u32>
",
            id = member.id,
            spawned = spawned_at("src/bin/dyn-future.rs:26:9")
        );
        assert_eq!(trace(&bundle, core, &member.id, false), expected);
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
        let task = task_with_future(
            &rows,
            "futurelock::main::{async_block#0}::{async_block_env#0}",
        );
        assert_eq!(task.state, "idle");
        assert_eq!(task.spawned, spawned("src/bin/futurelock.rs:15:17"));
        assert_eq!(task.defined, "src/bin/futurelock.rs:15");

        let expected = format!(
            "\
Task {id}: futurelock::main::{{async_block#0}}::{{async_block_env#0}} (idle)
{spawned}Defined at: src/bin/futurelock.rs:15

  0  async block   futurelock::main::{{async_block#0}}::{{async_block_env#0}}
     suspends:
       Suspend0  src/bin/futurelock.rs:22  1 local  futurelock::start_background_task::{{async_fn_env#0}}
     ▸ Suspend1  src/bin/futurelock.rs:25  1 local
       └─  1  async fn      futurelock::do_stuff::{{async_fn_env#0}}
          suspends:
            Suspend0  src/bin/futurelock.rs:59  4 locals  core::future::poll_fn::PollFn<futurelock::do_stuff::{{async_fn#0}}::{{closure_env#0}}>
          ▸ Suspend1  src/bin/futurelock.rs:64  3 locals
            └─  2  async fn      futurelock::do_async_thing::{{async_fn_env#0}}
               suspends:
               ▸ Suspend0  src/bin/futurelock.rs:72  2 locals
                 └─  3  async fn      tokio::sync::mutex::{{impl#10}}::lock::{{async_fn_env#0}}<()>
                    suspends:
                    ▸ Suspend0  tokio/src/sync/mutex.rs:LINE
                      └─  4  async block   tokio::sync::mutex::{{impl#10}}::lock::{{async_fn#0}}::{{async_block_env#0}}<()>
                         suspends:
                         ▸ Suspend0  tokio/src/sync/mutex.rs:LINE
                           └─  5  async fn      tokio::sync::mutex::{{impl#10}}::acquire::{{async_fn_env#0}}<()>
                              suspends:
                                Suspend0  tokio/src/sync/mutex.rs:LINE  1 local  tokio::trace::async_trace_leaf::TY
                              ▸ Suspend1  tokio/src/sync/mutex.rs:LINE
                                └─* 6  future        tokio::sync::batch_semaphore::Acquire
                                   waiting on a tokio::sync::Mutex (semaphore 0xADDR): 1 permit requested, 0 available; wake queue: task {id}
",
            id = task.id,
            spawned = spawned_at("src/bin/futurelock.rs:15:17")
        );
        assert_eq!(normalize(&trace(&bundle, core, &task.id, false)), expected);

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
            &format!("trace {} --verbose --depth 12", task.id),
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
            assert_eq!(row.spawned, spawned("src/bin/many-tasks.rs:27:13"));
            assert_eq!(row.defined, "src/bin/many-tasks.rs:9");
        }
        let ids: HashSet<&str> = rows.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(ids.len(), rows.len(), "task ids are unique");

        let task = &rows[0];
        let expected = format!(
            "\
Task {id}: many_tasks::park_task::{{async_fn_env#0}} (idle)
{spawned}Defined at: src/bin/many-tasks.rs:9

  0  async fn      many_tasks::park_task::{{async_fn_env#0}}
     suspends:
     ▸ Suspend0  src/bin/many-tasks.rs:11
       └─* 1  future        tokio::sync::oneshot::Receiver<u32>
",
            id = task.id,
            spawned = spawned_at("src/bin/many-tasks.rs:27:13")
        );
        assert_eq!(trace(&bundle, core, &task.id, false), expected);
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
        let sleeper = task_with_future(&rows, "sleep_join::sleeper::{async_fn_env#0}");
        let joiner = task_with_future(&rows, "sleep_join::joiner::{async_fn_env#0}");
        assert_eq!(sleeper.state, "idle");
        assert_eq!(joiner.state, "idle");

        let expected = format!(
            "\
Task {id}: sleep_join::sleeper::{{async_fn_env#0}} (idle)
{spawned}Defined at: src/bin/sleep-join.rs:9

  0  async fn      sleep_join::sleeper::{{async_fn_env#0}}
     suspends:
     ▸ Suspend0  src/bin/sleep-join.rs:11
       └─* 1  future        tokio::time::sleep::Sleep
          waiting on the timer: deadline TS
",
            id = sleeper.id,
            spawned = spawned_at("src/bin/sleep-join.rs:28:22")
        );
        assert_eq!(
            normalize(&trace(&bundle, core, &sleeper.id, false)),
            expected
        );

        let expected = format!(
            "\
Task {id}: sleep_join::joiner::{{async_fn_env#0}} (idle)
{spawned}Defined at: src/bin/sleep-join.rs:15

  0  async fn      sleep_join::joiner::{{async_fn_env#0}}
     suspends:
     ▸ Suspend0  src/bin/sleep-join.rs:17
       └─* 1  future        tokio::runtime::task::join::JoinHandle<u32>
          waiting on task {sleeper_id} (JoinHandle)
",
            id = joiner.id,
            sleeper_id = sleeper.id,
            spawned = spawned_at("src/bin/sleep-join.rs:29:23")
        );
        assert_eq!(trace(&bundle, core, &joiner.id, false), expected);
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
        let sleeper = task_with_future(&rows, "ct_runtime::sleeper::{async_fn_env#0}");
        let acquirer = task_with_future(&rows, "ct_runtime::acquirer::{async_fn_env#0}");
        assert_eq!(sleeper.state, "idle");
        assert_eq!(acquirer.state, "idle");

        let expected = format!(
            "\
Task {id}: ct_runtime::sleeper::{{async_fn_env#0}} (idle)
{spawned}Defined at: src/bin/ct-runtime.rs:10

  0  async fn      ct_runtime::sleeper::{{async_fn_env#0}}
     suspends:
     ▸ Suspend0  src/bin/ct-runtime.rs:12
       └─* 1  future        tokio::time::sleep::Sleep
          waiting on the timer: deadline TS
",
            id = sleeper.id,
            spawned = spawned_at("src/bin/ct-runtime.rs:31:24")
        );
        assert_eq!(
            normalize(&trace(&bundle, core, &sleeper.id, false)),
            expected
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
        let out = hansei_ok(&bundle, core, "threads");
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
/// listing tagged with the set (and the LWP it is pinned to, joined
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
        let joiner = task_with_future(&rows, "local_set::joiner::{async_fn_env#0}");
        let sleeper = task_with_future(&rows, "local_set::local_sleeper::{async_fn_env#0}");
        let acquirer = task_with_future(&rows, "local_set::local_acquirer::{async_fn_env#0}");

        // Groups: the scheduler task carries the runtime's tag, the two
        // local tasks the set's, with the owner LWP joined on.
        let rt_tag = regex::Regex::new(r"^runtime 0 @0x[0-9a-f]+ \(current_thread\)$").unwrap();
        assert!(rt_tag.is_match(&joiner.owner), "{rows:#?}");
        let set_tag = regex::Regex::new(r"^local set 0 @0x[0-9a-f]+ \(lwp \d+\)$").unwrap();
        assert!(set_tag.is_match(&sleeper.owner), "{rows:#?}");
        assert_eq!(sleeper.owner, acquirer.owner, "{rows:#?}");

        // The join edge names the local task with no "not in the
        // scheduler's owned tasks" caveat: it is simply listed now.
        let out = trace(&bundle, core, &joiner.id, false);
        assert!(
            out.contains(&format!("waiting on task {} (JoinHandle)\n", sleeper.id)),
            "{out}"
        );

        // The local tasks read like any listed task: the sleeper's
        // timer leaf decodes, and the acquirer's semaphore names its
        // queued waker as the task it would wake.
        let out = normalize(&trace(&bundle, core, &sleeper.id, false));
        assert!(out.contains("tokio::time::sleep::Sleep"), "{out}");
        assert!(out.contains("waiting on the timer: deadline TS"), "{out}");
        let out = normalize(&trace(&bundle, core, &acquirer.id, false));
        assert!(
            out.contains(&format!("wake queue: task {}", acquirer.id)),
            "{out}"
        );

        // `runtimes` names the set, its owner thread, its population,
        // and the route that found it.
        let out = normalize(&hansei_ok(&bundle, core, "runtimes"));
        let set_line = regex::Regex::new(
            r"local set +0 +@0xADDR +2 tasks, \d+ futures? +on lwp \d+, found via a JoinHandle held by an enumerated task",
        )
        .unwrap();
        assert!(set_line.is_match(&out), "{out}");
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
        let spawned = task_with_future(&rows, "local_set_timer::sleeper::{async_fn_env#0}");
        let sleeper = task_with_future(&rows, "local_set_timer::local_sleeper::{async_fn_env#0}");
        let acquirer = task_with_future(&rows, "local_set_timer::local_acquirer::{async_fn_env#0}");

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
        assert!(out.contains("waiting on the timer: deadline TS"), "{out}");
        let out = normalize(&trace(&bundle, core, &acquirer.id, false));
        assert!(
            out.contains(&format!("wake queue: task {}", acquirer.id)),
            "{out}"
        );

        // `runtimes` names the route, which is the whole point of the
        // fixture.
        let out = normalize(&hansei_ok(&bundle, core, "runtimes"));
        let set_line = regex::Regex::new(
            r"local set +0 +@0xADDR +2 tasks, \d+ futures? +on lwp \d+, found via a task waker on a timer parked in a runtime's wheel",
        )
        .unwrap();
        assert!(set_line.is_match(&out), "{out}");
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
        let spawned = task_with_future(&rows, "local_set_io::reader::{async_fn_env#0}");
        let members = ["local_reader", "local_watcher", "local_writer"].map(|name| {
            task_with_future(&rows, &format!("local_set_io::{name}::{{async_fn_env#0}}"))
        });

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

        // `runtimes` names the route, which is the whole point of the
        // fixture.
        let out = normalize(&hansei_ok(&bundle, core, "runtimes"));
        let set_line = regex::Regex::new(
            r"local set +0 +@0xADDR +3 tasks, \d+ futures? +on lwp \d+, found via a task waker on an io resource registered with a runtime's driver",
        )
        .unwrap();
        assert!(set_line.is_match(&out), "{out}");
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
        let joiner = task_with_future(&rows, "foreign_runtime::joiner::{async_fn_env#0}");
        let joined = task_with_future(&rows, "foreign_runtime::joined::{async_fn_env#0}");
        let detached = task_with_future(&rows, "foreign_runtime::detached::{async_fn_env#0}");
        let sleeper = task_with_future(&rows, "foreign_runtime::local_sleeper::{async_fn_env#0}");

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
            out.contains(&format!("task {} (JoinHandle)", joined.id)),
            "{out}"
        );
        assert!(!out.contains("does not list"), "{out}");

        // `runtimes` names the runtime and the route to it, and the set
        // that harvesting *its* wheel found. `info` counts them and
        // leaves the naming to the listing.
        let out = normalize(&hansei_ok(&bundle, core, "runtimes"));
        let hidden = regex::Regex::new(
            r"runtime +1 +current_thread +@0xADDR +2 tasks, \d+ futures? +no thread inside it, found via a JoinHandle held by an enumerated task",
        )
        .unwrap();
        assert!(hidden.is_match(&out), "{out}");
        let set_line = regex::Regex::new(
            r"local set +0 +@0xADDR +1 task, \d+ futures? +on lwp \d+, found via a task waker on a timer parked in a runtime's wheel",
        )
        .unwrap();
        assert!(set_line.is_match(&out), "{out}");

        let info = hansei_ok(&bundle, core, "info");
        assert!(
            info.contains("2 runtimes, 1 local set (see `runtimes`)"),
            "{info}"
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
        let sleeper = task_with_future(&rows, "sleep_join::sleeper::{async_fn_env#0}");
        let joiner = task_with_future(&rows, "sleep_join::joiner::{async_fn_env#0}");

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
                "Task {}: sleep_join::sleeper::{{async_fn_env#0}}\n",
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
        let driver = task_with_future(&rows, "unordered::driver::{async_fn_env#0}");

        // Two held futures, and one set holding three children. The
        // plain listing carries both counts, and says `0` for a task the
        // census found nothing for rather than staying silent;
        // `--futures` lists what each counted, under its own row.
        assert_eq!(driver.futures, "2", "{rows:?}");
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
            futures.contains("    Held futures: 2\n        "),
            "{futures}"
        );
        assert!(
            futures.contains("    Join sets: 1 (3 futures)\n        - "),
            "{futures}"
        );
        assert!(
            futures.contains(
                "futures_util::stream::futures_unordered::FuturesUnordered\
                 <unordered::set_member::{async_fn_env#0}> at 0x"
            ),
            "{futures}"
        );
        // The set's own row says the same, spelled for one set rather
        // than for the block's total.
        assert!(futures.contains("`): 3 children in flight"), "{futures}");
        // Set-child rows sit one indent step deeper than the set's own
        // bulleted row.
        let child = regex::Regex::new(
            r"\n            (0x[0-9a-f]+)  unordered::set_member::\{async_fn_env#0\}",
        )
        .unwrap();
        let nodes: Vec<String> = child
            .captures_iter(&futures)
            .map(|c| c[1].to_string())
            .collect();
        assert_eq!(nodes.len(), 3, "{futures}");

        // The held futures — a bare coroutine and a dyn-boxed one, the
        // census's other two detections — are listed off the driver's
        // spine, never yet polled.
        assert!(futures.contains("\n        (frame 0, `held`)"), "{futures}");
        assert!(
            futures.contains("\n        (frame 0, `boxed`)"),
            "{futures}"
        );
        assert!(
            futures.contains("unordered::set_member::{async_fn_env#0}  Unresumed"),
            "{futures}"
        );

        // Narrowing to the driver shows its block alone, with the same
        // finds under it: every one of them is the driver's.
        let narrowed = hansei_ok(&bundle, core, &format!("tasks -f {}", driver.id));
        assert!(
            narrowed.starts_with(&format!("Task {}: ", driver.id)),
            "{narrowed}"
        );
        assert!(!narrowed.contains("\n1 task\n"), "{narrowed}");
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
            &format!("trace {} --verbose --depth 12", driver.id),
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
                "Future {}: unordered::set_member::{{async_fn_env#0}}",
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
                "Future {}: unordered::set_member::{{async_fn_env#0}}",
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
            out.contains("0  async fn      unordered::set_member::{async_fn_env#0}"),
            "{out}"
        );

        // And so is a held future, by the address its row prints.
        let held = regex::Regex::new(r"\n        \(frame 0, `held`\): (0x[0-9a-f]+)")
            .unwrap()
            .captures(&futures)
            .map(|c| c[1].to_string())
            .expect("the held row prints an address");
        let out = hansei_ok(&bundle, core, &format!("trace {held}"));
        assert!(
            out.contains(&format!(
                "Held by: task {} — unordered::driver::{{async_fn_env#0}} (frame 0, `held`)",
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
            .find(&format!(
                "Task {}: unordered::driver::{{async_fn_env#0}}",
                driver.id
            ))
            .unwrap_or_else(|| panic!("the task holding the future is not reported:\n{out}"));
        assert!(out.contains("in the task's allocation (header 0x"), "{out}");
        assert!(out.contains("    At: offset 0x0 in the future"), "{out}");
        let future_block = out
            .find(&format!(
                "Future {held}: unordered::set_member::{{async_fn_env#0}}"
            ))
            .unwrap_or_else(|| panic!("the held future itself is not reported:\n{out}"));
        assert!(task_block < future_block, "{out}");
        assert!(
            out.contains(&format!(
                "    Held by: task {} — unordered::driver::{{async_fn_env#0}} (frame 0, `held`)",
                driver.id
            )),
            "{out}"
        );
    });
}

/// A `JoinSet` holds tasks rather than futures: `tasks --futures` lists
/// them under the task that drives the set, by the ids each has a block
/// of its own under — and no futures count moves, because a spawned task
/// is on its own await chain rather than off anybody's.
#[test]
fn test_join_set_acceptance() {
    let bundle = fixtures().bundle("joinset");
    with_core("joinset", |core| {
        let rows = list_tasks(&bundle, core);
        let driver = task_with_future(&rows, "joinset::driver::{async_fn_env#0}");

        // One set holding the three members it spawned — tasks, counted
        // apart from the futures a set of futures would hold — and
        // nothing held in the driver's own frames.
        assert_eq!(driver.sets, "1 (3 tasks)", "{rows:?}");
        assert_eq!(driver.futures, "0", "{rows:?}");
        for row in rows.iter().filter(|row| row.id != driver.id) {
            assert_eq!(row.sets, "0", "{row:?}");
        }

        let futures = hansei_ok(&bundle, core, "tasks --futures");
        assert!(
            futures.contains("    Join sets: 1 (3 tasks)\n        - "),
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
            regex::Regex::new(r"\n            task (\d+)  joinset::member::\{async_fn_env#0\}")
                .unwrap();
        let ids: Vec<String> = member
            .captures_iter(&futures)
            .map(|c| c[1].to_string())
            .collect();
        assert_eq!(ids.len(), 3, "{futures}");
        for id in &ids {
            assert!(rows.iter().any(|row| &row.id == id), "{rows:?}");
            let traced = hansei_ok(&bundle, core, &format!("trace {id}"));
            assert!(
                traced.contains("joinset::member::{async_fn_env#0}"),
                "{traced}"
            );
        }

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
/// which is `@1` in both places rather than two maskings that could
/// have hidden two different locks.
#[test]
fn test_futurelock_graph() {
    let bundle = fixtures().bundle("futurelock");
    with_core("futurelock", |core| {
        let rows = list_tasks(&bundle, core);
        let task = task_with_future(
            &rows,
            "futurelock::main::{async_block#0}::{async_block_env#0}",
        );
        let symbols = Symbols::new().task(&task.id, "blocked");
        golden("futurelock-graph", &symbols.apply(&graph(&bundle, core)));
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
        let sleeper = task_with_future(&rows, "sleep_join::sleeper::{async_fn_env#0}");
        let joiner = task_with_future(&rows, "sleep_join::joiner::{async_fn_env#0}");

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

/// The census counts the same target every other listing walks: the
/// threads by what their parkers say — including the one asleep in the
/// driver on the whole runtime's behalf — the tasks by lifecycle and by
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
        assert!(out.contains("    Lifecycle: 2 idle\n"), "{out}");
        assert!(
            out.contains(
                "        1  sleep_join::sleeper::{async_fn_env#0}\n           \
                 └─ 1  a timer\n"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "        1  sleep_join::joiner::{async_fn_env#0}\n           \
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
    });
}

/// What a set holds is counted apart from what a frame holds, with the
/// same split `tasks --futures` lists: three children in flight, and
/// two futures held off the driver's chain beside them.
#[test]
fn test_census_counts_a_set_and_what_is_held_beside_it() {
    let bundle = fixtures().bundle("unordered");
    with_core("unordered", |core| {
        let out = hansei_ok(&bundle, core, "census");
        assert!(
            out.contains(
                "        2  held in frames, off any await chain\n        \
                 3  in 1 FuturesUnordered\n"
            ),
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
                "        5  unordered::set_member::{async_fn_env#0}\n           \
                 ├─ 3  tokio::sync::notify::Notified\n"
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
        let shared = hansei_ok(&bundle, core, "runtime -s");
        assert!(shared.contains("multi_thread::worker::Shared"), "{shared}");
        assert!(shared.contains("owned:"), "{shared}");
        assert!(shared.contains("inject:"), "{shared}");
        assert!(shared.contains("num_workers:"), "{shared}");

        let drivers = hansei_ok(&bundle, core, "runtime -D");
        assert!(drivers.contains("runtime::driver::Handle"), "{drivers}");
        assert!(drivers.contains("io:"), "{drivers}");
        assert!(drivers.contains("time:"), "{drivers}");

        // Both views exist to show the runtime's insides, so the bundle's
        // elisions never apply to them: however deep the sweep goes, no
        // subtree may come back `<elided>` — a regression here means a new
        // elided row leaked into runtime introspection.
        for command in ["runtime -s -d 64", "runtime -D -d 64"] {
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
        assert!(out.contains("src/bin/simple-await.rs:34"), "{out}");

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

/// `--exec` asks from the command line what a pipeline would ask on
/// stdin, and the session exits with its answer.
#[test]
fn test_exec_asks_from_the_command_line() {
    let bundle = fixtures().bundle("simple-await");
    with_core("simple-await", |core| {
        // Two commands in one flag, and a second flag after it: both
        // spellings of "more than one question".
        let out = hansei_exec(&bundle, core, &["info ; runtime -D -d 1", "tasks"]);
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
        assert!(
            stderr.contains("no task with id 99999 is listed"),
            "{stderr}"
        );
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
        let out = hansei_ok(&bundle, core, "info ; runtime -D");
        assert!(out.contains("symbols resolved:"), "{out}");
        assert!(out.contains("runtime::driver::Handle"), "{out}");

        let out = hansei(&bundle, core, "info ; trace 99999 ; runtime -D");
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
        // The prefix names the command; its arguments are never inferred.
        assert!(hansei_ok(&bundle, core, "thr -f 0").contains("LWP "));
        // `runtime` and `runtimes` share every shorter prefix, so each
        // answers to its exact name and to nothing else.
        assert!(hansei_ok(&bundle, core, "runtime -D -d 1").contains("runtime::driver::Handle"));
        assert!(hansei_ok(&bundle, core, "runtime -s").contains("multi_thread::worker::Shared"));
        assert!(hansei_ok(&bundle, core, "runtimes").contains("multi_thread"));

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

/// Run hansei against `core` with exactly the `--program` given, past
/// the helper that would otherwise fill one in.
fn hansei_with_program(bundle: &Path, core: &Path, program: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hansei"));
    command.arg("--bundle").arg(bundle).arg("--core").arg(core);
    if let Some(program) = program {
        command.arg("--program").arg(program);
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
fn test_program_required_for_a_linux_core() {
    with_core("simple-await", |core| {
        let bundle = fixtures().bundle("simple-await");
        let out = hansei_with_program(&bundle, core, None);
        let stderr = String::from_utf8_lossy(&out.stderr);

        if !Proc::open_core(core).expect("core opens").needs_program() {
            assert!(
                out.status.success(),
                "a core carrying its own symbols needs no --program:\n{stderr}"
            );
            return;
        }

        assert!(
            !out.status.success(),
            "a Linux core without --program must be refused:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            stderr.contains("--program is required"),
            "diagnostic does not name the missing input:\n{stderr}"
        );
        // The failure this replaces blamed the bundle for a missing
        // file, which sent the reader after the wrong thing entirely.
        assert!(
            !stderr.contains("does not match this binary"),
            "a missing executable must not read as a bundle mismatch:\n{stderr}"
        );
    });
}

/// The debug build that produced the bundle resolves every symbol name
/// and shares none of the addresses, so the fingerprint cannot see the
/// substitution — the build id is what catches it.
#[test]
fn test_wrong_program_refused_by_build_id() {
    with_core("simple-await", |core| {
        if !Proc::open_core(core).expect("core opens").needs_program() {
            return;
        }
        let bundle = fixtures().bundle("simple-await");
        // A different fixture: a real binary, so it opens and parses,
        // and its build id is necessarily another one.
        let wrong = fixtures().program("futurelock");

        let out = hansei_with_program(&bundle, core, Some(&wrong));
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
            .arg("--bundle")
            .arg(&bundle)
            .arg("--core")
            .arg(core)
            .arg("--program")
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The version-matrix suite: every supported (toolchain, tokio,
//! unstable) cell of `test-programs/matrix.toml`, built on demand and
//! held against three per-cell goldens under `tests/matrix/<cell>/`.
//!
//! The point is turning silent declines loud. Both the display layer
//! and the runtime walk *fail safe* against a layout they do not
//! recognize — a detector declines and the type renders structurally, a
//! walk alternative stops binding and a fallback takes over — so a
//! tokio or toolchain release that moves a layout changes behavior
//! without failing anything. Per cell, three reports pin what actually
//! happened, and a release that moves anything is a one-line golden
//! diff:
//!
//! - `walk.snap` — the full walk-contract report per fixture program:
//!   which alternative spelling bound, what is absent and why.
//! - `formats.snap` — the detection catalog: every type a formatter
//!   attached to, with each selector resolved to its member-name chain.
//!   Deduplicated across programs (an entry is annotated with programs
//!   only where two disagree, itself a finding), and stripped of byte
//!   offsets — offsets legitimately differ across versions and
//!   platforms; the durable cross-version contract is the name chain.
//! - `summary.snap` — the portable extraction summary (task shapes,
//!   await lines, dyn-futures, infra/statics) per program, the same
//!   renderer the extraction goldens diff for the primary cell. This is
//!   what covers the await-chain machinery over arbitrary coroutine
//!   types, which no static path table can.
//!
//! Building a cell is a full tokio+std build with debug info — minutes
//! of wall clock and gigabytes of target dir the first time — so the
//! suite is opt-in: set `HANSEI_MATRIX=1` to run every cell, or
//! `HANSEI_MATRIX=<substring>` to run the cells whose name contains the
//! substring (e.g. `HANSEI_MATRIX=1.52` while chasing one version).
//! `INSTA_UPDATE=always` rewrites the goldens in place instead of
//! diffing; review the diff like any golden. A plain run leaves each
//! rejected golden beside its file as `<name>.snap.new` instead, and
//! reports every cell that diverged rather than the first. Cells whose
//! toolchain is not rustup-installed skip with a message, the same
//! contract the extraction goldens have. Run it alone (`cargo test -p
//! hansei-runtime --test matrix`), not under a workspace-wide
//! `cargo test`: the
//! primary cell shares its fixture dirs with the extraction goldens,
//! and two test binaries rebuilding one fixture dir race.
//!
//! The goldens are blessed from macOS. Everything in them is meant to
//! be LP64-portable — offsets are stripped, `futures_util` adapters are
//! filtered where monomorphization survival is the target's call — but
//! a platform whose type population differs may still diff; treat the
//! checked-in files as the macOS rendering until a second platform
//! needs them.

use exegesis::describe::describe_debug_format;
use exegesis::detect::Family;
use exegesis::extract::{ExtractOptions, extract_file};
use exegesis::summary::portable_summary;
use hansei_bundle::{Bundle, BundleView};
use hansei_runtime::tokio::contract::verify_walk_contract;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every tokio program `regen.sh` builds (its `ALL_PROGRAMS` minus
/// `park-target` and `core-target`, which are deliberately tokio-free
/// targets for the `proc` suites and so have nothing to extract): the
/// matrix builds and extracts each one per cell.
const PROGRAMS: &[&str] = &[
    "futurelock",
    "simple-await",
    "nested-await",
    "dyn-future",
    "select-combinator",
    "many-tasks",
    "sleep-join",
    "channels",
    "unordered",
    "joinset",
    "ct-runtime",
    "local-set",
    "local-set-timer",
    "local-set-io",
    "foreign-runtime",
];

fn test_programs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-programs")
}

// ---------------------------------------------------------------------------
// The matrix manifest
// ---------------------------------------------------------------------------

/// What `matrix.toml` declares. Parsed by hand: the file is ours, its
/// grammar is a fixed set of `key = "…"` / `key = […]` lines under
/// three sections, and a full TOML dependency buys nothing here.
struct Matrix {
    primary_tokio: String,
    primary_toolchain: String,
    tokio_floor: String,
    tokio_versions: Vec<String>,
    toolchain_versions: Vec<String>,
    no_unstable_tokio: Vec<String>,
    secondary_toolchain_tokio: Vec<String>,
    ct_only_tokio: Vec<String>,
}

/// The quoted strings in a line, in order.
fn quoted(line: &str) -> Vec<String> {
    line.split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_owned())
        .collect()
}

impl Matrix {
    fn load() -> Matrix {
        let path = test_programs_dir().join("matrix.toml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

        let mut section = String::new();
        let mut m = Matrix {
            primary_tokio: String::new(),
            primary_toolchain: String::new(),
            tokio_floor: String::new(),
            tokio_versions: Vec::new(),
            toolchain_versions: Vec::new(),
            no_unstable_tokio: Vec::new(),
            secondary_toolchain_tokio: Vec::new(),
            ct_only_tokio: Vec::new(),
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.to_owned();
                continue;
            }
            let Some((key, _)) = line.split_once('=') else {
                panic!("unparsed matrix.toml line: {line}");
            };
            let values = quoted(line);
            match (section.as_str(), key.trim()) {
                ("", "primary") => {
                    let [tokio, toolchain] = values.as_slice() else {
                        panic!("unparsed primary cell: {line}");
                    };
                    m.primary_tokio = tokio.clone();
                    m.primary_toolchain = toolchain.clone();
                }
                ("tokio", "floor") => m.tokio_floor = values[0].clone(),
                ("tokio", "versions") => m.tokio_versions = values,
                ("toolchain", "floor") => {}
                ("toolchain", "versions") => m.toolchain_versions = values,
                ("cells", "no_unstable_tokio") => m.no_unstable_tokio = values,
                ("cells", "secondary_toolchain_tokio") => m.secondary_toolchain_tokio = values,
                ("cells", "ct_only_tokio") => m.ct_only_tokio = values,
                _ => panic!("unrecognized matrix.toml key: {line}"),
            }
        }
        for (what, value) in [
            ("primary", &m.primary_tokio),
            ("tokio floor", &m.tokio_floor),
        ] {
            assert!(!value.is_empty(), "matrix.toml declares no {what}");
        }
        assert!(!m.tokio_versions.is_empty(), "matrix.toml lists no tokio");
        m
    }

    /// Resolve a `[cells]` role list to tokio versions, deduplicated —
    /// floor and primary are the same version today, so the roles name
    /// fewer versions than entries.
    fn roles(&self, roles: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for role in roles {
            let version: &str = match role.as_str() {
                "floor" => &self.tokio_floor,
                "primary" => &self.primary_tokio,
                "latest" => self.tokio_versions.last().expect("versions is non-empty"),
                other => other,
            };
            if !out.iter().any(|v| v == version) {
                out.push(version.to_owned());
            }
        }
        out
    }

    /// Every cell the matrix builds, primary first: the whole tokio
    /// axis on the primary toolchain with the cfg on, then the trimmed
    /// secondary axes, then the features-limited cells.
    fn cells(&self) -> Vec<Cell> {
        let cell = |toolchain: &str, tokio: String, unstable: bool, ct_only: bool| Cell {
            toolchain: toolchain.to_owned(),
            tokio,
            unstable,
            ct_only,
        };
        let mut cells = Vec::new();
        for tokio in &self.tokio_versions {
            cells.push(cell(&self.primary_toolchain, tokio.clone(), true, false));
        }
        for tokio in self.roles(&self.no_unstable_tokio) {
            cells.push(cell(&self.primary_toolchain, tokio, false, false));
        }
        for toolchain in &self.toolchain_versions {
            if *toolchain == self.primary_toolchain {
                continue;
            }
            for tokio in self.roles(&self.secondary_toolchain_tokio) {
                cells.push(cell(toolchain, tokio, true, false));
            }
        }
        for tokio in self.roles(&self.ct_only_tokio) {
            cells.push(cell(&self.primary_toolchain, tokio, false, true));
        }
        cells
    }
}

// ---------------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------------

struct Cell {
    toolchain: String,
    tokio: String,
    unstable: bool,
    /// tokio built without `rt-multi-thread` (`regen.sh --ct-only`):
    /// only `ct-runtime` compiles, so the cell holds one fixture, and
    /// its goldens pin the multi_thread rows as flavor absences.
    ct_only: bool,
}

impl Cell {
    /// The fixture-dir spelling `regen.sh` uses, which also names the
    /// golden dir.
    fn name(&self) -> String {
        let cfg = if self.ct_only {
            "ctonly"
        } else if self.unstable {
            "unstable"
        } else {
            "stable"
        };
        format!("rust-{}-tokio-{}-{cfg}", self.toolchain, self.tokio)
    }

    /// The fixtures the cell builds and extracts: everything, except
    /// that a ct-only build compiles only the fixture that never asks
    /// for the multi_thread scheduler.
    fn programs(&self) -> &'static [&'static str] {
        if self.ct_only {
            &["ct-runtime"]
        } else {
            PROGRAMS
        }
    }

    fn is_primary(&self, m: &Matrix) -> bool {
        self.unstable && self.tokio == m.primary_tokio && self.toolchain == m.primary_toolchain
    }

    /// Where `regen.sh` lands this cell's binaries.
    fn bin_dir(&self, m: &Matrix) -> PathBuf {
        let bins = test_programs_dir().join("fixtures/bin");
        if self.is_primary(m) {
            bins
        } else {
            bins.join(self.name())
        }
    }

    /// The file `extract` reads for a program: the binary on ELF
    /// platforms, the dSYM DWARF on macOS.
    fn dwarf_path(&self, m: &Matrix, program: &str) -> PathBuf {
        let bin = self.bin_dir(m).join(program);
        let dsym = bin
            .with_extension("dSYM")
            .join("Contents/Resources/DWARF")
            .join(program);
        if dsym.exists() { dsym } else { bin }
    }

    /// Build the cell's fixtures. `false` (skip) when the toolchain is
    /// not installed; panics on a real build failure.
    fn build(&self) -> bool {
        if !toolchain_installed(&self.toolchain) {
            eprintln!(
                "SKIP: cell {} needs toolchain {} \
                 (rustup toolchain install {})",
                self.name(),
                self.toolchain,
                self.toolchain
            );
            return false;
        }
        let status = Command::new(test_programs_dir().join("regen.sh"))
            .arg("--tokio")
            .arg(&self.tokio)
            .arg("--toolchain")
            .arg(&self.toolchain)
            .args(if self.ct_only {
                &["--ct-only"][..]
            } else if self.unstable {
                &[][..]
            } else {
                &["--no-unstable"][..]
            })
            .args(self.programs())
            .status()
            .expect("failed to run regen.sh");
        assert!(status.success(), "regen.sh failed for cell {}", self.name());
        true
    }
}

fn toolchain_installed(toolchain: &str) -> bool {
    Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
        .lines()
        .any(|l| l.starts_with(toolchain))
}

// ---------------------------------------------------------------------------
// The three per-cell reports
// ---------------------------------------------------------------------------

/// The walk-contract report for every program, concatenated.
fn walk_report(bundles: &[(&str, Bundle)]) -> String {
    let mut out = String::new();
    for (program, bundle) in bundles {
        writeln!(out, "program: {program}").unwrap();
        write!(out, "{}", verify_walk_contract(&BundleView::new(bundle))).unwrap();
        writeln!(out).unwrap();
    }
    out
}

/// The detection catalog: every debug format in any program's bundle,
/// deduplicated across programs, sorted by type name, offsets
/// stripped. A type two programs describe differently keeps both
/// renderings, each annotated with its programs — agreement is the
/// expected case, so the annotation itself is a diff to read.
///
/// The header line pins which detector [`Family`] the cell's bundles
/// selected — recomputed from each bundle's recorded tokio version by
/// the same selection extraction ran — so a release that shifts the
/// family boundary is a golden diff here, not a silent re-dispatch.
fn formats_report(bundles: &[(&str, Bundle)]) -> String {
    let offsets = regex::Regex::new(r"@\+\d+").unwrap();

    // family description -> programs. One line when all agree.
    let mut families: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for (program, bundle) in bundles {
        families
            .entry(Family::describe(bundle.meta.tokio_version.as_ref()))
            .or_default()
            .insert(program);
    }
    // type name -> rendering -> programs with that rendering.
    let mut catalog: BTreeMap<String, BTreeMap<String, BTreeSet<&str>>> = BTreeMap::new();
    for (program, bundle) in bundles {
        for (id, node) in &bundle.types.debug_formats {
            let rendered = describe_debug_format(bundle, *id, node);
            let (name, _) = rendered
                .split_once(" :: ")
                .unwrap_or_else(|| panic!("unexpected format rendering: {rendered}"));
            // Whether a futures_util adapter survives as its own
            // monomorphization is the target platform's call; pinning
            // one would make the catalog unportable.
            if name.starts_with("futures_util::") || name.starts_with("futures_core::") {
                continue;
            }
            let stripped = offsets.replace_all(&rendered, "").into_owned();
            catalog
                .entry(name.to_owned())
                .or_default()
                .entry(stripped)
                .or_default()
                .insert(program);
        }
    }

    let mut out = String::new();
    for (family, programs) in &families {
        if families.len() == 1 {
            writeln!(out, "family: {family}").unwrap();
        } else {
            let programs: Vec<&str> = programs.iter().copied().collect();
            writeln!(out, "family: {family} [{}]", programs.join(", ")).unwrap();
        }
    }
    writeln!(out).unwrap();
    for renderings in catalog.values() {
        for (rendering, programs) in renderings {
            if renderings.len() == 1 {
                writeln!(out, "{rendering}").unwrap();
            } else {
                let programs: Vec<&str> = programs.iter().copied().collect();
                writeln!(out, "{rendering} [{}]", programs.join(", ")).unwrap();
            }
        }
    }
    out
}

/// The portable extraction summary for every program, concatenated.
fn summary_report(bundles: &[(&str, Bundle)]) -> String {
    let mut out = String::new();
    for (program, bundle) in bundles {
        let crate_str = program.replace('-', "_");
        write!(out, "{}", portable_summary(bundle, program, &crate_str)).unwrap();
        writeln!(out).unwrap();
    }
    out
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Diff (or bless) one cell's golden, recording a mismatch rather than
/// raising it.
///
/// A snapshot assertion raises, which is right for a test that makes
/// one and wrong here: a cell is three goldens and the matrix is
/// fourteen cells, and what a new tokio release moves it moves in
/// several at once. Raising would report the first of them and build
/// every remaining cell for nothing. So the assertion is caught and
/// only which golden diverged is collected — the diff itself is
/// already on stdout by then, printed on the way out, and a rejected
/// golden is beside its file as `<name>.snap.new`.
fn check_golden(cell: &str, name: &str, actual: &str, failures: &mut Vec<String>) {
    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path(Path::new("matrix").join(cell));
    settings.set_prepend_module_to_snapshot(false);
    // These are generated reports; naming the expression that built one
    // says nothing a reader of the diff wants.
    settings.set_omit_expression(true);
    let checked = settings.bind(|| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            insta::assert_snapshot!(name, actual);
        }))
    });
    if checked.is_err() {
        failures.push(format!("{cell}/{name}.snap"));
    }
}

#[test]
fn test_matrix() {
    let Ok(filter) = std::env::var("HANSEI_MATRIX") else {
        eprintln!("SKIP: set HANSEI_MATRIX=1 to run the version matrix");
        return;
    };
    let matrix = Matrix::load();

    let mut failures = Vec::new();
    let mut ran = 0usize;
    for cell in matrix.cells() {
        let name = cell.name();
        if filter != "1" && !name.contains(&filter) {
            continue;
        }
        if !cell.build() {
            continue;
        }
        ran += 1;

        let bundles: Vec<(&str, Bundle)> = cell
            .programs()
            .iter()
            .map(|program| {
                let opts = ExtractOptions {
                    extract_args: format!("matrix-test {name} {program}"),
                    ..Default::default()
                };
                let (bundle, _stats) = extract_file(&cell.dwarf_path(&matrix, program), &opts)
                    .unwrap_or_else(|e| panic!("extract failed for {name}/{program}: {e}"));
                (*program, bundle)
            })
            .collect();

        check_golden(&name, "walk", &walk_report(&bundles), &mut failures);
        check_golden(&name, "formats", &formats_report(&bundles), &mut failures);
        check_golden(&name, "summary", &summary_report(&bundles), &mut failures);
        eprintln!("matrix: checked cell {name}");
    }

    assert!(ran > 0, "no matrix cell matched HANSEI_MATRIX={filter}");
    assert!(
        failures.is_empty(),
        "{} matrix golden(s) diverged (diffs above; INSTA_UPDATE=always to re-bless):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

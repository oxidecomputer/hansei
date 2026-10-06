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
//! reports every cell that diverged rather than the first. A cell whose
//! toolchain is not rustup-installed fails, naming the command that
//! installs it, rather than skip: a run that skipped cells would pass
//! without having built them. Run it alone (`cargo test -p
//! hansei-runtime --test matrix`), not under a workspace-wide
//! `cargo test`: the
//! primary cell shares its fixture dirs with the extraction goldens,
//! and two test binaries rebuilding one fixture dir race.
//!
//! Each cell also holds the reviews to the sources it builds: every
//! file a review read, at each crate release the cell's lockfile pins
//! and at the cell's toolchain, must hash to a revision the review
//! lists — so a checksum copied wrong, or a release whose file changed
//! with nobody reading it, fails here rather than vouching for code no
//! one saw. The toolchain's sources are its `rust-src` component. A
//! separate test, which needs no build, holds each reviewed tokio and
//! rustc span to the newest release the matrix pins in that minor.
//!
//! The goldens are the rendering in the Linux test image
//! (`.github/image/`): blessed there (`test-programs/matrix.sh bless`),
//! and checked there by CI's matrix workflow, which is dispatched by
//! hand. Offsets are stripped and `futures_util` adapters
//! filtered where monomorphization survival is the target's call, but
//! the type population is still the platform's own — its platform
//! types, and whatever identical code its linker folds away — so a run
//! anywhere else diffs without meaning anything.

use exegesis::describe::{describe_debug_format, describe_semantics};
use exegesis::detect::Family;
use exegesis::detect::reviewed::{Subject, sources};
use exegesis::detect::semantics::{RUSTC_RELEASES, Release, Releases, TOKIO_RELEASES};
use exegesis::extract::{ExtractOptions, extract_file};
use exegesis::summary::portable_summary;
use hansei_bundle::{Bundle, BundleView};
use hansei_runtime::testkit::matrix::Matrix;
use hansei_runtime::tokio::contract::verify_walk_contract;
use md5::{Digest, Md5};

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
    "blocking-pool",
    "delegation-cases",
    "armed-select",
    "watch-stream",
    "http-conns",
    "two-releases",
    "tls-conns",
];

fn test_programs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-programs")
}

// ---------------------------------------------------------------------------
// The matrix manifest
// ---------------------------------------------------------------------------

/// Resolve a `[cells]` role list to tokio versions, deduplicated —
/// floor and primary are the same version today, so the roles name
/// fewer versions than entries.
fn roles(m: &Matrix, roles: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for role in roles {
        let version: &str = match role.as_str() {
            "floor" => &m.tokio.floor,
            "primary" => &m.primary.tokio,
            "latest" => m.tokio.versions.last().expect("versions is non-empty"),
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
fn cells(m: &Matrix) -> Vec<Cell> {
    let cell = |toolchain: &str, tokio: String, unstable: bool, ct_only: bool| Cell {
        toolchain: toolchain.to_owned(),
        tokio,
        unstable,
        ct_only,
    };
    let mut cells = Vec::new();
    for tokio in &m.tokio.versions {
        cells.push(cell(&m.primary.toolchain, tokio.clone(), true, false));
    }
    for tokio in roles(m, &m.cells.no_unstable_tokio) {
        cells.push(cell(&m.primary.toolchain, tokio, false, false));
    }
    for toolchain in &m.toolchain.versions {
        if *toolchain == m.primary.toolchain {
            continue;
        }
        for tokio in roles(m, &m.cells.secondary_toolchain_tokio) {
            cells.push(cell(toolchain, tokio, true, false));
        }
    }
    for tokio in roles(m, &m.cells.ct_only_tokio) {
        cells.push(cell(&m.primary.toolchain, tokio, false, true));
    }
    cells
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
    fn programs(&self) -> Vec<&str> {
        if self.ct_only {
            vec!["ct-runtime"]
        } else {
            PROGRAMS.to_vec()
        }
    }

    fn is_primary(&self, m: &Matrix) -> bool {
        self.unstable && self.tokio == m.primary.tokio && self.toolchain == m.primary.toolchain
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

    /// Build the cell's fixtures; panics on a build failure.
    fn build(&self) {
        let dir = test_programs_dir();
        let matrix = Matrix::read(&dir);
        let recipe = testrun::fixture::Recipe {
            toolchain: self.toolchain.clone(),
            tokio: self.tokio.clone(),
            unstable: self.unstable,
            ct_only: self.ct_only,
            debug_info: true,
            dwp: false,
        };
        testrun::once_per_run(
            &dir.join("fixtures/.built")
                .join(format!("matrix-{}", self.name())),
            || {
                let mut inputs = testrun::Inputs::new();
                for program in self.programs() {
                    inputs.text(&recipe.inputs(&dir, &matrix, program));
                }
                inputs.finish()
            },
            || {
                // Through bash: a copied tree need not keep the mode bit.
                let status = Command::new("bash")
                    .arg(dir.join("regen.sh"))
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
            },
        );
    }
}

// ---------------------------------------------------------------------------
// The sources the reviews read
// ---------------------------------------------------------------------------

/// Every `(package, version)` a lockfile pins.
fn lock_packages(path: &Path) -> Vec<(String, semver::Version)> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let value = |line: &str, key: &str| {
        line.strip_prefix(key)
            .map(|rest| rest.trim_matches(|c| c == '"' || c == ' ').to_owned())
    };
    let mut out = Vec::new();
    let mut name = None;
    for line in text.lines() {
        if let Some(n) = value(line, "name = ") {
            name = Some(n);
        } else if let Some(v) = value(line, "version = ")
            && let Some(n) = name.take()
            && let Ok(v) = semver::Version::parse(&v)
        {
            out.push((n, v));
        }
    }
    out
}

/// Where cargo unpacked a registry release: `<CARGO_HOME>/registry/src/
/// <index>/<package>-<version>`, in whichever index holds it.
fn crate_root(package: &str, version: &semver::Version) -> Option<PathBuf> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))?;
    std::fs::read_dir(home.join("registry/src"))
        .ok()?
        .flatten()
        .map(|index| index.path().join(format!("{package}-{version}")))
        .find(|dir| dir.is_dir())
}

/// The root of a toolchain's `rust-src`, the standard library sources
/// as the toolchain ships them.
fn rust_src(toolchain: &str) -> PathBuf {
    let out = Command::new("rustup")
        .args(["run", toolchain, "rustc", "--print", "sysroot"])
        .output()
        .expect("failed to run rustc --print sysroot");
    let sysroot = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    PathBuf::from(sysroot).join("lib/rustlib/src/rust")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hold every review to the sources the cell builds: each file a
/// review read, at every release of its subject the cell pins inside
/// the review's releases, must hash to one of the revisions it lists.
/// A file absent from a release is the review's to explain, not a
/// mismatch; a review none of whose files a release ships is one.
fn check_sources(cell: &Cell, m: &Matrix, failures: &mut Vec<String>) {
    let dir = test_programs_dir();
    let lockfile = if cell.tokio == m.primary.tokio {
        dir.join("Cargo.lock")
    } else {
        dir.join(format!("locks/tokio-{}.lock", cell.tokio))
    };
    let toolchain = semver::Version::parse(&cell.toolchain).expect("a release toolchain");
    let packages = lock_packages(&lockfile);
    let name = cell.name();
    for review in sources() {
        let releases: Vec<(String, semver::Version, Option<PathBuf>)> = match review.subject {
            Subject::Rustc => {
                let root = rust_src(&cell.toolchain);
                let root = root.is_dir().then_some(root);
                vec![("rustc".to_owned(), toolchain.clone(), root)]
            }
            Subject::Crate(package) => packages
                .iter()
                .filter(|(n, _)| n == package)
                .map(|(n, v)| (n.clone(), v.clone(), crate_root(n, v)))
                .collect(),
        };
        for (subject, version, root) in releases {
            if !review.releases.covers(&version) || review.checksums.is_empty() {
                continue;
            }
            let Some(root) = root else {
                failures.push(format!(
                    "{name}: {subject} {version}'s sources are not on disk to check {} \
                     against{}",
                    review.family,
                    if subject == "rustc" {
                        format!(" (rustup component add rust-src --toolchain {version})")
                    } else {
                        String::new()
                    }
                ));
                continue;
            };
            let files: BTreeSet<&str> = review.checksums.iter().map(|&(f, _)| f).collect();
            let mut shipped = 0;
            for file in files {
                let Ok(bytes) = std::fs::read(root.join(file)) else {
                    continue;
                };
                shipped += 1;
                let actual: [u8; 16] = Md5::digest(&bytes).into();
                let reviewed = review
                    .checksums
                    .iter()
                    .any(|&(f, md5)| f == file && md5 == actual);
                if !reviewed {
                    failures.push(format!(
                        "{name}: {subject} {version}'s {file} hashes to {}, \
                         not a revision {} lists",
                        hex(&actual),
                        review.family
                    ));
                }
            }
            if shipped == 0 {
                failures.push(format!(
                    "{name}: {subject} {version} ships none of the files {} read",
                    review.family
                ));
            }
        }
    }
}

/// The spans a list of matrix versions implies: per minor, `.0`
/// through the newest patch listed.
fn spans_through(versions: &[String]) -> Vec<(Release, Release)> {
    let mut newest: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    for v in versions {
        let v = semver::Version::parse(v).expect("a matrix version");
        let patch = newest.entry((v.major, v.minor)).or_default();
        *patch = (*patch).max(v.patch);
    }
    newest
        .into_iter()
        .map(|((major, minor), patch)| ((major, minor, 0), (major, minor, patch)))
        .collect()
}

/// The tokio and rustc releases the reviews read end, minor by minor,
/// at the newest release the matrix pins there: a patch onboarded into
/// the matrix raises its span in the same change, and no span reaches
/// a release the matrix never built — the checksums each cell holds
/// the reviews to are only ever checked at what the matrix builds.
#[test]
fn test_reviewed_releases_end_at_the_matrix_pins() {
    let m = Matrix::load();
    let check = |what: &str, releases: Releases, versions: &[String]| {
        assert_eq!(
            releases.0,
            spans_through(versions).as_slice(),
            "the reviewed {what} releases ({releases}) and test-programs/matrix.toml's \
             {what} versions disagree: onboard and review a release in one change"
        );
    };
    check("tokio", TOKIO_RELEASES, &m.tokio.versions);
    check("rustc", RUSTC_RELEASES, &m.toolchain.versions);
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
            let mut stripped = offsets.replace_all(&rendered, "").into_owned();
            // The crate release the bundle labeled the type with: on a
            // cell whose fixture links a crate twice, two classes of
            // one name render two ways, and the label says which
            // release each rendering is for. Every tokio type carries
            // the cell's tokio version here, pinning it beside the
            // family line.
            if let Some(release) = BundleView::new(bundle)
                .ty(*id)
                .and_then(|ty| ty.crate_release())
            {
                stripped.push_str(&format!(" — {release}"));
            }
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
/// The semantic catalog: every origin, rule and record per program, as
/// `tokio-info dump` prints them. Single-target like the other reports,
/// so it names the rule ids and task indexes a bundle actually assigned.
fn semantics_report(bundles: &[(&str, Bundle)]) -> String {
    let mut out = String::new();
    for (program, bundle) in bundles {
        writeln!(out, "program: {program}").unwrap();
        write!(out, "{}", describe_semantics(bundle)).unwrap();
        writeln!(out).unwrap();
    }
    out
}

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
    let mut unreviewed = Vec::new();
    let mut matched = 0usize;
    for cell in cells(&matrix) {
        let name = cell.name();
        if filter != "1" && !name.contains(&filter) {
            continue;
        }
        matched += 1;
        if !toolchain_installed(&cell.toolchain) {
            failures.push(format!(
                "{name}: toolchain {0} is not installed (rustup toolchain install {0})",
                cell.toolchain
            ));
            continue;
        }
        cell.build();
        check_sources(&cell, &matrix, &mut unreviewed);

        let programs = cell.programs();
        let bundles: Vec<(&str, Bundle)> = programs
            .iter()
            .map(|program| {
                if *program == "delegation-cases" {
                    let found = exegesis::testkit::assert_instrumented_sources(
                        &cell.dwarf_path(&matrix, program),
                    );
                    assert_eq!(
                        found,
                        BTreeSet::from(["poll<delegation_cases::Probe<8>>".to_owned()]),
                        "{name}/{program}: Instrumented inventory covered the wrong functions"
                    );
                }
                let opts = ExtractOptions {
                    extract_args: format!("matrix-test {name} {program}"),
                    ..Default::default()
                };
                let (bundle, _stats) = extract_file(&cell.dwarf_path(&matrix, program), &opts)
                    .unwrap_or_else(|e| panic!("extract failed for {name}/{program}: {e}"));
                if *program == "delegation-cases" {
                    // Every cell is a DWARF 4 registry build of the pinned
                    // tracing: the rule binds on its path in each.
                    exegesis::testkit::assert_instrumented_origin(&bundle);
                }
                (*program, bundle)
            })
            .collect();

        check_golden(&name, "walk", &walk_report(&bundles), &mut failures);
        check_golden(&name, "formats", &formats_report(&bundles), &mut failures);
        check_golden(&name, "summary", &summary_report(&bundles), &mut failures);
        check_golden(
            &name,
            "semantics",
            &semantics_report(&bundles),
            &mut failures,
        );
        eprintln!("matrix: checked cell {name}");
    }

    assert!(matched > 0, "no matrix cell matched HANSEI_MATRIX={filter}");
    assert!(
        unreviewed.is_empty(),
        "{} reviewed source(s) do not match what the cells build:\n  {}",
        unreviewed.len(),
        unreviewed.join("\n  ")
    );
    assert!(
        failures.is_empty(),
        "{} matrix check(s) failed (golden diffs above; INSTA_UPDATE=always to re-bless):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

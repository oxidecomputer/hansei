//! Extraction golden tests (plan §11.2): run `extract` on the
//! test-programs fixtures and compare a textual summary against checked-in
//! expectations.
//!
//! Fixtures are never checked in: missing ones are built on demand by
//! `test-programs/regen.sh` with the pinned bundle-compatible toolchain;
//! when that toolchain is unavailable the tests skip with a message.
//! Because fixtures are always freshly built, these tests double as the
//! canary for DWARF-shape and mangling drift across toolchain bumps.
//!
//! The summaries contain only platform-portable facts — demangled type
//! names, variant shapes, await-point lines, presence of infra/statics —
//! and are filtered to the fixture crate's own types, so one golden file
//! serves macOS and illumos. Regenerate with `EXEGESIS_BLESS=1 cargo test
//! -p exegesis --test golden`.

use exegesis::bundle::{Bundle, StaticRole, TypeDef};
use exegesis::extract::{ExtractOptions, ExtractStats, extract_file};

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const TOOLCHAIN: &str = "1.97.0";

fn test_programs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-programs")
}

/// The file `extract` should read for a fixture: the binary itself on
/// ELF platforms, the dSYM DWARF on macOS.
fn dwarf_path(program: &str) -> PathBuf {
    let bin = test_programs_dir().join("fixtures/bin").join(program);
    let dsym = bin
        .with_extension("dSYM")
        .join("Contents/Resources/DWARF")
        .join(program);
    if dsym.exists() { dsym } else { bin }
}

/// Build a fixture if it is missing. Returns `false` (skip) when the
/// pinned toolchain is not installed; panics on real build failures.
fn ensure_fixture(program: &str) -> bool {
    // Serialize builds: parallel test threads would contend on the
    // fixture target dir.
    static BUILD_LOCK: Mutex<()> = Mutex::new(());
    let _guard = BUILD_LOCK.lock().unwrap();

    if dwarf_path(program).exists() {
        return true;
    }

    let toolchains = Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if !toolchains.lines().any(|l| l.starts_with(TOOLCHAIN)) {
        eprintln!(
            "SKIP: fixture {program} missing and toolchain {TOOLCHAIN} not installed \
             (rustup toolchain install {TOOLCHAIN})"
        );
        return false;
    }

    let status = Command::new(test_programs_dir().join("regen.sh"))
        .arg(program)
        .status()
        .expect("failed to run regen.sh");
    assert!(status.success(), "regen.sh failed for {program}");
    assert!(
        dwarf_path(program).exists(),
        "regen.sh succeeded but {program} fixture is still missing"
    );
    true
}

fn leaf_of(name: &str) -> &str {
    // The generic suffix may itself contain `::`; strip it first.
    let base = name.split('<').next().unwrap_or(name);
    let leaf_start = base.rfind("::").map(|i| i + 2).unwrap_or(0);
    &name[leaf_start..]
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Render the platform-portable summary of an extraction, filtered to
/// types mentioning `crate_str` (the fixture crate's name).
fn summarize(program: &str, crate_str: &str, bundle: &Bundle) -> String {
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>");
    let type_name = |id: exegesis::bundle::BundleTypeId| -> String {
        match &bundle.types.types[id.0 as usize] {
            TypeDef::Base { name, .. }
            | TypeDef::Struct { name, .. }
            | TypeDef::Union { name, .. }
            | TypeDef::Enum { name, .. }
            | TypeDef::CEnum { name, .. }
            | TypeDef::Opaque { name, .. } => s(*name).to_owned(),
            TypeDef::Pointer { .. } => "<pointer>".to_owned(),
            TypeDef::Array { .. } => "<array>".to_owned(),
        }
    };

    let mut out = String::new();
    writeln!(out, "program: {program}").unwrap();

    // Task entries for the fixture's own futures, grouped by future type.
    writeln!(out, "\n[tasks]").unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for (i, entry) in bundle.tasks.entries.iter().enumerate() {
        let display = s(entry.display_name);
        if !display.contains(crate_str) || !seen.insert(display.to_owned()) {
            continue;
        }

        let entries_for_future = bundle
            .tasks
            .entries
            .iter()
            .filter(|e| e.display_name == entry.display_name)
            .count();
        let symbols: Vec<usize> = bundle
            .tasks
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.display_name == entry.display_name)
            .map(|(j, _)| {
                bundle
                    .tasks
                    .by_symbol
                    .values()
                    .filter(|id| id.0 as usize == j)
                    .count()
            })
            .collect();

        writeln!(out, "task: {display}").unwrap();
        let p = &bundle.provenance.entries[i];
        writeln!(out, "  kind: {:?}", p.kind).unwrap();
        match &p.decl {
            Some(loc) => {
                writeln!(out, "  decl: {}:{}", basename(s(loc.file)), loc.line).unwrap()
            }
            None => writeln!(out, "  decl: <none>").unwrap(),
        }
        writeln!(out, "  entries: {entries_for_future}").unwrap();
        writeln!(
            out,
            "  symbols-per-entry: {}",
            symbols
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
        .unwrap();

        writeln!(out, "  stage: {}", leaf_of(&type_name(entry.stage))).unwrap();

        if let TypeDef::Enum { shape, .. } = &bundle.types.types[entry.future.0 as usize] {
            writeln!(out, "  variants:").unwrap();
            for v in &shape.variants {
                let payload = type_name(v.payload.ty);
                match &v.decl {
                    Some(loc) => writeln!(
                        out,
                        "    {} @ {}:{}",
                        leaf_of(&payload),
                        basename(s(loc.file)),
                        loc.line
                    )
                    .unwrap(),
                    None => writeln!(out, "    {}", leaf_of(&payload)).unwrap(),
                }
            }
        }
    }

    // Dyn-future entries for the fixture's own types: which symbol kinds
    // key each type.
    writeln!(out, "\n[dyn-futures]").unwrap();
    let mut dyn_types: std::collections::BTreeMap<String, (bool, bool)> = Default::default();
    for (sym, id) in &bundle.dyn_futures.by_symbol {
        let name = type_name(*id);
        if !name.contains(crate_str) {
            continue;
        }
        let e = dyn_types.entry(name).or_default();
        // drop_glue instantiations are recognizable in the v0 mangling.
        if sym.contains("9drop_glue") {
            e.1 = true;
        } else {
            e.0 = true;
        }
    }
    for (name, (poll, glue)) in &dyn_types {
        let mut kinds = Vec::new();
        if *poll {
            kinds.push("poll");
        }
        if *glue {
            kinds.push("drop_glue");
        }
        writeln!(out, "dyn: {name} ({})", kinds.join(", ")).unwrap();
    }

    writeln!(out, "\n[infra]").unwrap();
    let infra = &bundle.infra;
    for (what, id) in [
        ("header", infra.header),
        ("vtable", infra.vtable),
        ("trailer", infra.trailer),
        ("context", infra.context),
        ("scheduler_handle", infra.scheduler_handle),
        ("mt_handle", infra.mt_handle),
        ("location", infra.location),
        ("raw_waker_vtable", infra.raw_waker_vtable),
    ] {
        let name = type_name(id);
        let ok = if name.starts_with("<missing") { "MISSING" } else { "ok" };
        writeln!(out, "{what}: {ok}").unwrap();
    }

    writeln!(out, "\n[statics]").unwrap();
    for (role, label) in [
        (StaticRole::TlsContextKey, "tls-context-key"),
        (StaticRole::TaskWakerVtable, "task-waker-vtable"),
    ] {
        let ok = if bundle.statics.entries.contains_key(&role) { "ok" } else { "MISSING" };
        writeln!(out, "{label}: {ok}").unwrap();
    }

    out
}

/// Structural assertions that hold for every fixture — the "zero silent
/// drops" checks (§11.2) plus metadata sanity.
fn assert_clean(program: &str, bundle: &Bundle, stats: &ExtractStats) {
    assert_eq!(stats.cells_missing, 0, "{program}: cells missing");
    assert_eq!(stats.stages_missing, 0, "{program}: stages missing");
    assert_eq!(
        stats.vtable_missing_linkage, 0,
        "{program}: vtable fns without linkage names"
    );
    assert_eq!(
        stats.dyn_unresolved_self, 0,
        "{program}: Future::poll impls with unresolvable self"
    );
    assert!(stats.infra_missing.is_empty(), "{program}: {:?}", stats.infra_missing);
    assert!(
        stats.statics_missing.is_empty(),
        "{program}: {:?}",
        stats.statics_missing
    );

    assert!(
        bundle.meta.rustc_version.contains(TOOLCHAIN),
        "{program}: unexpected rustc version {:?}",
        bundle.meta.rustc_version
    );
    assert!(
        bundle.meta.tokio_version.is_some(),
        "{program}: tokio version not recovered"
    );
    assert!(
        !bundle.meta.symbol_fingerprint.is_empty(),
        "{program}: empty symbol fingerprint"
    );
    // Fingerprint symbols are poll instantiations, stored unsuffixed.
    for sym in &bundle.meta.symbol_fingerprint {
        assert!(sym.starts_with("_R"), "{program}: non-v0 fingerprint {sym:?}");
    }
    assert!(
        bundle
            .types
            .debug_formats
            .values()
            .any(|format| matches!(format, exegesis::bundle::DebugFormat::Transparent { .. })),
        "{program}: no transparent known-type formats were extracted"
    );
    assert!(
        bundle.types.debug_formats.iter().any(|(id, format)| {
            matches!(format, exegesis::bundle::DebugFormat::Transparent { .. })
                && match &bundle.types.types[id.0 as usize] {
                    TypeDef::Struct { name, .. } => bundle
                        .strings
                        .get(*name)
                        .is_some_and(|name| name.starts_with("core::ptr::non_null::NonNull<")),
                    _ => false,
                }
        }),
        "{program}: no transparent NonNull format was extracted"
    );
    for prefix in [
        "tokio::loom::std::unsafe_cell::UnsafeCell<",
        "tokio::loom::std::atomic_",
    ] {
        assert!(
            bundle.types.debug_formats.iter().any(|(id, format)| {
                matches!(format, exegesis::bundle::DebugFormat::Transparent { .. })
                    && match &bundle.types.types[id.0 as usize] {
                        TypeDef::Struct { name, .. } => bundle
                            .strings
                            .get(*name)
                            .is_some_and(|name| name.starts_with(prefix)),
                        _ => false,
                    }
            }),
            "{program}: no transparent {prefix} format was extracted"
        );
    }
    assert!(
        bundle.types.debug_formats.values().any(|format| matches!(
            format,
            exegesis::bundle::DebugFormat::Known(exegesis::bundle::KnownFormat::Atomic { .. })
        )),
        "{program}: no atomic known-type formats were extracted"
    );
    assert!(
        bundle.types.debug_formats.values().any(|format| matches!(
            format,
            exegesis::bundle::DebugFormat::Known(
                exegesis::bundle::KnownFormat::FunctionPointer
            )
        )),
        "{program}: no function-pointer known-type formats were extracted"
    );
    assert!(
        bundle.types.debug_formats.values().any(|format| matches!(
            format,
            exegesis::bundle::DebugFormat::Known(
                exegesis::bundle::KnownFormat::DynPointer { .. }
            )
        )),
        "{program}: no dyn-pointer known-type formats were extracted"
    );
    assert!(
        bundle.types.debug_formats.values().any(|format| matches!(
            format,
            exegesis::bundle::DebugFormat::Known(
                exegesis::bundle::KnownFormat::RawWakerVTable { .. }
            )
        )),
        "{program}: no RawWakerVTable known-type format was extracted"
    );
    if program == "simple-await" {
        assert!(
            bundle.types.debug_formats.values().any(|format| matches!(
                format,
                exegesis::bundle::DebugFormat::Known(
                    exegesis::bundle::KnownFormat::BTreeMap { .. }
                )
            )),
            "{program}: no BTreeMap known-type format was extracted"
        );
    }
}

fn run_golden(program: &str) {
    if !ensure_fixture(program) {
        return;
    }

    let opts = ExtractOptions {
        extract_args: format!("golden-test {program}"),
        ..Default::default()
    };
    let (bundle, stats) = extract_file(&dwarf_path(program), &opts)
        .unwrap_or_else(|e| panic!("extract failed for {program}: {e}"));

    // The bundle must survive its own validation and a save/load round
    // trip (save validates; load re-validates).
    let tmp = tempfile::NamedTempFile::new().unwrap();
    bundle.save(tmp.path()).expect("bundle failed validation on save");
    let reloaded = Bundle::load(tmp.path()).expect("bundle failed to reload");
    assert_eq!(reloaded, bundle, "{program}: save/load round trip changed the bundle");

    assert_clean(program, &bundle, &stats);

    let crate_str = program.replace('-', "_");
    let summary = summarize(program, &crate_str, &bundle);

    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{program}.golden"));
    if std::env::var_os("EXEGESIS_BLESS").is_some() {
        std::fs::write(&golden_path, &summary).unwrap();
        eprintln!("blessed {}", golden_path.display());
        return;
    }

    let expected = std::fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "no golden file {} — run with EXEGESIS_BLESS=1 to create it",
            golden_path.display()
        )
    });
    assert_eq!(
        summary, expected,
        "{program}: extraction summary diverged from {} \
         (EXEGESIS_BLESS=1 to re-bless)\n--- actual ---\n{summary}",
        golden_path.display()
    );
}

#[test]
fn test_golden_simple_await() {
    run_golden("simple-await");
}

#[test]
fn test_golden_nested_await() {
    run_golden("nested-await");
}

#[test]
fn test_golden_dyn_future() {
    run_golden("dyn-future");
}

#[test]
fn test_golden_select_combinator() {
    run_golden("select-combinator");
}

#[test]
fn test_golden_futurelock() {
    run_golden("futurelock");
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `exegesis` binary, run the way a user runs it.
//!
//! Everything below argv was already covered — extraction by the golden
//! suite, bundle io by the unit tests — but the commands themselves ran
//! under no test at all: `dump` is the sole production caller of the
//! full display-program describer, `dump-dwarf` is a second,
//! independent DWARF entry point, and the failure paths are what an
//! operator actually sees when a binary is not what they thought.
//!
//! No fixture is built here. The bundle-reading commands run over the
//! checked-in `hansei-runtime` fixture bundles — real tokio bundles
//! with every formatter attached — and the DWARF-reading ones over
//! this test binary itself, which is a real debug binary on every
//! platform and contains no tokio on any of them.

use exegesis::bundle::Bundle;
use exegesis::extract::{Error, ExtractOptions, extract_file};

use std::path::PathBuf;
use std::process::{Command, Output};

fn exegesis(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_exegesis"))
        .args(args)
        .output()
        .expect("failed to run exegesis")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The checked-in offline fixture bundles, shared with `hansei-runtime`.
///
/// The illumos set by name rather than whichever this build would read:
/// what these want is bundles to run the CLI over, and that set has one
/// per program on every platform, macOS included.
fn fixture_bundles() -> Vec<PathBuf> {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../hansei-runtime/tests/fixtures/illumos");
    let mut bundles: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("the fixture dir exists")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "bundle"))
        .collect();
    bundles.sort();
    assert!(!bundles.is_empty(), "no fixture bundles in {dir:?}");
    bundles
}

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create a tempdir")
}

// ---------------------------------------------------------------------------
// stats and dump, over every checked-in bundle
// ---------------------------------------------------------------------------

#[test]
fn test_stats_reports_a_bundle() {
    let bundle = fixture_bundles()
        .into_iter()
        .find(|p| p.ends_with("futurelock.bundle"))
        .expect("the futurelock fixture is checked in");
    let out = exegesis(&["stats", bundle.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    for want in [
        "format version:",
        "rustc:",
        "tokio:",
        "debug binary:",
        "fingerprint:",
        "types:",
        "struct",
        "task entries:",
    ] {
        assert!(text.contains(want), "missing {want:?} in:\n{text}");
    }
}

/// `dump` re-validates a loaded bundle in depth and renders every table,
/// including each attached display program resolved to the member paths
/// it addresses — the one production caller of the whole describer.
/// Every checked-in bundle must survive it.
#[test]
fn test_dump_renders_every_checked_in_bundle() {
    for bundle in fixture_bundles() {
        let out = exegesis(&["dump", bundle.to_str().unwrap()]);
        assert!(out.status.success(), "{bundle:?}: {}", stderr(&out));
        let text = stdout(&out);
        for want in [
            "== types (",
            "== tasks (",
            "== dyn futures (",
            "== statics (",
        ] {
            assert!(text.contains(want), "{bundle:?} missing {want:?}");
        }
        // A tokio bundle carries dozens of attached formatters; a dump
        // with hardly any means the describer or the bundle lost them.
        let described = text.matches("debug: ").count();
        assert!(described > 20, "{bundle:?}: only {described} debug formats");
    }
}

#[test]
fn test_bundle_commands_reject_what_is_not_a_bundle() {
    let dir = scratch();
    let path = dir.path().join("garbage");
    std::fs::write(&path, b"not a bundle").unwrap();
    for cmd in ["stats", "dump"] {
        let out = exegesis(&[cmd, path.to_str().unwrap()]);
        assert!(!out.status.success(), "{cmd} accepted garbage");
        assert!(
            stderr(&out).starts_with("error: "),
            "{cmd}: {}",
            stderr(&out)
        );
    }
}

// ---------------------------------------------------------------------------
// dump-dwarf
// ---------------------------------------------------------------------------

#[test]
fn test_dump_dwarf_summarizes_an_object() {
    let exe = std::env::current_exe().unwrap();
    let out = exegesis(&["dump-dwarf", exe.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("total types"), "{text}");
    assert!(text.contains("total statics"), "{text}");

    let dir = scratch();
    let path = dir.path().join("garbage");
    std::fs::write(&path, b"not an object").unwrap();
    let out = exegesis(&["dump-dwarf", path.to_str().unwrap()]);
    assert!(!out.status.success());
}

// ---------------------------------------------------------------------------
// extract: the failure paths an operator sees
// ---------------------------------------------------------------------------

/// The errors reach the user as their messages, hints included — not as
/// their `Debug` spelling, which is what returning them from `main`
/// printed.
#[test]
fn test_extract_failures_name_their_cause() {
    let out = exegesis(&["extract", "/no/such/binary", "-o", "/dev/null"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("error: failed to read the debug binary"),
        "{}",
        stderr(&out)
    );

    let dir = scratch();
    let path = dir.path().join("garbage");
    std::fs::write(&path, b"not an object file").unwrap();
    let out = exegesis(&["extract", path.to_str().unwrap(), "-o", "/dev/null"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("error: failed to parse the debug binary"),
        "{}",
        stderr(&out)
    );

    // A real debug binary with no tokio in it: refused, with the flag
    // that overrides the refusal named in the message.
    let exe = std::env::current_exe().unwrap();
    let out = exegesis(&["extract", exe.to_str().unwrap(), "-o", "/dev/null"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--allow-missing-infra"),
        "{}",
        stderr(&out)
    );
}

/// `--allow-missing-infra` extracts a tokio-less binary anyway: the
/// placeholder bundle round-trips through `stats` and through `dump`'s
/// in-depth validation.
#[test]
fn test_allow_missing_infra_extracts_a_placeholder_bundle() {
    let dir = scratch();
    let bundle = dir.path().join("self.bundle");
    let exe = std::env::current_exe().unwrap();
    let out = exegesis(&[
        "extract",
        exe.to_str().unwrap(),
        "-o",
        bundle.to_str().unwrap(),
        "--allow-missing-infra",
        "--stats",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("wrote "), "{}", stdout(&out));

    let out = exegesis(&["stats", bundle.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("tokio:           (unknown)"),
        "{}",
        stdout(&out)
    );

    let out = exegesis(&["dump", bundle.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
}

// ---------------------------------------------------------------------------
// The same failure modes as the library reports them
// ---------------------------------------------------------------------------

#[test]
fn test_extract_file_reports_typed_errors() {
    let opts = ExtractOptions::default();
    assert!(matches!(
        extract_file("/no/such/binary".as_ref(), &opts),
        Err(Error::Io(_))
    ));

    let dir = scratch();
    let path = dir.path().join("garbage");
    std::fs::write(&path, b"not an object file").unwrap();
    assert!(matches!(extract_file(&path, &opts), Err(Error::Object(_))));

    let exe = std::env::current_exe().unwrap();
    assert!(matches!(
        extract_file(&exe, &opts),
        Err(Error::NoTaskFutures)
    ));
}

/// The placeholder path yields a bundle that passes its own validation
/// and records what it could not recover, rather than inventing it.
#[test]
fn test_allow_missing_infra_yields_a_valid_bundle() {
    let exe = std::env::current_exe().unwrap();
    let opts = ExtractOptions {
        allow_missing_infra: true,
        ..Default::default()
    };
    let (bundle, stats) = extract_file(&exe, &opts).expect("placeholder extraction succeeds");
    bundle.validate().expect("the placeholder bundle validates");
    assert_eq!(bundle.meta.tokio_version, None);
    assert!(
        !stats.infra_missing.is_empty(),
        "a tokio-less binary is missing all infra"
    );
    assert!(bundle.tasks.entries.is_empty());

    // And it survives a save/load round trip like any other bundle.
    let dir = scratch();
    let path = dir.path().join("self.bundle");
    bundle.save(&path).expect("the placeholder bundle saves");
    Bundle::load(&path).expect("the placeholder bundle reloads");
}

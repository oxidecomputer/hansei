// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `hansei tokio-info …`, run the way a user runs it.
//!
//! Everything below argv is covered elsewhere — extraction by
//! exegesis's golden suite, bundle io by the wire crate's unit tests —
//! but the verbs themselves are what an operator types: `dump` is the
//! sole production caller of the full display-program describer,
//! `dump-dwarf` is a second, independent DWARF entry point, and the
//! failure paths are what they see when a binary is not what they
//! thought.
//!
//! No fixture is built here. The bundle-reading verbs run over the
//! checked-in `hansei-runtime` fixture bundles — real tokio bundles
//! with every formatter attached — and the DWARF-reading ones over
//! this test binary itself, which is a real object file on every
//! platform and contains no tokio on any of them.

use std::path::PathBuf;
use std::process::{Command, Output};

fn hansei(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hansei"))
        .arg("tokio-info")
        .args(args)
        .output()
        .expect("failed to run hansei")
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
/// what these want is bundles to run the verbs over, and that set has
/// one per program on every platform, macOS included.
fn fixture_bundles() -> Vec<PathBuf> {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../hansei-runtime/tests/fixtures/illumos");
    let mut bundles: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("the fixture dir exists")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "tinfo"))
        .collect();
    bundles.sort();
    assert!(!bundles.is_empty(), "no fixture bundles in {dir:?}");
    bundles
}

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create a tempdir")
}

/// The kind-breakdown rows of a `stats` listing: four spaces, a type
/// kind, its count, and nothing else on the line — which is what tells
/// them from the `normalized … keys` rows at the same indent.
fn kind_counts(text: &str) -> Vec<(&str, usize)> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.strip_prefix("    ")?.split_whitespace();
            let name = fields.next()?;
            let count = fields.next()?.parse().ok()?;
            fields.next().is_none().then_some((name, count))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// stats and dump, over every checked-in bundle
// ---------------------------------------------------------------------------

#[test]
fn test_stats_reports_a_bundle() {
    let bundle = fixture_bundles()
        .into_iter()
        .find(|p| p.ends_with("futurelock.tinfo"))
        .expect("the futurelock fixture is checked in");
    let out = hansei(&["stats", bundle.to_str().unwrap()]);
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
    let mut awaits = 0;
    for bundle in fixture_bundles() {
        let out = hansei(&["dump", bundle.to_str().unwrap()]);
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

        // An await site is printed only where it says something the
        // variant's declaration does not, so every one of these lines
        // must name a place its own `@ decl` did not.
        for line in text.lines().filter(|l| l.contains("(awaited at ")) {
            let (decl, site) = line.rsplit_once("(awaited at ").expect("the line matched");
            let site = site.trim_end_matches(')');
            let decl = decl.rsplit_once("@ ").map(|(_, d)| d.trim());
            assert_ne!(decl, Some(site), "{bundle:?}: {line}");
            awaits += 1;
        }
    }
    assert!(awaits > 0, "no fixture recorded an await site");
}

#[test]
fn test_the_verbs_reject_what_is_not_theirs_to_read() {
    let dir = scratch();
    let path = dir.path().join("garbage");
    std::fs::write(&path, b"not a bundle").unwrap();
    for verb in ["stats", "dump", "dump-dwarf"] {
        let out = hansei(&[verb, path.to_str().unwrap()]);
        assert!(!out.status.success(), "{verb} accepted garbage");
        // The whole cause chain, named file included: `Error: …` is
        // anyhow's `Debug`, which is where a context line shows up.
        let err = stderr(&out);
        assert!(err.starts_with("Error: "), "{verb}: {err}");
        assert!(err.contains(&path.display().to_string()), "{verb}: {err}");
    }
}

// ---------------------------------------------------------------------------
// dump-dwarf
// ---------------------------------------------------------------------------

#[test]
fn test_dump_dwarf_summarizes_an_object() {
    let exe = std::env::current_exe().unwrap();
    let out = hansei(&["dump-dwarf", exe.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("total types"), "{text}");
    assert!(text.contains("total statics"), "{text}");
}

// ---------------------------------------------------------------------------
// extract: the failure paths an operator sees
// ---------------------------------------------------------------------------

/// The errors reach the user as their messages, hints included, rather
/// than as the name of an error variant: what tells a missing file from
/// a file that is no object from a binary with no tokio in it is the
/// text, and each of the three has its own.
#[test]
fn test_extract_failures_name_their_cause() {
    let out = hansei(&["extract", "/no/such/binary", "-o", "/dev/null"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("failed to read the debug binary"),
        "{}",
        stderr(&out)
    );

    let dir = scratch();
    let path = dir.path().join("garbage");
    std::fs::write(&path, b"not an object file").unwrap();
    let out = hansei(&["extract", path.to_str().unwrap(), "-o", "/dev/null"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("failed to parse the debug binary"),
        "{}",
        stderr(&out)
    );

    // A real debug binary with no tokio in it: refused, with the flag
    // that overrides the refusal named in the message.
    let exe = std::env::current_exe().unwrap();
    let out = hansei(&["extract", exe.to_str().unwrap(), "-o", "/dev/null"]);
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
    let out = hansei(&[
        "extract",
        exe.to_str().unwrap(),
        "-o",
        bundle.to_str().unwrap(),
        "--allow-missing-infra",
        "--stats",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("wrote "), "{}", stdout(&out));

    let out = hansei(&["stats", bundle.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("tokio:           (unknown)"), "{text}");
    // The kind breakdown lists what the bundle has. This one is all
    // placeholders, so the kinds it has none of are absent rather than
    // listed as zeroes.
    let kinds = kind_counts(&text);
    assert!(!kinds.is_empty(), "{text}");
    for (kind, count) in kinds {
        assert!(count > 0, "{kind} listed with {count}:\n{text}");
    }

    let out = hansei(&["dump", bundle.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
}

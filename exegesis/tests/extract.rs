// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What `extract_file` reports when the binary is not what a caller
//! thought, and what it produces when it is only half of one.
//!
//! The golden suite covers extraction over the fixture programs, which
//! are all tokio binaries that extract cleanly; these are the paths a
//! caller has to distinguish between — a missing file, a file that is
//! no object, and a real binary with no tokio in it.
//!
//! No fixture is built here: the subject is this test binary itself,
//! which is a real debug binary on every platform and contains no tokio
//! on any of them.

use exegesis::bundle::Bundle;
use exegesis::extract::{Error, ExtractOptions, extract_file};

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create a tempdir")
}

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
    let path = dir.path().join("self.tinfo");
    bundle.save(&path).expect("the placeholder bundle saves");
    Bundle::load(&path).expect("the placeholder bundle reloads");
}

/// `dwarf_summary` reads a whole binary's DWARF rather than a bundle's
/// selection out of it, so this tokio-less test binary — which
/// `extract_file` refuses above — still summarizes. What it counts is
/// the target's business: macOS leaves the DWARF in the `.o` files a
/// dSYM would gather, so the executable itself carries none and every
/// count is zero there.
#[test]
fn test_dwarf_summary_reads_what_extraction_refuses() {
    let exe = std::env::current_exe().unwrap();
    let summary = exegesis::extract::dwarf_summary(&exe).expect("a Mach-O or ELF is readable");
    if cfg!(not(target_os = "macos")) {
        assert!(summary.types > 0, "{} types", summary.types);
        assert!(summary.strings > 0, "{} strings", summary.strings);
    }

    let dir = scratch();
    let path = dir.path().join("garbage");
    std::fs::write(&path, b"not an object file").unwrap();
    assert!(matches!(
        exegesis::extract::dwarf_summary(&path),
        Err(Error::Object(_))
    ));
}

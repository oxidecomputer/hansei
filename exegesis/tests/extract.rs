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

// ---------------------------------------------------------------------------
// The input contract, over synthetic ELFs: flavors are decided by
// content, split flavors demand their sibling, and a pair from two
// different links is refused. Real split pairs are covered by the
// golden suite's objcopy test; these pin the classification and the
// refusals themselves, which need every flavor including ones no
// fixture produces (a dwp, a mismatched build id).
// ---------------------------------------------------------------------------

use exegesis::extract::{DebugFlavor, DebugSources, classify_file, extract_sources};

use object::write::Object as WriteObject;
use object::{Architecture, BinaryFormat, Endianness, SectionKind};

use std::path::{Path, PathBuf};

/// A `.note.gnu.build-id` section's contents: one ELF note, type
/// NT_GNU_BUILD_ID, name "GNU", descriptor `id`.
fn build_id_note(id: &[u8]) -> Vec<u8> {
    let mut note = Vec::new();
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(&(id.len() as u32).to_le_bytes());
    note.extend_from_slice(&3u32.to_le_bytes());
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(id);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    note
}

/// Assemble a synthetic ELF from `(name, kind, contents)` triples;
/// `None` contents makes the section `SHT_NOBITS`, the shape a
/// companion's program sections have.
fn write_elf(dir: &Path, name: &str, sections: &[(&str, SectionKind, Option<&[u8]>)]) -> PathBuf {
    let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    for &(section_name, kind, contents) in sections {
        let id = obj.add_section(Vec::new(), section_name.as_bytes().to_vec(), kind);
        match contents {
            Some(data) => {
                obj.append_section_data(id, data, 4);
            }
            None => {
                obj.append_section_bss(id, 64, 4);
            }
        }
    }
    let path = dir.join(name);
    std::fs::write(&path, obj.write().expect("a synthetic ELF assembles")).expect("write");
    path
}

const CODE: &[u8] = &[0xc3; 16];
const DWARF: &[u8] = b"not real DWARF, but bytes in .debug_info";

fn full_binary(dir: &Path, name: &str, id: &[u8]) -> PathBuf {
    write_elf(
        dir,
        name,
        &[
            (".text", SectionKind::Text, Some(CODE)),
            (".debug_info", SectionKind::Debug, Some(DWARF)),
            (
                ".note.gnu.build-id",
                SectionKind::Note,
                Some(&build_id_note(id)),
            ),
        ],
    )
}

fn companion(dir: &Path, name: &str, id: &[u8]) -> PathBuf {
    write_elf(
        dir,
        name,
        &[
            (".text", SectionKind::UninitializedData, None),
            (".debug_info", SectionKind::Debug, Some(DWARF)),
            (
                ".note.gnu.build-id",
                SectionKind::Note,
                Some(&build_id_note(id)),
            ),
        ],
    )
}

#[test]
fn test_input_flavors_are_classified_by_content() {
    let dir = scratch();
    let full = full_binary(dir.path(), "full", b"same-link");
    assert_eq!(classify_file(&full).unwrap(), DebugFlavor::Full);

    let dbg = companion(dir.path(), "app.dbg", b"same-link");
    assert_eq!(classify_file(&dbg).unwrap(), DebugFlavor::Companion);

    let dwp = write_elf(
        dir.path(),
        "app.dwp",
        &[
            (".debug_info.dwo", SectionKind::Debug, Some(DWARF)),
            (".debug_cu_index", SectionKind::Debug, Some(&[1, 2, 3, 4])),
        ],
    );
    assert_eq!(classify_file(&dwp).unwrap(), DebugFlavor::Dwp);

    let plain = write_elf(
        dir.path(),
        "plain",
        &[(".text", SectionKind::Text, Some(CODE))],
    );
    assert_eq!(classify_file(&plain).unwrap(), DebugFlavor::NoDebugInfo);
}

/// The refusal matrix: each wrong shape of invocation is refused with
/// the flavor that was recognized and what is missing, before any
/// DWARF is read.
#[test]
fn test_the_refusal_matrix_names_what_it_recognized() {
    let dir = scratch();
    let opts = ExtractOptions::default();
    let full = full_binary(dir.path(), "full", b"same-link");
    let dbg = companion(dir.path(), "app.dbg", b"same-link");
    let dwp = write_elf(
        dir.path(),
        "app.dwp",
        &[(".debug_cu_index", SectionKind::Debug, Some(&[1, 2, 3, 4]))],
    );
    let plain = write_elf(
        dir.path(),
        "plain",
        &[(".text", SectionKind::Text, Some(CODE))],
    );
    let sources = |binary: &'static str, debug_info: Option<&'static str>| DebugSources {
        binary: match binary {
            "full" => &full,
            "dbg" => &dbg,
            "dwp" => &dwp,
            _ => &plain,
        },
        debug_info: debug_info.map(|d| match d {
            "dbg" => dbg.as_path(),
            "dwp" => dwp.as_path(),
            _ => plain.as_path(),
        }),
    };

    // Split debug info alone: refused naming the flavor and the need.
    let err = extract_sources(&sources("dbg", None), &opts).unwrap_err();
    assert!(matches!(err, Error::SplitAlone { .. }), "{err}");
    let msg = err.to_string();
    assert!(msg.contains("companion"), "{msg}");
    assert!(msg.contains("binary it was split from"), "{msg}");

    let err = extract_sources(&sources("dwp", None), &opts).unwrap_err();
    assert!(matches!(err, Error::SplitAlone { .. }), "{err}");
    assert!(err.to_string().contains("dwp"), "{}", err);

    // Split debug info cannot fill the binary role even when a debug
    // file is also given.
    let err = extract_sources(&sources("dbg", Some("dbg")), &opts).unwrap_err();
    assert!(matches!(err, Error::SplitAlone { .. }), "{err}");

    // A binary with no DWARF and nothing else: refused as such.
    let err = extract_sources(&sources("plain", None), &opts).unwrap_err();
    assert!(matches!(err, Error::NoDebugInfo { .. }), "{err}");
    assert!(err.to_string().contains("no debug info"), "{}", err);

    // A --debug-info file with no debug info in it: same refusal,
    // naming that file.
    let err = extract_sources(&sources("full", Some("plain")), &opts).unwrap_err();
    assert!(matches!(err, Error::NoDebugInfo { .. }), "{err}");
    assert!(err.to_string().contains("plain"), "{}", err);

    // A dwp beside its binary is accepted into the package reader —
    // which chokes on this one's junk index rather than refusing the
    // shape. The working package paths are covered by the synthetic
    // package below and the golden suite's packed-fixture test.
    let err = extract_sources(&sources("full", Some("dwp")), &opts).unwrap_err();
    assert!(matches!(err, Error::Dwarf(_)), "{err}");
}

/// Pairing is verified: matching build ids proceed (into the DWARF,
/// where these synthetic bytes fail), differing ones are refused as a
/// mismatched pair. The address-based check for id-less binaries runs
/// against real files in the golden suite's objcopy test.
#[test]
fn test_sibling_build_ids_adjudicate_the_pair() {
    let dir = scratch();
    let opts = ExtractOptions::default();
    let binary = full_binary(dir.path(), "app", b"same-link");
    let dbg = companion(dir.path(), "app.dbg", b"same-link");
    let foreign = companion(dir.path(), "other.dbg", b"another-link");

    let err = extract_sources(
        &DebugSources {
            binary: &binary,
            debug_info: Some(&foreign),
        },
        &opts,
    )
    .unwrap_err();
    assert!(matches!(err, Error::SiblingMismatch { .. }), "{err}");
    let msg = err.to_string();
    assert!(msg.contains("build ids differ"), "{msg}");
    assert!(msg.contains("separate debug build"), "{msg}");

    let err = extract_sources(
        &DebugSources {
            binary: &binary,
            debug_info: Some(&dbg),
        },
        &opts,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Dwarf(_)),
        "a matched pair should get as far as reading the (fake) DWARF: {err}"
    );
}

/// A `.debug_info` section that is present but empty is no debug info:
/// classification reads contents, not presence, so a stripped binary
/// keeping a zero-length stub still gets the crisp no-debug-info
/// refusal rather than an extraction that finds nothing.
#[test]
fn test_an_empty_debug_info_section_is_no_debug_info() {
    let dir = scratch();
    let empty = write_elf(
        dir.path(),
        "empty-debug",
        &[
            (".text", SectionKind::Text, Some(CODE)),
            (".debug_info", SectionKind::Debug, Some(&[])),
        ],
    );
    assert_eq!(classify_file(&empty).unwrap(), DebugFlavor::NoDebugInfo);
}

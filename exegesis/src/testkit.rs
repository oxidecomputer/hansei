// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::bundle::{Bundle, SemanticOrigin, SemanticRuleKind};
use crate::detect::semantics::TRACING_INSTRUMENTED_V0_1_40;
use crate::{DwReader, ReadArgs};

use object::{Object, ObjectSection};

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::Path;

pub fn with_reader<R>(path: &Path, check: impl FnOnce(&DwReader<'_>) -> R) -> R {
    let bytes = std::fs::read(path).expect("read fixture DWARF");
    let object = object::File::parse(&bytes[..]).expect("parse fixture object");
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let sections = gimli::DwarfSections::load(|id: gimli::SectionId| -> Result<_, object::Error> {
        match object.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data(),
            None => Ok(Cow::Borrowed(&[])),
        }
    })
    .unwrap();
    let dwarf = sections.borrow(|bytes| gimli::EndianSlice::new(bytes.as_ref(), endian));
    let reader = DwReader::read_types(&dwarf, ReadArgs::default()).unwrap();
    check(&reader)
}

/// Inventory defining origins rather than testing an all-decline binder.
///
/// Returns the distinct names of the `poll` functions declared in
/// tracing's `instrument.rs`, so a caller pins *which* functions the
/// inventory covered — the declaration-to-source association that a
/// third-party rule's origin evidence (the crate's registry path and
/// version) is read from. Whatever the file table carries beside the
/// name, a checksum included, is printed and not asserted: rustc emits
/// none today.
pub fn assert_instrumented_sources(path: &Path) -> BTreeSet<String> {
    with_reader(path, |reader| {
        let mut found = BTreeSet::new();
        for function in reader.functions.values() {
            let Some(name) = function.name.map(|name| reader.strings.get(name)) else {
                continue;
            };
            if !name.starts_with("poll") {
                continue;
            }
            let Some(location) = &function.source_loc else {
                continue;
            };
            let Some(file_id) = location.file_id else {
                continue;
            };
            let file = reader
                .source_file(file_id)
                .expect("retained declaration file");
            if !file
                .location
                .file
                .is_some_and(|name| reader.strings.get(name).ends_with("instrument.rs"))
            {
                continue;
            }
            let origin = &reader.origins[&file_id.origin];
            eprintln!(
                "Instrumented source: fn={name} producer={} DWARF={} file={} md5={:02x?}",
                origin
                    .producer
                    .map(|p| reader.strings.get(p))
                    .unwrap_or("<missing>"),
                origin.dwarf_version,
                reader.strings.get(file.location.file.unwrap()),
                file.md5
            );
            found.insert(name.to_owned());
        }
        assert!(
            !found.is_empty(),
            "no Instrumented declaration/source association in {}",
            path.display()
        );
        found
    })
}

/// The `Instrumented` rule's origin as a bundle extracted from the
/// `delegation-cases` fixture must record it: exactly one tracing
/// delegation origin, naming the pinned crate version, the family that
/// version selected, and a cargo registry path for `instrument.rs`
/// that re-parses to the same crate and version — with a
/// `TracingInstrumented` rule under it. Returns the recorded source
/// path. A bundle whose rule declined everywhere fails here: this is
/// the positive assertion, not an inventory. Delegation origins of
/// other crates — tokio's, where a target keeps the runtime's own
/// `Coop` — are not this assertion's business.
pub fn assert_instrumented_origin(bundle: &Bundle) -> String {
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>");
    let origins: Vec<(usize, &SemanticOrigin)> = bundle
        .semantics
        .origins
        .iter()
        .enumerate()
        .filter(|(_, o)| {
            matches!(o, SemanticOrigin::LibraryDelegation { package, .. }
                if s(*package) == "tracing")
        })
        .collect();
    let [(index, origin)] = origins.as_slice() else {
        panic!("expected exactly one tracing delegation origin, found {origins:?}");
    };
    let SemanticOrigin::LibraryDelegation {
        package,
        version,
        family,
        source,
        files,
    } = origin
    else {
        unreachable!()
    };
    assert_eq!(s(*package), "tracing");
    assert_eq!(s(*version), "0.1.40", "the fixture pins tracing 0.1.40");
    assert_eq!(s(*family), TRACING_INSTRUMENTED_V0_1_40.family);
    let source = s(*source).to_owned();
    let parsed = crate::bundle::origin::registry_origin(&source)
        .unwrap_or_else(|| panic!("{source} is not a registry path"));
    assert_eq!(parsed.package, "tracing");
    assert_eq!(parsed.version.to_string(), "0.1.40");
    assert!(
        source.ends_with("/tracing-0.1.40/src/instrument.rs"),
        "{source}"
    );
    // rustc emits no line-table checksums today; a build that carried
    // them would have to carry a reviewed one to have bound at all.
    for file in files {
        assert!(TRACING_INSTRUMENTED_V0_1_40.reviewed_checksum(&file.md5));
    }
    assert!(
        bundle
            .semantics
            .rules
            .iter()
            .any(|r| r.kind == SemanticRuleKind::TracingInstrumented
                && r.origin.0 as usize == *index),
        "no TracingInstrumented rule under the delegation origin"
    );
    source
}

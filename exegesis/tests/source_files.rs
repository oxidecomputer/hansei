// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use exegesis::{DwReader, ReadArgs};

use gimli::write::{self as w, AttributeValue as W};
use gimli::{EndianSlice, RunTimeEndian};

fn add_unit(dwarf: &mut w::Dwarf, version: u16, checksum: Option<[u8; 16]>) {
    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version,
        address_size: 8,
    };
    let mut lines = w::LineProgram::new(
        encoding,
        gimli::LineEncoding::default(),
        w::LineString::String(b"/build".to_vec()),
        None,
        w::LineString::String(b"main.rs".to_vec()),
        None,
    );
    lines.file_has_md5 = checksum.is_some();
    let directory = lines.add_directory(w::LineString::String(b"/crate/src".to_vec()));
    let file = lines.add_file(
        w::LineString::String(b"adapter.rs".to_vec()),
        directory,
        Some(w::FileInfo {
            md5: checksum.unwrap_or_default(),
            ..Default::default()
        }),
    );
    // This helper never appears in a line-program row. Its header entry is
    // still required evidence for an implementation that calls it.
    lines.add_file(
        w::LineString::String(b"helper.rs".to_vec()),
        directory,
        Some(w::FileInfo {
            md5: [9; 16],
            ..Default::default()
        }),
    );
    lines.begin_sequence(Some(w::Address::Constant(0x1000)));
    lines.row().file = file;
    lines.generate_row();
    lines.end_sequence(1);
    let mut unit = w::Unit::new(encoding, lines);
    let root = unit.root();
    unit.get_mut(root)
        .set(gimli::DW_AT_name, W::String(b"unit".to_vec()));
    unit.get_mut(root)
        .set(gimli::DW_AT_stmt_list, W::LineProgramRef);
    let ty = unit.add(root, gimli::DW_TAG_structure_type);
    unit.get_mut(ty)
        .set(gimli::DW_AT_name, W::String(b"Adapter".to_vec()));
    unit.get_mut(ty).set(gimli::DW_AT_byte_size, W::Udata(8));
    unit.get_mut(ty)
        .set(gimli::DW_AT_decl_file, W::FileIndex(Some(file)));
    dwarf.units.add(unit);
}

#[test]
fn test_header_checksums_preserve_conflicting_definition_origins() {
    let mut dwarf = w::Dwarf::new();
    add_unit(&mut dwarf, 5, Some([1; 16]));
    add_unit(&mut dwarf, 5, Some([2; 16]));
    add_unit(&mut dwarf, 5, None);
    add_unit(&mut dwarf, 4, None);
    let mut sections = w::Sections::new(w::EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections).unwrap();
    let dwarf = gimli::Dwarf::load(|id| -> Result<_, gimli::Error> {
        Ok(EndianSlice::new(
            sections.get(id).map_or(&[], |s| s.slice()),
            RunTimeEndian::Little,
        ))
    })
    .unwrap();
    let reader = DwReader::read_types(&dwarf, ReadArgs::default()).unwrap();
    let ty = reader
        .types
        .iter()
        .find(|(_, ty)| {
            ty.name()
                .is_some_and(|n| reader.strings.get(n) == "Adapter")
        })
        .unwrap()
        .0;
    let definitions: Vec<_> = reader.type_definitions(*ty).collect();
    assert_eq!(definitions.len(), 4);
    let checksums: Vec<_> = definitions
        .iter()
        .map(|id| {
            let exegesis::raw_types::RawType::Struct(ty) = &reader.types[id] else {
                panic!("expected struct")
            };
            let loc = ty.source_loc.as_ref().unwrap();
            let file_id = loc.file_id.unwrap();
            assert_eq!(file_id.origin, reader.die_origin(id.0).unwrap().0);
            let file = reader.source_file(file_id).unwrap();
            assert_eq!(
                reader.strings.get(file.location.file.unwrap()),
                "adapter.rs"
            );
            assert_eq!(reader.strings.get(file.location.dir.unwrap()), "/crate/src");
            file.md5
        })
        .collect();
    assert_eq!(checksums, [Some([1; 16]), Some([2; 16]), None, None]);
    let versions: Vec<_> = reader
        .origins
        .values()
        .map(|o| (o.dwarf_version, o.line_version))
        .collect();
    assert_eq!(
        versions,
        [(5, Some(5)), (5, Some(5)), (5, Some(5)), (4, Some(4))]
    );
    for origin in reader.origins.values() {
        let helper = origin
            .source_files
            .iter()
            .find(|f| reader.strings.get(f.location.file.unwrap()) == "helper.rs")
            .unwrap();
        assert_eq!(
            helper.md5,
            if origin.source_files.iter().any(|f| f.md5.is_some()) {
                Some([9; 16])
            } else {
                None
            }
        );
        let mut invalid = helper.location.file_id.unwrap();
        invalid.index = u64::MAX;
        assert!(reader.source_file(invalid).is_none());
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The DWARF-package reader over a synthetic skeleton + dwp pair.
//!
//! The load-bearing property is the id space: `DwarfPackage::find_cu`
//! hands each unit *sliced* sections, so DIE offsets restart near zero
//! per contribution, and two units' equal local offsets must not alias
//! one id. The two dwo units here are written byte-for-byte the same
//! shape — equal-length names, equal-width sizes — so every DIE sits at
//! the *same* local offset in both, and any conversion site that skips
//! the per-unit bias collapses the two type graphs into one, which the
//! member-resolution asserts catch loudly. The real-toolchain
//! counterpart (rustc + thorin over a fixture program) lives in the
//! golden suite; this one exists because a real dwp's offsets rarely
//! collide, which is exactly why a missed bias site stays silent there.

use exegesis::raw_types::RawType;
use exegesis::reader::DwReader;
use exegesis::{Error, ReadArgs};

use gimli::write as gwrite;
use gimli::write::AttributeValue as W;
use gimli::{EndianSlice, RunTimeEndian, SectionId};

use std::collections::HashMap;

type Slice<'a> = EndianSlice<'a, RunTimeEndian>;

const ENDIAN: RunTimeEndian = RunTimeEndian::Little;

/// Write one gimli-built `Dwarf` and collect its section bytes.
fn written_sections(dwarf: &mut gwrite::Dwarf) -> HashMap<SectionId, Vec<u8>> {
    let mut sections = gwrite::Sections::new(gwrite::EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections).expect("the unit assembles");
    let mut data = HashMap::new();
    sections
        .for_each(|id, vec| -> Result<(), ()> {
            data.insert(id, vec.slice().to_vec());
            Ok(())
        })
        .unwrap();
    data
}

fn new_unit(dwarf: &mut gwrite::Dwarf) -> gwrite::UnitId {
    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 4,
        address_size: 8,
    };
    dwarf
        .units
        .add(gwrite::Unit::new(encoding, gwrite::LineProgram::none()))
}

/// One split ("dwo") unit's `.debug_info.dwo` / `.debug_abbrev.dwo`
/// bytes: an inner struct, a holder struct whose member references it,
/// and a static whose location is an index into the binary's
/// `.debug_addr`. Callers pass names of equal length so two calls
/// produce units of identical layout.
fn dwo_unit(
    cu_name: &str,
    holder: &str,
    inner: &str,
    inner_size: u64,
    static_name: &str,
    addr_index: u8,
) -> (Vec<u8>, Vec<u8>) {
    let mut dwarf = gwrite::Dwarf::new();
    let unit_id = new_unit(&mut dwarf);
    let unit = dwarf.units.get_mut(unit_id);
    let root = unit.root();
    let entry = unit.get_mut(root);
    entry.set(gimli::DW_AT_name, W::String(cu_name.into()));
    entry.set(gimli::DW_AT_producer, W::String(b"synthetic".to_vec()));

    let inner_die = unit.add(root, gimli::DW_TAG_structure_type);
    let entry = unit.get_mut(inner_die);
    entry.set(gimli::DW_AT_name, W::String(inner.into()));
    entry.set(gimli::DW_AT_byte_size, W::Udata(inner_size));

    let holder_die = unit.add(root, gimli::DW_TAG_structure_type);
    let entry = unit.get_mut(holder_die);
    entry.set(gimli::DW_AT_name, W::String(holder.into()));
    entry.set(gimli::DW_AT_byte_size, W::Udata(inner_size));
    let member = unit.add(holder_die, gimli::DW_TAG_member);
    let entry = unit.get_mut(member);
    entry.set(gimli::DW_AT_name, W::String(b"value".to_vec()));
    entry.set(gimli::DW_AT_type, W::UnitRef(inner_die));
    entry.set(gimli::DW_AT_data_member_location, W::Udata(0));

    let var = unit.add(root, gimli::DW_TAG_variable);
    let entry = unit.get_mut(var);
    entry.set(gimli::DW_AT_name, W::String(static_name.into()));
    entry.set(gimli::DW_AT_type, W::UnitRef(inner_die));
    // The split spelling of a static's address: DW_OP_GNU_addr_index
    // into the `.debug_addr` the *binary* carries.
    entry.set(
        gimli::DW_AT_location,
        W::Exprloc(gwrite::Expression::raw(vec![
            gimli::DW_OP_GNU_addr_index.0,
            addr_index,
        ])),
    );

    let mut data = written_sections(&mut dwarf);
    (
        data.remove(&SectionId::DebugInfo).expect("info bytes"),
        data.remove(&SectionId::DebugAbbrev).expect("abbrev bytes"),
    )
}

/// The binary half: skeleton units carrying only their dwo-ids. `None`
/// writes a unit with no id — an object compiled without fission.
fn skeleton_sections(dwo_ids: &[Option<u64>]) -> HashMap<SectionId, Vec<u8>> {
    let mut dwarf = gwrite::Dwarf::new();
    for id in dwo_ids {
        let unit_id = new_unit(&mut dwarf);
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();
        let entry = unit.get_mut(root);
        entry.set(gimli::DW_AT_name, W::String(b"skeleton".to_vec()));
        entry.set(gimli::DW_AT_comp_dir, W::String(b"/src".to_vec()));
        if let Some(id) = id {
            entry.set(gimli::DW_AT_GNU_dwo_id, W::Udata(*id));
        }
    }
    written_sections(&mut dwarf)
}

/// Assemble a version-2 (GNU DWARF-4) `.debug_cu_index`: for each
/// `(dwo_id, contributions)` row, the info and abbrev `(offset, size)`
/// pairs. The hash table is open-addressed on the id's low bits, the
/// way `UnitIndex::find` probes it.
fn cu_index_v2(rows: &[(u64, [(u32, u32); 2])]) -> Vec<u8> {
    const SLOTS: usize = 8;
    assert!(rows.len() < SLOTS);
    let mut hashes = [0u64; SLOTS];
    let mut indices = [0u32; SLOTS];
    for (row, &(id, _)) in rows.iter().enumerate() {
        let mask = (SLOTS - 1) as u64;
        let mut slot = (id & mask) as usize;
        let step = (((id >> 32) & mask) | 1) as usize;
        while hashes[slot] != 0 {
            slot = (slot + step) % SLOTS;
        }
        hashes[slot] = id;
        indices[slot] = row as u32 + 1;
    }

    let mut out = Vec::new();
    let push = |out: &mut Vec<u8>, v: u32| out.extend_from_slice(&v.to_le_bytes());
    push(&mut out, 2); // version
    push(&mut out, 2); // section count: info, abbrev
    push(&mut out, rows.len() as u32);
    push(&mut out, SLOTS as u32);
    for hash in hashes {
        out.extend_from_slice(&hash.to_le_bytes());
    }
    for index in indices {
        push(&mut out, index);
    }
    push(&mut out, 1); // DW_SECT_INFO
    push(&mut out, 3); // DW_SECT_ABBREV
    for &(_, contributions) in rows {
        for (offset, _) in contributions {
            push(&mut out, offset);
        }
    }
    for &(_, contributions) in rows {
        for (_, size) in contributions {
            push(&mut out, size);
        }
    }
    out
}

/// Both synthetic units, their concatenated dwp-shaped sections, and
/// the index rows describing the concatenation.
struct SyntheticDwp {
    info: Vec<u8>,
    abbrev: Vec<u8>,
    rows: Vec<(u64, [(u32, u32); 2])>,
}

const DWO_ID_A: u64 = 0x1122_3344_5566_0001;
const DWO_ID_B: u64 = 0x1122_3344_5566_0002;

fn synthetic_dwp() -> SyntheticDwp {
    let (info_a, abbrev_a) = dwo_unit("cu-alpha", "HolderA", "InnerA", 4, "STATIC_A", 0);
    let (info_b, abbrev_b) = dwo_unit("cu-betaa", "HolderB", "InnerB", 8, "STATIC_B", 1);
    // The point of the whole arrangement: every DIE sits at the same
    // local offset in both contributions, so a single conversion site
    // that skips the bias aliases the two unit graphs.
    assert_eq!(info_a.len(), info_b.len(), "the units must mirror");
    assert_eq!(abbrev_a.len(), abbrev_b.len());

    let rows = vec![
        (
            DWO_ID_A,
            [(0, info_a.len() as u32), (0, abbrev_a.len() as u32)],
        ),
        (
            DWO_ID_B,
            [
                (info_a.len() as u32, info_b.len() as u32),
                (abbrev_a.len() as u32, abbrev_b.len() as u32),
            ],
        ),
    ];
    let mut info = info_a;
    info.extend_from_slice(&info_b);
    let mut abbrev = abbrev_a;
    abbrev.extend_from_slice(&abbrev_b);
    SyntheticDwp { info, abbrev, rows }
}

/// The addresses `.debug_addr` hands out for indexes 0 and 1.
const ADDRS: [u64; 2] = [0x1000, 0x2000];

fn debug_addr_bytes() -> Vec<u8> {
    ADDRS.iter().flat_map(|a| a.to_le_bytes()).collect()
}

fn load_dwarf<'a>(
    sections: &'a HashMap<SectionId, Vec<u8>>,
    debug_addr: &'a [u8],
) -> gimli::Dwarf<Slice<'a>> {
    gimli::Dwarf::load(|id| -> Result<Slice<'a>, gimli::Error> {
        let bytes = match id {
            SectionId::DebugAddr => debug_addr,
            _ => sections.get(&id).map_or(&[][..], Vec::as_slice),
        };
        Ok(EndianSlice::new(bytes, ENDIAN))
    })
    .expect("the skeleton sections load")
}

fn load_package<'a>(
    index: &'a [u8],
    info: &'a [u8],
    abbrev: &'a [u8],
) -> gimli::DwarfPackage<Slice<'a>> {
    gimli::DwarfPackage::load(
        |id| -> Result<Slice<'a>, gimli::Error> {
            let bytes: &[u8] = match id {
                SectionId::DebugCuIndex => index,
                SectionId::DebugInfo => info,
                SectionId::DebugAbbrev => abbrev,
                _ => &[],
            };
            Ok(EndianSlice::new(bytes, ENDIAN))
        },
        EndianSlice::new(&[], ENDIAN),
    )
    .expect("the package sections load")
}

/// Resolve a named struct and hand back `(its size, its sole member's
/// resolved target struct name and size)`.
fn holder_shape(reader: &DwReader<'_>, holder: &str) -> (String, u64) {
    let (_, ty) = reader
        .canonical_types()
        .find(|(_, ty)| ty.name().map(|n| reader.strings.get(n)) == Some(holder))
        .unwrap_or_else(|| panic!("no type named {holder}"));
    let RawType::Struct(holder) = ty else {
        panic!("{holder:?} is not a struct");
    };
    let [member] = holder.members.as_ref() else {
        panic!("one member expected");
    };
    let Some(RawType::Struct(inner)) = reader.canonical_type(member.type_id) else {
        panic!("the member's type does not resolve to a struct");
    };
    let name = inner
        .name
        .map(|n| reader.strings.get(n).to_owned())
        .expect("the inner struct is named");
    (name, inner.size)
}

/// Two contributions whose DIEs share every local offset stay two
/// distinct type graphs, and each unit's statics resolve their
/// addresses through the skeleton's `.debug_addr` base.
#[test]
fn test_package_units_with_identical_local_offsets_stay_distinct() {
    let dwp = synthetic_dwp();
    let index = cu_index_v2(&dwp.rows);
    let skeleton = skeleton_sections(&[Some(DWO_ID_A), Some(DWO_ID_B)]);
    let addr = debug_addr_bytes();
    let dwarf = load_dwarf(&skeleton, &addr);
    let package = load_package(&index, &dwp.info, &dwp.abbrev);

    let reader = DwReader::read_types_package(&dwarf, &package, ReadArgs::default())
        .expect("the package reads");

    assert_eq!(holder_shape(&reader, "HolderA"), ("InnerA".to_owned(), 4));
    assert_eq!(holder_shape(&reader, "HolderB"), ("InnerB".to_owned(), 8));

    let static_addr = |name: &str| {
        reader
            .variables
            .values()
            .find(|v| v.name.map(|n| reader.strings.get(n)) == Some(name))
            .unwrap_or_else(|| panic!("no static named {name}"))
            .addr
    };
    assert_eq!(static_addr("STATIC_A"), Some(ADDRS[0]));
    assert_eq!(static_addr("STATIC_B"), Some(ADDRS[1]));
}

/// A skeleton whose dwo-id the index does not know fails the whole
/// read with the found-of-total count: the join is the pairing check.
#[test]
fn test_a_missing_dwo_id_fails_the_join_with_a_count() {
    let dwp = synthetic_dwp();
    // The index knows only the first unit.
    let index = cu_index_v2(&dwp.rows[..1]);
    let skeleton = skeleton_sections(&[Some(DWO_ID_A), Some(DWO_ID_B)]);
    let addr = debug_addr_bytes();
    let dwarf = load_dwarf(&skeleton, &addr);
    let package = load_package(&index, &dwp.info, &dwp.abbrev);

    let err = DwReader::read_types_package(&dwarf, &package, ReadArgs::default())
        .expect_err("a missing dwo-id is a hard error");
    assert!(
        matches!(err, Error::DwpUnitsMissing { found: 1, total: 2 }),
        "{err}"
    );
    let msg = err.to_string();
    assert!(msg.contains("1 of 2"), "{msg}");
}

/// A binary whose units carry no dwo-ids offers the package nothing to
/// join against — refused, not read as empty.
#[test]
fn test_a_binary_without_skeletons_is_refused() {
    let dwp = synthetic_dwp();
    let index = cu_index_v2(&dwp.rows);
    let skeleton = skeleton_sections(&[None]);
    let addr = debug_addr_bytes();
    let dwarf = load_dwarf(&skeleton, &addr);
    let package = load_package(&index, &dwp.info, &dwp.abbrev);

    let err = DwReader::read_types_package(&dwarf, &package, ReadArgs::default())
        .expect_err("a skeleton-less binary is refused");
    assert!(matches!(err, Error::DwpNoSkeletons), "{err}");
}

// ---------------------------------------------------------------------------
// The same pair, through the user-facing entry point: the sections
// wrapped in ELF containers, the dwp recognized by content, its
// sections found under their `.dwo` names, and the extracted bundle
// carrying both units' types.
// ---------------------------------------------------------------------------

use exegesis::bundle::{TypeDef, VtableDataSource};
use exegesis::extract::{DebugSources, ExtractOptions, extract_sources};

use object::write::Object as WriteObject;
use object::{Architecture, BinaryFormat, Endianness, SectionKind};

use std::path::{Path, PathBuf};

fn write_elf(dir: &Path, name: &str, sections: &[(&str, SectionKind, &[u8])]) -> PathBuf {
    let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    for &(section_name, kind, contents) in sections {
        let id = obj.add_section(Vec::new(), section_name.as_bytes().to_vec(), kind);
        obj.append_section_data(id, contents, 4);
    }
    let path = dir.join(name);
    std::fs::write(&path, obj.write().expect("a synthetic ELF assembles")).expect("write");
    path
}

/// The synthetic pair as files: the skeleton binary and its dwp.
fn write_pair(dir: &Path) -> (PathBuf, PathBuf) {
    let dwp = synthetic_dwp();
    let index = cu_index_v2(&dwp.rows);
    let skeleton = skeleton_sections(&[Some(DWO_ID_A), Some(DWO_ID_B)]);
    let addr = debug_addr_bytes();

    let binary = write_elf(
        dir,
        "app",
        &[
            (".text", SectionKind::Text, &[0xc3; 16]),
            (
                ".debug_info",
                SectionKind::Debug,
                &skeleton[&SectionId::DebugInfo],
            ),
            (
                ".debug_abbrev",
                SectionKind::Debug,
                &skeleton[&SectionId::DebugAbbrev],
            ),
            (".debug_addr", SectionKind::Debug, &addr),
        ],
    );
    let package = write_elf(
        dir,
        "app.dwp",
        &[
            (".debug_cu_index", SectionKind::Debug, &index),
            (".debug_info.dwo", SectionKind::Debug, &dwp.info),
            (".debug_abbrev.dwo", SectionKind::Debug, &dwp.abbrev),
        ],
    );
    (binary, package)
}

#[test]
fn test_extraction_reads_a_dwp_beside_its_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (binary, package) = write_pair(dir.path());

    let opts = ExtractOptions {
        allow_missing_infra: true,
        include_types: vec!["HolderA".to_owned(), "HolderB".to_owned()],
        ..Default::default()
    };
    let (bundle, stats) = extract_sources(
        &DebugSources {
            binary: &binary,
            debug_info: Some(&package),
        },
        &opts,
    )
    .expect("extraction from the pair succeeds");

    assert!(stats.include_missing.is_empty(), "{stats}");
    let type_named = |want: &str| {
        bundle
            .types
            .types
            .iter()
            .find(|def| {
                matches!(def, TypeDef::Struct { name, .. }
                if bundle.strings.get(*name) == Some(want))
            })
            .unwrap_or_else(|| panic!("no bundle type named {want}"))
    };
    let inner_of = |holder: &str| {
        let TypeDef::Struct { members, .. } = type_named(holder) else {
            unreachable!()
        };
        let [member] = members.as_slice() else {
            panic!("{holder} has one member");
        };
        match &bundle.types.types[member.ty.0 as usize] {
            TypeDef::Struct { name, size, .. } => (bundle.strings.get(*name).unwrap(), *size),
            other => panic!("{holder}'s member resolves to {other:?}"),
        }
    };
    assert_eq!(inner_of("HolderA"), ("InnerA", 4));
    assert_eq!(inner_of("HolderB"), ("InnerB", 8));

    // The inputs are recorded the way any split pair's are: the dwp as
    // the debug source, the binary as what the vtable scan read.
    let debug_info = bundle.meta.debug_info.as_ref().expect("debug source");
    assert_eq!(debug_info.basename, "app.dwp");
    assert!(matches!(&bundle.meta.vtable_data, VtableDataSource::File(f) if f == "app"));
}

/// A packed-split binary alone classifies as full — it has DWARF with
/// contents — but its units are skeletons, and extracting from it
/// would find nothing and blame the target. The refusal names the real
/// problem: the DIEs live in a dwp this invocation did not pass.
#[test]
fn test_a_skeleton_binary_alone_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (binary, _) = write_pair(dir.path());

    let err = extract_sources(
        &DebugSources {
            binary: &binary,
            debug_info: None,
        },
        &ExtractOptions::default(),
    )
    .expect_err("a skeleton binary alone is refused");
    assert!(
        matches!(err, exegesis::extract::Error::SplitOutDwarf { .. }),
        "{err}"
    );
    let msg = err.to_string();
    assert!(msg.contains("split out"), "{msg}");
    assert!(msg.contains("--debug-info"), "{msg}");
}

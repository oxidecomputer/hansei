use crate::Encoding;
use crate::Error;
use crate::io::{FORMAT_VERSION, MAGIC};
use crate::schema::*;
use crate::strings::{StrRef, StringInterner};

use std::collections::BTreeMap;

/// Deterministic xorshift64* generator so the "arbitrary graph" round-trip
/// tests are reproducible without a property-testing dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Uniform-ish value in `0..n` (n > 0).
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The smallest bundle that passes validation: one type, all infra ids
/// pointing at it, empty join tables.
fn tiny_bundle() -> Bundle {
    let mut strings = StringInterner::new();
    let name = strings.intern("u64");
    let ty = BundleTypeId(0);
    let strings = strings.finish();
    let mut types = TypeTable {
        types: vec![TypeDef::Base {
            name,
            size: 8,
            encoding: Encoding::Unsigned,
        }],
        debug_formats: BTreeMap::new(),
        name_index: vec![(name, ty)],
        ..Default::default()
    };
    types.build_normalized_index(&strings);
    Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings,
        types,
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: ty,
            vtable: ty,
            trailer: ty,
            context: ty,
            scheduler_handle: ty,
            mt_handle: ty,
            ct_handle: ty,
            location: ty,
            raw_waker_vtable: ty,
        },
        provenance: ProvenanceTable::default(),
        impls: ImplTable::default(),
    }
}

/// Generate a structurally-valid random bundle: an arbitrary type graph
/// (cycles and forward references allowed, as in real DWARF) plus join
/// tables referencing it.
fn random_bundle(seed: u64) -> Bundle {
    let mut rng = Rng::new(seed);
    let mut strings = StringInterner::new();

    let n_types = 1 + rng.below(40);
    let any_ty = |rng: &mut Rng| BundleTypeId(rng.below(n_types) as u32);

    let mut types = Vec::with_capacity(n_types);
    for i in 0..n_types {
        let name = strings.intern(&format!("crate::mod{}::Ty{i}<Δ>", rng.below(4)));
        let member = |rng: &mut Rng, strings: &mut StringInterner, j: usize| MemberDef {
            name: strings.intern(&format!("m{j}")),
            ty: any_ty(rng),
            offset: rng.next() % 4096,
        };
        let def = match rng.below(8) {
            0 => TypeDef::Base {
                name,
                size: 1 << rng.below(5),
                encoding: Encoding::Signed,
            },
            1 => TypeDef::Pointer {
                name: if rng.below(2) == 0 { Some(name) } else { None },
                target: any_ty(&mut rng),
            },
            2 => TypeDef::Array {
                elem: any_ty(&mut rng),
                count: rng.next() % 256,
            },
            3 => TypeDef::Union {
                name,
                size: rng.next() % 128,
                members: (0..rng.below(4))
                    .map(|j| member(&mut rng, &mut strings, j))
                    .collect(),
            },
            4 => TypeDef::Enum {
                name,
                size: rng.next() % 128,
                shape: VariantShape {
                    discr: if rng.below(4) == 0 {
                        None
                    } else {
                        Some(DiscrDef {
                            offset: rng.next() % 64,
                            ty: any_ty(&mut rng),
                        })
                    },
                    variants: (0..1 + rng.below(5))
                        .map(|v| VariantDef {
                            name: strings.intern(&format!("Variant{v}")),
                            discr_values: match rng.below(3) {
                                0 => None,
                                1 => Some(DiscrValues(vec![DiscrValue::Value(
                                    (rng.next() as u128) << 64 | rng.next() as u128,
                                )])),
                                _ => Some(DiscrValues(vec![
                                    DiscrValue::Value(rng.next() as u128),
                                    DiscrValue::Range(0, rng.next() as u128),
                                ])),
                            },
                            payload: member(&mut rng, &mut strings, v),
                            decl: if rng.below(3) == 0 {
                                Some(SourceLoc {
                                    file: strings.intern("src/lib.rs"),
                                    line: (rng.next() % 10_000) as u32,
                                })
                            } else {
                                None
                            },
                            await_site: if rng.below(4) == 0 {
                                Some(SourceLoc {
                                    file: strings.intern("src/main.rs"),
                                    line: (rng.next() % 10_000) as u32,
                                })
                            } else {
                                None
                            },
                        })
                        .collect(),
                },
            },
            5 => TypeDef::CEnum {
                name,
                size: 4,
                repr: any_ty(&mut rng),
                enumerators: (0..rng.below(6))
                    .map(|e| {
                        (
                            strings.intern(&format!("E{e}")),
                            rng.next() as i128 - i64::MAX as i128,
                        )
                    })
                    .collect(),
            },
            6 => TypeDef::Opaque {
                name,
                size: if rng.below(2) == 0 {
                    Some(rng.next() % 512)
                } else {
                    None
                },
            },
            _ => TypeDef::Struct {
                name,
                size: rng.next() % 512,
                members: (0..rng.below(6))
                    .map(|j| member(&mut rng, &mut strings, j))
                    .collect(),
            },
        };
        types.push(def);
    }

    let n_tasks = rng.below(8);
    let entries: Vec<_> = (0..n_tasks)
        .map(|i| TaskFutureEntry {
            future: any_ty(&mut rng),
            cell: any_ty(&mut rng),
            stage: any_ty(&mut rng),
            scheduler: any_ty(&mut rng),
            display_name: strings.intern(&format!("some::async_fn{i}::{{async_fn_env#0}}")),
        })
        .collect();
    let mut by_symbol = BTreeMap::new();
    for (i, _) in entries.iter().enumerate() {
        // several vtable-fn keys may map to the same entry
        for f in ["poll", "dealloc", "shutdown"]
            .iter()
            .take(1 + rng.below(3))
        {
            by_symbol.insert(format!("_RINv_task{i}_{f}"), TaskEntryId(i as u32));
        }
    }

    let dyn_futures = DynFutureTable {
        by_symbol: (0..rng.below(6))
            .map(|i| (format!("_RNvX_dyn{i}_poll"), any_ty(&mut rng)))
            .collect(),
        by_normalized_symbol: BTreeMap::new(),
    };

    let mut statics = StaticsTable::default();
    if rng.below(2) == 0 {
        statics.entries.insert(
            StaticRole::TlsContextKey,
            StaticDef {
                symbol: "_RNvNC_CONTEXT_VAL".into(),
                display: "tokio::runtime::context::CONTEXT::{closure#0}::__RUST_STD_INTERNAL_VAL"
                    .into(),
            },
        );
    }

    let provenance = ProvenanceTable {
        entries: (0..n_tasks)
            .map(|_| Provenance {
                decl: if rng.below(3) == 0 {
                    None
                } else {
                    Some(SourceLoc {
                        file: strings.intern(&format!("src/f{}.rs", rng.below(3))),
                        line: rng.next() as u32,
                    })
                },
                kind: [
                    FutureKind::AsyncFn,
                    FutureKind::AsyncBlock,
                    FutureKind::Combinator,
                    FutureKind::Manual,
                ][rng.below(4)],
            })
            .collect(),
    };

    // name_index must be sorted by resolved string
    let mut name_index: Vec<(StrRef, BundleTypeId)> = types
        .iter()
        .enumerate()
        .filter_map(|(i, def)| match def {
            TypeDef::Base { name, .. }
            | TypeDef::Struct { name, .. }
            | TypeDef::Union { name, .. }
            | TypeDef::Enum { name, .. }
            | TypeDef::CEnum { name, .. }
            | TypeDef::Opaque { name, .. } => Some((*name, BundleTypeId(i as u32))),
            TypeDef::Pointer { name, .. } => name.map(|n| (n, BundleTypeId(i as u32))),
            TypeDef::Array { .. } => None,
        })
        .collect();
    let table = strings.finish();
    name_index.sort_by(|a, b| table.get(a.0).unwrap().cmp(table.get(b.0).unwrap()));
    let mut type_table = TypeTable {
        types,
        debug_formats: BTreeMap::new(),
        name_index,
        ..Default::default()
    };
    type_table.build_normalized_index(&table);

    Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            rustc_version: "rustc 1.97.0 (2d8144b78 2026-07-07)".into(),
            tokio_version: Some(semver::Version::new(1, 52, 3)),
            tokio_unstable: Some(true),
            binary: BinaryIdent {
                basename: "futurelock".into(),
                build_id: Some(vec![0xab; 20]),
                blake3: [0x5a; 32],
            },
            debug_info: Some(crate::DebugSourceIdent {
                basename: "futurelock.dbg".into(),
                blake3: [0xa5; 32],
            }),
            vtable_data: crate::VtableDataSource::File("futurelock".into()),
            extract_args: "tokio-info extract futurelock -o fl.tinfo".into(),
            symbol_fingerprint: (0..rng.below(20)).map(|i| format!("_RINv_fp{i}")).collect(),
            newest_family: Some(FamilyCeiling {
                name: "v1_53".into(),
                major: 1,
                minor: 53,
            }),
        },
        strings: table,
        types: type_table,
        tasks: TaskTable {
            by_symbol,
            by_normalized_symbol: BTreeMap::new(),
            entries,
        },
        dyn_futures,
        statics,
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: any_ty(&mut rng),
            vtable: any_ty(&mut rng),
            trailer: any_ty(&mut rng),
            context: any_ty(&mut rng),
            scheduler_handle: any_ty(&mut rng),
            mt_handle: any_ty(&mut rng),
            ct_handle: any_ty(&mut rng),
            location: any_ty(&mut rng),
            raw_waker_vtable: any_ty(&mut rng),
        },
        provenance,
        impls: ImplTable::default(),
    }
}

fn encode(b: &Bundle) -> Vec<u8> {
    let mut buf = Vec::new();
    b.write_to(&mut buf).expect("encode failed");
    buf
}

#[test]
fn test_roundtrip_tiny() {
    let b = tiny_bundle();
    let decoded = Bundle::read_from(encode(&b).as_slice()).expect("decode failed");
    assert_eq!(b, decoded);
}

#[test]
fn test_roundtrip_random_graphs() {
    for seed in 1..=64 {
        let b = random_bundle(seed);
        b.validate()
            .unwrap_or_else(|e| panic!("seed {seed}: generator made invalid bundle: {e}"));
        let decoded = Bundle::read_from(encode(&b).as_slice())
            .unwrap_or_else(|e| panic!("seed {seed}: decode failed: {e}"));
        assert_eq!(b, decoded, "seed {seed}: round trip mismatch");
    }
}

#[test]
fn test_deterministic_encoding() {
    let b = random_bundle(7);
    assert_eq!(encode(&b), encode(&b));
    assert_eq!(encode(&b), encode(&random_bundle(7)));
}

#[test]
fn test_file_sniffing_header() {
    let bytes = encode(&tiny_bundle());
    assert_eq!(&bytes[..8], b"exegesis");
    assert_eq!(
        u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        FORMAT_VERSION
    );
}

#[test]
fn test_bad_magic_rejected() {
    let mut bytes = encode(&tiny_bundle());
    bytes[0] = b'X';
    assert!(matches!(
        Bundle::read_from(bytes.as_slice()),
        Err(Error::BadMagic)
    ));
}

#[test]
fn test_version_mismatch_rejected() {
    let mut bytes = encode(&tiny_bundle());
    bytes[8..12].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
    match Bundle::read_from(bytes.as_slice()) {
        Err(Error::VersionMismatch { found, expected }) => {
            assert_eq!(found, FORMAT_VERSION + 1);
            assert_eq!(expected, FORMAT_VERSION);
        }
        other => panic!("expected VersionMismatch, got {other:?}"),
    }
}

#[test]
fn test_truncated_header_rejected() {
    let bytes = encode(&tiny_bundle());
    assert!(matches!(Bundle::read_from(&bytes[..6]), Err(Error::Io(_))));
}

#[test]
fn test_truncated_payload_rejected() {
    // A cut anywhere in the frame is a hash mismatch; a cut inside the
    // stored hash itself fails the header read.
    let bytes = encode(&random_bundle(3));
    let cut = 44 + (bytes.len() - 44) / 2;
    assert!(matches!(
        Bundle::read_from(&bytes[..cut]),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(Bundle::read_from(&bytes[..20]), Err(Error::Io(_))));
}

#[test]
fn test_damaged_payload_rejected() {
    // One flipped bit anywhere — the frame or the stored hash — is a
    // hash mismatch; the damage never reaches zstd or postcard.
    for at in [12usize, 44, 60] {
        let mut bytes = encode(&tiny_bundle());
        bytes[at] ^= 0x01;
        assert!(
            matches!(Bundle::read_from(bytes.as_slice()), Err(Error::Corrupt(_))),
            "flip at {at}"
        );
    }
}

#[test]
fn test_payload_not_a_bundle_rejected() {
    // valid framing + hash + valid zstd, but the payload isn't a Bundle
    let mut frame = Vec::new();
    zstd::stream::copy_encode(&b"not a bundle"[..], &mut frame, 0).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(blake3::hash(&frame).as_bytes());
    bytes.extend_from_slice(&frame);
    assert!(matches!(
        Bundle::read_from(bytes.as_slice()),
        Err(Error::Decode(_))
    ));
}

/// An older writer's streaming encoder records no decompressed size in
/// its frame; the reader falls back to the general decode.
#[test]
fn test_streamed_frame_without_content_size_still_loads() {
    let b = tiny_bundle();
    let payload = postcard::to_allocvec(&b).unwrap();
    let mut frame = Vec::new();
    zstd::stream::copy_encode(payload.as_slice(), &mut frame, 0).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(blake3::hash(&frame).as_bytes());
    bytes.extend_from_slice(&frame);
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);
}

#[test]
fn test_validate_rejects_oob_type_id() {
    let mut b = tiny_bundle();
    b.infra.header = BundleTypeId(999);
    // The reader trusts the payload hash: a semantically-broken bundle
    // that was framed intact loads — save() is where validation gates —
    // and validate() still names the corruption.
    let loaded = Bundle::read_from(encode(&b).as_slice()).expect("well-framed bundle must load");
    assert!(matches!(loaded.validate(), Err(Error::Corrupt(_))));
}

#[test]
fn test_validate_rejects_oob_str_ref() {
    let mut b = tiny_bundle();
    b.types.types[0] = TypeDef::Base {
        name: StrRef(42),
        size: 8,
        encoding: Encoding::Unsigned,
    };
    let loaded = Bundle::read_from(encode(&b).as_slice()).expect("well-framed bundle must load");
    assert!(matches!(loaded.validate(), Err(Error::Corrupt(_))));
}

/// [`tiny_bundle`] with an impl table holding `entries`, their strings
/// appended to the table (re-interning preserves every existing ref).
fn with_impls(entries: &[(&str, &str)]) -> Bundle {
    let mut b = tiny_bundle();
    let mut strings = StringInterner::new();
    for s in b.strings.iter() {
        strings.intern(s);
    }
    b.impls.entries = entries
        .iter()
        .map(|&(k, v)| (strings.intern(k), strings.intern(v)))
        .collect();
    b.strings = strings.finish();
    b
}

#[test]
fn test_impl_table_roundtrips() {
    let b = with_impls(&[("a::{impl#0}", "a::A"), ("b::{impl#12}", "b::B")]);
    b.validate().expect("sorted impl table validates");
    let loaded = Bundle::read_from(encode(&b).as_slice()).expect("well-framed bundle must load");
    assert_eq!(loaded, b);
}

#[test]
fn test_validate_rejects_broken_impl_tables() {
    // Out of order, duplicated, no impl segment in the key, an impl
    // segment in the value, and a dangling string ref.
    for broken in [
        with_impls(&[("b::{impl#1}", "b::B"), ("a::{impl#0}", "a::A")]),
        with_impls(&[("a::{impl#0}", "a::A"), ("a::{impl#0}", "a::B")]),
        with_impls(&[("a::plain", "a::A")]),
        with_impls(&[("a::{impl#0}", "a::{impl#1}")]),
        {
            let mut b = with_impls(&[("a::{impl#0}", "a::A")]);
            b.impls.entries[0].1 = StrRef(999);
            b
        },
    ] {
        assert!(matches!(broken.validate(), Err(Error::Corrupt(_))));
    }
}

#[test]
fn test_validate_rejects_bad_debug_format_path() {
    let mut b = tiny_bundle();
    b.types.debug_formats.insert(
        BundleTypeId(0),
        DisplayNode::Alias {
            at: Selector::member(0),
            follow_pointers: true,
        },
    );
    assert!(matches!(b.validate(), Err(Error::Corrupt(_))));
}

/// A selector may cross a pointer with a `Deref` step; the validator resolves
/// through it to the pointee. (No detector emits such a selector yet, but
/// the validator handles them — this guards that path.)
#[test]
fn test_validate_accepts_selector_through_deref() {
    let mut strings = StringInterner::new();
    let u64n = strings.intern("u64");
    let innern = strings.intern("Inner");
    let outern = strings.intern("Outer");
    let vn = strings.intern("v");
    let pn = strings.intern("p");
    let ty = BundleTypeId(0);
    let mut b = Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.finish(),
        types: TypeTable {
            types: vec![
                // 0: u64
                TypeDef::Base {
                    name: u64n,
                    size: 8,
                    encoding: Encoding::Unsigned,
                },
                // 1: *Inner
                TypeDef::Pointer {
                    name: None,
                    target: BundleTypeId(2),
                },
                // 2: Inner { v: u64 @0 }
                TypeDef::Struct {
                    name: innern,
                    size: 8,
                    members: vec![MemberDef {
                        name: vn,
                        ty: BundleTypeId(0),
                        offset: 0,
                    }],
                },
                // 3: Outer { p: *Inner @0 }
                TypeDef::Struct {
                    name: outern,
                    size: 8,
                    members: vec![MemberDef {
                        name: pn,
                        ty: BundleTypeId(1),
                        offset: 0,
                    }],
                },
            ],
            // Outer, rendered as its pointee's `v` field: p → deref → v.
            debug_formats: BTreeMap::from([(
                BundleTypeId(3),
                DisplayNode::Alias {
                    at: Selector(vec![
                        Step::Member(MemberRef::Index(0)),
                        Step::Deref,
                        Step::Member(MemberRef::Index(0)),
                    ]),
                    follow_pointers: true,
                },
            )]),
            name_index: vec![],
            ..Default::default()
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: ty,
            vtable: ty,
            trailer: ty,
            context: ty,
            scheduler_handle: ty,
            mt_handle: ty,
            ct_handle: ty,
            location: ty,
            raw_waker_vtable: ty,
        },
        provenance: ProvenanceTable::default(),
        impls: ImplTable::default(),
    };
    assert!(b.validate().is_ok());
    // Round-trips: validation runs on save and load too.
    b.types.name_index.clear();
    assert!(Bundle::read_from(encode(&b).as_slice()).is_ok());
}

/// Dereferencing a non-pointer in a selector is rejected.
#[test]
fn test_validate_rejects_deref_of_non_pointer() {
    let mut b = tiny_bundle();
    // Type 0 is a `u64`; a leading `Deref` cannot apply to it.
    b.types.debug_formats.insert(
        BundleTypeId(0),
        DisplayNode::Alias {
            at: Selector(vec![Step::Deref]),
            follow_pointers: true,
        },
    );
    assert!(matches!(b.validate(), Err(Error::Corrupt(_))));
}

#[test]
fn test_validate_rejects_symbol_node_on_non_pointer() {
    let mut b = tiny_bundle();
    // Type 0 is a `u64`; a symbol node must land on a pointer.
    b.types.debug_formats.insert(
        BundleTypeId(0),
        DisplayNode::Symbol {
            at: Selector::default(),
        },
    );
    assert!(matches!(b.validate(), Err(Error::Corrupt(_))));
}

/// A `Struct` node's `Member` field naming an index the scope type does not
/// have must be caught by `check_node`, not left for the renderer to trip over.
#[test]
fn test_validate_rejects_out_of_range_member() {
    let mut strings = StringInterner::new();
    let u32n = strings.intern("u32");
    let pointn = strings.intern("Point");
    let xn = strings.intern("x");
    let yn = strings.intern("y");
    let ty = BundleTypeId(0);
    let b = Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.finish(),
        types: TypeTable {
            types: vec![
                // 0: u32
                TypeDef::Base {
                    name: u32n,
                    size: 4,
                    encoding: Encoding::Unsigned,
                },
                // 1: Point { x: u32 @0, y: u32 @4 }
                TypeDef::Struct {
                    name: pointn,
                    size: 8,
                    members: vec![
                        MemberDef {
                            name: xn,
                            ty: BundleTypeId(0),
                            offset: 0,
                        },
                        MemberDef {
                            name: yn,
                            ty: BundleTypeId(0),
                            offset: 4,
                        },
                    ],
                },
            ],
            // Point has two members, so member 9 does not resolve.
            debug_formats: BTreeMap::from([(
                BundleTypeId(1),
                DisplayNode::Struct {
                    fields: vec![Field::member(MemberRef::Index(9))],
                },
            )]),
            name_index: vec![],
            ..Default::default()
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: ty,
            vtable: ty,
            trailer: ty,
            context: ty,
            scheduler_handle: ty,
            mt_handle: ty,
            ct_handle: ty,
            location: ty,
            raw_waker_vtable: ty,
        },
        provenance: ProvenanceTable::default(),
        impls: ImplTable::default(),
    };
    let err = b
        .validate()
        .expect_err("out-of-range Member must be rejected");
    assert!(format!("{err}").contains("out of range"), "{err}");

    // The first index past the end is out of range too — the boundary
    // where an off-by-one would let a renderer index one past `members`.
    let mut b = b;
    b.types.debug_formats.insert(
        BundleTypeId(1),
        DisplayNode::Struct {
            fields: vec![Field::member(MemberRef::Index(2))],
        },
    );
    let err = b
        .validate()
        .expect_err("member index == count must be rejected");
    assert!(format!("{err}").contains("out of range"), "{err}");
}

/// `resolve`'s bound is the contract itself: the first index past the
/// end answers to no member. The validator happens to re-screen with
/// `get`, but reify's resolution and exegesis's describe index the
/// member slice directly on a `Some`.
#[test]
fn test_member_ref_index_resolves_only_in_bounds() {
    let unnamed = |_: usize, _: StrRef| false;
    assert_eq!(MemberRef::Index(0).resolve(2, unnamed), Some(0));
    assert_eq!(MemberRef::Index(1).resolve(2, unnamed), Some(1));
    assert_eq!(MemberRef::Index(2).resolve(2, unnamed), None);
}

/// A member addressed by name resolves only when exactly one member answers to
/// it. Both failures — no such member, and two of them — are the same broken
/// program, and neither may quietly pick a member.
#[test]
fn test_validate_requires_a_named_member_to_be_unique() {
    let mut strings = StringInterner::new();
    let u32n = strings.intern("u32");
    let pointn = strings.intern("Point");
    let xn = strings.intern("x");
    let yn = strings.intern("y");
    let zn = strings.intern("z");
    let strings = strings.finish();
    let ty = BundleTypeId(0);

    // `Twice` repeats the name `x`, so nothing addresses either of its members
    // by that name; `Point` spells each of its own once.
    let member = |name, offset| MemberDef {
        name,
        ty: BundleTypeId(0),
        offset,
    };
    let bundle = |scope: BundleTypeId, at: MemberRef| Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.clone(),
        types: TypeTable {
            types: vec![
                TypeDef::Base {
                    name: u32n,
                    size: 4,
                    encoding: Encoding::Unsigned,
                },
                TypeDef::Struct {
                    name: pointn,
                    size: 8,
                    members: vec![member(xn, 0), member(yn, 4)],
                },
                TypeDef::Struct {
                    name: pointn,
                    size: 8,
                    members: vec![member(xn, 0), member(xn, 4)],
                },
            ],
            debug_formats: BTreeMap::from([(
                scope,
                DisplayNode::Struct {
                    fields: vec![Field::member(at)],
                },
            )]),
            name_index: vec![],
            ..Default::default()
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: ty,
            vtable: ty,
            trailer: ty,
            context: ty,
            scheduler_handle: ty,
            mt_handle: ty,
            ct_handle: ty,
            location: ty,
            raw_waker_vtable: ty,
        },
        provenance: ProvenanceTable::default(),
        impls: ImplTable::default(),
    };

    let point = BundleTypeId(1);
    let twice = BundleTypeId(2);
    bundle(point, MemberRef::Named(yn))
        .validate()
        .expect("a uniquely named member resolves");
    for (scope, at, why) in [
        (point, zn, "a name no member bears must be rejected"),
        (twice, xn, "a name two members share must be rejected"),
    ] {
        let err = bundle(scope, MemberRef::Named(at))
            .validate()
            .expect_err(why);
        assert!(format!("{err}").contains("no unique member"), "{err}");
    }
}

/// An `ActiveVariant` step never belongs in a display selector: which
/// variant continues is a runtime fact only the walk's interpreter decodes.
#[test]
fn test_validate_rejects_active_variant_in_display_selector() {
    let mut b = tiny_bundle();
    b.types.debug_formats.insert(
        BundleTypeId(0),
        DisplayNode::Alias {
            at: Selector(vec![Step::ActiveVariant]),
            follow_pointers: true,
        },
    );
    let err = b
        .validate()
        .expect_err("an active-variant display selector must be rejected");
    assert!(format!("{err}").contains("only a walk binding"), "{err}");
}

/// A bundle whose walks table exercises every step kind: `Sleep { entry }`
/// where `entry` is a two-variant enum, both of whose payloads carry a
/// `deadline` word — the shape the timer-flavor navigation walks. `broken_b`
/// drops the second variant's `deadline`, so an `ActiveVariant` crossing
/// cannot promise the remaining steps on every variant.
fn walk_bundle(broken_b: bool) -> Bundle {
    let mut strings = StringInterner::new();
    let u64n = strings.intern("u64");
    let an = strings.intern("A");
    let bn = strings.intern("B");
    let payloadn = strings.intern("payload");
    let deadlinen = strings.intern("deadline");
    let othern = strings.intern("other");
    let timern = strings.intern("Timer");
    let sleepn = strings.intern("Sleep");
    let entryn = strings.intern("entry");
    let ty = BundleTypeId(0);
    let member = |name, ty, offset| MemberDef { name, ty, offset };
    let variant = |name, ty, value| VariantDef {
        name,
        discr_values: Some(DiscrValues(vec![DiscrValue::Value(value)])),
        payload: member(payloadn, ty, 8),
        decl: None,
        await_site: None,
    };
    let mut b = Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.finish(),
        types: TypeTable {
            types: vec![
                // 0: u64
                TypeDef::Base {
                    name: u64n,
                    size: 8,
                    encoding: Encoding::Unsigned,
                },
                // 1: A's payload { deadline: u64 @0 }
                TypeDef::Struct {
                    name: an,
                    size: 8,
                    members: vec![member(deadlinen, ty, 0)],
                },
                // 2: B's payload { deadline: u64 @0 } (or `other`, broken)
                TypeDef::Struct {
                    name: bn,
                    size: 8,
                    members: vec![member(if broken_b { othern } else { deadlinen }, ty, 0)],
                },
                // 3: Timer, an enum over the two payloads.
                TypeDef::Enum {
                    name: timern,
                    size: 16,
                    shape: VariantShape {
                        discr: Some(DiscrDef { offset: 0, ty }),
                        variants: vec![
                            variant(an, BundleTypeId(1), 0),
                            variant(bn, BundleTypeId(2), 1),
                        ],
                    },
                },
                // 4: Sleep { entry: Timer @0 }
                TypeDef::Struct {
                    name: sleepn,
                    size: 16,
                    members: vec![member(entryn, BundleTypeId(3), 0)],
                },
            ],
            name_index: vec![],
            ..Default::default()
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: ty,
            vtable: ty,
            trailer: ty,
            context: ty,
            scheduler_handle: ty,
            mt_handle: ty,
            ct_handle: ty,
            location: ty,
            raw_waker_vtable: ty,
        },
        provenance: ProvenanceTable::default(),
        impls: ImplTable::default(),
    };
    b.walks.entries.insert(
        WalkRole::SleepDeadline,
        WalkBinding {
            roots: vec![BundleTypeId(4)],
            steps: vec![
                Step::Member(MemberRef::Named(entryn)),
                Step::ActiveVariant,
                Step::Member(MemberRef::Named(deadlinen)),
            ],
            outcome: WalkOutcome::Bound {
                spelling: 1,
                spellings: 3,
                note: None,
            },
        },
    );
    b
}

/// A bound walk binding resolves from every recorded root, fanning out over
/// an `ActiveVariant` crossing — and survives a save/load round-trip.
#[test]
fn test_validate_accepts_a_bound_walk_binding() {
    let b = walk_bundle(false);
    b.validate().expect("the binding resolves on every variant");
    assert!(Bundle::read_from(encode(&b).as_slice()).is_ok());
}

/// An `ActiveVariant` crossing requires *every* variant to satisfy the
/// remaining steps, since the runtime walker takes whichever is live.
#[test]
fn test_validate_requires_every_variant_to_satisfy_walk_steps() {
    let err = walk_bundle(true)
        .validate()
        .expect_err("a variant missing the walked member must be rejected");
    assert!(format!("{err}").contains("no unique member"), "{err}");
}

/// Absent and broken walk entries state outcomes, not navigations; a bound
/// one must record where it was resolved from.
#[test]
fn test_validate_constrains_walk_binding_shape() {
    // An unbound entry carrying steps.
    let mut b = walk_bundle(false);
    let binding = b.walks.entries.get_mut(&WalkRole::SleepDeadline).unwrap();
    binding.roots = Vec::new();
    binding.outcome = WalkOutcome::Absent {
        reason: "no Sleep in the bundle".to_owned(),
    };
    let err = b.validate().expect_err("an absent entry with steps");
    assert!(format!("{err}").contains("carries navigation"), "{err}");

    // And an unbound entry carrying roots. Navigation is steps *and*
    // where they start, so an entry that found nothing must state
    // neither: roots alone still claim a type the walk resolved
    // against, which is what an absent outcome says never happened.
    let mut b = walk_bundle(false);
    let binding = b.walks.entries.get_mut(&WalkRole::SleepDeadline).unwrap();
    binding.steps = Vec::new();
    binding.outcome = WalkOutcome::Absent {
        reason: "no Sleep in the bundle".to_owned(),
    };
    let err = b.validate().expect_err("an absent entry with roots");
    assert!(format!("{err}").contains("carries navigation"), "{err}");

    // A bound entry with no roots.
    let mut b = walk_bundle(false);
    b.walks
        .entries
        .get_mut(&WalkRole::SleepDeadline)
        .unwrap()
        .roots = Vec::new();
    let err = b.validate().expect_err("a bound entry with no roots");
    assert!(format!("{err}").contains("no roots"), "{err}");

    // A root id past the type table.
    let mut b = walk_bundle(false);
    b.walks
        .entries
        .get_mut(&WalkRole::SleepDeadline)
        .unwrap()
        .roots = vec![BundleTypeId(99)];
    let err = b.validate().expect_err("an out-of-range root");
    assert!(format!("{err}").contains("out of range"), "{err}");

    // A bound spelling index past its alternative count.
    let mut b = walk_bundle(false);
    b.walks
        .entries
        .get_mut(&WalkRole::SleepDeadline)
        .unwrap()
        .outcome = WalkOutcome::Bound {
        spelling: 3,
        spellings: 3,
        note: None,
    };
    let err = b.validate().expect_err("a spelling index out of range");
    assert!(format!("{err}").contains("spelling"), "{err}");
}

/// Role names are the report's row labels; two roles sharing one would make
/// the report ambiguous.
#[test]
fn test_walk_role_names_are_unique() {
    let names: std::collections::BTreeSet<_> = WalkRole::ALL.iter().map(|r| r.name()).collect();
    assert_eq!(names.len(), WalkRole::ALL.len());
}

#[test]
fn test_validate_rejects_provenance_length_mismatch() {
    let mut b = tiny_bundle();
    b.provenance.entries.push(Provenance {
        decl: None,
        kind: FutureKind::Manual,
    });
    assert!(matches!(b.validate(), Err(Error::Corrupt(_))));
}

/// The corruption `validate` names, rather than only that it named
/// one. A guard that reports the wrong thing — or a *different* guard
/// firing first — reads as a pass when the assertion is the error kind
/// alone, and several of these bundles are broken in a way more than
/// one guard could notice.
fn corruption(b: &Bundle) -> String {
    match b.validate() {
        Err(Error::Corrupt(why)) => why,
        other => panic!("expected a corruption, got {other:?}"),
    }
}

/// The name index is binary-searched, so its order is load-bearing, and
/// only a strict `>` between neighbours says so: a check that fired on
/// equal names would reject a bundle naming one type twice, which is
/// legal, and one that accepted a descending pair would leave the
/// search reading past its answer.
#[test]
fn test_validate_rejects_a_name_index_out_of_order() {
    let mut b = tiny_bundle();
    let mut strings = StringInterner::new();
    let z = strings.intern("zzz");
    let a = strings.intern("aaa");
    b.strings = strings.finish();
    b.types.types = vec![
        TypeDef::Base {
            name: z,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: a,
            size: 1,
            encoding: Encoding::Unsigned,
        },
    ];
    b.types.name_index = vec![(z, BundleTypeId(0)), (a, BundleTypeId(1))];
    b.types.build_normalized_index(&b.strings);
    assert!(
        corruption(&b).contains("name index not sorted"),
        "{}",
        corruption(&b)
    );

    // Sorted, and two rows naming the same type is not disorder.
    b.types.name_index = vec![(a, BundleTypeId(1)), (z, BundleTypeId(0))];
    b.types.build_normalized_index(&b.strings);
    b.validate().expect("a sorted index is not corruption");
}

/// A bundle naming two types, its indexes built from those names.
fn two_name_bundle() -> Bundle {
    let mut b = tiny_bundle();
    let mut strings = StringInterner::new();
    let a = strings.intern("aaa");
    let z = strings.intern("zzz");
    b.strings = strings.finish();
    b.types.types = vec![
        TypeDef::Base {
            name: a,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: z,
            size: 1,
            encoding: Encoding::Unsigned,
        },
    ];
    b.types.name_index = vec![(a, BundleTypeId(0)), (z, BundleTypeId(1))];
    b.types.build_normalized_index(&b.strings);
    b
}

/// A bundle carrying every shape a dyn-pointer check has an opinion
/// about: a `Box<dyn>` wide pointer with a valid `DynPointer` format on
/// the `ArcInner` at id 12, a wide pointer to a *sized* type at id 8,
/// one with no vtable member at id 9, and the `[usize; 4]` vtable both
/// of the real ones share.
fn dyn_bundle() -> Bundle {
    let mut b = tiny_bundle();
    let mut strings = StringInterner::new();
    let usizen = strings.intern("usize");
    let dynn =
        strings.intern("(dyn core::future::future::Future<Output=u32> + core::marker::Send)");
    let boxn = strings.intern("alloc::boxed::Box<(dyn core::future::future::Future<Output=u32> + core::marker::Send), alloc::alloc::Global>");
    let arc_innern = strings.intern("alloc::sync::ArcInner<(dyn core::future::future::Future<Output=u32> + core::marker::Send)>");
    let plainn = strings.intern("app::NotDyn");
    let datan = strings.intern("data");
    let pointer = strings.intern("pointer");
    let vtable = strings.intern("vtable");

    b.types = TypeTable {
        types: vec![
            // 0: usize
            TypeDef::Base {
                name: usizen,
                size: 8,
                encoding: Encoding::Unsigned,
            },
            // 1: the unsized dyn type
            TypeDef::Struct {
                name: dynn,
                size: 0,
                members: vec![],
            },
            // 2: *dyn
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(1),
            },
            // 3: [usize; 4]
            TypeDef::Array {
                elem: BundleTypeId(0),
                count: 4,
            },
            // 4: &[usize; 4]
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(3),
            },
            // 5: Box<dyn Future>
            TypeDef::Struct {
                name: boxn,
                size: 16,
                members: vec![
                    MemberDef {
                        name: pointer,
                        ty: BundleTypeId(2),
                        offset: 0,
                    },
                    MemberDef {
                        name: vtable,
                        ty: BundleTypeId(4),
                        offset: 8,
                    },
                ],
            },
            // 6: a sized struct (not a trait object)
            TypeDef::Struct {
                name: plainn,
                size: 8,
                members: vec![],
            },
            // 7: *NotDyn
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(6),
            },
            // 8: { pointer: *NotDyn, vtable: &[usize; 4] }
            TypeDef::Struct {
                name: plainn,
                size: 16,
                members: vec![
                    MemberDef {
                        name: pointer,
                        ty: BundleTypeId(7),
                        offset: 0,
                    },
                    MemberDef {
                        name: vtable,
                        ty: BundleTypeId(4),
                        offset: 8,
                    },
                ],
            },
            // 9: { pointer: *dyn } without a vtable member
            TypeDef::Struct {
                name: plainn,
                size: 8,
                members: vec![MemberDef {
                    name: pointer,
                    ty: BundleTypeId(2),
                    offset: 0,
                }],
            },
            // 10: an unsized wrapper whose final field is dyn
            TypeDef::Struct {
                name: arc_innern,
                size: 16,
                members: vec![MemberDef {
                    name: datan,
                    ty: BundleTypeId(1),
                    offset: 16,
                }],
            },
            // 11: *ArcInner<dyn Future>
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(10),
            },
            // 12: a wide pointer to the unsized wrapper
            TypeDef::Struct {
                name: arc_innern,
                size: 16,
                members: vec![
                    MemberDef {
                        name: pointer,
                        ty: BundleTypeId(11),
                        offset: 0,
                    },
                    MemberDef {
                        name: vtable,
                        ty: BundleTypeId(4),
                        offset: 8,
                    },
                ],
            },
        ],
        debug_formats: std::collections::BTreeMap::from([(
            BundleTypeId(12),
            DisplayNode::DynPointer {
                pointer: Selector::member(0),
                vtable: Selector::member(1),
                drop_in_place: 0,
                size: 1,
                align: 2,
                tail_offset: 0,
            },
        )]),
        name_index: vec![],
        ..Default::default()
    };
    b.strings = strings.finish();
    b.validate().expect("test bundle must validate");
    b
}

/// The normalized index is the same rows keyed by hash, so it carries
/// the same order requirement and two more of its own: every position
/// covered, and each of them once. A derived table that disagrees with
/// what it was derived from resolves a name to another name's type.
#[test]
fn test_validate_rejects_a_normalized_index_that_lies() {
    let mut b = two_name_bundle();
    let sound = b.types.by_normalized_name.clone();
    assert_eq!(sound.len(), 2, "{sound:?}");
    b.validate().expect("the index it was built with is sound");

    // Out of order by hash, and nothing else: the same rows, the same
    // count, each position once.
    b.types.by_normalized_name = sound.iter().copied().rev().collect();
    assert!(
        corruption(&b).contains("normalized name index not sorted"),
        "{}",
        corruption(&b)
    );

    // One position twice, which leaves the other unreachable — sorted,
    // and covering the right *number* of names, so only the seen-set
    // notices.
    b.types.by_normalized_name = vec![(sound[0].0, sound[0].1), (sound[1].0, sound[0].1)];
    assert!(
        corruption(&b).contains("repeats position"),
        "{}",
        corruption(&b)
    );

    // A position no row of `name_index` has.
    b.types.by_normalized_name = vec![(sound[0].0, sound[0].1), (sound[1].0, 2)];
    assert!(
        corruption(&b).contains("position 2 out of range"),
        "{}",
        corruption(&b)
    );
}

/// A type id is in range when it is *less* than the table's length, and
/// the id that says so is the one that is exactly its length: an
/// off-by-one here reads a type that is not there.
#[test]
fn test_validate_rejects_the_type_id_one_past_the_end() {
    let mut b = tiny_bundle();
    let past = BundleTypeId(b.types.types.len() as u32);
    b.infra.header = past;
    assert!(
        corruption(&b).contains(&format!("type id {} out of range", past.0)),
        "{}",
        corruption(&b)
    );

    b.infra.header = BundleTypeId(past.0 - 1);
    b.validate().expect("the last id in the table is in range");
}

#[test]
fn test_save_validates() {
    let mut b = tiny_bundle();
    b.infra.header = BundleTypeId(999);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.tinfo");
    assert!(matches!(b.save(&path), Err(Error::Corrupt(_))));
    assert!(!path.exists());
}

#[test]
fn test_save_load_file() {
    let b = random_bundle(11);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.tinfo");
    b.save(&path).expect("save failed");
    let loaded = Bundle::load(&path).expect("load failed");
    assert_eq!(b, loaded);
}

#[test]
fn test_strip_llvm_suffix() {
    assert_eq!(strip_llvm_suffix("_RfooE"), "_RfooE");
    assert_eq!(strip_llvm_suffix("_RfooE.llvm.12345"), "_RfooE");
    // not a real .llvm suffix: non-digits or nothing after it
    assert_eq!(strip_llvm_suffix("_RfooE.llvm.12x"), "_RfooE.llvm.12x");
    assert_eq!(strip_llvm_suffix("_RfooE.llvm."), "_RfooE.llvm.");
}

#[test]
fn test_symbol_lookup_is_mangled_exact_match() {
    // Joins are exact-match on mangled input, with .llvm stripping;
    // no demangling in the lookup path.
    let mut b = tiny_bundle();
    let mut strings = StringInterner::new();
    let name = strings.intern("u64");
    let display = strings.intern("my_future");
    b.strings = strings.finish();
    b.types.name_index = vec![(name, BundleTypeId(0))];
    b.tasks.entries.push(TaskFutureEntry {
        future: BundleTypeId(0),
        cell: BundleTypeId(0),
        stage: BundleTypeId(0),
        scheduler: BundleTypeId(0),
        display_name: display,
    });
    b.tasks
        .by_symbol
        .insert("_RINvNtNtNtC_5tokio_pollE".into(), TaskEntryId(0));
    b.dyn_futures
        .by_symbol
        .insert("_RNvX_dynE".into(), BundleTypeId(0));
    b.provenance.entries.push(Provenance {
        decl: None,
        kind: FutureKind::AsyncFn,
    });
    b.validate().expect("test bundle invalid");

    assert!(b.tasks.lookup("_RINvNtNtNtC_5tokio_pollE").is_some());
    assert!(
        b.tasks
            .lookup("_RINvNtNtNtC_5tokio_pollE.llvm.987")
            .is_some()
    );
    assert!(b.tasks.lookup("_RINvNtNtNtC_5tokio_otherE").is_none());
    assert_eq!(
        b.dyn_futures.lookup("_RNvX_dynE.llvm.1"),
        Some(BundleTypeId(0))
    );
    assert_eq!(b.dyn_futures.lookup("_RNvX_dynE"), Some(BundleTypeId(0)));
}

#[test]
fn test_symbol_lookup_falls_back_to_normalized_name() {
    const DEBUG: &str =
        "_RNvNCNvNtNtCs4y941wpZLOZ_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";
    const NODEBUG: &str =
        "_RNvNCNvNtNtCsbdypcaruIt3_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";

    let entry = TaskFutureEntry {
        future: BundleTypeId(0),
        cell: BundleTypeId(0),
        stage: BundleTypeId(0),
        scheduler: BundleTypeId(0),
        display_name: StrRef(0),
    };
    let by_symbol = BTreeMap::from([(DEBUG.to_owned(), TaskEntryId(0))]);
    let tasks = TaskTable {
        by_normalized_symbol: crate::symbols::normalized_value_index(&by_symbol),
        by_symbol,
        entries: vec![entry],
    };
    assert!(tasks.lookup(NODEBUG).is_some());
}

/// Two same-named futures from different crate builds normalize to the
/// same key; a third spelling must surface every candidate, and the
/// single-entry lookup must decline rather than pick one.
#[test]
fn test_symbol_lookup_reports_every_ambiguous_spelling() {
    const A: &str =
        "_RNvNCNvNtNtCs4y941wpZLOZ_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";
    const B: &str =
        "_RNvNCNvNtNtCsbdypcaruIt3_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";
    const OTHER: &str =
        "_RNvNCNvNtNtCs4y941wpZLOX_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";

    let entry = || TaskFutureEntry {
        future: BundleTypeId(0),
        cell: BundleTypeId(0),
        stage: BundleTypeId(0),
        scheduler: BundleTypeId(0),
        display_name: StrRef(0),
    };
    let by_symbol = BTreeMap::from([
        (A.to_owned(), TaskEntryId(0)),
        (B.to_owned(), TaskEntryId(1)),
    ]);
    let tasks = TaskTable {
        by_normalized_symbol: crate::symbols::normalized_value_index(&by_symbol),
        by_symbol,
        entries: vec![entry(), entry()],
    };
    assert_eq!(
        tasks.lookup_id(OTHER),
        SymbolLookup::Ambiguous(vec![TaskEntryId(0), TaskEntryId(1)])
    );
    assert!(tasks.lookup(OTHER).is_none());
}

#[test]
fn test_find_by_name() {
    let mut strings = StringInterner::new();
    let a = strings.intern("crate::A");
    let b_ = strings.intern("crate::B");
    let types = TypeTable {
        types: vec![
            TypeDef::Base {
                name: a,
                size: 1,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Base {
                name: b_,
                size: 2,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Base {
                name: b_,
                size: 4,
                encoding: Encoding::Unsigned,
            },
        ],
        debug_formats: BTreeMap::new(),
        name_index: vec![
            (a, BundleTypeId(0)),
            (b_, BundleTypeId(1)),
            (b_, BundleTypeId(2)),
        ],
        ..Default::default()
    };
    let table = strings.finish();
    let hits: Vec<_> = types.find_by_name(&table, "crate::B").collect();
    assert_eq!(hits, [BundleTypeId(1), BundleTypeId(2)]);
    let hits: Vec<_> = types.find_by_name(&table, "crate::A").collect();
    assert_eq!(hits, [BundleTypeId(0)]);
    assert_eq!(types.find_by_name(&table, "crate::C").count(), 0);
    assert_eq!(types.find_by_name(&table, "").count(), 0);
}

#[test]
fn test_discr_values_matches() {
    let v = DiscrValues(vec![DiscrValue::Value(3), DiscrValue::Range(10, 12)]);
    assert!(v.matches(3));
    assert!(!v.matches(4));
    assert!(v.matches(10));
    assert!(v.matches(12));
    assert!(!v.matches(13));
    // u128 discriminants (DWARFv4 two-u64 block encoding) survive intact
    let big = u128::MAX - 1;
    let v = DiscrValues(vec![DiscrValue::Value(big)]);
    assert!(v.matches(big));
    assert!(!v.matches(u128::MAX));
}

// ---------------------------------------------------------------------------
// BundleType view + variant decoding
// ---------------------------------------------------------------------------

mod view_tests {
    use super::dyn_bundle;
    use crate::Encoding;
    use crate::schema::*;
    use crate::strings::StringInterner;
    use crate::view::{BundleView, TypeKind, VariantError};

    /// Build a bundle whose type 0 is `u64`, type 1 is a zero-sized unit
    /// struct, and type 2 is an enum with the given shape. Additional
    /// payload types may be appended first via `extra`.
    fn enum_bundle(
        discr: Option<(u64, BundleTypeId)>,
        variants: Vec<(&str, Option<DiscrValues>, BundleTypeId, u64)>,
    ) -> Bundle {
        let mut b = super::tiny_bundle();
        let mut strings = StringInterner::new();
        let u64_name = strings.intern("u64");
        let u128_name = strings.intern("u128");
        let unit_name = strings.intern("Unit");
        let enum_name = strings.intern("E");

        let mut types = vec![
            // 0: u64
            TypeDef::Base {
                name: u64_name,
                size: 8,
                encoding: Encoding::Unsigned,
            },
            // 1: zero-sized unit struct
            TypeDef::Struct {
                name: unit_name,
                size: 0,
                members: vec![],
            },
            // 2: u128
            TypeDef::Base {
                name: u128_name,
                size: 16,
                encoding: Encoding::Unsigned,
            },
            // 3: u8 (handy discriminant type)
            TypeDef::Base {
                name: u64_name,
                size: 1,
                encoding: Encoding::Unsigned,
            },
        ];

        let variants = variants
            .into_iter()
            .map(|(name, discr_values, ty, offset)| VariantDef {
                name: strings.intern(name),
                discr_values,
                payload: MemberDef {
                    name: strings.intern(name),
                    ty,
                    offset,
                },
                decl: None,
                await_site: None,
            })
            .collect();

        types.push(TypeDef::Enum {
            name: enum_name,
            size: 24,
            shape: VariantShape {
                discr: discr.map(|(offset, ty)| DiscrDef { offset, ty }),
                variants,
            },
        });

        b.strings = strings.finish();
        b.types = TypeTable {
            types,
            debug_formats: std::collections::BTreeMap::new(),
            name_index: vec![],
            ..Default::default()
        };
        b.infra = InfraTypes {
            header: BundleTypeId(0),
            vtable: BundleTypeId(0),
            trailer: BundleTypeId(0),
            context: BundleTypeId(0),
            scheduler_handle: BundleTypeId(0),
            mt_handle: BundleTypeId(0),
            ct_handle: BundleTypeId(0),
            location: BundleTypeId(0),
            raw_waker_vtable: BundleTypeId(0),
        };
        b.validate().expect("test bundle must validate");
        b
    }

    const ENUM_ID: BundleTypeId = BundleTypeId(4);
    const U64_ID: BundleTypeId = BundleTypeId(0);
    const UNIT_ID: BundleTypeId = BundleTypeId(1);
    const U128_ID: BundleTypeId = BundleTypeId(2);
    const U8_ID: BundleTypeId = BundleTypeId(3);

    fn vals(vs: &[u128]) -> Option<DiscrValues> {
        Some(DiscrValues(
            vs.iter().map(|&v| DiscrValue::Value(v)).collect(),
        ))
    }

    #[test]
    fn test_active_variant_explicit_tags() {
        let b = enum_bundle(
            Some((0, U8_ID)),
            vec![
                ("A", vals(&[0]), U64_ID, 8),
                ("B", vals(&[1]), UNIT_ID, 0),
                ("C", vals(&[2]), U64_ID, 8),
            ],
        );
        let view = BundleView::new(&b);
        let e = view.ty(ENUM_ID).unwrap();

        let mut bytes = [0u8; 24];
        for (tag, want, want_off) in [(0u8, "A", 8), (1, "B", 0), (2, "C", 8)] {
            bytes[0] = tag;
            let v = e.active_variant(&bytes).unwrap().unwrap();
            assert_eq!(v.name, want);
            assert_eq!(v.offset, want_off);
        }
        assert_eq!(e.active_variant(&bytes).unwrap().unwrap().ty.name(), "u64");

        // Invalid tag with no default variant is an error, never a guess.
        bytes[0] = 9;
        assert_eq!(
            e.active_variant(&bytes).unwrap().unwrap_err(),
            VariantError::NoVariantMatch { raw: 9 }
        );
    }

    #[test]
    fn test_active_variant_niche_default() {
        // Option<NonNull<T>>-style: None has the explicit value 0, Some is
        // the default variant selected when nothing matches.
        let b = enum_bundle(
            Some((0, U64_ID)),
            vec![("None", vals(&[0]), UNIT_ID, 0), ("Some", None, U64_ID, 0)],
        );
        let view = BundleView::new(&b);
        let e = view.ty(ENUM_ID).unwrap();

        let mut bytes = [0u8; 24];
        assert_eq!(e.active_variant(&bytes).unwrap().unwrap().name, "None");

        bytes[..8].copy_from_slice(&0x1234_5678_9abcu64.to_le_bytes());
        let v = e.active_variant(&bytes).unwrap().unwrap();
        assert_eq!(v.name, "Some");
        assert_eq!(v.offset, 0);
    }

    #[test]
    fn test_active_variant_u128_discriminant() {
        // 16-byte discriminant, values above u64::MAX (the DWARFv4
        // two-u64-block case, resolved to u128 at extraction time).
        let big = (7u128 << 64) | 0x0102_0304;
        let b = enum_bundle(
            Some((0, U128_ID)),
            vec![
                ("Big", vals(&[big]), UNIT_ID, 16),
                ("Other", vals(&[u128::MAX]), UNIT_ID, 16),
            ],
        );
        let view = BundleView::new(&b);
        let e = view.ty(ENUM_ID).unwrap();

        let mut bytes = [0u8; 24];
        bytes[..16].copy_from_slice(&big.to_le_bytes());
        assert_eq!(e.active_variant(&bytes).unwrap().unwrap().name, "Big");

        bytes[..16].copy_from_slice(&u128::MAX.to_le_bytes());
        assert_eq!(e.active_variant(&bytes).unwrap().unwrap().name, "Other");
    }

    #[test]
    fn test_active_variant_discr_ranges() {
        // DWARFv5 DW_AT_discr_list: values and inclusive ranges mixed.
        let b = enum_bundle(
            Some((0, U8_ID)),
            vec![
                (
                    "Low",
                    Some(DiscrValues(vec![
                        DiscrValue::Value(0),
                        DiscrValue::Range(10, 20),
                    ])),
                    UNIT_ID,
                    0,
                ),
                (
                    "High",
                    Some(DiscrValues(vec![DiscrValue::Range(21, 30)])),
                    UNIT_ID,
                    0,
                ),
            ],
        );
        let view = BundleView::new(&b);
        let e = view.ty(ENUM_ID).unwrap();

        let mut bytes = [0u8; 24];
        for (tag, want) in [
            (0u8, "Low"),
            (10, "Low"),
            (20, "Low"),
            (21, "High"),
            (30, "High"),
        ] {
            bytes[0] = tag;
            assert_eq!(
                e.active_variant(&bytes).unwrap().unwrap().name,
                want,
                "tag {tag}"
            );
        }
        bytes[0] = 31;
        assert!(matches!(
            e.active_variant(&bytes).unwrap(),
            Err(VariantError::NoVariantMatch { raw: 31 })
        ));
    }

    #[test]
    fn test_active_variant_zero_sized_payload() {
        let b = enum_bundle(
            Some((8, U8_ID)),
            vec![
                ("Unit", vals(&[0]), UNIT_ID, 0),
                ("Full", vals(&[1]), U64_ID, 0),
            ],
        );
        let view = BundleView::new(&b);
        let e = view.ty(ENUM_ID).unwrap();

        // Discriminant at a nonzero offset, zero-sized payload.
        let bytes = [0u8; 24];
        let v = e.active_variant(&bytes).unwrap().unwrap();
        assert_eq!(v.name, "Unit");
        assert_eq!(v.ty.size(), 0);
    }

    #[test]
    fn test_active_variant_univariant() {
        let b = enum_bundle(None, vec![("Only", None, U64_ID, 0)]);
        let view = BundleView::new(&b);
        let e = view.ty(ENUM_ID).unwrap();

        // No discriminant to read; works even with an empty buffer.
        let v = e.active_variant(&[]).unwrap().unwrap();
        assert_eq!(v.name, "Only");
    }

    #[test]
    fn test_active_variant_error_cases() {
        // Uninhabited enum.
        let b = enum_bundle(None, vec![]);
        let e = BundleView::new(&b).ty(ENUM_ID).unwrap();
        assert_eq!(
            e.active_variant(&[]).unwrap().unwrap_err(),
            VariantError::Uninhabited
        );

        // Multiple variants, no discriminant: corrupt.
        let b = enum_bundle(None, vec![("A", None, UNIT_ID, 0), ("B", None, UNIT_ID, 0)]);
        let e = BundleView::new(&b).ty(ENUM_ID).unwrap();
        assert_eq!(
            e.active_variant(&[]).unwrap().unwrap_err(),
            VariantError::MissingDiscriminant
        );

        // Buffer shorter than the discriminant.
        let b = enum_bundle(Some((8, U64_ID)), vec![("A", vals(&[0]), UNIT_ID, 0)]);
        let e = BundleView::new(&b).ty(ENUM_ID).unwrap();
        assert_eq!(
            e.active_variant(&[0u8; 4]).unwrap().unwrap_err(),
            VariantError::ShortBuffer { needed: 16, len: 4 }
        );

        // Not an enum at all → outer None.
        assert!(
            BundleView::new(&b)
                .ty(U64_ID)
                .unwrap()
                .active_variant(&[0u8; 8])
                .is_none()
        );
    }

    #[test]
    fn test_check_variant() {
        let b = enum_bundle(
            Some((0, U8_ID)),
            vec![("A", vals(&[0]), U64_ID, 8), ("B", vals(&[1]), UNIT_ID, 0)],
        );
        let e = BundleView::new(&b).ty(ENUM_ID).unwrap();

        let mut bytes = [0u8; 24];
        // Active variant: payload type and offset returned.
        let (ty, off) = e.check_variant(&bytes, "A").unwrap().unwrap().unwrap();
        assert_eq!(ty.name(), "u64");
        assert_eq!(off, 8);
        // Inactive variant: Ok(None).
        assert!(e.check_variant(&bytes, "B").unwrap().unwrap().is_none());
        bytes[0] = 1;
        assert!(e.check_variant(&bytes, "B").unwrap().unwrap().is_some());
        // Unknown variant name: an error, not "inactive".
        assert_eq!(
            e.check_variant(&bytes, "Nope").unwrap().unwrap_err(),
            VariantError::NoSuchVariant
        );
    }

    /// A coroutine-shaped enum, as rustc 1.97 emits it: variant
    /// members are numbered ("0", "1", …); the state names live on the
    /// payload structs; suspend variants carry the awaited expression's
    /// decl coordinates.
    fn coroutine_bundle() -> Bundle {
        let mut b = super::tiny_bundle();
        let mut strings = StringInterner::new();
        let u8n = strings.intern("u8");
        let envn = strings.intern("app::work::{async_fn_env#0}");
        let unresumed = strings.intern("app::work::{async_fn_env#0}::Unresumed");
        let suspend0 = strings.intern("app::work::{async_fn_env#0}::Suspend0");
        let file = strings.intern("src/work.rs");
        let v0 = strings.intern("0");
        let v3 = strings.intern("3");

        let tag = |v: u128| Some(DiscrValues(vec![DiscrValue::Value(v)]));
        b.types = TypeTable {
            types: vec![
                // 0: u8
                TypeDef::Base {
                    name: u8n,
                    size: 1,
                    encoding: Encoding::Unsigned,
                },
                // 1: Unresumed payload
                TypeDef::Struct {
                    name: unresumed,
                    size: 8,
                    members: vec![],
                },
                // 2: Suspend0 payload
                TypeDef::Struct {
                    name: suspend0,
                    size: 8,
                    members: vec![],
                },
                // 3: the coroutine env
                TypeDef::Enum {
                    name: envn,
                    size: 8,
                    shape: VariantShape {
                        discr: Some(DiscrDef {
                            offset: 0,
                            ty: BundleTypeId(0),
                        }),
                        variants: vec![
                            VariantDef {
                                name: v0,
                                discr_values: tag(0),
                                payload: MemberDef {
                                    name: v0,
                                    ty: BundleTypeId(1),
                                    offset: 0,
                                },
                                decl: None,
                                await_site: None,
                            },
                            VariantDef {
                                name: v3,
                                discr_values: tag(3),
                                payload: MemberDef {
                                    name: v3,
                                    ty: BundleTypeId(2),
                                    offset: 0,
                                },
                                decl: Some(SourceLoc { file, line: 18 }),
                                await_site: None,
                            },
                        ],
                    },
                },
            ],
            debug_formats: std::collections::BTreeMap::new(),
            name_index: vec![],
            ..Default::default()
        };
        b.strings = strings.finish();
        b.validate().expect("test bundle must validate");
        b
    }

    #[test]
    fn test_coroutine_state_names_and_decl() {
        let b = coroutine_bundle();
        let e = BundleView::new(&b).ty(BundleTypeId(3)).unwrap();

        // Numbered variant members resolve their state name through the
        // payload struct; the awaited expression's decl coords surface on
        // the suspend variant.
        let v = e.active_variant(&[0u8; 8]).unwrap().unwrap();
        assert_eq!(v.name, "0");
        assert_eq!(v.state_name(), "Unresumed");
        assert_eq!(v.decl, None);

        let v = e
            .active_variant(&[3, 0, 0, 0, 0, 0, 0, 0])
            .unwrap()
            .unwrap();
        assert_eq!(v.name, "3");
        assert_eq!(v.state_name(), "Suspend0");
        assert_eq!(v.decl, Some(("src/work.rs", 18)));
    }

    #[test]
    fn test_named_variants_keep_their_names() {
        // Ordinary enums name the variant member itself; state_name must
        // not second-guess it from the payload type.
        let b = enum_bundle(
            Some((0, U8_ID)),
            vec![
                ("Running", vals(&[0]), U64_ID, 8),
                ("Consumed", vals(&[1]), UNIT_ID, 0),
            ],
        );
        let e = BundleView::new(&b).ty(ENUM_ID).unwrap();
        let v = e.active_variant(&[0u8; 24]).unwrap().unwrap();
        assert_eq!(v.state_name(), "Running");
    }

    /// A `Box<dyn Future>`-shaped wide pointer: a `pointer` member
    /// targeting the unsized `(dyn …)` struct plus a `vtable` pointer.

    #[test]
    fn test_dyn_pointer_detection() {
        let b = dyn_bundle();
        let view = BundleView::new(&b);

        let dp = view
            .ty(BundleTypeId(5))
            .unwrap()
            .dyn_pointer()
            .expect("Box<dyn> detected");
        assert_eq!(dp.data_offset, 0);
        assert_eq!(dp.vtable_offset, 8);
        assert!(dp.pointee.name().starts_with("(dyn core::future"));

        // Pointer to a sized type: not a trait object.
        assert!(view.ty(BundleTypeId(8)).unwrap().dyn_pointer().is_none());
        // No vtable member: not a wide pointer.
        assert!(view.ty(BundleTypeId(9)).unwrap().dyn_pointer().is_none());
        // Non-structs never match.
        assert!(view.ty(BundleTypeId(0)).unwrap().dyn_pointer().is_none());
    }

    #[test]
    fn test_view_structural_accessors() {
        let mut b = super::tiny_bundle();
        let mut strings = StringInterner::new();
        let point = strings.intern("Point");
        let x = strings.intern("x");
        let y = strings.intern("y");
        let u32n = strings.intern("u32");
        let f64n = strings.intern("f64");
        b.strings = strings.finish();
        b.types = TypeTable {
            types: vec![
                TypeDef::Base {
                    name: u32n,
                    size: 4,
                    encoding: Encoding::Unsigned,
                },
                TypeDef::Struct {
                    name: point,
                    size: 8,
                    members: vec![
                        MemberDef {
                            name: x,
                            ty: BundleTypeId(0),
                            offset: 0,
                        },
                        MemberDef {
                            name: y,
                            ty: BundleTypeId(0),
                            offset: 4,
                        },
                    ],
                },
                TypeDef::Pointer {
                    name: None,
                    target: BundleTypeId(1),
                },
                TypeDef::Array {
                    elem: BundleTypeId(0),
                    count: 3,
                },
                TypeDef::Base {
                    name: f64n,
                    size: 8,
                    encoding: Encoding::Float,
                },
            ],
            debug_formats: std::collections::BTreeMap::new(),
            name_index: vec![
                (point, BundleTypeId(1)),
                (f64n, BundleTypeId(4)),
                (u32n, BundleTypeId(0)),
            ],
            ..Default::default()
        };
        b.types.build_normalized_index(&b.strings);
        b.validate().expect("test bundle must validate");

        let view = BundleView::new(&b);
        let s = view.find_by_name("Point").next().expect("Point not found");
        assert_eq!(
            s.type_by_name(" Point ").map(|ty| ty.id()),
            Some(BundleTypeId(1))
        );
        assert_eq!(s.size(), 8);
        assert_eq!(s.members().len(), 2);
        let m = s.member("y").expect("no member y");
        assert_eq!(m.offset(), 4);
        assert_eq!(m.ty().name(), "u32");
        assert!(s.member("z").is_none());

        let p = view.ty(BundleTypeId(2)).unwrap();
        assert_eq!(p.size(), crate::view::POINTER_SIZE);
        assert_eq!(p.pointer_target().unwrap().name(), "Point");

        let a = view.ty(BundleTypeId(3)).unwrap();
        let (elem, count) = a.array_info().unwrap();
        assert_eq!(elem.name(), "u32");
        assert_eq!(count, 3);
        assert_eq!(a.size(), 12);

        // The coarse kinds, including the one float encoding splits off.
        assert_eq!(s.kind(), TypeKind::Struct);
        assert_eq!(view.ty(BundleTypeId(0)).unwrap().kind(), TypeKind::Integer);
        assert_eq!(view.ty(BundleTypeId(4)).unwrap().kind(), TypeKind::Float);

        // A handle is its bundle and id; another id is another type.
        assert_eq!(view.ty(BundleTypeId(1)), view.ty(BundleTypeId(1)));
        assert_ne!(view.ty(BundleTypeId(0)), view.ty(BundleTypeId(1)));

        assert_eq!(s.size_by_name(" u32 "), Some(4));

        // The member iterator's length tracks consumption.
        let mut members = s.members();
        assert_eq!(members.len(), 2);
        members.next();
        assert_eq!(members.len(), 1);

        assert_eq!(format!("{view:?}"), "BundleView { types: 5, tasks: 0 }");
    }

    /// Duplicate DIEs behind one name are benign only while they agree:
    /// same-size duplicates still answer `size_by_name`, two ids never
    /// answer `type_by_name`, and conflicting sizes answer neither.
    #[test]
    fn test_lookup_by_name_screens_ambiguity() {
        let mut b = super::tiny_bundle();
        let mut strings = StringInterner::new();
        let point = strings.intern("Point");
        let wide = strings.intern("Wide");
        let u32n = strings.intern("u32");
        b.strings = strings.finish();
        let sized_struct = |name, size| TypeDef::Struct {
            name,
            size,
            members: vec![],
        };
        b.types = TypeTable {
            types: vec![
                TypeDef::Base {
                    name: u32n,
                    size: 4,
                    encoding: Encoding::Unsigned,
                },
                sized_struct(point, 8),
                sized_struct(point, 8),
                sized_struct(wide, 8),
                sized_struct(wide, 12),
            ],
            debug_formats: std::collections::BTreeMap::new(),
            name_index: vec![
                (point, BundleTypeId(1)),
                (point, BundleTypeId(2)),
                (wide, BundleTypeId(3)),
                (wide, BundleTypeId(4)),
                (u32n, BundleTypeId(0)),
            ],
            ..Default::default()
        };
        b.types.build_normalized_index(&b.strings);
        b.validate().expect("test bundle must validate");

        let view = BundleView::new(&b);
        let scope = view.ty(BundleTypeId(0)).unwrap();
        assert_eq!(scope.size_by_name("Point"), Some(8));
        assert!(scope.type_by_name("Point").is_none());
        assert_eq!(scope.size_by_name("Wide"), None);
        assert!(scope.type_by_name("Wide").is_none());
        assert_eq!(scope.size_by_name("u32"), Some(4));
    }

    /// The words a kind renders as — reify's type-mismatch errors quote
    /// them.
    #[test]
    fn test_type_kind_display_words() {
        for (kind, word) in [
            (TypeKind::Integer, "integer"),
            (TypeKind::Float, "float"),
            (TypeKind::Pointer, "pointer"),
            (TypeKind::Array, "array"),
            (TypeKind::Struct, "struct"),
            (TypeKind::Union, "union"),
            (TypeKind::Enum, "enum"),
            (TypeKind::Other, "other"),
        ] {
            assert_eq!(kind.to_string(), word);
        }
    }
}

// ---------------------------------------------------------------------------
// Source paths
// ---------------------------------------------------------------------------

mod source_path_tests {
    use crate::strip_build_prefix;

    /// A `file!()` string reaches the reader without a line-table directory
    /// to join, so the same cut has to work on the whole path alone.
    #[test]
    fn test_strip_build_prefix_bare_path() {
        assert_eq!(
            strip_build_prefix(
                "/home/build/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                 qorb-0.4.1/src/pool.rs"
            ),
            "qorb-0.4.1/src/pool.rs"
        );
        assert_eq!(
            strip_build_prefix("test-programs/src/bin/simple-await.rs"),
            "test-programs/src/bin/simple-await.rs"
        );
    }
}

/// Negative validation for the newer display-node vocabulary: the
/// `ScalarDecode` tables, value expressions, `CustomList` programs,
/// `Variant` arms, `Bytes` notations, and the B-tree `MapEntries`.
/// `validate()` is the trust boundary for a bundle read from disk, and
/// until here nothing proved a malformed instance of these kinds is
/// *rejected* — only that valid ones are accepted.
mod node_validation {
    use super::*;

    use std::num::NonZeroU8;

    /// Validation fails *and* the message names this corruption — a
    /// rejection for some other reason is a false pass.
    #[track_caller]
    fn rejects(b: &Bundle, needle: &str) {
        match b.validate() {
            Err(Error::Corrupt(msg)) => assert!(
                msg.contains(needle),
                "rejected for the wrong reason:\n  wanted …{needle}…\n  got    {msg}"
            ),
            other => panic!("expected Corrupt(…{needle}…), got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // A scope to hang programs on: word and byte-array members.
    // -------------------------------------------------------------------

    const HOLDER: BundleTypeId = BundleTypeId(7);
    const OPAQUE: BundleTypeId = BundleTypeId(6);

    /// `Holder { word: u64@0, b4: [u8;4]@8, b5: [u8;5]@12, sb16: [i8;16]@17,
    /// b0: [u8;0]@33 }`, plus an opaque (unsized) type on the side.
    fn holder_bundle() -> Bundle {
        let mut b = super::tiny_bundle();
        let mut strings = StringInterner::new();
        let u64n = strings.intern("u64");
        let u8n = strings.intern("u8");
        let i8n = strings.intern("i8");
        let opaquen = strings.intern("Mystery");
        let holdern = strings.intern("Holder");
        let members: Vec<StrRef> = ["word", "b4", "b5", "sb16", "b0"]
            .iter()
            .map(|m| strings.intern(m))
            .collect();

        let types = vec![
            // 0: u64
            TypeDef::Base {
                name: u64n,
                size: 8,
                encoding: Encoding::Unsigned,
            },
            // 1: u8
            TypeDef::Base {
                name: u8n,
                size: 1,
                encoding: Encoding::Unsigned,
            },
            // 2: i8
            TypeDef::Base {
                name: i8n,
                size: 1,
                encoding: Encoding::Signed,
            },
            // 3: [u8; 4]
            TypeDef::Array {
                elem: BundleTypeId(1),
                count: 4,
            },
            // 4: [u8; 5]
            TypeDef::Array {
                elem: BundleTypeId(1),
                count: 5,
            },
            // 5: [i8; 16]
            TypeDef::Array {
                elem: BundleTypeId(2),
                count: 16,
            },
            // 6: an unsized type
            TypeDef::Opaque {
                name: opaquen,
                size: None,
            },
            // 7: Holder
            TypeDef::Struct {
                name: holdern,
                size: 40,
                members: [
                    (0u64, BundleTypeId(0)),
                    (8, BundleTypeId(3)),
                    (12, BundleTypeId(4)),
                    (17, BundleTypeId(5)),
                    (33, BundleTypeId(3)),
                ]
                .iter()
                .zip(&members)
                .map(|((offset, ty), name)| MemberDef {
                    name: *name,
                    ty: *ty,
                    offset: *offset,
                })
                .collect(),
            },
        ];
        // `b0` above reuses [u8;4]; re-point it at a zero-length array.
        let mut types = types;
        types.push(TypeDef::Array {
            elem: BundleTypeId(1),
            count: 0,
        });
        match &mut types[7] {
            TypeDef::Struct { members, .. } => members[4].ty = BundleTypeId(8),
            _ => unreachable!(),
        }

        b.strings = strings.finish();
        b.types = TypeTable {
            types,
            debug_formats: BTreeMap::new(),
            name_index: vec![],
            ..Default::default()
        };
        b.validate().expect("the holder fixture must validate");
        b
    }

    fn with_format(node: DisplayNode) -> Bundle {
        let mut b = holder_bundle();
        b.types.debug_formats.insert(HOLDER, node);
        b
    }

    fn scalar(decode: ScalarDecode) -> DisplayNode {
        DisplayNode::Scalar {
            at: Selector::member(0),
            decode,
        }
    }

    fn field(name: StrRef, shift: u8, width: Option<u8>, render: FieldRender) -> BitField {
        BitField {
            name,
            shift,
            width: width.map(|w| NonZeroU8::new(w).unwrap()),
            render,
        }
    }

    /// A string ref the fixture actually holds, for fields whose name
    /// is not what the test is about.
    fn a_name() -> StrRef {
        StrRef(0)
    }

    // -------------------------------------------------------------------
    // ScalarDecode
    // -------------------------------------------------------------------

    #[test]
    fn test_validate_rejects_an_empty_bits_decode() {
        let b = with_format(scalar(ScalarDecode::Bits(vec![])));
        rejects(&b, "Bits decode has no fields");
    }

    #[test]
    fn test_validate_rejects_a_bits_field_with_a_bad_name() {
        let b = with_format(scalar(ScalarDecode::Bits(vec![field(
            StrRef(999),
            0,
            None,
            FieldRender::Uint,
        )])));
        rejects(&b, "name string ref 999 out of range");
    }

    #[test]
    fn test_validate_rejects_a_shift_beyond_the_word() {
        let name = a_name();
        let b = with_format(scalar(ScalarDecode::Bits(vec![field(
            name,
            64,
            None,
            FieldRender::Uint,
        )])));
        rejects(&b, "beyond the 64-bit word");
    }

    #[test]
    fn test_validate_rejects_a_field_overflowing_the_word() {
        let name = a_name();
        let b = with_format(scalar(ScalarDecode::Bits(vec![field(
            name,
            60,
            Some(8),
            FieldRender::Uint,
        )])));
        rejects(&b, "overflows the 64-bit word");
    }

    #[test]
    fn test_validate_rejects_overlapping_bit_fields() {
        let name = a_name();
        let b = with_format(scalar(ScalarDecode::Bits(vec![
            field(name, 0, Some(4), FieldRender::Uint),
            field(name, 2, Some(4), FieldRender::Uint),
        ])));
        rejects(&b, "overlaps an earlier field");
    }

    #[test]
    fn test_validate_rejects_a_bad_enum_label_ref() {
        let name = a_name();
        let b = with_format(scalar(ScalarDecode::Bits(vec![field(
            name,
            0,
            Some(2),
            FieldRender::Enum(vec![(0, StrRef(999))]),
        )])));
        rejects(&b, "enum label string ref 999 out of range");
    }

    #[test]
    fn test_validate_rejects_an_enum_value_wider_than_its_field() {
        let name = a_name();
        let b = with_format(scalar(ScalarDecode::Bits(vec![field(
            name,
            0,
            Some(2),
            FieldRender::Enum(vec![(7, name)]),
        )])));
        rejects(&b, "enum value 7 does not fit its 2-bit field");
    }

    // -------------------------------------------------------------------
    // Value expressions (via `Computed`, which roots one)
    // -------------------------------------------------------------------

    #[test]
    fn test_validate_rejects_a_variable_outside_a_custom_list() {
        // `Computed` declares no loop variables, so any Var is out of
        // range — even nested inside other operators.
        let b = with_format(DisplayNode::Computed {
            value: ValueExpr::Add(
                Box::new(ValueExpr::Const(1)),
                Box::new(ValueExpr::Not(Box::new(ValueExpr::Var(0)))),
            ),
            decode: ScalarDecode::Raw,
        });
        rejects(&b, "variable 0 out of range (0 declared)");
    }

    #[test]
    fn test_validate_rejects_a_load_of_an_odd_width() {
        let b = with_format(DisplayNode::Computed {
            value: ValueExpr::Const(0).load(3),
            decode: ScalarDecode::Raw,
        });
        rejects(&b, "load size 3 is not a machine-word width");
    }

    #[test]
    fn test_validate_rejects_an_unresolvable_expression_read() {
        let b = with_format(DisplayNode::Computed {
            value: ValueExpr::Read(Selector::member(9)),
            decode: ScalarDecode::Raw,
        });
        rejects(&b, "a value-expression read");
    }

    // -------------------------------------------------------------------
    // Variant arms
    // -------------------------------------------------------------------

    #[test]
    fn test_validate_rejects_an_empty_variant_arm() {
        let b = with_format(DisplayNode::Variant {
            discriminant: ValueExpr::Const(0),
            arms: vec![Arm {
                value: 0,
                label: None,
                payload: None,
            }],
            default: None,
        });
        rejects(&b, "has neither a label nor a payload");
    }

    #[test]
    fn test_validate_rejects_a_bad_arm_label_ref() {
        let b = with_format(DisplayNode::Variant {
            discriminant: ValueExpr::Const(0),
            arms: vec![Arm {
                value: 0,
                label: Some(StrRef(999)),
                payload: None,
            }],
            default: None,
        });
        rejects(&b, "label string ref 999 out of range");
    }

    #[test]
    fn test_validate_checks_the_discriminant_expression() {
        let name = a_name();
        let b = with_format(DisplayNode::Variant {
            discriminant: ValueExpr::Var(2),
            arms: vec![Arm::labeled(0, name)],
            default: None,
        });
        rejects(&b, "variable 2 out of range");
    }

    // -------------------------------------------------------------------
    // CustomList programs
    // -------------------------------------------------------------------

    fn custom_list(vars: Vec<ValueExpr>, condition: ValueExpr, body: Vec<Stmt>) -> DisplayNode {
        DisplayNode::CustomList {
            vars,
            condition,
            body,
            element: BundleTypeId(0),
        }
    }

    #[test]
    fn test_validate_rejects_a_seed_referencing_a_variable() {
        // Seeds run before any variable exists, so even the variable a
        // seed itself declares is out of range in one.
        let b = with_format(custom_list(
            vec![ValueExpr::Var(0)],
            ValueExpr::Const(0),
            vec![],
        ));
        rejects(&b, "variable 0 out of range (0 declared)");
    }

    #[test]
    fn test_validate_rejects_a_condition_variable_out_of_range() {
        let b = with_format(custom_list(
            vec![ValueExpr::Const(1)],
            ValueExpr::Var(1),
            vec![],
        ));
        rejects(&b, "variable 1 out of range (1 declared)");
    }

    #[test]
    fn test_validate_rejects_an_assignment_to_an_undeclared_variable() {
        let b = with_format(custom_list(
            vec![ValueExpr::Const(1)],
            ValueExpr::Const(0),
            vec![Stmt::Set {
                var: 5,
                value: ValueExpr::Const(0),
            }],
        ));
        rejects(&b, "assigns out-of-range variable 5 (1 declared)");
    }

    #[test]
    fn test_validate_checks_statements_nested_in_branches() {
        let b = with_format(custom_list(
            vec![ValueExpr::Const(1)],
            ValueExpr::Const(0),
            vec![Stmt::If {
                cond: ValueExpr::Const(1),
                then: vec![Stmt::Break {
                    cond: ValueExpr::Var(9),
                }],
                otherwise: vec![],
            }],
        ));
        rejects(&b, "variable 9 out of range");
    }

    #[test]
    fn test_validate_checks_an_emit_address() {
        let b = with_format(custom_list(
            vec![ValueExpr::Const(1)],
            ValueExpr::Const(0),
            vec![Stmt::Emit {
                at: ValueExpr::Var(8),
            }],
        ));
        rejects(&b, "variable 8 out of range");
    }

    #[test]
    fn test_validate_rejects_a_custom_list_element_out_of_range() {
        let mut node = custom_list(vec![], ValueExpr::Const(0), vec![]);
        match &mut node {
            DisplayNode::CustomList { element, .. } => *element = BundleTypeId(99),
            _ => unreachable!(),
        }
        let b = with_format(node);
        rejects(&b, "CustomList element type id 99 out of range");
    }

    #[test]
    fn test_validate_rejects_an_unsized_custom_list_element() {
        let mut node = custom_list(vec![], ValueExpr::Const(0), vec![]);
        match &mut node {
            DisplayNode::CustomList { element, .. } => *element = OPAQUE,
            _ => unreachable!(),
        }
        let b = with_format(node);
        rejects(&b, "unsized element type");
    }

    // -------------------------------------------------------------------
    // Bytes notations
    // -------------------------------------------------------------------

    fn bytes(member: u32, notation: Notation) -> DisplayNode {
        DisplayNode::Bytes {
            at: Selector::member(member),
            notation,
        }
    }

    #[test]
    fn test_validate_rejects_a_notation_of_the_wrong_length() {
        // A UUID is exactly 16 bytes; an IP address is 4 or 16; hex
        // spells anything but nothing.
        rejects(
            &with_format(bytes(1, Notation::Uuid)),
            "4 bytes is not a length the Uuid notation spells",
        );
        rejects(
            &with_format(bytes(2, Notation::IpAddr)),
            "5 bytes is not a length the IpAddr notation spells",
        );
        rejects(
            &with_format(bytes(4, Notation::Hex)),
            "0 bytes is not a length the Hex notation spells",
        );
    }

    #[test]
    fn test_validate_rejects_a_notation_over_signed_bytes() {
        let b = with_format(bytes(3, Notation::Uuid));
        rejects(&b, "does not target unsigned bytes");
    }

    // -------------------------------------------------------------------
    // DynPointer
    // -------------------------------------------------------------------

    /// [`dyn_bundle`] with a `DynPointer` format on `scope`, built from
    /// the valid one it already carries and then bent.
    fn dyn_format(scope: BundleTypeId, f: impl FnOnce(&mut DisplayNode)) -> Bundle {
        let mut b = dyn_bundle();
        let mut node = b.types.debug_formats[&BundleTypeId(12)].clone();
        f(&mut node);
        b.types.debug_formats.clear();
        b.types.debug_formats.insert(scope, node);
        b
    }

    /// The data side of a wide pointer must target an unsized thing —
    /// the pointee is read at a `tail_offset` past a header, which is
    /// nonsense for a sized type, and the vtable would be read as one
    /// anyway.
    #[test]
    fn test_validate_rejects_a_dyn_pointer_at_a_sized_target() {
        let b = dyn_format(BundleTypeId(8), |_| {});
        rejects(&b, "does not target dyn");
    }

    /// A vtable is an array of machine words. A signed element is not
    /// one — nor is one of the wrong width — and the check has to say
    /// both, since a slot index is scaled by that width.
    #[test]
    fn test_validate_rejects_a_vtable_that_is_not_words() {
        let signed = |b: &mut Bundle| {
            b.types.types[0] = TypeDef::Base {
                name: match b.types.types[0] {
                    TypeDef::Base { name, .. } => name,
                    _ => unreachable!(),
                },
                size: 8,
                encoding: Encoding::Signed,
            };
        };
        let mut b = dyn_format(BundleTypeId(12), |_| {});
        signed(&mut b);
        rejects(&b, "not usize-sized");

        let mut b = dyn_format(BundleTypeId(12), |_| {});
        b.types.types[0] = TypeDef::Base {
            name: match b.types.types[0] {
                TypeDef::Base { name, .. } => name,
                _ => unreachable!(),
            },
            size: 4,
            encoding: Encoding::Unsigned,
        };
        rejects(&b, "not usize-sized");
    }

    /// The three header slots name three different vtable entries. Two
    /// of them being one entry is a detector that filled a field in
    /// twice, and the values it would read are another slot's.
    #[test]
    fn test_validate_rejects_a_dyn_pointer_reusing_a_header_slot() {
        for (drop_at, size_at, align_at) in [(0, 0, 2), (0, 1, 0), (0, 1, 1)] {
            let b = dyn_format(BundleTypeId(12), |node| {
                let DisplayNode::DynPointer {
                    drop_in_place,
                    size,
                    align,
                    ..
                } = node
                else {
                    unreachable!("the fixture format is a dyn pointer")
                };
                *drop_in_place = drop_at;
                *size = size_at;
                *align = align_at;
            });
            rejects(&b, "reuses a header slot");
        }
    }

    /// A slot index is an entry of the vtable it indexes, and the
    /// bound is the array's own count.
    #[test]
    fn test_validate_rejects_a_header_slot_past_the_vtable() {
        let b = dyn_format(BundleTypeId(12), |node| {
            let DisplayNode::DynPointer { align, .. } = node else {
                unreachable!("the fixture format is a dyn pointer")
            };
            *align = 4;
        });
        rejects(&b, "outside its 4-entry vtable");
    }

    /// A wide pointer at a wrapper `depth` levels above the dyn type it
    /// really points at: `ArcInner<Wrapper<…<dyn>>>`, each level's last
    /// member the next one down.
    fn nested_dyn_bundle(depth: usize) -> Bundle {
        let mut b = dyn_bundle();
        let name = match b.types.types[0] {
            TypeDef::Base { name, .. } => name,
            _ => unreachable!("id 0 is usize"),
        };
        let base = b.types.types.len() as u32;
        for level in 0..depth {
            // The last wrapper's tail is the dyn type itself (id 1).
            let tail = match level + 1 == depth {
                true => BundleTypeId(1),
                false => BundleTypeId(base + level as u32 + 1),
            };
            b.types.types.push(TypeDef::Struct {
                name,
                size: 8,
                members: vec![MemberDef {
                    name,
                    ty: tail,
                    offset: 0,
                }],
            });
        }
        let pointer = BundleTypeId(base + depth as u32);
        b.types.types.push(TypeDef::Pointer {
            name: None,
            target: BundleTypeId(base),
        });
        let wide = BundleTypeId(pointer.0 + 1);
        b.types.types.push(TypeDef::Struct {
            name,
            size: 16,
            members: vec![
                MemberDef {
                    name,
                    ty: pointer,
                    offset: 0,
                },
                MemberDef {
                    name,
                    ty: BundleTypeId(4),
                    offset: 8,
                },
            ],
        });
        let node = b.types.debug_formats[&BundleTypeId(12)].clone();
        b.types.debug_formats.clear();
        b.types.debug_formats.insert(wide, node);
        b
    }

    /// The search for a dyn tail is bounded, because the type graph it
    /// walks may be cyclic and a bundle is not to be trusted. So the
    /// bound is part of what a valid dyn pointer is: seven wrappers
    /// deep the tail is found, eight deep the pointer is rejected —
    /// not because the type is wrong, but because the validator will
    /// not look that far to find out.
    #[test]
    fn test_validate_finds_a_dyn_tail_only_within_the_bound() {
        nested_dyn_bundle(7)
            .validate()
            .expect("a tail seven wrappers down is still found");
        rejects(&nested_dyn_bundle(8), "does not target dyn");
    }

    // -------------------------------------------------------------------
    // The B-tree MapEntries
    // -------------------------------------------------------------------

    const LEAF: BundleTypeId = BundleTypeId(2);
    const ROOT_ENUM: BundleTypeId = BundleTypeId(6);
    const EDGES: BundleTypeId = BundleTypeId(7);
    const INTERNAL: BundleTypeId = BundleTypeId(8);
    const MAP_HOLDER: BundleTypeId = BundleTypeId(9);
    const U8: BundleTypeId = BundleTypeId(10);
    const NODE_REF_PTR: BundleTypeId = BundleTypeId(11);

    /// A miniature std `BTreeMap` layout, complete enough to satisfy
    /// every constraint `check_map_entries` states: a root
    /// `Option<NodeRef>`, a `NodeRef { height, node }`, a two-slot leaf,
    /// and an internal node that is the leaf plus an edge array one
    /// wider than its key count.
    fn map_bundle() -> Bundle {
        let mut b = super::tiny_bundle();
        let mut strings = StringInterner::new();
        let names: BTreeMap<&str, StrRef> = [
            "u64",
            "u8",
            "Leaf",
            "NodeRef",
            "Unit",
            "Root",
            "Internal",
            "MapHolder",
            "None",
            "Some",
            "len",
            "keys",
            "vals",
            "height",
            "node",
            "data",
            "edges",
            "root",
            "pad",
            "Mystery",
            "keys3",
            "bytes2",
            "keys0",
            "tail",
        ]
        .iter()
        .map(|n| (*n, strings.intern(n)))
        .collect();
        let n = |name: &str| names[name];
        let member = |name: &str, ty: u32, offset: u64| MemberDef {
            name: n(name),
            ty: BundleTypeId(ty),
            offset,
        };

        let types = vec![
            // 0: u64
            TypeDef::Base {
                name: n("u64"),
                size: 8,
                encoding: Encoding::Unsigned,
            },
            // 1: [u64; 2]
            TypeDef::Array {
                elem: BundleTypeId(0),
                count: 2,
            },
            // 2: Leaf { len, keys: [u64;2], vals: [u64;2], and three
            // arrays that are *not* its key or value storage: a wider
            // one, a narrower-element one, and an empty one, for
            // aiming a slot selector somewhere incompatible.
            TypeDef::Struct {
                name: n("Leaf"),
                size: 72,
                members: vec![
                    member("len", 0, 0),
                    member("keys", 1, 8),
                    member("vals", 1, 24),
                    member("keys3", 13, 40),
                    member("bytes2", 14, 64),
                    member("keys0", 12, 66),
                ],
            },
            // 3: *Leaf
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(2),
            },
            // 4: NodeRef { height, node: *Leaf }
            TypeDef::Struct {
                name: n("NodeRef"),
                size: 16,
                members: vec![member("height", 0, 0), member("node", 3, 8)],
            },
            // 5: Unit (the None payload)
            TypeDef::Struct {
                name: n("Unit"),
                size: 0,
                members: vec![],
            },
            // 6: Root = enum { None(Unit), Some(NodeRef) }, discr @16
            TypeDef::Enum {
                name: n("Root"),
                size: 24,
                shape: VariantShape {
                    discr: Some(DiscrDef {
                        offset: 16,
                        ty: BundleTypeId(0),
                    }),
                    variants: vec![
                        VariantDef {
                            name: n("None"),
                            discr_values: Some(DiscrValues(vec![DiscrValue::Value(0)])),
                            payload: member("None", 5, 0),
                            decl: None,
                            await_site: None,
                        },
                        VariantDef {
                            name: n("Some"),
                            discr_values: Some(DiscrValues(vec![DiscrValue::Value(1)])),
                            payload: member("Some", 4, 0),
                            decl: None,
                            await_site: None,
                        },
                    ],
                },
            },
            // 7: [*Leaf; 3] — one edge more than the two key slots
            TypeDef::Array {
                elem: BundleTypeId(3),
                count: 3,
            },
            // 8: Internal { data: Leaf @0, edges: [*Leaf;3], and a
            // second leaf that is not the prefix — the same type at a
            // different place, which is what tells "is the leaf" from
            // "is the leaf *at offset zero*".
            TypeDef::Struct {
                name: n("Internal"),
                size: 168,
                members: vec![
                    member("data", 2, 0),
                    member("edges", 7, 72),
                    member("tail", 2, 96),
                ],
            },
            // 9: MapHolder { len, root: Root, pad }
            TypeDef::Struct {
                name: n("MapHolder"),
                size: 40,
                members: vec![
                    member("len", 0, 0),
                    member("root", 6, 8),
                    member("pad", 0, 32),
                ],
            },
            // 10: u8 — a key type whose size no slot matches
            TypeDef::Base {
                name: n("u8"),
                size: 1,
                encoding: Encoding::Unsigned,
            },
            // 11: *NodeRef — a pointer to the wrong node type
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(4),
            },
            // 12: [u64; 0] — storage for no slots at all
            TypeDef::Array {
                elem: BundleTypeId(0),
                count: 0,
            },
            // 13: [u64; 3] — one slot more than the leaf really has
            TypeDef::Array {
                elem: BundleTypeId(0),
                count: 3,
            },
            // 14: [u8; 2] — the right count, the wrong element
            TypeDef::Array {
                elem: BundleTypeId(10),
                count: 2,
            },
        ];

        b.strings = strings.finish();
        b.types = TypeTable {
            types,
            debug_formats: BTreeMap::from([(MAP_HOLDER, map_node())]),
            name_index: vec![],
            ..Default::default()
        };
        b
    }

    fn map_node() -> DisplayNode {
        DisplayNode::Map {
            length: Selector::member(0),
            key: BundleTypeId(0),
            value: BundleTypeId(0),
            entries: Box::new(MapEntries::BTree {
                root: Selector::member(1),
                // The Some payload *is* the node reference, and an edge
                // element *is* the pointer: both auxiliary roots take
                // the empty path the validator deliberately admits.
                root_node: Selector::default(),
                height: Selector::member(0),
                node: Selector::member(1),
                leaf: LEAF,
                leaf_len: Selector::member(0),
                leaf_keys: Selector::member(1),
                leaf_values: Selector::member(2),
                internal: INTERNAL,
                internal_data: Selector::member(0),
                internal_edges: Selector::member(1),
                edge: Selector::default(),
            }),
        }
    }

    /// The map fixture with one `MapEntries` field rewritten.
    fn broken_map(f: impl FnOnce(&mut MapEntries)) -> Bundle {
        let mut b = map_bundle();
        let mut node = map_node();
        match &mut node {
            DisplayNode::Map { entries, .. } => f(entries),
            _ => unreachable!(),
        }
        b.types.debug_formats.insert(MAP_HOLDER, node);
        b
    }

    /// The baseline is genuinely valid, so each rejection below fails
    /// for the corruption it plants and not for a broken fixture.
    #[test]
    fn test_validate_accepts_a_btree_map() {
        assert!(map_bundle().validate().is_ok());
    }

    /// Keys and values are read slot for slot, so their storage has to
    /// agree: as many slots on each side, and at least one. Storage for
    /// nothing is not a B-tree leaf — a walk of it reads no entries and
    /// reports a map that is empty however full it is.
    #[test]
    fn test_validate_rejects_leaf_storage_for_no_slots() {
        let b = broken_map(|e| {
            let MapEntries::BTree {
                leaf_keys,
                leaf_values,
                ..
            } = e;
            // Both sides at the empty array: the counts still agree, so
            // only their being zero is wrong.
            *leaf_keys = Selector::member(5);
            *leaf_values = Selector::member(5);
        });
        rejects(&b, "incompatible key/value slots");
    }

    /// And where they disagree, the pairing is nonsense whichever count
    /// a walk believes.
    #[test]
    fn test_validate_rejects_leaf_storage_of_unequal_slots() {
        let b = broken_map(|e| {
            let MapEntries::BTree { leaf_values, .. } = e;
            *leaf_values = Selector::member(3);
        });
        rejects(&b, "incompatible key/value slots");
    }

    /// An internal node is a leaf *plus* edges, which is what lets one
    /// walk read both: the leaf part has to be its prefix, not merely
    /// some member of the same type. A selector naming a second leaf
    /// further in resolves to the right type at the wrong place, and
    /// every key read through it is another node's.
    #[test]
    fn test_validate_rejects_internal_data_at_a_nonzero_offset() {
        let b = broken_map(|e| {
            let MapEntries::BTree { internal_data, .. } = e;
            *internal_data = Selector::member(2);
        });
        rejects(&b, "internal data is not its leaf prefix");
    }

    #[test]
    fn test_validate_rejects_a_root_reused_as_length() {
        let b = broken_map(|e| {
            let MapEntries::BTree { root, .. } = e;
            *root = Selector::member(0);
        });
        rejects(&b, "reuses root as length");
    }

    #[test]
    fn test_validate_rejects_a_non_enum_root() {
        let b = broken_map(|e| {
            let MapEntries::BTree { root, .. } = e;
            *root = Selector::member(2);
        });
        rejects(&b, "B-tree root is not an enum");
    }

    #[test]
    fn test_validate_rejects_a_root_without_some() {
        let mut b = map_bundle();
        let TypeDef::Enum { shape, .. } = &mut b.types.types[ROOT_ENUM.0 as usize] else {
            unreachable!();
        };
        shape.variants[1].name = shape.variants[0].name;
        rejects(&b, "B-tree root has no Some variant");
    }

    #[test]
    fn test_validate_rejects_a_non_integer_height() {
        let b = broken_map(|e| {
            let MapEntries::BTree { height, .. } = e;
            *height = Selector::member(1);
        });
        rejects(&b, "height is not an unsigned integer");
    }

    #[test]
    fn test_validate_rejects_a_node_pointer_to_the_wrong_type() {
        let b = broken_map(|e| {
            let MapEntries::BTree { leaf, .. } = e;
            *leaf = INTERNAL;
        });
        rejects(&b, "node selector does not point to its leaf type");
    }

    #[test]
    fn test_validate_rejects_a_non_integer_leaf_length() {
        let b = broken_map(|e| {
            let MapEntries::BTree { leaf_len, .. } = e;
            *leaf_len = Selector::member(1);
        });
        rejects(&b, "leaf length is not an unsigned integer");
    }

    #[test]
    fn test_validate_rejects_mismatched_key_and_value_slots() {
        let mut b = map_bundle();
        let mut node = map_node();
        match &mut node {
            DisplayNode::Map { key, .. } => *key = U8,
            _ => unreachable!(),
        }
        b.types.debug_formats.insert(MAP_HOLDER, node);
        rejects(&b, "incompatible key/value slots");
    }

    #[test]
    fn test_validate_rejects_internal_data_that_is_not_the_leaf_prefix() {
        let b = broken_map(|e| {
            let MapEntries::BTree { internal_data, .. } = e;
            *internal_data = Selector::member(1);
        });
        rejects(&b, "internal data is not its leaf prefix");
    }

    #[test]
    fn test_validate_rejects_the_wrong_edge_capacity() {
        let mut b = map_bundle();
        let TypeDef::Array { count, .. } = &mut b.types.types[EDGES.0 as usize] else {
            unreachable!();
        };
        *count = 2;
        rejects(&b, "wrong edge capacity");
    }

    #[test]
    fn test_validate_rejects_an_edge_to_the_wrong_type() {
        let mut b = map_bundle();
        let TypeDef::Array { elem, .. } = &mut b.types.types[EDGES.0 as usize] else {
            unreachable!();
        };
        *elem = NODE_REF_PTR;
        rejects(&b, "edge does not point to its leaf type");
    }

    #[test]
    fn test_validate_rejects_a_map_type_out_of_range() {
        let mut b = map_bundle();
        let mut node = map_node();
        match &mut node {
            DisplayNode::Map { value, .. } => *value = BundleTypeId(99),
            _ => unreachable!(),
        }
        b.types.debug_formats.insert(MAP_HOLDER, node);
        rejects(&b, "map value type id 99 out of range");
    }
}

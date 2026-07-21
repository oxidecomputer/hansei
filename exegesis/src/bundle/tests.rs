use crate::bundle::io::FORMAT_VERSION;
use crate::bundle::schema::*;
use crate::bundle::strings::{StrRef, StringInterner};
use crate::bundle::{Error, MAGIC};
use crate::raw_types::Encoding;

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
    Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.finish(),
        types: TypeTable {
            types: vec![TypeDef::Base {
                name,
                size: 8,
                encoding: Encoding::Unsigned,
            }],
            debug_formats: BTreeMap::new(),
            name_index: vec![(name, ty)],
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        infra: InfraTypes {
            header: ty,
            vtable: ty,
            trailer: ty,
            context: ty,
            scheduler_handle: ty,
            mt_handle: ty,
            location: ty,
            raw_waker_vtable: ty,
        },
        provenance: ProvenanceTable::default(),
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

    Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            rustc_version: "rustc 1.97.0 (2d8144b78 2026-07-07)".into(),
            tokio_version: Some(semver::Version::new(1, 52, 3)),
            debug_binary: BinaryIdent {
                basename: "futurelock".into(),
                build_id: Some(vec![0xab; 20]),
                blake3: [0x5a; 32],
            },
            extract_args: "exegesis extract futurelock -o fl.bundle".into(),
            symbol_fingerprint: (0..rng.below(20)).map(|i| format!("_RINv_fp{i}")).collect(),
        },
        strings: table,
        types: TypeTable {
            types,
            debug_formats: BTreeMap::new(),
            name_index,
        },
        tasks: TaskTable {
            by_symbol,
            by_normalized_symbol: BTreeMap::new(),
            entries,
        },
        dyn_futures,
        statics,
        infra: InfraTypes {
            header: any_ty(&mut rng),
            vtable: any_ty(&mut rng),
            trailer: any_ty(&mut rng),
            context: any_ty(&mut rng),
            scheduler_handle: any_ty(&mut rng),
            mt_handle: any_ty(&mut rng),
            location: any_ty(&mut rng),
            raw_waker_vtable: any_ty(&mut rng),
        },
        provenance,
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
    let bytes = encode(&random_bundle(3));
    let cut = 12 + (bytes.len() - 12) / 2;
    assert!(matches!(
        Bundle::read_from(&bytes[..cut]),
        Err(Error::Io(_))
    ));
}

#[test]
fn test_corrupt_zstd_frame_rejected() {
    let mut bytes = encode(&tiny_bundle());
    // clobber the zstd frame header, right after our 12-byte header
    bytes[12] ^= 0xff;
    bytes[13] ^= 0xff;
    assert!(matches!(
        Bundle::read_from(bytes.as_slice()),
        Err(Error::Io(_))
    ));
}

#[test]
fn test_payload_not_a_bundle_rejected() {
    // valid framing + valid zstd, but the payload isn't a Bundle
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    zstd::stream::copy_encode(&b"not a bundle"[..], &mut bytes, 0).unwrap();
    assert!(matches!(
        Bundle::read_from(bytes.as_slice()),
        Err(Error::Decode(_))
    ));
}

#[test]
fn test_validate_rejects_oob_type_id() {
    let mut b = tiny_bundle();
    b.infra.header = BundleTypeId(999);
    // write_to skips validation on purpose; the reader must catch it
    assert!(matches!(
        Bundle::read_from(encode(&b).as_slice()),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn test_validate_rejects_oob_str_ref() {
    let mut b = tiny_bundle();
    b.types.types[0] = TypeDef::Base {
        name: StrRef(42),
        size: 8,
        encoding: Encoding::Unsigned,
    };
    assert!(matches!(
        Bundle::read_from(encode(&b).as_slice()),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn test_validate_rejects_bad_debug_format_path() {
    let mut b = tiny_bundle();
    b.types.debug_formats.insert(
        BundleTypeId(0),
        DebugFormat::Transparent {
            member: Selector::member(0),
        },
    );
    assert!(matches!(b.validate(), Err(Error::Corrupt(_))));
}

/// A selector may cross a pointer with a `Deref` step; the validator resolves
/// through it to the pointee. (Phase A emits no such selector yet, but the
/// validator handles them — this guards that path.)
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
                DebugFormat::Transparent {
                    member: Selector(vec![Step::Member(0), Step::Deref, Step::Member(0)]),
                },
            )]),
            name_index: vec![],
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        infra: InfraTypes {
            header: ty,
            vtable: ty,
            trailer: ty,
            context: ty,
            scheduler_handle: ty,
            mt_handle: ty,
            location: ty,
            raw_waker_vtable: ty,
        },
        provenance: ProvenanceTable::default(),
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
        DebugFormat::Transparent {
            member: Selector(vec![Step::Deref]),
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
        DebugFormat::Node(DisplayNode::Symbol {
            at: Selector::default(),
        }),
    );
    assert!(matches!(b.validate(), Err(Error::Corrupt(_))));
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

#[test]
fn test_validate_rejects_unsorted_name_index() {
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
    assert!(matches!(b.validate(), Err(Error::Corrupt(_))));
}

#[test]
fn test_save_validates() {
    let mut b = tiny_bundle();
    b.infra.header = BundleTypeId(999);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.bundle");
    assert!(matches!(b.save(&path), Err(Error::Corrupt(_))));
    assert!(!path.exists());
}

#[test]
fn test_save_load_file() {
    let b = random_bundle(11);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.bundle");
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
    // §11.1: joins are exact-match on mangled input, with .llvm stripping;
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
// BundleType view + variant decoding (§8, §11.1)
// ---------------------------------------------------------------------------

mod view_tests {
    use crate::bundle::schema::*;
    use crate::bundle::strings::StringInterner;
    use crate::bundle::view::{BundleView, VariantError};
    use crate::raw_types::Encoding;

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
        };
        b.infra = InfraTypes {
            header: BundleTypeId(0),
            vtable: BundleTypeId(0),
            trailer: BundleTypeId(0),
            context: BundleTypeId(0),
            scheduler_handle: BundleTypeId(0),
            mt_handle: BundleTypeId(0),
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

    /// A coroutine-shaped enum, as rustc 1.97 emits it (§5.5): variant
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
                            },
                        ],
                    },
                },
            ],
            debug_formats: std::collections::BTreeMap::new(),
            name_index: vec![],
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
    fn dyn_bundle() -> Bundle {
        let mut b = super::tiny_bundle();
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
                DebugFormat::Node(DisplayNode::DynPointer {
                    pointer: Selector::member(0),
                    vtable: Selector::member(1),
                    drop_in_place: 0,
                    size: 1,
                    align: 2,
                    tail_offset: 0,
                }),
            )]),
            name_index: vec![],
        };
        b.strings = strings.finish();
        b.validate().expect("test bundle must validate");
        b
    }

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
            ],
            debug_formats: std::collections::BTreeMap::new(),
            name_index: vec![(point, BundleTypeId(1)), (u32n, BundleTypeId(0))],
        };
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
        assert_eq!(p.size(), crate::bundle::view::POINTER_SIZE);
        assert_eq!(p.pointer_target().unwrap().name(), "Point");

        let a = view.ty(BundleTypeId(3)).unwrap();
        let (elem, count) = a.array_info().unwrap();
        assert_eq!(elem.name(), "u32");
        assert_eq!(count, 3);
        assert_eq!(a.size(), 12);
    }
}

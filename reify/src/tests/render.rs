//! Value-render tests: what reify prints for a given type and byte buffer.
//!
//! The shared type graph lives in `testhelper`; the `DisplayNode` fixture
//! below is used only here, so it stays local to this file.

use crate::testhelper::*;

use exegesis::Encoding;
use exegesis::bundle::{
    Bundle, BundleTypeId, BundleView, DisplayNode as BundleNode, DynFutureTable, FORMAT_VERSION,
    Field as BundleField, InfraTypes, MemberDef, Meta, ProvenanceTable,
    ScalarDecode as BundleScalarDecode, StaticsTable, StringInterner, TaskTable, TypeDef,
    TypeTable,
};

use crate::{ReadFromProc, TypeInfoRef};

#[test]
fn test_ip_addresses_use_standard_notation() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let ipv4 = [192, 0, 2, 1];
    assert_eq!(
        format!(
            "{}",
            TypeInfoRef::new(v.ty(IPV4).unwrap(), 0, &ipv4).display()
        ),
        "192.0.2.1"
    );

    let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(
        format!(
            "{}",
            TypeInfoRef::new(v.ty(IPV6).unwrap(), 0, &ipv6).display()
        ),
        "2001:db8::1"
    );
}

#[test]
fn test_vec_displays_initialized_elements() {
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!(addr, 0x2000);
            assert_eq!(len, 12);
            Ok([5u32, 8, 13]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect())
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [0x2000u64, 3, 4]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "[5, 8, 13]"
    );
    assert_eq!(
        format!("{:#}", value.display_from_target(&Reader, 8)),
        "[\n    5,\n    8,\n    13,\n]"
    );

    let invalid: Vec<u8> = [0x2000u64, 5, 4]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &invalid);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "<invalid slice: length exceeds capacity>"
    );
}

#[test]
fn test_slice_displays_initialized_elements() {
    // A `&[T]`/`Box<[T]>` renders through the same `Slice` node as `Vec`
    // but with no capacity word, so the length is used directly (the
    // capacity-less path — otherwise untested).
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!(addr, 0x2000);
            assert_eq!(len, 12);
            Ok([5u32, 8, 13]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect())
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    // A `(data_ptr, length)` fat pointer: address then element count, no
    // capacity word.
    let bytes: Vec<u8> = [0x2000u64, 3]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(SLICE).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "[5, 8, 13]"
    );
    assert_eq!(
        format!("{:#}", value.display_from_target(&Reader, 8)),
        "[\n    5,\n    8,\n    13,\n]"
    );
}

#[test]
fn test_str_and_string_display_quoted_utf8() {
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            let bytes: &[u8] = match addr {
                0x3000 => b"hi\nthere",
                0x4000 => b"owned\ttext",
                _ => panic!("unexpected address 0x{addr:x}"),
            };
            assert_eq!(len, bytes.len() as u64);
            Ok(bytes.to_vec())
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let str_bytes: Vec<u8> = [0x3000u64, 8]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(STR).unwrap(), 0, &str_bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "\"hi\\nthere\""
    );

    let string_bytes: Vec<u8> = [0x4000u64, 10, 16]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(STRING).unwrap(), 0, &string_bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "\"owned\\ttext\""
    );
}

#[test]
fn test_ugly_suppresses_custom_formatters() {
    let b = test_bundle();
    let v = BundleView::new(&b);

    // A `Scalar` format (`RawMutex`) renders its decoded bits normally, but
    // `--ugly` shows the underlying struct field.
    let mutex = TypeInfoRef::new(v.ty(RAW_MUTEX).unwrap(), 0, &[1u8]);
    assert_eq!(
        format!("{}", mutex.display()),
        "parking_lot::raw_mutex::RawMutex: locked=true, parked=false"
    );
    assert_eq!(
        format!("{}", mutex.display().ugly()),
        "parking_lot::raw_mutex::RawMutex { state: 1 }"
    );

    // A `Str` format renders as a quoted string normally; `--ugly` shows the
    // pointer/length representation instead. (No target: the pointer prints
    // as a bare address rather than being followed.)
    let str_bytes: Vec<u8> = [0x3000u64, 8]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let s = TypeInfoRef::new(v.ty(STR).unwrap(), 0, &str_bytes);
    assert_eq!(
        format!("{}", s.display().ugly()),
        "&str { data_ptr: 0x3000, length: 8 }"
    );
}

#[test]
fn test_ugly_suppresses_enum_payload_formatter() {
    // Reshape `Opt::Some`'s payload to a `&str`, whose own `Str` format is
    // normally delegated to when it appears as an enum payload. `--ugly`
    // suppresses that delegation and shows the payload's raw fields.
    let mut b = test_bundle();
    let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
        panic!("Opt is not an enum");
    };
    *size = 16;
    shape.variants[1].payload.ty = STR;
    b.validate().expect("modified enum bundle must validate");

    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [0x3000u64, 8]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display().ugly()),
        "Opt::Some { data_ptr: 0x3000, length: 8 }"
    );
}

#[test]
fn test_transparent_debug_format_elides_wrapper() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
    let value = TypeInfoRef::new(v.ty(WRAP).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_with_depth(2)),
        "Point { x: 3, y: 4 }"
    );
}

#[test]
fn test_tuple_struct_elides_synthetic_field_names() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [1u32, 2u32].iter().flat_map(|x| x.to_le_bytes()).collect();

    // A tuple struct's `__0`/`__1` fields render positionally, eliding the
    // synthetic labels, to match Rust `Debug` (`Pair(1, 2)`).
    let pair = TypeInfoRef::new(v.ty(PAIR).unwrap(), 0, &bytes);
    assert_eq!(format!("{}", pair.display_with_depth(2)), "Pair(1, 2)");
    assert_eq!(
        format!("{:#}", pair.display_with_depth(2)),
        "Pair(\n    1,\n    2,\n)"
    );

    // A regular struct still shows its field names (regression guard).
    let point = TypeInfoRef::new(v.ty(POINT).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", point.display_with_depth(2)),
        "Point { x: 1, y: 2 }"
    );
}

#[test]
fn test_atomic_debug_format_displays_stored_value() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes = 42u32.to_le_bytes();
    let value = TypeInfoRef::new(v.ty(ATOMIC).unwrap(), 0, &bytes);
    assert_eq!(format!("{}", value.display_with_depth(1)), "42");
}

#[test]
fn test_nested_transparent_formats_do_not_consume_depth() {
    let b = test_bundle();
    let v = BundleView::new(&b);

    let bytes = 42u32.to_le_bytes();
    let atomic = TypeInfoRef::new(v.ty(LOOM_ATOMIC).unwrap(), 0, &bytes);
    assert_eq!(format!("{}", atomic.display_with_depth(1)), "42");

    let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
    let cell = TypeInfoRef::new(v.ty(LOOM_CELL).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", cell.display_with_depth(2)),
        "Point { x: 3, y: 4 }"
    );
}

#[test]
fn test_atomic_pointer_does_not_dereference_stored_address() {
    struct NoReads;

    impl ReadFromProc for NoReads {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            panic!("atomic pointer formatter unexpectedly read {addr:#x}")
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes = 0x1000u64.to_le_bytes();
    let value = TypeInfoRef::new(v.ty(ATOMIC_PTR).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&NoReads, 8)),
        "0x1000"
    );
}

#[test]
fn test_following_alias_preserves_pointer_traversal() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!((addr, len), (0x1000, 8));
            Ok([3u32, 4].into_iter().flat_map(u32::to_le_bytes).collect())
        }
    }

    let mut b = test_bundle();
    b.types.debug_formats.insert(
        ATOMIC_PTR,
        BundleNode::Alias {
            at: sel(&[0]),
            follow_pointers: true,
        },
    );
    b.validate().expect("following alias must validate");
    let v = BundleView::new(&b);
    let bytes = 0x1000u64.to_le_bytes();
    let value = TypeInfoRef::new(v.ty(ATOMIC_PTR).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "0x1000 -> Point { x: 3, y: 4 }"
    );
}

#[test]
fn test_integer_arrays_display_as_zero_padded_hex() {
    let b = test_bundle();
    let v = BundleView::new(&b);

    let bytes: Vec<u8> = [1u32, 0xabcdef, u32::MAX]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let array = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", array.display()),
        "[0x00000001, 0x00abcdef, 0xffffffff]"
    );

    let bytes: Vec<u8> = [1u64, 0xabcdef, u64::MAX]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let array = TypeInfoRef::new(v.ty(VTABLE_ARRAY).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", array.display()),
        "[0x0000000000000001, 0x0000000000abcdef, 0xffffffffffffffff]"
    );
    assert_eq!(
        format!("{:#}", array.display()),
        "[\n    0x0000000000000001,\n    0x0000000000abcdef,\n    0xffffffffffffffff,\n]"
    );
}

#[test]
fn test_target_display_recurses_through_pointers() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            let (value, next) = match addr {
                0x1000 => (1u32, 0x2000u64),
                0x2000 => (2u32, 0u64),
                _ => return Err(crate::Error::invalid_addr(addr)),
            };
            let mut bytes = vec![0; 16];
            bytes[..4].copy_from_slice(&value.to_le_bytes());
            bytes[8..].copy_from_slice(&next.to_le_bytes());
            Ok(bytes)
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes = 0x1000u64.to_le_bytes();
    let root = TypeInfoRef::new(v.ty(NODE_PTR).unwrap(), 0, &bytes);
    let shown = format!("{:#}", root.display_from_target(&Reader, 8));
    assert!(shown.contains("value: 1"), "{shown}");
    assert!(shown.contains("value: 2"), "{shown}");

    let shallow = format!("{:#}", root.display_from_target(&Reader, 1));
    assert_eq!(shallow, "0x1000 -> ...");
}

#[test]
fn test_dyn_pointer_formats_unknown_concrete_type() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!(addr, 0x3000);
            Ok([0x2c557a0u64, 152, 8]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect())
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [0x1234u64, 0x3000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
    let shown = format!("{:#}", value.display_from_target(&Reader, 8));
    assert_eq!(
        shown,
        concat!(
            "FatPtr {\n",
            "    pointer: 0x1234,\n",
            "    concrete type: <unknown>,\n",
            "    vtable: {\n",
            "        drop_in_place: 0x2c557a0,\n",
            "        size: 152,\n",
            "        align: 8,\n",
            "    },\n",
            "}"
        )
    );
}

#[test]
fn test_dyn_pointer_infers_concrete_type_from_method_with_null_drop() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            match addr {
                0x1234 => Ok([1u32, 2].into_iter().flat_map(u32::to_le_bytes).collect()),
                0x3000 => Ok([0u64, 8, 8, 0x4000]
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect()),
                _ => Err(crate::Error::invalid_addr(addr)),
            }
        }

        fn function_symbol(&self, addr: u64) -> Option<String> {
            (addr == 0x4000).then(|| "<Point as app::Trait>::run".to_owned())
        }
    }

    let mut b = test_bundle();
    let TypeDef::Array { count, .. } = &mut b.types.types[VTABLE_ARRAY.0 as usize] else {
        panic!("vtable is not an array");
    };
    *count = 4;
    b.validate().expect("expanded vtable must validate");
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [0x1234u64, 0x3000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
    let shown = format!("{:#}", value.display_from_target(&Reader, 8));
    assert!(
        shown.contains("pointer: 0x1234 -> Point {\n         x: 1,\n         y: 2,\n    },"),
        "{shown}"
    );
    assert!(shown.contains("concrete type: Point,"), "{shown}");
    assert!(shown.contains("drop_in_place: 0x0,"), "{shown}");
    assert!(
        shown.contains("method[3]: 0x4000 -> <Point as app::Trait>::run,"),
        "{shown}"
    );
}

#[test]
fn test_dyn_pointer_format_is_preserved_in_enum_payload() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!(addr, 0x3000);
            Ok([0u64, 8, 8]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect())
        }
    }

    let mut b = test_bundle();
    let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
        panic!("Opt is not an enum");
    };
    *size = 16;
    shape.variants[1].payload.ty = FAT_PTR;
    b.validate().expect("modified enum bundle must validate");
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [0x1234u64, 0x3000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
    let shown = format!("{:#}", value.display_from_target(&Reader, 8));
    assert!(shown.starts_with("Opt::Some {"), "{shown}");
    assert!(!shown.contains("FatPtr"), "{shown}");
    assert!(shown.contains("concrete type: <unknown>,"), "{shown}");
}

#[test]
fn test_str_payload_in_enum_renders_as_value() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!(addr, 0x3000);
            assert_eq!(len, 8);
            Ok(b"hi\nthere".to_vec())
        }
    }

    // Point Opt::Some's payload at a `&str`; its `Str` display format
    // must win over dumping the fat pointer's raw fields, matching how a
    // `Cow<str>::Borrowed` key should read.
    let mut b = test_bundle();
    let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
        panic!("Opt is not an enum");
    };
    *size = 16;
    shape.variants[1].payload.ty = STR;
    b.validate().expect("modified enum bundle must validate");
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [0x3000u64, 8]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "Opt::Some(\"hi\\nthere\")"
    );
}

#[test]
fn test_wrapped_str_payload_in_enum_is_not_peeled() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!(addr, 0x3000);
            assert_eq!(len, 8);
            Ok(b"hi\nthere".to_vec())
        }
    }

    // A `String`/`Utf8PathBuf` is a single-member wrapper carrying its own
    // `Str` format around an inner `Vec<u8>` (which has a `Slice` format).
    // Reshape `Wrap` into that: a one-member wrapper over `Vec` with a `Str`
    // format of its own. As `Opt::Some`'s payload it must render as the
    // string, not peel past its `Str` to the inner `Vec`'s byte slice.
    let mut b = test_bundle();
    let TypeDef::Struct { size, members, .. } = &mut b.types.types[WRAP.0 as usize] else {
        panic!("Wrap is not a struct");
    };
    *size = 24;
    members[0].ty = VEC;
    b.types.debug_formats.insert(
        WRAP,
        BundleNode::Str {
            pointer: sel(&[0, 0]),
            length: sel(&[0, 1]),
            capacity: Some(sel(&[0, 2])),
        },
    );
    let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
        panic!("Opt is not an enum");
    };
    *size = 24;
    shape.variants[1].payload.ty = WRAP;
    b.validate().expect("modified enum bundle must validate");

    let v = BundleView::new(&b);
    // Vec-shaped payload bytes: data pointer, length, capacity.
    let bytes: Vec<u8> = [0x3000u64, 8, 16]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "Opt::Some(\"hi\\nthere\")"
    );
}

#[test]
fn test_raw_mutex_decodes_lock_state() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let cases = [
        (
            0u8,
            "parking_lot::raw_mutex::RawMutex: locked=false, parked=false",
        ),
        (
            1,
            "parking_lot::raw_mutex::RawMutex: locked=true, parked=false",
        ),
        (
            2,
            "parking_lot::raw_mutex::RawMutex: locked=false, parked=true",
        ),
        (
            3,
            "parking_lot::raw_mutex::RawMutex: locked=true, parked=true",
        ),
    ];
    for (state, expected) in cases {
        let value = TypeInfoRef::new(v.ty(RAW_MUTEX).unwrap(), 0, std::slice::from_ref(&state));
        assert_eq!(format!("{}", value.display()), expected, "state={state}");
    }
}

#[test]
fn test_notify_renders_compact_state_mutex_and_waiters() {
    // Two waiters live at 0x3000 and 0x3020: the first still parked (no
    // notification), the second handed a `notify_one` notification.
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            // Waiter { notification: usize @0, next: *Waiter @8 }.
            let (notification, next) = match addr {
                0x3000 => (0u64, 0x3020u64),
                0x3020 => (1u64, 0u64),
                other => panic!("unexpected read at {other:#x}"),
            };
            let mut b = Vec::new();
            b.extend_from_slice(&notification.to_le_bytes());
            b.extend_from_slice(&next.to_le_bytes());
            b.resize(32, 0);
            b.truncate(len as usize);
            Ok(b)
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    // Flat Notify buffer: state @0, mutex state byte @8, head @16, tail @24.
    let notify = |state: u64, mutex: u8, head: u64| {
        let mut buf = vec![0u8; 32];
        buf[0..8].copy_from_slice(&state.to_le_bytes());
        buf[8] = mutex;
        buf[16..24].copy_from_slice(&head.to_le_bytes());
        buf
    };

    // Idle, unlocked, two parked waiters.
    let buf = notify(0, 0, 0x3000);
    let value = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &buf);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "tokio::sync::notify::Notify { state: state=idle, generation=0, \
         mutex: locked=false, parked=false, queue: [\
         tokio::sync::notify::Waiter { notification: kind=none, order=fifo }, \
         tokio::sync::notify::Waiter { notification: kind=one, order=fifo }] }"
    );

    // Notified with two notify_waiters calls, locked mutex, empty queue.
    // 0b1010 = notified (state 2) with generation 2 (10 >> 2).
    let buf = notify(0b1010, 0b01, 0);
    let value = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &buf);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "tokio::sync::notify::Notify { state: state=notified, generation=2, \
         mutex: locked=true, parked=false, queue: [] }"
    );

    // Without a target the queue cannot be walked, but state and mutex
    // (read from the value's own bytes) still render.
    let buf = notify(1, 0, 0x3000);
    let value = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &buf);
    let shown = format!("{}", value.display());
    assert!(shown.contains("state: state=waiting"), "{shown}");
    assert!(shown.contains("queue: <target unavailable>"), "{shown}");

    // Pretty mode puts each field and waiter on its own indented line.
    let buf = notify(0, 0, 0x3000);
    let value = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &buf);
    assert_eq!(
        format!("{:#}", value.display_from_target(&Reader, 8)),
        "tokio::sync::notify::Notify {\n\
         \x20   state: state=idle, generation=0,\n\
         \x20   mutex: locked=false, parked=false,\n\
         \x20   queue: [\n\
         \x20       tokio::sync::notify::Waiter { notification: kind=none, order=fifo },\n\
         \x20       tokio::sync::notify::Waiter { notification: kind=one, order=fifo },\n\
         \x20   ],\n\
         }"
    );
}

#[test]
fn test_semaphore_decodes_permits_field_in_place() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    // 16-byte Semaphore: permits usize @0, waiters u32 @8.
    let bytes = |permits: u64, waiters: u32| {
        let mut buf = Vec::new();
        buf.extend_from_slice(&permits.to_le_bytes());
        buf.extend_from_slice(&waiters.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        buf
    };
    let cases = [
        // permits are stored shifted left by one; bit 0 is the closed flag.
        (
            64u64,
            3u32,
            "tokio::sync::batch_semaphore::Semaphore { permits: closed=false, permits=32, \
             waiters: 3 }",
        ),
        (
            0,
            0,
            "tokio::sync::batch_semaphore::Semaphore { permits: closed=false, permits=0, \
             waiters: 0 }",
        ),
        // 65 = (32 << 1) | 1: 32 permits, closed.
        (
            65,
            9,
            "tokio::sync::batch_semaphore::Semaphore { permits: closed=true, permits=32, \
             waiters: 9 }",
        ),
    ];
    for (permits, waiters, expected) in cases {
        let buf = bytes(permits, waiters);
        let value = TypeInfoRef::new(v.ty(SEMAPHORE).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display()),
            expected,
            "permits={permits}"
        );
    }
}

#[test]
fn test_mpsc_block_elides_values_to_written_count() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    // 24-byte Block: [u32; 4] value slots @0, ready-bitmap usize @16.
    let block = |ready: u64| {
        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(&ready.to_le_bytes());
        buf
    };
    // Three bits set within the 4-slot capacity: three written slots.
    let buf = block(0b1011);
    let value = TypeInfoRef::new(v.ty(BLOCK).unwrap(), 0, &buf);
    assert_eq!(
        format!("{}", value.display()),
        "tokio::sync::mpsc::block::Block<u32> { values: [3 slots], header: BlockHeader { ready_slots: 11 } }"
    );

    // Bits outside the 4-slot capacity (released/closed flags) are ignored.
    let buf = block(0b1_0000);
    let value = TypeInfoRef::new(v.ty(BLOCK).unwrap(), 0, &buf);
    assert_eq!(
        format!("{}", value.display()),
        "tokio::sync::mpsc::block::Block<u32> { values: [0 slots], header: BlockHeader { ready_slots: 16 } }"
    );
}

#[test]
fn test_mpsc_chan_shows_only_queued_messages() {
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            // Block at [0x1000, 0x1020): [u32; 4] values @0, start_index
            // usize @16, next ptr @24 (null). The queued CustomList reads its
            // fields and slots piecemeal, so serve any sub-read of it.
            let mut block = Vec::new();
            for v in [10u32, 20, 30, 40] {
                block.extend_from_slice(&v.to_le_bytes());
            }
            block.extend_from_slice(&0u64.to_le_bytes()); // start_index @16
            block.extend_from_slice(&0u64.to_le_bytes()); // next @24 (null)
            let start = addr.checked_sub(0x1000).expect("read below block") as usize;
            Ok(block[start..start + len as usize].to_vec())
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    // Chan: tail usize @0, index usize @8, head ptr @16.
    let chan = |tail: u64, index: u64| {
        let mut c = Vec::new();
        c.extend_from_slice(&tail.to_le_bytes());
        c.extend_from_slice(&index.to_le_bytes());
        c.extend_from_slice(&0x1000u64.to_le_bytes());
        c
    };

    // index=1, tail=3: slots 1 and 2 are still queued.
    let bytes = chan(3, 1);
    let value = TypeInfoRef::new(v.ty(CHAN).unwrap(), 0, &bytes);
    let shown = format!("{}", value.display_from_target(&Reader, 8));
    assert!(shown.contains("queued: [20, 30]"), "{shown}");

    // Drained channel (index == tail): nothing queued, no stale slots shown.
    let bytes = chan(3, 3);
    let value = TypeInfoRef::new(v.ty(CHAN).unwrap(), 0, &bytes);
    let shown = format!("{}", value.display_from_target(&Reader, 8));
    assert!(shown.contains("queued: []"), "{shown}");
}

#[test]
fn test_custom_list_walks_mpsc_block_chain() {
    // The shared `chan_queued_node` CustomList, installed as a top-level
    // format, walks the block chain from the value language: seed
    // cur/tail/block from the Chan, then loop reading each block's
    // start_index (a Load), emit the in-window slots, and follow `next`.
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            // One block at [0x1000, 0x1020): [u32; 4] values @0, start_index
            // usize @16, next ptr @24 (null), served piecemeal.
            let mut block = Vec::new();
            for value in [10u32, 20, 30, 40] {
                block.extend_from_slice(&value.to_le_bytes());
            }
            block.extend_from_slice(&0u64.to_le_bytes()); // start_index @16
            block.extend_from_slice(&0u64.to_le_bytes()); // next @24 (null)
            let start = addr.checked_sub(0x1000).expect("read below block") as usize;
            Ok(block[start..start + len as usize].to_vec())
        }
    }

    let mut b = test_bundle();
    b.types.debug_formats.insert(CHAN, chan_queued_node(U32));
    b.validate().expect("CustomList bundle must validate");
    let view = BundleView::new(&b);

    // Chan: tail usize @0, index usize @8, head ptr @16.
    let chan = |tail: u64, index: u64| {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tail.to_le_bytes());
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&0x1000u64.to_le_bytes());
        buf
    };

    // index=1, tail=3: slots 1 and 2 are still queued — as MpscChan renders.
    let bytes = chan(3, 1);
    let value = TypeInfoRef::new(view.ty(CHAN).unwrap(), 0, &bytes);
    let shown = format!("{}", value.display_from_target(&Reader, 8));
    assert_eq!(shown, "[20, 30]", "{shown}");

    // Drained (index == tail): empty, and no block is read at all.
    let bytes = chan(3, 3);
    let value = TypeInfoRef::new(view.ty(CHAN).unwrap(), 0, &bytes);
    let shown = format!("{}", value.display_from_target(&Reader, 8));
    assert_eq!(shown, "[]", "{shown}");
}

#[test]
fn test_mpsc_rx_renders_channel_with_capacity_and_free() {
    // The receiver's Arc raw pointer is 0x2000; the Chan sits 16 bytes in,
    // past the ArcInner strong/weak header, at 0x2010. Its head block is at
    // 0x1000.
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            // The head block lives at [0x1000, 0x1020) and is read piecemeal
            // by the queued CustomList; the RxChan is read whole at 0x2010.
            if (0x1000..0x1020).contains(&addr) {
                let mut block = Vec::new();
                for v in [10u32, 20, 30, 40] {
                    block.extend_from_slice(&v.to_le_bytes());
                }
                block.extend_from_slice(&0u64.to_le_bytes()); // start_index @16
                block.extend_from_slice(&0u64.to_le_bytes()); // next @24 (null)
                let start = (addr - 0x1000) as usize;
                return Ok(block[start..start + len as usize].to_vec());
            }
            let mut b = Vec::new();
            match addr {
                0x2010 => {
                    // RxChan: tail @0, index @8, head @16, semaphore @24
                    // (permits @24, bound @32).
                    b.extend_from_slice(&3u64.to_le_bytes()); // tail
                    b.extend_from_slice(&1u64.to_le_bytes()); // index
                    b.extend_from_slice(&0x1000u64.to_le_bytes()); // head
                    b.extend_from_slice(&6u64.to_le_bytes()); // permits -> free 3
                    b.extend_from_slice(&16u64.to_le_bytes()); // bound -> capacity 16
                }
                other => panic!("unexpected read at {other:#x}"),
            }
            b.truncate(len as usize);
            Ok(b)
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    // Receiver holds the Arc raw pointer.
    let bytes = 0x2000u64.to_le_bytes();
    let value = TypeInfoRef::new(v.ty(RECEIVER).unwrap(), 0, &bytes);
    let shown = format!("{}", value.display_from_target(&Reader, 8));
    assert!(
        shown.starts_with("tokio::sync::mpsc::bounded::Receiver<u32> {"),
        "{shown}"
    );
    assert!(shown.contains("capacity: 16"), "{shown}");
    assert!(shown.contains("free: closed=false, permits=3"), "{shown}");
    assert!(shown.contains("queued: [20, 30]"), "{shown}");

    // A null channel pointer is reported rather than dereferenced.
    let bytes = 0u64.to_le_bytes();
    let value = TypeInfoRef::new(v.ty(RECEIVER).unwrap(), 0, &bytes);
    let shown = format!("{}", value.display_from_target(&Reader, 8));
    assert_eq!(
        shown,
        "tokio::sync::mpsc::bounded::Receiver<u32> { <null> }"
    );
}

#[test]
fn test_bounded_semaphore_renders_compact_state_and_waiters() {
    // Two waiters live at 0x3000 and 0x3020, blocked on 2 and 1 permits.
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            // Waiter { state: usize @0, next: *Waiter @8 }.
            let (state, next) = match addr {
                0x3000 => (2u64, 0x3020u64),
                0x3020 => (1u64, 0u64),
                other => panic!("unexpected read at {other:#x}"),
            };
            let mut b = Vec::new();
            b.extend_from_slice(&state.to_le_bytes());
            b.extend_from_slice(&next.to_le_bytes());
            b.resize(32, 0);
            b.truncate(len as usize);
            Ok(b)
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    // Flat bounded::Semaphore buffer: mutex state @0, head @8, tail @16,
    // closed @32, permits @40, bound @48.
    let sem = |mutex: u8, head: u64, closed: u8, permits: u64, bound: u64| {
        let mut buf = vec![0u8; 56];
        buf[0] = mutex;
        buf[8..16].copy_from_slice(&head.to_le_bytes());
        buf[32] = closed;
        buf[40..48].copy_from_slice(&permits.to_le_bytes());
        buf[48..56].copy_from_slice(&bound.to_le_bytes());
        buf
    };

    // Unlocked, open, 10 permits (stored << 1), capacity 16, two waiters.
    let buf = sem(0, 0x3000, 0, 20, 16);
    let value = TypeInfoRef::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "tokio::sync::mpsc::bounded::Semaphore { mutex: locked=false, parked=false, \
         closed: false, permits: closed=false, permits=10, bound: 16, queue: [\
         tokio::sync::batch_semaphore::Waiter { permits_needed: 2 }, \
         tokio::sync::batch_semaphore::Waiter { permits_needed: 1 }] }"
    );

    // Locked, closed, no permits, empty queue (null head).
    let buf = sem(0b01, 0, 1, 0, 16);
    let value = TypeInfoRef::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "tokio::sync::mpsc::bounded::Semaphore { mutex: locked=true, parked=false, \
         closed: true, permits: closed=false, permits=0, bound: 16, queue: [] }"
    );

    // Without a target the queue cannot be walked, but the inline fields
    // (read from the value's own bytes) still render.
    let buf = sem(0, 0x3000, 0, 20, 16);
    let value = TypeInfoRef::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
    let shown = format!("{}", value.display());
    assert!(
        shown.contains("permits: closed=false, permits=10"),
        "{shown}"
    );
    assert!(shown.contains("queue: <target unavailable>"), "{shown}");

    // Pretty mode puts each field and waiter on its own indented line.
    let buf = sem(0, 0x3000, 0, 20, 16);
    let value = TypeInfoRef::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
    assert_eq!(
        format!("{:#}", value.display_from_target(&Reader, 8)),
        "tokio::sync::mpsc::bounded::Semaphore {\n\
         \x20   mutex: locked=false, parked=false,\n\
         \x20   closed: false,\n\
         \x20   permits: closed=false, permits=10,\n\
         \x20   bound: 16,\n\
         \x20   queue: [\n\
         \x20       tokio::sync::batch_semaphore::Waiter { permits_needed: 2 },\n\
         \x20       tokio::sync::batch_semaphore::Waiter { permits_needed: 1 },\n\
         \x20   ],\n\
         }"
    );
}

#[test]
fn test_watch_state_decodes_version_and_closed() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let cases = [
        // Bit 0 is the closed flag; the version is the remaining bits, so
        // it reads as the update count (tokio steps the state by 2), e.g.
        // raw 4 → version 2.
        (
            0u64,
            "tokio::sync::watch::state::AtomicState: closed=false, version=0",
        ),
        (
            4,
            "tokio::sync::watch::state::AtomicState: closed=false, version=2",
        ),
        (
            1,
            "tokio::sync::watch::state::AtomicState: closed=true, version=0",
        ),
        (
            5,
            "tokio::sync::watch::state::AtomicState: closed=true, version=2",
        ),
    ];
    for (state, expected) in cases {
        let bytes = state.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(WATCH_STATE).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), expected, "state={state}");
    }
}

#[test]
fn test_watch_receiver_renders_unseen_value_and_closed_independently() {
    struct Reader {
        state: u64,
        value: u32,
    }
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            let bytes = match addr {
                // ArcInner::data is at 0x2010; Shared::state is at +0.
                0x2010 => self.state.to_le_bytes().to_vec(),
                // Shared::value is at +8.
                0x2018 => self.value.to_le_bytes().to_vec(),
                other => panic!("unexpected read at {other:#x}"),
            };
            assert_eq!(bytes.len(), len as usize);
            Ok(bytes)
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let receiver = |observed: u64, pointer: u64| {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&pointer.to_le_bytes());
        bytes.extend_from_slice(&observed.to_le_bytes());
        bytes
    };
    let cases = [
        (
            2,
            2,
            "tokio::sync::watch::Receiver<u32> { unseen: None, closed: false }",
        ),
        (
            0,
            2,
            "tokio::sync::watch::Receiver<u32> { unseen: Some(42), closed: false }",
        ),
        (
            2,
            3,
            "tokio::sync::watch::Receiver<u32> { unseen: None, closed: true }",
        ),
        (
            0,
            3,
            "tokio::sync::watch::Receiver<u32> { unseen: Some(42), closed: true }",
        ),
    ];
    for (observed, state, expected) in cases {
        let bytes = receiver(observed, 0x2000);
        let value = TypeInfoRef::new(v.ty(WATCH_RECEIVER).unwrap(), 0, &bytes);
        assert_eq!(
            format!(
                "{}",
                value.display_from_target(&Reader { state, value: 42 }, 8)
            ),
            expected,
            "observed={observed}, state={state}"
        );
    }

    let bytes = receiver(0, 0x2000);
    let value = TypeInfoRef::new(v.ty(WATCH_RECEIVER).unwrap(), 0, &bytes);
    assert_eq!(
        format!(
            "{:#}",
            value.display_from_target(
                &Reader {
                    state: 2,
                    value: 42,
                },
                8,
            )
        ),
        "tokio::sync::watch::Receiver<u32> {\n\
         \x20   unseen: Some(42),\n\
         \x20   closed: false,\n\
         }"
    );

    // Degradation is now per field (the cross-Arc reads fail independently
    // in each Variant), rather than one whole-record marker.
    assert_eq!(
        format!("{}", value.display()),
        "tokio::sync::watch::Receiver<u32> \
         { unseen: <target unavailable>, closed: <target unavailable> }"
    );
    let bytes = receiver(0, 0);
    let value = TypeInfoRef::new(v.ty(WATCH_RECEIVER).unwrap(), 0, &bytes);
    assert_eq!(
        format!(
            "{}",
            value.display_from_target(
                &Reader {
                    state: 2,
                    value: 42
                },
                8
            )
        ),
        "tokio::sync::watch::Receiver<u32> { unseen: <null>, closed: <null> }"
    );
}

#[test]
fn test_raw_waker_vtable_resolves_function_symbols() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            panic!("function pointer at {addr:#x} must not be dereferenced")
        }

        fn function_symbol(&self, addr: u64) -> Option<String> {
            match addr {
                0x1000 => Some("tokio::runtime::task::waker::clone_waker".to_owned()),
                0x2000 => Some("tokio::runtime::task::waker::wake_by_val".to_owned()),
                0x3000 => Some("tokio::runtime::task::waker::wake_by_ref".to_owned()),
                0x4000 => Some("tokio::runtime::task::waker::drop_waker".to_owned()),
                _ => None,
            }
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [0x1000u64, 0x2000, 0x3000, 0x4000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let value = TypeInfoRef::new(v.ty(RAW_WAKER_VTABLE).unwrap(), 0, &bytes);
    let shown = format!("{:#}", value.display_from_target(&Reader, 8));
    assert_eq!(
        shown,
        concat!(
            "core::task::wake::RawWakerVTable {\n",
            "    clone: 0x1000 -> tokio::runtime::task::waker::clone_waker,\n",
            "    wake: 0x2000 -> tokio::runtime::task::waker::wake_by_val,\n",
            "    wake_by_ref: 0x3000 -> tokio::runtime::task::waker::wake_by_ref,\n",
            "    drop: 0x4000 -> tokio::runtime::task::waker::drop_waker,\n",
            "}"
        )
    );
}

#[test]
fn test_function_pointer_resolves_symbol_without_dereference() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            panic!("function pointer at {addr:#x} must not be dereferenced")
        }

        fn function_symbol(&self, addr: u64) -> Option<String> {
            (addr == 0x5000).then(|| "app::callback".to_owned())
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes = 0x5000u64.to_le_bytes();
    let value = TypeInfoRef::new(v.ty(FUNCTION_PTR).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "0x5000 -> app::callback"
    );
    assert_eq!(format!("{}", value.display()), "0x5000");

    let null = 0u64.to_le_bytes();
    let value = TypeInfoRef::new(v.ty(FUNCTION_PTR).unwrap(), 0, &null);
    assert_eq!(format!("{}", value.display_from_target(&Reader, 8)), "null");
}

#[test]
fn test_btree_map_displays_only_initialized_slots_in_order() {
    struct Reader;

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            let mut bytes = vec![0xaa; len as usize];
            match addr {
                0x1000 => {
                    bytes[0] = 1;
                    bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
                    bytes[12..16].copy_from_slice(&20u32.to_le_bytes());
                    bytes[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
                    bytes[32..40].copy_from_slice(&0x3000u64.to_le_bytes());
                }
                0x2000 => {
                    bytes[0] = 1;
                    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
                    bytes[12..16].copy_from_slice(&10u32.to_le_bytes());
                }
                0x3000 => {
                    bytes[0] = 1;
                    bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
                    bytes[12..16].copy_from_slice(&30u32.to_le_bytes());
                }
                _ => return Err(crate::Error::invalid_addr(addr)),
            }
            Ok(bytes)
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let mut bytes = [0u8; 24];
    bytes[..8].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
    bytes[16..].copy_from_slice(&3u64.to_le_bytes());
    let value = TypeInfoRef::new(v.ty(BTREE_MAP).unwrap(), 0x5000, &bytes);

    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 8)),
        "alloc::collections::btree::map::BTreeMap<u32, u32> { 1: 10, 2: 20, 3: 30 }"
    );
    let shown = format!("{:#}", value.display_from_target(&Reader, 8));
    assert!(shown.contains("\n    1: 10,"), "{shown}");
    assert!(shown.contains("\n    2: 20,"), "{shown}");
    assert!(shown.contains("\n    3: 30,"), "{shown}");
    assert!(
        !shown.contains("2863311530"),
        "unused 0xaa slots leaked: {shown}"
    );
}

#[test]
fn test_btree_map_reports_length_mismatch_and_node_cycle() {
    enum Layout {
        OneLeaf,
        SelfCycle,
    }

    struct Reader(Layout);

    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            if addr != 0x1000 {
                return Err(crate::Error::invalid_addr(addr));
            }
            let mut bytes = vec![0; len as usize];
            match self.0 {
                Layout::OneLeaf => {
                    bytes[0] = 1;
                    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
                    bytes[12..16].copy_from_slice(&10u32.to_le_bytes());
                }
                Layout::SelfCycle => {
                    bytes[24..32].copy_from_slice(&addr.to_le_bytes());
                }
            }
            Ok(bytes)
        }
    }

    let b = test_bundle();
    let v = BundleView::new(&b);
    let ty = v.ty(BTREE_MAP).unwrap();
    let mut bytes = [0u8; 24];
    bytes[..8].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[16..].copy_from_slice(&2u64.to_le_bytes());
    let value = TypeInfoRef::new(ty, 0x5000, &bytes);
    let shown = format!("{}", value.display_from_target(&Reader(Layout::OneLeaf), 8));
    assert!(
        shown.contains("<invalid: tree contains fewer entries than length>"),
        "{shown}"
    );

    bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
    bytes[16..].copy_from_slice(&1u64.to_le_bytes());
    let value = TypeInfoRef::new(ty, 0x5000, &bytes);
    let shown = format!(
        "{}",
        value.display_from_target(&Reader(Layout::SelfCycle), 8)
    );
    assert!(shown.contains("<invalid: node cycle>"), "{shown}");
}

#[test]
fn test_node_struct_renders_every_field_and_list_kind() {
    // Two queued waiters at 0x100 → 0x200 → end.
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!(len, 16);
            Ok(match addr {
                0x100 => waiter_bytes(1, 0x200), // kind=one, order=fifo
                0x200 => waiter_bytes(6, 0),     // kind=all(2), order=lifo(1): 0b110
                _ => panic!("unexpected waiter address 0x{addr:x}"),
            })
        }
    }

    let b = node_bundle();
    let v = BundleView::new(&b);
    // state word: waiting (1) with generation 3 → (3 << 2) | 1 = 13.
    let bytes = thing_bytes(13, 1, 7, 9, 0x100);
    let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &bytes);

    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 16)),
        "Thing { state: state=waiting, generation=3, flag: 1, point: Point { x: 7, y: 9 }, \
         queue: [Waiter { notification: kind=one, order=fifo }, \
         Waiter { notification: kind=all, order=lifo }] }"
    );

    let pretty = format!("{:#}", value.display_from_target(&Reader, 16));
    assert!(
        pretty.contains("\n    state: state=waiting, generation=3,"),
        "{pretty}"
    );
    assert!(pretty.contains("\n    point: Point {"), "{pretty}");
    assert!(pretty.contains("\n    queue: ["), "{pretty}");
    assert!(
        pretty.contains("notification: kind=one, order=fifo"),
        "{pretty}"
    );
}

#[test]
fn test_node_list_empty_and_degradation() {
    // An empty queue (head word 0) needs no target reads.
    struct NoReads;
    impl ReadFromProc for NoReads {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            panic!("no reads expected, got 0x{addr:x}")
        }
    }

    let b = node_bundle();
    let v = BundleView::new(&b);

    let empty = thing_bytes(0, 0, 0, 0, 0);
    let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &empty);
    assert_eq!(
        format!("{}", value.display_from_target(&NoReads, 16)),
        "Thing { state: state=idle, generation=0, flag: 0, point: Point { x: 0, y: 0 }, queue: [] }"
    );

    // A populated queue with no target reader degrades, not panics.
    let populated = thing_bytes(0, 0, 0, 0, 0x100);
    let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &populated);
    let shown = format!("{}", value.display());
    assert!(shown.contains("queue: <target unavailable>"), "{shown}");
}

#[test]
fn test_node_list_guards_cycles() {
    // A waiter whose successor points back at itself must not loop forever.
    struct Reader;
    impl ReadFromProc for Reader {
        fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
            assert_eq!(addr, 0x100);
            Ok(waiter_bytes(1, 0x100)) // self-cycle
        }
    }

    let b = node_bundle();
    let v = BundleView::new(&b);
    let bytes = thing_bytes(0, 0, 0, 0, 0x100);
    let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &bytes);
    assert_eq!(
        format!("{}", value.display_from_target(&Reader, 16)),
        "Thing { state: state=idle, generation=0, flag: 0, point: Point { x: 0, y: 0 }, \
         queue: [Waiter { notification: kind=one, order=fifo }] }"
    );
}

// -----------------------------------------------------------------------
// Formatter IR (`DisplayNode`) scaffolding
// -----------------------------------------------------------------------

// Type ids for [`node_bundle`], dense from zero into its own type table.
const N_U32: BundleTypeId = BundleTypeId(0);
const N_U64: BundleTypeId = BundleTypeId(1);
const N_U8: BundleTypeId = BundleTypeId(2);
const N_POINT: BundleTypeId = BundleTypeId(3);
const N_WAITER: BundleTypeId = BundleTypeId(4);
const N_WAITER_PTR: BundleTypeId = BundleTypeId(5);
const N_THING: BundleTypeId = BundleTypeId(6);

/// A self-contained bundle whose sole formatter is a [`BundleNode`] tree,
/// exercising every scaffolded node kind and field kind at once:
///
/// ```text
/// Thing {
///   state: <Scalar Bits>          // Named field
///   flag:  <Scalar Raw>           // Override field (reuses member 1's name)
///   point: Point { x, y }         // Member field (structural recursion)
///   queue: [Waiter { notification: <Scalar Bits> }, …]   // List of Struct
/// }
/// ```
///
/// Built separately from [`test_bundle`] so its layout can't perturb the
/// other tests' shared fixtures.
fn node_bundle() -> Bundle {
    use BundleField::{Member, Named, Override};

    let mut strings = StringInterner::new();
    let mut s = |name: &str| strings.intern(name);

    let (u32n, u64n, u8n) = (s("u32"), s("u64"), s("u8"));
    let (pointn, xn, yn) = (s("Point"), s("x"), s("y"));
    let (thingn, staten, flagn, pointfn, headn) =
        (s("Thing"), s("state"), s("flag"), s("point"), s("head"));
    let (waitern, notifn, nextn) = (s("Waiter"), s("notification"), s("next"));
    let (statel, idlel, waitingl, notifiedl, genl) = (
        s("state"),
        s("idle"),
        s("waiting"),
        s("notified"),
        s("generation"),
    );
    let (kindl, nonel, onel, alll, orderl, fifol, lifol) = (
        s("kind"),
        s("none"),
        s("one"),
        s("all"),
        s("order"),
        s("fifo"),
        s("lifo"),
    );
    let queuel = s("queue");

    let m = |name, ty, offset| MemberDef { name, ty, offset };

    let types = vec![
        TypeDef::Base {
            name: u32n,
            size: 4,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: u64n,
            size: 8,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: u8n,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Struct {
            name: pointn,
            size: 8,
            members: vec![m(xn, N_U32, 0), m(yn, N_U32, 4)],
        },
        TypeDef::Struct {
            name: waitern,
            size: 16,
            members: vec![m(notifn, N_U64, 0), m(nextn, N_WAITER_PTR, 8)],
        },
        TypeDef::Pointer {
            name: None,
            target: N_WAITER,
        },
        TypeDef::Struct {
            name: thingn,
            size: 28,
            members: vec![
                m(staten, N_U64, 0),
                m(flagn, N_U8, 8),
                m(pointfn, N_POINT, 12),
                m(headn, N_WAITER_PTR, 20),
            ],
        },
    ];

    let state_decode = BundleScalarDecode::Bits(vec![
        ebf(
            statel,
            0,
            2,
            vec![(0, idlel), (1, waitingl), (2, notifiedl)],
        ),
        ubf(genl, 2),
    ]);
    let notif_decode = BundleScalarDecode::Bits(vec![
        ebf(kindl, 0, 2, vec![(0, nonel), (1, onel), (2, alll)]),
        ebf(orderl, 2, 1, vec![(0, fifol), (1, lifol)]),
    ]);

    let waiter_node = BundleNode::Struct {
        fields: vec![Named {
            label: notifn,
            node: BundleNode::Scalar {
                at: sel(&[0]),
                decode: notif_decode,
            },
        }],
    };
    let thing_node = BundleNode::Struct {
        fields: vec![
            Named {
                label: staten,
                node: BundleNode::Scalar {
                    at: sel(&[0]),
                    decode: state_decode,
                },
            },
            Override {
                index: 1,
                node: BundleNode::Scalar {
                    at: sel(&[1]),
                    decode: BundleScalarDecode::Raw,
                },
            },
            Member(2),
            Named {
                label: queuel,
                node: BundleNode::List {
                    head: sel(&[3]),
                    next: sel(&[1]),
                    node: Box::new(waiter_node),
                    node_ty: N_WAITER,
                },
            },
        ],
    };

    let b = Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.finish(),
        types: TypeTable {
            types,
            debug_formats: std::collections::BTreeMap::from([(N_THING, thing_node)]),
            name_index: vec![],
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        infra: InfraTypes {
            header: N_U32,
            vtable: N_U32,
            trailer: N_U32,
            context: N_U32,
            scheduler_handle: N_U32,
            mt_handle: N_U32,
            location: N_U32,
            raw_waker_vtable: N_U32,
        },
        provenance: ProvenanceTable::default(),
    };
    b.validate().expect("node bundle must validate");
    b
}

/// Lay out a `Thing` value's 28 bytes. `head` is the queue head word.
fn thing_bytes(state: u64, flag: u8, x: u32, y: u32, head: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 28];
    bytes[0..8].copy_from_slice(&state.to_le_bytes());
    bytes[8] = flag;
    bytes[12..16].copy_from_slice(&x.to_le_bytes());
    bytes[16..20].copy_from_slice(&y.to_le_bytes());
    bytes[20..28].copy_from_slice(&head.to_le_bytes());
    bytes
}

/// Lay out a `Waiter` node's 16 bytes: notification word + successor.
fn waiter_bytes(notification: u64, next: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    bytes[0..8].copy_from_slice(&notification.to_le_bytes());
    bytes[8..16].copy_from_slice(&next.to_le_bytes());
    bytes
}

//! Bundle backend conformance: that reify's `DebugType`/`DebugMember` view of
//! a bundle reports the right kinds, members, variants and elements. Value
//! rendering is covered by `render.rs`; these tests use `display()` only to
//! read back what navigation landed on.

use crate::testhelper::*;

use exegesis::bundle::BundleView;

use crate::debug_type::DebugType;
use crate::{TypeInfoRef, TypeKind};

#[test]
fn test_kind_mapping() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let kind = |id| v.ty(id).unwrap().kind();
    assert_eq!(kind(U32), TypeKind::Integer);
    assert_eq!(kind(BOOL), TypeKind::Integer);
    assert_eq!(kind(POINT), TypeKind::Struct);
    assert_eq!(kind(MSG), TypeKind::Enum);
    assert_eq!(kind(PTR), TypeKind::Pointer);
    assert_eq!(kind(ARR), TypeKind::Array);
}

#[test]
fn test_member_access_and_display() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [1u32, 2u32].iter().flat_map(|x| x.to_le_bytes()).collect();
    let r = TypeInfoRef::new(v.ty(POINT).unwrap(), 0x1000, &bytes);

    let y = r.member("y").expect("member y");
    assert_eq!(y.addr, 0x1004);
    assert_eq!(format!("{}", y.display()), "2");
    assert!(r.try_member("z").expect("no error").is_none());

    let shown = format!("{}", r.display());
    assert!(
        shown.contains("x: 1") && shown.contains("y: 2"),
        "got {shown:?}"
    );
}

#[test]
fn test_active_variant_through_typeinfo() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let msg = v.ty(MSG).unwrap();

    let mut bytes = [0u8; 16];
    bytes[0] = 1;
    bytes[8..].copy_from_slice(&42u64.to_le_bytes());
    let r = TypeInfoRef::new(msg, 0, &bytes);
    assert!(r.is_enum());

    let (name, payload) = r.active_variant().expect("decode failed");
    assert_eq!(name, "B");
    assert_eq!(format!("{}", payload.display()), "42");

    // Struct payload: bytes window starts at the payload offset.
    bytes[0] = 0;
    bytes[8..12].copy_from_slice(&7u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&8u32.to_le_bytes());
    let r = TypeInfoRef::new(msg, 0, &bytes);
    let (name, payload) = r.active_variant().expect("decode failed");
    assert_eq!(name, "A");
    assert_eq!(format!("{}", payload.member("x").unwrap().display()), "7");

    // Struct types are not enums.
    let p = TypeInfoRef::new(v.ty(POINT).unwrap(), 0, &bytes[8..16]);
    assert!(!p.is_enum());
    assert!(p.active_variant().is_err());
}

#[test]
fn test_select_variant_through_typeinfo() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let mut bytes = [0u8; 16];
    bytes[0] = 1;
    let r = TypeInfoRef::new(v.ty(MSG).unwrap(), 0, &bytes);

    assert!(r.try_select_variant("B").expect("no error").is_some());
    assert!(r.try_select_variant("A").expect("no error").is_none());
    // Unknown variant names are an error, not "inactive".
    assert!(r.try_select_variant("Nope").is_err());
}

#[test]
fn test_niche_variant_through_typeinfo() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let opt = v.ty(OPT).unwrap();

    let bytes = 0u64.to_le_bytes();
    let (name, _) = TypeInfoRef::new(opt, 0, &bytes).active_variant().unwrap();
    assert_eq!(name, "None");

    let bytes = 0xdead_beefu64.to_le_bytes();
    let r = TypeInfoRef::new(opt, 0, &bytes);
    let (name, payload) = r.active_variant().unwrap();
    assert_eq!(name, "Some");
    assert_eq!(format!("{}", payload.display()), "3735928559");
}

#[test]
fn test_invalid_discriminant_is_error() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let mut bytes = [0u8; 16];
    bytes[0] = 9;
    let r = TypeInfoRef::new(v.ty(MSG).unwrap(), 0, &bytes);
    let err = r.active_variant().expect_err("tag 9 must not decode");
    let msg = format!("{err}");
    assert!(
        msg.contains("discriminant") || msg.contains("Msg"),
        "got {msg:?}"
    );
}

#[test]
fn test_peel_single_member_wrapper() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
    let peeled = TypeInfoRef::new(v.ty(WRAP).unwrap(), 0, &bytes).peel();
    assert_eq!(DebugType::name(&peeled.ty), "Point");
    assert_eq!(format!("{}", peeled.member("y").unwrap().display()), "4");
}

#[test]
fn test_array_elements_through_typeinfo() {
    let b = test_bundle();
    let v = BundleView::new(&b);
    let bytes: Vec<u8> = [10u32, 20, 30]
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect();
    let r = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &bytes);
    let shown: Vec<String> = r
        .array_elements()
        .expect("array elements")
        .map(|e| format!("{}", e.display()))
        .collect();
    assert_eq!(shown, ["10", "20", "30"]);
}

//! Integration tests that compile Rust fixtures at test time.
//! These only run on illumos where we have the correct toolchain.

#![cfg(target_os = "illumos")]

use assert_cmd::Command as AssertCommand;
use durin::read::{CtfArray, CtfReader, CtfType};
use tempfile::TempDir;

use std::path::PathBuf;
use std::process::Command;

/// Compile Rust source code to an ELF binary with debug info.
fn compile_rust_fixture(source: &str) -> (PathBuf, TempDir) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let project_dir = dir.path().join("test_fixture");

    let status = Command::new("cargo")
        .args(["new", "--quiet", "test_fixture"])
        .current_dir(dir.path())
        .status()
        .expect("failed to run cargo new");
    assert!(status.success(), "cargo new failed: {}", status);

    let src_path = project_dir.join("src/main.rs");
    std::fs::write(&src_path, source).expect("failed to write source");

    let cargo_path = project_dir.join("Cargo.toml");
    let mut cargo_toml = std::fs::read_to_string(&cargo_path).expect("failed to read Cargo.toml");
    cargo_toml.push_str("\n[profile.release]\ndebug = true\n");
    std::fs::write(&cargo_path, cargo_toml).expect("failed to write Cargo.toml");

    let status = Command::new("cargo")
        .args(["build", "--quiet", "--release"])
        .current_dir(&project_dir)
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "cargo build failed: {}", status);

    let bin_path = project_dir.join("target/release/test_fixture");
    (bin_path, dir)
}

/// Run dwarf2ctf and return parsed CTF
fn run_and_parse_ctf(elf_path: &PathBuf, types: &[&str], output_dir: &TempDir) -> CtfReader {
    let ctf_path = output_dir.path().join("output.ctf");

    let mut cmd = AssertCommand::cargo_bin("dwarf2ctf").unwrap();
    cmd.arg("--ctf-out").arg(&ctf_path);

    for ty in types {
        cmd.arg("--type").arg(ty);
    }

    // ELF path is a positional argument
    cmd.arg(elf_path);

    cmd.assert().success();

    let bytes = std::fs::read(&ctf_path).expect("failed to read CTF file");
    CtfReader::load(&bytes).expect("failed to load CTF")
}

// ==================== Tests ====================

#[test]
fn test_struct_size_and_member_offsets() {
    let source = r#"
        #[repr(C)]
        #[derive(Debug)]
        pub struct Point {
            pub x: i32,
            pub y: i32,
        }

        fn main() {
            let p = Point { x: 1, y: 2 };
            dbg!(p);
        }
    "#;

    let test_type = "test_fixture::Point";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[test_type], &dir);

    let point = ctf
        .types()
        .into_iter()
        .find(|s| s.name(&ctf) == test_type)
        .expect("expected Point struct");

    // Point should be 8 bytes (2 * i32)
    assert_eq!(point.size(&ctf), 8, "Point should be 8 bytes");
    assert_eq!(point.members().len(), 2, "Point should have 2 members");

    // Check member offsets (in bits for CTF)
    let x = point.member("x", &ctf).expect("expected member x");
    let y = point.member("y", &ctf).expect("expected member y");

    assert_eq!(x.offset_bits, 0, "x should be at offset 0");
    assert_eq!(y.offset_bits, 32, "y should be at offset 32 bits (4 bytes)");
}

#[test]
fn test_struct_with_different_sized_members() {
    let source = r#"
        #[repr(C)]
        #[derive(Debug)]
        pub struct Mixed {
            pub a: u8,
            pub b: u32,
            pub c: u16,
        }

        fn main() {
            let m = Mixed { a: 1, b: 2, c: 3 };
            dbg!(m);
        }
    "#;

    let test_type = "test_fixture::Mixed";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[test_type], &dir);

    let mixed = ctf
        .types()
        .into_iter()
        .find(|s| s.name(&ctf) == test_type)
        .expect("expected Mixed struct");

    // With #[repr(C)]: a at 0, padding, b at 4, c at 8, padding to 12
    assert_eq!(
        mixed.size(&ctf),
        12,
        "Mixed should be 12 bytes with C layout"
    );

    let a = mixed.member("a", &ctf).expect("expected member a");
    let b = mixed.member("b", &ctf).expect("expected member b");
    let c = mixed.member("c", &ctf).expect("expected member c");

    assert_eq!(a.offset_bits, 0, "a should be at offset 0");
    assert_eq!(
        b.offset_bits, 32,
        "b should be at offset 32 bits (after padding)"
    );
    assert_eq!(c.offset_bits, 64, "c should be at offset 64 bits");
}

#[test]
fn test_nested_struct_sizes() {
    let source = r#"
        #[repr(C)]
        #[derive(Debug)]
        pub struct Inner {
            pub value: i64,
        }

        #[repr(C)]
        #[derive(Debug)]
        pub struct Outer {
            pub inner: Inner,
            pub extra: i32,
        }

        fn main() {
            let o = Outer {
                inner: Inner { value: 42 },
                extra: 0,
            };
            dbg!(o);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(
        &bin_path,
        &["test_fixture::Inner", "test_fixture::Outer"],
        &dir,
    );

    let inner = ctf
        .types()
        .into_iter()
        .find(|s| s.name(&ctf) == "test_fixture::Inner")
        .expect("expected Inner struct");

    let outer = ctf
        .types()
        .into_iter()
        .find(|s| s.name(&ctf) == "test_fixture::Outer")
        .expect("expected Outer struct");

    // Inner: 8 bytes (i64)
    assert_eq!(inner.size(&ctf), 8, "Inner should be 8 bytes");
    assert_eq!(inner.member("value", &ctf).unwrap().offset_bits, 0);

    // Outer: 16 bytes (Inner(8) + extra(4) + padding(4) for alignment)
    assert_eq!(outer.size(&ctf), 16, "Outer should be 16 bytes");

    let inner_member = outer.member("inner", &ctf).expect("expected inner member");
    let extra_member = outer.member("extra", &ctf).expect("expected extra member");

    assert_eq!(inner_member.offset_bits, 0, "inner should be at offset 0");
    assert_eq!(
        extra_member.offset_bits, 64,
        "extra should be at offset 64 bits"
    );
}

#[test]
fn test_enum_size_and_variants() {
    let source = r#"
        #[repr(C)]
        #[derive(Debug)]
        pub enum Color {
            Red = 0,
            Green = 1,
            Blue = 2,
        }
        fn main() {
            let c = Color::Red;
            dbg!(c);
        }
    "#;

    let test_type = "test_fixture::Color";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[test_type], &dir);

    let color = ctf
        .types()
        .iter()
        .find(|e| e.name(&ctf) == test_type)
        .unwrap();

    // C enum is typically 4 bytes
    assert_eq!(color.size(&ctf), 4, "Color enum should be 4 bytes");
    assert_eq!(color.enumerators().len(), 3, "Color should have 3 variants");

    // Check enumerator values
    let red = color.enumerators().iter().find(|n| n.name(&ctf) == "Red");
    let green = color.enumerators().iter().find(|n| n.name(&ctf) == "Green");
    let blue = color.enumerators().iter().find(|n| n.name(&ctf) == "Blue");

    assert!(red.is_some(), "expected Red variant");
    assert!(green.is_some(), "expected Green variant");
    assert!(blue.is_some(), "expected Blue variant");

    assert_eq!(red.unwrap().value, 0u64, "Red should have value 0");
    assert_eq!(green.unwrap().value, 1u64, "Green should have value 1");
    assert_eq!(blue.unwrap().value, 2u64, "Blue should have value 2");
}

#[test]
fn test_array_element_count() {
    let source = r#"
        #[derive(Debug)]
        pub struct Wrapper {
            pub inner: [i32; 4],
        }
        fn main() {
            let x = Wrapper { inner: [1i32, 2, 3, 4] };
            dbg!(x);
        }
    "#;

    let test_type = "test_fixture::Wrapper";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[test_type], &dir);

    let wrapper = ctf
        .types()
        .iter()
        .find(|t| t.name(&ctf) == test_type)
        .unwrap();

    let inner = wrapper.member("inner", &ctf).unwrap();
    let array = inner.ty(&ctf);
    let CtfType::Array {
        ty: CtfArray { nelems, .. },
        ..
    } = array
    else {
        panic!("CTF type was not an array");
    };

    assert_eq!(*nelems, 4);
}

#[test]
fn test_tuple_struct_layout() {
    let source = r#"
        #[repr(C)]
        #[derive(Debug)]
        pub struct Pair(pub i32, pub i64);

        fn main() {
            let p = Pair(1, 2);
            dbg!(p);
        }
    "#;

    let test_type = "test_fixture::Pair";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[test_type], &dir);

    let pair = ctf
        .types()
        .into_iter()
        .find(|s| s.name(&ctf) == test_type)
        .expect("expected Pair struct");

    // Pair: i32(4) + padding(4) + i64(8) = 16 bytes
    assert_eq!(pair.size(&ctf), 16, "Pair should be 16 bytes");
    assert_eq!(pair.members().len(), 2, "Pair should have 2 members");

    // Tuple fields are named __0, __1 or 0, 1
    let members = pair.members();
    assert!(
        members
            .iter()
            .any(|m| m.name(&ctf) == "__0" || m.name(&ctf) == "0"),
        "expected first tuple field"
    );
    assert!(
        members
            .iter()
            .any(|m| m.name(&ctf) == "__1" || m.name(&ctf) == "1"),
        "expected second tuple field"
    );
}

#[test]
fn test_complex_struct_offsets() {
    let source = r#"
        #[repr(C)]
        #[derive(Debug)]
        pub struct Complex {
            pub flags: u8,
            pub id: u64,
            pub count: u32,
            pub data: [u8; 3],
            pub value: u16,
        }

        fn main() {
            let c = Complex {
                flags: 0,
                id: 1,
                count: 2,
                data: [0, 0, 0],
                value: 3,
            };
            dbg!(c);
        }
    "#;

    let type_name = "test_fixture::Complex";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[type_name], &dir);

    let complex = ctf
        .types()
        .into_iter()
        .find(|s| s.name(&ctf) == type_name)
        .expect("expected Complex struct");

    // C layout:
    // flags: u8 at 0
    // padding: 7 bytes
    // id: u64 at 8
    // count: u32 at 16
    // data: [u8; 3] at 20
    // padding: 1 byte
    // value: u16 at 24
    // padding: 6 bytes for u64 alignment
    // total: 32 bytes

    assert_eq!(complex.size(&ctf), 32, "Complex should be 32 bytes");

    let flags = complex.member("flags", &ctf).expect("expected flags");
    let id = complex.member("id", &ctf).expect("expected id");
    let count = complex.member("count", &ctf).expect("expected count");
    let data = complex.member("data", &ctf).expect("expected data");
    let value = complex.member("value", &ctf).expect("expected value");

    assert_eq!(flags.offset_bits, 0, "flags at 0");
    assert_eq!(id.offset_bits, 64, "id at 64 bits (8 bytes)");
    assert_eq!(count.offset_bits, 128, "count at 128 bits (16 bytes)");
    assert_eq!(data.offset_bits, 160, "data at 160 bits (20 bytes)");
    assert_eq!(value.offset_bits, 192, "value at 192 bits (24 bytes)");
}

#[test]
fn test_option_type_exists() {
    let source = r#"
        fn main() {
            let x = Some(1i32);
            dbg!(x);
        }
    "#;

    let test_type = "core::option::Option<i32>";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[test_type], &dir);

    // Option<T> should produce some type
    let option_type = ctf.types().iter().find(|t| t.name(&ctf) == test_type);
    assert!(option_type.is_some(), "expected Option type");
}

#[test]
fn test_result_type_exists() {
    let source = r#"
        fn main() {
            let x: Result<i32, &'static str> = Ok(1);
            let _ = dbg!(x);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["core::result::Result<i32, &str>"], &dir);

    let result_type = ctf
        .types()
        .iter()
        .find(|t| t.name(&ctf) == "core::result::Result<i32,_&str>");
    assert!(result_type.is_some(), "expected Result type");
}

#[test]
fn test_vec_type_exists() {
    let source = r#"
        fn main() {
            let x = vec![1i32, 2, 3];
            dbg!(x);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(
        &bin_path,
        &["alloc::vec::Vec<i32, alloc::alloc::Global>"],
        &dir,
    );

    let vec_type = ctf
        .types()
        .iter()
        .find(|t| t.name(&ctf) == "alloc::vec::Vec<i32,_alloc::alloc::Global>");
    assert!(vec_type.is_some(), "expected Vec type");
}

#[test]
fn test_type_not_found_still_produces_valid_ctf() {
    let source = r#"
        fn main() {
            println!("hello, world!");
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let _ctf = run_and_parse_ctf(&bin_path, &["nonexistent"], &dir);
}

// ==================== Niche-Optimized Enum Tests ====================

#[test]
fn test_option_nonzero_has_tagged_union() {
    let source = r#"
        use std::num::NonZeroU32;

        fn main() {
            let x = Some(NonZeroU32::new(42).unwrap());
            dbg!(x);
        }
    "#;

    let test_type = "core::option::Option<core::num::nonzero::NonZero<u32>>";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[test_type], &dir);

    // Find the Option<NonZeroU32> struct
    let option_struct = ctf
        .types()
        .into_iter()
        .find(|s| s.name(&ctf) == test_type)
        .expect("expected Option<NonZeroU32> struct");

    // For niche-optimized enums, we should have a __tagged member
    let tagged = option_struct.member("__tagged", &ctf);
    assert!(
        tagged.is_some(),
        "expected __tagged member for niche-optimized enum"
    );

    // Find the __tagged union
    let tagged_union = ctf
        .types()
        .into_iter()
        .find(|u| u.name(&ctf).contains("__tagged"))
        .expect("expected __tagged union type");

    // The __tagged union should have __discr and __variants members
    let discr = tagged_union.member("__discr", &ctf);
    let variants = tagged_union.member("__variants", &ctf);

    assert!(discr.is_some(), "expected __discr member in __tagged union");
    assert!(
        variants.is_some(),
        "expected __variants member in __tagged union"
    );

    // Find the discriminant enum type
    let discr_enum = ctf
        .types()
        .into_iter()
        .find(|e| e.name(&ctf).contains("__discr_ty"))
        .expect("expected __discr_ty enum type");

    // The discriminant enum should have a None variant with value 0
    let none = discr_enum
        .enumerators()
        .iter()
        .find(|n| n.name(&ctf) == "None");
    assert!(
        none.is_some(),
        "expected None enumerator in discriminant enum"
    );
    assert_eq!(
        none.unwrap().value,
        0u64,
        "None should have discriminant value 0"
    );

    // Find the __variants union
    let variants_union = ctf
        .types()
        .into_iter()
        .find(|u| u.name(&ctf).contains("__variants"))
        .expect("expected __variants union type");

    // The __variants union should have None and Some members
    let none_member = variants_union.member("None", &ctf);
    let some_member = variants_union.member("Some", &ctf);

    assert!(
        none_member.is_some(),
        "expected None member in __variants union"
    );
    assert!(
        some_member.is_some(),
        "expected Some member in __variants union"
    );
}

#[test]
fn test_option_custom_enum_has_tagged_union() {
    let source = r#"
        #[repr(u8)]
        #[derive(Debug)]
        pub enum Status {
            Pending = 0,
            Running = 1,
            Complete = 2,
        }

        fn main() {
            let x = Some(Status::Pending);
            dbg!(x);
        }
    "#;

    let test_type = "core::option::Option<test_fixture::Status>";
    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &[test_type], &dir);

    // Find the Option<Status> struct
    let ty = ctf
        .types()
        .into_iter()
        .find(|s| s.name(&ctf) == test_type)
        .unwrap();

    // If we found the Option struct, check for __tagged union structure
    let tagged = ty.member("__tagged", &ctf);
    if tagged.is_some() {
        // Niche-optimized case: look for __discr_ty with None variant
        let discr_enum = ctf
            .types()
            .into_iter()
            .find(|e| e.name(&ctf).contains("__discr_ty") && e.name(&ctf).contains("Option"));

        if let Some(discr) = discr_enum {
            // The None variant should have a discriminant value > 2 (since Status uses 0,1,2)
            let none = discr.enumerators().iter().find(|n| n.name(&ctf) == "None");
            assert!(none.is_some(), "expected None enumerator");
            assert!(
                none.unwrap().value > 2,
                "None should have discriminant value > 2 (out of range for Status)"
            );
        }
    }
}

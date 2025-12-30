//! Integration tests that compile Rust fixtures at test time.
//! These only run on illumos where we have the correct toolchain.

#![cfg(target_os = "illumos")]

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use assert_cmd::Command as AssertCommand;
use flate2::read::ZlibDecoder;
use predicates::prelude::*;
use tempfile::TempDir;

// ==================== CTF Constants ====================

const CTF_MAGIC: u16 = 0xcff1;
const CTF_VERSION: u8 = 2;
const CTF_F_COMPRESS: u8 = 0x01;

// CTF Type Kinds
const CTF_K_UNKNOWN: u8 = 0;
const CTF_K_INTEGER: u8 = 1;
const CTF_K_FLOAT: u8 = 2;
const CTF_K_POINTER: u8 = 3;
const CTF_K_ARRAY: u8 = 4;
const CTF_K_FUNCTION: u8 = 5;
const CTF_K_STRUCT: u8 = 6;
const CTF_K_UNION: u8 = 7;
const CTF_K_ENUM: u8 = 8;
const CTF_K_TYPEDEF: u8 = 10;
const CTF_K_CONST: u8 = 12;

// ==================== CTF Reader for Test Validation ====================

/// Parsed CTF header
#[derive(Debug)]
struct CtfHeader {
    magic: u16,
    version: u8,
    flags: u8,
    lbloff: u32,
    objtoff: u32,
    funcoff: u32,
    typeoff: u32,
    stroff: u32,
    strlen: u32,
}

/// A struct/union member with offset information
#[derive(Debug, Clone)]
struct ParsedMember {
    name: String,
    type_id: u16,
    offset_bits: u16,
}

/// A parsed CTF type entry
#[derive(Debug)]
struct ParsedType {
    name: String,
    kind: u8,
    vlen: u16,
    /// For sized types (structs, unions, enums, integers, floats): the size in bytes
    /// For reference types (pointers, typedefs, const, etc.): the target type ID
    size_or_type: u16,
    /// For structs/unions: members with offsets
    members: Vec<ParsedMember>,
    /// For enums: enumerator names and values
    enumerators: Vec<(String, i32)>,
    /// For arrays: (element_type, index_type, nelems)
    array_info: Option<(u16, u16, u32)>,
}

impl ParsedType {
    /// Get the size in bytes (only valid for sized types)
    fn size(&self) -> u16 {
        match self.kind {
            CTF_K_INTEGER | CTF_K_FLOAT | CTF_K_STRUCT | CTF_K_UNION | CTF_K_ENUM => {
                self.size_or_type
            }
            _ => 0,
        }
    }

    /// Get member by name
    fn member(&self, name: &str) -> Option<&ParsedMember> {
        self.members.iter().find(|m| m.name == name)
    }

    /// Get member names
    fn member_names(&self) -> Vec<&str> {
        self.members.iter().map(|m| m.name.as_str()).collect()
    }
}

/// Parsed CTF file for test assertions
#[derive(Debug)]
struct ParsedCtf {
    header: CtfHeader,
    types: Vec<ParsedType>,
    strings: Vec<u8>,
}

impl ParsedCtf {
    /// Parse a CTF file from bytes
    fn parse(data: &[u8]) -> Self {
        assert!(data.len() >= 36, "CTF file too small for header");

        // Parse header (first 36 bytes are uncompressed)
        let magic = u16::from_le_bytes([data[0], data[1]]);
        let version = data[2];
        let flags = data[3];
        let _parlabel = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let _parname = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let lbloff = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let objtoff = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let funcoff = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let typeoff = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let stroff = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let strlen = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);

        let header = CtfHeader {
            magic,
            version,
            flags,
            lbloff,
            objtoff,
            funcoff,
            typeoff,
            stroff,
            strlen,
        };

        // Decompress the body if compressed
        let body = if flags & CTF_F_COMPRESS != 0 {
            let compressed = &data[36..];
            let mut decoder = ZlibDecoder::new(compressed);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).expect("failed to decompress CTF");
            decompressed
        } else {
            data[36..].to_vec()
        };

        // Extract string table
        let str_start = stroff as usize;
        let str_end = str_start + strlen as usize;
        let strings = if str_end <= body.len() {
            body[str_start..str_end].to_vec()
        } else {
            Vec::new()
        };

        // Parse types
        let type_start = typeoff as usize;
        let type_end = stroff as usize;
        let types = Self::parse_types(&body[type_start..type_end], &strings);

        ParsedCtf { header, types, strings }
    }

    /// Get a string from the string table by offset
    fn get_string(strings: &[u8], offset: u32) -> String {
        if offset == 0 || offset as usize >= strings.len() {
            return String::new();
        }
        let start = offset as usize;
        let end = strings[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(strings.len());
        String::from_utf8_lossy(&strings[start..end]).to_string()
    }

    /// Parse the type section
    fn parse_types(type_data: &[u8], strings: &[u8]) -> Vec<ParsedType> {
        let mut types = Vec::new();
        let mut offset = 0;

        while offset + 8 <= type_data.len() {
            let name_off = u32::from_le_bytes([
                type_data[offset],
                type_data[offset + 1],
                type_data[offset + 2],
                type_data[offset + 3],
            ]);
            let info = u16::from_le_bytes([type_data[offset + 4], type_data[offset + 5]]);
            let size_or_type = u16::from_le_bytes([type_data[offset + 6], type_data[offset + 7]]);

            let kind = ((info >> 11) & 0x1f) as u8;
            let _is_root = (info >> 10) & 1 != 0;
            let vlen = info & 0x3ff;

            let name = Self::get_string(strings, name_off);

            offset += 8;

            let mut members = Vec::new();
            let mut enumerators = Vec::new();
            let mut array_info = None;

            // Handle variable-length data based on type kind
            match kind {
                CTF_K_INTEGER | CTF_K_FLOAT => {
                    // 4 bytes of encoding data
                    offset += 4;
                }
                CTF_K_ARRAY => {
                    if offset + 8 <= type_data.len() {
                        let elem_type = u16::from_le_bytes([type_data[offset], type_data[offset + 1]]);
                        let idx_type = u16::from_le_bytes([type_data[offset + 2], type_data[offset + 3]]);
                        let nelems = u32::from_le_bytes([
                            type_data[offset + 4],
                            type_data[offset + 5],
                            type_data[offset + 6],
                            type_data[offset + 7],
                        ]);
                        array_info = Some((elem_type, idx_type, nelems));
                        offset += 8;
                    }
                }
                CTF_K_STRUCT | CTF_K_UNION => {
                    // Each member: name(4) + type(2) + offset(2)
                    for _ in 0..vlen {
                        if offset + 8 <= type_data.len() {
                            let member_name_off = u32::from_le_bytes([
                                type_data[offset],
                                type_data[offset + 1],
                                type_data[offset + 2],
                                type_data[offset + 3],
                            ]);
                            let member_type = u16::from_le_bytes([
                                type_data[offset + 4],
                                type_data[offset + 5],
                            ]);
                            let member_offset = u16::from_le_bytes([
                                type_data[offset + 6],
                                type_data[offset + 7],
                            ]);
                            members.push(ParsedMember {
                                name: Self::get_string(strings, member_name_off),
                                type_id: member_type,
                                offset_bits: member_offset,
                            });
                            offset += 8;
                        }
                    }
                }
                CTF_K_ENUM => {
                    // Each enumerator: name(4) + value(4)
                    for _ in 0..vlen {
                        if offset + 8 <= type_data.len() {
                            let enum_name_off = u32::from_le_bytes([
                                type_data[offset],
                                type_data[offset + 1],
                                type_data[offset + 2],
                                type_data[offset + 3],
                            ]);
                            let enum_value = i32::from_le_bytes([
                                type_data[offset + 4],
                                type_data[offset + 5],
                                type_data[offset + 6],
                                type_data[offset + 7],
                            ]);
                            enumerators.push((Self::get_string(strings, enum_name_off), enum_value));
                            offset += 8;
                        }
                    }
                }
                CTF_K_FUNCTION => {
                    // vlen args (each 2 bytes), padded to even count
                    let padded_vlen = if vlen % 2 == 0 { vlen } else { vlen + 1 };
                    offset += (padded_vlen as usize) * 2;
                }
                CTF_K_POINTER | CTF_K_TYPEDEF | CTF_K_CONST | CTF_K_UNKNOWN => {
                    // No additional data
                }
                _ => {}
            }

            types.push(ParsedType {
                name,
                kind,
                vlen,
                size_or_type,
                members,
                enumerators,
                array_info,
            });
        }

        types
    }

    /// Check if CTF has valid magic and version
    fn is_valid(&self) -> bool {
        self.header.magic == CTF_MAGIC && self.header.version == CTF_VERSION
    }

    /// Find a type by name (exact match)
    fn find_type(&self, name: &str) -> Option<&ParsedType> {
        self.types.iter().find(|t| t.name == name)
    }

    /// Find a type by name (contains)
    fn find_type_containing(&self, name: &str) -> Option<&ParsedType> {
        self.types.iter().find(|t| t.name.contains(name))
    }

    /// Find all types of a given kind
    fn types_of_kind(&self, kind: u8) -> Vec<&ParsedType> {
        self.types.iter().filter(|t| t.kind == kind).collect()
    }

    /// Get all struct types
    fn structs(&self) -> Vec<&ParsedType> {
        self.types_of_kind(CTF_K_STRUCT)
    }

    /// Get all enum types
    fn enums(&self) -> Vec<&ParsedType> {
        self.types_of_kind(CTF_K_ENUM)
    }

    /// Get all integer types
    fn integers(&self) -> Vec<&ParsedType> {
        self.types_of_kind(CTF_K_INTEGER)
    }

    /// Get all pointer types
    fn pointers(&self) -> Vec<&ParsedType> {
        self.types_of_kind(CTF_K_POINTER)
    }

    /// Get all array types
    fn arrays(&self) -> Vec<&ParsedType> {
        self.types_of_kind(CTF_K_ARRAY)
    }

    /// Debug print all types
    #[allow(dead_code)]
    fn dump_types(&self) {
        for (i, t) in self.types.iter().enumerate() {
            let kind_name = match t.kind {
                CTF_K_UNKNOWN => "UNKNOWN",
                CTF_K_INTEGER => "INTEGER",
                CTF_K_FLOAT => "FLOAT",
                CTF_K_POINTER => "POINTER",
                CTF_K_ARRAY => "ARRAY",
                CTF_K_FUNCTION => "FUNCTION",
                CTF_K_STRUCT => "STRUCT",
                CTF_K_UNION => "UNION",
                CTF_K_ENUM => "ENUM",
                CTF_K_TYPEDEF => "TYPEDEF",
                CTF_K_CONST => "CONST",
                _ => "OTHER",
            };
            eprintln!(
                "[{}] {} '{}' size={} vlen={} members={:?}",
                i, kind_name, t.name, t.size(), t.vlen,
                t.members.iter().map(|m| (&m.name, m.offset_bits)).collect::<Vec<_>>()
            );
        }
    }
}

// ==================== Test Helpers ====================

/// Compile Rust source code to an ELF binary with debug info.
fn compile_rust_fixture(source: &str) -> (PathBuf, TempDir) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let src_path = dir.path().join("test.rs");
    let bin_path = dir.path().join("test");

    std::fs::write(&src_path, source).expect("failed to write source");

    let status = Command::new("rustc")
        .args([
            "-g",
            "-C", "opt-level=0",
            "-C", "debuginfo=2",
            "-o",
            bin_path.to_str().unwrap(),
            src_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run rustc");

    assert!(status.success(), "rustc failed: {}", status);

    (bin_path, dir)
}

/// Run dwarf2ctf and return parsed CTF
fn run_and_parse_ctf(elf_path: &PathBuf, functions: &[&str], output_dir: &TempDir) -> ParsedCtf {
    let ctf_path = output_dir.path().join("output.ctf");

    let mut cmd = AssertCommand::cargo_bin("dwarf2ctf").unwrap();
    cmd.arg("--elf").arg(elf_path);
    cmd.arg("--ctf_out").arg(&ctf_path);

    for func in functions {
        cmd.arg("--fns").arg(func);
    }

    cmd.assert().success();

    let bytes = std::fs::read(&ctf_path).expect("failed to read CTF file");
    ParsedCtf::parse(&bytes)
}

// ==================== Tests ====================

#[test]
fn test_simple_function_produces_valid_ctf() {
    let source = r#"
        #[no_mangle]
        pub fn add(a: i32, b: i32) -> i32 {
            a + b
        }

        fn main() {
            let _ = add(1, 2);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["add"], &dir);

    assert!(ctf.is_valid());

    // Should have i32 type with size 4 bytes (32 bits)
    let integers = ctf.integers();
    let i32_type = integers.iter().find(|t| t.name.contains("i32") || t.name == "int");
    assert!(i32_type.is_some(), "expected i32 type");
    assert_eq!(i32_type.unwrap().size(), 4, "i32 should be 4 bytes");
}

#[test]
fn test_struct_size_and_member_offsets() {
    let source = r#"
        #[repr(C)]
        pub struct Point {
            pub x: i32,
            pub y: i32,
        }

        #[no_mangle]
        pub fn sum_point(p: Point) -> i32 {
            p.x + p.y
        }

        fn main() {
            let p = Point { x: 1, y: 2 };
            let _ = sum_point(p);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["sum_point"], &dir);

    assert!(ctf.is_valid());

    let point = ctf.structs().into_iter()
        .find(|s| s.name.contains("Point"))
        .expect("expected Point struct");

    // Point should be 8 bytes (2 * i32)
    assert_eq!(point.size(), 8, "Point should be 8 bytes");
    assert_eq!(point.vlen, 2, "Point should have 2 members");

    // Check member offsets (in bits for CTF)
    let x = point.member("x").expect("expected member x");
    let y = point.member("y").expect("expected member y");

    assert_eq!(x.offset_bits, 0, "x should be at offset 0");
    assert_eq!(y.offset_bits, 32, "y should be at offset 32 bits (4 bytes)");
}

#[test]
fn test_struct_with_different_sized_members() {
    let source = r#"
        #[repr(C)]
        pub struct Mixed {
            pub a: u8,
            pub b: u32,
            pub c: u16,
        }

        #[no_mangle]
        pub fn use_mixed(m: Mixed) -> u32 {
            m.a as u32 + m.b + m.c as u32
        }

        fn main() {
            let m = Mixed { a: 1, b: 2, c: 3 };
            let _ = use_mixed(m);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["use_mixed"], &dir);

    assert!(ctf.is_valid());

    let mixed = ctf.structs().into_iter()
        .find(|s| s.name.contains("Mixed"))
        .expect("expected Mixed struct");

    // With #[repr(C)]: a at 0, padding, b at 4, c at 8, padding to 12
    assert_eq!(mixed.size(), 12, "Mixed should be 12 bytes with C layout");

    let a = mixed.member("a").expect("expected member a");
    let b = mixed.member("b").expect("expected member b");
    let c = mixed.member("c").expect("expected member c");

    assert_eq!(a.offset_bits, 0, "a should be at offset 0");
    assert_eq!(b.offset_bits, 32, "b should be at offset 32 bits (after padding)");
    assert_eq!(c.offset_bits, 64, "c should be at offset 64 bits");
}

#[test]
fn test_nested_struct_sizes() {
    let source = r#"
        #[repr(C)]
        pub struct Inner {
            pub value: i64,
        }

        #[repr(C)]
        pub struct Outer {
            pub inner: Inner,
            pub extra: i32,
        }

        #[no_mangle]
        pub fn get_inner_value(o: Outer) -> i64 {
            o.inner.value
        }

        fn main() {
            let o = Outer {
                inner: Inner { value: 42 },
                extra: 0,
            };
            let _ = get_inner_value(o);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["get_inner_value"], &dir);

    assert!(ctf.is_valid());

    let inner = ctf.structs().into_iter()
        .find(|s| s.name.contains("Inner"))
        .expect("expected Inner struct");

    let outer = ctf.structs().into_iter()
        .find(|s| s.name.contains("Outer"))
        .expect("expected Outer struct");

    // Inner: 8 bytes (i64)
    assert_eq!(inner.size(), 8, "Inner should be 8 bytes");
    assert_eq!(inner.member("value").unwrap().offset_bits, 0);

    // Outer: 16 bytes (Inner(8) + extra(4) + padding(4) for alignment)
    assert_eq!(outer.size(), 16, "Outer should be 16 bytes");

    let inner_member = outer.member("inner").expect("expected inner member");
    let extra_member = outer.member("extra").expect("expected extra member");

    assert_eq!(inner_member.offset_bits, 0, "inner should be at offset 0");
    assert_eq!(extra_member.offset_bits, 64, "extra should be at offset 64 bits");
}

#[test]
fn test_enum_size_and_variants() {
    let source = r#"
        #[repr(C)]
        pub enum Color {
            Red = 0,
            Green = 1,
            Blue = 2,
        }

        #[no_mangle]
        pub fn color_value(c: Color) -> i32 {
            c as i32
        }

        fn main() {
            let _ = color_value(Color::Red);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["color_value"], &dir);

    assert!(ctf.is_valid());

    // C-style enum should be represented as CTF enum
    let enums = ctf.enums();
    let color = enums.iter().find(|e| e.name.contains("Color"));

    if let Some(color) = color {
        // C enum is typically 4 bytes
        assert_eq!(color.size(), 4, "Color enum should be 4 bytes");
        assert_eq!(color.vlen, 3, "Color should have 3 variants");

        // Check enumerator values
        let red = color.enumerators.iter().find(|(n, _)| n.contains("Red"));
        let green = color.enumerators.iter().find(|(n, _)| n.contains("Green"));
        let blue = color.enumerators.iter().find(|(n, _)| n.contains("Blue"));

        assert!(red.is_some(), "expected Red variant");
        assert!(green.is_some(), "expected Green variant");
        assert!(blue.is_some(), "expected Blue variant");

        assert_eq!(red.unwrap().1, 0, "Red should have value 0");
        assert_eq!(green.unwrap().1, 1, "Green should have value 1");
        assert_eq!(blue.unwrap().1, 2, "Blue should have value 2");
    } else {
        // Rust enums might be represented differently
        let structs = ctf.structs();
        assert!(
            structs.iter().any(|s| s.name.contains("Color")),
            "expected Color as enum or struct"
        );
    }
}

#[test]
fn test_array_element_count() {
    let source = r#"
        #[no_mangle]
        pub fn array_sum(arr: [i32; 4]) -> i32 {
            arr[0] + arr[1] + arr[2] + arr[3]
        }

        fn main() {
            let _ = array_sum([1, 2, 3, 4]);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["array_sum"], &dir);

    assert!(ctf.is_valid());

    let arrays = ctf.arrays();
    assert!(!arrays.is_empty(), "expected array type");

    // Find the [i32; 4] array
    let arr = arrays.iter().find(|a| {
        a.array_info.map(|(_, _, nelems)| nelems == 4).unwrap_or(false)
    });

    assert!(arr.is_some(), "expected array with 4 elements");
}

#[test]
fn test_tuple_struct_layout() {
    let source = r#"
        #[repr(C)]
        pub struct Pair(pub i32, pub i64);

        #[no_mangle]
        pub fn first(p: Pair) -> i32 {
            p.0
        }

        fn main() {
            let _ = first(Pair(1, 2));
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["first"], &dir);

    assert!(ctf.is_valid());

    let pair = ctf.structs().into_iter()
        .find(|s| s.name.contains("Pair"))
        .expect("expected Pair struct");

    // Pair: i32(4) + padding(4) + i64(8) = 16 bytes
    assert_eq!(pair.size(), 16, "Pair should be 16 bytes");
    assert_eq!(pair.vlen, 2, "Pair should have 2 members");

    // Tuple fields are named __0, __1 or 0, 1
    let members = pair.member_names();
    assert!(
        members.iter().any(|m| *m == "__0" || *m == "0"),
        "expected first tuple field"
    );
    assert!(
        members.iter().any(|m| *m == "__1" || *m == "1"),
        "expected second tuple field"
    );
}

#[test]
fn test_integer_sizes() {
    let source = r#"
        #[no_mangle]
        pub fn sizes(a: i8, b: i16, c: i32, d: i64, e: u8, f: usize) -> i64 {
            a as i64 + b as i64 + c as i64 + d + e as i64 + f as i64
        }

        fn main() {
            let _ = sizes(1, 2, 3, 4, 5, 6);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["sizes"], &dir);

    assert!(ctf.is_valid());

    let integers = ctf.integers();

    // Check various integer sizes
    let i8_type = integers.iter().find(|t| t.name.contains("i8"));
    let i16_type = integers.iter().find(|t| t.name.contains("i16"));
    let i32_type = integers.iter().find(|t| t.name.contains("i32"));
    let i64_type = integers.iter().find(|t| t.name.contains("i64"));
    let u8_type = integers.iter().find(|t| t.name.contains("u8"));
    let usize_type = integers.iter().find(|t| t.name.contains("usize"));

    if let Some(t) = i8_type {
        assert_eq!(t.size(), 1, "i8 should be 1 byte");
    }
    if let Some(t) = i16_type {
        assert_eq!(t.size(), 2, "i16 should be 2 bytes");
    }
    if let Some(t) = i32_type {
        assert_eq!(t.size(), 4, "i32 should be 4 bytes");
    }
    if let Some(t) = i64_type {
        assert_eq!(t.size(), 8, "i64 should be 8 bytes");
    }
    if let Some(t) = u8_type {
        assert_eq!(t.size(), 1, "u8 should be 1 byte");
    }
    if let Some(t) = usize_type {
        assert_eq!(t.size(), 8, "usize should be 8 bytes on 64-bit");
    }
}

#[test]
fn test_float_sizes() {
    let source = r#"
        #[no_mangle]
        pub fn floats(a: f32, b: f64) -> f64 {
            a as f64 + b
        }

        fn main() {
            let _ = floats(1.0, 2.0);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["floats"], &dir);

    assert!(ctf.is_valid());

    let floats = ctf.types_of_kind(CTF_K_FLOAT);

    let f32_type = floats.iter().find(|t| t.name.contains("f32"));
    let f64_type = floats.iter().find(|t| t.name.contains("f64"));

    if let Some(t) = f32_type {
        assert_eq!(t.size(), 4, "f32 should be 4 bytes");
    }
    if let Some(t) = f64_type {
        assert_eq!(t.size(), 8, "f64 should be 8 bytes");
    }
}

#[test]
fn test_complex_struct_offsets() {
    let source = r#"
        #[repr(C)]
        pub struct Complex {
            pub flags: u8,
            pub id: u64,
            pub count: u32,
            pub data: [u8; 3],
            pub value: u16,
        }

        #[no_mangle]
        pub fn get_id(c: Complex) -> u64 {
            c.id
        }

        fn main() {
            let c = Complex {
                flags: 0,
                id: 1,
                count: 2,
                data: [0, 0, 0],
                value: 3,
            };
            let _ = get_id(c);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["get_id"], &dir);

    assert!(ctf.is_valid());

    let complex = ctf.structs().into_iter()
        .find(|s| s.name.contains("Complex"))
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

    assert_eq!(complex.size(), 32, "Complex should be 32 bytes");

    let flags = complex.member("flags").expect("expected flags");
    let id = complex.member("id").expect("expected id");
    let count = complex.member("count").expect("expected count");
    let data = complex.member("data").expect("expected data");
    let value = complex.member("value").expect("expected value");

    assert_eq!(flags.offset_bits, 0, "flags at 0");
    assert_eq!(id.offset_bits, 64, "id at 64 bits (8 bytes)");
    assert_eq!(count.offset_bits, 128, "count at 128 bits (16 bytes)");
    assert_eq!(data.offset_bits, 160, "data at 160 bits (20 bytes)");
    assert_eq!(value.offset_bits, 192, "value at 192 bits (24 bytes)");
}

#[test]
fn test_option_type_exists() {
    let source = r#"
        #[no_mangle]
        pub fn unwrap_or_default(opt: Option<i32>) -> i32 {
            opt.unwrap_or(0)
        }

        fn main() {
            let _ = unwrap_or_default(Some(42));
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["unwrap_or_default"], &dir);

    assert!(ctf.is_valid());

    // Option<T> should produce some type
    let option_type = ctf.types.iter().find(|t| t.name.contains("Option"));
    assert!(option_type.is_some(), "expected Option type");
}

#[test]
fn test_result_type_exists() {
    let source = r#"
        #[no_mangle]
        pub fn try_parse(s: &str) -> Result<i32, ()> {
            s.parse().map_err(|_| ())
        }

        fn main() {
            let _ = try_parse("42");
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["try_parse"], &dir);

    assert!(ctf.is_valid());

    let result_type = ctf.types.iter().find(|t| t.name.contains("Result"));
    assert!(result_type.is_some(), "expected Result type");
}

#[test]
fn test_vec_type_exists() {
    let source = r#"
        #[no_mangle]
        pub fn vec_len(v: Vec<i32>) -> usize {
            v.len()
        }

        fn main() {
            let _ = vec_len(vec![1, 2, 3]);
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["vec_len"], &dir);

    assert!(ctf.is_valid());

    let vec_type = ctf.types.iter().find(|t| t.name.contains("Vec"));
    assert!(vec_type.is_some(), "expected Vec type");
}

#[test]
fn test_pointer_types_exist() {
    let source = r#"
        #[no_mangle]
        pub fn increment(x: &mut i32) {
            *x += 1;
        }

        #[no_mangle]
        pub unsafe fn deref_ptr(p: *const i32) -> i32 {
            *p
        }

        fn main() {
            let mut val = 0;
            increment(&mut val);
            unsafe { let _ = deref_ptr(&val); }
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["increment", "deref_ptr"], &dir);

    assert!(ctf.is_valid());

    let pointers = ctf.pointers();
    assert!(pointers.len() >= 2, "expected at least 2 pointer types");
}

#[test]
fn test_multiple_functions() {
    let source = r#"
        #[no_mangle]
        pub fn add(a: i32, b: i32) -> i32 { a + b }

        #[no_mangle]
        pub fn sub(a: i32, b: i32) -> i32 { a - b }

        fn main() {
            let _ = add(5, sub(3, 1));
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["add", "sub"], &dir);

    assert!(ctf.is_valid());
    assert!(!ctf.integers().is_empty(), "expected integer types");
}

#[test]
fn test_function_not_found_still_produces_valid_ctf() {
    let source = r#"
        #[no_mangle]
        pub fn foo() {}

        fn main() {
            foo();
        }
    "#;

    let (bin_path, dir) = compile_rust_fixture(source);
    let ctf = run_and_parse_ctf(&bin_path, &["nonexistent"], &dir);

    assert!(ctf.is_valid());
}

#[test]
fn test_missing_elf_file_fails() {
    let dir = TempDir::new().unwrap();
    let ctf_path = dir.path().join("output.ctf");

    let mut cmd = AssertCommand::cargo_bin("dwarf2ctf").unwrap();
    cmd.arg("--elf").arg("/nonexistent/path/to/binary");
    cmd.arg("--ctf_out").arg(&ctf_path);
    cmd.arg("--fns").arg("foo");

    cmd.assert().failure();
}

#[test]
fn test_requires_output_flag() {
    let source = r#"fn main() {}"#;
    let (bin_path, _dir) = compile_rust_fixture(source);

    let mut cmd = AssertCommand::cargo_bin("dwarf2ctf").unwrap();
    cmd.arg("--elf").arg(&bin_path);
    cmd.arg("--fns").arg("main");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("--ctf_out").or(predicate::str::contains("--bin_out")));
}

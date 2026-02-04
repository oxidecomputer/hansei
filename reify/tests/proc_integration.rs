//! Integration tests for process introspection using CTF.
//!
//! These tests generate a test binary with known types and values,
//! then use CTF to read those values from the running process.
//!
//! Only runs on illumos where libproc is available.

#![cfg(target_os = "illumos")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use durin::read::CtfReader;
use proc::Proc;
use reify::{ParseCtx, ParseWithCtf};
use tempfile::TempDir;

const TEST_PROGRAM: &str = r#"
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[no_mangle]
pub static GLOBAL_POINT: Point = Point { x: 42, y: 100 };

#[no_mangle]
pub static GLOBAL_U64: u64 = 0xDEADBEEF_CAFEBABE;

#[no_mangle]
pub static GLOBAL_ARRAY: [i32; 4] = [1, 2, 3, 4];

fn main() {
    // Park the main thread so we can attach to the process
    std::thread::park();
}
"#;

/// Set up a test binary by creating a cargo project, writing the test program,
/// and building it.
fn setup_test_binary() -> TempDir {
    let tmpdir = tempfile::tempdir().expect("failed to create temp dir");

    // Initialize cargo project
    let status = Command::new("cargo")
        .args(["init", "--name", "test_types"])
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run cargo init");
    assert!(status.success(), "cargo init failed");

    // Write test program
    std::fs::write(tmpdir.path().join("src/main.rs"), TEST_PROGRAM)
        .expect("failed to write test program");

    // Build with debug info
    let status = Command::new("cargo")
        .args(["build"])
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "cargo build failed");

    tmpdir
}

/// Generate CTF from the test binary using dwarf2ctf.
fn generate_ctf(tmpdir: &Path) -> PathBuf {
    let binary = tmpdir.join("target/debug/test_types");
    let ctf_path = tmpdir.join("test_types.ctf");

    // Get the path to dwarf2ctf - it should be in the same workspace
    let status = Command::new("cargo")
        .args([
            "run",
            "-p",
            "dwarf2ctf",
            "--",
            binary.to_str().unwrap(),
            "-t",
            "test_types::Point",
            "-t",
            "u64",
            "-t",
            "[i32; 4]",
            "-c",
            ctf_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run dwarf2ctf");
    assert!(status.success(), "dwarf2ctf failed");

    ctf_path
}

/// Spawn the test binary and return the child process.
fn spawn_test_binary(tmpdir: &Path) -> Child {
    let binary = tmpdir.join("target/debug/test_types");
    Command::new(&binary)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn test binary")
}

/// Context for reading types from a process using CTF.
struct TestContext<'a> {
    ctf: &'a CtfReader,
    proc: &'a Proc,
}

impl<'a> ParseCtx<'a> for TestContext<'a> {
    fn ctf(&self) -> &'a CtfReader {
        self.ctf
    }

    fn proc(&self) -> &'a Proc {
        self.proc
    }
}

/// Find a symbol's address in the process.
fn find_symbol_addr(proc: &Proc, name: &str) -> Option<u64> {
    let symbols = proc.symbols().ok()?;
    symbols
        .iter()
        .find(|s| s.name() == name)
        .map(|s| s.value())
}

#[test]
fn read_global_point() {
    let tmpdir = setup_test_binary();
    let ctf_path = generate_ctf(tmpdir.path());

    // Spawn the test binary
    let mut child = spawn_test_binary(tmpdir.path());
    let pid = child.id();

    // Give the process time to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Load CTF and attach to process
    let ctf_bytes = std::fs::read(&ctf_path).expect("failed to read CTF");
    let ctf = CtfReader::load(&ctf_bytes).expect("failed to load CTF");
    let proc = Proc::open_pid(pid as i32).expect("failed to open process");

    let ctx = TestContext { ctf: &ctf, proc: &proc };

    // Find the GLOBAL_POINT symbol
    let addr = find_symbol_addr(&proc, "GLOBAL_POINT")
        .expect("GLOBAL_POINT symbol not found");

    // Find the Point type in CTF
    let point_ty = ctf
        .find_ty("test_types::Point", durin::TypeKind::Struct)
        .expect("Point type not found in CTF");

    // Read the value
    let info = reify::TypeInfo::from_addr(&ctx, point_ty, addr)
        .expect("failed to read type")
        .expect("address unmapped");

    // Extract x and y values
    let x: i32 = info.member(&ctx, "x").expect("x member").parse(&ctx).expect("parse x");
    let y: i32 = info.member(&ctx, "y").expect("y member").parse(&ctx).expect("parse y");

    assert_eq!(x, 42, "x value mismatch");
    assert_eq!(y, 100, "y value mismatch");

    // Clean up
    child.kill().ok();
    child.wait().ok();
}

#[test]
fn read_global_u64() {
    let tmpdir = setup_test_binary();
    let ctf_path = generate_ctf(tmpdir.path());

    let mut child = spawn_test_binary(tmpdir.path());
    let pid = child.id();

    std::thread::sleep(std::time::Duration::from_millis(100));

    let ctf_bytes = std::fs::read(&ctf_path).expect("failed to read CTF");
    let ctf = CtfReader::load(&ctf_bytes).expect("failed to load CTF");
    let proc = Proc::open_pid(pid as i32).expect("failed to open process");

    let ctx = TestContext { ctf: &ctf, proc: &proc };

    let addr = find_symbol_addr(&proc, "GLOBAL_U64")
        .expect("GLOBAL_U64 symbol not found");

    let u64_ty = ctf
        .find_ty("u64", durin::TypeKind::Integer)
        .expect("u64 type not found in CTF");

    let info = reify::TypeInfo::from_addr(&ctx, u64_ty, addr)
        .expect("failed to read type")
        .expect("address unmapped");

    let value: u64 = info.parse(&ctx).expect("parse u64");
    assert_eq!(value, 0xDEADBEEF_CAFEBABE, "u64 value mismatch");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn read_global_array() {
    let tmpdir = setup_test_binary();
    let ctf_path = generate_ctf(tmpdir.path());

    let mut child = spawn_test_binary(tmpdir.path());
    let pid = child.id();

    std::thread::sleep(std::time::Duration::from_millis(100));

    let ctf_bytes = std::fs::read(&ctf_path).expect("failed to read CTF");
    let ctf = CtfReader::load(&ctf_bytes).expect("failed to load CTF");
    let proc = Proc::open_pid(pid as i32).expect("failed to open process");

    let ctx = TestContext { ctf: &ctf, proc: &proc };

    let addr = find_symbol_addr(&proc, "GLOBAL_ARRAY")
        .expect("GLOBAL_ARRAY symbol not found");

    let array_ty = ctf
        .types()
        .iter()
        .find(|t| t.kind() == durin::TypeKind::Array)
        .expect("array type not found in CTF");

    let info = reify::TypeInfo::from_addr(&ctx, array_ty, addr)
        .expect("failed to read type")
        .expect("address unmapped");

    let values: [i32; 4] = info.parse(&ctx).expect("parse array");
    assert_eq!(values, [1, 2, 3, 4], "array values mismatch");

    child.kill().ok();
    child.wait().ok();
}

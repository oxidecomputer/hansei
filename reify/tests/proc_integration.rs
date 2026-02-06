//! Integration tests for process introspection using CTF.
//!
//! These tests generate a test binary with known types and values,
//! then use CTF to read those values from the running process.
//!
//! Only runs on illumos where libproc is available.

#![cfg(target_os = "illumos")]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use durin::read::CtfReader;
use proc::{Mappings, Proc};
use reify::ParseCtx;
use reify::ParseWithCtf;
use tempfile::TempDir;

const TEST_PROGRAM: &str = r#"
use std::io::Write;

pub struct Point {
    pub x: i32,
    pub y: i32,
}

pub enum Foo {
    A(u64),
    B(i8),
}

#[unsafe(no_mangle)]
pub static GLOBAL_POINT: Point = Point { x: 42, y: 100 };

#[unsafe(no_mangle)]
pub static GLOBAL_FOO: Foo = Foo::A(500);

fn main() {
    // Signal to parent that we've started.
    let mut stdout = std::io::stdout();
    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();

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
            "test_types::Foo",
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
    let mut child = Command::new(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn test binary");

    let mut stdout = child.stdout.take().unwrap();
    let mut buf = [0u8; 1];

    // Wait for the child to start and write to stdout.
    match stdout.read(&mut buf) {
        Ok(1) => return child,
        _ => unreachable!(),
    }
}

/// Context for reading types from a process using CTF.
struct TestContext<'a> {
    ctf: &'a CtfReader,
    proc: &'a Proc,
    mappings: &'a Mappings,
}

impl<'a> ParseCtx<'a> for TestContext<'a> {
    fn ctf(&self) -> &'a CtfReader {
        self.ctf
    }

    fn proc(&self) -> &'a Proc {
        self.proc
    }

    fn mappings(&self) -> &'a Mappings {
        self.mappings
    }
}

#[derive(PartialEq, Debug)]
enum Foo {
    A(u64),
    B(i8),
}

impl<'a> ParseWithCtf<'a, TestContext<'a>> for Foo {
    fn parse_with_ctf(
        ctx: &TestContext<'a>,
        info: &reify::TypeInfoRef<'_, 'a>,
    ) -> reify::Result<Self> {
        match info.active_variant(ctx)? {
            ("A", variant_info) => {
                let val = variant_info.parse(ctx)?;
                Ok(Foo::A(val))
            }
            ("B", variant_info) => {
                let val = variant_info.parse(ctx)?;
                Ok(Foo::B(val))
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn read_global_point() {
    let tmpdir = setup_test_binary();
    let ctf_path = generate_ctf(tmpdir.path());

    // Spawn the test binary
    let mut child = spawn_test_binary(tmpdir.path());
    let pid = child.id();

    // Give the process time to start
    //std::thread::sleep(std::time::Duration::from_millis(100));

    // Load CTF and attach to process
    let ctf_bytes = std::fs::read(&ctf_path).expect("failed to read CTF");
    let ctf = CtfReader::load(&ctf_bytes).expect("failed to load CTF");
    let proc = Proc::grab_pid(pid).expect("failed to open process");
    let mappings = proc.mappings().expect("failed to get mappings");

    let ctx = TestContext {
        ctf: &ctf,
        proc: &proc,
        mappings: &mappings,
    };

    // Find the GLOBAL_POINT symbol
    let addr = proc
        .lookup_symbol_by_name("GLOBAL_POINT")
        .expect("GLOBAL_POINT symbol not found")
        .st_value;

    // Find the Point type in CTF
    let point_ty = ctf
        .find_ty("test_types::Point", durin::TypeKind::Struct)
        .expect("Point type not found in CTF");

    // Read the value
    let info = reify::TypeInfo::from_addr(&ctx, point_ty, addr)
        .expect("failed to read type")
        .expect("address unmapped");

    // Extract x and y values
    let x: i32 = info
        .member(&ctx, "x")
        .expect("x member")
        .parse(&ctx)
        .expect("parse x");
    let y: i32 = info
        .member(&ctx, "y")
        .expect("y member")
        .parse(&ctx)
        .expect("parse y");

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

    let ctf_bytes = std::fs::read(&ctf_path).expect("failed to read CTF");
    let ctf = CtfReader::load(&ctf_bytes).expect("failed to load CTF");
    let proc = Proc::grab_pid(pid).expect("failed to open process");
    let mappings = proc.mappings().expect("failed to get mappings");

    let ctx = TestContext {
        ctf: &ctf,
        proc: &proc,
        mappings: &mappings,
    };

    let addr = proc
        .lookup_symbol_by_name("GLOBAL_FOO")
        .expect("GLOBAL_FOO symbol not found")
        .st_value;

    let foo_ty = ctf
        .find_ty("test_types::Foo", durin::TypeKind::Struct)
        .expect("Foo type not found in CTF");

    let info = reify::TypeInfo::from_addr(&ctx, foo_ty, addr)
        .expect("failed to read type")
        .expect("address unmapped");

    let value: Foo = info.parse(&ctx).expect("parse u64");
    assert_eq!(value, Foo::A(500), "Foo value mismatch");

    child.kill().ok();
    child.wait().ok();
}

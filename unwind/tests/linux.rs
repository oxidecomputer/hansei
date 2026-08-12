//! Unwinding a real core, on the one platform where this workspace can
//! make one without a second machine.
//!
//! The unwinder had no tests at all before, its only caller then being
//! a DWARF path whose own suite needed a core nobody checks in. What it
//! exercises here is the part that used to be hardcoded — a
//! backtrace that starts in libc and ends in the executable crosses two
//! objects, and reaching the fixture's own frames from a thread parked
//! in the kernel means the loader's and libc's unwind tables were found
//! and used.
//!
//! The target is `test-programs`' `core-target`, dumped with gdb's
//! `gcore` the same way `proc`'s own Linux suite does it; see
//! `proc/tests/linux.rs` for why it is done that way and not with
//! `core_pattern`.

#![cfg(target_os = "linux")]

use proc::{Proc, Target};

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const PROGRAM: &str = "core-target";
/// The fixture parks its workers here, at the bottom of every worker
/// stack. The name is mangled in the symtab, so it is matched after
/// demangling.
const PARK_FN: &str = "core_target::park_forever";

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

/// Build the fixture, run it to its abort under gdb, and dump it there.
fn core() -> &'static Path {
    static CORE: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &CORE
        .get_or_init(|| {
            let test_programs = workspace_root().join("test-programs");
            let status = Command::new(test_programs.join("regen.sh"))
                .arg(PROGRAM)
                .status()
                .expect("failed to run regen.sh");
            assert!(
                status.success(),
                "regen.sh failed; is the pinned toolchain installed?"
            );
            let fixture = test_programs.join("fixtures/bin").join(PROGRAM);

            let dir = tempfile::tempdir().expect("failed to create a tempdir");
            let core = dir.path().join("core");
            let out = Command::new("gdb")
                .args(["-batch", "-nx", "-ex", "run", "-ex"])
                .arg(format!("gcore {}", core.display()))
                .args(["-ex", "kill", "--args"])
                .arg(&fixture)
                .env("MALLOC_ARENA_MAX", "1")
                .output()
                .unwrap_or_else(|e| panic!("failed to run gdb ({e}); it has to be on PATH"));
            assert!(
                core.exists(),
                "gdb wrote no core:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (dir, core)
        })
        .1
}

fn demangled(frames: &unwind::Backtrace) -> Vec<String> {
    frames
        .frames
        .iter()
        .map(|f| match &f.symbol {
            Some(s) => format!("{:#}", rustc_demangle::demangle(&s.name)),
            None => format!("{:#x}", f.pc),
        })
        .collect()
}

/// Every thread unwinds, and the walk crosses from the object it
/// stopped in back into the executable.
#[test]
fn test_every_thread_unwinds() {
    let p = Proc::open_core(core()).expect("failed to open the core");
    let stacks = unwind::load_frames(&p).expect("failed to unwind the core");

    let lwps = p.lwps().unwrap();
    assert_eq!(stacks.len(), lwps.len(), "not every thread got a backtrace");
    assert_eq!(
        lwps.len(),
        4,
        "the fixture runs a main thread and 3 workers"
    );

    for (tid, bt) in &stacks {
        let names = demangled(bt);
        assert!(
            bt.frames.len() >= 2,
            "tid {tid} unwound {} frame(s): {names:#?}",
            bt.frames.len()
        );
        // The innermost frame is where the thread actually stopped.
        assert_eq!(bt.frames[0].pc, bt.frames[0].regs.rip);
    }
}

/// The workers are parked in the kernel, so their stacks start in libc
/// and have to be walked back into the executable to reach the fixture.
/// Getting there means an object other than the executable supplied the
/// unwind information for the frames in between — the thing the
/// unwinder used to hardcode.
#[test]
fn test_backtraces_cross_objects() {
    let p = Proc::open_core(core()).expect("failed to open the core");
    let stacks = unwind::load_frames(&p).expect("failed to unwind the core");
    let maps = p.mappings().unwrap();

    let exec = p.exec_name().unwrap();
    let exec_ranges: Vec<_> = maps
        .iter()
        .filter(|m| m.path.as_deref() == exec.to_str())
        .map(|m| m.range())
        .collect();
    let in_exec = |pc: u64| exec_ranges.iter().any(|r| r.contains(&pc));

    let parked: Vec<_> = stacks
        .iter()
        .filter(|(_, bt)| demangled(bt).iter().any(|n| n.contains(PARK_FN)))
        .collect();
    assert_eq!(
        parked.len(),
        3,
        "expected the 3 workers to be parked; stacks were {:#?}",
        stacks
            .iter()
            .map(|(t, b)| (t, demangled(b)))
            .collect::<Vec<_>>()
    );

    for (tid, bt) in parked {
        let names = demangled(bt);
        assert!(
            !in_exec(bt.frames[0].pc),
            "tid {tid} did not stop outside the executable: {names:#?}"
        );
        assert!(
            bt.frames.iter().any(|f| in_exec(f.pc)),
            "tid {tid} never got back into the executable: {names:#?}"
        );
    }
}

/// The thread that called `abort` has libc's own frames below it, which
/// only libc's unwind tables describe.
#[test]
fn test_the_aborting_thread_unwinds_through_libc() {
    let p = Proc::open_core(core()).expect("failed to open the core");
    let stacks = unwind::load_frames(&p).expect("failed to unwind the core");

    let aborted = stacks
        .values()
        .map(demangled)
        .find(|names| {
            names
                .iter()
                .any(|n| n.contains("abort") || n.contains("raise"))
        })
        .unwrap_or_else(|| {
            panic!(
                "no thread looks like the one that aborted: {:#?}",
                stacks.values().map(demangled).collect::<Vec<_>>()
            )
        });

    assert!(
        aborted.iter().any(|n| n.contains("core_target")),
        "the aborting thread never reached the fixture's own code: {aborted:#?}"
    );
}

/// The rendered form callers actually print.
#[test]
fn test_stack_trace_renders_frames() {
    let p = Proc::open_core(core()).expect("failed to open the core");
    let stacks = unwind::load_frames(&p).expect("failed to unwind the core");
    let bt = stacks.values().next().expect("at least one thread");

    let lines = bt.stack_trace(3);
    assert!(lines.len() <= 3);
    assert_eq!(lines.len(), bt.frames.len().min(3));
    for (line, frame) in lines.iter().zip(&bt.frames) {
        assert!(
            line.starts_with(&format!("{:#018x} ", frame.regs.rip)),
            "{line}"
        );
    }
}

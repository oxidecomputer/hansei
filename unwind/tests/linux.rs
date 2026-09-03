// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
///
/// The build goes once per *run*, not once per process: under nextest
/// each test is its own process, and proc's core suite reads the very
/// same binary — a rebuild landing while another test's gdb runs it
/// turns that test's mapped path into a deleted file. The stamp and
/// digest match proc's for the same program, so whichever suite gets
/// there first builds and every other caller skips.
fn core() -> &'static Path {
    static CORE: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &CORE
        .get_or_init(|| {
            let test_programs = workspace_root().join("test-programs");
            testrun::once_per_run(
                &test_programs.join("fixtures/.built").join(PROGRAM),
                || built_from(&test_programs),
                || {
                    let status = Command::new(test_programs.join("regen.sh"))
                        .arg(PROGRAM)
                        .status()
                        .expect("failed to run regen.sh");
                    assert!(
                        status.success(),
                        "regen.sh failed; is the pinned toolchain installed?"
                    );
                },
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

/// What the fixture binary is built from — byte-identical to the proc
/// suite's digest for the same program, so the two suites agree on the
/// stamp and only one of them builds.
fn built_from(dir: &Path) -> String {
    let mut inputs = testrun::Inputs::new();
    inputs
        .file(&dir.join("src/lib.rs"))
        .file(&dir.join("src/bin").join(format!("{PROGRAM}.rs")))
        .file(&dir.join("Cargo.toml"))
        .file(&dir.join("Cargo.lock"))
        .file(&dir.join("regen.sh"));
    inputs.finish()
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
    let stacks = unwind::load_frames(&p)
        .expect("failed to unwind the core")
        .stacks;

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
        // Every backing file is on this machine, so every walk should
        // reach the CFI's own bottom: a truncation here means CFI that
        // should have loaded did not.
        assert!(
            bt.truncated.is_none(),
            "tid {tid}'s walk ended early ({:?}): {names:#?}",
            bt.truncated
        );
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
    let stacks = unwind::load_frames(&p)
        .expect("failed to unwind the core")
        .stacks;
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
    let stacks = unwind::load_frames(&p)
        .expect("failed to unwind the core")
        .stacks;

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

/// A copy of the core cut down to what the kernel's default
/// `coredump_filter` would have written: a file-backed read-only
/// mapping keeps only its first page, and everything else about it —
/// the ELF header past that page, `.eh_frame`, the symtab — has to
/// come from the backing file on disk. gdb's `gcore` dumps those pages
/// wholesale, which is why a suite built on it alone never notices a
/// reader that cannot cross the dumped/on-disk seam.
///
/// The cut is done to the program headers of the copy: every
/// non-writable `PT_LOAD` that lands in a mapping with a backing path
/// gets its `p_filesz` clamped to one page. Offsets all stay valid —
/// readers just find less of the segment in the file.
fn kernel_shaped(core: &Path) -> (tempfile::TempDir, PathBuf) {
    const PAGE: u64 = 4096;
    const PT_LOAD: u32 = 1;
    const PF_W: u32 = 2;

    let pathed: Vec<std::ops::Range<u64>> = {
        let p = Proc::open_core(core).expect("failed to open the core");
        let maps = p.mappings().unwrap();
        maps.iter()
            .filter(|m| m.path.is_some())
            .map(|m| m.range())
            .collect()
    };

    let mut bytes = std::fs::read(core).expect("failed to read the core");
    let e_phoff = u64::from_le_bytes(bytes[0x20..0x28].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(bytes[0x36..0x38].try_into().unwrap()) as u64;
    let e_phnum = u16::from_le_bytes(bytes[0x38..0x3a].try_into().unwrap()) as u64;

    let mut cut = 0;
    for i in 0..e_phnum {
        let at = (e_phoff + i * e_phentsize) as usize;
        let p_type = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let p_flags = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(bytes[at + 16..at + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(bytes[at + 32..at + 40].try_into().unwrap());
        if p_type != PT_LOAD
            || p_flags & PF_W != 0
            || p_filesz <= PAGE
            || !pathed.iter().any(|r| r.contains(&p_vaddr))
        {
            continue;
        }
        bytes[at + 32..at + 40].copy_from_slice(&PAGE.to_le_bytes());
        cut += 1;
    }
    // A cut that removes nothing is a fixture change, not a pass: gcore
    // stopped dumping these pages itself, and the test is now vacuous.
    assert!(cut > 0, "no segment was cut; what does gcore dump now?");

    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let doctored = dir.path().join("core");
    std::fs::write(&doctored, bytes).expect("failed to write the doctored core");
    (dir, doctored)
}

/// The workers still unwind out of libc and back into the executable
/// when the core carries only the first page of every file-backed
/// read-only mapping — the shape the kernel actually dumps, where the
/// unwind tables exist only in the files on disk.
#[test]
fn test_a_kernel_shaped_core_unwinds() {
    let (_dir, doctored) = kernel_shaped(core());
    let p = Proc::open_core(&doctored).expect("failed to open the doctored core");
    let stacks = unwind::load_frames(&p)
        .expect("failed to unwind the doctored core")
        .stacks;

    let parked = stacks
        .values()
        .map(demangled)
        .filter(|names| names.iter().any(|n| n.contains(PARK_FN)))
        .count();
    assert_eq!(
        parked,
        3,
        "the 3 workers no longer reach {PARK_FN}; stacks were {:#?}",
        stacks.values().map(demangled).collect::<Vec<_>>()
    );
}

/// A copy of the core doctored to look like `tid` called through a null
/// function pointer: its pc is 0, and the address the faulting `call`
/// pushed — the thread's real pc — sits at the top of its stack.
fn with_null_call(core: &Path, tid: u32, rip: u64, rsp: u64) -> (tempfile::TempDir, PathBuf) {
    const PT_LOAD: u32 = 1;
    const PT_NOTE: u32 = 4;
    const NT_PRSTATUS: u32 = 1;
    // Offsets into `struct elf_prstatus`: the thread id, then `pr_reg`,
    // within which `rip` and `rsp` sit at their `user_regs_struct`
    // indices (16 and 19).
    const PR_PID: usize = 32;
    const PR_RIP: usize = 112 + 16 * 8;
    const PR_RSP: usize = 112 + 19 * 8;

    let mut bytes = std::fs::read(core).expect("failed to read the core");
    let e_phoff = u64::from_le_bytes(bytes[0x20..0x28].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(bytes[0x36..0x38].try_into().unwrap()) as u64;
    let e_phnum = u16::from_le_bytes(bytes[0x38..0x3a].try_into().unwrap()) as u64;

    // (p_type, p_offset, p_vaddr, p_filesz) of every program header,
    // read out before any of the bytes they describe are rewritten.
    let phdrs: Vec<(u32, u64, u64, u64)> = (0..e_phnum)
        .map(|i| {
            let at = (e_phoff + i * e_phentsize) as usize;
            let field =
                |o: usize| u64::from_le_bytes(bytes[at + o..at + o + 8].try_into().unwrap());
            (
                u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
                field(8),
                field(16),
                field(32),
            )
        })
        .collect();

    // The faulting call: pc 0, return address pushed at rsp - 8.
    let pushed_at = rsp - 8;
    let &(_, p_offset, p_vaddr, _) = phdrs
        .iter()
        .find(|&&(p_type, _, p_vaddr, p_filesz)| {
            p_type == PT_LOAD && (p_vaddr..p_vaddr + p_filesz).contains(&pushed_at)
        })
        .expect("no dumped segment holds the top of the thread's stack");
    let at = (p_offset + (pushed_at - p_vaddr)) as usize;
    bytes[at..at + 8].copy_from_slice(&rip.to_le_bytes());

    // The thread's registers: walk the note segment to its NT_PRSTATUS.
    let mut patched = false;
    for &(p_type, p_offset, _, p_filesz) in &phdrs {
        if p_type != PT_NOTE {
            continue;
        }
        let mut at = p_offset as usize;
        let end = (p_offset + p_filesz) as usize;
        while at + 12 <= end {
            let word = |o: usize| u32::from_le_bytes(bytes[at + o..at + o + 4].try_into().unwrap());
            let (namesz, descsz, n_type) = (word(0), word(4), word(8));
            let desc = at + 12 + (namesz as usize).next_multiple_of(4);
            if n_type == NT_PRSTATUS
                && u32::from_le_bytes(bytes[desc + PR_PID..desc + PR_PID + 4].try_into().unwrap())
                    == tid
            {
                bytes[desc + PR_RIP..desc + PR_RIP + 8].copy_from_slice(&0u64.to_le_bytes());
                bytes[desc + PR_RSP..desc + PR_RSP + 8].copy_from_slice(&pushed_at.to_le_bytes());
                patched = true;
            }
            at = desc + (descsz as usize).next_multiple_of(4);
        }
    }
    assert!(patched, "no NT_PRSTATUS note carries tid {tid}");

    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let doctored = dir.path().join("core");
    std::fs::write(&doctored, bytes).expect("failed to write the doctored core");
    (dir, doctored)
}

/// A thread that called through a null pointer faults with pc 0, which
/// no CFI describes. The return address the `call` pushed is still at
/// the top of its stack, and popping it by hand recovers the caller —
/// so the doctored thread's backtrace is the null frame followed by
/// exactly the frames the undoctored thread had.
#[test]
fn test_a_null_call_unwinds_to_the_caller() {
    let p = Proc::open_core(core()).expect("failed to open the core");
    let stacks = unwind::load_frames(&p)
        .expect("failed to unwind the core")
        .stacks;

    let (tid, original) = stacks
        .iter()
        .find(|(_, bt)| demangled(bt).iter().any(|n| n.contains(PARK_FN)))
        .expect("no parked worker to doctor");
    let frame0 = &original.frames[0];
    let (_dir, doctored) = with_null_call(core(), *tid, frame0.regs.rip, frame0.regs.rsp);

    let p = Proc::open_core(&doctored).expect("failed to open the doctored core");
    let crashed = &unwind::load_frames(&p)
        .expect("failed to unwind the doctored core")
        .stacks[tid];

    assert_eq!(crashed.frames[0].pc, 0, "the null frame leads the walk");
    let pcs = |frames: &[unwind::Frame]| frames.iter().map(|f| f.pc).collect::<Vec<_>>();
    assert_eq!(
        pcs(&crashed.frames[1..]),
        pcs(&original.frames),
        "past the null frame, the walk is the original thread's"
    );
}

/// The rendered form callers actually print.
#[test]
fn test_stack_trace_renders_frames() {
    let p = Proc::open_core(core()).expect("failed to open the core");
    let stacks = unwind::load_frames(&p)
        .expect("failed to unwind the core")
        .stacks;
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

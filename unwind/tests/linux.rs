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

use proc::{CoreFiles, Proc, Target};

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const PROGRAM: &str = "core-target";
/// The fixture parks its workers here, at the bottom of every worker
/// stack. The name is mangled in the symtab, so it is matched after
/// demangling.
const PARK_FN: &str = "core_target::park_forever";
/// A function symbol the fixture exports unmangled, with an entry
/// address to stop a thread on.
const MARKER_FN: &str = "core_marker_fn";

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
                // gdb stops the target on SIGUSR1 by default; the fixture's
                // signalled worker needs it delivered.
                .args(["-batch", "-nx"])
                .args(["-ex", "handle SIGUSR1 nostop noprint pass"])
                .args(["-ex", "run", "-ex"])
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

/// Every file a core names, copied into a fresh directory at its
/// recorded path beneath it: the sysroot a core read on another
/// machine would be handed.
fn sysroot_of(p: &Proc) -> (tempfile::TempDir, BTreeSet<String>) {
    let files: BTreeSet<String> = p
        .mappings()
        .unwrap()
        .iter()
        .filter_map(|m| m.path.clone())
        .filter(|path| Path::new(path).is_file())
        .collect();
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    for file in &files {
        let at = dir.path().join(file.trim_start_matches('/'));
        std::fs::create_dir_all(at.parent().unwrap()).expect("failed to create a sysroot dir");
        std::fs::copy(file, &at).expect("failed to copy into the sysroot");
    }
    (dir, files)
}

fn with_sysroot(core: &Path, sysroot: &Path) -> Proc {
    let files = CoreFiles {
        sysroot: Some(sysroot),
        ..CoreFiles::default()
    };
    Proc::open_core_with(core, files).expect("failed to open the core with a sysroot")
}

fn every_stack(p: &Proc) -> Vec<Vec<String>> {
    unwind::load_frames(p)
        .expect("failed to unwind the core")
        .stacks
        .values()
        .map(demangled)
        .collect()
}

/// The libraries a core names, copied into a sysroot at their recorded
/// paths, walk and resolve exactly as the files at those paths do —
/// on the kernel-shaped core, where libc's unwind tables and every
/// symbol table exist only in the files. A copy of another build put
/// in libc's place is then refused for its build id, which is how this
/// knows the copies were what got read and not the recorded paths.
#[test]
fn test_a_sysroot_supplies_the_libraries() {
    let (_dir, doctored) = kernel_shaped(core());
    let direct = Proc::open_core(&doctored).expect("failed to open the doctored core");
    let (sysroot, files) = sysroot_of(&direct);

    let through = with_sysroot(&doctored, sysroot.path());
    for file in &files {
        assert_eq!(
            through.backing_file_problem(file),
            None,
            "{file} was not read from the sysroot"
        );
    }
    assert_eq!(every_stack(&through), every_stack(&direct));

    let libc = files
        .iter()
        .find(|f| {
            f.rsplit('/')
                .next()
                .is_some_and(|n| n.starts_with("libc.so"))
        })
        .expect("libc is not mapped");
    let other = files
        .iter()
        .find(|f| *f != libc && f.contains(".so"))
        .expect("no other library is mapped");
    std::fs::copy(other, sysroot.path().join(libc.trim_start_matches('/')))
        .expect("failed to put another build in libc's place");

    let swapped = with_sysroot(&doctored, sysroot.path());
    let problem = swapped
        .backing_file_problem(libc)
        .expect("a library of another build was read");
    assert!(problem.contains("the core recorded"), "{problem}");
    let missing = unwind::load_frames(&swapped)
        .expect("failed to unwind the core")
        .missing;
    let why = &missing
        .iter()
        .find(|m| m.path == *libc)
        .unwrap_or_else(|| panic!("libc's CFI still loaded: {missing:#?}"))
        .why;
    assert!(why.starts_with(&problem), "{why}");

    // Its symbols went with it: the threads stopped in libc resolve
    // there through the sysroot's copy and not through the other build.
    let in_libc: Vec<u64> = direct
        .lwps()
        .unwrap()
        .iter()
        .map(|l| l.regs.rip)
        .filter(|&rip| {
            direct
                .mappings()
                .unwrap()
                .get(rip)
                .is_some_and(|m| m.path.as_deref() == Some(libc.as_str()))
        })
        .collect();
    assert!(!in_libc.is_empty(), "no thread stopped in libc");
    for rip in in_libc {
        assert!(through.lookup_symbol_by_addr(rip).is_some(), "{rip:#x}");
        assert!(swapped.lookup_symbol_by_addr(rip).is_none(), "{rip:#x}");
    }
}

/// A copy of the core doctored to look like `tid` called through a null
/// function pointer: its pc is 0, and the address the faulting `call`
/// pushed — the thread's real pc — sits at the top of its stack.
/// A copy of the core with thread `tid` stopped as if it had just
/// been called from `caller`: the call's return address — the pc
/// `caller` was walked at — pushed at the top of a fresh frame, the
/// thread's pc at `rip`, and its callee-saved registers as `caller`
/// had them, so the walk below the doctored frame is the original
/// thread's from that frame on.
///
/// The thread's registers are in its `NT_PRSTATUS` note, and the
/// pushed word lands in whichever dumped segment holds that stack.
fn with_call_from(
    core: &Path,
    tid: u32,
    rip: u64,
    caller: &proc::Regs,
) -> (tempfile::TempDir, PathBuf) {
    const PT_LOAD: u32 = 1;
    const PT_NOTE: u32 = 4;
    const NT_PRSTATUS: u32 = 1;
    // Offsets into `struct elf_prstatus`: the thread id, then `pr_reg`,
    // within which each register sits at its `user_regs_struct` index.
    const PR_PID: usize = 32;
    const PR_REG: usize = 112;
    const R15: usize = 0;
    const R14: usize = 1;
    const R13: usize = 2;
    const R12: usize = 3;
    const RBP: usize = 4;
    const RBX: usize = 5;
    const RIP: usize = 16;
    const RSP: usize = 19;

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

    // The call: its return address pushed at the caller's rsp - 8.
    let pushed_at = caller.rsp - 8;
    let &(_, p_offset, p_vaddr, _) = phdrs
        .iter()
        .find(|&&(p_type, _, p_vaddr, p_filesz)| {
            p_type == PT_LOAD && (p_vaddr..p_vaddr + p_filesz).contains(&pushed_at)
        })
        .expect("no dumped segment holds the top of the thread's stack");
    let at = (p_offset + (pushed_at - p_vaddr)) as usize;
    bytes[at..at + 8].copy_from_slice(&caller.rip.to_le_bytes());

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
                let mut set = |index: usize, value: u64| {
                    let at = desc + PR_REG + index * 8;
                    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
                };
                set(RIP, rip);
                set(RSP, pushed_at);
                set(RBP, caller.rbp);
                set(RBX, caller.rbx);
                set(R12, caller.r12);
                set(R13, caller.r13);
                set(R14, caller.r14);
                set(R15, caller.r15);
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

/// The parked worker's walk, and its id: the thread the doctoring
/// tests rebuild a frame on.
fn parked_worker(
    stacks: &std::collections::BTreeMap<u32, unwind::Backtrace>,
) -> (u32, &unwind::Backtrace) {
    let (tid, bt) = stacks
        .iter()
        .find(|(_, bt)| demangled(bt).iter().any(|n| n.contains(PARK_FN)))
        .expect("no parked worker to doctor");
    (*tid, bt)
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

    let (tid, original) = parked_worker(&stacks);
    let (_dir, doctored) = with_call_from(core(), tid, 0, &original.frames[0].regs);

    let p = Proc::open_core(&doctored).expect("failed to open the doctored core");
    let crashed = &unwind::load_frames(&p)
        .expect("failed to unwind the doctored core")
        .stacks[&tid];

    assert_eq!(crashed.frames[0].pc, 0, "the null frame leads the walk");
    let pcs = |frames: &[unwind::Frame]| frames.iter().map(|f| f.pc).collect::<Vec<_>>();
    assert_eq!(
        pcs(&crashed.frames[1..]),
        pcs(&original.frames),
        "past the null frame, the walk is the original thread's"
    );
}

/// A thread stopped on a function's first instruction — the `push`
/// that a stack overflow faults in, a leaf's first load through a bad
/// pointer — is looked up where it stopped, not one byte back in
/// whatever precedes the function. Here the parked worker is rebuilt
/// as if `park_forever`'s frame had just called `core_marker_fn`: the
/// doctored walk is that function's entry frame followed by exactly
/// the original frames from `park_forever` down, and the entry frame
/// is named for the function it is in. Looked up one byte back, the
/// walk pops through the preceding function's last row and lands
/// somewhere else.
#[test]
fn test_a_stop_at_a_function_entry_pops_its_caller() {
    let p = Proc::open_core(core()).expect("failed to open the core");
    let stacks = unwind::load_frames(&p)
        .expect("failed to unwind the core")
        .stacks;
    let entry = p
        .lookup_symbol_by_name(MARKER_FN)
        .expect("the fixture's marker function is in the symtab")
        .st_value;

    let (tid, original) = parked_worker(&stacks);
    let names = demangled(original);
    let park = names
        .iter()
        .position(|n| n.contains(PARK_FN))
        .expect("the worker is parked");
    let (_dir, doctored) = with_call_from(core(), tid, entry, &original.frames[park].regs);

    let p = Proc::open_core(&doctored).expect("failed to open the doctored core");
    let stopped = &unwind::load_frames(&p)
        .expect("failed to unwind the doctored core")
        .stacks[&tid];

    let pcs = |frames: &[unwind::Frame]| frames.iter().map(|f| f.pc).collect::<Vec<_>>();
    assert_eq!(
        pcs(&stopped.frames[..1]),
        [entry],
        "the entry frame leads the walk: {:#?}",
        demangled(stopped)
    );
    assert_eq!(
        pcs(&stopped.frames[1..]),
        pcs(&original.frames[park..]),
        "past the entry frame, the walk is the original thread's from the caller down:\n{:#?}\nagainst\n{:#?}",
        demangled(stopped),
        &names[park..]
    );
    assert_eq!(demangled(stopped)[0], MARKER_FN);
    assert!(stopped.frames[0].interrupted && !stopped.frames[1].interrupted);
    assert_eq!(stopped.truncated, None, "{:#?}", demangled(stopped));
}

/// One worker parks inside a signal handler, so its stack carries the
/// trampoline the kernel laid between the handler and the frame it
/// interrupted. The walk crosses it — the trampoline's CFI restores
/// every register by expression, out of the ucontext — marks it, and
/// lands on an interrupted frame below which the fixture's own
/// frames follow. Every backing object is on this machine, so the
/// walk still reaches the bottom.
#[test]
fn test_a_signal_handler_frame_is_crossed_and_marked() {
    let p = Proc::open_core(core()).expect("failed to open the core");
    let stacks = unwind::load_frames(&p)
        .expect("failed to unwind the core")
        .stacks;

    let with: Vec<_> = stacks
        .iter()
        .filter(|(_, bt)| bt.frames.iter().any(|f| f.trampoline))
        .collect();
    assert_eq!(
        with.len(),
        1,
        "exactly one thread parks in a signal handler: {:#?}",
        stacks
            .iter()
            .map(|(t, b)| (t, demangled(b)))
            .collect::<Vec<_>>()
    );
    let (tid, bt) = with[0];
    let names = demangled(bt);
    let at = bt.frames.iter().position(|f| f.trampoline).unwrap();
    assert!(
        at > 0 && names[..at].iter().any(|n| n.contains(PARK_FN)),
        "tid {tid}: the handler parks above the trampoline: {names:#?}"
    );
    assert!(
        bt.frames[at].interrupted && bt.frames[at + 1].interrupted,
        "tid {tid}: the trampoline and the frame it restores are both stopped, not suspended at a call: {names:#?}"
    );
    assert!(
        names[at + 1..].iter().any(|n| n.contains("core_target")),
        "tid {tid}: the walk never reached the fixture's frames below the interrupted one: {names:#?}"
    );
    assert_eq!(bt.truncated, None, "tid {tid}: {names:#?}");
    let line = &bt.stack_trace(64)[at];
    assert!(
        line.ends_with(unwind::SIGNAL_HANDLER_CALLED),
        "the listing spells the seam: {line}"
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

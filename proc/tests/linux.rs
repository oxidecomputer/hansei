//! The real-core suite for the ELF-backed Linux reader: the half of
//! the Linux backend that can only be checked against a core something
//! else wrote. It compiles nowhere else.
//!
//! The unit tests in `src/linux.rs` drive the reader with cores this
//! suite could never produce — a region dumped and file-backed at once,
//! a mapping whose file is gone, a truncated note — and they carry most
//! of the coverage. What they cannot check is whether the layout this
//! crate believes in is the layout a real dumper writes. That is this
//! file's job, and it is why every assertion here is against something
//! the target itself reported on stdout before it died.
//!
//! The target is `test-programs`' `core-target`, built by `regen.sh` the
//! way every other suite gets its fixtures. It prints its thread ids and
//! the thread-local each of them set, then aborts.
//!
//! The core comes from gdb's `gcore`, with gdb as the target's parent so
//! that it dumps the target where it stopped. Nothing here touches
//! `core_pattern`, which is global, often a pipe to a crash handler, and
//! needs root to change; running gdb as the parent also sidesteps
//! `ptrace_scope`, which on many distributions forbids tracing anything
//! but a descendant. All the suite needs is gdb on `PATH`.
//!
//! gdb dumps more than the kernel would — it writes out file-backed text
//! the kernel's default filter drops — so which regions land in the file
//! is not something to assume. [`dumped_ranges`] reads that back out of
//! the core's own program headers, and the tests use it to make sure
//! they are exercising the path they mean to.

#![cfg(target_os = "linux")]

use proc::Target;
use proc::coredump::linux::Core;

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The fixture program, and the markers it carries. Keep in step with
/// `test-programs/src/bin/core-target.rs`.
const PROGRAM: &str = "core-target";
const READY: &str = "core-target ready:";
const SLOT_LINE: &str = "core-target slot:";
const WORKERS: usize = 3;
const MARKER_FN: &str = "core_marker_fn";
const MARKER_VALUE_SYM: &str = "CORE_MARKER_VALUE";
const MARKER_VALUE: u64 = 0x0123_4567_89ab_cdef;
const COUNTER_SYM: &str = "CORE_COUNTER";
/// The mangled `CORE_SLOT` thread-local carries this in its name.
const SLOT_SYM: &str = "CORE_SLOT";

/// The first page is never mapped in any process.
const UNMAPPED: u64 = 0x1000;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

/// Build the fixture once per suite run and hand back its path.
///
/// Once per *run* rather than once per process: under nextest each test
/// is its own process, and a rebuild landing while another test reads
/// the binary's symtab — or gdb executes it — hands that test a
/// half-written ELF.
fn fixture() -> &'static Path {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| {
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
        test_programs.join("fixtures/bin").join(PROGRAM)
    })
}

/// What the fixture binary is built from, for a run reusing what an
/// earlier one left behind (`testrun::REUSE`): the program's own source
/// and the crate it calls into, the manifest and lock that pin what it
/// links, and the script that drives the build and pins the toolchain.
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

/// A core from the fixture, and everything the fixture said about
/// itself on the way down.
struct Dumped {
    core: PathBuf,
    /// Thread id -> where that thread's copy of the thread-local was
    /// and what it held, as the thread itself saw them.
    slots: BTreeMap<u32, Slot>,
    /// Kept so the core outlives the test that reads it.
    _dir: tempfile::TempDir,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Slot {
    value: u64,
    addr: u64,
}

/// Run the fixture to its abort under gdb and dump it there.
///
/// Produced once for the whole suite: every test here reads the same
/// core, and the target has nothing to say that changes between runs.
fn dumped() -> &'static Dumped {
    static DUMPED: OnceLock<Dumped> = OnceLock::new();
    DUMPED.get_or_init(|| {
        let dir = tempfile::tempdir().expect("failed to create a tempdir");
        let core = dir.path().join("core");

        // gdb runs the target, stops when it aborts, and dumps it where
        // it stands. One arena keeps glibc from reserving 64MiB per
        // thread that gdb would then write out in full; the kernel
        // skips those pages, gdb does not.
        let out = Command::new("gdb")
            .args(["-batch", "-nx", "-ex", "run", "-ex"])
            .arg(format!("gcore {}", core.display()))
            .args(["-ex", "kill", "--args"])
            .arg(fixture())
            .env("MALLOC_ARENA_MAX", "1")
            .output()
            .unwrap_or_else(|e| {
                panic!(
                    "failed to run gdb ({e}); this suite dumps the target with \
                     gcore, so gdb has to be on PATH. The unit tests in \
                     src/linux.rs cover the reader itself and need nothing."
                )
            });
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            core.exists(),
            "gdb wrote no core to {}:\n{stdout}\n{}",
            core.display(),
            String::from_utf8_lossy(&out.stderr)
        );

        // gdb passes the target's stdout through with its own; the
        // target's lines are the ones that say whose they are.
        let mut slots = BTreeMap::new();
        let mut ready = false;
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix(SLOT_LINE) {
                let fields: Vec<&str> = rest.split_whitespace().collect();
                let [tid, value, addr] = fields[..] else {
                    panic!("malformed slot line: {line}");
                };
                slots.insert(
                    tid.parse().expect("thread ids are numbers"),
                    Slot {
                        value: hex(value),
                        addr: hex(addr),
                    },
                );
            } else if line.starts_with(READY) {
                ready = true;
            }
        }
        assert!(ready, "the target never reported ready:\n{stdout}");
        assert_eq!(
            slots.len(),
            WORKERS + 1,
            "not every thread reported in:\n{stdout}"
        );

        Dumped {
            core,
            slots,
            _dir: dir,
        }
    })
}

/// The address ranges whose bytes the core file actually carries, read
/// out of its program headers.
///
/// This is the one thing the tests cannot ask the reader, because it is
/// what the reader is being checked on: which side of a read the bytes
/// came from. How much a core holds depends on who wrote it — the
/// kernel drops private file-backed pages, gdb keeps them — so the
/// tests establish it rather than assume it.
fn dumped_ranges(core: &Path) -> Vec<Range<u64>> {
    let bytes = std::fs::read(core).expect("failed to read the core");
    let elf = goblin::elf::Elf::parse(&bytes).expect("the core is an ELF file");
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD && ph.p_filesz > 0)
        .map(|ph| ph.p_vaddr..ph.p_vaddr + ph.p_filesz)
        .collect()
}

fn hex(field: &str) -> u64 {
    let digits = field
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("{field} is not hex"));
    u64::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("{field} is not hex"))
}

fn target() -> Core {
    Core::open(&dumped().core).expect("failed to open the core")
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

/// Every thread the fixture reported is in the core, with registers
/// that put it on its own stack.
#[test]
fn test_threads_match_the_target() {
    let p = target();
    let lwps = p.lwps().unwrap();

    let tids: Vec<u32> = lwps.iter().map(|l| l.tid).collect();
    let mut want: Vec<u32> = dumped().slots.keys().copied().collect();
    want.sort_unstable();
    let mut got = tids.clone();
    got.sort_unstable();
    assert_eq!(got, want, "the core and the target disagree about threads");

    let maps = p.mappings().unwrap();
    for lwp in &lwps {
        let tid = lwp.tid;
        assert_ne!(lwp.regs.fsbase, 0, "tid {tid} has no thread pointer");
        assert!(
            lwp.stack_range.contains(&lwp.regs.rsp),
            "tid {tid}: %rsp {:#x} outside stack {:#x}..{:#x}",
            lwp.regs.rsp,
            lwp.stack_range.start,
            lwp.stack_range.end
        );
        // Every thread died in the kernel or in libc, so its program
        // counter is in mapped text either way.
        assert!(
            maps.get(lwp.regs.rip).is_some_and(|m| m.is_text()),
            "tid {tid}: %rip {:#x} is not in mapped text",
            lwp.regs.rip
        );
        assert_eq!(p.regs(tid).unwrap(), lwp.regs);
    }

    // The thread that died is one of them, and the first one listed.
    assert_eq!(p.status().active_lwp, lwps[0].tid);
    assert!(tids.contains(&p.status().active_lwp));
}

// ---------------------------------------------------------------------------
// Thread-locals
// ---------------------------------------------------------------------------

/// The headline check: resolving one `STT_TLS` symbol per thread lands
/// on exactly the address that thread saw for it, holding the value it
/// left there. Nothing else in this crate can confirm that the Variant
/// II arithmetic agrees with what the linker and glibc actually did.
#[test]
fn test_thread_locals_resolve_per_thread() {
    let p = target();
    let sym = p
        .object_symbols()
        .unwrap()
        .into_iter()
        .find(|s| s.name.contains(SLOT_SYM))
        .expect("the fixture's thread-local is in the symtab");
    // Its value is an offset into a TLS block, not an address, and so
    // far too small to be one.
    assert!(sym.st_value < 0x1000, "{sym:?} looks biased");

    let got: BTreeMap<u32, Slot> = p
        .lwps()
        .unwrap()
        .iter()
        .map(|lwp| {
            let addr = p
                .tls_var_addr(&lwp.regs, &sym)
                .unwrap_or_else(|e| panic!("tid {}: {e}", lwp.tid))
                .unwrap_or_else(|| panic!("tid {} holds no thread-local", lwp.tid));
            let value = p
                .read_u64(addr)
                .unwrap_or_else(|e| panic!("tid {} slot at {addr:#x}: {e}", lwp.tid));
            (lwp.tid, Slot { value, addr })
        })
        .collect();

    assert_eq!(got, dumped().slots);
    // Every thread got its own answer, so a resolver that ignored the
    // thread could not have passed.
    let addrs: std::collections::BTreeSet<u64> = got.values().map(|s| s.addr).collect();
    assert_eq!(addrs.len(), got.len(), "threads shared a thread-local");
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// A read served out of the core, and the precedence that makes it the
/// right answer. `CORE_COUNTER` is zero in the executable on disk and
/// holds the marker value only because the process wrote it, so reading
/// the marker back proves the bytes came from the core — a reader that
/// preferred the file would return zero.
#[test]
fn test_dumped_pages_come_from_the_core() {
    let p = target();
    let dumped = dumped_ranges(&dumped().core);

    let counter = p
        .lookup_symbol_by_name(COUNTER_SYM)
        .expect("the counter is in the symtab");
    assert!(
        dumped.iter().any(|r| r.contains(&counter.st_value)),
        "{COUNTER_SYM} at {:#x} is not in the core; this test would prove nothing",
        counter.st_value
    );
    assert_eq!(p.read_u64(counter.st_value).unwrap(), MARKER_VALUE);
    assert!(
        p.mappings()
            .unwrap()
            .get(counter.st_value)
            .unwrap()
            .is_data()
    );

    assert!(p.read_bytes(UNMAPPED, 8).is_err());
    assert!(p.read_u64(UNMAPPED).is_err());
}

/// A read served off disk. Whoever wrote the core left some file-backed
/// region out of it — the kernel drops all of the executable's text,
/// gdb only some of libc's — and reads that land there have to come
/// from the file the mapping names.
///
/// The expected bytes are worked out the way a debugger does it, from
/// the mapping base and the object's own program headers, so that what
/// the reader returns is checked against the file and not against a
/// second copy of the reader.
#[test]
fn test_undumped_pages_come_from_disk() {
    let p = target();
    let dumped = dumped_ranges(&dumped().core);
    let maps = p.mappings().unwrap();

    let mut checked = 0;
    for m in &maps {
        let Some(path) = m.path.as_deref() else {
            continue;
        };
        // Only wholly-absent regions: a partly dumped one would not say
        // which side answered.
        if dumped
            .iter()
            .any(|r| r.start < m.range().end && m.vaddr < r.end)
        {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(elf) = goblin::elf::Elf::parse(&bytes) else {
            continue;
        };

        // Where this object landed, and so where in the file this
        // mapping's first byte came from.
        let base = maps
            .iter()
            .filter(|o| o.path.as_deref() == Some(path))
            .map(|o| o.vaddr)
            .min()
            .unwrap();
        let lowest = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|ph| ph.p_vaddr)
            .min()
            .unwrap();
        let link_addr = m.vaddr - (base - lowest);
        let Some(ph) = elf.program_headers.iter().find(|ph| {
            ph.p_type == goblin::elf::program_header::PT_LOAD
                && (ph.p_vaddr..ph.p_vaddr + ph.p_filesz).contains(&link_addr)
        }) else {
            continue;
        };
        let at = (ph.p_offset + (link_addr - ph.p_vaddr)) as usize;
        let want = &bytes[at..at + 64];

        assert_eq!(
            p.read_bytes(m.vaddr, 64).unwrap(),
            want,
            "{path} at {:#x} did not come back off disk",
            m.vaddr
        );
        checked += 1;
    }

    assert!(
        checked > 0,
        "no mapping was left out of the core, so the disk path went \
         untested; mappings were {maps:#?}"
    );
}

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

/// Symbols come from the files on disk, biased to where the loader put
/// them, and round-trip by name and by address.
#[test]
fn test_symbols_round_trip() {
    let p = target();
    assert_eq!(p.exec_name().unwrap(), fixture());

    let sym = p
        .lookup_symbol_by_name(MARKER_FN)
        .unwrap_or_else(|| panic!("{MARKER_FN} is not in the target's symtab"));
    assert!(sym.st_size > 0);

    // The address is where the mapping says the executable landed, not
    // the link-time value.
    let maps = p.mappings().unwrap();
    assert!(
        maps.get(sym.st_value).is_some_and(|m| m.is_text()),
        "{MARKER_FN} at {:#x} is not in mapped text",
        sym.st_value
    );

    let back = p
        .lookup_symbol_by_addr(sym.st_value)
        .expect("the marker fn does not resolve back");
    assert_eq!(back.name, MARKER_FN);
    // And from an address inside it, not just its first byte.
    assert_eq!(
        p.lookup_symbol_by_addr(sym.st_value + sym.st_size - 1)
            .map(|s| s.name),
        Some(MARKER_FN.to_string())
    );

    // The masks split the symtab the way libproc's do.
    let functions = p.symbols().unwrap();
    let objects = p.object_symbols().unwrap();
    assert!(functions.iter().any(|s| s.name == MARKER_FN));
    assert!(!objects.iter().any(|s| s.name == MARKER_FN));
    for name in [MARKER_VALUE_SYM, COUNTER_SYM] {
        assert!(
            objects.iter().any(|s| s.name == name),
            "{name} is not an object symbol"
        );
        assert!(
            !functions.iter().any(|s| s.name == name),
            "{name} is a function symbol"
        );
    }

    assert!(p.lookup_symbol_by_name("no_such_symbol_anywhere").is_none());
    assert!(p.lookup_symbol_by_addr(UNMAPPED).is_none());

    // The trait sees exactly what the inherent methods do.
    assert_eq!(Target::symbols(&p).unwrap(), functions);
    assert_eq!(Target::object_symbols(&p).unwrap(), objects);
    assert_eq!(
        Target::lookup_symbol_by_name(&p, MARKER_FN).as_ref(),
        Some(&sym)
    );
}

/// libproc resolves an address in any mapped object, not just the
/// executable; so does this. Every thread died inside libc, which is
/// the object that proves it.
#[test]
fn test_addresses_resolve_in_libraries() {
    let p = target();
    let maps = p.mappings().unwrap();
    assert!(
        maps.iter()
            .any(|m| m.file_name().is_some_and(|n| n.starts_with("libc.so"))),
        "libc is not mapped: {maps:#?}"
    );

    let lwps = p.lwps().unwrap();
    let resolved = lwps
        .iter()
        .filter_map(|l| p.lookup_symbol_by_addr(l.regs.rip))
        .count();
    assert!(
        resolved > 0,
        "no thread's %rip resolved to a symbol; {:#x?}",
        lwps.iter().map(|l| l.regs.rip).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Mappings
// ---------------------------------------------------------------------------

#[test]
fn test_mappings_describe_the_address_space() {
    let p = target();
    let maps = p.mappings().unwrap();
    assert!(!maps.is_empty());

    for m in &maps {
        assert!(m.size > 0, "empty mapping {m:#?}");
        assert_eq!(m.range(), m.vaddr..m.vaddr + m.size, "{m:#?}");
    }

    // The executable is mapped, with text and data both present, and
    // the anonymous regions carry no path.
    let exec = fixture().to_str().unwrap();
    let mine: Vec<_> = maps
        .iter()
        .filter(|m| m.path.as_deref() == Some(exec))
        .collect();
    assert!(mine.iter().any(|m| m.is_text()), "{mine:#?}");
    assert!(mine.iter().any(|m| m.is_data()), "{mine:#?}");
    assert!(maps.iter().any(|m| m.flags.is_anon() && m.path.is_none()));

    assert!(!maps.contains_addr(UNMAPPED));
    assert!(p.addr_to_map(UNMAPPED).is_none());
    assert!(p.addr_is_mapped(maps.first().unwrap().vaddr));
    assert_eq!(Target::mappings(&p).unwrap(), maps);
}

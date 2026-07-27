//! The real-core suite for the ELF-backed [`Proc`] target: the half of
//! the Linux backend that can only be checked against a core the kernel
//! actually wrote. It compiles nowhere else.
//!
//! The unit tests in `src/linux.rs` drive the reader with cores this
//! suite could never produce — a region dumped and file-backed at once,
//! a mapping whose file is gone, a truncated note — and they carry most
//! of the coverage. What they cannot check is whether the layout this
//! crate believes in is the layout Linux writes. That is this file's
//! job, and it is why every assertion here is against something the
//! target itself reported on stdout before it died.
//!
//! The target is `test-programs`' `core-target`, built by `regen.sh` the
//! way every other suite gets its fixtures. It prints its thread ids and
//! the thread-local each of them set, then aborts.
//!
//! Retrieving the core is the one part that depends on how the machine
//! is configured: `core_pattern` is normally a pipe to
//! `systemd-coredump`, so the core is fetched back with `coredumpctl`.
//! Where that is not available the suite says so and stops rather than
//! passing silently.

#![cfg(target_os = "linux")]

use proc::{Proc, Target};

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

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

/// How long to wait for `systemd-coredump` to finish storing the core.
/// It runs asynchronously, so unlike the illumos suite there is no
/// event to block on; this polls instead of guessing a single sleep.
const CORE_WAIT: Duration = Duration::from_millis(250);
const CORE_TRIES: usize = 40;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

/// Build the fixture once per suite run and hand back its path.
fn fixture() -> &'static Path {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let test_programs = workspace_root().join("test-programs");
        let status = Command::new(test_programs.join("regen.sh"))
            .arg(PROGRAM)
            .status()
            .expect("failed to run regen.sh");
        assert!(
            status.success(),
            "regen.sh failed; is the pinned toolchain installed?"
        );
        test_programs.join("fixtures/bin").join(PROGRAM)
    })
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

/// Run the fixture to its abort, then fetch the core back.
///
/// Produced once for the whole suite: a core is a few megabytes and
/// every test here reads the same one.
fn dumped() -> &'static Dumped {
    static DUMPED: OnceLock<Dumped> = OnceLock::new();
    DUMPED.get_or_init(|| {
        let mut child = Command::new(fixture())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn the target");

        let mut slots = BTreeMap::new();
        let mut pid = None;
        let stdout = BufReader::new(child.stdout.take().expect("the target has a stdout"));
        for line in stdout.lines() {
            let line = line.expect("failed to read the target's stdout");
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
            } else if let Some(rest) = line.strip_prefix(READY) {
                pid = Some(rest.trim().to_string());
                break;
            }
        }
        let pid = pid.expect("the target never reported ready");
        assert_eq!(slots.len(), WORKERS + 1, "not every thread reported in");
        child.wait().expect("failed to wait for the target");

        let dir = tempfile::tempdir().expect("failed to create a tempdir");
        let core = dir.path().join("core");
        fetch_core(&pid, &core);

        Dumped {
            core,
            slots,
            _dir: dir,
        }
    })
}

/// Pull the core back out of `systemd-coredump`, which stores it
/// asynchronously after the process dies.
fn fetch_core(pid: &str, out: &Path) {
    if Command::new("coredumpctl")
        .arg("--version")
        .output()
        .is_err()
    {
        panic!(
            "coredumpctl is not installed, so the core of pid {pid} cannot be \
             retrieved. This machine's core_pattern is {}, which is a pipe to \
             systemd-coredump; the unit tests in src/linux.rs cover the reader \
             itself and do not need one.",
            core_pattern()
        );
    }

    for _ in 0..CORE_TRIES {
        let status = Command::new("coredumpctl")
            .args(["dump", "--output"])
            .arg(out)
            .arg(pid)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("failed to run coredumpctl");
        if status.success() && out.exists() {
            return;
        }
        std::thread::sleep(CORE_WAIT);
    }
    panic!(
        "no core for pid {pid} after {:?}; core_pattern is {}. Is storage \
         disabled in coredump.conf, or the core size limit too low?",
        CORE_WAIT * CORE_TRIES as u32,
        core_pattern()
    );
}

fn hex(field: &str) -> u64 {
    let digits = field
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("{field} is not hex"));
    u64::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("{field} is not hex"))
}

fn core_pattern() -> String {
    std::fs::read_to_string("/proc/sys/kernel/core_pattern")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "<unreadable>".to_string())
}

fn target() -> Proc {
    Proc::open_core(&dumped().core).expect("failed to open the core")
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

/// Both halves of a read: `.rodata` is dropped by the default dump
/// filter and has to come off the executable on disk, while a page the
/// process wrote is in the core itself. Both hold the same value here,
/// so only the path differs.
#[test]
fn test_reads_reach_both_sources() {
    let p = target();

    let rodata = p
        .lookup_symbol_by_name(MARKER_VALUE_SYM)
        .expect("the marker value is in the symtab");
    assert_eq!(p.read_u64(rodata.st_value).unwrap(), MARKER_VALUE);

    let data = p
        .lookup_symbol_by_name(COUNTER_SYM)
        .expect("the counter is in the symtab");
    assert_eq!(p.read_u64(data.st_value).unwrap(), MARKER_VALUE);

    // The two live in different mappings, and the counter's was dumped.
    let maps = p.mappings().unwrap();
    assert!(maps.contains_addr(rodata.st_value));
    assert!(maps.get(data.st_value).unwrap().is_data());

    assert!(p.read_bytes(UNMAPPED, 8).is_err());
    assert!(p.read_u64(UNMAPPED).is_err());
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

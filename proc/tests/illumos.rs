//! The on-box suite for the libproc-backed [`Proc`] target: the half of
//! the crate that can only be exercised against a real illumos process.
//! It compiles nowhere else, so `cargo test -p proc` runs it on the box
//! and skips it everywhere else.
//!
//! The target is `test-programs`' `park-target`, built by `regen.sh` the
//! way every other on-box suite gets its fixtures and driven to its
//! parked steady state by blocking on the readiness line it prints —
//! there are no timing sleeps anywhere. Its symbols, its memory contents
//! and its threads are all known to this file, and it reports the LWP
//! ids procfs has for it, which libproc's own enumeration is held to.
//!
//! Every read-only test runs twice: against a core taken from the parked
//! target, and against the live process. libproc serves both through the
//! same handle, and so does everything built on it.

#![cfg(target_os = "illumos")]

use proc::snapshot::{Recorder, Snapshot};
use proc::{Proc, Target};

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

/// The fixture program, and the markers it carries. Keep in step with
/// `test-programs/src/bin/park-target.rs`.
const PROGRAM: &str = "park-target";
const PARK_READY: &str = "park-target ready:";
const WORKERS: [&str; 3] = ["park-worker-0", "park-worker-1", "park-worker-2"];
const MARKER_FN: &str = "park_marker_fn";
const MARKER_VALUE_SYM: &str = "PARK_MARKER_VALUE";
const MARKER_VALUE: u64 = 0x0123_4567_89ab_cdef;
const COUNTER_SYM: &str = "PARK_COUNTER";
const TSD_KEY_SYM: &str = "PARK_TSD_KEY";

/// The first page is never mapped in any process.
const UNMAPPED: u64 = 0x1000;

/// How long [`Proc::stop`] may wait for the target to come to rest.
const STOP_WAIT_MS: u32 = 5_000;

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

/// The fixture program, running at its parked steady state.
struct Parked {
    child: Child,
    /// Every LWP the target had when it reported ready, straight from
    /// procfs: an oracle libproc had no hand in.
    tids: BTreeSet<u32>,
}

impl Parked {
    fn spawn() -> Self {
        Self::start(&[])
    }

    /// A target with the counter-bumping thread as well.
    fn spinning() -> Self {
        Self::start(&["--spin"])
    }

    /// Launch the target and block on its stdout until it reports the
    /// LWP ids it parked with.
    fn start(args: &[&str]) -> Self {
        let path = fixture();
        let mut child = Command::new(path)
            .args(args)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to launch {}: {e}", path.display()));

        let stdout = child.stdout.take().expect("the child's stdout is piped");
        let mut lines = BufReader::new(stdout).lines();
        let tids = loop {
            match lines.next() {
                Some(Ok(line)) => match line.strip_prefix(PARK_READY) {
                    Some(ids) => {
                        break ids
                            .trim()
                            .split(',')
                            .map(|id| id.parse().expect("the target printed a bad lwp id"))
                            .collect();
                    }
                    None => continue,
                },
                Some(Err(e)) => panic!("failed to read the target's stdout: {e}"),
                None => panic!("the target exited before it parked"),
            }
        };
        // The target prints nothing more, but keep draining so it can
        // never take a signal from a full pipe.
        thread::spawn(move || lines.for_each(drop));

        Self { child, tids }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Parked {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Take a core of the parked target; it lives in the caller's tempdir
/// and is cleaned up with it.
fn gcore(pid: u32, dir: &Path) -> PathBuf {
    let out = Command::new("gcore")
        .arg("-o")
        .arg(dir.join("core"))
        .arg(pid.to_string())
        .output()
        .expect("failed to run gcore");
    assert!(
        out.status.success(),
        "gcore of {pid} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let core = dir.join(format!("core.{pid}"));
    assert!(core.exists(), "gcore left no {}", core.display());
    core
}

/// Run `check` against the same parked target twice: once through a core
/// taken from it, once through the live process. The core is taken first,
/// while the target is still running, so neither view disturbs the other.
fn for_each_target(check: impl Fn(&Proc, &Parked, &str)) {
    let parked = Parked::spawn();
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core = gcore(parked.pid(), dir.path());

    let from_core = Proc::open_core(&core).expect("failed to open the core");
    check(&from_core, &parked, "core");

    let live = Proc::grab_pid(parked.pid()).expect("failed to grab the live target");
    check(&live, &parked, "live");
}

/// The runtime address of one of the target's marker symbols.
fn marker_addr(p: &Proc, name: &str) -> u64 {
    p.lookup_symbol_by_name(name)
        .unwrap_or_else(|| panic!("{name} is not in the target's symtab"))
        .st_value
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// Every read helper lands on the marker static, and reads of the
/// unmapped first page fail rather than returning zeroes.
#[test]
fn test_reads_see_the_targets_memory() {
    for_each_target(|p, _, who| {
        let addr = marker_addr(p, MARKER_VALUE_SYM);

        assert_eq!(p.read_u64(addr).unwrap(), MARKER_VALUE, "({who})");
        assert_eq!(p.read_u32(addr).unwrap(), MARKER_VALUE as u32, "({who})");
        assert_eq!(p.read_u16(addr).unwrap(), MARKER_VALUE as u16, "({who})");
        assert_eq!(p.read_u8(addr).unwrap(), MARKER_VALUE as u8, "({who})");
        // The halves are where little-endian says they are.
        assert_eq!(
            p.read_u32(addr + 4).unwrap(),
            (MARKER_VALUE >> 32) as u32,
            "({who})"
        );

        let mut buf = [0u8; 8];
        p.pread_exact(&mut buf, addr).unwrap();
        assert_eq!(buf, MARKER_VALUE.to_le_bytes(), "({who})");
        assert_eq!(p.pread(&mut buf, addr).unwrap(), 8, "({who})");

        // And the same bytes through the Target trait.
        assert_eq!(
            Target::read_bytes(p, addr, 8).unwrap(),
            MARKER_VALUE.to_le_bytes(),
            "({who})"
        );
        assert_eq!(Target::read_u64(p, addr).unwrap(), MARKER_VALUE, "({who})");

        // Nothing is mapped at the first page, so every read that has to
        // fill its buffer fails there.
        assert!(p.read_u64(UNMAPPED).is_err(), "({who})");
        assert!(p.read_u8(UNMAPPED).is_err(), "({who})");
        assert!(p.pread_exact(&mut buf, UNMAPPED).is_err(), "({who})");
        assert!(Target::read_bytes(p, UNMAPPED, 8).is_err(), "({who})");
        // A bare pread need not: a live grab fails it outright, but a
        // core just comes up short, which is the whole reason the
        // helpers above insist on the count.
        let short = p.pread(&mut buf, UNMAPPED).unwrap_or(0);
        assert!(
            short < buf.len() as u64,
            "({who}) read {short} bytes of unmapped memory"
        );
    });
}

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

/// By-name and by-address lookups agree with each other, and the type
/// masks put each marker in exactly one of the two symbol tables.
#[test]
fn test_symbol_lookups_round_trip() {
    for_each_target(|p, _, who| {
        let sym = p
            .lookup_symbol_by_name(MARKER_FN)
            .unwrap_or_else(|| panic!("({who}) {MARKER_FN} is not in the target's symtab"));
        assert_ne!(sym.st_value, 0, "({who})");
        assert!(sym.st_size > 0, "({who})");

        // Back by address, from the entry point and from inside the body.
        let back = p
            .lookup_symbol_by_addr(sym.st_value)
            .unwrap_or_else(|| panic!("({who}) {:#x} resolved to nothing", sym.st_value));
        assert_eq!(
            (back.name.as_str(), back.st_value, back.st_size),
            (MARKER_FN, sym.st_value, sym.st_size),
            "({who})"
        );
        assert_eq!(
            p.lookup_symbol_name_by_addr(sym.st_value + 1).as_deref(),
            Some(MARKER_FN),
            "({who})"
        );

        // Misses stay misses.
        assert!(
            p.lookup_symbol_by_name("no_such_symbol_anywhere").is_none(),
            "({who})"
        );
        assert!(
            p.lookup_symbol_by_name("interior\0nul").is_none(),
            "({who})"
        );
        assert!(p.lookup_symbol_by_addr(UNMAPPED).is_none(), "({who})");

        // The type masks split the symtab in two.
        let functions = p.symbols().unwrap();
        let objects = p.object_symbols().unwrap();
        assert!(functions.iter().any(|s| s.name == MARKER_FN), "({who})");
        assert!(!objects.iter().any(|s| s.name == MARKER_FN), "({who})");
        for name in [MARKER_VALUE_SYM, COUNTER_SYM, TSD_KEY_SYM] {
            assert!(
                objects.iter().any(|s| s.name == name),
                "({who}) {name} is not an object symbol"
            );
            assert!(
                !functions.iter().any(|s| s.name == name),
                "({who}) {name} is a function symbol"
            );
        }
        // Local bindings are in the mask too: nothing exports these.
        assert!(functions.iter().any(|s| s.name == "main"), "({who})");

        // The trait sees exactly what the inherent methods do.
        assert_eq!(Target::symbols(p).unwrap(), functions, "({who})");
        assert_eq!(Target::object_symbols(p).unwrap(), objects, "({who})");
        assert_eq!(
            Target::lookup_symbol_by_name(p, MARKER_FN).as_ref(),
            Some(&sym),
            "({who})"
        );
        assert_eq!(
            Target::lookup_symbol_by_addr(p, sym.st_value).as_ref(),
            Some(&back),
            "({who})"
        );
    });
}

// ---------------------------------------------------------------------------
// Mappings
// ---------------------------------------------------------------------------

/// The mapping table places the markers in the segments they belong to,
/// is sorted, and agrees with `Paddr_to_map` object by object.
#[test]
fn test_mappings_cover_the_address_space() {
    for_each_target(|p, _, who| {
        let maps = p.mappings().unwrap();
        assert!(!maps.is_empty(), "({who}) no mappings at all");
        assert!(
            maps.as_slice().windows(2).all(|w| w[0].vaddr <= w[1].vaddr),
            "({who}) mappings are not sorted: {maps:#?}"
        );

        // The marker function is in the fixture's own executable text.
        let fn_addr = marker_addr(p, MARKER_FN);
        let text = maps
            .get(fn_addr)
            .unwrap_or_else(|| panic!("({who}) {fn_addr:#x} is unmapped"));
        assert!(text.is_text(), "({who}) {text:#?}");
        assert!(text.range().contains(&fn_addr), "({who}) {text:#?}");
        assert_eq!(text.file_name(), Some(PROGRAM), "({who}) {text:#?}");
        assert!(maps.contains_addr(fn_addr), "({who})");
        assert_eq!(maps[fn_addr], *text, "({who})");

        // Paddr_to_map is a second path to the same object.
        let direct = p
            .addr_to_map(fn_addr)
            .unwrap_or_else(|| panic!("({who}) {fn_addr:#x} has no map"));
        assert_eq!(
            (direct.vaddr, direct.size, direct.flags, direct.range()),
            (text.vaddr, text.size, text.flags, text.range()),
            "({who})"
        );
        assert!(p.addr_is_mapped(fn_addr), "({who})");

        // The marker static is readable; the counter is writable.
        let value = maps.get(marker_addr(p, MARKER_VALUE_SYM));
        assert!(
            value.is_some_and(|m| m.flags.is_read()),
            "({who}) {value:#?}"
        );
        let counter = maps.get(marker_addr(p, COUNTER_SYM));
        assert!(
            counter.is_some_and(|m| m.flags.is_read() && m.flags.is_write()),
            "({who}) {counter:#?}"
        );

        // Holes stay holes, whichever way they are asked about.
        assert!(maps.get(UNMAPPED).is_none(), "({who})");
        assert!(!maps.contains_addr(UNMAPPED), "({who})");
        assert!(!p.addr_is_mapped(UNMAPPED), "({who})");
        assert!(p.addr_to_map(UNMAPPED).is_none(), "({who})");

        // libc is mapped, and every mapping is a real, non-empty range.
        assert!(
            maps.iter()
                .any(|m| m.file_name().is_some_and(|n| n.starts_with("libc.so"))),
            "({who}) libc is not mapped: {maps:#?}"
        );
        for m in &maps {
            assert!(m.size > 0, "({who}) empty mapping {m:#?}");
            assert_eq!(m.range(), m.vaddr..m.vaddr + m.size, "({who}) {m:#?}");
        }

        assert_eq!(Target::mappings(p).unwrap(), maps, "({who})");
    });
}

// ---------------------------------------------------------------------------
// LWPs and registers
// ---------------------------------------------------------------------------

/// libproc's LWP iteration finds exactly the threads procfs lists, each
/// with registers that agree with a direct read and a stack that holds
/// its own stack pointer.
#[test]
fn test_lwps_match_procfs() {
    for_each_target(|p, parked, who| {
        let lwps = p.lwps().unwrap();
        let tids: BTreeSet<u32> = lwps.iter().map(|l| l.tid).collect();
        assert_eq!(
            tids, parked.tids,
            "({who}) libproc and procfs disagree about the target's LWPs"
        );

        let maps = p.mappings().unwrap();

        // The fixture's exported slot index, read back out of the target
        // rather than repeated here, so the suite pins the composition
        // and not the constant.
        let key_sym = p
            .lookup_symbol_by_name(TSD_KEY_SYM)
            .unwrap_or_else(|| panic!("({who}) {TSD_KEY_SYM} is not in the target's symtab"));
        let key = p.read_u64(key_sym.st_value).unwrap() as usize;

        for lwp in &lwps {
            let tid = lwp.tid;
            assert_eq!(p.regs(tid).unwrap(), lwp.regs, "({who}) tid {tid}");

            // A parked thread sits in the kernel on its own stack, with
            // its program counter in mapped text.
            assert!(
                lwp.stack_range.contains(&lwp.regs.rsp),
                "({who}) tid {tid}: %rsp {:#x} outside stack {:#x}..{:#x}",
                lwp.regs.rsp,
                lwp.stack_range.start,
                lwp.stack_range.end
            );
            assert!(
                maps.get(lwp.regs.rip).is_some_and(|m| m.is_text()),
                "({who}) tid {tid}: %rip {:#x} is not in mapped text",
                lwp.regs.rip
            );
            assert_ne!(lwp.regs.fsbase, 0, "({who}) tid {tid}");
            assert!(lwp.tstamp.tv_sec > 0, "({who}) tid {tid} {:?}", lwp.tstamp);

            // The TSD slots hang off %fsbase however they are reached.
            let tsd = p.lwp_tsd(tid).unwrap();
            assert_eq!(
                p.tsd_from_regs(&lwp.regs).unwrap(),
                tsd,
                "({who}) tid {tid}"
            );

            // And a thread-local lands on the slot its key names: the
            // whole walk, over a real ulwp_t, in one call. A null slot
            // is no address rather than the address zero.
            let want = (tsd[key] != 0).then_some(tsd[key]);
            assert_eq!(
                p.tls_var_addr(&lwp.regs, &key_sym).unwrap(),
                want,
                "({who}) tid {tid}"
            );
        }

        // A key past the ninth slot would need the slow TSD array:
        // PARK_MARKER_VALUE is nobody's key, and says so rather than
        // reading some other thread's memory.
        let bogus = p.lookup_symbol_by_name(MARKER_VALUE_SYM).unwrap();
        let err = match p.tls_var_addr(&lwps[0].regs, &bogus) {
            Err(e) => e,
            Ok(addr) => panic!("({who}) a bogus key resolved to {addr:?}"),
        };
        assert_eq!(
            err.to_string(),
            format!(
                "pthread key {MARKER_VALUE} is outside the fast-TSD range; \
                 slow TSD is unsupported"
            ),
            "({who})"
        );

        // The named threads kept their names.
        let names: Vec<String> = lwps
            .iter()
            .map(|l| p.lwp_name(l.tid).unwrap_or_default())
            .collect();
        for worker in WORKERS {
            assert!(
                names.iter().any(|n| n == worker),
                "({who}) no LWP named {worker}: {names:?}"
            );
        }

        // A thread handle reports the stop timestamp the iteration did.
        let first = &lwps[0];
        let handle = p
            .lwp_handle(first.tid)
            .unwrap_or_else(|e| panic!("({who}) failed to grab tid {}: {e}", first.tid));
        assert_eq!(handle.status(), first.tstamp, "({who})");

        // There is no LWP 0.
        assert!(p.lwp_handle(0).is_err(), "({who})");
        assert!(p.lwp_name(0).is_err(), "({who})");
        assert!(p.regs(0).is_err(), "({who})");

        assert_eq!(Target::lwps(p).unwrap(), lwps, "({who})");
    });
}

/// The process status names a real LWP and a mapped stack.
#[test]
fn test_status_describes_the_process() {
    for_each_target(|p, parked, who| {
        let status = p.status();
        assert!(
            parked.tids.contains(&status.active_lwp),
            "({who}) the representative LWP {} is not one of {:?}",
            status.active_lwp,
            parked.tids
        );
        assert!(
            status.stack_range.start < status.stack_range.end,
            "({who}) {status:#?}"
        );
        assert!(
            status.brk_range.start <= status.brk_range.end,
            "({who}) {status:#?}"
        );
        assert!(
            p.addr_is_mapped(status.stack_range.start),
            "({who}) the main stack is unmapped: {status:#?}"
        );
    });
}

// ---------------------------------------------------------------------------
// Process control
// ---------------------------------------------------------------------------

/// Stopping and running the target, observed through the one thing in it
/// that moves: a spinning thread's counter.
#[test]
fn test_stop_and_run_control_the_target() {
    let parked = Parked::spinning();
    let p = Proc::grab_pid(parked.pid()).expect("failed to grab the target");
    let counter = marker_addr(&p, COUNTER_SYM);

    // Grabbing it stopped it, so the spinner cannot advance.
    assert_stopped(&p, counter);

    // Set running, it advances again.
    p.run().expect("failed to resume the target");
    assert_running(&p, counter);

    // And it comes back to rest on demand.
    p.stop(STOP_WAIT_MS).expect("failed to stop the target");
    assert_stopped(&p, counter);

    // Releasing the handle clears the stop: PRELEASE_CLEAR in Drop.
    drop(p);
    // A no-stop grab leaves it running, and can watch it do so.
    let p = Proc::grab_pid_no_stop(parked.pid()).expect("failed to re-grab the target");
    assert_running(&p, counter);
}

/// A stopped target's spinner cannot run, so its counter holds still
/// across as many reads as we care to make.
fn assert_stopped(p: &Proc, counter: u64) {
    let want = p.read_u64(counter).expect("failed to read the counter");
    for _ in 0..10_000 {
        assert_eq!(
            p.read_u64(counter).expect("failed to read the counter"),
            want,
            "the target ran while it was supposed to be stopped"
        );
    }
}

/// A running target's spinner must move the counter. Polled rather than
/// slept on, and bounded so a stuck target fails instead of hanging.
fn assert_running(p: &Proc, counter: u64) {
    let want = p.read_u64(counter).expect("failed to read the counter");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if p.read_u64(counter).expect("failed to read the counter") != want {
            return;
        }
    }
    panic!("the counter never moved: the target is not running");
}

// ---------------------------------------------------------------------------
// Cores
// ---------------------------------------------------------------------------

/// A core and the process it was taken from answer the same questions
/// the same way. Registers are left out: gcore stops and restarts the
/// target, so its parked threads may have gone round their park loop
/// once more by the time the live handle reads them.
#[test]
fn test_core_and_live_agree() {
    let parked = Parked::spawn();
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core = Proc::open_core(&gcore(parked.pid(), dir.path())).expect("failed to open the core");
    let live = Proc::grab_pid(parked.pid()).expect("failed to grab the target");

    assert_eq!(live.exec_name().unwrap(), core.exec_name().unwrap());
    assert_eq!(
        live.exec_name().unwrap().file_name(),
        Some(std::ffi::OsStr::new(PROGRAM))
    );

    assert_eq!(core.symbols().unwrap(), live.symbols().unwrap());
    assert_eq!(
        core.object_symbols().unwrap(),
        live.object_symbols().unwrap()
    );
    for name in [MARKER_FN, MARKER_VALUE_SYM, COUNTER_SYM] {
        assert_eq!(
            core.lookup_symbol_by_name(name),
            live.lookup_symbol_by_name(name),
            "{name}"
        );
    }

    let marker = marker_addr(&live, MARKER_VALUE_SYM);
    assert_eq!(core.read_u64(marker).unwrap(), MARKER_VALUE);

    // A core keeps the shape of the address space and the permissions on
    // it, but not every provenance bit procfs has for a live process:
    // MA_ANON and MA_SHARED do not survive the dump. Compare what a core
    // is able to carry, laid out the way pmap prints it.
    let layout = |p: &Proc| -> Vec<String> {
        p.mappings()
            .unwrap()
            .iter()
            .map(|m| {
                let bit = |set, c| if set { c } else { '-' };
                format!(
                    "{:#018x}..{:#018x} {}{}{} {}",
                    m.vaddr,
                    m.range().end,
                    bit(m.flags.is_read(), 'r'),
                    bit(m.flags.is_write(), 'w'),
                    bit(m.flags.is_exec(), 'x'),
                    m.path.as_deref().unwrap_or("[ anon ]"),
                )
            })
            .collect()
    };
    assert_eq!(layout(&core), layout(&live));

    // Thread identity and stacks are fixed for the life of a thread,
    // whatever its registers are doing.
    let stacks = |p: &Proc| -> BTreeMap<u32, (u64, Range<u64>)> {
        p.lwps()
            .unwrap()
            .into_iter()
            .map(|l| (l.tid, (l.regs.fsbase, l.stack_range)))
            .collect()
    };
    assert_eq!(stacks(&core), stacks(&live));
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/// A snapshot recorded from a real process replays everything the
/// capture touched, through a file, with the process itself gone from
/// the picture — the whole point of [`Recorder`].
#[test]
fn test_snapshot_replays_a_live_target() {
    let parked = Parked::spawn();
    let live = Proc::grab_pid(parked.pid()).expect("failed to grab the target");
    let recorder = Recorder::new(&live);

    let addr = marker_addr(&live, MARKER_VALUE_SYM);
    let bytes = recorder
        .read_bytes(addr, 64)
        .expect("failed to read memory");
    let by_name = recorder
        .lookup_symbol_by_name(MARKER_FN)
        .expect("the marker fn is in the symtab");
    let fn_addr = by_name.st_value;
    let by_addr = recorder.lookup_symbol_by_addr(fn_addr);
    assert!(
        recorder
            .lookup_symbol_by_name("no_such_symbol_anywhere")
            .is_none()
    );
    let lwps = recorder.lwps().expect("failed to list the target's lwps");
    let key_sym = live
        .lookup_symbol_by_name(TSD_KEY_SYM)
        .expect("the tsd key is in the symtab");
    let tls: Vec<Option<u64>> = lwps
        .iter()
        .map(|l| {
            recorder
                .tls_var_addr(&l.regs, &key_sym)
                .expect("failed to resolve the thread-local")
        })
        .collect();
    let snapshot = recorder.snapshot().expect("failed to build the snapshot");

    // Through a file, the way the capture tools write it.
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let path = dir.path().join("park.snapshot");
    snapshot.save(&path).expect("failed to save the snapshot");
    let replay = Snapshot::load(&path).expect("failed to load the snapshot");
    assert_eq!(replay, snapshot);

    assert_eq!(replay.read_bytes(addr, 64).unwrap(), bytes);
    assert_eq!(replay.read_u64(addr).unwrap(), MARKER_VALUE);
    assert_eq!(replay.lookup_symbol_by_name(MARKER_FN), Some(by_name));
    assert_eq!(replay.lookup_symbol_by_addr(fn_addr), by_addr);
    assert!(
        replay
            .lookup_symbol_by_name("no_such_symbol_anywhere")
            .is_none()
    );
    assert_eq!(replay.lwps().unwrap(), lwps);
    assert_eq!(replay.mappings().unwrap(), live.mappings().unwrap());

    // Every thread-local the capture resolved replays, and one it never
    // asked about is a hole in the snapshot rather than a null answer.
    for (lwp, want) in lwps.iter().zip(&tls) {
        assert_eq!(replay.tls_var_addr(&lwp.regs, &key_sym).unwrap(), *want);
    }
    let unseen = proc::Regs {
        fsbase: 0xdead_0000,
        ..lwps[0].regs.clone()
    };
    assert!(replay.tls_var_addr(&unseen, &key_sym).is_err());

    // The symtabs come over whole, sorted by address.
    let mut functions = live.symbols().unwrap();
    functions.sort_by_key(|s| s.st_value);
    assert_eq!(replay.symbols().unwrap(), functions);
    let mut objects = live.object_symbols().unwrap();
    objects.sort_by_key(|s| s.st_value);
    assert_eq!(replay.object_symbols().unwrap(), objects);

    // What the capture never read is not there to read.
    assert!(replay.read_bytes(UNMAPPED, 8).is_err());
    assert!(replay.read_bytes(addr, 4096).is_err());
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Everything that can go wrong on the way to a handle does, and says so.
#[test]
fn test_grab_failures() {
    // A pid that has come and gone.
    let mut child = Command::new("/bin/true")
        .spawn()
        .expect("failed to run true");
    let reaped = child.id();
    child.wait().expect("failed to reap true");
    let err = Proc::grab_pid(reaped).expect_err("grabbed a process that had exited");
    assert!(
        err.to_string().starts_with("failed to grab process: "),
        "{err}"
    );
    assert!(Proc::grab_pid_no_stop(reaped).is_err());

    // A core is identified before a backend is chosen, so a file that
    // is not one is turned away by the reader rather than by libproc.
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let junk = dir.path().join("junk");
    std::fs::write(&junk, b"ELF, honest").expect("failed to write the junk file");
    let err = Proc::open_core(&junk).expect_err("opened a file that is not a core");
    assert_eq!(err.to_string(), "malformed core file: not an ELF file");

    // Nor can a file that is not there be identified, nor a path the
    // operating system will not accept at all.
    assert!(Proc::open_core(&dir.path().join("missing")).is_err());
    assert!(Proc::open_core(Path::new("core\0dump")).is_err());
}

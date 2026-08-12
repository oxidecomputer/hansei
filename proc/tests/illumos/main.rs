//! The on-box suite that holds the portable illumos core reader to
//! libproc, the reference reader, on the one machine that has both. It
//! compiles nowhere else, so `cargo test -p proc` runs it on the box
//! and skips it everywhere else.
//!
//! The target is `test-programs`' `park-target`, built by `regen.sh` the
//! way every other on-box suite gets its fixtures and driven to its
//! parked steady state by blocking on the readiness line it prints —
//! there are no timing sleeps anywhere. Its symbols, its memory contents
//! and its threads are all known to this file, and it reports the LWP
//! ids procfs has for it, an oracle neither reader had a hand in.
//!
//! Every test runs against a core taken from the parked target, read
//! twice: through the portable reader, and through libproc.

#![cfg(target_os = "illumos")]

use proc::snapshot::{Recorder, Snapshot};

mod libproc;
use libproc::Core as LibprocCore;
use proc::{Proc, Target};

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread;

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

/// One core, two readers behind one set of method names: the portable
/// facade and the reference reader dispatch here the way the facade
/// used to dispatch when libproc was one of its variants, so a check
/// written once pins both.
enum Reader {
    Portable(Proc),
    Libproc(LibprocCore),
}

/// Forward a method call to whichever reader is in hand. Both spell the
/// whole surface these tests use identically, inherent or via [`Target`].
macro_rules! forward {
    ($self:ident, $method:ident($($arg:expr),*)) => {
        match $self {
            Reader::Portable(p) => p.$method($($arg),*),
            Reader::Libproc(c) => c.$method($($arg),*),
        }
    };
}

impl Reader {
    /// The reader as a [`Target`], for the asserts that pin the trait
    /// surface against the inherent one. Only the portable reader is
    /// one: libproc copies through a handle and cannot lend, which is
    /// exactly what keeps it out of the facade.
    fn as_target(&self) -> Option<&dyn Target> {
        match self {
            Reader::Portable(p) => Some(p),
            Reader::Libproc(_) => None,
        }
    }

    /// An owning read both readers can answer: the portable reader
    /// copies out of the lend, libproc copies through its handle.
    fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<Vec<u8>> {
        match self {
            Reader::Portable(p) => Target::read_bytes(p, addr, len).map(<[u8]>::to_vec),
            Reader::Libproc(c) => c.read_bytes(addr, len),
        }
    }

    fn read_u64(&self, addr: u64) -> proc::Result<u64> {
        forward!(self, read_u64(addr))
    }
    fn read_u32(&self, addr: u64) -> proc::Result<u32> {
        forward!(self, read_u32(addr))
    }
    fn read_u16(&self, addr: u64) -> proc::Result<u16> {
        forward!(self, read_u16(addr))
    }
    fn read_u8(&self, addr: u64) -> proc::Result<u8> {
        forward!(self, read_u8(addr))
    }
    fn lookup_symbol_by_name(&self, name: &str) -> Option<proc::SymbolBuf> {
        forward!(self, lookup_symbol_by_name(name))
    }
    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<proc::SymbolBuf> {
        forward!(self, lookup_symbol_by_addr(addr))
    }
    fn lookup_symbol_name_by_addr(&self, addr: u64) -> Option<String> {
        forward!(self, lookup_symbol_name_by_addr(addr))
    }
    fn symbols(&self) -> proc::Result<Vec<proc::SymbolBuf>> {
        forward!(self, symbols())
    }
    fn object_symbols(&self) -> proc::Result<Vec<proc::SymbolBuf>> {
        forward!(self, object_symbols())
    }
    fn mappings(&self) -> proc::Result<proc::Mappings> {
        forward!(self, mappings())
    }
    fn addr_to_map(&self, addr: u64) -> Option<proc::LoadedObject> {
        forward!(self, addr_to_map(addr))
    }
    fn addr_is_mapped(&self, addr: u64) -> bool {
        forward!(self, addr_is_mapped(addr))
    }
    fn regs(&self, lwp: u32) -> proc::Result<proc::Regs> {
        forward!(self, regs(lwp))
    }
    fn lwps(&self) -> proc::Result<Vec<proc::LwpInfo>> {
        forward!(self, lwps())
    }
    fn lwp_name(&self, lwpid: u32) -> proc::Result<String> {
        forward!(self, lwp_name(lwpid))
    }
    fn lwp_tsd(&self, lwp: u32) -> proc::Result<[u64; 9]> {
        forward!(self, lwp_tsd(lwp))
    }
    fn tsd_from_regs(&self, regs: &proc::Regs) -> proc::Result<[u64; 9]> {
        forward!(self, tsd_from_regs(regs))
    }
    fn tls_var_addr(&self, regs: &proc::Regs, sym: &proc::SymbolBuf) -> proc::Result<Option<u64>> {
        forward!(self, tls_var_addr(regs, sym))
    }
    fn status(&self) -> proc::Status {
        forward!(self, status())
    }
}

/// Run `check` against the same core twice: once through the portable
/// reader, once through libproc — every behavior these tests pin is
/// pinned for the reference reader and the reader held to it alike.
fn for_each_target(check: impl Fn(&Reader, &Parked, &str)) {
    let parked = Parked::spawn();
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core = gcore(parked.pid(), dir.path());

    let portable = Proc::open_core(&core).expect("failed to open the core");
    check(&Reader::Portable(portable), &parked, "portable");

    let libproc = LibprocCore::open(&core).expect("libproc failed to open the core");
    check(&Reader::Libproc(libproc), &parked, "libproc");
}

/// The portable reader is held to libproc, on the same core, on the one
/// machine that has both.
///
/// It is what a Linux host gets when handed an illumos core, and there
/// is nothing there to check it against — so it is checked here, where
/// the answer is known. Anything the two disagree about is the portable
/// reader being wrong, since libproc is what this crate has always
/// meant by reading a core.
#[test]
fn test_the_portable_reader_agrees_with_libproc() {
    use proc::coredump::illumos::Core;

    let parked = Parked::spawn();
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core_path = gcore(parked.pid(), dir.path());

    let libproc = LibprocCore::open(&core_path).expect("libproc failed to open the core");
    let portable = Core::open(&core_path).expect("the portable reader failed to open the core");

    // Threads, their registers, and the stacks they are running on.
    let want = libproc.lwps().unwrap();
    let got = portable.lwps().unwrap();
    assert_eq!(
        got.iter().map(|l| l.tid).collect::<Vec<_>>(),
        want.iter().map(|l| l.tid).collect::<Vec<_>>()
    );
    for (a, b) in got.iter().zip(&want) {
        assert_eq!(a.regs, b.regs, "tid {} registers", a.tid);
        assert_eq!(a.stack_range, b.stack_range, "tid {} stack", a.tid);
        assert_eq!(a.tstamp, b.tstamp, "tid {} timestamp", a.tid);
    }
    assert_eq!(portable.exec_name().unwrap(), libproc.exec_name().unwrap());

    // Thread names, which the portable reader takes from the core's own
    // NT_LWPNAME notes and libproc asks the same core for its way. The
    // main thread was never given one, so both report nothing for it.
    for lwp in &want {
        assert_eq!(
            portable.lwp_name(lwp.tid).unwrap_or_default(),
            libproc.lwp_name(lwp.tid).unwrap_or_default(),
            "tid {} name",
            lwp.tid
        );
    }
    let names: BTreeSet<String> = want
        .iter()
        .filter_map(|l| portable.lwp_name(l.tid).ok())
        .collect();
    for worker in WORKERS {
        assert!(names.contains(worker), "{worker} missing from {names:?}");
    }

    // Symbols of the executable, by name and by address. The core
    // carries its own symbol table, so this is the reader reading it
    // rather than the binary on disk.
    for name in [MARKER_FN, MARKER_VALUE_SYM, COUNTER_SYM, TSD_KEY_SYM] {
        assert_eq!(
            portable.lookup_symbol_by_name(name),
            libproc.lookup_symbol_by_name(name),
            "{name}"
        );
    }

    // The whole table, not just the markers: a systematic error in
    // reading the core's symbols — an offset, a bias, a filter — shows
    // up here and in no single lookup. Compared as name to address,
    // since the two arrive at their tables by different routes and need
    // not agree about ordering or duplicates.
    let table = |syms: Vec<proc::SymbolBuf>| -> BTreeMap<String, u64> {
        syms.into_iter().map(|s| (s.name, s.st_value)).collect()
    };
    let want_fns = table(libproc.symbols().unwrap());
    let got_fns = table(portable.symbols().unwrap());
    assert!(!want_fns.is_empty(), "libproc found no function symbols");
    compare_tables("function symbols", &got_fns, &want_fns);
    compare_tables(
        "object symbols",
        &table(portable.object_symbols().unwrap()),
        &table(libproc.object_symbols().unwrap()),
    );

    // Every function in that table resolves back by address, through
    // both readers alike, to the same name. The linker folds identical
    // code and leaves several names on one address, so this is also
    // where the two have to agree about which alias to pick.
    for (name, addr) in &want_fns {
        assert_eq!(
            portable.lookup_symbol_by_addr(*addr).map(|s| s.name),
            libproc.lookup_symbol_by_addr(*addr).map(|s| s.name),
            "{name} at {addr:#x}"
        );
    }
    let marker = portable.lookup_symbol_by_name(MARKER_FN).unwrap();
    assert_eq!(
        portable
            .lookup_symbol_by_addr(marker.st_value)
            .map(|s| s.name),
        Some(MARKER_FN.to_string())
    );
    // And in a shared object, where the core's tables hold offsets from
    // where the object was loaded rather than addresses.
    for lwp in &want {
        assert_eq!(
            portable.lookup_symbol_by_addr(lwp.regs.rip),
            libproc.lookup_symbol_by_addr(lwp.regs.rip),
            "tid {} pc {:#x}",
            lwp.tid,
            lwp.regs.rip
        );
    }

    // Memory, at an address whose contents the fixture fixes.
    let addr = libproc
        .lookup_symbol_by_name(MARKER_VALUE_SYM)
        .expect("the marker static is in the symtab")
        .st_value;
    assert_eq!(portable.read_u64(addr).unwrap(), MARKER_VALUE);
    assert_eq!(
        Target::read_bytes(&portable, addr, 64).unwrap(),
        libproc.read_bytes(addr, 64).unwrap().as_slice()
    );
    assert!(Target::read_bytes(&portable, UNMAPPED, 8).is_err());

    // Thread-locals, walked through the core's own memory rather than
    // through libproc's handle.
    let key = portable.lookup_symbol_by_name(TSD_KEY_SYM).unwrap();
    for lwp in &want {
        assert_eq!(
            portable.tls_var_addr(&lwp.regs, &key).unwrap(),
            libproc.tls_var_addr(&lwp.regs, &key).unwrap(),
            "tid {} thread-local",
            lwp.tid
        );
    }

    // Mappings, names included. An illumos core writes down no such
    // names, so both readers arrive at them by walking the runtime
    // linker's list in the target's memory.
    let named = |m: &proc::Mappings| {
        m.iter()
            .map(|o| (o.range(), o.path.clone()))
            .collect::<Vec<_>>()
    };
    let want_maps = named(&libproc.mappings().unwrap());
    assert!(
        want_maps.iter().filter(|(_, p)| p.is_some()).count() >= 3,
        "libproc named too little for this to be a test: {want_maps:#?}"
    );
    assert_eq!(named(&portable.mappings().unwrap()), want_maps);
}

/// Compare two symbol tables and say how they differ, rather than
/// printing both: these run to thousands of mangled names, and the
/// interesting part is the handful that disagree.
fn compare_tables(what: &str, got: &BTreeMap<String, u64>, want: &BTreeMap<String, u64>) {
    let sample = |mut names: Vec<String>| {
        names.truncate(5);
        names
    };
    let missing = sample(
        want.keys()
            .filter(|k| !got.contains_key(*k))
            .cloned()
            .collect(),
    );
    let extra = sample(
        got.keys()
            .filter(|k| !want.contains_key(*k))
            .cloned()
            .collect(),
    );
    let moved: Vec<String> = sample(
        want.iter()
            .filter(|(k, v)| got.get(*k).is_some_and(|g| g != *v))
            .map(|(k, v)| format!("{k} want {v:#x} got {:#x}", got[k]))
            .collect(),
    );

    assert!(
        missing.is_empty() && extra.is_empty() && moved.is_empty(),
        "{what}: {} in libproc, {} in the portable reader\n  \
         missing {missing:#?}\n  extra {extra:#?}\n  moved {moved:#?}",
        want.len(),
        got.len()
    );
}

/// The runtime address of one of the target's marker symbols.
fn marker_addr(p: &Reader, name: &str) -> u64 {
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

        // An owning read serves the same bytes from both readers; the
        // portable reader also lends them straight from the mapped core
        // through the Target trait, which libproc — copying through a
        // handle — is not.
        assert_eq!(
            p.read_bytes(addr, 8).unwrap(),
            MARKER_VALUE.to_le_bytes(),
            "({who})"
        );
        if let Some(t) = p.as_target() {
            let lent = t.read_bytes(addr, 8).expect("the core lends the marker");
            assert_eq!(lent, MARKER_VALUE.to_le_bytes());
            assert_eq!(t.read_u64(addr).unwrap(), MARKER_VALUE);
        } else {
            assert_eq!(who, "libproc", "only libproc is not a Target");
        }

        // Nothing is mapped at the first page, so every read that has to
        // fill its buffer fails there.
        assert!(p.read_u64(UNMAPPED).is_err(), "({who})");
        assert!(p.read_u8(UNMAPPED).is_err(), "({who})");
        assert!(p.read_bytes(UNMAPPED, 8).is_err(), "({who})");
        if let Some(t) = p.as_target() {
            assert!(t.read_bytes(UNMAPPED, 8).is_err(), "({who})");
        }
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
        if let Some(t) = p.as_target() {
            assert_eq!(t.symbols().unwrap(), functions, "({who})");
            assert_eq!(t.object_symbols().unwrap(), objects, "({who})");
            assert_eq!(
                t.lookup_symbol_by_name(MARKER_FN).as_ref(),
                Some(&sym),
                "({who})"
            );
            assert_eq!(
                t.lookup_symbol_by_addr(sym.st_value).as_ref(),
                Some(&back),
                "({who})"
            );
        }
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

        if let Some(t) = p.as_target() {
            assert_eq!(t.mappings().unwrap(), maps, "({who})");
        }
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

        // There is no LWP 0.
        assert!(p.lwp_name(0).is_err(), "({who})");
        assert!(p.regs(0).is_err(), "({who})");

        if let Some(t) = p.as_target() {
            assert_eq!(t.lwps().unwrap(), lwps, "({who})");
        }
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
// Snapshots
// ---------------------------------------------------------------------------

/// A snapshot recorded from a real target replays everything the
/// capture touched, through a file, with the target itself gone from
/// the picture — the whole point of [`Recorder`].
#[test]
fn test_snapshot_replays_a_recorded_target() {
    let parked = Parked::spawn();
    let dir = tempfile::tempdir().expect("failed to create a tempdir");
    let core = gcore(parked.pid(), dir.path());
    let source = Proc::open_core(&core).expect("failed to open the core");
    let recorder = Recorder::new(&source);

    let addr = source
        .lookup_symbol_by_name(MARKER_VALUE_SYM)
        .expect("the marker static is in the symtab")
        .st_value;
    let bytes = recorder
        .read_bytes(addr, 64)
        .expect("failed to read memory")
        .to_vec();
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
    let key_sym = source
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
    assert_eq!(replay.mappings().unwrap(), source.mappings().unwrap());

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
    let mut functions = source.symbols().unwrap();
    functions.sort_by_key(|s| s.st_value);
    assert_eq!(replay.symbols().unwrap(), functions);
    let mut objects = source.object_symbols().unwrap();
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
fn test_open_core_failures() {
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

    // libproc turns away the same junk its own way.
    let err = LibprocCore::open(&junk).expect_err("libproc opened a non-core");
    assert!(
        err.to_string().starts_with("failed to grab process: "),
        "{err}"
    );
}

//! Unit tests for the platform-independent half of the crate: the
//! register model, the mapping table, and the memory helpers every
//! [`Target`] inherits.
//!
//! The core readers are covered by their own unit tests and the
//! on-box suites under `tests/`; snapshot capture and replay by the
//! tests in [`crate::snapshot`].

use crate::x86_64::*;
use crate::*;

use std::cmp::Ordering;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------

/// Every register field set to its own DWARF number, so an index that
/// lands on the wrong field cannot pass unnoticed.
fn numbered_regs() -> Regs {
    Regs {
        rax: 0,
        rdx: 1,
        rcx: 2,
        rbx: 3,
        rsi: 4,
        rdi: 5,
        rbp: 6,
        rsp: 7,
        r8: 8,
        r9: 9,
        r10: 10,
        r11: 11,
        r12: 12,
        r13: 13,
        r14: 14,
        r15: 15,
        rip: 16,
        ..Regs::default()
    }
}

/// [`x86_64::REGS`] is in DWARF-number order, and indexing a `Regs` by
/// one reaches the field of that name.
#[test]
fn test_index_reaches_the_named_field() {
    let regs = numbered_regs();
    for (number, reg) in REGS.iter().enumerate() {
        assert_eq!(reg.0 as usize, number, "{reg} is out of DWARF order");
        assert_eq!(regs[*reg], number as u64, "{reg} indexes the wrong field");
    }
}

#[test]
fn test_index_mut_writes_the_named_field() {
    let mut regs = Regs::default();
    for (number, reg) in REGS.iter().enumerate() {
        regs[*reg] = number as u64;
    }
    // %rip is not reachable through the index; everything else is.
    let want = Regs {
        rip: 0,
        ..numbered_regs()
    };
    assert_eq!(regs, want);
}

/// %rip has a DWARF number but no slot in the index tables: the general
/// registers stop at %r15.
#[test]
#[should_panic]
fn test_index_rejects_rip() {
    let _ = numbered_regs()[RIP];
}

#[test]
fn test_register_names() {
    let names: Vec<String> = (0..=16).map(|n| Reg(n).to_string()).collect();
    assert_eq!(
        names,
        [
            "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15", "rip",
        ]
    );
    assert_eq!(Reg(17).to_string(), "<unknown_register>");
    // Debug is the raw DWARF number, in hex.
    assert_eq!(format!("{:?}", Reg(10)), "0xa");
}

/// The System V callee-saved set.
#[test]
fn test_callee_saved_set() {
    let saved: Vec<Reg> = (0..=16).map(Reg).filter(|r| r.is_callee_saved()).collect();
    assert_eq!(saved, [RBX, RBP, R12, R13, R14, R15]);
}

#[test]
fn test_gimli_register_round_trip() {
    for n in 0..=16 {
        let reg = Reg(n);
        let gimli: gimli::Register = reg.into();
        assert_eq!(gimli.0, n);
        assert_eq!(Reg::from(gimli), reg);
    }
}

/// The two-column register dump, pinned exactly: it is what `hansei`
/// prints for a thread.
#[test]
fn test_regs_display_layout() {
    let pad = " ".repeat(25);
    let expected = format!(
        "%rax = 0x0000000000000000\t%r8  = 0x0000000000000008\n\
         %rbx = 0x0000000000000003\t%r9  = 0x0000000000000009\n\
         %rcx = 0x0000000000000002\t%r10 = 0x000000000000000a\n\
         %rdx = 0x0000000000000001\t%r11 = 0x000000000000000b\n\
         %rsi = 0x0000000000000004\t%r12 = 0x000000000000000c\n\
         %rdi = 0x0000000000000005\t%r13 = 0x000000000000000d\n\
         {pad}\t%r14 = 0x000000000000000e\n\
         {pad}\t%r15 = 0x000000000000000f\n\
         \n\
         %rip = 0x0000000000000010\n\
         %rbp = 0x0000000000000006\n\
         %rsp = 0x0000000000000007"
    );
    assert_eq!(numbered_regs().to_string(), expected);
}

/// Debug prints every field, values in hex rather than decimal.
#[test]
fn test_regs_debug_is_hex() {
    let debug = format!("{:?}", numbered_regs());
    assert!(debug.starts_with("Regs {"), "{debug}");
    for field in ["rip: 0x10", "r15: 0xf", "rax: 0x0", "gsbase: 0x0"] {
        assert!(debug.contains(field), "{field} missing from {debug}");
    }
}

// ---------------------------------------------------------------------------
// Mapping flags and loaded objects
// ---------------------------------------------------------------------------

/// One `pr_mflags` bit, the predicate that reads it, and its name.
type FlagProbe = (&'static str, u32, fn(&MapFlags) -> bool);

/// The `prmap_t.pr_mflags` bits, each read by exactly one predicate.
#[test]
fn test_map_flags_decode_procfs_bits() {
    let probes: [FlagProbe; 6] = [
        ("exec", 0x01, MapFlags::is_exec),
        ("write", 0x02, MapFlags::is_write),
        ("read", 0x04, MapFlags::is_read),
        ("shared", 0x08, MapFlags::is_shared),
        ("break", 0x10, MapFlags::is_break),
        ("anon", 0x40, MapFlags::is_anon),
    ];
    for (name, bit, _) in probes {
        let flags = MapFlags(bit);
        for (other, _, pred) in probes {
            assert_eq!(
                pred(&flags),
                name == other,
                "the {name} bit {bit:#x} answers is_{other}"
            );
        }
    }

    // A guard page has no bits at all; nothing claims it.
    let none = MapFlags(0);
    assert!(probes.iter().all(|(_, _, pred)| !pred(&none)));
}

#[test]
fn test_map_flags_debug_spells_out_the_bits() {
    let debug = format!("{:?}", MapFlags(0x05));
    for field in ["is_read: true", "is_exec: true", "is_write: false"] {
        assert!(debug.contains(field), "{field} missing from {debug}");
    }
    assert!(debug.contains("0b00000000000101"), "{debug}");
}

fn obj(path: Option<&str>, vaddr: u64, size: u64, flags: u32) -> LoadedObjectWithPath {
    LoadedObjectWithPath {
        path: path.map(str::to_string),
        vaddr,
        size,
        flags: MapFlags(flags),
    }
}

/// The four mapping kinds a target is sorted into, and the flag
/// combinations that must *not* be mistaken for them.
#[test]
fn test_mapping_classification() {
    let text = obj(Some("/bin/prog"), 0x1000, 0x1000, 0x05); // r-x
    let data = obj(Some("/bin/prog"), 0x2000, 0x1000, 0x06); // rw-, file backed
    let heap = obj(None, 0x3000, 0x1000, 0x56); // rw- anon, the break
    let stack = obj(None, 0x4000, 0x1000, 0x46); // rw- anon, not the break
    let guard = obj(None, 0x5000, 0x1000, 0x00);

    for (name, m, want) in [
        // (is_text, is_data, is_heap, is_guard)
        ("text", &text, [true, false, false, false]),
        ("data", &data, [false, true, false, false]),
        ("heap", &heap, [false, false, true, false]),
        ("stack", &stack, [false, false, false, false]),
        ("guard", &guard, [false, false, false, true]),
    ] {
        let got = [m.is_text(), m.is_data(), m.is_heap(), m.is_guard()];
        assert_eq!(got, want, "{name} classified as {got:?}");
    }
}

#[test]
fn test_file_name_is_the_last_path_component() {
    assert_eq!(
        obj(Some("/lib/libc.so.1"), 0, 0, 0).file_name(),
        Some("libc.so.1")
    );
    assert_eq!(obj(Some("/bin/prog"), 0, 0, 0).file_name(), Some("prog"));
    assert_eq!(obj(None, 0, 0, 0).file_name(), None);
    // libproc resolves mapping names to absolute paths, so a bare name
    // never reaches here; it has no separator and so no component.
    assert_eq!(obj(Some("prog"), 0, 0, 0).file_name(), None);
    assert_eq!(obj(Some("/bin/"), 0, 0, 0).file_name(), Some(""));
}

#[test]
fn test_ranges_saturate_at_the_top_of_the_address_space() {
    assert_eq!(obj(None, 0x1000, 0x100, 0).range(), 0x1000..0x1100);
    assert_eq!(
        obj(None, u64::MAX - 8, 0x100, 0).range(),
        u64::MAX - 8..u64::MAX
    );
    let bare = LoadedObject {
        vaddr: u64::MAX,
        size: 1,
        flags: MapFlags(0),
    };
    assert_eq!(bare.range(), u64::MAX..u64::MAX);
}

/// Mappings order by address alone: two objects at the same address are
/// equal for sorting however else they differ.
#[test]
fn test_loaded_objects_order_by_address() {
    let low = obj(Some("/z"), 0x1000, 0x4000, 0x06);
    let high = obj(Some("/a"), 0x2000, 0x10, 0x05);
    assert_eq!(low.cmp(&high), Ordering::Less);
    assert_eq!(high.cmp(&low), Ordering::Greater);
    assert_eq!(low.cmp(&obj(None, 0x1000, 0, 0)), Ordering::Equal);
    assert_eq!(low.partial_cmp(&high), Some(Ordering::Less));

    let bare = |vaddr| LoadedObject {
        vaddr,
        size: 0,
        flags: MapFlags(0),
    };
    assert_eq!(bare(1).cmp(&bare(2)), Ordering::Less);
    assert_eq!(bare(2).partial_cmp(&bare(2)), Some(Ordering::Equal));
}

// ---------------------------------------------------------------------------
// The mapping table
// ---------------------------------------------------------------------------

/// Three mappings with a hole between the second and third.
fn mappings() -> Mappings {
    Mappings {
        inner: vec![
            obj(Some("/bin/prog"), 0x1000, 0x1000, 0x05),
            obj(Some("/bin/prog"), 0x2000, 0x1000, 0x06),
            obj(None, 0x9000, 0x1000, 0x46),
        ],
    }
}

#[test]
fn test_lookup_finds_the_containing_mapping() {
    let maps = mappings();
    for (addr, want) in [
        (0x1000, Some("/bin/prog")),
        (0x1fff, Some("/bin/prog")),
        (0x9000, None),
    ] {
        let found = maps
            .get(addr)
            .unwrap_or_else(|| panic!("{addr:#x} unmapped"));
        assert_eq!(found.path.as_deref(), want);
        assert!(found.range().contains(&addr));
        assert!(maps.contains_addr(addr));
        assert_eq!(maps[addr], *found);
    }

    // Below, between and above the mapped ranges.
    for addr in [0, 0xfff, 0x3000, 0x8fff, 0xa000] {
        assert!(maps.get(addr).is_none(), "{addr:#x} resolved");
        assert!(!maps.contains_addr(addr));
    }
}

#[test]
#[should_panic(expected = "no object found for address")]
fn test_indexing_an_unmapped_address_panics() {
    let _ = mappings()[0x3000];
}

#[test]
fn test_mappings_expose_their_slice() {
    let maps = mappings();
    assert_eq!(maps.as_slice().len(), 3);
    // Deref reaches the slice's own methods.
    assert_eq!(maps.len(), 3);
    assert_eq!(maps.first().unwrap().vaddr, 0x1000);
    assert!(maps.iter().eq(maps.as_slice().iter()));

    // Borrowed and owned iteration walk the same objects in order.
    let borrowed: Vec<u64> = (&maps).into_iter().map(|m| m.vaddr).collect();
    let owned: Vec<u64> = maps.clone().into_iter().map(|m| m.vaddr).collect();
    assert_eq!(borrowed, [0x1000, 0x2000, 0x9000]);
    assert_eq!(owned, borrowed);
}

// ---------------------------------------------------------------------------
// The provided Target methods
// ---------------------------------------------------------------------------

/// A memory-only [`Target`], recording the last read so tests can pin
/// what the provided methods asked the target for.
struct MemTarget {
    base: u64,
    bytes: Vec<u8>,
    last_read: Mutex<Option<(u64, u64)>>,
}

impl MemTarget {
    fn new(base: u64, bytes: Vec<u8>) -> Self {
        Self {
            base,
            bytes,
            last_read: Mutex::new(None),
        }
    }
}

impl Target for MemTarget {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<&[u8]> {
        *self.last_read.lock().unwrap() = Some((addr, len));
        let start = addr
            .checked_sub(self.base)
            .ok_or_else(|| Error::unmapped(addr, len))? as usize;
        let end = start
            .checked_add(len as usize)
            .ok_or_else(|| Error::unmapped(addr, len))?;
        self.bytes
            .get(start..end)
            .ok_or_else(|| Error::unmapped(addr, len))
    }

    fn lookup_symbol_by_addr(&self, _addr: u64) -> Option<SymbolBuf> {
        None
    }

    fn lookup_symbol_by_name(&self, _name: &str) -> Option<SymbolBuf> {
        None
    }

    fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        Ok(Vec::new())
    }

    fn mappings(&self) -> Result<Mappings> {
        Ok(Mappings { inner: Vec::new() })
    }

    fn lwps(&self) -> Result<Vec<LwpInfo>> {
        Ok(Vec::new())
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        tls_addr_from_pthread_key(&|addr| self.read_u64(addr), regs, sym)
    }
}

#[test]
fn test_read_u64_decodes_little_endian() {
    let target = MemTarget::new(0x1000, (1..=16).collect());
    assert_eq!(target.read_u64(0x1000).unwrap(), 0x0807_0605_0403_0201);
    assert_eq!(*target.last_read.lock().unwrap(), Some((0x1000, 8)));
    assert_eq!(target.read_u64(0x1008).unwrap(), 0x100f_0e0d_0c0b_0a09);
    // A word straddling the end of memory is an error, not a short read.
    assert!(target.read_u64(0x100c).is_err());
}

/// Targets without an object symtab report an empty one rather than
/// failing; only [`crate::snapshot::Snapshot`] and `Proc` override it.
#[test]
fn test_object_symbols_default_to_none() {
    let target = MemTarget::new(0, Vec::new());
    assert!(target.object_symbols().unwrap().is_empty());
}

/// `ulwp_t.ul_ftsd` sits at a fixed offset past `%fsbase` and holds nine
/// pointers: the offset, the length and the decode are all pinned here,
/// because nothing in the target tells us when they go wrong.
#[test]
fn test_tsd_reads_ul_ftsd_past_fsbase() {
    const FSBASE: u64 = 0x7000;
    const UL_FTSD_OFFSET: u64 = 320;

    let mut bytes = vec![0xaa; UL_FTSD_OFFSET as usize];
    let slots: [u64; 9] = [1, 2, 3, 4, 5, 6, 7, 8, u64::MAX];
    bytes.extend(slots.iter().flat_map(|slot| slot.to_le_bytes()));
    // Trailing bytes the read must not reach.
    bytes.extend([0xff; 64]);

    let target = MemTarget::new(FSBASE, bytes);
    let regs = Regs {
        fsbase: FSBASE,
        ..Regs::default()
    };
    let read_u64 = |addr| target.read_u64(addr);
    assert_eq!(tsd_from_fsbase(&read_u64, &regs).unwrap(), slots);
    assert_eq!(
        *target.last_read.lock().unwrap(),
        Some((FSBASE + UL_FTSD_OFFSET + 8 * 8, 8)),
        "the TSD reads moved off ul_ftsd"
    );
}

#[test]
fn test_tsd_fails_when_fsbase_is_not_readable() {
    let target = MemTarget::new(0x7000, vec![0; 320 + 8]);
    let regs = Regs {
        fsbase: 0x7000,
        ..Regs::default()
    };
    // The slots run past the end of the mapping.
    assert!(tsd_from_fsbase(&|addr| target.read_u64(addr), &regs).is_err());

    let regs = Regs {
        fsbase: 0,
        ..Regs::default()
    };
    assert!(tsd_from_fsbase(&|addr| target.read_u64(addr), &regs).is_err());
}

// ---------------------------------------------------------------------------
// Thread-locals through a pthread key
// ---------------------------------------------------------------------------

/// A target laid out the way the illumos TLS model expects: the key
/// static at `KEY_ADDR` holds `key`, and the fast-TSD slots sit past
/// `%fsbase`, slot *n* holding `0xf00 + n` so a misindex is visible.
fn keyed_target(key: u64) -> (MemTarget, Regs, SymbolBuf) {
    const BASE: u64 = 0x7000;
    const KEY_ADDR: u64 = 0x7000;
    const UL_FTSD_OFFSET: u64 = 320;

    let mut bytes = key.to_le_bytes().to_vec();
    bytes.resize(UL_FTSD_OFFSET as usize, 0xaa);
    // Slot 4 is null: a thread that never set that key.
    for slot in 0..9u64 {
        let value = if slot == 4 { 0 } else { 0xf00 + slot };
        bytes.extend(value.to_le_bytes());
    }

    let regs = Regs {
        fsbase: BASE,
        ..Regs::default()
    };
    let sym = SymbolBuf {
        name: "CONTEXT_KEY".to_string(),
        st_name: 0,
        st_info: 0,
        st_other: 0,
        st_shndx: 1,
        st_value: KEY_ADDR,
        st_size: 8,
    };
    (MemTarget::new(BASE, bytes), regs, sym)
}

#[test]
fn test_pthread_key_indexes_the_tsd_slot() {
    for key in [0, 3, 8] {
        let (target, regs, sym) = keyed_target(key);
        assert_eq!(
            target.tls_var_addr(&regs, &sym).unwrap(),
            Some(0xf00 + key),
            "key {key} reached the wrong slot"
        );
    }
}

/// A null slot is an ordinary answer — most LWPs in a tokio process
/// never set the key — and must not be confused with the address 0.
#[test]
fn test_unset_key_holds_nothing() {
    let (target, regs, sym) = keyed_target(4);
    assert_eq!(target.tls_var_addr(&regs, &sym).unwrap(), None);
}

/// A key past the ninth slot lives in the slow TSD array, which is not
/// supported; it must say so rather than index out of bounds.
#[test]
fn test_key_past_the_fast_slots_is_rejected() {
    for key in [9, 64, u64::MAX] {
        let (target, regs, sym) = keyed_target(key);
        let err = target.tls_var_addr(&regs, &sym).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("pthread key {key} is outside the fast-TSD range; slow TSD is unsupported")
        );
    }
}

/// The two reads it depends on fail independently: an unreadable key
/// static, and an unreadable `ulwp_t`.
#[test]
fn test_key_resolution_needs_both_reads() {
    let (target, regs, mut sym) = keyed_target(0);
    sym.st_value = 0;
    assert!(target.tls_var_addr(&regs, &sym).is_err());

    let (target, _, sym) = keyed_target(0);
    let regs = Regs {
        fsbase: 0,
        ..Regs::default()
    };
    assert!(target.tls_var_addr(&regs, &sym).is_err());
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[test]
fn test_error_messages() {
    let cases = [
        (
            Error::unmapped(0x10, 8),
            "address range 0x10..+0x8 is not mapped in the target",
        ),
        (
            Error::grab_failed("no such process"),
            "failed to grab process: no such process",
        ),
        (
            Error::lgrab_failed("no such lwp"),
            "failed to grab thread: no such lwp",
        ),
        (Error::lwp_iter_failed(), "failed to iterate over lwps"),
        (Error::map_iter_failed(), "failed to iterate over mappings"),
        (Error::no_exec_name(), "failed to get exec name"),
        (Error::no_lwp_name(), "failed to get lwp name"),
        (
            Error::symbol_iter_failed(),
            "failed to iterate over symbols",
        ),
        (
            Error::tls_key_out_of_range(12),
            "pthread key 12 is outside the fast-TSD range; slow TSD is unsupported",
        ),
        (
            Error::tls_not_recorded("CONTEXT", 0x7000),
            "the capture recorded no address for thread-local CONTEXT in the thread at 0x7000",
        ),
        (Error::unexpected_eof(), "failed to fill whole buffer"),
    ];
    for (err, want) in cases {
        assert_eq!(err.to_string(), want);
        // Every error carries a backtrace slot, captured or not.
        let _ = err.backtrace();
    }
}

#[test]
fn test_errors_wrap_their_sources() {
    let nul = std::ffi::CString::new("with\0nul").unwrap_err();
    assert_eq!(
        Error::bad_path(nul).to_string(),
        "could not convert path to C string"
    );

    let no_nul = std::ffi::CStr::from_bytes_until_nul(b"no terminator").unwrap_err();
    assert_eq!(Error::no_nul(no_nul).to_string(), "no nul byte in C string");

    let io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert!(Error::read(io).to_string().starts_with("error: "));
}

// ---------------------------------------------------------------------------
// Fatal signals
// ---------------------------------------------------------------------------

/// Every fault-class signal decodes its codes through the shared
/// table, and everything else — codes past a table, user-sent codes,
/// signals that never fault — decodes nothing.
#[test]
fn test_fault_codes_decode_for_every_fault_signal() {
    assert_eq!(fault_code_name("SIGSEGV", 1), Some("SEGV_MAPERR"));
    assert_eq!(fault_code_name("SIGBUS", 3), Some("BUS_OBJERR"));
    assert_eq!(fault_code_name("SIGILL", 8), Some("ILL_BADSTK"));
    assert_eq!(fault_code_name("SIGFPE", 1), Some("FPE_INTDIV"));
    assert_eq!(fault_code_name("SIGTRAP", 2), Some("TRAP_TRACE"));
    assert_eq!(fault_code_name("SIGSEGV", 3), None);
    assert_eq!(fault_code_name("SIGSEGV", 0), None);
    assert_eq!(fault_code_name("SIGSEGV", -1), None);
    assert_eq!(fault_code_name("SIGKILL", 1), None);
}

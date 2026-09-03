// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What every fixture program needs before it parks.
//!
//! The fixtures exist to be cored while they run, and the suites take
//! that core by pid — `gcore <pid>` from a sibling test process. Linux's
//! Yama LSM decides whether that is allowed, and its common default
//! (`kernel.yama.ptrace_scope = 1`) permits tracing only a descendant,
//! which a sibling is not. A fixture that says nothing therefore cannot
//! be cored at all on a Debian or Ubuntu box, so each one declares who
//! may trace it.

/// Let any process of this uid trace this one, so a test harness can
/// core it by pid whatever `ptrace_scope` says.
///
/// The relation is the calling process's own, so this has to run in the
/// fixture rather than in whatever spawned it, and it is only ever a
/// widening: a system that already allows the attach is unaffected, and
/// no other system's tracing rules are involved.
#[cfg(target_os = "linux")]
pub fn allow_any_tracer() {
    // Yama's own `prctl(2)` option and its "anybody" argument. Both are
    // spelled out here because `libc` does not carry the second.
    const PR_SET_PTRACER: libc::c_int = 0x59616d61;
    const PR_SET_PTRACER_ANY: libc::c_ulong = libc::c_ulong::MAX;

    // SAFETY: `prctl` is variadic; this option takes one unsigned-long
    // argument and touches nothing of ours. A kernel without Yama fails
    // it with EINVAL, which is as good an answer as success.
    unsafe {
        libc::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    }
}

/// Nothing to declare: no other system gates tracing on the tracee's
/// say-so.
#[cfg(not(target_os = "linux"))]
pub fn allow_any_tracer() {}

/// The builder every fixture parks a runtime from. `oxide-tokio-rt`
/// re-exports this same type, so both arms of [`run_builder`] take it.
pub use tokio::runtime::Builder;

/// With the `unstable` feature (the default recipe, built with
/// `--cfg tokio_unstable`), the runtime is oxide-tokio-rt's.
#[cfg(feature = "unstable")]
pub use oxide_tokio_rt::run_builder;

/// Without it, a plain tokio runtime with the same call shape, so a
/// fixture's `main` is identical however the cell is built.
#[cfg(not(feature = "unstable"))]
pub fn run_builder<T>(builder: &mut Builder, main: impl std::future::Future<Output = T>) -> T {
    match builder.enable_all().build() {
        Ok(rt) => rt.block_on(main),
        Err(e) => panic!("failed to initialize Tokio runtime: {e:?}"),
    }
}

/// The ground-truth registry: what a fixture built, stamped into the
/// target's own memory so a reader of its core can hold the census to
/// it.
///
/// A fixture program calls these as it constructs state, before
/// signaling READY — from the code that owns each value, at the moment
/// its address is final (a local live across an await sits in the
/// pinned coroutine frame from the start, so an address taken while
/// the body runs is the address a capture sees). Everything lands in
/// one `#[no_mangle]` static the read side finds by symbol name alone,
/// no DWARF involved; the layout is plain-old-data, re-spelled by hand
/// on the read side (`hansei-runtime`'s `testkit::expect`, which names
/// this module), so the two must move together.
///
/// Registration is silent — the acceptance suite asserts the fixtures
/// write nothing to stderr — and thread-safe: an entry's index is
/// reserved first, its fields written, and only then counted into
/// `committed`, so a reader never sees a half-written entry. The
/// fixtures quiesce before READY, so a capture sees every entry.
pub mod census_expect {
    use std::cell::UnsafeCell;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Room for more entries than any fixture registers; running out is
    /// a fixture bug and panics loudly at fixture runtime.
    const CAPACITY: usize = 64;

    /// Names are substrings matched against monomorphized type names,
    /// so they stay short; longer ones are truncated.
    const NAME_CAP: usize = 64;

    // The `kind` values the read side dispatches on.
    const HELD: u32 = 1;
    const HELD_IN: u32 = 2;
    const SET: u32 = 3;
    const JOIN_SET: u32 = 4;
    const TASK: u32 = 5;

    /// One expectation. `flags` is reserved (a later phase marks
    /// cappable registrations there); `name` is NUL-padded UTF-8.
    #[repr(C)]
    struct Entry {
        kind: u32,
        flags: u32,
        addr: u64,
        count: u64,
        name: [u8; NAME_CAP],
    }

    const EMPTY: Entry = Entry {
        kind: 0,
        flags: 0,
        addr: 0,
        count: 0,
        name: [0; NAME_CAP],
    };

    /// The registry itself: `committed` first so the read side can find
    /// it at offset zero, then the reservation counter, then the
    /// entries.
    #[repr(C)]
    pub struct Registry {
        committed: AtomicU64,
        reserved: AtomicU64,
        entries: UnsafeCell<[Entry; CAPACITY]>,
    }

    // SAFETY: every write goes to an index `reserved` handed out
    // exactly once, and readers look only below `committed`, which
    // counts an entry only after its fields are written (Release).
    unsafe impl Sync for Registry {}

    #[unsafe(no_mangle)]
    static HANSEI_CENSUS_EXPECT: Registry = Registry {
        committed: AtomicU64::new(0),
        reserved: AtomicU64::new(0),
        entries: UnsafeCell::new([EMPTY; CAPACITY]),
    };

    fn register(kind: u32, addr: u64, count: u64, name: &str) {
        let reg = &HANSEI_CENSUS_EXPECT;
        let index = reg.reserved.fetch_add(1, Ordering::Relaxed) as usize;
        assert!(index < CAPACITY, "census_expect registry overflow");
        let mut padded = [0u8; NAME_CAP];
        let len = name.len().min(NAME_CAP);
        padded[..len].copy_from_slice(&name.as_bytes()[..len]);
        // SAFETY: `index` was reserved above, so this entry is this
        // call's alone; see the `Sync` justification.
        unsafe {
            (*reg.entries.get())[index] = Entry {
                kind,
                flags: 0,
                addr,
                count,
                name: padded,
            };
        }
        reg.committed.fetch_add(1, Ordering::Release);
    }

    /// A future some frame holds off its task's active spine: the
    /// census must list a held find at exactly this slot — the value's
    /// own address, `&local as *const _ as u64` — whose future name
    /// contains `name`.
    pub fn held(slot: u64, name: &str) {
        register(HELD, slot, 0, name);
    }

    /// A future carried *inside* a registered held future — `holder`'s
    /// argument, which has no address the fixture can name — keyed by
    /// the carrying future's slot instead: the census must list a find
    /// reached via the held find at `parent_slot`, named `name`.
    pub fn held_in(parent_slot: u64, name: &str) {
        register(HELD_IN, parent_slot, 0, name);
    }

    /// A `FuturesUnordered` at `addr` holding exactly `children`
    /// resident futures.
    pub fn set(addr: u64, children: usize) {
        register(SET, addr, children as u64, "");
    }

    /// A `JoinSet` at `addr` holding exactly `members` tasks, reaped or
    /// parked.
    pub fn join_set(addr: u64, members: usize) {
        register(JOIN_SET, addr, members as u64, "");
    }

    /// A task whose future name contains `name` is in the enumerated
    /// listing. Registered by the task's own body, so a task that never
    /// ran registers nothing — the check is one-directional on purpose,
    /// and a task that completes before the capture (the joinset
    /// fixture's finisher) must not register at all.
    pub fn task(name: &str) {
        register(TASK, 0, 0, name);
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The core-dump target for the `proc` crate's Linux suite
//! (`proc/tests/linux.rs`): a process that reports exactly what it is
//! holding, then dumps core on purpose, with no tokio anywhere in it.
//!
//! It is the Linux counterpart of `park-target`, which parks forever for
//! a suite that reads a live process. Nothing reads a live process on
//! Linux yet, so this one aborts instead, and the suite works from the
//! core the kernel writes.
//!
//! It carries a known function symbol, two known object symbols, and a
//! `thread_local!` that every thread sets to a value derived from its
//! own thread id — whose names and values the suite repeats as
//! constants; keep the two in step. Each thread reports its id and slot
//! value on stdout before parking, so the suite knows what the core
//! should say without having to trust the code that reads it.
//!
//! Reading `/proc/thread-self` makes this a Linux program at runtime,
//! which is where the suite that drives it runs.

use std::cell::Cell;
use std::hint::black_box;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;

/// A function symbol the suite resolves by name and back by address.
/// Only the symbol matters; the body just has to survive the optimizer.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn core_marker_fn(x: u64) -> u64 {
    black_box(x).wrapping_mul(3)
}

/// An object symbol with a known value, read back out of the core.
#[unsafe(no_mangle)]
pub static CORE_MARKER_VALUE: u64 = 0x0123_4567_89ab_cdef;

/// Written once before the abort, so the suite can tell a page that was
/// dumped from one that was read back off the executable on disk.
#[unsafe(no_mangle)]
pub static CORE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The value every thread leaves in its own copy of [`CORE_SLOT`],
/// tagged so a stray zero cannot be mistaken for one.
pub const SLOT_TAG: u64 = 0x5107_0000_0000_0000;

thread_local! {
    /// Native ELF TLS: each thread has its own, and the suite checks
    /// that resolving the symbol per thread finds each one.
    static CORE_SLOT: Cell<u64> = const { Cell::new(0) };
}

/// One LWP each, under the names the suite looks for.
const WORKERS: [&str; 3] = ["core-worker-0", "core-worker-1", "core-worker-2"];

/// This thread's id, from procfs: an oracle the core parser had no hand
/// in. `/proc/thread-self` resolves to `<pid>/task/<tid>`.
fn tid() -> u32 {
    std::fs::read_link("/proc/thread-self")
        .expect("failed to read /proc/thread-self")
        .file_name()
        .expect("/proc/thread-self resolves to a task directory")
        .to_str()
        .expect("thread ids are ASCII")
        .parse()
        .expect("thread ids are numbers")
}

/// Claim this thread's slot and report where it is and what it holds.
///
/// The address is reported, and not just the value, for two reasons:
/// it is the oracle the suite checks the resolver against, and letting
/// it escape is what keeps the optimizer from dropping the symbol that
/// names the slot.
fn claim_slot() -> (u32, u64, u64) {
    let tid = tid();
    let value = SLOT_TAG | u64::from(tid);
    CORE_SLOT.with(|slot| {
        slot.set(value);
        let addr = black_box(slot) as *const Cell<u64> as u64;
        (tid, value, addr)
    })
}

fn main() {
    test_programs::allow_any_tracer();

    // Every thread reports in before parking, so once they have all
    // been heard from the thread set below is final.
    let (tx, rx) = mpsc::channel();
    for name in WORKERS {
        let tx = tx.clone();
        thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                tx.send(claim_slot()).expect("nobody is waiting");
                park_forever();
            })
            .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
    }
    drop(tx);

    let mut slots = vec![claim_slot()];
    for _ in 0..WORKERS.len() {
        slots.push(rx.recv().expect("a thread died before reporting in"));
    }
    slots.sort_unstable();

    // Nothing here reads the markers; make sure they reach the symtab
    // anyway. The counter is written so its page is dirty, and so
    // certain to be in the core rather than read back off the file.
    black_box(&CORE_MARKER_VALUE);
    CORE_COUNTER.store(CORE_MARKER_VALUE, Ordering::SeqCst);
    black_box(core_marker_fn as extern "C" fn(u64) -> u64);

    let mut out = std::io::stdout().lock();
    for (tid, value, addr) in &slots {
        writeln!(out, "core-target slot: {tid} {value:#x} {addr:#x}").expect("failed to write");
    }
    writeln!(out, "core-target ready: {}", std::process::id()).expect("failed to write");
    out.flush().expect("failed to flush stdout");
    drop(out);

    // SIGABRT with every worker parked: the core has all four threads.
    std::process::abort();
}

/// Block in the kernel until the process dies. `park` may return
/// spuriously, so this is a loop and not a single call.
fn park_forever() -> ! {
    loop {
        thread::park();
    }
}

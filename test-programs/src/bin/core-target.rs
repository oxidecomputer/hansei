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
//! A report says the thread is about to park, not that it has: the
//! send that delivers it is what wakes `main`, which can reach the
//! abort while the reporter is still returning from `send`. So `main`
//! also waits, through procfs, until the kernel says each worker is
//! asleep, and the core then holds every worker in `park_forever`
//! rather than one of them mid-report.
//!
//! The last worker parks inside a signal handler rather than on its
//! own frames, so one stack in the core has the trampoline the kernel
//! lays between a handler and the frame it interrupted — the seam the
//! unwinder's suite checks a walk crosses and marks. That worker
//! reports in from inside the handler, so the abort that ends the
//! process cannot come before the handler's frame exists. The suite
//! that runs the fixture under gdb has to let SIGUSR1 through.
//!
//! Reading `/proc/thread-self` makes this a Linux program at runtime,
//! which is where the suite that drives it runs.

use std::cell::Cell;
use std::hint::black_box;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};
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
/// The worker that parks inside a signal handler.
const SIGNALLED: &str = "core-worker-2";

/// The signalled worker's report channel, for its handler to report
/// through: a handler takes no arguments of ours.
#[cfg(target_os = "linux")]
static SIGNALLED_TX: Mutex<Option<mpsc::Sender<(u32, u64, u64)>>> = Mutex::new(None);

/// The handler: reports in, then parks for good, so the trampoline
/// that would return to the interrupted frame stays on the stack.
/// Nothing here is async-signal-safe, and nothing needs to be: the
/// thread raised the signal at itself from a quiet spot.
#[cfg(target_os = "linux")]
extern "C" fn report_and_park_in_handler(_: libc::c_int) {
    let tx = SIGNALLED_TX
        .lock()
        .expect("nothing panics holding it")
        .take()
        .expect("the handler runs once");
    tx.send(claim_slot()).expect("nobody is waiting");
    park_forever()
}

/// Deliver `SIGUSR1` to this thread and report and park in its
/// handler. `raise` runs the handler before it returns, and the
/// handler never does. Linux only, like the core the suite takes of
/// it: `libc` is a Linux dependency of this crate.
#[cfg(target_os = "linux")]
fn report_and_park_in_signal_handler(tx: mpsc::Sender<(u32, u64, u64)>) -> ! {
    *SIGNALLED_TX.lock().expect("nothing panics holding it") = Some(tx);
    // SAFETY: the handler is a plain function of the signature
    // `signal` wants, and it blocks forever.
    unsafe {
        libc::signal(
            libc::SIGUSR1,
            report_and_park_in_handler as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
        libc::raise(libc::SIGUSR1);
    }
    unreachable!("the SIGUSR1 handler parks forever")
}

/// Elsewhere the worker reports and parks like the others.
#[cfg(not(target_os = "linux"))]
fn report_and_park_in_signal_handler(tx: mpsc::Sender<(u32, u64, u64)>) -> ! {
    tx.send(claim_slot()).expect("nobody is waiting");
    park_forever()
}

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
                if name == SIGNALLED {
                    report_and_park_in_signal_handler(tx);
                }
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
    // Every worker has reported; now let each reach the park before
    // the abort finds it still on its way there. Nothing here runs
    // once parked, so every thread but this one going to sleep is the
    // whole set arriving.
    test_programs::quiesce();

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

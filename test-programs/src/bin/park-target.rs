//! The parked target for the `proc` crate's on-box suite
//! (`proc/tests/illumos.rs`): a process holding still in a state that
//! suite knows exactly, with no tokio anywhere in it.
//!
//! It carries a known function symbol and three known object symbols —
//! whose names and values the suite repeats as constants; keep the two
//! in step — and spawns a named thread per worker, one LWP each. Once every
//! thread has reported in it prints the LWP ids procfs has for it, an
//! oracle libproc had no hand in, and parks forever. The suite blocks on
//! that line, so nothing here is timing-dependent.
//!
//! With `--spin` one extra thread bumps `PARK_COUNTER` as fast as it
//! can: the only thing in the target that moves while it runs, and so
//! the suite's way of telling a stopped process from a running one.
//!
//! Reading `/proc/self/lwp` makes this an illumos program at runtime,
//! which is where the suite that drives it runs.

use std::hint::black_box;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;

/// A function symbol the suite resolves by name and back by address.
/// Only the symbol matters; the body just has to survive the optimizer.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn park_marker_fn(x: u64) -> u64 {
    black_box(x).wrapping_mul(3)
}

/// An object symbol with a known value, read back out of the target
/// through every read helper the crate offers.
#[unsafe(no_mangle)]
pub static PARK_MARKER_VALUE: u64 = 0x0123_4567_89ab_cdef;

/// Bumped forever by the `--spin` thread, and by nothing else.
#[unsafe(no_mangle)]
pub static PARK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fast-TSD slot index, exported the way std exports the
/// `pthread_key_t` behind a `thread_local!` on this platform. The suite
/// hands this symbol to `Target::tls_var_addr`, which is what it is for:
/// the key-read-then-index walk is under test, not libc's key allocator,
/// so a fixed slot serves better than a real key whose value nothing
/// here would know.
#[unsafe(no_mangle)]
pub static PARK_TSD_KEY: u64 = 1;

/// One LWP each, under the names the suite looks for.
const WORKERS: [&str; 3] = ["park-worker-0", "park-worker-1", "park-worker-2"];

fn main() {
    let spin = std::env::args().any(|arg| arg == "--spin");

    // Every thread reports in before parking, so once they have all been
    // heard from the LWP set below is final.
    let (tx, rx) = mpsc::channel();
    for name in WORKERS {
        let tx = tx.clone();
        thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                tx.send(()).expect("nobody is waiting for the workers");
                park_forever();
            })
            .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
    }
    if spin {
        let tx = tx.clone();
        thread::Builder::new()
            .name("park-spinner".to_string())
            .spawn(move || {
                tx.send(()).expect("nobody is waiting for the spinner");
                loop {
                    PARK_COUNTER.fetch_add(1, Ordering::Relaxed);
                    std::hint::spin_loop();
                }
            })
            .expect("failed to spawn the spinner");
    }
    drop(tx);
    for _ in 0..WORKERS.len() + usize::from(spin) {
        rx.recv().expect("a thread died before reporting in");
    }

    // Nothing here reads the markers; make sure they reach the symtab
    // anyway.
    black_box(&PARK_MARKER_VALUE);
    black_box(&PARK_COUNTER);
    black_box(&PARK_TSD_KEY);
    black_box(park_marker_fn as extern "C" fn(u64) -> u64);

    let mut tids: Vec<u32> = std::fs::read_dir("/proc/self/lwp")
        .expect("failed to read /proc/self/lwp")
        .map(|entry| {
            entry
                .expect("failed to read an lwp entry")
                .file_name()
                .into_string()
                .expect("lwp ids are ASCII")
                .parse()
                .expect("lwp ids are numbers")
        })
        .collect();
    tids.sort_unstable();
    let ids: Vec<String> = tids.iter().map(u32::to_string).collect();

    println!("park-target ready: {}", ids.join(","));
    std::io::stdout().flush().expect("failed to flush stdout");

    park_forever();
}

/// Block in the kernel until killed. `park` may return spuriously, so
/// this is a loop and not a single call.
fn park_forever() -> ! {
    loop {
        thread::park();
    }
}

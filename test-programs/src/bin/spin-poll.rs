// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One spawned task caught mid-poll: it commits a single await, then
//! spins forever in a synchronous section of its poll — the shape whose
//! trace stops at the last committed await while the truth of what the
//! task is doing sits on the polling thread's native stack. The
//! acceptance suite cores this steady state and asserts the trace
//! appends that native continuation.
//!
//! The steady state is deterministic with no timing involved: readiness
//! is signaled from *inside* the spin function, so from `READY` on, the
//! polling thread executes nothing but [`grind`]'s loop — every core
//! taken after it finds the pc there, in a frame the join must print.

use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::oneshot;

/// Never set: the loop below is forever. A load the optimizer cannot
/// fold away is what keeps the spin a real loop in a release build.
static STOP: AtomicBool = AtomicBool::new(false);

/// The synchronous section the task spins in. `#[inline(never)]` keeps
/// it a frame of its own in the no-debug-info release build the core is
/// taken from — the frame the joined trace names.
#[inline(never)]
fn grind(ready: oneshot::Sender<()>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    let mut spins: u32 = 0;
    while !STOP.load(Ordering::Relaxed) {
        spins = spins.wrapping_add(1);
        std::hint::spin_loop();
    }
    spins
}

/// The yield commits one await unconditionally (its first poll is
/// always `Pending`), so the resumed task spins with a committed chain
/// that claims it is awaiting the yield — the misleading stopping point
/// the native continuation exists to correct.
async fn spinner(ready: oneshot::Sender<()>) -> u32 {
    tokio::task::yield_now().await;
    grind(ready)
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(1);
    test_programs::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();

        let _task = tokio::spawn(spinner(ready_tx));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

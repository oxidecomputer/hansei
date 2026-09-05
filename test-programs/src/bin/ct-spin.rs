// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `spin-poll`'s shape on a current_thread runtime: one spawned task
//! caught mid-poll, spinning forever in a synchronous section — with
//! the runtime's one thread, the `block_on` thread, as the thread
//! polling it. The subject is that thread's state: its scheduler core
//! is checked into the context with its driver, exactly as it is while
//! the root future is polled, and only the thread-local task id tells
//! the two apart.
//!
//! The steady state is deterministic with no timing involved, and
//! readiness has to be signaled from inside the spin: on this flavor a
//! spawned task runs only when the root future yields, and once the
//! task spins nothing else on the thread runs again — least of all a
//! root future that would print `READY`.

use std::sync::atomic::{AtomicBool, Ordering};

/// Never set: the loop below is forever. A load the optimizer cannot
/// fold away is what keeps the spin a real loop in a release build.
static STOP: AtomicBool = AtomicBool::new(false);

/// The synchronous section the task spins in, and where readiness is
/// signaled from. `#[inline(never)]` keeps it a frame of its own in
/// the no-debug-info release build the core is taken from.
#[inline(never)]
fn grind() -> u32 {
    println!("READY");
    let mut spins: u32 = 0;
    while !STOP.load(Ordering::Relaxed) {
        spins = spins.wrapping_add(1);
        std::hint::spin_loop();
    }
    spins
}

/// Spawned by the spinner just before it starts to spin, and never
/// polled: on this flavor a spawned task runs only when the running
/// one yields, and the spinner never does again. Its root future sits
/// `Unresumed` for the rest of the process — a state that is at no
/// await, whatever coordinates the debug info records on it.
async fn dormant() -> u32 {
    tokio::task::yield_now().await;
    1
}

/// The yield commits one await unconditionally (its first poll is
/// always `Pending`), so the task has been scheduled and resumed by the
/// time it spins — a poll the scheduler's run loop entered, not the
/// root future.
async fn spinner() -> u32 {
    tokio::task::yield_now().await;
    let _never = tokio::spawn(dormant());
    grind()
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_current_thread();
    test_programs::run_builder(&mut builder, async {
        let _task = tokio::spawn(spinner());
        std::future::pending::<()>().await
    })
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A task parked at an await with two locals pointing at memory the
//! allocator has taken back — the one shape no fixture had, and the
//! reason the render gates and the census's corroboration read as
//! untested.
//!
//! Every other fixture is healthy, so the allocator corroboration in
//! `reify` never refuses anything when the suite runs: a sweep reports
//! the session's gate accessors as untested because nothing can tell a
//! working gate from a gate wired to nothing. This program is the
//! counter-example. It hands two blocks back and then parks holding
//! both addresses, so a core taken here has live locals pointing into
//! freed memory and `trace` must decline to expand them.
//!
//! The two blocks are refused by different readers, which is why there
//! are two. [`Payload`] is a plain pointer, and it is the *renderer*
//! that must not follow it. [`StaleFuture`] is a boxed future's wide
//! pointer, which is one of only two pointers the **census** follows
//! as it discovers futures — so it is the one that puts a freed block
//! where the census would otherwise list a future in flight.
//!
//! One thing makes the freed state observable rather than a coin flip,
//! and it is load-bearing: **the free is the last allocator call the
//! program makes.** libumem hands a freed block straight back out to
//! the next request of its size class, so anything freed before the
//! program settles is simply allocated again. Each freed block is sized
//! into a class of its own for the same reason — nothing else here asks
//! for two kilobytes, or for the four the boxed future occupies. The
//! `println!` below is what makes that worth stating: it allocates
//! stdout's line buffer the first time it runs, and a block in that
//! size class would be handed straight to it.
//!
//! Where the block then sits is the allocator's business rather than
//! this program's: a free goes to the per-CPU magazine first and
//! reaches a slab's freelist only when that magazine fills. Both are
//! free, and hansei reads both, so this needs no allocator options set
//! and runs the way anything else on the system runs.
//!
//! On a target whose allocator is not libumem — a Linux capture, on
//! glibc — none of that applies and the pointer simply reads as
//! ordinary memory. The program still parks in the same shape; the
//! assertions that depend on a verdict are the ones that check first
//! whether the target has an allocator to ask.

use tokio::sync::oneshot;

use std::future::Future;

/// Two kilobytes, in a size class nothing else in this program touches.
/// A smaller payload would share a cache with the incidental
/// allocations around it and be handed straight back out.
struct Payload {
    /// Never read by this program — the bytes are here to occupy the
    /// size class and to be what a reader of the core would decode if
    /// it followed the stale pointer.
    #[allow(dead_code)]
    data: [u64; 256],
}

/// The address of a block that has been handed back.
///
/// Carried across an await so a core catches it live in the frame.
/// Never dereferenced by this program — it exists to be *read* by a
/// debugger walking the core, which is the whole point.
struct Stale(*const Payload);

// Safety: the pointer is never followed here, only carried. It crosses
// to the spawned task and then sits in its frame until the process is
// cored.
unsafe impl Send for Stale {}

/// The same, for a future: the wide pointer to a boxed future whose
/// block has been handed back.
///
/// A raw pointer rather than the `Box` itself, so the allocation has
/// one owner and that owner frees it exactly once; what stays in the
/// frame is a copy of the pointer and nothing more. The census follows
/// a dyn future's wide pointer to the allocation behind it — that and
/// a set's node list are the only pointers its discovery follows — so
/// what it finds through this one is a future in freed memory, and it
/// must decline to list it.
struct StaleFuture(*const (dyn Future<Output = ()> + Send));

// Safety: as [`Stale`] — carried across the await, never followed.
unsafe impl Send for StaleFuture {}

/// Park forever holding both addresses, so they live in the suspended
/// frame rather than being optimized out. Readiness is signalled before
/// the await, so the caller knows the frame exists before it frees.
async fn holder(ready: oneshot::Sender<()>, stale: Stale, future: StaleFuture) {
    ready.send(()).expect("main waits for readiness");
    std::future::pending::<()>().await;
    // Unreachable, and there to keep both locals live across the await
    // above: a local the body never uses again is a local rustc is
    // free to drop from the suspend state.
    std::hint::black_box((stale.0, future.0));
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(1);
    test_programs::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();

        let boxed = Box::new(Payload { data: [0x41; 256] });
        let addr = Box::into_raw(boxed);

        // A future of its own size class, never polled: what the census
        // would list, standing where the census must refuse to. The
        // padding is live across the await inside it, so the coroutine
        // is four kilobytes wide and shares its cache with nothing.
        let held: Box<dyn Future<Output = ()> + Send> = Box::new(async {
            let pad = [0x42u64; 512];
            std::future::pending::<()>().await;
            std::hint::black_box(pad);
        });
        let future = Box::into_raw(held);

        let _task = tokio::spawn(holder(ready_tx, Stale(addr), StaleFuture(future)));
        ready_rx.await.expect("the task signals readiness");

        // The task is parked and holding both addresses. Hand the
        // blocks back now, after every other allocation this program
        // makes, so nothing asks for their size classes again and the
        // allocator goes on holding them wherever it put them.
        //
        // Safety: both came from `Box::into_raw` above and neither has
        // been freed. The copies the task holds are not second owners
        // — they are never dereferenced, which is what this fixture is
        // for.
        drop(unsafe { Box::from_raw(addr) });
        drop(unsafe { Box::from_raw(future) });

        println!("READY");
        std::future::pending::<()>().await
    })
}

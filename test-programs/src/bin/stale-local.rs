//! A task parked at an await with a local pointing at memory the
//! allocator has taken back — the one shape no fixture had, and the
//! reason the render gates read as untested.
//!
//! Every other fixture is healthy, so the allocator corroboration in
//! `reify` never refuses anything when the suite runs: a sweep reports
//! the session's gate accessors as untested because nothing can tell a
//! working gate from a gate wired to nothing. This program is the
//! counter-example. It hands a block back and then parks holding the
//! address, so a core taken here has a live local pointing into freed
//! memory and `trace` must decline to expand it.
//!
//! One thing makes the freed state observable rather than a coin flip,
//! and it is load-bearing: **the free is the last allocator call the
//! program makes.** libumem hands a freed block straight back out to
//! the next request of its size class, so anything freed before the
//! program settles is simply allocated again. [`Payload`] is sized into
//! a class of its own for the same reason — nothing else here asks for
//! two kilobytes.
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

/// Park forever holding `stale`, so it lives in the suspended frame
/// rather than being optimized out. Readiness is signalled before the
/// await, so the caller knows the frame exists before it frees.
async fn holder(ready: oneshot::Sender<()>, stale: Stale) {
    ready.send(()).expect("main waits for readiness");
    std::future::pending::<()>().await;
    // Unreachable, and there to keep `stale` live across the await
    // above: a local the body never uses again is a local rustc is
    // free to drop from the suspend state.
    std::hint::black_box(stale.0);
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(1);
    test_programs::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();

        let boxed = Box::new(Payload { data: [0x41; 256] });
        let addr = Box::into_raw(boxed);

        let _task = tokio::spawn(holder(ready_tx, Stale(addr)));
        ready_rx.await.expect("the task signals readiness");

        // The task is parked and holding the address. Hand the block
        // back now, after every other allocation this program makes,
        // so nothing asks for its size class again and the allocator
        // goes on holding it wherever it put it.
        //
        // Safety: `addr` came from `Box::into_raw` above and has not
        // been freed. The copy the task holds is not a second owner —
        // it is never dereferenced, which is what this fixture is for.
        drop(unsafe { Box::from_raw(addr) });

        println!("READY");
        std::future::pending::<()>().await
    })
}

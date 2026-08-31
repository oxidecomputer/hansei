//! `spawn_blocking` cells as rows: one claimed by the pool's only
//! thread and running, one parked in the queue behind it, and a task
//! awaiting each handle — join edges that point at listed rows.
//!
//! The pool is saturated deterministically: the running closure
//! signals from inside itself, so by the time the second cell is
//! spawned the one blocking thread is provably taken and the cell can
//! only queue. The closure then parks on a channel nothing sends on,
//! whose sender the main future keeps alive past `READY`.

use std::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

async fn running_waiter(ready: oneshot::Sender<()>, handle: JoinHandle<u32>) -> u32 {
    test_programs::census_expect::task("blocking_pool::running_waiter");
    ready.send(()).expect("main waits for readiness");
    handle.await.unwrap_or(0) + 1
}

async fn queued_waiter(ready: oneshot::Sender<()>, handle: JoinHandle<u32>) -> u32 {
    test_programs::census_expect::task("blocking_pool::queued_waiter");
    ready.send(()).expect("main waits for readiness");
    handle.await.unwrap_or(0) * 2
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2).max_blocking_threads(1);
    test_programs::run_builder(&mut builder, async {
        let (started_tx, started_rx) = oneshot::channel();
        let (never_tx, never_rx) = mpsc::channel::<()>();
        let running = tokio::task::spawn_blocking(move || {
            started_tx.send(()).expect("main awaits the start");
            never_rx.recv().ok();
            17
        });
        started_rx.await.expect("the running closure starts");
        // The pool's one thread is inside the closure above, so this
        // cell has nowhere to go but the queue.
        let queued = tokio::task::spawn_blocking(|| 29);
        // A queued cell nothing awaits: its handle is dropped on the
        // spot, so the pool's queue is the only thing that names it —
        // the row only the queue walk can produce.
        drop(tokio::task::spawn_blocking(|| [0u8; 3].len()));

        let (ready_a_tx, ready_a_rx) = oneshot::channel();
        let (ready_b_tx, ready_b_rx) = oneshot::channel();
        let _running = tokio::spawn(running_waiter(ready_a_tx, running));
        let _queued = tokio::spawn(queued_waiter(ready_b_tx, queued));
        ready_a_rx.await.expect("running waiter signals readiness");
        ready_b_rx.await.expect("queued waiter signals readiness");
        println!("READY");
        let _keep = never_tx;
        std::future::pending::<()>().await
    });
}

//! A current_thread runtime: the same parked shapes the multi_thread
//! fixtures use — a timer sleeper and a semaphore waiter — scheduled by
//! the flavor whose discovery chain crosses the `CurrentThread` variant.
//! The runtime itself is the subject; the tasks exist so enumeration,
//! tracing, and the leaf readers have something to decode.

use std::time::Duration;
use tokio::sync::{Semaphore, oneshot};

async fn sleeper(ready: oneshot::Sender<()>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    tokio::time::sleep(Duration::from_secs(1_000_000)).await;
    17
}

async fn acquirer(ready: oneshot::Sender<()>, semaphore: &'static Semaphore) -> u32 {
    ready.send(()).expect("main waits for readiness");
    let _permit = semaphore.acquire().await.expect("the semaphore stays open");
    23
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_current_thread();
    test_programs::run_builder(&mut builder, async {
        // No permits, so the acquirer parks on the semaphore for good.
        let semaphore: &'static Semaphore = Box::leak(Box::new(Semaphore::new(0)));
        let (ready_a_tx, ready_a_rx) = oneshot::channel();
        let (ready_b_tx, ready_b_rx) = oneshot::channel();
        let _sleeper = tokio::spawn(sleeper(ready_a_tx));
        let _acquirer = tokio::spawn(acquirer(ready_b_tx, semaphore));
        // On current_thread a spawned task runs only when this future
        // yields; once both readiness sends have arrived, both tasks
        // have been polled past their sends and parked at their leaves.
        ready_a_rx.await.expect("sleeper signals readiness");
        ready_b_rx.await.expect("acquirer signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

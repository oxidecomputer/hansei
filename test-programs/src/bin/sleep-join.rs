//! `Sleep` and `JoinHandle` leaves: one task parked on the
//! timer wheel, another awaiting the first task's `JoinHandle` — the
//! dependency edge the leaf-future knowledge base reports.

use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

async fn sleeper(ready: oneshot::Sender<()>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    tokio::time::sleep(Duration::from_secs(1_000_000)).await;
    17
}

async fn joiner(ready: oneshot::Sender<()>, handle: JoinHandle<u32>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    handle.await.unwrap_or(0)
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (ready_a_tx, ready_a_rx) = oneshot::channel();
        let (ready_b_tx, ready_b_rx) = oneshot::channel();
        let handle = tokio::spawn(sleeper(ready_a_tx));
        let _joiner = tokio::spawn(joiner(ready_b_tx, handle));
        ready_a_rx.await.expect("sleeper signals readiness");
        ready_b_rx.await.expect("joiner signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

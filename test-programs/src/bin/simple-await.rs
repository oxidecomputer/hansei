//! One spawned async fn with two await points and known locals (§11.2).
//!
//! The task reaches a deterministic steady state: it passes one
//! trivially-ready await point, signals readiness, then parks forever on
//! a oneshot whose sender is intentionally leaked. `READY` on stdout
//! means the state is stable — no timing involved.

use tokio::sync::oneshot;

async fn ready_value() -> u32 {
    41
}

async fn work(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    let count: u32 = 3;
    let first = ready_value().await;
    ready.send(()).expect("main waits for readiness");
    let second = park.await.unwrap_or(0);
    count + first + second
}

fn main() {
    let mut builder = oxide_tokio_rt::Builder::new_multi_thread();
    builder.worker_threads(2);
    oxide_tokio_rt::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (park_tx, park_rx) = oneshot::channel();
        // Leak the sender: dropping it would close the channel and wake
        // the task out of its steady state.
        std::mem::forget(park_tx);

        let _task = tokio::spawn(work(ready_tx, park_rx));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

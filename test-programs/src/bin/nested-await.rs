//! An async fn awaiting an async fn awaiting a leaf future (§11.2): a
//! three-deep await chain, parked deterministically on a oneshot whose
//! sender is intentionally leaked.

use tokio::sync::oneshot;

async fn leaf(park: oneshot::Receiver<u32>) -> u32 {
    park.await.unwrap_or(7)
}

async fn middle(park: oneshot::Receiver<u32>) -> u32 {
    let inner = leaf(park).await;
    inner + 1
}

async fn outer(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    let nested = middle(park).await;
    nested + 1
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (park_tx, park_rx) = oneshot::channel();
        std::mem::forget(park_tx);

        let _task = tokio::spawn(outer(ready_tx, park_rx));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

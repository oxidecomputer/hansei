//! A `Pin<Box<dyn Future>>` awaitee plus a `JoinSet` (§11.2): exercises
//! the dyn-future join table, since the boxed future's concrete type is
//! only reachable through its vtable's poll/drop_glue symbols.

use std::future::Future;
use std::pin::Pin;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

async fn boxed_leaf(park: oneshot::Receiver<u32>) -> u32 {
    park.await.unwrap_or(11)
}

async fn set_member(park: oneshot::Receiver<u32>) -> u32 {
    park.await.unwrap_or(13)
}

async fn driver(
    ready: oneshot::Sender<()>,
    park_boxed: oneshot::Receiver<u32>,
    park_set: oneshot::Receiver<u32>,
) -> u32 {
    let boxed: Pin<Box<dyn Future<Output = u32> + Send>> = Box::pin(boxed_leaf(park_boxed));

    let mut set = JoinSet::new();
    set.spawn(set_member(park_set));

    ready.send(()).expect("main waits for readiness");
    let a = boxed.await;
    let b = set.join_next().await.and_then(|r| r.ok()).unwrap_or(0);
    a + b
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = oxide_tokio_rt::Builder::new_multi_thread();
    builder.worker_threads(2);
    oxide_tokio_rt::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (park_boxed_tx, park_boxed_rx) = oneshot::channel();
        let (park_set_tx, park_set_rx) = oneshot::channel();
        std::mem::forget(park_boxed_tx);
        std::mem::forget(park_set_tx);

        let _task = tokio::spawn(driver(ready_tx, park_boxed_rx, park_set_rx));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

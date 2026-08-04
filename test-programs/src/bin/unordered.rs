//! Futures the task listings never show (the `hansei futures` census):
//! a `FuturesUnordered` whose children park in a shared `Notify`'s wait
//! queue — their registered wakers carry the set's node addresses
//! rather than any task Header — plus two futures the driver merely
//! *holds* across its await, one a bare coroutine and one behind a
//! `dyn Future` box, covering both of the census's other detections.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{Notify, oneshot};

/// How many children the driver's set holds. The acceptance suite
/// asserts this count, so the two must agree.
const CHILDREN: usize = 3;

async fn set_member(notify: Arc<Notify>) -> u32 {
    notify.notified().await;
    7
}

async fn driver(ready: oneshot::Sender<()>, notify: Arc<Notify>) -> u32 {
    let mut set: FuturesUnordered<_> = (0..CHILDREN).map(|_| set_member(notify.clone())).collect();

    // Held, never polled while the set is awaited: live across the
    // await below because both are consumed after it.
    let held = set_member(notify.clone());
    let boxed: Pin<Box<dyn Future<Output = u32> + Send>> = Box::pin(set_member(notify.clone()));

    ready.send(()).expect("main waits for readiness");
    let mut sum = 0;
    while let Some(value) = set.next().await {
        sum += value;
    }
    sum + held.await + boxed.await
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = oxide_tokio_rt::Builder::new_multi_thread();
    builder.worker_threads(2);
    oxide_tokio_rt::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        // Never notified: the children park in the Notify's wait queue
        // for good, each registering the set's waker for its node.
        let notify = Arc::new(Notify::new());

        let _task = tokio::spawn(driver(ready_tx, notify));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

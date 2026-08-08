//! Tasks a `JoinSet` holds (the `hansei tasks --futures` census): a
//! driver parked in `join_next` while the tasks it spawned onto the set
//! park in a shared `Notify`. Unlike a `FuturesUnordered`'s children,
//! these are tasks the runtime owns and every listing shows — what the
//! set adds is which of them this one task is waiting to join.

use std::sync::Arc;

use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinSet;

/// How many tasks the driver spawns onto its set. The acceptance suite
/// asserts this count, so the two must agree.
const MEMBERS: usize = 3;

async fn member(started: mpsc::Sender<()>, notify: Arc<Notify>) -> u32 {
    started.send(()).await.expect("the driver waits for us");
    notify.notified().await;
    7
}

async fn driver(ready: oneshot::Sender<()>, notify: Arc<Notify>) -> u32 {
    // Room for every member, so reporting in never parks a member on
    // the channel instead of on the Notify below.
    let (started_tx, mut started_rx) = mpsc::channel(MEMBERS);
    let mut set = JoinSet::new();
    for _ in 0..MEMBERS {
        set.spawn(member(started_tx.clone(), notify.clone()));
    }
    drop(started_tx);

    // Every member has run before the target is declared ready, so the
    // set holds tasks the listing can show rather than ones the
    // scheduler has not reached yet.
    for _ in 0..MEMBERS {
        started_rx.recv().await.expect("every member reports in");
    }
    ready.send(()).expect("main waits for readiness");

    let mut sum = 0;
    while let Some(value) = set.join_next().await {
        sum += value.expect("no member panics");
    }
    sum
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        // Never notified: the members park in the Notify's wait queue
        // for good, so the driver stays parked in `join_next`.
        let notify = Arc::new(Notify::new());

        let _task = tokio::spawn(driver(ready_tx, notify));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

//! Many parked tasks: enough spawned tasks to give the
//! `OwnedTasks` shards more than one task each, so a backend list walk
//! that mishandles the intrusive links cannot round-trip the task count.

use tokio::sync::oneshot;

const TASKS: usize = 32;

async fn park_task(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    park.await.unwrap_or(0)
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let mut ready = Vec::new();
        for _ in 0..TASKS {
            let (ready_tx, ready_rx) = oneshot::channel();
            let (park_tx, park_rx) = oneshot::channel();
            // Leak the sender: dropping it would close the channel and
            // wake the task out of its steady state.
            std::mem::forget(park_tx);
            tokio::spawn(park_task(ready_tx, park_rx));
            ready.push(ready_rx);
        }
        // READY only once every task has signalled from inside its poll.
        for rx in ready {
            rx.await.expect("task signals readiness");
        }
        println!("READY");
        std::future::pending::<()>().await
    })
}

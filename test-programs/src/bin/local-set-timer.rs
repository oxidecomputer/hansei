//! A `LocalSet` whose only trace outside its own list is a timer: both
//! its tasks are spawned with their `JoinHandle`s dropped on the spot,
//! and the one they park on — a semaphore nothing else touches — is
//! never in a queue any enumerated task's chain reaches. Nothing in the
//! scheduler's population points at either of them, and a parked core
//! reads the `CURRENT` anchor empty, so the cell bootstrap and the TLS
//! probe both come up empty. What does see them is the runtime's own
//! timer wheel, where the local sleeper's entry sits armed with its
//! task's waker — and one member found is the whole set.

use std::time::Duration;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::LocalSet;

async fn local_sleeper(ready: oneshot::Sender<()>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    tokio::time::sleep(Duration::from_secs(1_000_000)).await;
    41
}

async fn local_acquirer(ready: oneshot::Sender<()>, semaphore: &'static Semaphore) -> u32 {
    ready.send(()).expect("main waits for readiness");
    let _permit = semaphore.acquire().await.expect("the semaphore stays open");
    43
}

/// The ordinary spawned task. It parks on a timer like the local
/// sleeper, so its entry sits in the same wheel the harvest walks, and
/// it carries a value the local sleeper does not — without that, the two
/// state machines are the same shape and a linker free to fold identical
/// drop glue leaves only one of them named in the extraction summary,
/// which is not a fact a portable golden may rest on.
async fn sleeper(ready: oneshot::Sender<()>, tag: &'static str) -> usize {
    ready.send(()).expect("main waits for readiness");
    tokio::time::sleep(Duration::from_secs(1_000_000)).await;
    tag.len()
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_current_thread();
    test_programs::run_builder(&mut builder, async {
        // The local acquirer's own semaphore: no permits, so it parks
        // for good, and no other task waits on it — so no walked wait
        // queue names the task either.
        let semaphore: &'static Semaphore = Box::leak(Box::new(Semaphore::new(0)));
        let (ready_a_tx, ready_a_rx) = oneshot::channel();
        let (ready_b_tx, ready_b_rx) = oneshot::channel();
        let (ready_c_tx, ready_c_rx) = oneshot::channel();
        let local = LocalSet::new();
        // Dropping both handles detaches the tasks without cancelling
        // them: they stay in the set's list, and nothing outside it
        // holds a pointer to either.
        drop(local.spawn_local(local_sleeper(ready_a_tx)));
        drop(local.spawn_local(local_acquirer(ready_b_tx, semaphore)));
        // An ordinary spawned task, parked on a timer of its own: the
        // scheduler's population is not empty, and its entry sits in
        // the same wheel the harvest walks — already listed, so not a
        // candidate.
        let _sleeper = tokio::spawn(sleeper(ready_c_tx, "spawned"));
        local
            .run_until(async move {
                // On current_thread, spawned and local tasks alike run
                // only when this future yields; once every readiness
                // send has arrived, each task has been polled past its
                // send and parked at its leaf.
                ready_a_rx.await.expect("local sleeper signals readiness");
                ready_b_rx.await.expect("local acquirer signals readiness");
                ready_c_rx.await.expect("sleeper signals readiness");
                println!("READY");
                std::future::pending::<()>().await
            })
            .await
    })
}

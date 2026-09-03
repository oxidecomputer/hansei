// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A `LocalSet` on a current_thread runtime: two tasks spawned onto the
//! set's own `LocalOwnedTasks` list — one parked on the timer, one on a
//! semaphore — and one ordinary spawned task awaiting a local task's
//! JoinHandle. That handle is the edge route-1 discovery joins on: the
//! scheduler task's await chain reaches a Header no enumerated list
//! carries, whose cell's scheduler is the `Arc<local::Shared>` that owns
//! the whole set.

use std::time::Duration;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::LocalSet;

async fn local_sleeper(ready: oneshot::Sender<()>) -> u32 {
    test_programs::census_expect::task("local_set::local_sleeper");
    ready.send(()).expect("main waits for readiness");
    tokio::time::sleep(Duration::from_secs(1_000_000)).await;
    31
}

async fn local_acquirer(ready: oneshot::Sender<()>, semaphore: &'static Semaphore) -> u32 {
    test_programs::census_expect::task("local_set::local_acquirer");
    ready.send(()).expect("main waits for readiness");
    let _permit = semaphore.acquire().await.expect("the semaphore stays open");
    37
}

async fn joiner(ready: oneshot::Sender<()>, handle: tokio::task::JoinHandle<u32>) -> u32 {
    test_programs::census_expect::task("local_set::joiner");
    ready.send(()).expect("main waits for readiness");
    handle.await.expect("the sleeper never finishes")
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_current_thread();
    test_programs::run_builder(&mut builder, async {
        // No permits, so the acquirer parks on the semaphore for good.
        let semaphore: &'static Semaphore = Box::leak(Box::new(Semaphore::new(0)));
        let (ready_a_tx, ready_a_rx) = oneshot::channel();
        let (ready_b_tx, ready_b_rx) = oneshot::channel();
        let (ready_c_tx, ready_c_rx) = oneshot::channel();
        let local = LocalSet::new();
        // The sleeper's handle crosses to an ordinary spawned task: a
        // JoinHandle edge from the scheduler's population into the set's.
        let sleeper = local.spawn_local(local_sleeper(ready_a_tx));
        let _acquirer = local.spawn_local(local_acquirer(ready_b_tx, semaphore));
        let _joiner = tokio::spawn(joiner(ready_c_tx, sleeper));
        local
            .run_until(async move {
                // On current_thread, spawned and local tasks alike run
                // only when this future yields; once every readiness
                // send has arrived, each task has been polled past its
                // send and parked at its leaf.
                ready_a_rx.await.expect("sleeper signals readiness");
                ready_b_rx.await.expect("acquirer signals readiness");
                ready_c_rx.await.expect("joiner signals readiness");
                println!("READY");
                std::future::pending::<()>().await
            })
            .await
    })
}

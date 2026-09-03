// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A second current_thread runtime that no thread is inside. It is
//! built on a thread of its own, spawned onto, driven until everything
//! it owns has parked, and then left alone: its `block_on` returns, so
//! its handle is in no thread's runtime context and TLS-anchored
//! discovery cannot see it. One of its tasks is joined from the main
//! runtime, and that `JoinHandle` is the whole way in — from the task
//! it names, the cell says which runtime owns it, and the shard walk
//! takes the rest.
//!
//! The set is the second half of the proof. Its one task parks on a
//! timer registered in the *hidden* runtime's wheel and nothing points
//! at it, so it is reachable only once that runtime is admitted and its
//! own drivers are harvested in turn.

use std::future::pending;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::{JoinHandle, LocalSet};

/// The main runtime's own task: it holds the hidden runtime's
/// `JoinHandle` and parks on it, which is the edge discovery follows.
async fn joiner(handle: JoinHandle<u32>, ready: oneshot::Sender<()>) -> u32 {
    test_programs::census_expect::task("foreign_runtime::joiner");
    ready.send(()).expect("main waits for readiness");
    handle.await.expect("the joined task never completes")
}

/// The hidden runtime's joined task. It parks on a semaphore nobody
/// releases, so the join never completes.
async fn joined(ready: oneshot::Sender<()>, semaphore: &'static Semaphore) -> u32 {
    test_programs::census_expect::task("foreign_runtime::joined");
    ready
        .send(())
        .expect("the runtime thread waits for readiness");
    let _permit = semaphore.acquire().await.expect("the semaphore stays open");
    23
}

/// Its sibling, which nothing outside the runtime's own list points at:
/// the handle is dropped on the spot and no other task joins it. It
/// carries a value the joined task does not, so the two state machines
/// are different shapes — identical ones have identical drop glue, and
/// a linker free to fold them leaves only one named in the extraction
/// summary.
async fn detached(ready: oneshot::Sender<()>, tag: &'static str) -> usize {
    test_programs::census_expect::task("foreign_runtime::detached");
    ready
        .send(())
        .expect("the runtime thread waits for readiness");
    pending::<()>().await;
    tag.len()
}

/// The local task, spawned into a set the hidden runtime drives. Its
/// timer entry sits in that runtime's wheel — the only trace it leaves
/// anywhere.
async fn local_sleeper(ready: oneshot::Sender<()>) -> u64 {
    test_programs::census_expect::task("foreign_runtime::local_sleeper");
    ready
        .send(())
        .expect("the runtime thread waits for readiness");
    tokio::time::sleep(Duration::from_secs(1_000_000)).await;
    5
}

/// Build the hidden runtime, drive it until everything it owns has
/// parked, and hold it — with the set — alive on this thread's stack
/// while the process is cored.
fn hidden_runtime(handle_tx: oneshot::Sender<JoinHandle<u32>>, parked_tx: oneshot::Sender<()>) {
    let semaphore: &'static Semaphore = Box::leak(Box::new(Semaphore::new(0)));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the second runtime builds");

    let (ready_j_tx, ready_j_rx) = oneshot::channel();
    let (ready_d_tx, ready_d_rx) = oneshot::channel();
    let (ready_l_tx, ready_l_rx) = oneshot::channel();
    // Spawned before anything drives the runtime: they run when
    // `block_on` below does, and park where it leaves them.
    handle_tx
        .send(runtime.spawn(joined(ready_j_tx, semaphore)))
        .expect("main awaits the handle");
    drop(runtime.spawn(detached(ready_d_tx, "detached")));
    let local = LocalSet::new();
    drop(local.spawn_local(local_sleeper(ready_l_tx)));

    // Every task is polled past its readiness send — and so to its leaf
    // — before the root future this awaits with completes, since a poll
    // runs to the task's next await before control comes back here.
    //
    // `run_until` is awaited inside a block of this program's own
    // rather than handed to `block_on` directly: whether its wrappers
    // survive as their own monomorphizations is the target's call, and
    // as `block_on`'s root they would name a type in the portable
    // summary that only one platform emits.
    runtime.block_on(async {
        local
            .run_until(async move {
                ready_j_rx.await.expect("the joined task signals readiness");
                ready_d_rx
                    .await
                    .expect("the detached task signals readiness");
                ready_l_rx.await.expect("the local task signals readiness");
            })
            .await;
    });

    // `block_on` has returned, so this thread's runtime context is
    // restored and nothing points at the runtime any more — while the
    // runtime, the set, and everything they own are still alive here.
    parked_tx.send(()).expect("main awaits the park");
    let (_never_tx, never_rx) = mpsc::channel::<()>();
    never_rx.recv().expect_err("nothing ever sends");
}

fn main() {
    test_programs::allow_any_tracer();

    let (handle_tx, handle_rx) = oneshot::channel();
    let (parked_tx, parked_rx) = oneshot::channel();
    std::thread::spawn(move || hidden_runtime(handle_tx, parked_tx));

    let mut builder = test_programs::Builder::new_current_thread();
    test_programs::run_builder(&mut builder, async move {
        let handle = handle_rx.await.expect("the hidden runtime sends a handle");
        let (ready_tx, ready_rx) = oneshot::channel();
        let _joiner = tokio::spawn(joiner(handle, ready_tx));
        ready_rx.await.expect("the joiner signals readiness");
        parked_rx.await.expect("the hidden runtime parks");
        println!("READY");
        pending::<()>().await
    })
}

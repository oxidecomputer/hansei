// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A `Pin<Box<dyn Future>>` awaitee plus a `JoinSet`: exercises
//! the dyn-future join table, since the boxed future's concrete type is
//! only reachable through its vtable's poll/drop_glue symbols.

use std::future::Future;
use std::pin::Pin;
use test_programs::census_expect;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

async fn boxed_leaf(park: oneshot::Receiver<u32>) -> u32 {
    park.await.unwrap_or(11)
}

async fn set_member(park: oneshot::Receiver<u32>) -> u32 {
    census_expect::task("dyn_future::set_member");
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

    // Ground truth for the census diff. `boxed` is not registered: it
    // is this frame's active awaitee below, not a held future.
    census_expect::task("dyn_future::driver");
    census_expect::join_set(&set as *const _ as u64, 1);

    ready.send(()).expect("main waits for readiness");
    let a = boxed.await;
    let b = set.join_next().await.and_then(|r| r.ok()).unwrap_or(0);
    a + b
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (park_boxed_tx, park_boxed_rx) = oneshot::channel();
        let (park_set_tx, park_set_rx) = oneshot::channel();
        std::mem::forget(park_boxed_tx);
        std::mem::forget(park_set_tx);

        let _task = tokio::spawn(driver(ready_tx, park_boxed_rx, park_set_rx));
        let (aligned_ready_tx, aligned_ready_rx) = oneshot::channel();
        let (park_aligned_tx, park_aligned_rx) = oneshot::channel();
        std::mem::forget(park_aligned_tx);
        let _holder = tokio::spawn(hold_aligned(aligned_ready_tx, park_aligned_rx));

        ready_rx.await.expect("task signals readiness");
        aligned_ready_rx.await.expect("holder signals readiness");
        test_programs::quiesce();
        println!("READY");
        std::future::pending::<()>().await
    })
}

/// What `hold_aligned`'s `Arc<dyn Aligned>` erases: a value whose alignment
/// outruns the `ArcInner` header, so std places it at the first 64-byte
/// boundary past the refcounts rather than right after them.
trait Aligned: Send + Sync {
    fn value(&self) -> u32;
}

#[repr(align(64))]
struct Padded {
    value: u32,
}

impl Aligned for Padded {
    fn value(&self) -> u32 {
        self.value
    }
}

/// Holds an over-aligned trait object across an await, so `print aligned`
/// has to find the value past the header, not at its end. `padded` keeps
/// the concrete type in the bundle: a type reaches it through a frame's
/// locals, and the vtable can name `Padded` but not describe it.
async fn hold_aligned(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    let padded = std::sync::Arc::new(Padded { value: 7 });
    let aligned: std::sync::Arc<dyn Aligned> = padded.clone();
    census_expect::task("dyn_future::hold_aligned");
    ready.send(()).expect("main waits for readiness");
    park.await.unwrap_or(0) + aligned.value() + padded.value
}

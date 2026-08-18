//! Futures the task listings never show (the `hansei futures` census):
//! a `FuturesUnordered` whose children park in a shared `Notify`'s wait
//! queue — their registered wakers carry the set's node addresses
//! rather than any task Header — plus two futures the driver merely
//! *holds* across its await, one a bare coroutine and one behind a
//! `dyn Future` box, covering both of the census's other detections.
//!
//! It is also where the census's *recursive* scan is exercised: a
//! future reached only by descending into an aggregate (the `pair`
//! tuple) or into an enum's active variant (`maybe`, and each child's
//! `inner`), and a find two hops from the driver's own frames — one
//! child holds a set of its own, and every child holds a future — so
//! that what the census attributes to whom is pinned by something
//! other than a comment. Both ways out of a task's own frames are
//! covered: through a set's child, and through a future the driver
//! holds (`nested_hold`), which carries a future of its own.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{Notify, oneshot};

/// How many children the driver's set holds. The acceptance suite
/// asserts this count, so the two must agree.
const CHILDREN: usize = 3;

/// How many futures the nesting child's own set holds.
const NESTED: usize = 2;

/// The bottom of every chain here, and the one future type that holds
/// nothing itself: a child of a nested set, or a future held inside a
/// tuple, an enum, or another future.
async fn leaf(notify: Arc<Notify>) -> u32 {
    notify.notified().await;
    7
}

/// A future holding another future as an *argument* rather than as a
/// body local. An unpolled coroutine's frame carries its arguments and
/// nothing else, so this is the one shape whose chain still has a
/// future to find while it sits unpolled in the frame holding it — and
/// so the only way a future held by a *held* future arises here.
async fn holder<F: Future<Output = u32>>(inner: F, notify: Arc<Notify>) -> u32 {
    notify.notified().await;
    inner.await
}

/// A child of the driver's set, holding futures of its own across the
/// park: a set when `nest`, and a bare future either way. Both are
/// reached only by scanning this child's frames, which the census does
/// only because the child is a set member — one hop further out than
/// the driver's own locals.
async fn set_member(notify: Arc<Notify>, nest: bool) -> u32 {
    let inner: Option<FuturesUnordered<_>> =
        nest.then(|| (0..NESTED).map(|_| leaf(notify.clone())).collect());
    let held = leaf(notify.clone());

    notify.notified().await;

    let nested = match inner {
        Some(set) => set.count().await as u32,
        None => 0,
    };
    nested + held.await
}

async fn driver(ready: oneshot::Sender<()>, notify: Arc<Notify>) -> u32 {
    let mut set: FuturesUnordered<_> = (0..CHILDREN)
        .map(|i| set_member(notify.clone(), i == 0))
        .collect();

    // Held, never polled while the set is awaited: live across the
    // await below because both are consumed after it.
    let held = set_member(notify.clone(), false);
    let boxed: Pin<Box<dyn Future<Output = u32> + Send>> =
        Box::pin(set_member(notify.clone(), false));
    // The same, one level in: a future the scan reaches only by
    // descending into a tuple, and one it reaches only through an
    // enum's active variant.
    let pair = (leaf(notify.clone()), 11);
    let maybe = Some(leaf(notify.clone()));
    // One hop further out than the rest: unpolled like them, but its
    // frame carries the future passed to it, so what the census finds
    // here holds a future of its own.
    let nested_hold = holder(leaf(notify.clone()), notify.clone());

    ready.send(()).expect("main waits for readiness");
    let mut sum = 0;
    while let Some(value) = set.next().await {
        sum += value;
    }
    sum + held.await
        + boxed.await
        + pair.0.await
        + pair.1
        + maybe.unwrap().await
        + nested_hold.await
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! tokio sync primitives parked in a steady state: a holder task parks
//! forever owning a bounded `mpsc` with queued,
//! unreceived messages, a `watch`, a `Semaphore`, and a `Notify` — the types
//! the tokio-sync formatters (`MpscRx`/`MpscChan`/`MpscBlock`,
//! `BoundedSemaphore`, `WatchState`, `Semaphore`, `Notify`) detect. A second
//! task parks a waiter in the `Notify`'s queue. `READY` on stdout means every
//! primitive has reached its parked state; there are no timing sleeps —
//! readiness is signalled over oneshots.

use std::sync::Arc;
use test_programs::census_expect;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot, watch};

/// Enqueue a waiter in `notify`'s intrusive waiter list, then park on it.
/// `Notified::enable()` registers the waiter synchronously, so once we signal
/// readiness the waiter is deterministically parked in the queue — no sleep.
async fn notify_waiter(notify: Arc<Notify>, ready: oneshot::Sender<()>) {
    census_expect::task("channels::notify_waiter");
    let notified = notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    // Ground truth for the census diff: the pinned leaf is a held find
    // — what this frame awaits below is the `Pin` reference, not the
    // `Notified` itself.
    census_expect::held(
        notified.as_ref().get_ref() as *const _ as u64,
        "tokio::sync::notify::Notified",
    );
    ready.send(()).expect("main waits for readiness");
    notified.await;
}

/// Park forever holding every primitive so their private layouts stay part of
/// the fixture's async state on every target. Signals `ready` once parked.
#[allow(clippy::too_many_arguments)]
async fn hold(
    _tx: mpsc::Sender<u32>,
    _rx: mpsc::Receiver<u32>,
    _watch_tx: watch::Sender<u32>,
    _watch_rx: watch::Receiver<u32>,
    _sem: Arc<Semaphore>,
    _notify: Arc<Notify>,
    ready: oneshot::Sender<()>,
    park: oneshot::Receiver<u32>,
) -> u32 {
    census_expect::task("channels::hold");
    ready.send(()).expect("main waits for readiness");
    park.await.unwrap_or(0)
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        // Bounded mpsc with two queued, unreceived messages: the sends
        // complete immediately (capacity available) and the messages stay in
        // the channel because `rx` is parked, never polled for recv.
        let (tx, rx) = mpsc::channel::<u32>(8);
        tx.send(10).await.expect("capacity available");
        tx.send(20).await.expect("capacity available");

        // A watch channel with a value published after receiver creation, so
        // the receiver's one-slot inbox remains unseen while it is parked.
        let (watch_tx, watch_rx) = watch::channel(7u32);
        watch_tx.send(11).expect("watch receiver remains live");

        // A semaphore with available permits.
        let sem = Arc::new(Semaphore::new(4));

        // A Notify with one parked waiter.
        let notify = Arc::new(Notify::new());
        let (waiter_ready_tx, waiter_ready_rx) = oneshot::channel();
        let _waiter = tokio::spawn(notify_waiter(notify.clone(), waiter_ready_tx));
        waiter_ready_rx.await.expect("waiter signals readiness");

        // Park the holder forever: its `park` sender is leaked so it is never
        // woken out of the steady state.
        let (holder_ready_tx, holder_ready_rx) = oneshot::channel();
        let (park_tx, park_rx) = oneshot::channel();
        std::mem::forget(park_tx);
        let _holder = tokio::spawn(hold(
            tx,
            rx,
            watch_tx,
            watch_rx,
            sem,
            notify,
            holder_ready_tx,
            park_rx,
        ));
        holder_ready_rx.await.expect("holder signals readiness");

        println!("READY");
        std::future::pending::<()>().await
    })
}

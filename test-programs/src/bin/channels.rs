// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! tokio sync primitives parked in a steady state: a holder task parks
//! forever owning a bounded `mpsc` with queued, unreceived messages, two
//! more whose senders have dropped (one with a message still queued, one
//! drained first), a `watch`, a `Semaphore`, and a `Notify` — the types
//! the tokio-sync formatters (`MpscRx`/`MpscChan`/`MpscBlock`,
//! `BoundedSemaphore`, `WatchState`, `Semaphore`, `Notify`) detect. A second
//! task parks a waiter in the `Notify`'s queue, and a third parks in
//! `Receiver::recv` on an empty bounded channel whose sender the holder
//! keeps alive. A fourth parks in a `select!` whose one live branch is
//! a bounded `send` on a full channel, beside two branches the macro
//! disabled before their first poll. `READY` on stdout means every
//! primitive has reached its parked state; there are no timing sleeps —
//! readiness is signalled over oneshots.

use std::sync::Arc;
use std::time::Duration;
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
    // Not registered as a held find: what this frame awaits below is a
    // `Pin` reference to it, so the pinned leaf is the chain's own last
    // frame, reached through that reference, not a future held beside
    // the chain.
    ready.send(()).expect("main waits for readiness");
    notified.await;
}

/// Park in `recv` on an empty bounded channel: the first poll registers
/// this task's waker in the channel's receiver slot and parks until a
/// message arrives or the last sender drops — and the holder keeps the
/// sender alive. Readiness is signalled just ahead of the await, in the
/// same poll that registers.
async fn recv_waiter(mut rx: mpsc::Receiver<u32>, ready: oneshot::Sender<()>) -> Option<u32> {
    census_expect::task("channels::recv_waiter");
    ready.send(()).expect("main waits for readiness");
    rx.recv().await
}

/// Park forever holding every primitive so their private layouts stay part of
/// the fixture's async state on every target. Signals `ready` once parked.
#[allow(clippy::too_many_arguments)]
async fn hold(
    _tx: mpsc::Sender<u32>,
    _rx: mpsc::Receiver<u32>,
    _recv_tx: mpsc::Sender<u32>,
    _closed_rx: mpsc::Receiver<u32>,
    _drained_rx: mpsc::Receiver<u32>,
    _full_rx: mpsc::Receiver<u32>,
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

/// Park in a `select!` over three branches, only one of them live: a
/// `send` on a full bounded channel, whose `Acquire` queues this
/// task's waker on the channel's capacity semaphore with no permit
/// free — and nothing ever receives. The other two are disabled before
/// they are polled: a sleep under a false precondition, so its timer
/// is never registered, and a block that completes at once with an
/// output that misses the branch's pattern. Each branch future is a
/// pinned local the `select!` borrows, so the census lists exactly
/// the three the fixture registers — a `select!` over owned futures
/// would hold them in a tuple nothing can name. Readiness is
/// signalled just ahead of the `select!`, in the same poll that
/// registers.
async fn send_waiter(tx: mpsc::Sender<u32>, ready: oneshot::Sender<()>) {
    census_expect::task("channels::send_waiter");
    let send = tx.send(50);
    let sleep = tokio::time::sleep(Duration::from_secs(3600));
    let missed = async { Err::<(), ()>(()) };
    tokio::pin!(send, sleep, missed);
    census_expect::held(&*send as *const _ as u64, "send");
    census_expect::held(&*sleep as *const _ as u64, "Sleep");
    census_expect::held(&*missed as *const _ as u64, "send_waiter");
    ready.send(()).expect("main waits for readiness");
    tokio::select! {
        _ = &mut send => {}
        _ = &mut sleep, if false => {}
        Ok(()) = &mut missed => {}
    }
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

        // Two channels whose senders have all dropped. Closing claims a
        // slot past the last message and never writes it, so the tail
        // sits one ahead of what the receiver can read: one channel with
        // a message still queued ahead of that slot, one drained before
        // the close so nothing is.
        let (closed_tx, closed_rx) = mpsc::channel::<u32>(8);
        closed_tx.send(30).await.expect("capacity available");
        drop(closed_tx);
        let (drained_tx, mut drained_rx) = mpsc::channel::<u32>(8);
        drained_tx.send(40).await.expect("capacity available");
        drop(drained_tx);
        assert_eq!(drained_rx.recv().await, Some(40));

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

        // An empty bounded channel with a receiver parked in `recv` and
        // its one sender held by the holder, so the receive never ends.
        let (recv_tx, recv_rx) = mpsc::channel::<u32>(4);
        let (recv_ready_tx, recv_ready_rx) = oneshot::channel();
        let _recv_waiter = tokio::spawn(recv_waiter(recv_rx, recv_ready_tx));
        recv_ready_rx.await.expect("receiver signals readiness");

        // A bounded channel of one, filled: the holder keeps its receiver
        // unpolled, so the `send` below never gets its permit back.
        let (full_tx, full_rx) = mpsc::channel::<u32>(1);
        full_tx.send(1).await.expect("capacity available");

        // Park the holder forever: its `park` sender is leaked so it is never
        // woken out of the steady state.
        let (holder_ready_tx, holder_ready_rx) = oneshot::channel();
        let (park_tx, park_rx) = oneshot::channel();
        std::mem::forget(park_tx);
        let _holder = tokio::spawn(hold(
            tx,
            rx,
            recv_tx,
            closed_rx,
            drained_rx,
            full_rx,
            watch_tx,
            watch_rx,
            sem,
            notify,
            holder_ready_tx,
            park_rx,
        ));
        holder_ready_rx.await.expect("holder signals readiness");

        // A sender parked in a `select!` on the full channel, its waker
        // queued on the channel's semaphore beside two disabled branches.
        let (send_ready_tx, send_ready_rx) = oneshot::channel();
        let _send_waiter = tokio::spawn(send_waiter(full_tx, send_ready_tx));
        send_ready_rx.await.expect("sender signals readiness");

        test_programs::quiesce();
        println!("READY");
        std::future::pending::<()>().await
    })
}

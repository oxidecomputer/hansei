// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Wakers parked in several places at once, and wakers parked nowhere:
//! the population the waker sweep is judged over. A `select!` parks
//! one task's waker in four slots the registries do not all reach — a
//! oneshot's `rx_task`, a bounded mpsc's receiver slot, a watch's
//! `Notify` node and a `Sleep`'s wheel entry — while a holder keeps a
//! `Notified` it never polled beside a oneshot it awaits, a waiter
//! parks in a bare `Notify`, a `FuturesUnordered` drives two children
//! whose oneshots hold the *set's* wakers rather than the task's, and
//! two tasks park in an `Interval`'s `tick`. `READY` on stdout means
//! every task has parked, signalled over oneshots, never by sleeping.

use futures::stream::{FuturesUnordered, StreamExt};
use test_programs::census_expect;
use tokio::sync::futures::Notified;
use tokio::sync::{Notify, mpsc, oneshot, watch};

use std::time::Duration;

/// Four branches, each parking this task's waker somewhere else: the
/// oneshot's receiver slot, the channel's receiver slot, the watch's
/// notify node and the sleep's wheel entry. Nothing ever fires — the
/// senders live in `main` unsent, and the sleep is an hour. Each
/// branch future is a named local the select borrows, so the census
/// lists exactly the four the fixture registers: a `select!` over
/// owned futures would hold them in a tuple nothing can name.
async fn selector(
    ready: oneshot::Sender<()>,
    mut once: oneshot::Receiver<u32>,
    mut queue: mpsc::Receiver<u32>,
    mut published: watch::Receiver<u32>,
) -> u32 {
    census_expect::task("armed_select::selector");
    let recv = queue.recv();
    let changed = published.changed();
    let sleep = tokio::time::sleep(Duration::from_secs(3600));
    tokio::pin!(recv, changed, sleep);
    census_expect::held(&once as *const _ as u64, "oneshot::Receiver");
    census_expect::held(&*recv as *const _ as u64, "recv");
    census_expect::held(&*changed as *const _ as u64, "changed");
    // `changed` awaits `changed_impl` through tokio's `Coop` wrapper; the
    // chain crosses both, so the inner future is no find of its own.
    census_expect::held(&*sleep as *const _ as u64, "Sleep");
    ready.send(()).expect("main waits for readiness");
    tokio::select! {
        got = &mut once => got.unwrap_or(1),
        got = &mut recv => got.unwrap_or(2),
        changed = &mut changed => changed.map(|()| 3).unwrap_or(7),
        _ = &mut sleep => 8,
    }
}

/// Holds a `Notified` it never polls — a slot-less find, held rather
/// than awaited — while parked on a oneshot nobody sends on.
async fn holder(
    ready: oneshot::Sender<()>,
    notified: Notified<'static>,
    park: oneshot::Receiver<u32>,
) -> u32 {
    census_expect::task("armed_select::holder");
    census_expect::held(&notified as *const _ as u64, "Notified");
    ready.send(()).expect("main waits for readiness");
    let got = park.await.unwrap_or(4);
    drop(notified);
    got
}

/// Parked in the same `Notify` the holder's unpolled `Notified` came
/// from: its waker sits in the node inside its own frame.
async fn waiter(ready: oneshot::Sender<()>, notify: &'static Notify) -> u32 {
    census_expect::task("armed_select::waiter");
    ready.send(()).expect("main waits for readiness");
    notify.notified().await;
    5
}

/// A set child parked on a oneshot: the slot holds the set's waker for
/// this child's node, not the driving task's.
async fn child(park: oneshot::Receiver<u32>) -> u32 {
    park.await.unwrap_or(6)
}

/// Drives two children through `next()`; its own waker sits in the
/// set's ready queue, none of the children's slots.
async fn driver(
    ready: oneshot::Sender<()>,
    first: oneshot::Receiver<u32>,
    second: oneshot::Receiver<u32>,
) -> u32 {
    census_expect::task("armed_select::driver");
    let mut set = FuturesUnordered::new();
    set.push(child(first));
    set.push(child(second));
    census_expect::set(&set as *const _ as u64, 2);
    ready.send(()).expect("main waits for readiness");
    let mut sum = 0;
    while let Some(got) = set.next().await {
        sum += got;
    }
    sum
}

/// Where an `Interval` keeps its boxed `Sleep`: the offset of its
/// `delay` member, which no public surface exposes, so the markers
/// below name the box's slot by hand. rustc lays the `Duration` first
/// and the box after it.
const INTERVAL_DELAY: u64 = 16;

/// A `select!` over an interval's `tick` and a oneshot nobody sends
/// on: the `Sleep` boxed inside the interval is registered in the
/// wheel by the tick's first poll and never fires. The interval
/// starts a period out — a plain `interval()` completes its first
/// tick at once — so the one tick in flight is the one parked.
async fn ticker(ready: oneshot::Sender<()>, mut once: oneshot::Receiver<u32>) -> u32 {
    census_expect::task("armed_select::ticker");
    let period = Duration::from_secs(3600);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    census_expect::held(&interval as *const _ as u64 + INTERVAL_DELAY, "Sleep");
    let tick = interval.tick();
    tokio::pin!(tick);
    census_expect::held(&once as *const _ as u64, "oneshot::Receiver");
    census_expect::held(&*tick as *const _ as u64, "tick");
    ready.send(()).expect("main waits for readiness");
    tokio::select! {
        got = &mut once => got.unwrap_or(9),
        _ = &mut tick => 10,
    }
}

/// Parked in a bare `tick().await` on one interval while holding,
/// pinned and never polled, the `tick` of a second one made by a plain
/// `interval()`: that `Sleep`'s deadline is already past, but it is
/// registered in no wheel until polled, so nothing arms the held tick.
async fn pacer(ready: oneshot::Sender<()>) -> u32 {
    census_expect::task("armed_select::pacer");
    let period = Duration::from_secs(3600);
    let mut spare = tokio::time::interval(period);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    census_expect::held(&spare as *const _ as u64 + INTERVAL_DELAY, "Sleep");
    census_expect::held(&interval as *const _ as u64 + INTERVAL_DELAY, "Sleep");
    let spare_tick = spare.tick();
    tokio::pin!(spare_tick);
    census_expect::held(&*spare_tick as *const _ as u64, "tick");
    ready.send(()).expect("main waits for readiness");
    interval.tick().await;
    11
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (once_tx, once_rx) = oneshot::channel::<u32>();
        let (queue_tx, queue_rx) = mpsc::channel::<u32>(4);
        let (published_tx, published_rx) = watch::channel(0u32);
        let (selector_ready_tx, selector_ready_rx) = oneshot::channel();
        let _selector = tokio::spawn(selector(selector_ready_tx, once_rx, queue_rx, published_rx));
        selector_ready_rx.await.expect("selector signals readiness");

        let notify: &'static Notify = Box::leak(Box::new(Notify::new()));
        let (holder_park_tx, holder_park_rx) = oneshot::channel::<u32>();
        let (holder_ready_tx, holder_ready_rx) = oneshot::channel();
        let _holder = tokio::spawn(holder(holder_ready_tx, notify.notified(), holder_park_rx));
        holder_ready_rx.await.expect("holder signals readiness");

        let (waiter_ready_tx, waiter_ready_rx) = oneshot::channel();
        let _waiter = tokio::spawn(waiter(waiter_ready_tx, notify));
        waiter_ready_rx.await.expect("waiter signals readiness");

        let (first_tx, first_rx) = oneshot::channel::<u32>();
        let (second_tx, second_rx) = oneshot::channel::<u32>();
        let (driver_ready_tx, driver_ready_rx) = oneshot::channel();
        let _driver = tokio::spawn(driver(driver_ready_tx, first_rx, second_rx));
        driver_ready_rx.await.expect("driver signals readiness");

        let (ticker_once_tx, ticker_once_rx) = oneshot::channel::<u32>();
        let (ticker_ready_tx, ticker_ready_rx) = oneshot::channel();
        let _ticker = tokio::spawn(ticker(ticker_ready_tx, ticker_once_rx));
        ticker_ready_rx.await.expect("ticker signals readiness");

        let (pacer_ready_tx, pacer_ready_rx) = oneshot::channel();
        let _pacer = tokio::spawn(pacer(pacer_ready_tx));
        pacer_ready_rx.await.expect("pacer signals readiness");

        // The senders that must never send: leaked, so no drop closes
        // a channel and wakes anyone. The mpsc and watch senders stay
        // alive here for the same reason, and `main` never returns.
        for tx in [once_tx, holder_park_tx, first_tx, second_tx, ticker_once_tx] {
            std::mem::forget(tx);
        }
        let _keep = (queue_tx, published_tx);

        println!("READY");
        std::future::pending::<()>().await
    })
}

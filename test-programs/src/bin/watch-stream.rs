// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Boxed `changed()` futures behind stream wrappers: the population
//! the stream routes are judged over. A tokio-stream `WatchStream`
//! keeps the `changed()` it is waiting on in a `Pin<Box<dyn Future>>`
//! (tokio-util's `ReusableBoxFuture`), and a `StreamMap` of them polls
//! every entry with the polling task's own context. One task parks a
//! `select!` on one such stream's `next()` beside a oneshot, one on a
//! three-entry map's, one holds a fresh stream's `next()` it never
//! polls, and one awaits a bare `changed()` with no box in the way.
//! Every watch sender lives in `main` unsent. `READY` on stdout means
//! every task has parked; readiness is signalled over oneshots, never
//! by sleeping.

use futures::StreamExt;
use test_programs::census_expect;
use tokio::sync::{oneshot, watch};
use tokio_stream::StreamMap;
use tokio_stream::wrappers::WatchStream;

/// One boxed `changed()` behind a `WatchStream`: the stream's `next()`
/// is a named local the `select!` borrows beside a oneshot nobody
/// sends on. The box holds `make_future`, polled once and parked in
/// the watch's `Notify`, so its waiter carries this task's waker. The
/// stream is registered at its own slot: it owns the box, and the
/// census lists what an owned route reaches under the local it starts
/// from.
async fn resolver(
    ready: oneshot::Sender<()>,
    mut once: oneshot::Receiver<u32>,
    published: watch::Receiver<u32>,
) -> u32 {
    census_expect::task("watch_stream::resolver");
    let mut stream = WatchStream::from_changes(published);
    census_expect::held(&stream as *const _ as u64, "make_future");
    let next = stream.next();
    tokio::pin!(next);
    census_expect::held(&once as *const _ as u64, "oneshot::Receiver");
    census_expect::held(&*next as *const _ as u64, "Next");
    ready.send(()).expect("main waits for readiness");
    tokio::select! {
        got = &mut once => got.unwrap_or(1),
        got = &mut next => got.unwrap_or(2),
    }
}

/// Three boxed `changed()`s behind a `StreamMap` of `WatchStream`s.
/// The map polls each entry with this task's own context and keeps
/// every pending one registered, so all three boxes' waiters carry
/// this task's waker — there is no per-child waker as in a
/// `FuturesUnordered`. Each entry's stream is registered at its own
/// slot in the map's buffer, the way the resolver's is at its local:
/// the census lists a map's entries as finds of the task that polls
/// it.
async fn mapper(
    ready: oneshot::Sender<()>,
    mut once: oneshot::Receiver<u32>,
    receivers: [watch::Receiver<u32>; 3],
) -> u32 {
    census_expect::task("watch_stream::mapper");
    let mut map = StreamMap::new();
    for (key, rx) in ["alpha", "beta", "gamma"].into_iter().zip(receivers) {
        map.insert(key, WatchStream::from_changes(rx));
    }
    for (_, stream) in map.iter() {
        census_expect::held(stream as *const _ as u64, "make_future");
    }
    let next = map.next();
    tokio::pin!(next);
    census_expect::held(&once as *const _ as u64, "oneshot::Receiver");
    census_expect::held(&*next as *const _ as u64, "Next");
    ready.send(()).expect("main waits for readiness");
    tokio::select! {
        got = &mut once => got.unwrap_or(3),
        got = &mut next => got.map(|(_, value)| value).unwrap_or(4),
    }
}

/// A `WatchStream::new` whose `next()` is held and never polled: its
/// box holds the block that yields the current value, still
/// `Unresumed`, so the find is listed and nothing arms it — a box is
/// not a wait because it exists. Parked on a oneshot nobody sends on.
async fn fresh(
    ready: oneshot::Sender<()>,
    once: oneshot::Receiver<u32>,
    current: watch::Receiver<u32>,
) -> u32 {
    census_expect::task("watch_stream::fresh");
    let mut stream = WatchStream::new(current);
    census_expect::held(&stream as *const _ as u64, "new::{async_block");
    let next = stream.next();
    census_expect::held(&next as *const _ as u64, "Next");
    ready.send(()).expect("main waits for readiness");
    let got = once.await.unwrap_or(5);
    drop(next);
    got
}

/// A bare `changed()`: the chain from the stop to the watch's
/// `Notified` crosses tokio's `Coop` wrapper and no box, so the route
/// every boxed chain ends in is proven where nothing else is in the
/// way.
async fn direct(ready: oneshot::Sender<()>, mut published: watch::Receiver<u32>) -> u32 {
    census_expect::task("watch_stream::direct");
    ready.send(()).expect("main waits for readiness");
    published.changed().await.map(|()| 6).unwrap_or(7)
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (resolver_once_tx, resolver_once_rx) = oneshot::channel::<u32>();
        let (resolver_watch_tx, resolver_watch_rx) = watch::channel(0u32);
        let (resolver_ready_tx, resolver_ready_rx) = oneshot::channel();
        let _resolver = tokio::spawn(resolver(
            resolver_ready_tx,
            resolver_once_rx,
            resolver_watch_rx,
        ));
        resolver_ready_rx.await.expect("resolver signals readiness");

        let (mapper_once_tx, mapper_once_rx) = oneshot::channel::<u32>();
        let (alpha_tx, alpha_rx) = watch::channel(0u32);
        let (beta_tx, beta_rx) = watch::channel(0u32);
        let (gamma_tx, gamma_rx) = watch::channel(0u32);
        let (mapper_ready_tx, mapper_ready_rx) = oneshot::channel();
        let _mapper = tokio::spawn(mapper(
            mapper_ready_tx,
            mapper_once_rx,
            [alpha_rx, beta_rx, gamma_rx],
        ));
        mapper_ready_rx.await.expect("mapper signals readiness");

        let (fresh_once_tx, fresh_once_rx) = oneshot::channel::<u32>();
        let (fresh_watch_tx, fresh_watch_rx) = watch::channel(0u32);
        let (fresh_ready_tx, fresh_ready_rx) = oneshot::channel();
        let _fresh = tokio::spawn(fresh(fresh_ready_tx, fresh_once_rx, fresh_watch_rx));
        fresh_ready_rx.await.expect("fresh signals readiness");

        let (direct_watch_tx, direct_watch_rx) = watch::channel(0u32);
        let (direct_ready_tx, direct_ready_rx) = oneshot::channel();
        let _direct = tokio::spawn(direct(direct_ready_tx, direct_watch_rx));
        direct_ready_rx.await.expect("direct signals readiness");

        // The senders that must never send: leaked, so no drop closes
        // a channel and wakes anyone. The watch senders stay alive here
        // for the same reason, and `main` never returns.
        for tx in [resolver_once_tx, mapper_once_tx, fresh_once_tx] {
            std::mem::forget(tx);
        }
        let _keep = (
            resolver_watch_tx,
            alpha_tx,
            beta_tx,
            gamma_tx,
            fresh_watch_tx,
            direct_watch_tx,
        );

        println!("READY");
        std::future::pending::<()>().await
    })
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One crate linked at two releases: async-channel 1.9 and 2.5, side by
//! side through a renamed dependency, so every type the releases lay
//! out differently — the `Receiver` (24 bytes against 16), the
//! `Channel` behind its `Arc`, the `Recv` future — is in the DWARF
//! twice under one name, and the pointer-sized wrappers over them
//! (`Box`, `Option<Box>`, `Sender`, `Pin<Box<Recv>>`) are byte-identical
//! across the two and differ only in what they reference. `keeper`
//! holds a box, an option of a box and a sender of each release across
//! a oneshot park; `old_waiter` and `new_waiter` each await one
//! release's `recv()` through a `Pin<Box<…>>` on a channel whose
//! sender lives in `main` unsent. `READY` on stdout means every task
//! has parked; readiness is signalled over oneshots, never by sleeping.

use std::pin::Pin;

use async_channel_old as old;
use test_programs::census_expect;
use tokio::sync::oneshot;

/// Both releases' channel ends, held across an await that never
/// completes: a `Box<Receiver>` of each, an `Option<Box<Receiver>>` of
/// each, and a `Sender` of each. Every one of the six is a pointer
/// wide, and each pair shares its name with the other release's.
async fn keeper(
    ready: oneshot::Sender<()>,
    park: oneshot::Receiver<u32>,
    old_tx: old::Sender<u32>,
    old_rx: old::Receiver<u32>,
    new_tx: async_channel::Sender<u32>,
    new_rx: async_channel::Receiver<u32>,
) -> u32 {
    census_expect::task("two_releases::keeper");
    let old_box = Box::new(old_rx);
    let new_box = Box::new(new_rx);
    let old_some = Some(old_box.clone());
    let new_some = Some(new_box.clone());
    ready.send(()).expect("main waits for readiness");
    let parked = park.await.unwrap_or(0);
    let queued = old_box.len()
        + new_box.len()
        + old_some.map_or(0, |rx| rx.len())
        + new_some.map_or(0, |rx| rx.len())
        + old_tx.len()
        + new_tx.len();
    parked + queued as u32
}

/// The old release's `recv()`, awaited through a `Pin<Box<…>>`: the
/// pin and the box are the same eight bytes as the new release's, and
/// only the `Recv` behind them differs.
async fn old_waiter(ready: oneshot::Sender<()>, rx: old::Receiver<u32>) -> u32 {
    census_expect::task("two_releases::old_waiter");
    let recv: Pin<Box<old::Recv<'_, u32>>> = Box::pin(rx.recv());
    // What the census finds under the pin: the old release's `Recv`
    // keeps its event listener as a member of its own, at a slot this
    // frame cannot name.
    census_expect::held_by_task("two_releases::old_waiter", "event_listener::EventListener");
    ready.send(()).expect("main waits for readiness");
    recv.await.unwrap_or(1)
}

/// The new release's `recv()`, awaited the same way.
async fn new_waiter(ready: oneshot::Sender<()>, rx: async_channel::Receiver<u32>) -> u32 {
    census_expect::task("two_releases::new_waiter");
    let recv: Pin<Box<async_channel::Recv<'_, u32>>> = Box::pin(rx.recv());
    // The new release's `Recv` is event-listener-strategy's wrapper
    // over the channel's own state, which keeps the listener: two
    // finds under the pin, one inside the other.
    census_expect::held_by_task(
        "two_releases::new_waiter",
        "FutureWrapper<async_channel::RecvInner",
    );
    census_expect::held_by_task(
        "two_releases::new_waiter",
        "event_listener::EventListener<()>",
    );
    ready.send(()).expect("main waits for readiness");
    recv.await.unwrap_or(2)
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (park_tx, park_rx) = oneshot::channel::<u32>();
        let (old_tx, old_rx) = old::bounded::<u32>(4);
        let (new_tx, new_rx) = async_channel::bounded::<u32>(4);
        let (keeper_ready_tx, keeper_ready_rx) = oneshot::channel();
        let _keeper = tokio::spawn(keeper(
            keeper_ready_tx,
            park_rx,
            old_tx,
            old_rx,
            new_tx,
            new_rx,
        ));
        keeper_ready_rx.await.expect("keeper signals readiness");

        let (old_wait_tx, old_wait_rx) = old::bounded::<u32>(1);
        let (old_ready_tx, old_ready_rx) = oneshot::channel();
        let _old_waiter = tokio::spawn(old_waiter(old_ready_tx, old_wait_rx));
        old_ready_rx.await.expect("old_waiter signals readiness");

        let (new_wait_tx, new_wait_rx) = async_channel::bounded::<u32>(1);
        let (new_ready_tx, new_ready_rx) = oneshot::channel();
        let _new_waiter = tokio::spawn(new_waiter(new_ready_tx, new_wait_rx));
        new_ready_rx.await.expect("new_waiter signals readiness");

        // The senders that must never send: leaked, so no drop closes
        // a channel and wakes anyone out of its park, and `main` never
        // returns.
        std::mem::forget(park_tx);
        let _keep = (old_wait_tx, new_wait_tx);

        test_programs::quiesce();
        println!("READY");
        std::future::pending::<()>().await
    })
}

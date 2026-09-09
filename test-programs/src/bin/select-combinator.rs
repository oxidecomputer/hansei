// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `select!` and `join!` shapes, and the reviewed futures-util
//! adapters: five spawned tasks suspended inside combinator-generated
//! futures, parked deterministically on oneshots whose senders are
//! intentionally leaked.
//!
//! The last three park behind adapters a chain has to cross to name
//! what they wait on: `FutureExt::map`, `TryFutureExt::map_err` (whose
//! own layout is a `Map` over an `IntoFuture`), and a trait object
//! whose principal trait is not `Future` but requires one.

use futures::{FutureExt, TryFutureExt};
use tokio::sync::oneshot;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

async fn wait(park: oneshot::Receiver<u32>) -> u32 {
    park.await.unwrap_or(17)
}

async fn selector(
    ready: oneshot::Sender<()>,
    park_a: oneshot::Receiver<u32>,
    park_b: oneshot::Receiver<u32>,
) -> u32 {
    ready.send(()).expect("main waits for readiness");
    tokio::select! {
        a = wait(park_a) => a,
        b = wait(park_b) => b,
    }
}

async fn joiner(
    ready: oneshot::Sender<()>,
    park_a: oneshot::Receiver<u32>,
    park_b: oneshot::Receiver<u32>,
) -> u32 {
    ready.send(()).expect("main waits for readiness");
    let (a, b) = tokio::join!(wait(park_a), wait(park_b));
    a + b
}

/// A trait that is not `Future` and cannot be implemented without one.
/// A `Pin<Box<dyn Parked>>` polls whatever it holds through the
/// vtable's `Future` slot, which is what makes the box a future — but
/// which slot that is belongs to this trait's declaration, so the
/// concrete pointee is named by its drop glue instead.
trait Parked: Future<Output = u32> + Send {}

impl<F: Future<Output = u32> + Send> Parked for F {}

/// A future that can be written down. The adapters below are generic,
/// and their `poll` is one forward that a build is free to inline away
/// — which leaves no declaration saying whose implementation it was,
/// and an origin-gated rule then declines. Naming each `poll` keeps the
/// declaration, and that needs a nameable instantiation: an `async fn`'s
/// environment is not one.
struct Park(oneshot::Receiver<u32>);

impl Future for Park {
    type Output = u32;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u32> {
        Pin::new(&mut self.0).poll(cx).map(|got| got.unwrap_or(19))
    }
}

/// The same, returning a `Result` so `map_err` has a `TryFuture`.
struct Fallible(oneshot::Receiver<u32>);

impl Future for Fallible {
    type Output = Result<u32, u32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<u32, u32>> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|got| Ok(got.unwrap_or(23)))
    }
}

type Mapped = futures::future::Map<Park, fn(u32) -> u32>;
type Remapped = futures::future::MapErr<Fallible, fn(u32) -> u32>;

fn increment(value: u32) -> u32 {
    value + 1
}

async fn mapper(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    let mapped: Mapped = Park(park).map(increment as fn(u32) -> u32);
    mapped.await
}

async fn remapper(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    let remapped: Remapped = Fallible(park).map_err(increment as fn(u32) -> u32);
    remapped.await.unwrap_or(29)
}

async fn dynamic(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    ready.send(()).expect("main waits for readiness");
    let parked: Pin<Box<dyn Parked>> = Box::pin(wait(park));
    parked.await
}

fn main() {
    test_programs::allow_any_tracer();

    // Name each adapter's `poll` without calling it, so its declaration
    // survives however aggressively the real call was inlined.
    std::hint::black_box(
        <Mapped as Future>::poll as fn(Pin<&mut Mapped>, &mut Context<'_>) -> Poll<u32>,
    );
    std::hint::black_box(
        <Remapped as Future>::poll
            as fn(Pin<&mut Remapped>, &mut Context<'_>) -> Poll<Result<u32, u32>>,
    );

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (ready_sel_tx, ready_sel_rx) = oneshot::channel();
        let (ready_join_tx, ready_join_rx) = oneshot::channel();
        let (sel_a_tx, sel_a_rx) = oneshot::channel();
        let (sel_b_tx, sel_b_rx) = oneshot::channel();
        let (join_a_tx, join_a_rx) = oneshot::channel();
        let (join_b_tx, join_b_rx) = oneshot::channel();
        let (ready_map_tx, ready_map_rx) = oneshot::channel();
        let (ready_remap_tx, ready_remap_rx) = oneshot::channel();
        let (ready_dyn_tx, ready_dyn_rx) = oneshot::channel();
        let (map_tx, map_rx) = oneshot::channel();
        let (remap_tx, remap_rx) = oneshot::channel();
        let (dyn_tx, dyn_rx) = oneshot::channel();
        for tx in [
            sel_a_tx, sel_b_tx, join_a_tx, join_b_tx, map_tx, remap_tx, dyn_tx,
        ] {
            std::mem::forget(tx);
        }

        let _sel = tokio::spawn(selector(ready_sel_tx, sel_a_rx, sel_b_rx));
        let _join = tokio::spawn(joiner(ready_join_tx, join_a_rx, join_b_rx));
        let _map = tokio::spawn(mapper(ready_map_tx, map_rx));
        let _remap = tokio::spawn(remapper(ready_remap_tx, remap_rx));
        let _dynamic = tokio::spawn(dynamic(ready_dyn_tx, dyn_rx));

        ready_sel_rx.await.expect("selector signals readiness");
        ready_join_rx.await.expect("joiner signals readiness");
        ready_map_rx.await.expect("mapper signals readiness");
        ready_remap_rx.await.expect("remapper signals readiness");
        ready_dyn_rx.await.expect("dynamic signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

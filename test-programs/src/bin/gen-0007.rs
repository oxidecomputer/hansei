// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The first soak's catch, quarantined as a permanent fixture: a
//! `JoinSet` reached only through an `Option`'s active variant — the
//! shape whose find the census silently dropped until the scan
//! stopped taking enum payloads pre-peeled (peel walked through the
//! `JoinSet`'s single-member wrapper before the name screen ran).
//! The registry diff over this pair is the end-to-end regression.
//!
//! A frozen genfix output (seed 7 of the generator as first landed);
//! the generator moves on, so regeneration is not expected to
//! reproduce it — treat it as an ordinary fixture: edit if needed,
//! then recapture its pairs.
#![allow(dead_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use test_programs::census_expect;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;

/// Every running body reports in before main declares readiness.
const TOTAL_BODIES: usize = 5;

/// A hand-written select: ready when any arm is.
struct GfSel2<A, B> {
    a: A,
    b: B,
}

impl<A: Future<Output = u64>, B: Future<Output = u64>> Future for GfSel2<A, B> {
    type Output = u64;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
        // SAFETY: no arm is ever moved out of the pinned struct.
        let this = unsafe { self.get_unchecked_mut() };
        if let Poll::Ready(v) = unsafe { Pin::new_unchecked(&mut this.a) }.poll(cx) {
            return Poll::Ready(v);
        }
        if let Poll::Ready(v) = unsafe { Pin::new_unchecked(&mut this.b) }.poll(cx) {
            return Poll::Ready(v);
        }
        Poll::Pending
    }
}

/// A hand-written select: ready when any arm is.
struct GfSel3<A, B, C> {
    a: A,
    b: B,
    c: C,
}

impl<A: Future<Output = u64>, B: Future<Output = u64>, C: Future<Output = u64>> Future
    for GfSel3<A, B, C>
{
    type Output = u64;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
        // SAFETY: no arm is ever moved out of the pinned struct.
        let this = unsafe { self.get_unchecked_mut() };
        if let Poll::Ready(v) = unsafe { Pin::new_unchecked(&mut this.a) }.poll(cx) {
            return Poll::Ready(v);
        }
        if let Poll::Ready(v) = unsafe { Pin::new_unchecked(&mut this.b) }.poll(cx) {
            return Poll::Ready(v);
        }
        if let Poll::Ready(v) = unsafe { Pin::new_unchecked(&mut this.c) }.poll(cx) {
            return Poll::Ready(v);
        }
        Poll::Pending
    }
}

async fn leaf_01(notify: Arc<Notify>) -> u64 {
    notify.notified().await;
    1
}

async fn leaf_05() -> u64 {
    tokio::time::sleep(Duration::from_secs(3_000_000)).await;
    5
}

async fn leaf_09() -> u64 {
    let (tx, rx) = oneshot::channel::<u64>();
    std::mem::forget(tx);
    let _ = rx.await;
    9
}

/// Holds another future as an argument across its own park — the
/// one shape whose chain still has a future to find while unpolled.
async fn holder_04<F: Future<Output = u64>>(inner: F, notify: Arc<Notify>) -> u64 {
    notify.notified().await;
    inner.await
}

/// Holds another future as an argument across its own park — the
/// one shape whose chain still has a future to find while unpolled.
async fn holder_08<F: Future<Output = u64>>(inner: F, notify: Arc<Notify>) -> u64 {
    notify.notified().await;
    inner.await
}

async fn driver_00(
    started: mpsc::UnboundedSender<()>,
    notify: Arc<Notify>,
    sem: Arc<Semaphore>,
) -> u64 {
    let v0 = (0..3)
        .map(|_| leaf_01(notify.clone()))
        .collect::<FuturesUnordered<_>>();
    let v1 = Some({
        let mut js = JoinSet::new();
        js.spawn(member_02(started.clone(), notify.clone(), sem.clone()));
        js.spawn(member_03(started.clone(), notify.clone(), sem.clone()));
        js
    });
    census_expect::task("driver_00");
    census_expect::set(&v0 as *const _ as u64, 3);
    census_expect::join_set(v1.as_ref().unwrap() as *const _ as u64, 2);
    started.send(()).expect("main counts readiness");
    let mut sum: u64 = GfSel3 {
        a: std::future::pending::<u64>(),
        b: std::future::pending::<u64>(),
        c: std::future::pending::<u64>(),
    }
    .await;
    sum = sum.wrapping_add(v0.count().await as u64);
    let t0 = v1.unwrap();
    sum = sum.wrapping_add(t0.len() as u64);
    sum
}

async fn member_02(
    started: mpsc::UnboundedSender<()>,
    notify: Arc<Notify>,
    _sem: Arc<Semaphore>,
) -> u64 {
    census_expect::task("member_02");
    started.send(()).expect("main counts readiness");
    notify.notified().await;
    let sum: u64 = 0;
    sum
}

async fn member_03(
    started: mpsc::UnboundedSender<()>,
    notify: Arc<Notify>,
    sem: Arc<Semaphore>,
) -> u64 {
    let v0 = holder_04(leaf_05(), notify.clone());
    let v1 = {
        let mut js = JoinSet::new();
        js.spawn(member_06(started.clone(), notify.clone(), sem.clone()));
        js.spawn(member_07(started.clone(), notify.clone(), sem.clone()));
        js
    };
    census_expect::task("member_03");
    census_expect::held(&v0 as *const _ as u64, "holder_04");
    census_expect::held_in(&v0 as *const _ as u64, "leaf_05");
    census_expect::join_set(&v1 as *const _ as u64, 2);
    started.send(()).expect("main counts readiness");
    tokio::time::sleep(Duration::from_secs(3_000_000)).await;
    let mut sum: u64 = 0;
    sum = sum.wrapping_add(v0.await);
    sum = sum.wrapping_add(v1.len() as u64);
    sum
}

async fn member_06(
    started: mpsc::UnboundedSender<()>,
    _notify: Arc<Notify>,
    _sem: Arc<Semaphore>,
) -> u64 {
    census_expect::task("member_06");
    started.send(()).expect("main counts readiness");
    let sum: u64 = GfSel2 {
        a: std::future::pending::<u64>(),
        b: std::future::pending::<u64>(),
    }
    .await;
    sum
}

async fn member_07(
    started: mpsc::UnboundedSender<()>,
    notify: Arc<Notify>,
    _sem: Arc<Semaphore>,
) -> u64 {
    let v0 = holder_08(leaf_09(), notify.clone());
    census_expect::task("member_07");
    census_expect::held(&v0 as *const _ as u64, "holder_08");
    census_expect::held_in(&v0 as *const _ as u64, "leaf_09");
    started.send(()).expect("main counts readiness");
    let mut sum: u64 = GfSel2 {
        a: std::future::pending::<u64>(),
        b: std::future::pending::<u64>(),
    }
    .await;
    sum = sum.wrapping_add(v0.await);
    sum
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (started_tx, mut started_rx) = mpsc::unbounded_channel::<()>();
        // Never notified, and never granted a permit: every leaf
        // parks for good.
        let notify = Arc::new(Notify::new());
        let sem = Arc::new(Semaphore::new(0));

        let _t0 = tokio::spawn(driver_00(started_tx.clone(), notify.clone(), sem.clone()));
        drop(started_tx);

        for _ in 0..TOTAL_BODIES {
            started_rx.recv().await.expect("every body reports in");
        }
        println!("READY");
        std::future::pending::<()>().await
    })
}

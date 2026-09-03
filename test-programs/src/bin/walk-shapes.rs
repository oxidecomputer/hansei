// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shapes that pin the walk's internals, quarantined like `gen-0007`:
//! this program is in the snapshot-pair suite and the capture list
//! only — the golden, matrix, and acceptance lists enumerate
//! explicitly and do not carry it.
//!
//! - `chained` awaits a hand-written struct wrapper over a
//!   hand-written `#[repr(C, u8)]` enum wrapper over a coroutine: the
//!   chain must step through both non-coroutine frames, through
//!   members past offset zero.
//! - `holder`/`abandoner`/`victim` build a futurelock whose abandoned
//!   acquire is held *by value* (polled once by hand, then never
//!   again), so its waiter node derives from the frame member's own
//!   address rather than through a box the way `futurelock`'s does.
//! - `blocked` twice on a zero-permit semaphore shared with a task on
//!   a second runtime (`hidden_runtime`), whose only edge out is its
//!   waiter in that semaphore's wake queue.
//! - Two `LocalSet`s: one driven by `run_until`, one held on a plain
//!   thread behind `LocalSet::enter` with a never-polled local task —
//!   anchored in that thread's TLS and nowhere else.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use test_programs::census_expect;
use tokio::sync::{Mutex, Notify, Semaphore, oneshot};
use tokio::task::LocalSet;

/// A hand-written wrapper future: exactly one future member, past a
/// sized tag — `repr(C)` keeps the declared order, so the member the
/// chain steps to sits at a nonzero offset.
#[repr(C)]
struct WrapS<F> {
    tag: u64,
    inner: F,
}

impl<F: Future> Future for WrapS<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        assert_eq!(self.tag, 7);
        // SAFETY: `inner` is pinned structurally and never moved out.
        unsafe { self.map_unchecked_mut(|w| &mut w.inner) }.poll(cx)
    }
}

/// A hand-written enum future, the `futures_util::Map` shape: a named
/// variant holding the live future. `repr(C, u8)` puts the
/// discriminant byte first and the variant's fields behind it at the
/// payload's own alignment, so the variant payload sits at a nonzero
/// offset by contract.
#[repr(C, u8)]
enum WrapE<F> {
    Running {
        tag: u64,
        inner: F,
    },
    #[allow(dead_code)]
    Done,
}

impl<F: Future> Future for WrapE<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // SAFETY: `inner` is pinned structurally; the variant never
        // changes while polled.
        match unsafe { self.get_unchecked_mut() } {
            WrapE::Running { tag, inner } => {
                assert_eq!(*tag, 9);
                unsafe { Pin::new_unchecked(inner) }.poll(cx)
            }
            WrapE::Done => Poll::Pending,
        }
    }
}

/// Not a future and never polled: a pure wrapper whose only sized
/// member is a future beside a zero-sized marker. Held across an
/// await so the type survives into the bundle — the is_future unit
/// tests pin that the wrapper unwrap follows the sized member and
/// steps over the marker.
struct WrapZ<F> {
    inner: F,
    _zst: std::marker::PhantomData<u8>,
}

async fn deep(park: Arc<Notify>) -> u32 {
    park.notified().await;
    5
}

async fn chained(ready: oneshot::Sender<()>, park: Arc<Notify>, held_park: Arc<Notify>) -> u32 {
    census_expect::task("walk_shapes::chained");
    let wz = WrapZ {
        inner: deep(held_park),
        _zst: std::marker::PhantomData,
    };
    census_expect::held(&wz.inner as *const _ as u64, "deep");
    ready.send(()).expect("main waits for readiness");
    // Awaited as an expression, not a binding: a named local would
    // leave a moved-from copy of the wrappers in this frame for the
    // census to find.
    WrapS {
        tag: 7,
        inner: WrapE::Running {
            tag: 9,
            inner: deep(park),
        },
    }
    .await;
    drop(wz);
    17
}

async fn holder(
    taken_a: oneshot::Sender<()>,
    taken_v: oneshot::Sender<()>,
    park: Arc<Notify>,
    lock: Arc<Mutex<()>>,
) {
    census_expect::task("walk_shapes::holder");
    let _guard = lock.lock().await;
    taken_a.send(()).expect("the abandoner waits");
    taken_v.send(()).expect("the victim waits");
    park.notified().await;
}

async fn abandoner(
    taken: oneshot::Receiver<()>,
    ready: oneshot::Sender<()>,
    park: Arc<Notify>,
    lock: Arc<Mutex<()>>,
) {
    census_expect::task("walk_shapes::abandoner");
    taken.await.expect("the holder signals");
    let mut fut = lock.lock();
    // Enqueue the acquire — one poll against a waker that wakes
    // nobody — then never poll it again: an abandoned waiter held by
    // value in this frame.
    // SAFETY: `fut` is never moved after this poll; it lives here
    // until the frame drops.
    let polled =
        unsafe { Pin::new_unchecked(&mut fut) }.poll(&mut Context::from_waker(Waker::noop()));
    assert!(polled.is_pending(), "the holder holds the lock");
    census_expect::held(&fut as *const _ as u64, "mutex");
    ready.send(()).expect("main waits for readiness");
    park.notified().await;
    drop(fut);
}

async fn victim(taken: oneshot::Receiver<()>, ready: oneshot::Sender<()>, lock: Arc<Mutex<()>>) {
    census_expect::task("walk_shapes::victim");
    taken.await.expect("the holder signals");
    ready.send(()).expect("main waits for readiness");
    let _guard = lock.lock().await;
}

async fn blocked(ready: oneshot::Sender<()>, sem: Arc<Semaphore>) {
    census_expect::task("walk_shapes::blocked");
    ready.send(()).expect("main waits for readiness");
    let _permit = sem.acquire().await.expect("the semaphore stays open");
}

async fn hidden_blocked(ready: oneshot::Sender<()>, sem: Arc<Semaphore>) {
    census_expect::task("walk_shapes::hidden_blocked");
    ready.send(()).expect("main waits for readiness");
    let _permit = sem.acquire().await.expect("the semaphore stays open");
}

/// A second runtime driven to its parked state and then left idle on
/// this thread's stack, the `foreign-runtime` shape: no thread is
/// inside it and no JoinHandle leaves it, so its one task's waiter in
/// the shared semaphore's wake queue is the only edge from the
/// enumerated population to it.
fn hidden_runtime(ready: oneshot::Sender<()>, sem: Arc<Semaphore>) {
    let runtime = test_programs::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the second runtime builds");
    let (queued_tx, queued_rx) = oneshot::channel();
    drop(runtime.spawn(hidden_blocked(queued_tx, sem)));
    // A task's poll runs from its readiness send to its leaf before
    // the root future observing that send is polled again
    // (current_thread), so the acquire is queued once this returns.
    runtime.block_on(async move { queued_rx.await.expect("the task signals") });
    ready.send(()).expect("main waits for readiness");
    let (_never_tx, never_rx) = std::sync::mpsc::channel::<()>();
    let _ = never_rx.recv();
}

async fn local_parker(ready: oneshot::Sender<()>, park: Arc<Notify>) -> u32 {
    census_expect::task("walk_shapes::local_parker");
    ready.send(()).expect("main waits for readiness");
    park.notified().await;
    41
}

async fn joiner(ready: oneshot::Sender<()>, handle: tokio::task::JoinHandle<u32>) -> u32 {
    census_expect::task("walk_shapes::joiner");
    ready.send(()).expect("main waits for readiness");
    handle.await.expect("the parker never finishes")
}

async fn side_parker() {
    std::future::pending::<()>().await
}

/// A `LocalSet` a plain thread holds entered but never runs: its one
/// local task is never polled, no `JoinHandle` crosses out, and the
/// set is anchored in this thread's TLS and nowhere else.
fn side_set(ready: oneshot::Sender<()>) {
    let (_never_tx, never_rx) = std::sync::mpsc::channel::<()>();
    let local = LocalSet::new();
    let _side = local.spawn_local(side_parker());
    let _guard = local.enter();
    ready.send(()).expect("main waits for readiness");
    let _ = never_rx.recv();
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_current_thread();
    test_programs::run_builder(&mut builder, async {
        let lock = Arc::new(Mutex::new(()));
        let sem = Arc::new(Semaphore::new(0));
        let chain_park = Arc::new(Notify::new());
        let hold_park = Arc::new(Notify::new());
        let abandon_park = Arc::new(Notify::new());
        let local_park = Arc::new(Notify::new());

        let (taken_a_tx, taken_a_rx) = oneshot::channel();
        let (taken_v_tx, taken_v_rx) = oneshot::channel();
        let (r_chain_tx, r_chain_rx) = oneshot::channel();
        let (r_abandon_tx, r_abandon_rx) = oneshot::channel();
        let (r_victim_tx, r_victim_rx) = oneshot::channel();
        let (r_ba_tx, r_ba_rx) = oneshot::channel();
        let (r_bb_tx, r_bb_rx) = oneshot::channel();
        let (r_hidden_tx, r_hidden_rx) = oneshot::channel();
        let (r_parker_tx, r_parker_rx) = oneshot::channel();
        let (r_joiner_tx, r_joiner_rx) = oneshot::channel();
        let (r_side_tx, r_side_rx) = oneshot::channel();

        let held_park = Arc::new(Notify::new());
        tokio::spawn(chained(r_chain_tx, chain_park.clone(), held_park.clone()));
        tokio::spawn(holder(
            taken_a_tx,
            taken_v_tx,
            hold_park.clone(),
            lock.clone(),
        ));
        tokio::spawn(abandoner(
            taken_a_rx,
            r_abandon_tx,
            abandon_park.clone(),
            lock.clone(),
        ));
        tokio::spawn(victim(taken_v_rx, r_victim_tx, lock.clone()));
        tokio::spawn(blocked(r_ba_tx, sem.clone()));
        tokio::spawn(blocked(r_bb_tx, sem.clone()));
        {
            let sem = sem.clone();
            std::thread::spawn(move || hidden_runtime(r_hidden_tx, sem));
        }
        std::thread::spawn(move || side_set(r_side_tx));

        let local = LocalSet::new();
        let parker = local.spawn_local(local_parker(r_parker_tx, local_park.clone()));
        tokio::spawn(joiner(r_joiner_tx, parker));

        local
            .run_until(async move {
                // On current_thread, spawned and local tasks run only
                // when this future yields; once every readiness send
                // has arrived, each task has been polled past its send
                // and parked at its leaf — the queued acquires are in
                // their wake queues.
                r_chain_rx.await.expect("chained signals readiness");
                r_abandon_rx.await.expect("abandoner signals readiness");
                r_victim_rx.await.expect("victim signals readiness");
                r_ba_rx.await.expect("blocked signals readiness");
                r_bb_rx.await.expect("blocked signals readiness");
                r_hidden_rx
                    .await
                    .expect("the hidden task signals readiness");
                r_parker_rx.await.expect("local parker signals readiness");
                r_joiner_rx.await.expect("joiner signals readiness");
                r_side_rx.await.expect("the side thread signals readiness");
                println!("READY");
                std::future::pending::<()>().await
            })
            .await
    })
}

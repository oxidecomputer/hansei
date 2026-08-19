//! Tasks a `JoinSet` holds (the `hansei tasks --futures` census): a
//! driver parked in `join_next` while the tasks it spawned onto the set
//! park in a shared `Notify`. Unlike a `FuturesUnordered`'s children,
//! these are tasks the runtime owns and every listing shows — what the
//! set adds is which of them this one task is waiting to join.
//!
//! Beside it the driver holds a second set it never joins, one of whose
//! members has run to completion: a task that has left the runtime's
//! owned list, so no listing shows it, and which only the set's entry
//! still names. That is the one member state a set can hold that the
//! listings cannot corroborate.

use std::sync::Arc;

use test_programs::census_expect;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinSet;

/// How many tasks the driver spawns onto the set it joins. The
/// acceptance suite asserts this count, so the two must agree.
const MEMBERS: usize = 3;

/// How many it spawns onto the set it never joins, the last of which
/// completes rather than parking.
const KEPT: usize = 3;

async fn member(started: mpsc::Sender<()>, notify: Arc<Notify>) -> u32 {
    census_expect::task("joinset::member");
    started.send(()).await.expect("the driver waits for us");
    notify.notified().await;
    7
}

/// A member that reports in and returns, so that by the time the target
/// is declared ready its task is complete and no longer owned by the
/// runtime — held alive only by the set's entry for it. It registers
/// nothing: a registered task must still be listed at the capture, and
/// leaving the listing is this one's whole job.
async fn finisher(started: mpsc::Sender<()>) -> u32 {
    started.send(()).await.expect("the driver waits for us");
    13
}

async fn driver(ready: oneshot::Sender<()>, notify: Arc<Notify>) -> u32 {
    // Room for every member, so reporting in never parks a member on
    // the channel instead of on the Notify below.
    let (started_tx, mut started_rx) = mpsc::channel(MEMBERS + KEPT);
    let mut set = JoinSet::new();
    for _ in 0..MEMBERS {
        set.spawn(member(started_tx.clone(), notify.clone()));
    }

    // The set the driver never joins: nothing takes the finisher's
    // output, so its entry stays in the set's notified list with the
    // completed task behind it.
    let mut kept = JoinSet::new();
    for _ in 1..KEPT {
        kept.spawn(member(started_tx.clone(), notify.clone()));
    }
    kept.spawn(finisher(started_tx.clone()));
    drop(started_tx);

    // Ground truth for the census diff: both sets, with everything they
    // hold counted — the completed finisher included, since its entry
    // stays in `kept` until joined.
    census_expect::task("joinset::driver");
    census_expect::join_set(&set as *const _ as u64, MEMBERS);
    census_expect::join_set(&kept as *const _ as u64, KEPT);

    // Every member has run before the target is declared ready, so the
    // set holds tasks the listing can show rather than ones the
    // scheduler has not reached yet.
    for _ in 0..MEMBERS + KEPT {
        started_rx.recv().await.expect("every member reports in");
    }
    ready.send(()).expect("main waits for readiness");

    let mut sum = 0;
    while let Some(value) = set.join_next().await {
        sum += value.expect("no member panics");
    }
    sum + kept.len() as u32
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        // Never notified: the members park in the Notify's wait queue
        // for good, so the driver stays parked in `join_next`.
        let notify = Arc::new(Notify::new());

        let _task = tokio::spawn(driver(ready_tx, notify));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

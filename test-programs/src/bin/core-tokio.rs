//! The tokio target for hansei's Linux suite (`hansei/tests/linux.rs`):
//! a runtime driven to a deterministic steady state that then dumps
//! core on purpose.
//!
//! It is `simple-await` with a different ending. That fixture parks
//! forever, because the illumos suite attaches to it while it runs;
//! nothing reads a live process on Linux yet, so this one aborts once
//! its task is parked and the suite works from the core.
//!
//! Two tasks, both idle at a known await point: one parked on a oneshot
//! whose sender is leaked, and one on a channel nobody sends to. Their
//! locals are spelled out so the suite can check that hansei reads them
//! back rather than merely finding them.
//!
//! Keep the names and values here in step with the suite's constants.

use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot};

/// The suite looks for this value in `parked_task`'s locals.
pub const MARKER: u64 = 0x0123_4567_89ab_cdef;

async fn parked_task(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    let marker: u64 = MARKER;
    let counts = BTreeMap::from([(1u64, 10u32), (2, 20), (3, 30)]);
    #[allow(clippy::useless_vec)]
    let values = vec![5u32, 8, 13];
    ready.send(()).expect("main waits for readiness");
    // Parks forever: the sender is leaked by main.
    let parked = park.await.unwrap_or(0);
    parked + counts.len() as u32 + values[0] + marker as u32
}

async fn receiving_task(ready: oneshot::Sender<()>, mut rx: mpsc::Receiver<u32>) -> u32 {
    let label = String::from("receiver");
    ready.send(()).expect("main waits for readiness");
    // Parks forever: the sender is leaked by main.
    let got = rx.recv().await.unwrap_or(0);
    got + label.len() as u32
}

fn main() {
    let mut builder = oxide_tokio_rt::Builder::new_multi_thread();
    builder.worker_threads(2);
    oxide_tokio_rt::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (park_tx, park_rx) = oneshot::channel();
        // Leaked: dropping it would close the channel and wake the task
        // out of its steady state.
        std::mem::forget(park_tx);
        let _parked = tokio::spawn(parked_task(ready_tx, park_rx));

        let (rx_ready_tx, rx_ready_rx) = oneshot::channel();
        let (chan_tx, chan_rx) = mpsc::channel::<u32>(4);
        std::mem::forget(chan_tx);
        let _receiving = tokio::spawn(receiving_task(rx_ready_tx, chan_rx));

        ready_rx.await.expect("the parked task signals readiness");
        rx_ready_rx
            .await
            .expect("the receiving task signals readiness");
        println!("READY");

        // Both tasks are parked at a known await point; take the core
        // here rather than leaving the process running, since nothing
        // reads a live process on this platform yet.
        std::process::abort()
    })
}

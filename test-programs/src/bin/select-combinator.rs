// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `select!` and `join!` shapes: two spawned tasks suspended
//! inside combinator-generated futures, parked deterministically on
//! oneshots whose senders are intentionally leaked.

use tokio::sync::oneshot;

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

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (ready_sel_tx, ready_sel_rx) = oneshot::channel();
        let (ready_join_tx, ready_join_rx) = oneshot::channel();
        let (sel_a_tx, sel_a_rx) = oneshot::channel();
        let (sel_b_tx, sel_b_rx) = oneshot::channel();
        let (join_a_tx, join_a_rx) = oneshot::channel();
        let (join_b_tx, join_b_rx) = oneshot::channel();
        for tx in [sel_a_tx, sel_b_tx, join_a_tx, join_b_tx] {
            std::mem::forget(tx);
        }

        let _sel = tokio::spawn(selector(ready_sel_tx, sel_a_rx, sel_b_rx));
        let _join = tokio::spawn(joiner(ready_join_tx, join_a_rx, join_b_rx));

        ready_sel_rx.await.expect("selector signals readiness");
        ready_join_rx.await.expect("joiner signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

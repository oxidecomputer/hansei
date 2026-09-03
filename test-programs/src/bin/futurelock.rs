// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;
use test_programs::census_expect;
use tokio::spawn;
use tokio::sync::Mutex;
use tokio::time::sleep;

/// This is the demo program from RFD 609, but using oxide-tokio-rt
fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(4);
    test_programs::run_builder(&mut builder, async {
        let h = spawn(async move {
            census_expect::task("futurelock::main");

            // Create a lock that will be shared by multiple tasks.
            let lock = Arc::new(Mutex::new(()));

            // Start a background task that takes the lock and holds it for a few
            // seconds.  This is just to simulate some contention.  This function only
            // returns once the lock has been taken in the background task.
            start_background_task(lock.clone()).await;

            // The guts of the example.
            do_stuff(lock.clone()).await;
        });

        h.await.unwrap()
    })
}

// Starts a background task that grabs the lock, holds it for 5 seconds,
// and then drops it.  Returns once the task is holding the lock.
// The purpose of this is to simulate contention.
async fn start_background_task(lock: Arc<Mutex<()>>) {
    // Use a channel to coordinate with the task so that it can tell us when
    // its taken the lock.
    let (tx, rx) = tokio::sync::oneshot::channel();
    // Detached on purpose: the task runs to completion without being awaited.
    #[allow(clippy::let_underscore_future)]
    let _ = tokio::spawn(async move {
        println!("background task: start");
        let _guard = lock.lock().await;
        let _ = tx.send(());
        sleep(Duration::from_secs(5)).await;
        println!("background task: done (dropping lock)")
    });
    // Wait for the task to take the lock before returning.
    let _ = rx.await;
}

// The guts of the example
async fn do_stuff(lock: Arc<Mutex<()>>) {
    let mut future1 = do_async_thing("op1", lock.clone()).boxed();
    // Ground truth for the census diff: the future the futurelock is
    // about, registered by the slot its box sits in.
    census_expect::held(&future1 as *const _ as u64, "futurelock::do_async_thing");

    // Try to execute `future1`.  If it takes more than 500ms, do
    // a related thing instead.
    println!("do_stuff: entering select");
    tokio::select! {
        _ = &mut future1 => {
            println!("do_stuff: arm1 future finished");
        }
        _ = sleep(Duration::from_millis(500)) => {
            do_async_thing("op2", lock.clone()).await;
        }
    };
    println!("do_stuff: all done");
}

async fn do_async_thing(label: &str, lock: Arc<Mutex<()>>) {
    println!("{label}: started");
    let _ = lock.lock().await;
    println!("{label}: acquired lock");
    println!("{label}: done");
}

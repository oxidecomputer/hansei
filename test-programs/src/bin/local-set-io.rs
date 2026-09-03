// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A `LocalSet` whose only trace outside its own list is io: its tasks
//! are spawned with their `JoinHandle`s dropped on the spot, nothing
//! outside the set waits on anything they hold, and a parked core reads
//! the `CURRENT` anchor empty — so the cell bootstrap and the TLS probe
//! both come up empty. Nothing here parks on time either, so the timer
//! wheel is empty and route 2's first registry has nothing to say. What
//! does see them is the io driver's own registration list, where each
//! socket they await holds the awaiting task's waker.
//!
//! One member per waker site, because a `ScheduledIo` has three and
//! they are not interchangeable: `AsyncRead` and `AsyncWrite` park in
//! the two direction slots, which are in no list at all, while an
//! `Interest`-based readiness await pushes a node onto the resource's
//! waiter list.

use std::io::ErrorKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::LocalSet;

/// The `AsyncRead` park: the waker lands in the resource's `reader`
/// slot. The peer never writes, so the read never completes.
async fn local_reader(ready: oneshot::Sender<()>, mut stream: UnixStream) -> usize {
    test_programs::census_expect::task("local_set_io::local_reader");
    let mut buf = [0u8; 8];
    ready.send(()).expect("main waits for readiness");
    stream.read(&mut buf).await.expect("the peer stays open")
}

/// The `Interest` park: the waker lands on a `Waiter` node in the
/// resource's own list, the site the other two never touch.
async fn local_watcher(ready: oneshot::Sender<()>, stream: UnixStream, tag: &'static str) -> usize {
    test_programs::census_expect::task("local_set_io::local_watcher");
    ready.send(()).expect("main waits for readiness");
    stream.readable().await.expect("the peer stays open");
    tag.len()
}

/// The `AsyncWrite` park: the waker lands in the `writer` slot. Parking
/// there takes a socket the kernel will accept no more bytes for, so
/// the buffer is filled first — establishing writability, then writing
/// until the write refuses — and only the write after that can park.
/// The peer never reads, so nothing ever drains it.
async fn local_writer(ready: oneshot::Sender<()>, mut stream: UnixStream, fill: Vec<u8>) -> usize {
    test_programs::census_expect::task("local_set_io::local_writer");
    stream.writable().await.expect("the peer stays open");
    loop {
        match stream.try_write(&fill) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => panic!("failed to fill the socket: {e}"),
        }
    }
    ready.send(()).expect("main waits for readiness");
    stream.write_all(&fill).await.expect("the peer stays open");
    fill.len()
}

/// The ordinary spawned task. It parks on io like the set's members, so
/// its own waker sits on a registration the harvest walks — already
/// listed, and so not a candidate, which is the other half of what the
/// harvest has to get right. It captures what none of them do, so no
/// two of these state machines are the same shape: identical drop glue
/// is foldable, and a build that folds it leaves only one of them named
/// in the extraction summary.
async fn reader(ready: oneshot::Sender<()>, mut stream: UnixStream, seed: u64) -> u64 {
    test_programs::census_expect::task("local_set_io::reader");
    let mut buf = [0u8; 16];
    ready.send(()).expect("main waits for readiness");
    seed + stream.read(&mut buf).await.expect("the peer stays open") as u64
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_current_thread();
    test_programs::run_builder(&mut builder, async {
        // One pair per task: a resource with two tasks on it would put
        // two wakers on one registration, and the point here is that
        // each site is reached on its own. The peer halves are held by
        // this future, which never completes — a closed peer would end
        // every await below with an EOF instead of a park.
        let (reader_a, peer_a) = UnixStream::pair().expect("a socketpair");
        let (watcher_b, peer_b) = UnixStream::pair().expect("a socketpair");
        let (writer_c, peer_c) = UnixStream::pair().expect("a socketpair");
        let (reader_d, peer_d) = UnixStream::pair().expect("a socketpair");
        let _peers = (peer_a, peer_b, peer_c, peer_d);

        let (ready_a_tx, ready_a_rx) = oneshot::channel();
        let (ready_b_tx, ready_b_rx) = oneshot::channel();
        let (ready_c_tx, ready_c_rx) = oneshot::channel();
        let (ready_d_tx, ready_d_rx) = oneshot::channel();
        let local = LocalSet::new();
        // Dropping the handles detaches the tasks without cancelling
        // them: they stay in the set's list, and nothing outside it
        // holds a pointer to any of them.
        drop(local.spawn_local(local_reader(ready_a_tx, reader_a)));
        drop(local.spawn_local(local_watcher(ready_b_tx, watcher_b, "watching")));
        drop(local.spawn_local(local_writer(ready_c_tx, writer_c, vec![0xa5; 64 * 1024])));
        let _reader = tokio::spawn(reader(ready_d_tx, reader_d, 100));
        local
            .run_until(async move {
                // On current_thread, spawned and local tasks alike run
                // only when this future yields; once every readiness
                // send has arrived, each task has been polled past its
                // send and parked at its leaf.
                ready_a_rx.await.expect("local reader signals readiness");
                ready_b_rx.await.expect("local watcher signals readiness");
                ready_c_rx.await.expect("local writer signals readiness");
                ready_d_rx.await.expect("reader signals readiness");
                println!("READY");
                std::future::pending::<()>().await
            })
            .await
    })
}

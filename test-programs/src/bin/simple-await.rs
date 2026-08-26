//! One spawned async fn with two await points and known locals.
//!
//! The task reaches a deterministic steady state: it passes one
//! trivially-ready await point, signals readiness, then parks forever on
//! a oneshot whose sender is intentionally leaked. `READY` on stdout
//! means the state is stable — no timing involved.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::oneshot;

async fn ready_value() -> u32 {
    41
}

async fn work(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    test_programs::census_expect::task("simple_await::work");
    let count: u32 = 3;
    let labels = BTreeMap::from([(1u64, 10u32), (2, 20), (3, 30)]);
    // A real `Vec` (not an array) so the fixture exercises the Vec formatter;
    // the golden test asserts its resolved member path.
    #[allow(clippy::useless_vec)]
    let values = vec![5u32, 8, 13];
    // A boxed slice and a borrowed slice: `Box<[T]>`/`&[T]` are `(ptr, len)`
    // fat pointers with no capacity, exercising the Slice formatter's
    // no-capacity path. Both are kept live across the await below.
    let boxed: Box<[u32]> = vec![21u32, 34].into_boxed_slice();
    let slice: &[u32] = &values;
    let ipv4 = Ipv4Addr::new(192, 0, 2, 1);
    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let borrowed = "borrowed\ntext";
    let owned = String::from("owned\ttext");
    // C strings need not be UTF-8 (the 0xFF byte exercises the lossy
    // rendering), and their recorded length counts the NUL terminator.
    let c_owned = CString::new(b"c\xFFtext".to_vec()).unwrap();
    let c_borrowed: &CStr = c"cstr";
    let first = ready_value().await;
    ready.send(()).expect("main waits for readiness");
    let second = park.await.unwrap_or(0);
    count
        + first
        + second
        + label_for(&labels, u64::from(second))
        + values[0]
        + boxed[0]
        + slice[2]
        + u32::from(ipv4.octets()[3])
        + u32::from(ipv6.octets()[15])
        + borrowed.len() as u32
        + owned.len() as u32
        + c_owned.as_bytes().len() as u32
        + c_borrowed.to_bytes().len() as u32
}

// Keep the map live across `park.await` so its private layout remains part of
// the fixture's async state on every target.
#[inline(never)]
fn label_for(labels: &BTreeMap<u64, u32>, key: u64) -> u32 {
    labels.get(&key).copied().unwrap_or(0)
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (park_tx, park_rx) = oneshot::channel();
        // Leak the sender: dropping it would close the channel and wake
        // the task out of its steady state.
        std::mem::forget(park_tx);

        let _task = tokio::spawn(work(ready_tx, park_rx));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

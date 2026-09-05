// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Enums whose tag constants DWARF does not spell at the tag's width.
//!
//! LLVM writes a `DW_AT_discr_value` in the narrowest data form that
//! holds the constant as a number of the repr's signedness: `-1` on a
//! `#[repr(i32)]` enum is one `0xff` byte, while `0xffff_ffff` on a
//! `#[repr(u32)]` one is four. Extraction has to widen the former to
//! the tag's `0xffff_ffff` and leave the latter alone, and the golden
//! test pins each variant's stored bits against these shapes — the
//! canary for the day the form selection changes. Every enum is held
//! across a park by one task so it reaches the bundle.
//!
//! The task parks deterministically: it signals readiness, then waits
//! forever on a oneshot whose sender is intentionally leaked. This
//! program is in the golden list only.

use tokio::sync::oneshot;

/// Negative constants narrower than the four-byte tag, and one wider
/// than a byte.
#[repr(i32)]
#[allow(dead_code)]
enum Signed32 {
    Below(u8) = -1,
    Zero(u16) = 0,
    Wide(u32) = 1000,
}

/// The same on an eight-byte tag, plus a constant that needs all eight
/// bytes.
#[repr(i64)]
#[allow(dead_code)]
enum Signed64 {
    Below(u8) = -2,
    Zero(u16) = 0,
    Floor(u32) = i64::MIN,
}

/// The unsigned control: a one-byte constant on a four-byte tag must
/// not be sign-extended, and a full-width one is already the tag's.
#[repr(u32)]
#[allow(dead_code)]
enum Unsigned32 {
    Byte(u8) = 0xff,
    Zero(u16) = 0,
    Top(u32) = 0xffff_ffff,
}

/// A C-style enum with a negative enumerator, whose constant DWARF
/// spells as a signed `sdata` rather than a data form.
#[repr(i32)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
enum Level {
    Below = -1,
    Base = 0,
    Above = 7,
}

async fn hold(ready: oneshot::Sender<()>, park: oneshot::Receiver<u32>) -> u32 {
    test_programs::census_expect::task("enum_reprs::hold");
    let signed32 = Signed32::Below(1);
    let signed64 = Signed64::Below(2);
    let unsigned32 = Unsigned32::Byte(3);
    let level = Level::Below;
    ready.send(()).expect("main waits for readiness");
    let parked = park.await.unwrap_or(0);
    let payload = |value: u32| value + parked;
    payload(match signed32 {
        Signed32::Below(v) => u32::from(v),
        Signed32::Zero(v) => u32::from(v),
        Signed32::Wide(v) => v,
    }) + payload(match signed64 {
        Signed64::Below(v) => u32::from(v),
        Signed64::Zero(v) => u32::from(v),
        Signed64::Floor(v) => v,
    }) + payload(match unsigned32 {
        Unsigned32::Byte(v) => u32::from(v),
        Unsigned32::Zero(v) => u32::from(v),
        Unsigned32::Top(v) => v,
    }) + payload(level as i32 as u32)
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

        let _task = tokio::spawn(hold(ready_tx, park_rx));

        ready_rx.await.expect("task signals readiness");
        println!("READY");
        std::future::pending::<()>().await
    })
}

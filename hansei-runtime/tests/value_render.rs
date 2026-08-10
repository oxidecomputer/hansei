// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Offline value-render tests: join a real extracted bundle against a
//! real captured snapshot and assert on reify's *rendered* output.
//!
//! `two_binary.rs` proves the task/await analysis; the golden tests in
//! `exegesis` prove a detector resolves the right member paths. Neither
//! feeds a real extracted bundle to the value renderer, so a detector
//! that emits a valid-but-wrong offset the renderer then reads
//! "successfully" is invisible to both. These tests close that loop: the
//! `channels` snapshot was captured with the value renderer driven over
//! every frame's locals (`hansei snapshot` warms them), so the pages
//! behind the formatted values — the bounded mpsc channel, `Notify`,
//! `Semaphore`, and `watch` — are recorded and replay here, in plain
//! `cargo test` on any platform.
//!
//! The expected render is a golden in `tests/value_render/`; regenerate
//! after an intended change with `VALUE_RENDER_BLESS=1 cargo test -p
//! hansei-runtime --test value_render` and review the diff.

use exegesis::bundle::{Bundle, BundleView};
use hansei_runtime::tokio::bundle::{Context, TaskStage};
use proc::Target;
use proc::snapshot::Snapshot;
use reify::TypeInfoRef;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn load(program: &str) -> (Bundle, Snapshot) {
    let bundle = Bundle::load(&fixture(&format!("{program}.bundle")))
        .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
    let snapshot = Snapshot::load(&fixture(&format!("{program}.snapshot")))
        .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
    (bundle, snapshot)
}

/// Mask the run-varying heap/text addresses so the golden compares
/// exactly; the decoded semantics (permit counts, queued values, waiter
/// queues) are what the golden pins.
fn mask(s: &str) -> String {
    regex::Regex::new(r"0x[0-9a-f]+")
        .unwrap()
        .replace_all(s, "0xADDR")
        .into_owned()
}

/// Render the first source-level local named `local` in running task
/// `task_id`'s outermost frame, pretty-printed and address-masked.
fn render_local(
    ctx: &Context<'_, Snapshot>,
    snapshot: &Snapshot,
    list: &hansei_runtime::tokio::bundle::TaskList,
    task_id: u64,
    local: &str,
    depth: usize,
) -> String {
    let task = list
        .tasks
        .iter()
        .find(|t| t.task_id == Some(task_id))
        .unwrap_or_else(|| panic!("no task {task_id}"));
    let TaskStage::Running(future) = ctx.task_stage(task).unwrap() else {
        panic!("task {task_id} is not running");
    };
    let chain = ctx.await_chain(future);
    let frame = chain.frames.first().expect("a running frame");
    let payload = match &frame.state {
        Some(state) => state.payload.as_ref(),
        None => frame.future.as_ref(),
    };
    let m = payload
        .ty
        .members()
        .find(|m| m.name() == local && m.ty().size() > 0)
        .unwrap_or_else(|| panic!("no local `{local}` in task {task_id}"));
    let start = m.offset() as usize;
    let bytes = &payload.bytes[start..start + m.ty().size() as usize];
    // No `peel()`: rendering the local at its declared type is what
    // dispatches the top-level formatter under test (e.g. `MpscRx`'s
    // compact form); peeling would strip `bounded::Receiver` down to its
    // inner `Arc<Chan>` and defeat it.
    let v = TypeInfoRef::new(m.ty(), payload.addr + m.offset(), bytes);
    mask(&format!("{:#}", v.display_from_target(snapshot, depth)))
}

/// Render one local per formatter into a single golden-friendly summary.
/// Task 4 is the holder parked owning every primitive; task 3 is the
/// waiter parked in the shared `Notify`'s queue.
fn interpret(bundle: &Bundle, snapshot: &Snapshot) -> String {
    let view = BundleView::new(bundle);
    let ctx = Context::new(snapshot, view).expect("snapshot has mappings");

    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let shared = ctx.find_shared(&workers).expect("a MultiThread runtime");
    let list = ctx.enumerate_tasks(&shared).expect("the owned-task walk");
    assert!(
        list.errors.is_empty(),
        "task walk errors: {:?}",
        list.errors
    );

    // (header, task id, local, depth) — one entry per formatter exercised.
    let cases = [
        ("mpsc::bounded::Receiver (_rx)", 4, "_rx", 20),
        ("Arc<Semaphore> (_sem)", 4, "_sem", 20),
        ("Arc<Notify> (_notify)", 4, "_notify", 20),
        ("watch::Receiver (_watch_rx)", 4, "_watch_rx", 20),
        ("mpsc::bounded::Sender (_tx)", 4, "_tx", 20),
        ("watch::Sender (_watch_tx)", 4, "_watch_tx", 20),
    ];

    let mut out = String::new();
    for (header, task_id, local, depth) in cases {
        writeln!(out, "== {header} ==").unwrap();
        writeln!(
            out,
            "{}",
            render_local(&ctx, snapshot, &list, task_id, local, depth)
        )
        .unwrap();
        writeln!(out).unwrap();
    }
    out
}

#[track_caller]
fn assert_golden(program: &str, golden: &str) {
    let (bundle, snapshot) = load(program);
    let actual = interpret(&bundle, &snapshot);
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/value_render")
        .join(golden);

    if std::env::var_os("VALUE_RENDER_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &actual).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing golden {}; regenerate with VALUE_RENDER_BLESS=1",
            path.display()
        )
    });
    assert_eq!(
        actual.trim(),
        expected.trim(),
        "\n== value render for {program} (bless with VALUE_RENDER_BLESS=1) ==\n{actual}"
    );
}

/// The four tokio-sync formatters, rendered from real target memory:
/// the bounded mpsc receiver surfacing its two queued-but-unreceived
/// messages and free permits, the semaphore's permit count, the shared
/// `Notify` with its one parked waiter, and the watch's published value.
#[test]
fn test_channels_value_render() {
    assert_golden("channels", "channels.golden");
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Snapshot-based two-binary offline tests (plan §11.3).
//!
//! Each fixture pair was produced by `test-programs/capture-snapshots.sh`:
//! the `.snapshot` is everything the analysis read from a live run of
//! one compilation (build A), and the `.bundle` was extracted from a
//! *separate* compilation of the same sources (build B). Joining B's
//! layouts against A's memory by mangled symbol name is the two-binary
//! constraint the whole design rests on (§2), exercised here in plain
//! `cargo test` on any platform.
//!
//! The expected summaries are goldens: they change only when the
//! fixtures are regenerated (new sources, toolchain, or tokio), and a
//! diff here is reviewable line by line. `fingerprint N/N` counts the
//! symbols the *capturing* platform's linker kept, so it is a property
//! of where the pair was made rather than of where the test runs.
//!
//! What the pairs were captured from is recorded in `fixtures/SOURCES`
//! and checked by [`test_fixtures_record_the_current_programs`], since
//! nothing else here would notice the programs moving on without them.

use exegesis::bundle::{Bundle, BundleView};
use hansei_types::tokio::bundle::{AwaitChain, ChainEnd, Context, FutureInfo, TaskStage};
use hansei_types::tokio::graph;
use proc::Target;
use proc::snapshot::Snapshot;

use std::collections::HashSet;
use std::fmt::Write;
use std::path::{Path, PathBuf};

/// Every program `capture-snapshots.sh` captures a fixture pair for.
const PROGRAMS: &[&str] = &[
    "simple-await",
    "nested-await",
    "dyn-future",
    "futurelock",
    "sleep-join",
    "channels",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// What a fixture pair was captured from: the program's own source, and
/// the crate every program calls into before it parks.
fn source_digest(program: &str) -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate is in a workspace")
        .join("test-programs/src");
    let mut hasher = blake3::Hasher::new();
    for path in [
        src.join("lib.rs"),
        src.join("bin").join(format!("{program}.rs")),
    ] {
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        hasher.update(&bytes);
    }
    hasher.finalize().to_hex()[..32].to_string()
}

/// The fixtures record programs that go on being edited underneath
/// them.
///
/// A pair is captured once and checked in, and nothing else in the
/// suite rebuilds it: the summaries below quote line numbers out of
/// `test-programs/src`, but they are compared against a snapshot taken
/// when those lines were somewhere else, so the two agree with each
/// other however far the sources have moved on. That is how a golden
/// here went on saying `simple-await.rs:65:21` long after the
/// acceptance suite, which does rebuild, had moved to `:67:21` — both
/// passing.
///
/// So the sources are hashed at capture and checked here. Nothing about
/// a stale pair is wrong, exactly; it is a real recording of a real
/// program. It is just no longer a recording of *this* one, which is
/// what reading these goldens assumes.
#[test]
fn test_fixtures_record_the_current_programs() {
    let manifest = fixture("SOURCES");
    let digests: String = PROGRAMS
        .iter()
        .map(|p| format!("{p} {}\n", source_digest(p)))
        .collect();

    if std::env::var_os("FIXTURE_SOURCES_BLESS").is_some() {
        std::fs::write(&manifest, &digests).expect("failed to write the source manifest");
        return;
    }

    let recorded = std::fs::read_to_string(&manifest).unwrap_or_default();
    assert_eq!(
        digests, recorded,
        "\nthe fixture programs have changed since these snapshots were captured, so \
         the goldens in this file describe a program that is no longer in the tree. \
         Recapture with test-programs/capture-snapshots.sh, then re-bless the \
         goldens here and in value_render.rs.\n"
    );
}

fn load(program: &str) -> (Bundle, Snapshot) {
    let bundle = Bundle::load(&fixture(&format!("{program}.bundle")))
        .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
    let snapshot = Snapshot::load(&fixture(&format!("{program}.snapshot")))
        .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
    (bundle, snapshot)
}

/// Mask the run-varying values the analysis output carries — heap
/// addresses and timer deadlines — so goldens compare exactly.
fn mask(s: &str) -> String {
    let addrs = regex::Regex::new(r"0x[0-9a-f]+").unwrap();
    let deadlines = regex::Regex::new(r"deadline \d+\.\d{3}s").unwrap();
    deadlines
        .replace_all(&addrs.replace_all(s, "0xADDR"), "deadline TS")
        .into_owned()
}

/// Run the full offline pipeline — fingerprint, discovery, enumeration,
/// stage decode, await chains, and the dependency analysis — and render
/// it as a golden-friendly summary.
fn interpret(bundle: &Bundle, snapshot: &Snapshot) -> String {
    let view = BundleView::new(bundle);
    let ctx = Context::new(snapshot, view).expect("snapshot has mappings");

    let mut out = String::new();
    let fp = ctx.validate_fingerprint();
    writeln!(out, "fingerprint {}/{}", fp.matched, fp.total).unwrap();

    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    writeln!(out, "workers {}", workers.len()).unwrap();

    let shared = ctx.find_shared(&workers).expect("a MultiThread runtime");
    let list = ctx.enumerate_tasks(&shared).expect("the owned-task walk");
    assert!(
        list.errors.is_empty(),
        "task walk reported errors: {:?}",
        list.errors
    );

    // The dependency analysis (§3.6/§10): wait targets come from it so
    // the per-task lines and the diagnoses agree by construction.
    let analysis = graph::analyze(&ctx, &list);
    assert!(
        analysis.errors.is_empty(),
        "graph analysis reported errors: {:?}",
        analysis.errors
    );

    for (task, wait) in list.tasks.iter().zip(&analysis.waits) {
        let id = task.task_id.expect("every fixture task has an id");
        let (future, defined) = match &task.future {
            FutureInfo::Known(known) => (
                known.display_name.as_str(),
                known
                    .decl
                    .as_ref()
                    .map(|(file, line)| format!("{file}:{line}"))
                    .unwrap_or_else(|| "-".into()),
            ),
            FutureInfo::Unknown { poll_symbol } => {
                panic!("unresolved future type (poll symbol {poll_symbol:?})")
            }
            FutureInfo::Ambiguous { symbol, candidates } => {
                panic!("ambiguous future type ({symbol}: {candidates:?})")
            }
        };
        let spawned = task
            .spawn_location
            .as_ref()
            .map(|loc| loc.to_string())
            .unwrap_or_else(|| "-".into());
        writeln!(
            out,
            "task {id} {} {future}\n  spawned {spawned}\n  defined {defined}",
            task.state.lifecycle()
        )
        .unwrap();

        match ctx.task_stage(task).expect("stage decodes") {
            TaskStage::Running(future) => {
                render_chain(&mut out, &ctx.await_chain(future));
                if let Some(target) = &wait.target {
                    writeln!(out, "  waiting on {}", mask(&target.to_string())).unwrap();
                }
            }
            TaskStage::Finished(_) => writeln!(out, "  finished").unwrap(),
            TaskStage::Consumed => writeln!(out, "  consumed").unwrap(),
        }
    }

    for fl in &analysis.futurelocks {
        let acq = &fl.acquire;
        let grant = if acq.granted() {
            "granted"
        } else {
            "queued for"
        };
        let owner = acq.owner.map(|o| format!("the {o} ")).unwrap_or_default();
        let loc = acq
            .await_loc
            .as_ref()
            .map(|(file, line)| format!(" @ {file}:{line}"))
            .unwrap_or_default();
        let blocked: Vec<String> = fl.blocked.iter().map(ToString::to_string).collect();
        writeln!(
            out,
            "futurelock: {} holds `{}` ({}), {grant} {} permit(s) of {}semaphore {}",
            fl.holder,
            acq.local,
            acq.future,
            acq.num_permits,
            owner,
            mask(&format!("{:#x}", acq.semaphore)),
        )
        .unwrap();
        writeln!(out, "  held across {} {}{loc}", acq.frame, acq.state).unwrap();
        writeln!(out, "  blocked: [{}]", blocked.join(", ")).unwrap();
    }
    out
}

fn render_chain(out: &mut String, chain: &AwaitChain<'_>) {
    for frame in &chain.frames {
        let dyn_marker = if frame.dyn_symbol.is_some() {
            " [dyn]"
        } else {
            ""
        };
        write!(out, "  await {}{dyn_marker}", frame.future.ty.name()).unwrap();
        let Some(state) = &frame.state else {
            writeln!(out).unwrap();
            continue;
        };
        write!(out, " {}", state.name).unwrap();
        if let Some((file, line)) = state.await_loc {
            write!(out, " @ {file}:{line}").unwrap();
        }
        // The state's live locals: source-level names only, sliced the
        // way the display code does (positionally, deduplicated —
        // a coroutine may alias an upvar and a saved local).
        let mut seen = HashSet::new();
        let locals: Vec<&str> = state
            .payload
            .ty
            .members()
            .filter(|m| {
                m.ty().size() > 0
                    && !m.name().starts_with("__")
                    && seen.insert((m.name(), m.offset()))
            })
            .map(|m| m.name())
            .collect();
        if locals.is_empty() {
            writeln!(out).unwrap();
        } else {
            writeln!(out, " locals [{}]", locals.join(", ")).unwrap();
        }
    }
    match &chain.end {
        ChainEnd::Leaf => writeln!(out, "  end leaf").unwrap(),
        other => writeln!(out, "  end {other:?}").unwrap(),
    }
}

#[track_caller]
fn assert_summary(program: &str, expected: &str) {
    let (bundle, snapshot) = load(program);
    let actual = interpret(&bundle, &snapshot);
    assert_eq!(
        actual.trim(),
        expected.trim(),
        "\n== summary for {program} ==\n{actual}"
    );
}

/// One spawned async fn parked on a leaked oneshot: the baseline
/// discovery → enumeration → chain flow, with the known locals live at
/// the second await point.
#[test]
fn test_simple_await_offline() {
    assert_summary(
        "simple-await",
        r#"
fingerprint 3/3
workers 3
task 3 idle simple_await::work::{async_fn_env#0}
  spawned test-programs/src/bin/simple-await.rs:67:21
  defined simple-await.rs:16
  await simple_await::work::{async_fn_env#0} Suspend1 @ simple-await.rs:34 locals [count, labels, values, boxed, slice, ipv4, ipv6, borrowed, owned, first, ready, park]
  await tokio::sync::oneshot::Receiver<u32>
  end leaf
"#,
    );
}

/// async fn awaiting async fn awaiting a leaf: the exact three-deep
/// chain, every await point mapped to its source line.
#[test]
fn test_nested_await_offline() {
    assert_summary(
        "nested-await",
        r#"
fingerprint 3/3
workers 3
task 3 idle nested_await::outer::{async_fn_env#0}
  spawned test-programs/src/bin/nested-await.rs:32:21
  defined nested-await.rs:16
  await nested_await::outer::{async_fn_env#0} Suspend0 @ nested-await.rs:18 locals [ready, park]
  await nested_await::middle::{async_fn_env#0} Suspend0 @ nested-await.rs:12 locals [park]
  await nested_await::leaf::{async_fn_env#0} Suspend0 @ nested-await.rs:8 locals [park]
  await tokio::sync::oneshot::Receiver<u32>
  end leaf
"#,
    );
}

/// A `Pin<Box<dyn Future>>` awaitee: the concrete type is reachable
/// only through the vtable in target memory joined against the
/// bundle's dyn-future table (the [dyn] frame). The JoinSet member is
/// its own task.
#[test]
fn test_dyn_future_offline() {
    assert_summary(
        "dyn-future",
        r#"
fingerprint 5/5
workers 3
task 3 idle dyn_future::driver::{async_fn_env#0}
  spawned test-programs/src/bin/dyn-future.rs:46:21
  defined dyn-future.rs:22
  await dyn_future::driver::{async_fn_env#0} Suspend0 @ dyn-future.rs:29 locals [set, ready, park_boxed, park_set]
  await dyn_future::boxed_leaf::{async_fn_env#0} [dyn] Suspend0 @ dyn-future.rs:11 locals [park]
  await tokio::sync::oneshot::Receiver<u32>
  end leaf
task 4 idle dyn_future::set_member::{async_fn_env#0}
  spawned test-programs/src/bin/dyn-future.rs:26:9
  defined dyn-future.rs:14
  await dyn_future::set_member::{async_fn_env#0} Suspend0 @ dyn-future.rs:15 locals [park]
  await tokio::sync::oneshot::Receiver<u32>
  end leaf
"#,
    );
}

/// The RFD 609 futurelock, fully automatically: do_stuff suspended in
/// the select! arm while still holding `future1` (visible in its
/// locals) and op2 blocked down the Mutex lock/acquire chain on the
/// semaphore leaf.
#[test]
fn test_futurelock_offline() {
    assert_summary(
        "futurelock",
        r#"
fingerprint 5/5
workers 5
task 5 idle futurelock::main::{async_block#0}::{async_block_env#0}
  spawned test-programs/src/bin/futurelock.rs:15:17
  defined futurelock.rs:15
  await futurelock::main::{async_block#0}::{async_block_env#0} Suspend1 @ futurelock.rs:25 locals [lock]
  await futurelock::do_stuff::{async_fn_env#0} Suspend1 @ futurelock.rs:64 locals [lock, future1, disabled]
  await futurelock::do_async_thing::{async_fn_env#0} Suspend0 @ futurelock.rs:72 locals [label, lock]
  await tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}<()> Suspend0 @ src/sync/mutex.rs:455 locals [self]
  await tokio::sync::mutex::{impl#10}::lock::{async_fn#0}::{async_block_env#0}<()> Suspend0 @ src/sync/mutex.rs:436 locals [_ref__self]
  await tokio::sync::mutex::{impl#10}::acquire::{async_fn_env#0}<()> Suspend1 @ src/sync/mutex.rs:658 locals [self]
  await tokio::sync::batch_semaphore::Acquire
  end leaf
  waiting on a tokio::sync::Mutex (semaphore 0xADDR): 1 permit requested, 0 available; wake queue: task 5
futurelock: task 5 holds `future1` (futurelock::do_async_thing::{async_fn_env#0}), granted 1 permit(s) of the tokio::sync::Mutex semaphore 0xADDR
  held across futurelock::do_stuff::{async_fn_env#0} Suspend1 @ futurelock.rs:64
  blocked: [task 5]
"#,
    );
}

/// The leaf-future wait targets and dependency edges, offline: the
/// sleeper reports its (masked) timer deadline, the joiner reports the
/// sleeper's id through its JoinHandle, and a healthy runtime yields
/// no futurelock diagnosis.
#[test]
fn test_sleep_join_offline() {
    assert_summary(
        "sleep-join",
        r#"
fingerprint 5/5
workers 3
task 3 idle sleep_join::sleeper::{async_fn_env#0}
  spawned test-programs/src/bin/sleep-join.rs:28:22
  defined sleep-join.rs:9
  await sleep_join::sleeper::{async_fn_env#0} Suspend0 @ sleep-join.rs:11 locals [ready]
  await tokio::time::sleep::Sleep
  end leaf
  waiting on the timer: deadline TS on the target's monotonic clock
task 4 idle sleep_join::joiner::{async_fn_env#0}
  spawned test-programs/src/bin/sleep-join.rs:29:23
  defined sleep-join.rs:15
  await sleep_join::joiner::{async_fn_env#0} Suspend0 @ sleep-join.rs:17 locals [ready, handle]
  await tokio::runtime::task::join::JoinHandle<u32>
  end leaf
  waiting on task 3 (JoinHandle)
"#,
    );
}

/// The wrong-bundle failure mode (§5.1, §11.5): a bundle from a
/// different program shares tokio-internal instantiations with the
/// target but misses its program-specific ones, so the fingerprint
/// lands strictly between zero and complete — and the default <100%
/// policy refuses it.
#[test]
fn test_mismatched_bundle_is_detected() {
    let (bundle, _) = load("futurelock");
    let (_, snapshot) = load("simple-await");
    let view = BundleView::new(&bundle);
    let ctx = Context::new(&snapshot, view).unwrap();

    let fp = ctx.validate_fingerprint();
    assert!(!fp.is_complete(), "wrong bundle must not fingerprint clean");
    assert!(
        fp.matched > 0,
        "programs share tokio-internal task instantiations"
    );
    assert!(fp.matched < fp.total, "{}/{}", fp.matched, fp.total);
}

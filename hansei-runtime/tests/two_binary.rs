// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Snapshot-based two-binary offline tests.
//!
//! Each fixture pair was produced by `test-programs/capture-snapshots.sh`:
//! the `.snapshot` is everything the analysis read from a live run of
//! one compilation (build A), and the `.bundle` was extracted from a
//! *separate* compilation of the same sources (build B). Joining B's
//! layouts against A's memory by mangled symbol name is the two-binary
//! constraint the whole design rests on, exercised here in plain
//! `cargo test` on any platform.
//!
//! The expected summaries are goldens: they change only when the
//! fixtures are regenerated (new sources, toolchain, or tokio), and a
//! diff here is reviewable line by line. `fingerprint N/N` counts the
//! symbols the *capturing* system's linker kept, so it is a property of
//! where the pair was made rather than of where the test runs — which
//! is why each system that can core a process keeps a set of its own
//! (`testkit::FIXTURE_SETS`) and a golden per set, suffixed with it — and
//! every set is read wherever these run, macOS included.
//!
//! Two things differ between the sets, and both are the capture's:
//! that fingerprint count, and how a timer deadline reads — illumos
//! lwps stamp a stop time so it is reported relative to it, a Linux
//! core records none so the absolute point on the monotonic clock is
//! printed instead. Holding a set per system is what got the second
//! spelling under an offline golden at all. Everything else — the
//! tasks found, the chains walked, the locals live at each await —
//! agrees across the sets, which is the point of holding both.
//!
//! What the pairs were captured from is recorded in
//! `fixtures/<set>/SOURCES.snap` and checked by
//! [`test_fixtures_record_the_current_programs`], since nothing else
//! here would notice the programs moving on without them.

use hansei_bundle::{Bundle, BundleView};
use hansei_runtime::testkit::{FIXTURE_SETS, load, load_any};
use hansei_runtime::tokio::Lifecycle;
use hansei_runtime::tokio::bundle::{
    AwaitChain, ChainEnd, Context, DiscoveryRoute, FutureInfo, RuntimeFlavor, Task, TaskStage,
    UnlistedTaskKind,
};
use hansei_runtime::tokio::{census, graph};
use proc::Target;
use proc::snapshot::Snapshot;

use std::collections::HashSet;
use std::fmt::Write;
use std::path::Path;

/// Every program `capture-snapshots.sh` captures a fixture pair for.
const PROGRAMS: &[&str] = &[
    "simple-await",
    "nested-await",
    "dyn-future",
    "futurelock",
    "sleep-join",
    "channels",
    "unordered",
    "joinset",
    "ct-runtime",
    "local-set",
    "local-set-timer",
    "local-set-io",
    "foreign-runtime",
];

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
    let digests: String = PROGRAMS
        .iter()
        .map(|p| format!("{p} {}\n", source_digest(p)))
        .collect();

    // Every set: each was captured on its own system, at its own time,
    // and a set left behind by an edit to the programs is as stale as
    // one captured before it, however recently the other was redone.
    for set in FIXTURE_SETS {
        let mut settings = insta::Settings::clone_current();
        // Beside the pairs it describes.
        settings.set_snapshot_path(Path::new("fixtures").join(set));
        settings.set_prepend_module_to_snapshot(false);
        settings.set_omit_expression(true);
        settings.set_description(
            "the fixture programs these snapshots were captured from. A digest that \
             moved means the goldens in this file describe a program no longer in the \
             tree: recapture with test-programs/capture-snapshots.sh, then re-bless the \
             goldens here and in value_render.rs.",
        );
        settings.bind(|| insta::assert_snapshot!("SOURCES", digests));
    }
}

/// Mask the run-varying values the analysis output carries — heap
/// addresses and timer deadlines (relative to the stop instant, so they
/// shift with how long the capture took) — so goldens compare exactly.
fn mask(s: &str) -> String {
    let addrs = regex::Regex::new(r"0x[0-9a-f]+").unwrap();
    let deadlines = regex::Regex::new(r"deadline -?\d+\.\d{3}s").unwrap();
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

    let runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");
    assert!(
        list.errors.is_empty(),
        "task walk reported errors: {:?}",
        list.errors
    );

    // The dependency analysis: wait targets come from it so
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

/// Diff a program's analysis against the golden for the set this build
/// reads.
///
/// One golden per set, not one for both: the summary opens with the
/// fingerprint the pair joined on, and how many `poll` symbols a
/// capture had to fingerprint against is the capturing system's — as
/// is the deadline spelling a timer leaf reports. See this file's
/// header for both.
#[track_caller]
fn assert_summary(program: &str) {
    for set in FIXTURE_SETS {
        let (bundle, snapshot) = load(set, program);
        let actual = interpret(&bundle, &snapshot);
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path("two_binary");
        settings.set_prepend_module_to_snapshot(false);
        settings.set_snapshot_suffix(*set);
        settings.set_omit_expression(true);
        settings.bind(|| insta::assert_snapshot!(program, actual.trim()));
    }
}

/// One spawned async fn parked on a leaked oneshot: the baseline
/// discovery → enumeration → chain flow, with the known locals live at
/// the second await point.
#[test]
fn test_simple_await_offline() {
    assert_summary("simple-await");
}

/// async fn awaiting async fn awaiting a leaf: the exact three-deep
/// chain, every await point mapped to its source line.
#[test]
fn test_nested_await_offline() {
    assert_summary("nested-await");
}

/// A `Pin<Box<dyn Future>>` awaitee: the concrete type is reachable
/// only through the vtable in target memory joined against the
/// bundle's dyn-future table (the [dyn] frame). The JoinSet member is
/// its own task.
#[test]
fn test_dyn_future_offline() {
    assert_summary("dyn-future");
}

/// The RFD 609 futurelock, fully automatically: do_stuff suspended in
/// the select! arm while still holding `future1` (visible in its
/// locals) and op2 blocked down the Mutex lock/acquire chain on the
/// semaphore leaf.
#[test]
fn test_futurelock_offline() {
    assert_summary("futurelock");
}

/// The leaf-future wait targets and dependency edges, offline: the
/// sleeper reports its (masked) timer deadline, the joiner reports the
/// sleeper's id through its JoinHandle, and a healthy runtime yields
/// no futurelock diagnosis.
#[test]
fn test_sleep_join_offline() {
    assert_summary("sleep-join");
}

/// The future census, offline: the futurelock fixture's `future1` — a
/// dyn-boxed lock future held across `do_stuff`'s suspension, the very
/// future the futurelock diagnosis is about — is found as a held
/// future, dyn-resolved to its concrete type, with the contended Mutex
/// it waits on.
#[test]
fn test_futurelock_census_offline() {
    let (bundle, snapshot) = load_any("futurelock");
    let ctx = hansei_runtime::testkit::context(&bundle, &snapshot);
    let list = hansei_runtime::testkit::tasks(&ctx, &snapshot);

    let census = census::census(&ctx, &list);
    let future1 = census
        .held
        .iter()
        .find(|h| h.local == "future1")
        .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));
    assert!(
        future1
            .future
            .contains("futurelock::do_async_thing::{async_fn_env#0}"),
        "{future1:#?}"
    );
    assert_eq!(list.tasks[future1.owner].task_id, Some(5), "{future1:#?}");
    assert!(
        future1
            .waiting_on
            .as_deref()
            .unwrap_or_default()
            .contains("tokio::sync::Mutex"),
        "{future1:#?}"
    );

    // The recorded root re-roots the future: reading it back by
    // (addr, ty) and chaining again reproduces the identity the census
    // summarized — the contract tracing a future by address rests on.
    let ty = ctx
        .view
        .ty(future1.ty)
        .expect("the root type is in the bundle");
    let root =
        reify::Value::read(ctx.proc, ty, future1.addr).expect("the recorded root reads back");
    let chain = ctx.await_chain(root);
    let first = chain.frames.first().expect("the re-rooted chain decodes");
    assert_eq!(first.future.ty.name(), future1.future, "{future1:#?}");
}

/// A `FuturesUnordered` is a sub-executor the task listing never
/// shows: the driver's chain ends at the set itself, and its children
/// are the census's business (below).
#[test]
fn test_unordered_offline() {
    assert_summary("unordered");
}

/// A `JoinSet`'s members are real tasks: each is its own listing entry
/// parked in the shared `Notify`, while the driver parks in
/// `join_next` over the `IdleNotifiedSet`.
#[test]
fn test_joinset_offline() {
    assert_summary("joinset");
}

/// The resolved future name of a task the fixtures guarantee decodes.
fn known_name(task: &Task) -> &str {
    match &task.future {
        FutureInfo::Known(known) => known.display_name.as_str(),
        other => panic!("unresolved future: {other:?}"),
    }
}

/// The whole pipeline up to the census, shared by the census tests.
fn census_of<'a>(
    bundle: &'a Bundle,
    snapshot: &'a Snapshot,
) -> (
    Context<'a, Snapshot>,
    hansei_runtime::tokio::bundle::TaskList,
    census::FutureCensus,
) {
    let ctx = hansei_runtime::testkit::context(bundle, snapshot);
    let list = hansei_runtime::testkit::tasks(&ctx, snapshot);
    let census = census::census(&ctx, &list);
    assert!(census.errors.is_empty(), "{:?}", census.errors);
    assert_eq!(census.capped, 0, "the walk hit a hard limit");
    (ctx, list, census)
}

/// The `FuturesUnordered` census, offline: the intrusive
/// `head_all` → `next_all` node walk finds all three children with
/// their suspend states and `Notified` leaves, and the two futures the
/// driver merely holds — one bare, one dyn-boxed — are found beside
/// it, never yet polled.
///
/// And the scan's recursion, which no other pair exercises: a future
/// reached only by descending into a tuple, one reached only through
/// an enum's active variant, and — a hop out from the driver's own
/// frames — the future and the set that each child of the set holds,
/// each attributed to the child it was found under.
#[test]
fn test_unordered_census_offline() {
    let (bundle, snapshot) = load_any("unordered");
    let (ctx, list, census) = census_of(&bundle, &snapshot);

    let (set, inner) = match census.sets.as_slice() {
        [set, inner] => (set, inner),
        other => panic!("expected two sets, got {other:#?}"),
    };
    assert_eq!(set.local, "set");
    assert!(
        known_name(&list.tasks[set.owner]).contains("unordered::driver"),
        "{:?}",
        list.tasks[set.owner].future
    );
    assert!(set.ty.starts_with(
        "futures_util::stream::futures_unordered::FuturesUnordered<\
         unordered::set_member::{async_fn_env#0}>"
    ));

    assert_eq!(set.children.len(), 3, "{:#?}", set.children);
    for child in &set.children {
        assert_eq!(
            child.future.as_deref(),
            Some("unordered::set_member::{async_fn_env#0}"),
            "{child:#?}"
        );
        assert!(
            child
                .state
                .as_deref()
                .unwrap_or_default()
                .contains("Suspend0"),
            "{child:#?}"
        );
        assert_eq!(
            child.leaf.as_deref(),
            Some("tokio::sync::notify::Notified"),
            "{child:#?}"
        );
    }

    // A child's recorded root re-roots it: reading it back by
    // (addr, ty) and chaining again reproduces the identity the census
    // summarized — what tracing a child node by address rests on.
    let root = set.children[0].root.as_ref().expect("a decoded child");
    let ty = ctx
        .view
        .ty(root.ty)
        .expect("the root type is in the bundle");
    let future = reify::Value::read(ctx.proc, ty, root.addr).expect("the recorded root reads back");
    let chain = ctx.await_chain(future);
    assert_eq!(
        chain
            .frames
            .first()
            .expect("the re-rooted chain decodes")
            .future
            .ty
            .name(),
        "unordered::set_member::{async_fn_env#0}"
    );

    // What the driver holds in its own frame: a bare coroutine and a
    // dyn-boxed one, plus the two the scan sees only by descending —
    // one inside a tuple, one inside an enum's active variant. All four
    // are `Unresumed`, and all four are the driver's own.
    let mut own: Vec<(&str, &str)> = census
        .held
        .iter()
        .filter(|held| held.via.is_none())
        .map(|held| (held.local.as_str(), held.future.as_str()))
        .collect();
    own.sort_unstable();
    assert_eq!(
        own,
        [
            ("boxed", "unordered::set_member::{async_fn_env#0}"),
            ("held", "unordered::set_member::{async_fn_env#0}"),
            ("maybe", "unordered::leaf::{async_fn_env#0}"),
            ("pair", "unordered::leaf::{async_fn_env#0}"),
        ],
        "{:#?}",
        census.held
    );
    for held in &census.held {
        assert!(
            held.state
                .as_deref()
                .unwrap_or_default()
                .contains("Unresumed"),
            "{held:#?}"
        );
        assert_eq!(list.tasks[held.owner].task_id, Some(3), "{held:#?}");
    }

    // A hop further out: each child holds a future of its own, found
    // only because the census scans the frames of what it finds, and
    // attributed to the child it was found under rather than to the
    // task. One per child, no two under the same one.
    let mut under: Vec<String> = census
        .held
        .iter()
        .filter_map(|held| {
            let via = held.via?;
            assert_eq!(held.local, "held", "{held:#?}");
            assert_eq!(
                held.future, "unordered::leaf::{async_fn_env#0}",
                "{held:#?}"
            );
            Some(census.describe(via))
        })
        .collect();
    under.sort();
    let mut nodes: Vec<String> = set
        .children
        .iter()
        .map(|child| format!("set child at {:#x}", child.node))
        .collect();
    nodes.sort();
    assert_eq!(under, nodes, "{:#?}", census.held);

    // One child holds a whole set of its own, so a find of a find is a
    // set too: its children are futures nobody has polled, and it is
    // attributed to the child whose frames it was found in. The outer
    // set keeps the index it reserved before descending into its
    // children — had it not, this `via` would name the nested set
    // itself rather than the one holding it.
    assert_eq!(inner.local, "inner");
    let via = inner
        .via
        .expect("the nested set was reached through a child");
    let census::Via::SetChild { set: parent, child } = via else {
        panic!("expected a set child, got {via:?}");
    };
    assert_eq!(parent, 0, "{inner:#?}");
    assert_eq!(
        census.describe(via),
        format!("set child at {:#x}", set.children[child].node)
    );
    assert_eq!(inner.children.len(), 2, "{:#?}", inner.children);
    for child in &inner.children {
        assert_eq!(
            child.future.as_deref(),
            Some("unordered::leaf::{async_fn_env#0}"),
            "{child:#?}"
        );
        assert!(
            child
                .state
                .as_deref()
                .unwrap_or_default()
                .contains("Unresumed"),
            "{child:#?}"
        );
    }
}

/// The `JoinSet` census, offline: the `IdleNotifiedSet`'s two lists
/// walked entry by entry, every member resolved to a task the listing
/// also shows — by id, parked, join-interested.
///
/// Except one. The second set is never joined, so the member that ran
/// to completion is still in it: a task the runtime no longer owns and
/// no listing carries, which only this entry names. That is what
/// `listed` is for, and the only state a set can hold that nothing
/// else in a listing corroborates.
#[test]
fn test_joinset_census_offline() {
    let (bundle, snapshot) = load_any("joinset");
    let (_ctx, list, census) = census_of(&bundle, &snapshot);

    assert!(census.sets.is_empty(), "{:#?}", census.sets);
    assert!(census.held.is_empty(), "{:#?}", census.held);

    let (set, kept) = match census.join_sets.as_slice() {
        [set, kept] => (set, kept),
        other => panic!("expected two join sets, got {other:#?}"),
    };
    assert_eq!(set.local, "set");
    assert_eq!(kept.local, "kept");
    for join_set in [set, kept] {
        assert_eq!(join_set.ty, "tokio::task::join_set::JoinSet<u32>");
        assert!(
            known_name(&list.tasks[join_set.owner]).contains("joinset::driver"),
            "{:?}",
            list.tasks[join_set.owner].future
        );
        // The set's own length word and what the walk found agree.
        assert_eq!(join_set.length, 3, "{join_set:#?}");
        assert_eq!(join_set.children.len(), 3, "{:#?}", join_set.children);
    }

    let mut ids: Vec<u64> = set
        .children
        .iter()
        .map(|c| c.id.expect("every member has an id"))
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, [4, 5, 6], "{:#?}", set.children);
    for child in &set.children {
        assert_eq!(child.state.lifecycle(), Lifecycle::Idle, "{child:#?}");
        // `listed`: the member is a task the plain listing also shows.
        assert!(child.listed, "{child:#?}");
        assert!(
            list.tasks.iter().any(|t| t.addr.0 == child.task),
            "{child:#?}"
        );
    }

    // The set nobody joined: two members parked like the others, and
    // one complete — off the runtime's owned list, so the listing has
    // no row for it, and the walk reaches it only through the entry.
    let (complete, parked): (Vec<_>, Vec<_>) =
        kept.children.iter().partition(|child| !child.listed);
    let [done] = complete.as_slice() else {
        panic!("expected one unlisted member, got {complete:#?}");
    };
    assert_eq!(done.state.lifecycle(), Lifecycle::Complete, "{done:#?}");
    assert!(
        !list.tasks.iter().any(|t| t.addr.0 == done.task),
        "{done:#?}"
    );
    for child in parked {
        assert_eq!(child.state.lifecycle(), Lifecycle::Idle, "{child:#?}");
        assert!(
            list.tasks.iter().any(|t| t.addr.0 == child.task),
            "{child:#?}"
        );
    }
}

/// The current_thread pair: discovery lands on the CT flavor's chain,
/// and everything downstream — enumeration, the stage decode, await
/// chains, the timer and semaphore leaf readers — runs unchanged, since
/// the task subsystem is shared between flavors.
///
/// Property assertions rather than an exact summary: the shapes worth
/// pinning (the flavor, the leaves) hold across recaptures without
/// re-quoting line numbers.
#[test]
fn test_ct_runtime_offline() {
    let (bundle, snapshot) = load_any("ct-runtime");
    let ctx = hansei_runtime::testkit::context(&bundle, &snapshot);

    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let [runtime] = runtimes.as_slice() else {
        panic!("expected one runtime, got {}", runtimes.len());
    };
    assert_eq!(runtime.flavor, RuntimeFlavor::CurrentThread);
    assert!(!runtime.worker_tids.is_empty());

    let list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");
    assert!(list.errors.is_empty(), "{:?}", list.errors);

    let analysis = graph::analyze(&ctx, &list);
    assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);

    // The two spawned tasks parked at their leaves, decoded through the
    // same leaf readers the multi_thread fixtures exercise.
    let mut leaves = Vec::new();
    for (task, wait) in list.tasks.iter().zip(&analysis.waits) {
        let name = known_name(task);
        if !name.starts_with("ct_runtime::") {
            continue;
        }
        let target = wait
            .target
            .as_ref()
            .unwrap_or_else(|| panic!("{name} decodes no wait target"));
        leaves.push((name.to_owned(), mask(&target.to_string())));
    }
    leaves.sort_unstable();
    let [(acquirer, acquirer_wait), (sleeper, sleeper_wait)] = leaves.as_slice() else {
        panic!("expected the two fixture tasks, got {leaves:#?}");
    };
    assert!(acquirer.contains("acquirer"), "{leaves:#?}");
    assert!(
        acquirer_wait.contains("semaphore") && acquirer_wait.contains("1 permit requested"),
        "{leaves:#?}"
    );
    assert!(sleeper.contains("sleeper"), "{leaves:#?}");
    assert!(sleeper_wait.contains("the timer"), "{leaves:#?}");
}

/// The `LocalSet` pair: tasks bound into a set's own list are found and
/// enumerated offline, from a snapshot of a parked target — the whole
/// discovery chain, replayed on any platform.
///
/// The set is reached by the cell bootstrap alone: nothing polls it in
/// a parked core, so the TLS anchor reads empty and the only evidence
/// is the scheduler task's `JoinHandle` on one of its members. One
/// member redeems the set, which is what makes the *other* local task —
/// externally invisible, parked on a semaphore nobody else holds —
/// listed at all.
///
/// Property assertions rather than an exact summary, like the
/// current_thread pair: what is worth pinning is the shapes, which hold
/// across recaptures without re-quoting addresses.
#[test]
fn test_local_set_offline() {
    let (bundle, snapshot) = load_any("local-set");
    let ctx = hansei_runtime::testkit::context(&bundle, &snapshot);

    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let mut runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let mut list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");

    // Before discovery the scheduler owns one task, and the one it
    // joins is not in any list this session can show.
    assert_eq!(list.tasks.len(), 1, "{:#?}", list.tasks);
    let joiner = list.tasks[0].addr;
    let joined = match graph::analyze(&ctx, &list).waits[0].target.clone() {
        Some(hansei_runtime::tokio::bundle::WaitTarget::Task {
            addr, listed, kind, ..
        }) => {
            assert!(!listed, "the local task must not be listed yet");
            // Classified from the cell's recorded scheduler type, not
            // guessed: this is a local task, definitely.
            assert_eq!(kind, Some(UnlistedTaskKind::LocalSet));
            addr
        }
        other => panic!("the joiner does not await a task: {other:?}"),
    };

    // Discovery finds the set through that one handle, and both its
    // tasks — the joined one and its invisible sibling — join the
    // population, stamped with the set's own group.
    let sets = ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[], &mut list);
    assert!(list.errors.is_empty(), "{:?}", list.errors);
    let [set] = sets.as_slice() else {
        panic!("expected one local set, got {}", sets.len());
    };
    assert_eq!(set.route, DiscoveryRoute::JoinHandle);
    assert_ne!(set.owned_id, 0);

    assert_eq!(list.tasks.len(), 3, "{:#?}", list.tasks);
    let group = runtimes.len();
    let local: Vec<&Task> = list.tasks.iter().filter(|t| t.group == group).collect();
    assert_eq!(local.len(), 2, "{local:#?}");
    // Every member carries the set's owned-list id — the cross-check
    // that says the set claims them — and the scheduler task keeps its
    // runtime's group.
    for task in &local {
        assert_eq!(task.owner_id, Some(set.owned_id), "{task:#?}");
        assert!(
            known_name(task).starts_with("local_set::local_"),
            "{task:#?}"
        );
    }
    assert!(local.iter().any(|t| t.addr.0 == joined), "{local:#?}");
    assert_eq!(
        list.tasks.iter().filter(|t| t.addr == joiner).count(),
        1,
        "the scheduler's own task is not duplicated"
    );

    // And the local tasks read like any other: both leaves decode
    // through the readers the scheduler-owned fixtures exercise.
    let analysis = graph::analyze(&ctx, &list);
    assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);
    let mut leaves: Vec<String> = list
        .tasks
        .iter()
        .zip(&analysis.waits)
        .filter(|(task, _)| task.group == group)
        .map(|(task, wait)| {
            let target = wait
                .target
                .as_ref()
                .unwrap_or_else(|| panic!("{} decodes no wait target", known_name(task)));
            mask(&target.to_string())
        })
        .collect();
    leaves.sort_unstable();
    let [semaphore, timer] = leaves.as_slice() else {
        panic!("expected the set's two leaves, got {leaves:#?}");
    };
    assert!(
        semaphore.contains("semaphore") && semaphore.contains("1 permit requested"),
        "{leaves:#?}"
    );
    assert!(timer.contains("the timer"), "{leaves:#?}");

    // The joined task is now simply listed — the third `listed: false`
    // case the plan called for, closed by discovery rather than worded.
    let rejoined = graph::analyze(&ctx, &list);
    let joiner_wait = rejoined
        .waits
        .iter()
        .find(|wait| wait.task.addr == joiner)
        .expect("the joiner is still in the population");
    match &joiner_wait.target {
        Some(hansei_runtime::tokio::bundle::WaitTarget::Task { listed, .. }) => {
            assert!(listed, "the joined local task is listed after discovery");
        }
        other => panic!("the joiner does not await a task: {other:?}"),
    }
}

/// The wheel harvest: a `LocalSet` nothing points at, found through the
/// timer its sleeper parked in the runtime's own wheel.
///
/// This is the case route 1 provably cannot reach. Both handles were
/// dropped when the set's tasks were spawned, the semaphore the second
/// one waits on is nobody else's, and a parked core reads the TLS
/// anchor empty — so the cell bootstrap sweeps every enumerated chain
/// and comes back with nothing. The set is redeemed by a member the
/// wheel names, and its externally invisible sibling comes with it.
#[test]
fn test_local_set_timer_offline() {
    let (bundle, snapshot) = load_any("local-set-timer");
    let ctx = hansei_runtime::testkit::context(&bundle, &snapshot);

    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let mut runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let mut list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");

    // Before discovery: the scheduler owns one task, and it points at
    // nothing outside its own list — it is parked on a timer of its
    // own, which is what makes the wheel the only way in.
    assert_eq!(list.tasks.len(), 1, "{:#?}", list.tasks);
    let scheduler_task = list.tasks[0].addr;
    match graph::analyze(&ctx, &list).waits[0].target.clone() {
        Some(hansei_runtime::tokio::bundle::WaitTarget::Timer { .. }) => {}
        other => panic!("the spawned task does not await a timer: {other:?}"),
    }

    let sets = ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[], &mut list);
    assert!(list.errors.is_empty(), "{:?}", list.errors);
    let [set] = sets.as_slice() else {
        panic!("expected one local set, got {}", sets.len());
    };
    assert_eq!(set.route, DiscoveryRoute::Wheel);
    assert_ne!(set.owned_id, 0);

    // Both members join the population under the set's group, the
    // scheduler's own task keeps its runtime's, and the harvest did not
    // take the listed task its own wheel entry names.
    assert_eq!(list.tasks.len(), 3, "{:#?}", list.tasks);
    let group = runtimes.len();
    let local: Vec<&Task> = list.tasks.iter().filter(|t| t.group == group).collect();
    assert_eq!(local.len(), 2, "{local:#?}");
    for task in &local {
        assert_eq!(task.owner_id, Some(set.owned_id), "{task:#?}");
        assert!(
            known_name(task).starts_with("local_set_timer::local_"),
            "{task:#?}"
        );
    }
    assert_eq!(
        list.tasks
            .iter()
            .filter(|t| t.addr == scheduler_task)
            .count(),
        1,
        "the scheduler's own task is not duplicated"
    );

    // Both members read like any listed task, including the one the
    // wheel never named: nothing outside the set points at the
    // semaphore waiter, and it is listed all the same.
    let analysis = graph::analyze(&ctx, &list);
    assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);
    let mut leaves: Vec<String> = list
        .tasks
        .iter()
        .zip(&analysis.waits)
        .filter(|(task, _)| task.group == group)
        .map(|(task, wait)| {
            let target = wait
                .target
                .as_ref()
                .unwrap_or_else(|| panic!("{} decodes no wait target", known_name(task)));
            mask(&target.to_string())
        })
        .collect();
    leaves.sort_unstable();
    let [semaphore, timer] = leaves.as_slice() else {
        panic!("expected the set's two leaves, got {leaves:#?}");
    };
    assert!(semaphore.contains("semaphore"), "{leaves:#?}");
    assert!(timer.contains("the timer"), "{leaves:#?}");
}

/// The io harvest: a `LocalSet` nothing points at, found through the
/// sockets its members are parked on.
///
/// Every cheaper route provably comes up empty here. Both the cell
/// bootstrap and the TLS probe are in the position the wheel fixture
/// put them in — handles dropped at spawn, nothing outside the set
/// waiting on anything its members hold, a parked core reading the
/// anchor empty — and the wheel joins them, because nothing in this
/// program parks on time at all. What redeems the set is the io
/// driver's registration list, and the whole set comes with the first
/// member it names.
#[test]
fn test_local_set_io_offline() {
    let (bundle, snapshot) = load_any("local-set-io");
    let ctx = hansei_runtime::testkit::context(&bundle, &snapshot);

    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let mut runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let mut list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");

    // Before discovery: the scheduler owns one task, parked on a socket
    // of its own — so its own waker sits on a registration the harvest
    // walks, and being listed is what keeps it out of the candidates.
    assert_eq!(list.tasks.len(), 1, "{:#?}", list.tasks);
    let scheduler_task = list.tasks[0].addr;

    // A resource holds wakers in three places, and this program has one
    // member parked in each. All three are candidates: a harvest that
    // walked only the waiter list, or only one direction slot, would
    // still find the set — and would yield fewer here.
    let candidates = hansei_runtime::testkit::io_candidates(&ctx, &snapshot);
    assert_eq!(candidates.len(), 3, "{candidates:#x?}");
    assert!(
        !candidates.contains(&scheduler_task.0),
        "the listed task's own registration is not a candidate: {candidates:#x?}"
    );

    let sets = ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[], &mut list);
    assert!(list.errors.is_empty(), "{:?}", list.errors);
    let [set] = sets.as_slice() else {
        panic!("expected one local set, got {}", sets.len());
    };
    assert_eq!(set.route, DiscoveryRoute::Io);
    assert_ne!(set.owned_id, 0);

    // All three members join the population under the set's group, and
    // they are exactly the three the harvest named.
    assert_eq!(list.tasks.len(), 4, "{:#?}", list.tasks);
    let group = runtimes.len();
    let local: Vec<&Task> = list.tasks.iter().filter(|t| t.group == group).collect();
    assert_eq!(local.len(), 3, "{local:#?}");
    let mut names: Vec<&str> = local.iter().map(|t| known_name(t)).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "local_set_io::local_reader::{async_fn_env#0}",
            "local_set_io::local_watcher::{async_fn_env#0}",
            "local_set_io::local_writer::{async_fn_env#0}",
        ],
        "{local:#?}"
    );
    for task in &local {
        assert_eq!(task.owner_id, Some(set.owned_id), "{task:#?}");
    }
    let members: HashSet<u64> = local.iter().map(|t| t.addr.0).collect();
    assert_eq!(
        candidates.iter().copied().collect::<HashSet<u64>>(),
        members,
        "every candidate is one of the set's members"
    );
    assert_eq!(
        list.tasks
            .iter()
            .filter(|t| t.addr == scheduler_task)
            .count(),
        1,
        "the scheduler's own task is not duplicated"
    );
}

/// A runtime no thread's `Context` reaches, and the set inside it.
///
/// The hidden runtime's `block_on` has returned, so TLS-anchored
/// discovery finds only the main one and everything the hidden one owns
/// is unlisted. One `JoinHandle`, held by the main runtime's own task,
/// is the entire way in — and what it names is a task, not a runtime,
/// so the runtime is reached through that task's own cell. Admitting it
/// is what puts its drivers in reach, and the set's one member is
/// parked on a timer in *that* runtime's wheel: it is found by no
/// earlier route, and would be found by none at all had the runtime
/// stayed hidden.
#[test]
fn test_foreign_runtime_offline() {
    let (bundle, snapshot) = load_any("foreign-runtime");
    let ctx = hansei_runtime::testkit::context(&bundle, &snapshot);

    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let mut runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let mut list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");

    // Before discovery: one runtime, one task — the joiner — and the
    // task it awaits is in no list, classified from its cell as a task
    // of a runtime this session has not reached.
    assert_eq!(runtimes.len(), 1, "{runtimes:#?}");
    assert_eq!(list.tasks.len(), 1, "{:#?}", list.tasks);
    let joiner = list.tasks[0].addr;
    let joined = match graph::analyze(&ctx, &list).waits[0].target.clone() {
        Some(hansei_runtime::tokio::bundle::WaitTarget::Task {
            addr, listed, kind, ..
        }) => {
            assert!(!listed, "the hidden runtime's task must not be listed yet");
            assert_eq!(
                kind,
                Some(UnlistedTaskKind::OtherRuntime(RuntimeFlavor::CurrentThread))
            );
            addr
        }
        other => panic!("the joiner does not await a task: {other:?}"),
    };

    let sets = ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[], &mut list);
    assert!(list.errors.is_empty(), "{:?}", list.errors);

    // The runtime joins the session's list with no thread inside it,
    // and the route that found it recorded.
    let [_main, hidden] = runtimes.as_slice() else {
        panic!("expected two runtimes, got {}", runtimes.len());
    };
    assert_eq!(hidden.route, DiscoveryRoute::JoinHandle);
    assert!(hidden.worker_tids.is_empty(), "{hidden:#?}");

    // Both of its tasks are enumerated under its group — the one the
    // joiner named, and the one nothing outside its list points at.
    assert_eq!(list.tasks.len(), 4, "{:#?}", list.tasks);
    let mut hidden_tasks: Vec<&Task> = list.tasks.iter().filter(|t| t.group == 1).collect();
    hidden_tasks.sort_by_key(|t| known_name(t));
    let names: Vec<&str> = hidden_tasks.iter().map(|t| known_name(t)).collect();
    assert_eq!(
        names,
        [
            "foreign_runtime::detached::{async_fn_env#0}",
            "foreign_runtime::joined::{async_fn_env#0}",
        ],
        "{hidden_tasks:#?}"
    );
    assert!(
        hidden_tasks.iter().any(|t| t.addr.0 == joined),
        "{hidden_tasks:#?}"
    );

    // And the set, which only the hidden runtime's own wheel names.
    let [set] = sets.as_slice() else {
        panic!("expected one local set, got {}", sets.len());
    };
    assert_eq!(set.route, DiscoveryRoute::Wheel);
    let group = runtimes.len();
    let local: Vec<&Task> = list.tasks.iter().filter(|t| t.group == group).collect();
    let [member] = local.as_slice() else {
        panic!("expected the set's one member, got {local:#?}");
    };
    assert_eq!(
        known_name(member),
        "foreign_runtime::local_sleeper::{async_fn_env#0}"
    );
    assert_eq!(member.owner_id, Some(set.owned_id), "{member:#?}");

    // The join edge resolves now: its target is one of the enumerated
    // tasks rather than something the session cannot name.
    assert_eq!(
        list.tasks.iter().filter(|t| t.addr == joiner).count(),
        1,
        "the main runtime's own task is not duplicated"
    );
    let analysis = graph::analyze(&ctx, &list);
    assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);
    let joiner_wait = list
        .tasks
        .iter()
        .zip(&analysis.waits)
        .find(|(t, _)| t.addr == joiner)
        .map(|(_, wait)| wait)
        .expect("the joiner is still in the population");
    match joiner_wait.target.as_ref() {
        Some(hansei_runtime::tokio::bundle::WaitTarget::Task { listed, .. }) => {
            assert!(listed, "the joined task is listed now: {joiner_wait:?}");
        }
        other => panic!("the joiner does not await a task: {other:?}"),
    }
}

/// A `--runtime` selection is a filter, so what it leaves out must not
/// come back through the cell bootstrap: the excluded handle is handed
/// to discovery, which declines to admit it.
#[test]
fn test_excluded_runtime_stays_excluded() {
    let (bundle, snapshot) = load_any("foreign-runtime");
    let ctx = hansei_runtime::testkit::context(&bundle, &snapshot);

    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let mut runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let mut list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");

    // Discovery once, to learn the hidden runtime's handle.
    let (probed, _, _) = hansei_runtime::testkit::discover(&ctx, &snapshot);
    let hidden = probed[1].handle.addr;

    // Again with that handle excluded, as a `--runtime` selection
    // would: nothing is admitted, and the set inside it stays out of
    // reach too, since only that runtime's own wheel names it.
    let sets = ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[hidden], &mut list);
    assert_eq!(runtimes.len(), 1, "{runtimes:#?}");
    assert_eq!(list.tasks.len(), 1, "{:#?}", list.tasks);
    assert!(sets.is_empty(), "{sets:#?}");
    assert!(list.errors.is_empty(), "{:?}", list.errors);
}

/// The wrong-bundle failure mode: a bundle from a
/// different program shares tokio-internal instantiations with the
/// target but misses its program-specific ones, so the fingerprint
/// lands strictly between zero and complete — and the default <100%
/// policy refuses it.
#[test]
fn test_mismatched_bundle_is_detected() {
    let (bundle, _) = load_any("futurelock");
    let (_, snapshot) = load_any("simple-await");
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

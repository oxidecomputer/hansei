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
//! Two things differ between the per-system sets, and both are the
//! capture's: that fingerprint count, and how a timer deadline reads —
//! illumos lwps stamp a stop time so it is reported relative to it, a
//! Linux core records none so the absolute point on the monotonic
//! clock is printed instead. Holding a set per system is what got the
//! second spelling under an offline golden at all. Everything else —
//! the tasks found, the chains walked, the locals live at each await —
//! agrees across the sets, which is the point of holding both. The
//! `linux-floor` set differs on the other axis instead: the same
//! fixtures built against `matrix.toml`'s tokio floor, so the walks
//! *execute* against the oldest supported release's memory rather than
//! only binding to its layouts in the matrix.
//!
//! What the pairs were captured from is recorded in
//! `fixtures/<set>/SOURCES.snap` and checked by
//! [`test_fixtures_record_the_current_programs`], since nothing else
//! here would notice the programs moving on without them.

use hansei_bundle::{Bundle, BundleView};
use hansei_runtime::testkit::{FIXTURE_SETS, load, load_any, matrix};
use hansei_runtime::tokio::Lifecycle;
use hansei_runtime::tokio::bundle::{
    AwaitChain, ChainEnd, Context, DiscoveryRoute, FutureInfo, RuntimeFlavor, Task, TaskStage,
    UnlistedTaskKind,
};
use hansei_runtime::tokio::{census, graph};
use proc::Target;
use proc::snapshot::Snapshot;

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write;
use std::path::Path;

/// Every program `capture-snapshots.sh` captures a fixture pair for.
/// `gen-0007` is quarantined generated output (see its header): it is
/// in this suite and the capture loop only, not the golden, matrix, or
/// acceptance lists.
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
    "gen-0007",
];

/// What a fixture pair was captured from: the program's own source, and
/// the crate every program calls into before it parks.
fn source_digest(program: &str) -> String {
    let src = test_programs_dir().join("src");
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

fn test_programs_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate is in a workspace")
        .join("test-programs")
}

/// Which lockfile a set's pairs are built from — the other half of what
/// a pair was captured from, since two builds of identical sources
/// against different lockfiles are different programs. The version
/// endpoint set (`<os>-floor`) pins tokio at `matrix.toml`'s floor;
/// every other set is the primary `Cargo.lock`.
fn lockfile_of(set: &str) -> String {
    if set.ends_with("-floor") {
        format!("locks/tokio-{}.lock", matrix::floor())
    } else {
        "Cargo.lock".to_owned()
    }
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
    let sources: String = PROGRAMS
        .iter()
        .map(|p| format!("{p} {}\n", source_digest(p)))
        .collect();

    // Every set: each was captured on its own system, at its own time,
    // and a set left behind by an edit to the programs is as stale as
    // one captured before it, however recently the other was redone.
    for set in FIXTURE_SETS {
        // The lockfile is per set — the floor set exists to build the
        // same sources against a different tokio — so its record is
        // too, a header line above the per-program digests.
        let lock = lockfile_of(set);
        let lock_path = test_programs_dir().join(&lock);
        let lock_bytes = std::fs::read(&lock_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", lock_path.display()));
        let digests = format!(
            "lock {lock} {}\n{sources}",
            &blake3::hash(&lock_bytes).to_hex()[..32]
        );
        let mut settings = insta::Settings::clone_current();
        // Beside the pairs it describes.
        settings.set_snapshot_path(Path::new("fixtures").join(set));
        settings.set_prepend_module_to_snapshot(false);
        settings.set_omit_expression(true);
        // Name the exact recapture command, because it is per set: the
        // floor set needs the --tokio pin, and the mismatch this test
        // reports is how a floor advance learns the set went stale.
        let recapture = if set.ends_with("-floor") {
            format!(
                "test-programs/capture-snapshots.sh --tokio {}",
                matrix::floor()
            )
        } else {
            "test-programs/capture-snapshots.sh".to_owned()
        };
        settings.set_description(format!(
            "the fixture programs (and lockfile) these snapshots were captured from. \
             A digest that moved means the goldens in this file describe a program no \
             longer in the tree: recapture with {recapture}, then re-bless the goldens \
             here and in value_render.rs."
        ));
        settings.bind(|| insta::assert_snapshot!("SOURCES", digests));
    }
}

/// The other half of the inventory: every pair on disk is one the
/// suite reads.
///
/// A program in [`PROGRAMS`] with no pair already fails loudly — the
/// first `load` panics. The reverse is silent: a program added to
/// `capture-snapshots.sh` but forgotten here leaves its pair sitting
/// in every `fixtures/<set>/` directory with nothing reading it, and
/// nothing to say so. So each set's `*.bundle`/`*.snapshot` basenames
/// must be exactly the program list; non-pair files (`SOURCES.snap`)
/// are exempt by extension.
#[test]
fn test_every_fixture_pair_is_in_the_program_list() {
    let expected: BTreeSet<String> = PROGRAMS.iter().map(|p| p.to_string()).collect();
    for set in FIXTURE_SETS {
        let dir = hansei_runtime::testkit::fixture_dir(set);
        let mut bundles = BTreeSet::new();
        let mut snapshots = BTreeSet::new();
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", dir.display()))
        {
            let path = entry.expect("the fixture directory lists").path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            match path.extension().and_then(|e| e.to_str()) {
                Some("bundle") => {
                    bundles.insert(stem.to_owned());
                }
                Some("snapshot") => {
                    snapshots.insert(stem.to_owned());
                }
                _ => {}
            }
        }
        assert_eq!(
            bundles, expected,
            "[{set}] the *.bundle files are not exactly PROGRAMS — \
             a pair captured but not listed is read by nothing"
        );
        assert_eq!(
            snapshots, expected,
            "[{set}] the *.snapshot files are not exactly PROGRAMS — \
             a pair captured but not listed is read by nothing"
        );
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
    let (ctx, list, census) = census_of(&bundle, &snapshot);
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

/// The ground-truth registry, diffed both directions over every pair.
///
/// Each fixture registered what it built as it built it — its tasks,
/// each held future by the slot it sits in, each set and join set with
/// its address and count — into a `#[no_mangle]` static the capture
/// read along with everything else (`test-programs`' `census_expect`
/// is the write side, `testkit::expect` the read side). A registered
/// item with no matching census row is an omission; a held, set, or
/// join-set row nothing registered is a fabrication, because the
/// fixtures register exhaustively. This is what retired the hand-kept
/// structural bookkeeping the census tests below used to carry: the
/// expectations now live beside the fixture code that creates the
/// state, so a new fixture shape brings its own.
#[test]
fn test_the_census_matches_what_the_fixtures_registered() {
    for program in PROGRAMS {
        for set in FIXTURE_SETS {
            let (bundle, snapshot) = load(set, program);
            let r = hansei_runtime::testkit::run(&bundle, &snapshot);
            let healthy = r.healthy_problems();
            assert!(healthy.is_empty(), "{program} [{set}]:\n{healthy:#?}");
            let problems = r.registry_problems();
            assert!(problems.is_empty(), "{program} [{set}]:\n{problems:#?}");
        }
    }
}

/// The outcome list itself is `testkit::outcomes`, shared with the
/// generated-fixture checker (`tests/genfix.rs`) so both corpora
/// accumulate over the same names.
///
/// Deliberately not asserted here, so its loss is not mistaken for an
/// oversight: no find in the checked-in corpus carries a Timer or Task
/// wait — every held fixture future is unresumed (an unpolled future
/// waits on nothing), and the one polled find the corpus has is
/// futurelock's abandoned lock future, whose wait is the mutex's
/// semaphore. The generated corpus parks polled bodies on timers, so
/// the timer entry is its to satisfy. (A reaped set slot and the
/// `<undecoded>` / `<unresolved: …>` summaries are absent from the
/// shared list outright: producible only by damage, pinned in
/// `degraded.rs`.)
const OUTCOMES_ELSEWHERE: &[&str] = &["a timer wait"];

/// The corpus still exercises every outcome the census can produce —
/// somewhere, not everywhere. Each test above asserts what one pair
/// shows; none of them notices when a fixture edit quietly stops a
/// path from ever *finding* anything, because a walk that finds
/// nothing passes every exact assertion over the nothing it found.
/// This is the "sometimes" list: an outcome no pair in
/// `PROGRAMS × FIXTURE_SETS` produces any more fails here, naming the
/// coverage that decayed. Grow it when the fixtures grow a shape.
#[test]
fn test_the_corpus_still_exercises_every_census_outcome() {
    let mut hit_by: std::collections::BTreeMap<&'static str, bool> = Default::default();
    for program in PROGRAMS {
        for set in FIXTURE_SETS {
            let (bundle, snapshot) = load(set, program);
            let (_ctx, _list, census) = census_of(&bundle, &snapshot);
            for (name, hit) in hansei_runtime::testkit::outcomes(&census) {
                *hit_by.entry(name).or_default() |= hit;
            }
        }
    }
    // The accumulator's keys are the shared list itself: an
    // `outcomes` that returns nothing (or something else) would
    // otherwise make the emptiness below pass vacuously.
    let names: Vec<&str> = hit_by.keys().copied().collect();
    assert_eq!(
        names,
        [
            "a dyn find re-rooted at its heap referent",
            "a find attributed to a held future's chain",
            "a find attributed to a set child's chain",
            "a find reached through a struct descent",
            "a find reached through an active enum variant",
            "a semaphore wait",
            "a timer wait",
            "an unlisted join-set member",
        ],
        "testkit::outcomes no longer lists what this test expects"
    );
    let missing: Vec<&str> = hit_by
        .iter()
        .filter(|&(_, &hit)| !hit)
        .map(|(name, _)| *name)
        .filter(|name| !OUTCOMES_ELSEWHERE.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "outcomes no fixture pair produces any more: {missing:#?}"
    );
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

/// The whole pipeline up to the census, shared by the census tests:
/// `testkit::run` plus everything a healthy capture is entitled to
/// (the total audit panics inside `run`; the rest reports here).
fn census_of<'a>(
    bundle: &'a Bundle,
    snapshot: &'a Snapshot,
) -> (
    Context<'a, Snapshot>,
    hansei_runtime::tokio::bundle::TaskList,
    census::FutureCensus,
) {
    let r = hansei_runtime::testkit::run(bundle, snapshot);
    let problems = r.healthy_problems();
    assert!(problems.is_empty(), "{problems:#?}");
    (r.ctx, r.list, r.census)
}

/// The `FuturesUnordered` census, offline: what the intrusive node
/// walk and the recursive scan *find* — the children, the held
/// futures, the nested set, and who each was attributed to — is pinned
/// by the registry diff above. What stays here is the re-rooting
/// contract: a child's recorded root, read back by (addr, ty) and
/// chained again, reproduces the identity the census summarized —
/// which is what tracing a child node by address rests on.
#[test]
fn test_unordered_census_offline() {
    let (bundle, snapshot) = load_any("unordered");
    let (ctx, _list, census) = census_of(&bundle, &snapshot);

    let set = census.sets.first().expect("the driver's set");
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
}

/// The size of one `FuturesUnordered`'s heap node, named from the set's
/// own type: `FuturesUnordered<F>` holds its children in `Task<F>`, and
/// that allocation is what a child's span covers.
fn node_size(bundle: &Bundle, set_ty: &str) -> u64 {
    const SET: &str = "futures_util::stream::futures_unordered::FuturesUnordered<";
    const NODE: &str = "futures_util::stream::futures_unordered::task::Task<";
    let future = set_ty
        .strip_prefix(SET)
        .and_then(|rest| rest.strip_suffix('>'))
        .unwrap_or_else(|| panic!("{set_ty} does not name the future it holds"));
    let want = format!("{NODE}{future}>");
    let view = BundleView::new(bundle);
    (0..bundle.types.types.len() as u32)
        .filter_map(|i| view.ty(hansei_bundle::BundleTypeId(i)))
        .find(|ty| ty.name() == want)
        .unwrap_or_else(|| panic!("the bundle carries no {want}"))
        .size()
}

/// An address inside a set child's node resolves to that child, which
/// is how a raw pointer — a queued waker's data word, an address typed
/// at `whatis` — is turned into the future it belongs to.
///
/// The spans are the walk's own record of where each node lies, so
/// this is the one thing the census reports that nothing else in a
/// listing corroborates: a wrong span is a `whatis` that names the
/// wrong child, or none.
#[test]
fn test_a_node_address_locates_the_set_child_that_owns_it() {
    let (bundle, snapshot) = load_any("unordered");
    let (_ctx, _list, census) = census_of(&bundle, &snapshot);

    let mut nodes = Vec::new();
    for (set_index, set) in census.sets.iter().enumerate() {
        // What the span is meant to cover: the node allocation, whose
        // size is the set's own node type's — read from the bundle
        // rather than written down, since it moves with the future the
        // set holds.
        let size = node_size(&bundle, &set.ty);
        for (child_index, child) in set.children.iter().enumerate() {
            let here = Some((set_index, child_index, 0));
            // The node's own address, a little way into it, and its
            // last byte: all name the child, and the offset says where
            // the address fell.
            assert_eq!(census.locate(child.node), here);
            assert_eq!(
                census.locate(child.node + 0x18),
                Some((set_index, child_index, 0x18))
            );
            assert_eq!(
                census.locate(child.node + size - 1),
                Some((set_index, child_index, size - 1))
            );
            // One past its end is not this child's, whoever else's it
            // is: an allocation ends where the next one may begin.
            let past = census.locate(child.node + size);
            assert!(
                !matches!(past, Some((s, c, _)) if (s, c) == (set_index, child_index)),
                "{past:?} is still child {child_index} of set {set_index}"
            );
            nodes.push(child.node);
        }
    }
    assert_eq!(nodes.len(), 5, "{:#?}", census.sets);

    // Memory no node covers is nobody's: below every span, far past
    // the last of them, and the unmapped word a corrupt pointer reads
    // as.
    let last = nodes.iter().copied().max().expect("the sets have nodes");
    assert_eq!(census.locate(0), None);
    assert_eq!(census.locate(last + 0x1_0000), None);
    assert_eq!(census.locate(u64::MAX), None);
}

/// The `JoinSet` census, offline: which sets exist and how many
/// members each holds is pinned by the registry diff above; the member
/// resolution — ids, states, who is listed — is acceptance's
/// rendered-text business. What stays here is the one member state
/// nothing else in a listing corroborates: the never-joined set holds
/// a completed task the runtime no longer owns, reachable only through
/// the set's entry — `listed: false`, and absent from the enumerated
/// population.
#[test]
fn test_joinset_census_offline() {
    let (bundle, snapshot) = load_any("joinset");
    let (_ctx, list, census) = census_of(&bundle, &snapshot);

    let unlisted: Vec<_> = census
        .join_sets
        .iter()
        .flat_map(|s| &s.children)
        .filter(|child| !child.listed)
        .collect();
    let [done] = unlisted.as_slice() else {
        panic!("expected one unlisted member, got {unlisted:#?}");
    };
    assert_eq!(done.state.lifecycle(), Lifecycle::Complete, "{done:#?}");
    assert!(
        !list.tasks.iter().any(|t| t.addr.0 == done.task),
        "{done:#?}"
    );
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

    let e = hansei_runtime::testkit::enumerate(&ctx, &snapshot);
    let [runtime] = e.runtimes.as_slice() else {
        panic!("expected one runtime, got {}", e.runtimes.len());
    };
    assert_eq!(runtime.flavor, RuntimeFlavor::CurrentThread);
    assert!(!runtime.worker_tids.is_empty());

    let list = e.list;
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

    let mut e = hansei_runtime::testkit::enumerate(&ctx, &snapshot);

    // Before discovery the scheduler owns one task, and the one it
    // joins is not in any list this session can show.
    assert_eq!(e.list.tasks.len(), 1, "{:#?}", e.list.tasks);
    let joiner = e.list.tasks[0].addr;
    let joined = match graph::analyze(&ctx, &e.list).waits[0].target.clone() {
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
    let sets = e.discover(&ctx, &[]);
    let list = e.list;
    assert!(list.errors.is_empty(), "{:?}", list.errors);
    let [set] = sets.as_slice() else {
        panic!("expected one local set, got {}", sets.len());
    };
    assert_eq!(set.route, DiscoveryRoute::JoinHandle);
    assert_ne!(set.owned_id, 0);

    assert_eq!(list.tasks.len(), 3, "{:#?}", list.tasks);
    let group = e.runtimes.len();
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

    let mut e = hansei_runtime::testkit::enumerate(&ctx, &snapshot);

    // Before discovery: the scheduler owns one task, and it points at
    // nothing outside its own list — it is parked on a timer of its
    // own, which is what makes the wheel the only way in.
    assert_eq!(e.list.tasks.len(), 1, "{:#?}", e.list.tasks);
    let scheduler_task = e.list.tasks[0].addr;
    match graph::analyze(&ctx, &e.list).waits[0].target.clone() {
        Some(hansei_runtime::tokio::bundle::WaitTarget::Timer { .. }) => {}
        other => panic!("the spawned task does not await a timer: {other:?}"),
    }

    let sets = e.discover(&ctx, &[]);
    let list = e.list;
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
    let group = e.runtimes.len();
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

    let mut e = hansei_runtime::testkit::enumerate(&ctx, &snapshot);

    // Before discovery: the scheduler owns one task, parked on a socket
    // of its own — so its own waker sits on a registration the harvest
    // walks, and being listed is what keeps it out of the candidates.
    assert_eq!(e.list.tasks.len(), 1, "{:#?}", e.list.tasks);
    let scheduler_task = e.list.tasks[0].addr;

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

    let sets = e.discover(&ctx, &[]);
    let list = e.list;
    assert!(list.errors.is_empty(), "{:?}", list.errors);
    let [set] = sets.as_slice() else {
        panic!("expected one local set, got {}", sets.len());
    };
    assert_eq!(set.route, DiscoveryRoute::Io);
    assert_ne!(set.owned_id, 0);

    // All three members join the population under the set's group, and
    // they are exactly the three the harvest named.
    assert_eq!(list.tasks.len(), 4, "{:#?}", list.tasks);
    let group = e.runtimes.len();
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

    let mut e = hansei_runtime::testkit::enumerate(&ctx, &snapshot);

    // Before discovery: one runtime, one task — the joiner — and the
    // task it awaits is in no list, classified from its cell as a task
    // of a runtime this session has not reached.
    assert_eq!(e.runtimes.len(), 1, "{:#?}", e.runtimes);
    assert_eq!(e.list.tasks.len(), 1, "{:#?}", e.list.tasks);
    let joiner = e.list.tasks[0].addr;
    let joined = match graph::analyze(&ctx, &e.list).waits[0].target.clone() {
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

    let sets = e.discover(&ctx, &[]);
    let list = e.list;
    assert!(list.errors.is_empty(), "{:?}", list.errors);

    // The runtime joins the session's list with no thread inside it,
    // and the route that found it recorded.
    let [_main, hidden] = e.runtimes.as_slice() else {
        panic!("expected two runtimes, got {}", e.runtimes.len());
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
    let group = e.runtimes.len();
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

    // Discovery once, over a probe enumeration of its own, to learn
    // the hidden runtime's handle.
    let mut probe = hansei_runtime::testkit::enumerate(&ctx, &snapshot);
    probe.discover(&ctx, &[]);
    let hidden = probe.runtimes[1].handle.addr;

    // A fresh sweep with that handle excluded, as a `--runtime`
    // selection would run it: nothing is admitted, and the set inside
    // it stays out of reach too, since only that runtime's own wheel
    // names it.
    let mut e = hansei_runtime::testkit::enumerate(&ctx, &snapshot);
    let sets = e.discover(&ctx, &[hidden]);
    assert_eq!(e.runtimes.len(), 1, "{:#?}", e.runtimes);
    assert_eq!(e.list.tasks.len(), 1, "{:#?}", e.list.tasks);
    assert!(sets.is_empty(), "{sets:#?}");
    assert!(e.list.errors.is_empty(), "{:?}", e.list.errors);
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

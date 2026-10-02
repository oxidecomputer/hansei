// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The feature-gated `snapshot` command: capture a replayable fixture
//! of everything the bundle-backed analysis reads.

use crate::{Session, discover_workers, print_warnings};

use anyhow::{Context as _, Result};
use hansei_bundle::BundleView;
use hansei_runtime::heap::{self, view::GateCounts, view::HeapView};
use hansei_runtime::tokio::graph as rt_graph;
use hansei_runtime::tokio::observe::ReadContext;
use hansei_runtime::tokio::{attribution, bundle, census, wakers};
use proc::snapshot::{CaptureLimits, RecordedHeapEvidence, Recorder};

use std::io::{self, Write};
use std::path::Path;

/// Render every running frame's source-level locals through reify,
/// discarding the output. The renderer follows the pointers inside
/// formatted values (mpsc channels, `Notify`, `Semaphore`, `watch`, …)
/// that the task/await analysis never touches; driving it through the
/// recording target is what puts those pages into the snapshot, so the
/// offline render tests replay the same reads. The depth is generous so
/// the recorded reads are a superset of any the tests perform.
///
/// Each local is rendered twice: peeled (how `trace` displays it)
/// and unpeeled (which dispatches the local's own top-level formatter —
/// e.g. `bounded::Receiver`'s compact `MpscRx` form, which peeling would
/// strip away). The two read slightly different page sets, so warming
/// both keeps the snapshot faithful to either rendering path.
///
/// Rendered under the capture's own allocator evidence, as a session
/// renders: the gates read malloc tags to corroborate a buffer's base,
/// and those reads belong in the snapshot for the replay's gates to
/// make. Nothing here adds to the recorded inventory — it is bytes
/// for inspection, and the replay discovers for itself.
fn warm_frame_values<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    chain: &bundle::AwaitChain<'_>,
    heap: Option<&dyn reify::Heap>,
) {
    for frame in &chain.frames {
        let payload = match &frame.state {
            Some(state) => state.payload,
            None => frame.future,
        };
        for m in payload.ty.members() {
            if m.ty().size() == 0 {
                continue;
            }
            let start = m.offset() as usize;
            let end = start + m.ty().size() as usize;
            let Some(bytes) = payload.bytes.get(start..end) else {
                continue;
            };
            let v = reify::Value::new(m.ty(), payload.addr + m.offset(), bytes);
            warm_render(ctx, v, heap);
            warm_render(ctx, v.peel(), heap);
        }
    }
}

/// One warming render of `v`, discarded: the reads it makes are the
/// point.
fn warm_render<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    v: reify::Value<'_>,
    heap: Option<&dyn reify::Heap>,
) {
    const WARM_DEPTH: usize = 200;
    let display = v.display_from_target(ctx.proc, WARM_DEPTH);
    let display = match heap {
        Some(heap) => display.heap(heap),
        None => display,
    };
    let _ = format!("{display:#}");
}

/// Drive every read the `threads` listings make, discarding the
/// output, so the offline table and blocks replay: every lwp's stack
/// memory, each context's own rendered state, the worker cores, the
/// parker arrays, the blocking pool's counters, and which threads are
/// the pool's: every lwp's std thread id and each pool's handles.
///
/// Deliberately *not* the unwinder's own reads: CFI walking reads
/// each mapped object's whole image, which is megabytes per fixture
/// against the few tens of kilobytes everything else records. With
/// the stack bytes in hand the offline walk bridges by frame pointer
/// instead — validated against mapping metadata and symbolized from
/// the function table, both of which every snapshot already carries.
/// The exact CFI walk stays covered where real cores are: the
/// acceptance suite.
fn warm_threads<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    lwps: &[proc::LwpInfo],
    workers: &[bundle::Worker],
    runtimes: &[bundle::RuntimeRef<'_>],
    heap: Option<&dyn reify::Heap>,
) {
    for lwp in lwps {
        let len = lwp.stack_range.end.saturating_sub(lwp.stack_range.start);
        let runs = proc::readable_runs(lwp.stack_range.start, len, |addr, max| {
            ctx.proc.readable_len(addr, max)
        });
        for (addr, run) in runs {
            let _ = ctx.proc.read_bytes(addr, run);
        }
        let _ = ctx.std_thread_id(lwp);
    }
    for rt in runtimes {
        if let bundle::RuntimeFlavor::MultiThread = rt.flavor {
            let _ = ctx.park_states(rt.handle);
        }
        let _ = ctx.blocking_pool(rt.handle);
        let _ = ctx.pool_thread_ids(rt, &ReadContext { heap });
    }
    for worker in workers {
        let Ok(info) = ctx.context_info(worker.context_addr) else {
            continue;
        };
        for field in ["thread_id", "runtime", "budget"] {
            if let Ok(value) = info.member(field) {
                warm_render(ctx, value, heap);
            }
        }
        if let Ok(Some(worker_ctx)) = ctx.worker_context(worker) {
            let _ = ctx.worker_index(worker_ctx);
            warm_scheduler_ctx(ctx, worker_ctx, heap);
        }
        if let Ok(Some(ct_ctx)) = ctx.ct_worker_context(worker) {
            if let Some(rt) = runtimes
                .iter()
                .find(|r| r.worker_tids.contains(&worker.tid))
            {
                let _ = ctx.ct_park_state(rt.handle, ct_ctx, worker.current_task_id);
            }
            warm_scheduler_ctx(ctx, ct_ctx, heap);
        }
    }
}

/// The reads under one scheduler context's block: the deferred wakers
/// and the checked-in `Core`, rendered the way `thread` renders
/// them.
fn warm_scheduler_ctx<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    sched_ctx: reify::Value<'_>,
    heap: Option<&dyn reify::Heap>,
) {
    if let Ok(defer) = sched_ctx.member("defer") {
        warm_render(ctx, defer, heap);
    }
    if let Ok(core) = sched_ctx.member("core").and_then(|c| c.member("value"))
        && let Ok(Some(boxed)) = core.try_select_variant("Some")
        && let Ok(core) = boxed.deref_ptr(ctx.proc)
    {
        warm_render(ctx, core, heap);
    }
}

/// Drive the full bundle-backed analysis with a recording Target in
/// place, then persist what it read. Every task's stage
/// and await chain is walked so the snapshot can answer the offline
/// tests' whole question set; walk problems are warnings, not errors,
/// since a partially-traceable target is still worth capturing.
///
/// A capture that reaches one of its `limits` is a failure, not a
/// smaller capture: the recorder refuses every read past the limit and
/// refuses to assemble, and nothing is written over `output`.
pub(crate) fn exec_snapshot<T: proc::Target>(
    session: &Session<'_, T>,
    output: &Path,
    limits: CaptureLimits,
    out: &mut dyn io::Write,
) -> Result<()> {
    // The recording wrapper has to sit under its own context: what makes
    // a snapshot is the reads going through `Recorder`, so the session's
    // context — which reads the target directly — cannot serve here. The
    // whole analysis is therefore driven a second time.
    let proc = session.proc;
    let recorder = Recorder::with_limits(proc, limits);
    let ctx =
        bundle::Context::with_policy(&recorder, BundleView::new(session.bundle), session.policy)?;
    // Not a policy check — the session already made it, and refused if it
    // failed. This is for the reads it makes, which belong in the
    // snapshot like any other.
    let _ = ctx.validate_fingerprint();

    // The allocator index first, through the recorder: the symbol
    // queries and metadata reads that build it are what lets the
    // replay rebuild the same index and gate the same reads. The walk
    // answers "no index" to any read it cannot make, a limit's refusal
    // included, so the recorder's own account is checked before the
    // answer is read as anything about the target.
    let prepared = heap::prepare(&recorder);
    if let Some(exceeded) = recorder.failure() {
        return Err(
            anyhow::Error::new(exceeded).context("the allocator walk reached a capture limit")
        );
    }
    let umem = prepared.context("failed to prepare the allocator evidence")?;
    let gates = GateCounts::default();
    let view = umem
        .as_ref()
        .map(|umem| HeapView::new(umem, &recorder, &gates));
    let heap = view.as_ref().map(|view| view as &dyn reify::Heap);
    let read = ReadContext { heap };

    let lwps = proc.lwps().context("failed to read lwps")?;
    let workers = discover_workers(&lwps, &ctx)?;
    let mut runtimes = ctx.find_runtimes(&workers)?;
    let mut list = ctx.enumerate_all_tasks(&runtimes)?;
    // A snapshot records only the reads the capture performs, so
    // discovery must be driven here for the offline pairs to replay it.
    let (_, registries) =
        ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[], &mut list, &read);
    print_warnings(&list.errors)?;

    let mut chains = 0usize;
    for task in &list.tasks {
        if !matches!(task.future, bundle::FutureInfo::Known(_)) {
            continue;
        }
        match ctx.inspect_task(task, &read) {
            Ok(Some(inspection)) => {
                if let bundle::ChainEnd::Error(e) = &inspection.chain.end {
                    writeln!(
                        io::stderr(),
                        "warning: await chain of task {:?} is incomplete: {e:#}",
                        task.addr
                    )?;
                }
                // Drive reify's value renderer over the frame locals too,
                // so the pages behind formatted values are recorded for
                // the offline render tests.
                warm_frame_values(&ctx, &inspection.chain, heap);
                chains += 1;
            }
            Ok(None) => {}
            Err(e) => {
                writeln!(
                    io::stderr(),
                    "warning: failed to read the root of task {:?}: {e:#}",
                    task.addr
                )?;
            }
        }
    }

    // Drive the analysis — the engine's chains through every vtable
    // word it checks, the protocols' queue, registration and trailer
    // reads, the held chains behind the polling barriers — so its
    // reads are in the snapshot. Its failures duplicate the per-task
    // warnings above.
    let analysis = rt_graph::analyze(&ctx, &list, &registries, &read);

    // And the sub-executor census, so the set node chains and child
    // futures it reads replay offline as well. A session that raised
    // `--search-depth` reads deeper than the default walk would, and
    // its snapshot has to carry those pages; one that lowered it still
    // captures everything the offline tests replay, which is what the
    // warming is for. Gated by the capture's own allocator evidence,
    // exactly as the replay's census is gated by the index it rebuilds
    // from these reads: a find refused here is refused there, and the
    // pages behind it are not the snapshot's to hold.
    let census = census::census_bounded(
        &ctx,
        &list,
        census::Bounds {
            scan_depth: session
                .bounds
                .scan_depth
                .max(census::Bounds::default().scan_depth),
            ..session.bounds
        },
        &read,
    );

    // The waker slots' attribution, so the reads that name a slot — the
    // `Arc` a hop follows, a oneshot's state word, the watch `Shared` a
    // `Notify` lies in — replay offline. The sweep itself runs over the
    // target directly, not through the recorder: it reads every mapping,
    // and a snapshot of the whole address space is no snapshot. Its
    // hits are addresses, which the recorded attribution then reads
    // behind.
    let extents = ctx.task_extents(&list);
    let wakers = session.ctx.sweep_wakers(&wakers::Territory {
        list: &list,
        extents: &extents,
        census: &census,
        heap: umem.as_ref(),
        lwps: &lwps,
    });
    let _ = ctx.attribute_slots(
        &wakers,
        &attribution::Sources {
            list: &list,
            census: &census,
            registries: &registries,
            analysis: &analysis,
            heap: umem.as_ref(),
            impls: &session.impl_fold,
        },
    );

    // The threads listings' reads: stacks, contexts, parkers, pool.
    warm_threads(&ctx, &lwps, &workers, &runtimes, heap);

    // The fixture's ground-truth registry, when the target carries one:
    // driving the read through the recorder is what puts its bytes (and
    // the symbol lookup) into the snapshot, so the offline registry
    // diff replays it. Real targets have no such symbol and skip.
    if let Some(Err(e)) = hansei_runtime::testkit::expect::read_from(&recorder) {
        writeln!(
            io::stderr(),
            "warning: failed to read the census registry: {e:#}"
        )?;
    }

    if let Some(result) = hansei_runtime::testkit::delegation::read_from(&recorder) {
        result.context("failed to record the delegation fixture ground truth")?;
    }

    // The policy the replay reads under is what this capture did:
    // an index built above, whose every read is in the log, or none —
    // in which case the replay gates nothing on evidence the capture
    // did not gather. A capture that reached a limit assembles
    // nothing, whatever it recorded before: the recorder checks its
    // own account first.
    let evidence = match umem {
        Some(_) => RecordedHeapEvidence::Available,
        None => RecordedHeapEvidence::Unavailable,
    };
    let snapshot = recorder
        .snapshot(evidence)
        .context("failed to assemble snapshot")?;
    let charged = recorder.charged();
    snapshot
        .save(output, limits.output_bytes)
        .with_context(|| format!("failed to write {}", output.display()))?;
    writeln!(
        out,
        "captured {} tasks ({chains} await chains, {} polling barriers) to {}; \
         the read log held {} bytes in {} reads",
        list.tasks.len(),
        analysis.barriers.len(),
        output.display(),
        charged.bytes,
        charged.entries,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline::session_args;

    use hansei_runtime::testkit;
    use proc::snapshot::Snapshot;

    /// A capture that reaches a limit fails whole. Every walk between
    /// the recorder and this driver treats a failed read as a warning
    /// or a smaller answer, so the failure has to be the recorder's
    /// own to survive them — and what it protects is the file at the
    /// output path, a previous valid capture left byte for byte, with
    /// no temporary beside it. Within its limits the same session
    /// captures, replaces that file, and records the neutral heap
    /// policy, since this capture builds no index.
    #[test]
    fn test_a_capture_past_its_limit_publishes_nothing() {
        let (bundle, snapshot) = testkit::load(testkit::set_or_any("linux"), "simple-await");
        let args = session_args(testkit::set_or_any("linux"), "simple-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("recapture.snapshot");
        let previous = b"a previous capture, not to be touched";
        std::fs::write(&output, previous).unwrap();
        let listing = || -> Vec<String> {
            let mut names: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };

        let mut out = Vec::new();
        let limits = CaptureLimits {
            read_log_entries: 8,
            ..CaptureLimits::default()
        };
        let err = exec_snapshot(&session, &output, limits, &mut out)
            .expect_err("a capture past its limit fails");
        assert!(
            format!("{err:#}").contains("read-log entries against its limit of 8"),
            "{err:#}"
        );
        assert_eq!(std::fs::read(&output).unwrap(), previous);
        assert_eq!(listing(), ["recapture.snapshot"]);
        assert!(out.is_empty());

        exec_snapshot(&session, &output, CaptureLimits::default(), &mut out)
            .expect("the capture fits its default limits");
        let recaptured = Snapshot::load(&output).expect("the published file is a snapshot");
        assert_eq!(
            recaptured.heap_evidence(),
            RecordedHeapEvidence::Unavailable
        );
        assert_eq!(listing(), ["recapture.snapshot"]);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("the read log held"), "{out}");
    }

    /// A pair whose capture built an allocator index recaptures with
    /// one: the index is rebuilt through the recorder, so the reads
    /// that rebuild it are in the new file, which records `Available`
    /// and attaches with the index in hand — and the census the
    /// session then gates by it is the census the capture gated.
    #[test]
    fn test_a_recapture_carries_its_allocator_index() {
        // The illumos captures are the ones under libumem; a run that
        // does not read that set has no index to recapture.
        if !testkit::reads("illumos") {
            return;
        }
        let (bundle, snapshot) = testkit::load("illumos", "joinset");
        if let testkit::Fixture::Snapshot(recorded) = &snapshot {
            assert_eq!(recorded.heap_evidence(), RecordedHeapEvidence::Available);
        }
        let args = session_args("illumos", "joinset");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        assert!(session.umem().is_some());
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("recapture.snapshot");
        let mut out = Vec::new();
        exec_snapshot(&session, &output, CaptureLimits::default(), &mut out)
            .expect("the capture fits its default limits");

        let recaptured = Snapshot::load(&output).expect("the published file is a snapshot");
        assert_eq!(recaptured.heap_evidence(), RecordedHeapEvidence::Available);
        let replay = Session::attach(&recaptured, &bundle, &args).expect("the recapture attaches");
        let index = replay.umem().expect("the recapture rebuilds its index");
        assert_eq!(index.stats().slabs, session.umem().unwrap().stats().slabs);
        fn population<T: proc::Target>(s: &Session<'_, T>) -> (usize, usize, usize, usize, usize) {
            let census = s.census();
            (
                census.held.len(),
                census.sets.len(),
                census.join_sets.len(),
                census.refused,
                s.tasks.tasks.len(),
            )
        }
        assert_eq!(population(&replay), population(&session));
    }
}

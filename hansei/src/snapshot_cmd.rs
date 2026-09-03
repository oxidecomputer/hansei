// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The feature-gated `snapshot` command: capture a replayable fixture
//! of everything the bundle-backed analysis reads.

use crate::{Session, discover_workers, print_warnings};

use anyhow::{Context as _, Result};
use hansei_bundle::BundleView;
use hansei_runtime::tokio::graph as rt_graph;
use hansei_runtime::tokio::{bundle, census};
use proc::snapshot::Recorder;

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
fn warm_frame_values<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    chain: &bundle::AwaitChain<'_>,
) {
    const WARM_DEPTH: usize = 200;
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
            let _ = format!("{:#}", v.display_from_target(ctx.proc, WARM_DEPTH));
            let _ = format!("{:#}", v.peel().display_from_target(ctx.proc, WARM_DEPTH));
        }
    }
}

/// Drive every read the `threads` listings make, discarding the
/// output, so the offline table and blocks replay: every lwp's stack
/// memory, each context's own rendered state, the worker cores, the
/// parker arrays, and the blocking pool's counters.
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
) {
    const WARM_DEPTH: usize = 200;
    for lwp in lwps {
        let len = lwp.stack_range.end.saturating_sub(lwp.stack_range.start);
        let runs = proc::readable_runs(lwp.stack_range.start, len, |addr, max| {
            ctx.proc.readable_len(addr, max)
        });
        for (addr, run) in runs {
            let _ = ctx.proc.read_bytes(addr, run);
        }
    }
    for rt in runtimes {
        if let bundle::RuntimeFlavor::MultiThread = rt.flavor {
            let _ = ctx.park_states(rt.handle);
        }
        let _ = ctx.blocking_pool(rt.handle);
    }
    for worker in workers {
        let Ok(info) = ctx.context_info(worker.context_addr) else {
            continue;
        };
        for field in ["thread_id", "runtime", "budget"] {
            if let Ok(value) = info.member(field) {
                let _ = format!("{:#}", value.display_from_target(ctx.proc, WARM_DEPTH));
            }
        }
        if let Ok(Some(worker_ctx)) = ctx.worker_context(worker) {
            let _ = ctx.worker_index(worker_ctx);
            warm_scheduler_ctx(ctx, worker_ctx);
        }
        if let Ok(Some(ct_ctx)) = ctx.ct_worker_context(worker) {
            if let Some(rt) = runtimes
                .iter()
                .find(|r| r.worker_tids.contains(&worker.tid))
            {
                let _ = ctx.ct_park_state(rt.handle, ct_ctx);
            }
            warm_scheduler_ctx(ctx, ct_ctx);
        }
    }
}

/// The reads under one scheduler context's block: the deferred wakers
/// and the checked-in `Core`, rendered the way `thread` renders
/// them.
fn warm_scheduler_ctx<T: proc::Target>(ctx: &bundle::Context<'_, T>, sched_ctx: reify::Value<'_>) {
    const WARM_DEPTH: usize = 200;
    if let Ok(defer) = sched_ctx.member("defer") {
        let _ = format!("{:#}", defer.display_from_target(ctx.proc, WARM_DEPTH));
    }
    if let Ok(core) = sched_ctx.member("core").and_then(|c| c.member("value"))
        && let Ok(Some(boxed)) = core.try_select_variant("Some")
        && let Ok(core) = boxed.deref_ptr(ctx.proc)
    {
        let _ = format!("{:#}", core.display_from_target(ctx.proc, WARM_DEPTH));
    }
}

/// Drive the full bundle-backed analysis with a recording Target in
/// place, then persist what it read. Every task's stage
/// and await chain is walked so the snapshot can answer the offline
/// tests' whole question set; walk problems are warnings, not errors,
/// since a partially-traceable target is still worth capturing.
pub(crate) fn exec_snapshot<T: proc::Target>(
    session: &Session<'_, T>,
    output: &Path,
    out: &mut dyn io::Write,
) -> Result<()> {
    // The recording wrapper has to sit under its own context: what makes
    // a snapshot is the reads going through `Recorder`, so the session's
    // context — which reads the target directly — cannot serve here. The
    // whole analysis is therefore driven a second time.
    let proc = session.proc;
    let recorder = Recorder::new(proc);
    let ctx =
        bundle::Context::with_policy(&recorder, BundleView::new(session.bundle), session.policy)?;
    // Not a policy check — the session already made it, and refused if it
    // failed. This is for the reads it makes, which belong in the
    // snapshot like any other.
    let _ = ctx.validate_fingerprint();

    let lwps = proc.lwps().context("failed to read lwps")?;
    let workers = discover_workers(&lwps, &ctx)?;
    let mut runtimes = ctx.find_runtimes(&workers)?;
    let mut list = ctx.enumerate_all_tasks(&runtimes)?;
    // A snapshot records only the reads the capture performs, so
    // discovery must be driven here for the offline pairs to replay it.
    let (_, registries) = ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[], &mut list);
    print_warnings(&list.errors)?;

    let mut chains = 0usize;
    for task in &list.tasks {
        if !matches!(task.future, bundle::FutureInfo::Known(_)) {
            continue;
        }
        match ctx.task_stage(task) {
            Ok(bundle::TaskStage::Running(future)) => {
                let chain = ctx.await_chain(future);
                if let bundle::ChainEnd::Error(e) = &chain.end {
                    writeln!(
                        io::stderr(),
                        "warning: await chain of task {:?} is incomplete: {e:#}",
                        task.addr
                    )?;
                }
                // Drive the leaf-future interpretation too, so its reads
                // are in the snapshot for the offline tests.
                if let Some(Err(e)) = ctx.wait_target(&chain, &list) {
                    writeln!(
                        io::stderr(),
                        "warning: failed to read what task {:?} waits on: {e:#}",
                        task.addr
                    )?;
                }
                // Drive reify's value renderer over the frame locals too,
                // so the pages behind formatted values are recorded for
                // the offline render tests.
                warm_frame_values(&ctx, &chain);
                chains += 1;
            }
            Ok(_) => {}
            Err(e) => {
                writeln!(
                    io::stderr(),
                    "warning: failed to read the stage of task {:?}: {e:#}",
                    task.addr
                )?;
            }
        }
    }

    // Drive the dependency analysis too — wake queues and the
    // off-path acquire scan — so its reads are in the snapshot. Its
    // failures duplicate the per-task warnings above.
    let analysis = rt_graph::analyze(&ctx, &list, &registries);

    // And the sub-executor census, so the set node chains and child
    // futures it reads replay offline as well. A session that raised
    // `--search-depth` reads deeper than the default walk would, and
    // its snapshot has to carry those pages; one that lowered it still
    // captures everything the offline tests replay, which is what the
    // warming is for.
    let _ = census::census_bounded(
        &ctx,
        &list,
        census::Bounds {
            scan_depth: session
                .bounds
                .scan_depth
                .max(census::Bounds::default().scan_depth),
            ..session.bounds
        },
        // Deliberately uncorroborated, whatever this target's
        // allocator says. A snapshot holds the pages the capture read,
        // and the offline replay of it has no umem metadata to consult
        // — so a walk that refused a find here would leave the pages
        // that find's chain needs out of the snapshot, and the replay,
        // which refuses nothing, would then read what is not there.
        // The capture reads the whole walk; the gate is a session's.
        None,
    );

    // The threads listings' reads: stacks, contexts, parkers, pool.
    warm_threads(&ctx, &lwps, &workers, &runtimes);

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

    let snapshot = recorder.snapshot().context("failed to assemble snapshot")?;
    snapshot
        .save(output)
        .with_context(|| format!("failed to write {}", output.display()))?;
    writeln!(
        out,
        "captured {} tasks ({chains} await chains, {} futurelocks) to {}",
        list.tasks.len(),
        analysis.futurelocks.len(),
        output.display()
    )?;
    Ok(())
}

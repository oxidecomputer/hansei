//! The feature-gated `snapshot` command: capture a replayable fixture
//! of everything the bundle-backed analysis reads.

use crate::{Session, discover_workers, print_warnings};

use anyhow::{Context as _, Result};
use hansei_bundle::BundleView;
use hansei_runtime::tokio::graph as rt_graph;
use hansei_runtime::tokio::{bundle, census};
use proc::Target;
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

/// Drive the full bundle-backed analysis with a recording Target in
/// place, then persist what it read. Every task's stage
/// and await chain is walked so the snapshot can answer the offline
/// tests' whole question set; walk problems are warnings, not errors,
/// since a partially-traceable target is still worth capturing.
pub(crate) fn exec_snapshot(
    session: &Session<'_>,
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
    ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[], &mut list);
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
    let analysis = rt_graph::analyze(&ctx, &list);

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
    );

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

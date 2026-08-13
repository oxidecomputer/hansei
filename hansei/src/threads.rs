//! The `threads`, `drivers` and `shared-state` commands: the runtime
//! state read straight through the bundle’s layouts.

use crate::trace::print_variable;
use crate::{Proc, RenderOpts, RuntimeField, Session};

use anyhow::Result;
use hansei_runtime::tokio::{Lifecycle, bundle};
use reify::Value;

use std::collections::BTreeMap;
use std::io::{self, Write};

/// Every thread the runtime is running on, as the runtime sees it and
/// as the stack sees it: the task it is polling, the worker core it
/// holds while it runs, and the frames it is parked in.
pub(crate) fn exec_threads(
    session: &Session<'_>,
    frames: usize,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    // Unwinding reads the CFI of every mapped object, so it is done once
    // for the whole target and only when a command asks for it. A target
    // it cannot walk still has runtime state worth printing, so a failure
    // costs the stacks and nothing else.
    let stacks = match unwind::load_frames(session.proc) {
        Ok(stacks) => stacks,
        Err(e) => {
            writeln!(
                io::stderr(),
                "warning: cannot unwind the target's threads: {e:#}"
            )?;
            BTreeMap::new()
        }
    };

    for (i, worker) in session.workers.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        writeln!(out, "LWP {}  {}", worker.tid, polling(session, worker))?;

        if let Err(e) = print_thread_context(session, worker, opts, out) {
            writeln!(out, "  thread context unreadable: {e:#}")?;
        }

        match session.ctx.worker_context(worker) {
            Ok(Some(worker_ctx)) => print_worker_state(session, worker_ctx, opts, out)?,
            // A thread inside the runtime without a scheduler context is
            // ordinary: `block_on` enters the runtime from a thread that
            // never runs the worker loop.
            Ok(None) => writeln!(out, "  not in the scheduler's run loop")?,
            Err(e) => writeln!(out, "  scheduler context unreadable: {e:#}")?,
        }

        match stacks.get(&worker.tid) {
            Some(backtrace) => {
                writeln!(out, "  stack:")?;
                for line in backtrace.stack_trace(frames) {
                    writeln!(out, "    {line}")?;
                }
            }
            None => writeln!(out, "  stack: unavailable")?,
        }
    }
    Ok(())
}

/// What a thread is doing with the task it last entered. tokio restores
/// the thread-local task id after a poll returns, but a thread that was
/// interrupted mid-poll — and any thread whose id belongs to a task that
/// has since finished — leaves a stale one behind, so the claim is only
/// made for a task the runtime still owns and still calls running.
fn polling(session: &Session<'_>, worker: &bundle::Worker) -> String {
    let Some(id) = worker.current_task_id else {
        return "polling no task".to_string();
    };
    let running = session
        .tasks
        .tasks
        .iter()
        .any(|t| t.task_id == Some(id) && t.state.lifecycle() == Lifecycle::Running);
    if running {
        format!("polling task {id}")
    } else {
        format!("last polled task {id}")
    }
}

/// The tokio state a thread carries in its own thread-local `Context`:
/// which thread the runtime takes it for, whether it has entered a
/// runtime, and what is left of the task's cooperative budget.
fn print_thread_context(
    session: &Session<'_>,
    worker: &bundle::Worker,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let info = session.ctx.context_info(worker.context_addr)?;
    for field in ["thread_id", "runtime", "budget"] {
        let value = info.member(field)?;
        print_rendered(session, field, &value, opts, out)?;
    }
    Ok(())
}

/// Print one named value the way the threads listing indents them.
fn print_rendered(
    session: &Session<'_>,
    name: &str,
    value: &Value<'_>,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    print_variable(
        out,
        "  ",
        name,
        &format_args!("{:#}", render(session, value, opts).line_prefix("    ")),
    )
}

/// A worker thread's own state: which worker it is, the `Core` it holds
/// while it runs — the run queue, the LIFO slot, the park state and the
/// counters the scheduler keeps per worker — and the wakers it has
/// deferred until the current poll returns.
fn print_worker_state<'b>(
    session: &Session<'_>,
    worker_ctx: Value<'b>,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    writeln!(out, "  worker {}", ctx.worker_index(worker_ctx)?)?;

    let defer = worker_ctx.member("defer")?;
    print_rendered(session, "defer", &defer, opts, out)?;

    // The core is moved out of the thread's context while the scheduler
    // parks or hands it to another thread, so its absence is a state
    // worth naming rather than an error.
    let core = worker_ctx.member("core")?.member("value")?;
    let Some(boxed) = core.try_select_variant("Some")? else {
        writeln!(out, "  core: not held by this thread")?;
        return Ok(());
    };
    let core = boxed.deref_ptr(ctx.proc)?;
    print_rendered(session, "core", &core, opts, out)?;
    Ok(())
}

/// Render one of the runtime handle's fields out of the target: the
/// scheduler state the workers share, or the drivers they park on.
///
/// Both are read straight through the bundle's layouts rather than into
/// a hand-written mirror of tokio's structs, so a field tokio adds shows
/// up without hansei being taught about it.
pub(crate) fn exec_runtime_field(
    session: &Session<'_>,
    field: RuntimeField,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let member = match field {
        RuntimeField::Drivers => "driver",
        RuntimeField::Shared => "shared",
    };
    // Both scheduler flavors' handles carry these members. Sessions
    // holding more than one runtime show the first discovered; a
    // per-runtime selector is multi-runtime UX still to come.
    let value = session.runtimes[0].handle.member(member)?;
    // The bundle's `Elided` formats hide the runtime graph from *user*
    // values; these commands exist to show the runtime's own insides, so
    // they must never apply here — a new elided row must not be able to
    // blank part of this output.
    let no_elide = reify::ElideOverride {
        no_elide: true,
        types: Vec::new(),
    };
    writeln!(
        out,
        "{:#}",
        render(session, &value, opts).elide_override(&no_elide)
    )?;
    Ok(())
}

/// Display a value read from the target, honouring the custom formatters
/// unless asked for the raw structural view. Nothing is rendered until the
/// caller formats the result (with `{:#}` for the usual pretty layout), so
/// the text can stream to its destination instead of through a `String`.
fn render<'r, 'b>(
    session: &'r Session<'b>,
    value: &'r Value<'b>,
    opts: RenderOpts,
) -> reify::DisplayValue<'r, 'b, Proc> {
    let display = value.display_from_target(session.ctx.proc, opts.depth);
    if opts.ugly { display.ugly() } else { display }
}

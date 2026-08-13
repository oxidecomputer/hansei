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
        // Which runtime the thread runs is only worth a tag when the
        // target holds more than one.
        let tag = match session.runtimes.len() {
            0 | 1 => String::new(),
            _ => match session.runtime_of(worker.tid) {
                Some((index, rt)) => format!("  runtime {index} ({})", rt.flavor),
                None => String::new(),
            },
        };
        writeln!(out, "LWP {}  {}{tag}", worker.tid, polling(session, worker))?;

        if let Err(e) = print_thread_context(session, worker, opts, out) {
            writeln!(out, "  thread context unreadable: {e:#}")?;
        }

        match scheduler_state(session, worker) {
            Ok(SchedulerState::Worker(worker_ctx)) => {
                print_worker_state(session, worker_ctx, opts, out)?
            }
            Ok(SchedulerState::BlockOn(ct_ctx)) => {
                print_block_on_state(session, worker, ct_ctx, opts, out)?
            }
            // A thread inside the runtime without a scheduler context is
            // ordinary: `block_on` enters the runtime from a thread that
            // never runs the worker loop.
            Ok(SchedulerState::None) => writeln!(out, "  not in the scheduler's run loop")?,
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

/// The scheduler context a thread's stack holds, of whichever flavor.
enum SchedulerState<'b> {
    Worker(Value<'b>),
    BlockOn(Value<'b>),
    None,
}

fn scheduler_state<'b>(
    session: &Session<'b>,
    worker: &bundle::Worker,
) -> Result<SchedulerState<'b>> {
    if let Some(worker_ctx) = session.ctx.worker_context(worker)? {
        return Ok(SchedulerState::Worker(worker_ctx));
    }
    match session.ctx.ct_worker_context(worker)? {
        Some(ct_ctx) => Ok(SchedulerState::BlockOn(ct_ctx)),
        None => Ok(SchedulerState::None),
    }
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
    writeln!(out, "  worker {}", session.ctx.worker_index(worker_ctx)?)?;

    let defer = worker_ctx.member("defer")?;
    print_rendered(session, "defer", &defer, opts, out)?;

    // The core is moved out of the thread's context while the scheduler
    // parks or hands it to another thread, so its absence is a state
    // worth naming rather than an error.
    print_checked_in_core(session, worker_ctx, "not held by this thread", opts, out)
}

/// A current_thread `block_on` thread's state: what it is doing — read
/// from where its core and driver are — and the `Core` itself while it
/// is checked into the context, which is exactly while the thread parks
/// or polls the `block_on` future.
fn print_block_on_state<'b>(
    session: &Session<'_>,
    worker: &bundle::Worker,
    ct_ctx: Value<'b>,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    writeln!(out, "  block_on thread of its current_thread runtime")?;
    if let Some((_, rt)) = session.runtime_of(worker.tid) {
        match session.ctx.ct_park_state(rt.handle, ct_ctx) {
            Ok(state) => {
                let woken = if state.woken {
                    ", a wakeup pending"
                } else {
                    ""
                };
                writeln!(out, "  {}{woken}", state.activity)?;
            }
            Err(e) => writeln!(out, "  park state unreadable: {e:#}")?,
        }
    }

    let defer = ct_ctx.member("defer")?;
    print_rendered(session, "defer", &defer, opts, out)?;

    print_checked_in_core(
        session,
        ct_ctx,
        "checked out, on the thread's stack",
        opts,
        out,
    )
}

/// Print the `Core` a scheduler context has checked in, or the absence
/// line the flavor words its checked-out state with. Both flavors keep
/// it in the same place: a `RefCell<Option<Box<Core>>>` member named
/// `core`.
fn print_checked_in_core(
    session: &Session<'_>,
    sched_ctx: Value<'_>,
    absent: &str,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let core = sched_ctx.member("core")?.member("value")?;
    let Some(boxed) = core.try_select_variant("Some")? else {
        writeln!(out, "  core: {absent}")?;
        return Ok(());
    };
    let core = boxed.deref_ptr(session.ctx.proc)?;
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
    // The bundle's `Elided` formats hide the runtime graph from *user*
    // values; these commands exist to show the runtime's own insides, so
    // they must never apply here — a new elided row must not be able to
    // blank part of this output.
    let no_elide = reify::ElideOverride {
        no_elide: true,
        types: Vec::new(),
    };
    // Both scheduler flavors' handles carry these members: one section
    // per discovered runtime, headed only when there is more than one.
    for (i, rt) in session.runtimes.iter().enumerate() {
        if session.runtimes.len() > 1 {
            if i > 0 {
                writeln!(out)?;
            }
            writeln!(out, "runtime {i} ({}):", rt.flavor)?;
        }
        let value = rt.handle.member(member)?;
        writeln!(
            out,
            "{:#}",
            render(session, &value, opts).elide_override(&no_elide)
        )?;
    }
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

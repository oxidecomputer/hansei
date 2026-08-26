//! The `threads` command: every thread the runtime is running on, as
//! the runtime sees it and as the stack sees it.

use crate::trace::print_variable;
use crate::{Proc, RenderOpts, Session};

use anyhow::Result;
use hansei_runtime::tokio::bundle;
use proc::Target;
use reify::Value;

use std::collections::BTreeMap;
use std::io::{self, Write};

/// Every thread the runtime is running on, as the runtime sees it and
/// as the stack sees it: the task it is polling, the worker core it
/// holds while it runs, and the frames it is parked in.
/// `lwps` narrows the listing to the named threads' blocks, and is
/// empty for the whole listing. The lwp that took the fatal signal
/// prints its registers unasked — that is exactly when they matter —
/// and `registers` asks the same of every listed thread.
pub(crate) fn exec_threads(
    session: &Session<'_>,
    frames: usize,
    lwps: &[u32],
    registers: bool,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    // Resolve the selection before any work, so an lwp the listing does
    // not hold says so rather than printing nothing — and without first
    // paying for (or warning about) the unwind below.
    for &tid in lwps {
        if !session.workers.iter().any(|w| w.tid == tid) {
            return Err(no_such_thread(&session.workers, tid));
        }
    }

    // Unwinding reads the CFI of every mapped object, so it is done once
    // for the whole target and only when a command asks for it. A target
    // it cannot walk still has runtime state worth printing, so a failure
    // costs the stacks and nothing else.
    let stacks = match unwind::load_frames(session.proc) {
        Ok(unwound) => unwound.stacks,
        Err(e) => {
            writeln!(
                io::stderr(),
                "warning: cannot unwind the target's threads: {e:#}"
            )?;
            BTreeMap::new()
        }
    };

    let fatal = session.proc.fatal_signal();
    let selected = session
        .workers
        .iter()
        .filter(|w| lwps.is_empty() || lwps.contains(&w.tid));
    for (i, worker) in selected.enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        // Which runtime the thread runs is only worth a tag when the
        // listings tag their groups at all — more than one runtime, or
        // a local set sharing the population.
        let tag = if session.group_tags().is_empty() {
            String::new()
        } else {
            match session.runtime_of(worker.tid) {
                Some((index, rt)) => format!("  {}", crate::runtimes::runtime_label(index, rt)),
                None => String::new(),
            }
        };
        let took = fatal_tag(fatal.as_ref(), worker.tid);
        writeln!(
            out,
            "lwp {}  {}{tag}{took}",
            worker.tid,
            polling(session, worker)
        )?;

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

        // Frame 0 of the stack below, so it prints just above it.
        if shows_registers(registers, fatal.as_ref(), worker.tid) {
            crate::registers::print_lwp_registers(session, worker.tid, "  ", out)?;
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

/// The error for an lwp no runtime is running on: name the lwps the
/// listing does hold, since the number asked for came from somewhere
/// else.
fn no_such_thread(workers: &[bundle::Worker], tid: u32) -> anyhow::Error {
    let tids: Vec<u32> = workers.iter().map(|w| w.tid).collect();
    anyhow::anyhow!(
        "no thread with lwp {tid} is listed; the target's runtimes run on {} thread(s): {tids:?}",
        tids.len()
    )
}

/// The heading tag for the lwp that took the fatal signal — empty for
/// every other thread, and for a target that took none. The signal
/// tied to what the thread was polling is the join this listing
/// exists to make.
fn fatal_tag(fatal: Option<&proc::FatalSignal>, tid: u32) -> String {
    match fatal {
        Some(sig) if sig.lwp == Some(tid) => {
            format!(
                " — took the fatal {}",
                crate::summary::fatal_signal_line(sig)
            )
        }
        _ => String::new(),
    }
}

/// Whether a thread's block prints its registers: asked for with
/// `--registers`, or earned by taking the fatal signal — that is
/// exactly when they matter, and healthy captures stay unaffected.
fn shows_registers(registers: bool, fatal: Option<&proc::FatalSignal>, tid: u32) -> bool {
    registers || fatal.is_some_and(|sig| sig.lwp == Some(tid))
}

/// What a thread is doing with the task it last entered. tokio restores
/// the thread-local task id after a poll returns, but a thread that was
/// interrupted mid-poll — and any thread whose id belongs to a task that
/// has since finished — leaves a stale one behind, so the claim is only
/// made for a task the runtime still owns and still calls running.
fn polling(session: &Session<'_>, worker: &bundle::Worker) -> String {
    polling_line(
        worker.current_task_id,
        crate::tasks::polled_task(worker.current_task_id, &session.tasks),
    )
}

/// The claim as the heading spells it: believed, stale, or absent.
fn polling_line(current: Option<u64>, believed: Option<u64>) -> String {
    match (current, believed) {
        (None, _) => "polling no task".to_string(),
        (Some(id), Some(_)) => format!("polling task {id}"),
        (Some(id), None) => format!("last polled task {id}"),
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
    let heap = session.heap_view();
    let heap = heap.as_ref().map(|view| view as &dyn reify::Heap);
    print_variable(
        out,
        "  ",
        name,
        &format_args!(
            "{:#}",
            render(session, value, opts, heap).line_prefix("    ")
        ),
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

/// Display a value read from the target, honouring the custom formatters
/// unless asked for the raw structural view. Nothing is rendered until the
/// caller formats the result (with `{:#}` for the usual pretty layout), so
/// the text can stream to its destination instead of through a `String`.
pub(crate) fn render<'r, 'b>(
    session: &'r Session<'b>,
    value: &'r Value<'b>,
    opts: RenderOpts,
    heap: Option<&'r dyn reify::Heap>,
) -> reify::DisplayValue<'r, 'b, Proc> {
    let mut display = value
        .display_from_target(session.ctx.proc, opts.depth)
        .max_str_len(Some(opts.max_str_len))
        .max_array_len(Some(opts.max_array_len));
    if let Some(heap) = heap {
        display = display.heap(heap);
    }
    if opts.ugly { display.ugly() } else { display }
}

#[cfg(test)]
mod tests {
    use super::{bundle, fatal_tag, no_such_thread, polling_line};

    /// The three spellings of the heading's claim: believed, stale,
    /// and absent — the stale word is reported, but not as a poll in
    /// progress.
    #[test]
    fn test_the_polling_claim_has_three_spellings() {
        assert_eq!(polling_line(None, None), "polling no task");
        assert_eq!(polling_line(Some(7), Some(7)), "polling task 7");
        assert_eq!(polling_line(Some(7), None), "last polled task 7");
    }

    fn segv(lwp: Option<u32>) -> proc::FatalSignal {
        proc::FatalSignal {
            name: "SIGSEGV",
            signo: 11,
            code: 1,
            code_name: Some("SEGV_MAPERR"),
            fault_addr: Some(0),
            lwp,
        }
    }

    /// Exactly the lwp the signal names is tagged: not its siblings,
    /// not anyone on a target that took no signal, and nobody when the
    /// core did not say which lwp took it.
    #[test]
    fn test_the_faulting_lwp_alone_is_tagged() {
        let sig = segv(Some(7));
        assert_eq!(
            fatal_tag(Some(&sig), 7),
            " — took the fatal SIGSEGV (SEGV_MAPERR), fault address 0x0"
        );
        assert_eq!(fatal_tag(Some(&sig), 8), "");
        assert_eq!(fatal_tag(None, 7), "");
        assert_eq!(fatal_tag(Some(&segv(None)), 7), "");
    }

    /// The register block is earned by exactly the lwp the fatal
    /// signal names — not its siblings, not anyone on a healthy
    /// capture, nobody when the core did not say which lwp took it —
    /// and `--registers` asks it of every thread regardless.
    #[test]
    fn test_registers_print_for_the_faulting_lwp_or_on_request() {
        use super::shows_registers;
        let sig = segv(Some(7));
        assert!(shows_registers(false, Some(&sig), 7));
        assert!(!shows_registers(false, Some(&sig), 8));
        assert!(!shows_registers(false, None, 7));
        assert!(!shows_registers(false, Some(&segv(None)), 7));
        assert!(shows_registers(true, None, 8));
        assert!(shows_registers(true, Some(&sig), 8));
    }

    /// An lwp the listing does not hold names the ones it does, since
    /// the number asked for came from somewhere else.
    #[test]
    fn test_an_unlisted_lwp_names_the_listed_ones() {
        let workers: Vec<bundle::Worker> = [3, 5]
            .into_iter()
            .map(|tid| bundle::Worker {
                tid,
                context_addr: 0,
                current_task_id: None,
            })
            .collect();
        assert_eq!(
            no_such_thread(&workers, 9).to_string(),
            "no thread with lwp 9 is listed; the target's runtimes run on 2 thread(s): [3, 5]"
        );
    }
}

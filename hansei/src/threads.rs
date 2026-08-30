//! The `threads` command: every thread the runtime is running on, as
//! the runtime sees it and as the stack sees it.

use crate::summary;
use crate::trace::print_variable;
use crate::{RenderOpts, Session};

use anyhow::Result;
use hansei_runtime::tokio::bundle::{self, ParkState};
use reify::Value;

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};

/// Every thread the runtime is running on, as the runtime sees it and
/// as the stack sees it: the task it is polling, the worker core it
/// holds while it runs, and the frames it is parked in.
/// `lwps` narrows the listing to the named threads' blocks, and is
/// empty for the whole listing. The lwp that took the fatal signal
/// prints its registers unasked — that is exactly when they matter —
/// and `registers` asks the same of every listed thread.
/// One row of the `threads` table: the compact per-lwp answer, built
/// once — with the one unwind of every stack — and cached beside the
/// task rows.
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct ThreadRow {
    pub(crate) lwp: u32,
    /// The thread's recorded name; only illumos cores carry one.
    pub(crate) name: Option<String>,
    /// The place the thread holds in a runtime, spelled by
    /// [`park_word`] and its callers: `worker N, <state>`, `block_on
    /// caller`, `blocking, running` / `blocking, idle` (read from the
    /// stack — the runtime side cannot tell a blocking thread apart),
    /// `entered runtime`, or `no runtime`.
    pub(crate) role: String,
    /// The task it is polling, believed only when the listing agrees.
    pub(crate) task: Option<u64>,
    /// The top of the unwound stack, [`headline`]-joined.
    pub(crate) frame0: String,
}

/// The table's rows, built on first use and cached on the session.
pub(crate) fn rows<'s, T: proc::Target>(session: &'s Session<'_, T>) -> &'s [ThreadRow] {
    session.thread_rows.get_or_init(|| build_rows(session))
}

fn build_rows<T: proc::Target>(session: &Session<'_, T>) -> Vec<ThreadRow> {
    let stacks = load_stacks(session);
    // One parker-array read per runtime, shared by its workers' rows.
    let mut parks: HashMap<usize, Option<bundle::ParkStates>> = HashMap::new();
    let mut rows: Vec<ThreadRow> = session
        .lwps
        .iter()
        .map(|lwp| {
            let worker = session.workers.iter().find(|w| w.tid == lwp.tid);
            let stack = stacks.get(&lwp.tid);
            ThreadRow {
                lwp: lwp.tid,
                name: session.proc.lwp_name(lwp.tid),
                role: role_of(session, lwp.tid, worker, stack, &mut parks),
                task: worker
                    .and_then(|w| crate::tasks::polled_task(w.current_task_id, &session.tasks)),
                frame0: headline(&stack_names(stack)),
            }
        })
        .collect();
    rows.sort_by_key(|row| row.lwp);
    rows
}

/// Unwind every stack, once; a target that cannot be walked still has
/// runtime state worth listing, so a failure costs the stack columns
/// and a warning, nothing else.
fn load_stacks<T: proc::Target>(session: &Session<'_, T>) -> BTreeMap<u32, unwind::Backtrace> {
    match unwind::load_frames(session.proc) {
        Ok(unwound) => unwound.stacks,
        Err(e) => {
            let _ = writeln!(
                io::stderr(),
                "warning: cannot unwind the target's threads: {e:#}"
            );
            BTreeMap::new()
        }
    }
}

/// The `ROLE` cell for one lwp.
fn role_of<T: proc::Target>(
    session: &Session<'_, T>,
    tid: u32,
    worker: Option<&bundle::Worker>,
    stack: Option<&unwind::Backtrace>,
    parks: &mut HashMap<usize, Option<bundle::ParkStates>>,
) -> String {
    // No tokio context at all: nothing of the runtime's to say.
    let Some(worker) = worker else {
        return "no runtime".to_string();
    };
    match scheduler_state(session, worker) {
        Ok(SchedulerState::Worker(worker_ctx)) => {
            let index = session.ctx.worker_index(worker_ctx).ok();
            let park = index.and_then(|index| {
                let (rt_index, rt) = session.runtime_of(tid)?;
                parks
                    .entry(rt_index)
                    .or_insert_with(|| match rt.flavor {
                        bundle::RuntimeFlavor::MultiThread => {
                            session.ctx.park_states(rt.handle).ok()
                        }
                        bundle::RuntimeFlavor::CurrentThread => None,
                    })
                    .as_ref()
                    .and_then(|parks| parks.workers.get(index as usize))
                    .copied()
            });
            let polling =
                crate::tasks::polled_task(worker.current_task_id, &session.tasks).is_some();
            let worker_name = match index {
                Some(index) => format!("worker {index}"),
                None => "worker ?".to_string(),
            };
            // With several runtimes a worker index means nothing
            // without the scheduler that numbered it.
            let scoped = match (session.runtimes.len() > 1, session.runtime_of(tid)) {
                (true, Some((rt_index, _))) => format!("rt {rt_index} {worker_name}"),
                _ => worker_name,
            };
            format!("{scoped}, {}", park_word(park, polling))
        }
        Ok(SchedulerState::BlockOn(_)) => "block_on caller".to_string(),
        // A thread inside the runtime without a scheduler context:
        // the blocking pool's, if its stack says so — the runtime
        // keeps only counters about the pool, so the stack is the
        // only witness — else a thread that merely entered.
        Ok(SchedulerState::None) => blocking_role(&stack_names(stack))
            .unwrap_or("entered runtime")
            .to_string(),
        // A context that could not be read is not a thread that
        // merely entered; say what happened instead of guessing.
        Err(_) => "context unreadable".to_string(),
    }
}

/// The state half of a worker's role: what the task listing says it is
/// doing where the runtime records a poll, else what its parker says.
fn park_word(park: Option<ParkState>, polling: bool) -> &'static str {
    if polling {
        return "polling";
    }
    match park {
        Some(ParkState::Awake) => "awake",
        Some(ParkState::Condvar) => "parked",
        Some(ParkState::Driver) => "in driver",
        Some(ParkState::Notified) => "notified",
        Some(ParkState::Unknown(_)) | None => "park state unread",
    }
}

/// The blocking-pool spellings, classified from the unwound stack: a
/// thread inside `blocking::pool::Inner::run` is the pool's, idle when
/// it is parked above that frame and running someone's closure
/// otherwise. `None` for every other stack — including an absent one,
/// which cannot testify either way.
fn blocking_role(frames: &[String]) -> Option<&'static str> {
    let run = frames
        .iter()
        .position(|name| name.contains("blocking::pool::Inner::run"))?;
    let parked = frames[..run].iter().any(|name| {
        name.contains("std::thread::park")
            || name.contains("cond_wait")
            || name.contains("__lwp_park")
            || name.contains("futex")
    });
    Some(match parked {
        true => "blocking, idle",
        false => "blocking, running",
    })
}

/// Every frame's symbol, demangled without the hash — the spelling the
/// role classifier matches on and the headline prints.
fn stack_names(stack: Option<&unwind::Backtrace>) -> Vec<String> {
    stack
        .map(|bt| {
            bt.frames
                .iter()
                .map(|frame| match &frame.symbol {
                    Some(symbol) => format!("{:#}", rustc_demangle::demangle(&symbol.name)),
                    None => format!("{:#x}", frame.pc),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The `FRAME 0` cell: the top three symbols `←`-joined — the mdb
/// `::stacks` headline — or `—` where no stack could be walked.
fn headline(names: &[String]) -> String {
    match names.is_empty() {
        true => "—".to_string(),
        false => names[..names.len().min(3)].join(" \u{2190} "),
    }
}

/// Print the table: one row per lwp, in lwp order, nothing truncated.
fn print_thread_table(rows: &[ThreadRow], out: &mut dyn io::Write) -> Result<()> {
    let mut table = crate::output::Table::new(5).header(["LWP", "NAME", "ROLE", "TASK", "FRAME 0"]);
    let dash = || "—".to_string();
    for row in rows {
        table.row([
            row.lwp.to_string(),
            row.name.clone().unwrap_or_else(dash),
            row.role.clone(),
            row.task.map(|id| id.to_string()).unwrap_or_else(dash),
            row.frame0.clone(),
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    Ok(())
}

pub(crate) fn exec_threads<T: proc::Target>(
    session: &Session<'_, T>,
    verbose: bool,
    frames: Option<usize>,
    lwps: &[u32],
    registers: bool,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    // Resolve the selection before any work, so an lwp the target does
    // not hold says so rather than printing nothing — and without first
    // paying for (or warning about) the unwind below.
    for &tid in lwps {
        if !session.lwps.iter().any(|l| l.tid == tid) {
            return Err(no_such_thread(session.lwps.len(), tid));
        }
    }

    // The bare command is the table; anything that asks after one
    // thread's insides — a named lwp, a frame budget, registers —
    // asks for the block form.
    if !(verbose || registers || frames.is_some() || !lwps.is_empty()) {
        return print_thread_table(rows(session), out);
    }
    let frames = frames.unwrap_or(50);

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
    let mut selected: Vec<&proc::LwpInfo> = session
        .lwps
        .iter()
        .filter(|l| lwps.is_empty() || lwps.contains(&l.tid))
        .collect();
    selected.sort_by_key(|l| l.tid);
    for (i, lwp) in selected.into_iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        // A thread holding no tokio context has only its stack to
        // show; everything below the heading is the runtime's.
        let Some(worker) = session.workers.iter().find(|w| w.tid == lwp.tid) else {
            let took = fatal_tag(fatal.as_ref(), lwp.tid);
            writeln!(out, "lwp {}  no runtime{took}", lwp.tid)?;
            if shows_registers(registers, fatal.as_ref(), lwp.tid) {
                crate::registers::print_lwp_registers(session, lwp.tid, "  ", out)?;
            }
            match stacks.get(&lwp.tid) {
                Some(backtrace) => {
                    writeln!(out, "  stack:")?;
                    for line in backtrace.stack_trace(frames) {
                        writeln!(out, "    {line}")?;
                    }
                }
                None => writeln!(out, "  stack: unavailable")?,
            }
            continue;
        };
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

/// The error for an lwp the target does not hold. It counts the lwps
/// there are rather than naming them — `threads` is the listing, and
/// on a real target it is long.
fn no_such_thread(lwps: usize, tid: u32) -> anyhow::Error {
    anyhow::anyhow!("no lwp {tid} ({})", summary::counted(lwps, "lwp"))
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
fn polling<T: proc::Target>(session: &Session<'_, T>, worker: &bundle::Worker) -> String {
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
fn print_thread_context<T: proc::Target>(
    session: &Session<'_, T>,
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
fn print_rendered<T: proc::Target>(
    session: &Session<'_, T>,
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

fn scheduler_state<'b, T: proc::Target>(
    session: &Session<'b, T>,
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
fn print_worker_state<'b, T: proc::Target>(
    session: &Session<'_, T>,
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
fn print_block_on_state<'b, T: proc::Target>(
    session: &Session<'_, T>,
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
fn print_checked_in_core<T: proc::Target>(
    session: &Session<'_, T>,
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
pub(crate) fn render<'r, 'b, T: proc::Target>(
    session: &'r Session<'b, T>,
    value: &'r Value<'b>,
    opts: RenderOpts,
    heap: Option<&'r dyn reify::Heap>,
) -> reify::DisplayValue<'r, 'b, T> {
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
    use super::{
        ParkState, blocking_role, fatal_tag, headline, no_such_thread, park_word, polling_line,
    };

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

    /// An lwp the target does not hold counts the ones it does, since
    /// the number asked for came from somewhere else.
    #[test]
    fn test_an_unlisted_lwp_counts_the_listed_ones() {
        assert_eq!(no_such_thread(2, 9).to_string(), "no lwp 9 (2 lwps)");
        assert_eq!(no_such_thread(1, 9).to_string(), "no lwp 9 (1 lwp)");
    }
    /// One spelling per state the parker reports, the poll the task
    /// listing believes winning over all of them, and an unreadable
    /// parker saying so rather than borrowing a state.
    #[test]
    fn test_the_worker_role_spellings() {
        assert_eq!(park_word(Some(ParkState::Awake), true), "polling");
        assert_eq!(park_word(None, true), "polling");
        assert_eq!(park_word(Some(ParkState::Awake), false), "awake");
        assert_eq!(park_word(Some(ParkState::Condvar), false), "parked");
        assert_eq!(park_word(Some(ParkState::Driver), false), "in driver");
        assert_eq!(park_word(Some(ParkState::Notified), false), "notified");
        assert_eq!(
            park_word(Some(ParkState::Unknown(7)), false),
            "park state unread"
        );
        assert_eq!(park_word(None, false), "park state unread");
    }

    /// A blocking-pool thread is known by its stack — `Inner::run`
    /// below, a park above when idle — and no other stack, absent
    /// ones included, testifies at all.
    #[test]
    fn test_the_blocking_role_is_read_from_the_stack() {
        let names = |list: &[&str]| -> Vec<String> { list.iter().map(|s| s.to_string()).collect() };
        let idle = names(&[
            "__lwp_park",
            "cond_wait_queue",
            "std::thread::park",
            "tokio::runtime::blocking::pool::Inner::run",
            "std::sys::pal::unix::thread::Thread::new::thread_start",
        ]);
        assert_eq!(blocking_role(&idle), Some("blocking, idle"));

        let running = names(&[
            "memcpy",
            "app::compress",
            "tokio::runtime::blocking::pool::Inner::run",
        ]);
        assert_eq!(blocking_role(&running), Some("blocking, running"));

        // A worker parks through the same condvars without ever being
        // the pool's; nothing below says Inner::run, so nothing is
        // claimed.
        let worker = names(&["__lwp_park", "cond_wait_queue", "worker::run"]);
        assert_eq!(blocking_role(&worker), None);
        assert_eq!(blocking_role(&[]), None);

        // Each parked spelling testifies alone — the two systems park
        // through different symbols, and no capture shows them all.
        for park in [
            "std::thread::park",
            "cond_wait_queue",
            "__lwp_park",
            "futex_wait",
        ] {
            let idle = names(&[park, "tokio::runtime::blocking::pool::Inner::run"]);
            assert_eq!(blocking_role(&idle), Some("blocking, idle"), "{park}");
        }
    }

    /// The headline is the top three symbols and no more; a stack
    /// that could not be walked is a `—`, not an empty cell.
    #[test]
    fn test_the_headline_takes_three_frames() {
        let names: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        assert_eq!(headline(&names), "a \u{2190} b \u{2190} c");
        assert_eq!(headline(&names[..1]), "a");
        assert_eq!(headline(&[]), "—");
    }
}

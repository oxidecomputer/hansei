//! The session cursor: one selected position in the target — an lwp,
//! a chain root, a frame within that root's await chain — that every
//! single-target command falls back to when given no target, and that
//! the selectors (`task`, `future`, `thread`, `frame`, `up`, `down`)
//! move.
//!
//! One cursor, three coordinates: `lwp ⊃ chain root ⊃ frame`. The
//! root is a task wherever a task can claim the position — a `future`
//! that some task holds collapses to that task at the holding frame —
//! and a lone `Future` root exists only for the chains no task
//! contains. Listings never read the cursor; only the selectors and
//! `frame`/`up`/`down` move it, and `$_` — the current frame's base
//! address — moves with it and with nothing else.

use crate::tasks::{self, no_such_task};
use crate::{RenderFlags, Session, TraceOpts, TraceTarget, output, threads, trace};

use anyhow::{Result, anyhow};
use hansei_bundle::names;
use hansei_runtime::tokio::{Lifecycle, bundle, census};
use reify::Value;

use std::io;

/// Where the session is positioned. `Default` is no cursor at all —
/// the state every session starts in.
#[derive(Clone, Copy, Default)]
pub struct Cursor {
    /// The selected lwp: set by `thread`, and by `task` when the task
    /// is mid-poll on one; cleared when `task` selects an idle task.
    pub lwp: Option<u32>,
    /// The chain root: the task, or the lone future no task contains.
    pub root: Option<TraceTarget>,
    /// The frame within the root's await chain.
    pub frame: usize,
    /// `$_`: the base address of the current frame's future — the
    /// task's stage at frame #0, a lone root's own address, the lwp's
    /// stack pointer for a thread cursor with no task.
    pub last_addr: Option<u64>,
}

/// The prompt's account of the cursor: `hansei : task 129 #1`,
/// `hansei : future 0xf7d9670 #0`, `hansei : lwp 115` (only when no
/// root stands), bare `hansei` with no cursor — the separator marks
/// where the tool's name ends and the position begins.
pub(crate) fn prompt_label(c: &Cursor) -> String {
    match (c.root, c.lwp) {
        (Some(TraceTarget::Task(id)), _) => format!("hansei : task {id} #{}", c.frame),
        (Some(TraceTarget::Future(addr)), _) => {
            format!("hansei : future {addr:#x} #{}", c.frame)
        }
        (None, Some(lwp)) => format!("hansei : lwp {lwp}"),
        (None, None) => "hansei".to_string(),
    }
}

/// `task`: select one, or print the cursor's.
pub(crate) fn exec_task<T: proc::Target>(
    session: &Session<'_, T>,
    target: Option<TraceTarget>,
    verbose: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let index = match target {
        Some(target) => select_task(session, target)?,
        None => cursor_task(session).ok_or_else(|| anyhow!("no task selected"))?,
    };
    match verbose {
        true => tasks::print_task_block(session, index, out),
        false => Ok(writeln!(out, "{}", tasks::row_line(session, index))?),
    }
}

/// The task the cursor stands on, if its root is one: a `Task` root,
/// or a `Future` root that is really a task's allocation (an id-less
/// task is rooted by its header address).
pub(crate) fn cursor_task<T: proc::Target>(session: &Session<'_, T>) -> Option<usize> {
    match session.cursor.borrow().root? {
        TraceTarget::Task(id) => task_index(session, id).ok(),
        TraceTarget::Future(addr) => session.extents().locate(addr).map(|(index, _)| index),
    }
}

fn task_index<T: proc::Target>(session: &Session<'_, T>, id: u64) -> Result<usize> {
    session
        .tasks
        .tasks
        .iter()
        .position(|t| t.task_id == Some(id))
        .ok_or_else(|| no_such_task(&session.tasks, id))
}

/// Move the cursor to a task: by id at frame #0, or by an address
/// inside its allocation at the frame that claims the address
/// (`whatis` semantics). Selecting a running task selects the lwp
/// polling it; selecting an idle one clears any thread cursor.
pub(crate) fn select_task<T: proc::Target>(
    session: &Session<'_, T>,
    target: TraceTarget,
) -> Result<usize> {
    let list = &session.tasks;
    let index = match target {
        TraceTarget::Task(id) => task_index(session, id)?,
        TraceTarget::Future(addr) => session
            .extents()
            .locate(addr)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                anyhow!(
                    "{addr:#x} is in no task's allocation; if it is a lone \
                     future, `future {addr:#x}`"
                )
            })?,
    };
    let task = &list.tasks[index];
    let root = task_root(task);
    let (frame, last_addr) = match session.ctx.task_stage(task).ok() {
        Some(bundle::TaskStage::Running(future)) => match target {
            // An address deeper than the header lands on the deepest
            // chain frame containing it, the way `whatis` attributes
            // it; the header (and anything no frame claims) is #0.
            TraceTarget::Future(addr) if addr != task.addr.0 => {
                let chain = session.ctx.await_chain(future);
                match claiming_frame(&chain, addr) {
                    Some(i) => (i, chain.frames[i].future.addr),
                    None => (0, future.addr),
                }
            }
            _ => (0, future.addr),
        },
        // A complete task has no stage to stand on; its allocation is
        // still an address worth having in hand.
        _ => (0, task.addr.0),
    };
    *session.cursor.borrow_mut() = Cursor {
        lwp: polling_worker(&session.workers, task),
        root: Some(root),
        frame,
        last_addr: Some(last_addr),
    };
    Ok(index)
}

/// How a task roots the cursor: by id, or — for a task the target
/// records no id for — by its header address, which every address
/// command resolves back to it.
fn task_root(task: &bundle::Task) -> TraceTarget {
    match task.task_id {
        Some(id) => TraceTarget::Task(id),
        None => TraceTarget::Future(task.addr.0),
    }
}

/// The worker whose `current_task_id` names a still-running task —
/// apart from the session for the suites, since no fixture capture
/// holds a mid-poll task.
fn polling_worker(workers: &[bundle::Worker], task: &bundle::Task) -> Option<u32> {
    if task.state.lifecycle() != Lifecycle::Running {
        return None;
    }
    let id = task.task_id?;
    workers
        .iter()
        .find(|w| w.current_task_id == Some(id))
        .map(|w| w.tid)
}

/// The deepest chain frame whose future's bytes contain `addr` — the
/// frames nest by value, so the deepest containing frame is the one
/// that claims the address.
fn claiming_frame(chain: &bundle::AwaitChain<'_>, addr: u64) -> Option<usize> {
    chain
        .frames
        .iter()
        .enumerate()
        .rev()
        .find(|(_, f)| f.future.addr <= addr && addr < f.future.addr + f.future.ty.size())
        .map(|(i, _)| i)
}

/// `future`: select a lone future, or print the cursor's.
pub(crate) fn exec_future<T: proc::Target>(
    session: &Session<'_, T>,
    addr: Option<u64>,
    verbose: bool,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let Some(addr) = addr else {
        // Bare `future` reprints the cursor's lone future. A `Future`
        // root inside a task's allocation is a task cursor in address
        // clothing (an id-less task), not a lone future.
        let addr = match session.cursor.borrow().root {
            Some(TraceTarget::Future(addr)) if session.extents().locate(addr).is_none() => addr,
            _ => return Err(anyhow!("no future selected")),
        };
        if verbose {
            return print_root_chain(session, theme, out);
        }
        writeln!(out, "{}", future_line(session, addr)?)?;
        return Ok(());
    };
    // The selection line is the one line either way — whether the
    // address stayed a lone root or collapsed to the task holding it.
    select_future(session, addr, out)?;
    if verbose {
        return print_root_chain(session, theme, out);
    }
    Ok(())
}

/// Move the cursor to the future at `addr`, printing the one line of
/// what was selected. An address some task holds collapses to that
/// task at the holding frame — one cursor, never two; only a chain no
/// task contains (a set child in its heap node) roots as a future.
pub(crate) fn select_future<T: proc::Target>(
    session: &Session<'_, T>,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let census = session.census();
    let list = &session.tasks;
    let found = trace::future_at(
        &session.ctx.view,
        list,
        session.extents(),
        census,
        &session.impl_fold,
        addr,
    )?;
    match found {
        trace::FutureAt::Held(i) => {
            let h = &census.held[i];
            writeln!(
                out,
                "future {:#x}: {} — held by {} (frame #{})",
                h.addr,
                names::display_future_name(&h.future, &session.impl_fold),
                tasks::task_label(list, h.owner),
                h.frame,
            )?;
            let task = &list.tasks[h.owner];
            // $_ is the holding frame's own base, not the held
            // future's: the cursor stands on the frame.
            let last_addr = frame_base(session, task, h.frame).unwrap_or(h.addr);
            *session.cursor.borrow_mut() = Cursor {
                lwp: polling_worker(&session.workers, task),
                root: Some(task_root(task)),
                frame: h.frame,
                last_addr: Some(last_addr),
            };
        }
        trace::FutureAt::Child { set, child } => {
            let s = &census.sets[set];
            let c = &s.children[child];
            let root = c
                .root
                .expect("future_at returns only children still in flight");
            let future = match &c.future {
                Some(future) => names::display_future_name(future, &session.impl_fold),
                None => "<undecoded>".to_string(),
            };
            writeln!(
                out,
                "future {:#x}: {future} — child of {} polled by {}",
                root.addr,
                names::fold_type_name(&s.ty, &session.impl_fold),
                tasks::task_label(list, s.owner),
            )?;
            *session.cursor.borrow_mut() = Cursor {
                lwp: None,
                root: Some(TraceTarget::Future(root.addr)),
                frame: 0,
                last_addr: Some(root.addr),
            };
        }
    }
    Ok(())
}

/// Frame `n`'s base address in a task's chain, where the task has
/// one. Frame #0 is the stage itself, no chain walk needed — what
/// keeps a per-task scope (`tasks --exec`) cheap.
fn frame_base<T: proc::Target>(
    session: &Session<'_, T>,
    task: &bundle::Task,
    n: usize,
) -> Option<u64> {
    match session.ctx.task_stage(task).ok()? {
        bundle::TaskStage::Running(future) if n == 0 => Some(future.addr),
        bundle::TaskStage::Running(future) => {
            let chain = session.ctx.await_chain(future);
            chain.frames.get(n).map(|f| f.future.addr)
        }
        _ => None,
    }
}

/// Scope the cursor to one task at frame #0 — what `tasks --exec`
/// sets before each surviving task's run, so the command's omitted
/// target and `$_` are that task's.
pub(crate) fn scope_to<T: proc::Target>(session: &Session<'_, T>, index: usize) {
    let task = &session.tasks.tasks[index];
    let last_addr = frame_base(session, task, 0).unwrap_or(task.addr.0);
    *session.cursor.borrow_mut() = Cursor {
        lwp: polling_worker(&session.workers, task),
        root: Some(task_root(task)),
        frame: 0,
        last_addr: Some(last_addr),
    };
}

/// The one-line spelling of a lone future, by asking the census what
/// the address is.
fn future_line<T: proc::Target>(session: &Session<'_, T>, addr: u64) -> Result<String> {
    let census = session.census();
    let found = trace::future_at(
        &session.ctx.view,
        &session.tasks,
        session.extents(),
        census,
        &session.impl_fold,
        addr,
    )?;
    Ok(match found {
        trace::FutureAt::Held(i) => {
            let h = &census.held[i];
            format!(
                "future {:#x}: {}",
                h.addr,
                names::display_future_name(&h.future, &session.impl_fold)
            )
        }
        trace::FutureAt::Child { set, child } => {
            let c = &census.sets[set].children[child];
            let future = match &c.future {
                Some(future) => names::display_future_name(future, &session.impl_fold),
                None => "<undecoded>".to_string(),
            };
            format!("future {addr:#x}: {future}")
        }
    })
}

/// The cursor root's chain, printed the way `trace` prints it.
fn print_root_chain<T: proc::Target>(
    session: &Session<'_, T>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let root = session
        .cursor
        .borrow()
        .root
        .ok_or_else(|| anyhow!("no future selected"))?;
    let render = RenderFlags::default().resolve(&session.settings.borrow());
    let elide = reify::ElideOverride::default();
    let heap = session.heap_view();
    let opts = TraceOpts {
        verbose: false,
        render,
        elide: &elide,
        theme,
        heap: heap.as_ref().map(|view| view as &dyn reify::Heap),
    };
    trace::exec_trace(session, root, &opts, out)
}

/// `thread`: select an lwp, or print the cursor's.
pub(crate) fn exec_thread<T: proc::Target>(
    session: &Session<'_, T>,
    lwp: Option<u32>,
    verbose: bool,
    frames: Option<usize>,
    registers: bool,
    render: crate::RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let tid = match lwp {
        Some(tid) => {
            select_thread(session, tid)?;
            tid
        }
        None => session
            .cursor
            .borrow()
            .lwp
            .ok_or_else(|| anyhow!("no thread selected"))?,
    };
    if verbose || registers || frames.is_some() {
        return threads::exec_threads(session, true, frames, &[tid], registers, render, out);
    }
    let line = threads::row_line(session, tid)
        .ok_or_else(|| threads::no_such_thread(session.lwps.len(), tid))?;
    writeln!(out, "{line}")?;
    Ok(())
}

/// Move the cursor to an lwp: the thread, and the task it is polling
/// if any — a thread polling nothing leaves no root, and the
/// task-taking commands answer `no task selected` until `task` moves
/// on. `$_` becomes the polled task's stage, else the lwp's stack
/// pointer.
pub(crate) fn select_thread<T: proc::Target>(session: &Session<'_, T>, tid: u32) -> Result<()> {
    if !session.lwps.iter().any(|l| l.tid == tid) {
        return Err(threads::no_such_thread(session.lwps.len(), tid));
    }
    let worker = session.workers.iter().find(|w| w.tid == tid);
    let polled = worker.and_then(|w| tasks::polled_task(w.current_task_id, &session.tasks));
    let (root, last_addr) = match polled {
        Some(id) => {
            let index = task_index(session, id).expect("polled_task returns owned ids");
            let task = &session.tasks.tasks[index];
            let base = frame_base(session, task, 0).unwrap_or(task.addr.0);
            (Some(TraceTarget::Task(id)), Some(base))
        }
        None => (
            None,
            session
                .lwps
                .iter()
                .find(|l| l.tid == tid)
                .map(|l| l.regs.rsp),
        ),
    };
    *session.cursor.borrow_mut() = Cursor {
        lwp: Some(tid),
        root,
        frame: 0,
        last_addr,
    };
    Ok(())
}

/// `frame`: move within the root's await chain, or — with no index —
/// print the current frame the way `trace -v` prints one. `verbose`
/// selects between that full block and the bare frame line `up` and
/// `down` land with.
pub(crate) fn exec_frame<T: proc::Target>(
    session: &Session<'_, T>,
    index: Option<usize>,
    verbose: bool,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let cursor = *session.cursor.borrow();
    let root = cursor.root.ok_or_else(|| anyhow!("no task selected"))?;
    let resolved = chain_of(session, root)?;
    let n = index.unwrap_or(cursor.frame);
    if n >= resolved.chain.frames.len() {
        return Err(refuse_frame(
            n,
            resolved.chain.frames.len(),
            mid_poll(
                &session.tasks.tasks[resolved.owner],
                resolved.origin,
                &session.workers,
            ),
        ));
    }
    if index.is_some() {
        let mut c = session.cursor.borrow_mut();
        c.frame = n;
        c.last_addr = Some(resolved.chain.frames[n].future.addr);
    }
    print_cursor_frame(session, &resolved, n, verbose, theme, out)
}

/// `up`: one frame outward, toward #0, the chain's root, landing with
/// the frame line alone — `up locals` asks for more.
pub(crate) fn exec_up<T: proc::Target>(
    session: &Session<'_, T>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let frame = cursor_frame(session)?;
    if frame == 0 {
        return Err(anyhow!("already at frame #0, the chain's root"));
    }
    exec_frame(session, Some(frame - 1), false, theme, out)
}

/// `down`: one frame inward, toward the leaf, landing with the frame
/// line alone — `down locals` asks for more.
pub(crate) fn exec_down<T: proc::Target>(
    session: &Session<'_, T>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let frame = cursor_frame(session)?;
    exec_frame(session, Some(frame + 1), false, theme, out)
}

/// `locals`: list the variables the cursor frame holds live — the
/// live state's locals, or a plain leaf future's own fields — each
/// rendered the way a verbose `trace` renders it, flat at the margin.
pub(crate) fn exec_locals<T: proc::Target>(
    session: &Session<'_, T>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let cursor = *session.cursor.borrow();
    let root = cursor.root.ok_or_else(|| anyhow!("no task selected"))?;
    let resolved = chain_of(session, root)?;
    let frames = &resolved.chain.frames;
    let n = cursor.frame;
    let Some(frame) = frames.get(n) else {
        return Err(refuse_frame(
            n,
            frames.len(),
            mid_poll(
                &session.tasks.tasks[resolved.owner],
                resolved.origin,
                &session.workers,
            ),
        ));
    };
    // What the frame can be read as: the active variant of its future,
    // whose members are the locals, or the future itself where no
    // state decodes.
    let payload = match &frame.state {
        Some(state) => state.payload,
        None => frame.future,
    };
    let render = RenderFlags::default().resolve(&session.settings.borrow());
    let elide = reify::ElideOverride::default();
    let heap = session.heap_view();
    let opts = TraceOpts {
        verbose: false,
        render,
        elide: &elide,
        theme,
        heap: heap.as_ref().map(|view| view as &dyn reify::Heap),
    };
    let extents = session.extents();
    let census = session.census();
    let list = &session.tasks;
    let annotate = move |ptr: u64| {
        if let Some((index, _)) = extents.locate(ptr) {
            return Some(tasks::task_label(list, index));
        }
        let (set, _, _) = census.locate(ptr)?;
        Some(format!(
            "{} via FuturesUnordered",
            tasks::task_label(list, census.sets[set].owner)
        ))
    };
    let count = trace::print_locals(
        &session.ctx,
        payload,
        "",
        &opts,
        Some(&annotate as &reify::AddrAnnotator<'_>),
        out,
    )?;
    if count == 0 {
        writeln!(out, "no locals")?;
    }
    Ok(())
}

fn cursor_frame<T: proc::Target>(session: &Session<'_, T>) -> Result<usize> {
    let cursor = session.cursor.borrow();
    match cursor.root {
        Some(_) => Ok(cursor.frame),
        None => Err(anyhow!("no task selected")),
    }
}

/// A cursor root's chain, with the coordinates the census records it
/// under — what the frame printer's holds tally and annotations key on.
pub(crate) struct ResolvedChain<'b> {
    pub(crate) chain: bundle::AwaitChain<'b>,
    /// The owning task's index in the task list.
    owner: usize,
    /// `None` for a task's own chain; the held-future or set-child
    /// origin for a lone root's.
    origin: Option<census::Via>,
}

/// Resolve the cursor root to its await chain. A `Future` root inside
/// a task's allocation is that task's chain (an id-less task roots by
/// its header address); one outside every task is asked of the census
/// the way `trace 0x…` asks.
pub(crate) fn chain_of<'b, T: proc::Target>(
    session: &Session<'b, T>,
    root: TraceTarget,
) -> Result<ResolvedChain<'b>> {
    let task_chain = |index: usize| -> Result<ResolvedChain<'b>> {
        let task = &session.tasks.tasks[index];
        match session.ctx.task_stage(task)? {
            bundle::TaskStage::Running(future) => Ok(ResolvedChain {
                chain: session.ctx.await_chain(future),
                owner: index,
                origin: None,
            }),
            bundle::TaskStage::Finished(_) | bundle::TaskStage::Consumed => {
                Err(anyhow!("no await chain ({})", task.state.lifecycle()))
            }
        }
    };
    match root {
        TraceTarget::Task(id) => task_chain(task_index(session, id)?),
        TraceTarget::Future(addr) => {
            if let Some((index, _)) = session.extents().locate(addr) {
                return task_chain(index);
            }
            let census = session.census();
            let found = trace::future_at(
                &session.ctx.view,
                &session.tasks,
                session.extents(),
                census,
                &session.impl_fold,
                addr,
            )?;
            let (root, owner, origin) = match found {
                trace::FutureAt::Held(i) => {
                    let h = &census.held[i];
                    (
                        census::FutureRoot {
                            addr: h.addr,
                            ty: h.ty,
                        },
                        h.owner,
                        census::Via::Held(i),
                    )
                }
                trace::FutureAt::Child { set, child } => {
                    let s = &census.sets[set];
                    let c = &s.children[child];
                    (
                        c.root
                            .expect("future_at returns only children still in flight"),
                        s.owner,
                        census::Via::SetChild { set, child },
                    )
                }
            };
            let ty =
                session.ctx.view.ty(root.ty).ok_or_else(|| {
                    anyhow!("the census recorded a type the bundle does not carry")
                })?;
            let value = Value::read(session.ctx.proc, ty, root.addr)
                .map_err(|e| anyhow!("failed to read the future at {:#x}: {e}", root.addr))?;
            Ok(ResolvedChain {
                chain: session.ctx.await_chain(value),
                owner,
                origin: Some(origin),
            })
        }
    }
}

/// Whether the chain's owner is mid-poll — the case where an index
/// past the chain lands in the native continuation `trace` numbers on
/// from it — and, if so, the lwp whose stack shows it.
/// Apart from the session for the suites, since no fixture capture
/// holds a mid-poll task.
fn mid_poll(
    task: &bundle::Task,
    origin: Option<census::Via>,
    workers: &[bundle::Worker],
) -> Option<Option<u32>> {
    (origin.is_none() && task.state.lifecycle() == Lifecycle::Running)
        .then(|| polling_worker(workers, task))
}

/// The refusal an out-of-range frame index earns: a running task's
/// native continuation is a traditional debugger's territory and is
/// named as such; anything else is measured against the chain.
fn refuse_frame(n: usize, len: usize, mid_poll: Option<Option<u32>>) -> anyhow::Error {
    if let Some(lwp) = mid_poll {
        let threads = match lwp {
            Some(lwp) => format!("threads {lwp}"),
            None => "threads".to_string(),
        };
        return anyhow!("frame #{n} is a native frame; `{threads}` shows it");
    }
    anyhow!(
        "no frame #{n}: the chain has {}",
        crate::summary::counted(len, "frame")
    )
}

/// Print one frame the way `trace -v` prints it: the `#N` line, its
/// detail — the leaf's is the wait target — and the locals.
fn print_cursor_frame<T: proc::Target>(
    session: &Session<'_, T>,
    resolved: &ResolvedChain<'_>,
    n: usize,
    verbose: bool,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let chain = &resolved.chain;
    let render = RenderFlags::default().resolve(&session.settings.borrow());
    let elide = reify::ElideOverride::default();
    let heap = session.heap_view();
    let opts = TraceOpts {
        verbose,
        render,
        elide: &elide,
        theme,
        heap: heap.as_ref().map(|view| view as &dyn reify::Heap),
    };
    let wait = match Some(n) == chain.frames.len().checked_sub(1) {
        true => trace::wait_line(&session.ctx, chain, &session.tasks)?,
        false => None,
    };
    let holds = trace::frame_holds(
        session.census(),
        resolved.owner,
        resolved.origin,
        chain.frames.len(),
    );
    let extents = session.extents();
    let census = session.census();
    let list = &session.tasks;
    let annotate = move |ptr: u64| {
        if let Some((index, _)) = extents.locate(ptr) {
            return Some(tasks::task_label(list, index));
        }
        let (set, _, _) = census.locate(ptr)?;
        Some(format!(
            "{} via FuturesUnordered",
            tasks::task_label(list, census.sets[set].owner)
        ))
    };
    trace::print_frame(
        &session.ctx,
        chain,
        n,
        trace::chain_num_width(chain),
        wait.as_deref(),
        &holds,
        &opts,
        &session.impl_fold,
        Some(&annotate as &reify::AddrAnnotator<'_>),
        out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline::session_args;
    use crate::{Session, dispatch, repl};

    use hansei_runtime::testkit;

    /// The prompt spells each cursor state its own way, and the lwp
    /// shows only when no root stands.
    #[test]
    fn test_the_prompt_spells_the_cursor() {
        let c = |lwp, root, frame| Cursor {
            lwp,
            root,
            frame,
            last_addr: None,
        };
        assert_eq!(prompt_label(&c(None, None, 0)), "hansei");
        assert_eq!(prompt_label(&c(Some(115), None, 0)), "hansei : lwp 115");
        assert_eq!(
            prompt_label(&c(None, Some(TraceTarget::Task(129)), 1)),
            "hansei : task 129 #1"
        );
        // A thread cursor that also holds a task shows the task; the
        // lwp is not lost, merely not the headline.
        assert_eq!(
            prompt_label(&c(Some(115), Some(TraceTarget::Task(129)), 0)),
            "hansei : task 129 #0"
        );
        assert_eq!(
            prompt_label(&c(None, Some(TraceTarget::Future(0xf7d9670)), 0)),
            "hansei : future 0xf7d9670 #0"
        );
    }

    /// The out-of-range refusals: a running task's native continuation
    /// is named as native (with the lwp where one is known), anything
    /// else is measured against the chain.
    #[test]
    fn test_the_frame_refusals_name_what_stands_past_the_chain() {
        assert_eq!(
            refuse_frame(6, 3, Some(Some(115))).to_string(),
            "frame #6 is a native frame; `threads 115` shows it"
        );
        assert_eq!(
            refuse_frame(6, 3, Some(None)).to_string(),
            "frame #6 is a native frame; `threads` shows it"
        );
        assert_eq!(
            refuse_frame(9, 4, None).to_string(),
            "no frame #9: the chain has 4 frames"
        );
    }

    /// `print $_` with no type defaults to the cursor frame; a thread
    /// cursor has no frame, and the refusal says what `$_` is there.
    #[test]
    fn test_print_last_addr_defaults_only_at_a_frame() {
        let (bundle, snapshot) = testkit::load("linux", "nested-await");
        let args = session_args("linux", "nested-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let render = || crate::RenderOpts {
            depth: 3,
            ugly: false,
            max_string_len: 64,
            max_array_values: 8,
        };

        let lwp = session.lwps.first().expect("lwps recorded").tid;
        select_thread(&session, lwp).expect("the lwp selects");
        assert!(
            session.cursor.borrow().root.is_none(),
            "a parked capture polls nothing"
        );
        let dollar = || vec!["$_".to_string()];
        let err = crate::print::exec_print(&session, &dollar(), render(), &mut Vec::new())
            .expect_err("no frame, no default type");
        assert!(err.to_string().contains("stack pointer"), "{err}");

        let id = session
            .tasks
            .tasks
            .first()
            .and_then(|t| t.task_id)
            .expect("the fixture's tasks carry ids");
        select_task(&session, TraceTarget::Task(id)).expect("the task selects");
        let mut out = Vec::new();
        crate::print::exec_print(&session, &dollar(), render(), &mut out)
            .expect("the frame is the default");
        assert!(!out.is_empty());
        // The default is the frame itself: identical to bare `print`.
        let mut bare = Vec::new();
        crate::print::exec_print(&session, &[], render(), &mut bare).expect("bare print");
        assert_eq!(out, bare);
    }

    /// The selectors over a fixture pair: `task` roots the cursor and
    /// stamps `$_`, an address inside the task selects the same task,
    /// one outside every task points at `future`, `thread` selects the
    /// lwp (and no task on a parked capture), and `task` again clears
    /// it. A listing moves nothing.
    #[test]
    fn test_the_selectors_move_the_cursor() {
        let (bundle, snapshot) = testkit::load("linux", "nested-await");
        let args = session_args("linux", "nested-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let task = session
            .tasks
            .tasks
            .first()
            .expect("the fixture owns a task");
        let id = task.task_id.expect("the fixture's tasks carry ids");

        let mut out = Vec::new();
        exec_task(&session, Some(TraceTarget::Task(id)), false, &mut out)
            .expect("a task id selects");
        {
            let c = session.cursor.borrow();
            assert!(matches!(c.root, Some(TraceTarget::Task(i)) if i == id));
            assert_eq!(c.frame, 0);
            assert_eq!(c.lwp, None, "an idle task selects no lwp");
            assert!(c.last_addr.is_some(), "$_ stands after a selection");
        }
        let addr = session.cursor.borrow().last_addr.expect("$_ stands");

        // Any address inside the allocation selects the same task.
        exec_task(
            &session,
            Some(TraceTarget::Future(task.addr.0)),
            false,
            &mut Vec::new(),
        )
        .expect("the header address selects");
        assert!(matches!(
            session.cursor.borrow().root,
            Some(TraceTarget::Task(i)) if i == id
        ));

        // An address outside every task refuses toward `future`.
        let err = exec_task(
            &session,
            Some(TraceTarget::Future(0x10)),
            false,
            &mut Vec::new(),
        )
        .expect_err("a wild address refuses");
        assert_eq!(
            err.to_string(),
            "0x10 is in no task's allocation; if it is a lone future, `future 0x10`"
        );

        // A listing consults nothing and moves nothing.
        let command = repl::parse_line("tasks").expect("tasks parses");
        dispatch(
            &session,
            command,
            crate::output::Theme::plain(),
            &mut Vec::new(),
        )
        .expect("tasks lists");
        assert_eq!(session.cursor.borrow().last_addr, Some(addr));

        // The omitted target falls back to the cursor: a bare trace
        // is the selected task's.
        let command = repl::parse_line("trace").expect("trace parses");
        let mut traced = Vec::new();
        dispatch(
            &session,
            command,
            crate::output::Theme::plain(),
            &mut traced,
        )
        .expect("a bare trace answers under a cursor");
        let traced = String::from_utf8(traced).expect("trace output is UTF-8");
        assert!(traced.starts_with(&format!("Task {id}:")), "{traced}");

        // `whatis` falls back to `$_`.
        let command = repl::parse_line("whatis").expect("whatis parses");
        dispatch(
            &session,
            command,
            crate::output::Theme::plain(),
            &mut Vec::new(),
        )
        .expect("a bare whatis answers under a cursor");

        // `thread` selects the lwp; a parked capture polls nothing, so
        // no root comes with it and the task commands refuse.
        let lwp = session.lwps.first().expect("the fixture has lwps").tid;
        exec_thread(
            &session,
            Some(lwp),
            false,
            None,
            false,
            RenderFlags::default().resolve(&session.settings.borrow()),
            &mut Vec::new(),
        )
        .expect("an lwp selects");
        {
            let c = session.cursor.borrow();
            assert_eq!(c.lwp, Some(lwp));
            assert!(c.root.is_none(), "a parked lwp brings no task");
            assert!(c.last_addr.is_some(), "$_ is the lwp's stack pointer");
        }
        let command = repl::parse_line("trace").expect("trace parses");
        let err = dispatch(
            &session,
            command,
            crate::output::Theme::plain(),
            &mut Vec::new(),
        )
        .expect_err("a thread cursor with no task refuses the task commands");
        assert!(err.to_string().contains("no task selected"), "{err}");

        // `task` moves back and replaces the thread.
        exec_task(
            &session,
            Some(TraceTarget::Task(id)),
            false,
            &mut Vec::new(),
        )
        .expect("the task selects again");
        assert_eq!(session.cursor.borrow().lwp, None);
    }

    /// `frame` moves within the chain and `$_` moves with it; `up`
    /// refuses at the root, and an index past the chain names it.
    #[test]
    fn test_frame_moves_within_the_chain() {
        let (bundle, snapshot) = testkit::load("linux", "nested-await");
        let args = session_args("linux", "nested-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let id = session.tasks.tasks[0].task_id.expect("ids are recorded");
        exec_task(
            &session,
            Some(TraceTarget::Task(id)),
            false,
            &mut Vec::new(),
        )
        .expect("the task selects");
        let at_zero = session.cursor.borrow().last_addr;

        let theme = crate::output::Theme::plain();
        exec_frame(&session, Some(1), true, theme, &mut Vec::new()).expect("the chain nests");
        {
            let c = session.cursor.borrow();
            assert_eq!(c.frame, 1);
            assert_ne!(c.last_addr, at_zero, "$_ moved with the frame");
        }
        exec_up(&session, theme, &mut Vec::new()).expect("up moves toward the root");
        assert_eq!(session.cursor.borrow().frame, 0);
        let err = exec_up(&session, theme, &mut Vec::new()).expect_err("the root is the top");
        assert_eq!(err.to_string(), "already at frame #0, the chain's root");

        let err =
            exec_frame(&session, Some(99), true, theme, &mut Vec::new()).expect_err("out of range");
        assert!(err.to_string().starts_with("no frame #99: "), "{err}");
        assert_eq!(session.cursor.borrow().frame, 0, "a refusal moves nothing");

        exec_down(&session, theme, &mut Vec::new()).expect("down moves toward the leaf");
        assert_eq!(session.cursor.borrow().frame, 1);
    }

    /// A held future collapses to the task holding it, positioned at
    /// the holding frame — one cursor, never two.
    #[test]
    fn test_a_held_future_collapses_to_its_task() {
        let (bundle, snapshot) = testkit::load("linux", "futurelock");
        let args = session_args("linux", "futurelock");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let (addr, owner, frame) = {
            let census = session.census();
            let h = census.held.first().expect("futurelock holds a future");
            (h.addr, h.owner, h.frame)
        };
        let mut out = Vec::new();
        exec_future(
            &session,
            Some(addr),
            false,
            crate::output::Theme::plain(),
            &mut out,
        )
        .expect("a held future selects");
        let line = String::from_utf8(out).expect("the selection line is UTF-8");
        assert!(line.contains("held by"), "{line}");

        let c = *session.cursor.borrow();
        assert_eq!(c.frame, frame);
        let expected = crate::cursor::task_root(&session.tasks.tasks[owner]);
        match (c.root, expected) {
            (Some(TraceTarget::Task(a)), TraceTarget::Task(b)) => assert_eq!(a, b),
            (Some(TraceTarget::Future(a)), TraceTarget::Future(b)) => assert_eq!(a, b),
            other => panic!("the cursor did not collapse to the task: {other:?}"),
        }
        // `$_` is the holding frame's own base — the cursor stands on
        // the frame, not on the held future. Computed here from the
        // chain itself so nothing under test corroborates itself.
        let task = &session.tasks.tasks[owner];
        let stage = session.ctx.task_stage(task).expect("the stage reads");
        if let hansei_runtime::tokio::bundle::TaskStage::Running(future) = stage {
            let chain = session.ctx.await_chain(future);
            if let Some(f) = chain.frames.get(frame) {
                assert_eq!(c.last_addr, Some(f.future.addr));
            }
        }
    }

    /// A scoped prefix runs its command under a temporary cursor and
    /// puts the session's back; `$_` resolves against the scope, and
    /// the shell half of a line is never substituted.
    #[test]
    fn test_a_scoped_prefix_does_not_move_the_cursor() {
        let (bundle, snapshot) = testkit::load("linux", "sleep-join");
        let args = session_args("linux", "sleep-join");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let ids: Vec<u64> = session
            .tasks
            .tasks
            .iter()
            .filter_map(|t| t.task_id)
            .collect();
        assert!(ids.len() >= 2, "sleep-join spawns a second task: {ids:?}");

        // No cursor stands, and the `$_` sits after the `!`: it is the
        // shell's text, never substituted, so nothing refuses.
        repl::execute(&session, repl::Mode::Scripted, "set ! head -c 0 # $_")
            .expect("the shell half is never substituted");
        // The same token in the command half refuses without a cursor.
        let err = repl::execute(&session, repl::Mode::Scripted, "whatis $_ ! head -c 0")
            .expect_err("$_ without a cursor refuses");
        assert!(err.to_string().contains("no cursor"), "{err}");

        // Scope a command to another task: the session's cursor — root,
        // frame, `$_` — stays put.
        exec_task(
            &session,
            Some(TraceTarget::Task(ids[0])),
            false,
            &mut Vec::new(),
        )
        .expect("the first task selects");
        let mine = session.cursor.borrow().last_addr;
        repl::execute(
            &session,
            repl::Mode::Scripted,
            &format!("task {} trace ! head -c 0", ids[1]),
        )
        .expect("the scoped run answers");
        let c = *session.cursor.borrow();
        assert!(matches!(c.root, Some(TraceTarget::Task(i)) if i == ids[0]));
        assert_eq!(c.last_addr, mine);

        // `$_` inside the scope is the scoped task's — the command
        // answers — and the session's own `$_` still survives.
        repl::execute(
            &session,
            repl::Mode::Scripted,
            &format!("task {} whatis $_ ! head -c 0", ids[1]),
        )
        .expect("a scoped $_ resolves");
        assert_eq!(session.cursor.borrow().last_addr, mine);
    }

    /// `tasks --exec` scopes each run to its task, so any command with
    /// an omitted target — not just trace — answers per task.
    #[test]
    fn test_exec_scopes_every_omitted_target() {
        let (bundle, snapshot) = testkit::load("linux", "sleep-join");
        let args = session_args("linux", "sleep-join");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let command = repl::parse_line("tasks --exec whatis").expect("the exec line parses");
        let mut out = Vec::new();
        dispatch(&session, command, crate::output::Theme::plain(), &mut out)
            .expect("whatis answers under every task's scope");
        let text = String::from_utf8(out).expect("output is UTF-8");
        assert!(text.contains(", 0 failed"), "{text}");
        // And the loop leaves no cursor behind.
        assert!(session.cursor.borrow().root.is_none());
    }

    /// `task 0x…` lands on the frame that claims the address: each
    /// chain frame's own base selects that frame, and a byte the
    /// inner frame's span has ended before belongs to the outer one.
    #[test]
    fn test_an_interior_address_lands_on_the_claiming_frame() {
        let (bundle, snapshot) = testkit::load("linux", "nested-await");
        let args = session_args("linux", "nested-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let task = &session.tasks.tasks[0];
        let stage = session.ctx.task_stage(task).expect("the stage reads");
        let hansei_runtime::tokio::bundle::TaskStage::Running(future) = stage else {
            panic!("the fixture's task is suspended mid-chain");
        };
        let chain = session.ctx.await_chain(future);
        assert!(chain.frames.len() >= 2, "nested-await nests");
        let f0 = chain.frames[0].future.addr;
        let f0_end = f0 + chain.frames[0].future.ty.size();
        let f1 = chain.frames[1].future.addr;
        let f1_end = f1 + chain.frames[1].future.ty.size();

        exec_task(
            &session,
            Some(TraceTarget::Future(f1)),
            false,
            &mut Vec::new(),
        )
        .expect("an inner frame's base selects");
        {
            let c = session.cursor.borrow();
            assert_eq!(c.frame, 1, "the inner frame claims its own base");
            assert_eq!(c.last_addr, Some(f1));
        }
        exec_task(
            &session,
            Some(TraceTarget::Future(f0)),
            false,
            &mut Vec::new(),
        )
        .expect("the root frame's base selects");
        {
            let c = session.cursor.borrow();
            assert_eq!(c.frame, 0);
            assert_eq!(c.last_addr, Some(f0), "$_ is the stage, not the header");
        }
        // A byte past the inner frame but inside the outer one is the
        // outer frame's.
        if f1_end < f0_end {
            exec_task(
                &session,
                Some(TraceTarget::Future(f1_end)),
                false,
                &mut Vec::new(),
            )
            .expect("a byte past the inner frame selects");
            assert_eq!(session.cursor.borrow().frame, 0);
        }
    }

    /// Bare `task` prints the task the cursor stands on — whichever
    /// one was selected, not a fixed row.
    #[test]
    fn test_bare_task_prints_the_cursor_task() {
        let (bundle, snapshot) = testkit::load("linux", "sleep-join");
        let args = session_args("linux", "sleep-join");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let ids: Vec<u64> = session
            .tasks
            .tasks
            .iter()
            .filter_map(|t| t.task_id)
            .collect();
        assert!(ids.len() >= 2, "sleep-join spawns a second task");
        for &id in ids.iter().take(2) {
            exec_task(
                &session,
                Some(TraceTarget::Task(id)),
                false,
                &mut Vec::new(),
            )
            .expect("the task selects");
            let mut out = Vec::new();
            exec_task(&session, None, false, &mut out).expect("bare task prints the cursor's");
            let line = String::from_utf8(out).expect("the row is UTF-8");
            assert!(line.starts_with(&id.to_string()), "{id}: {line}");
            // The row's five cells, double-space joined: a
            // single-group target carries no RT cell.
            assert_eq!(line.trim_end().split("  ").count(), 5, "{line}");
        }

        // `-v` prints the cursor task's full block.
        let mut out = Vec::new();
        exec_task(&session, None, true, &mut out).expect("bare task -v prints the block");
        let block = String::from_utf8(out).expect("the block is UTF-8");
        assert!(block.contains("Task "), "{block}");
    }

    /// A set child roots as a lone future: its selection line prints
    /// once, bare `future` reprints it, and a task cursor answers `no
    /// future selected`.
    #[test]
    fn test_bare_future_prints_only_a_lone_root() {
        let (bundle, snapshot) = testkit::load("linux", "unordered");
        let args = session_args("linux", "unordered");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();
        let addr = {
            let census = session.census();
            let set = census.sets.first().expect("unordered drives a set");
            let child = set
                .children
                .iter()
                .find(|c| c.root.is_some())
                .expect("a child is in flight");
            child.root.expect("checked above").addr
        };

        let mut out = Vec::new();
        exec_future(&session, Some(addr), false, theme, &mut out).expect("a set child selects");
        let sel = String::from_utf8(out).expect("the selection line is UTF-8");
        assert!(sel.contains("child of"), "{sel}");
        assert_eq!(sel.lines().count(), 1, "one selection line only: {sel}");

        let mut out = Vec::new();
        exec_future(&session, None, false, theme, &mut out).expect("bare future reprints it");
        let line = String::from_utf8(out).expect("the line is UTF-8");
        assert!(line.starts_with(&format!("future {addr:#x}:")), "{line}");

        // `-v` prints the chain rather than the one line.
        let mut out = Vec::new();
        exec_future(&session, None, true, theme, &mut out).expect("future -v prints the chain");
        assert!(!out.is_empty(), "the chain prints");

        let id = session
            .tasks
            .tasks
            .iter()
            .find_map(|t| t.task_id)
            .expect("ids are recorded");
        exec_task(
            &session,
            Some(TraceTarget::Task(id)),
            false,
            &mut Vec::new(),
        )
        .expect("a task selects");
        let err = exec_future(&session, None, false, theme, &mut Vec::new())
            .expect_err("a task cursor holds no lone future");
        assert_eq!(err.to_string(), "no future selected");
    }

    /// The polling join, apart from a session: only a task the
    /// runtime still calls running names an lwp, and only through the
    /// worker whose current word matches its id.
    #[test]
    fn test_only_a_running_task_names_the_lwp_polling_it() {
        use hansei_runtime::tokio::bundle::{FutureInfo, Task, Worker};
        use hansei_runtime::tokio::{TaskAddr, TaskState};

        let task = |state: u64, task_id: Option<u64>| Task {
            addr: TaskAddr(0x2000),
            state: TaskState(state),
            owner_id: None,
            task_id,
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            group: 0,
            blocking: false,
        };
        let worker = |tid, current_task_id| Worker {
            tid,
            context_addr: 0,
            current_task_id,
        };
        let workers = [worker(7, Some(41)), worker(9, Some(42))];
        // RUNNING is bit 0 of the state word.
        assert_eq!(polling_worker(&workers, &task(0b1, Some(42))), Some(9));
        // Idle: a stale current word is not a poll in progress.
        assert_eq!(polling_worker(&workers, &task(0, Some(42))), None);
        // Running with no recorded id: unknowable.
        assert_eq!(polling_worker(&workers, &task(0b1, None)), None);
        // Running but on no worker's current word.
        assert_eq!(polling_worker(&workers, &task(0b1, Some(1))), None);

        // The native-continuation question rides the same join: only a
        // task's own chain (no census origin) continues natively, and
        // only while the owner is mid-poll.
        assert_eq!(
            mid_poll(&task(0b1, Some(42)), None, &workers),
            Some(Some(9))
        );
        assert_eq!(
            mid_poll(&task(0b1, Some(42)), Some(census::Via::Held(0)), &workers),
            None,
            "a lone root's chain is never continued natively"
        );
        assert_eq!(mid_poll(&task(0, Some(42)), None, &workers), None);
        assert_eq!(
            mid_poll(&task(0b1, Some(1)), None, &workers),
            Some(None),
            "mid-poll on no known lwp still refuses as native"
        );
    }

    /// The thread selector: an unknown lwp refuses, the row names the
    /// selected lwp in the table's cells, `$_` is exactly its stack
    /// pointer, and each block-form flag asks for the block.
    #[test]
    fn test_thread_rows_and_blocks_spell_the_selected_lwp() {
        let (bundle, snapshot) = testkit::load("linux", "nested-await");
        let args = session_args("linux", "nested-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let lwp = session.lwps.first().expect("the fixture has lwps");
        let (tid, rsp) = (lwp.tid, lwp.regs.rsp);
        let render = RenderFlags::default().resolve(&session.settings.borrow());

        let err = exec_thread(
            &session,
            Some(999_999),
            false,
            None,
            false,
            render,
            &mut Vec::new(),
        )
        .expect_err("an unknown lwp refuses");
        assert!(err.to_string().starts_with("no lwp 999999"), "{err}");

        let mut out = Vec::new();
        exec_thread(&session, Some(tid), false, None, false, render, &mut out)
            .expect("the lwp selects");
        let line = String::from_utf8(out).expect("the row is UTF-8");
        assert!(line.starts_with(&tid.to_string()), "{line}");
        assert_eq!(line.trim_end().split("  ").count(), 5, "{line}");
        assert_eq!(session.cursor.borrow().last_addr, Some(rsp));

        for (verbose, frames, registers) in [
            (true, None, false),
            (false, Some(3), false),
            (false, None, true),
        ] {
            let mut out = Vec::new();
            exec_thread(
                &session,
                Some(tid),
                verbose,
                frames,
                registers,
                render,
                &mut out,
            )
            .expect("the block form answers");
            let text = String::from_utf8(out).expect("the block is UTF-8");
            assert!(text.contains("stack"), "{text}");
        }
    }

    /// `frame` prints the selected frame the way `trace -v` prints it:
    /// numbered, and — on the leaf — carrying the decoded wait target.
    #[test]
    fn test_frame_prints_like_trace() {
        let (bundle, snapshot) = testkit::load("linux", "sleep-join");
        let args = session_args("linux", "sleep-join");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();
        // A task whose chain nests and bottoms out in a decoded wait.
        let mut picked = None;
        for t in &session.tasks.tasks {
            let Some(id) = t.task_id else { continue };
            let Ok(resolved) = chain_of(&session, TraceTarget::Task(id)) else {
                continue;
            };
            if resolved.chain.frames.len() >= 2
                && trace::wait_line(&session.ctx, &resolved.chain, &session.tasks)
                    .ok()
                    .flatten()
                    .is_some()
            {
                picked = Some((id, resolved.chain.frames.len()));
                break;
            }
        }
        let (id, len) = picked.expect("sleep-join parks a chain on a decoded wait");
        exec_task(
            &session,
            Some(TraceTarget::Task(id)),
            false,
            &mut Vec::new(),
        )
        .expect("the task selects");

        let mut out = Vec::new();
        exec_frame(&session, Some(len - 1), true, theme, &mut out).expect("the leaf prints");
        let leaf = String::from_utf8(out).expect("the frame is UTF-8");
        assert!(leaf.starts_with(&format!("#{}", len - 1)), "{leaf}");
        assert!(leaf.contains("waiting on"), "{leaf}");

        let mut out = Vec::new();
        exec_frame(&session, Some(0), true, theme, &mut out).expect("the root prints");
        let root = String::from_utf8(out).expect("the frame is UTF-8");
        assert!(root.starts_with("#0"), "{root}");
        assert!(!root.contains("waiting on"), "{root}");
    }

    /// `locals` lists the cursor frame's live variables and only
    /// them — the values a verbose trace nests under the frame line,
    /// flat at the margin, with no frame line and no heading.
    #[test]
    fn test_locals_lists_the_cursor_frames_variables() {
        let (bundle, snapshot) = testkit::load("linux", "simple-await");
        let args = session_args("linux", "simple-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();

        let err = exec_locals(&session, theme, &mut Vec::new())
            .expect_err("no cursor stands, so there is no frame to list");
        assert_eq!(err.to_string(), "no task selected");

        // The frame the verbose-trace test pins the same locals under:
        // work's coroutine, parked in Suspend1 with `count` live.
        let mut found = None;
        for t in &session.tasks.tasks {
            let Some(id) = t.task_id else { continue };
            let Ok(resolved) = chain_of(&session, TraceTarget::Task(id)) else {
                continue;
            };
            for (i, f) in resolved.chain.frames.iter().enumerate() {
                if f.future.ty.name().contains("simple_await::work") {
                    found = Some((id, i));
                }
            }
        }
        let (id, i) = found.expect("the capture parks work's frame");
        exec_task(
            &session,
            Some(TraceTarget::Task(id)),
            false,
            &mut Vec::new(),
        )
        .expect("the task selects");
        exec_frame(&session, Some(i), true, theme, &mut Vec::new()).expect("the frame selects");

        let mut out = Vec::new();
        exec_locals(&session, theme, &mut out).expect("the locals list");
        let text = String::from_utf8(out).expect("the listing is UTF-8");
        assert!(text.contains("count: u32 = 3"), "{text}");
        assert!(!text.contains("no locals"), "{text}");
        assert!(!text.contains("locals:"), "{text}");
        assert!(!text.contains('#'), "{text}");
        let first = text.lines().next().expect("at least one local");
        assert!(!first.starts_with(' '), "{text}");
    }

    /// `print` renders the named type's bytes; a snapshot recorded the
    /// task header, so the read answers offline.
    #[test]
    fn test_print_renders_memory_as_the_named_type() {
        let (bundle, snapshot) = testkit::load("linux", "nested-await");
        let args = session_args("linux", "nested-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let addr = session.tasks.tasks[0].addr.0;
        let command = repl::parse_line(&format!("print {addr:#x} u64")).expect("print parses");
        let mut out = Vec::new();
        dispatch(&session, command, crate::output::Theme::plain(), &mut out)
            .expect("print answers");
        assert!(!out.is_empty(), "print writes the value");
    }

    /// A scope that does not select fails the command rather than
    /// silently running it under whatever cursor stood before.
    #[test]
    fn test_a_scope_that_does_not_select_fails_the_command() {
        let (bundle, snapshot) = testkit::load("linux", "sleep-join");
        let args = session_args("linux", "sleep-join");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let id = session
            .tasks
            .tasks
            .iter()
            .find_map(|t| t.task_id)
            .expect("ids are recorded");
        exec_task(
            &session,
            Some(TraceTarget::Task(id)),
            false,
            &mut Vec::new(),
        )
        .expect("a cursor stands");
        let err = repl::execute(
            &session,
            repl::Mode::Scripted,
            "task 999999 trace ! head -c 0",
        )
        .expect_err("a bad scope fails the command");
        assert!(err.to_string().contains("no task 999999"), "{err}");
    }
}

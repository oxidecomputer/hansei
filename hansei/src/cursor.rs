// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The session cursor: one selected position in the target — an lwp,
//! a chain root, a frame within that root's await chain — that every
//! single-target command falls back to when given no target, and that
//! the selectors (`task`, `future`, `thread`, `frame`, `up`, `down`)
//! move.
//!
//! One cursor, three coordinates: `lwp ⊃ chain root ⊃ frame`. The
//! root is one chain: a task's, or a future's own — a future some task
//! holds roots at itself, its chain ending at its own root frame, and
//! the holder is a separate selection rather than a frame above it.
//! Listings never read the cursor; only the selectors and
//! `frame`/`up`/`down` move it, and `$_` — the current frame's base
//! address — moves with it and with nothing else.

use crate::tasks::{self, no_such_task};
use crate::{RenderOpts, Session, TraceOpts, TraceTarget, futures, output, threads, trace};

use anyhow::{Result, anyhow};
use hansei_runtime::tokio::chain::InspectionMode;
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
    /// The census future a `Future` root was selected as. An address
    /// alone does not always name one: a future held as another's
    /// first member starts where its holder starts, so several finds
    /// print the same address, and resolving it again picks the
    /// innermost. Every command that falls back to the root asks this
    /// instead; `None` for a task root, and for a `Future` root at a
    /// task's header.
    pub future: Option<trace::FutureAt>,
    /// The frame within the root's await chain, numbered the way the
    /// listings display frames: #0 the most recently polled, counting
    /// outward to the root.
    pub frame: usize,
    /// `$_`: the base address of the current frame's future — the
    /// chain's leaf at selection (#0), a lone root's own address where
    /// its chain cannot be walked, the lwp's stack pointer for a thread
    /// cursor with no task.
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
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let index = match target {
        Some(target) => select_task(session, target)?,
        None => cursor_task(session).ok_or_else(|| anyhow!("no task selected"))?,
    };
    tasks::print_task(session, index, fit, out)
}

/// `children`: list the census's finds inside the cursor's root under
/// their counts — the task's, or the lone future's where the root is
/// one (the same root bare `future` reprints: a `Future` root that is
/// really a task's allocation is the task's). Under `futures --exec`
/// the root is the future itself, so the listing is the future's own,
/// as `trace` and `locals` are its own there.
pub(crate) fn exec_children<T: proc::Target>(
    session: &Session<'_, T>,
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let root = session.cursor.borrow().root;
    match root {
        Some(TraceTarget::Future(addr)) if !task_rooted(session, addr) => {
            futures::print_children(session, root_future(session, addr)?, fit, out)
        }
        _ => {
            let index =
                cursor_task(session).ok_or_else(|| anyhow!("no task or future selected"))?;
            tasks::print_children(session, index, fit, out)
        }
    }
}

/// The task the cursor's root belongs to: a `Task` root's own, or the
/// task a `Future` root sits in — its allocation for an id-less task
/// rooted at its header and for a future held inline in a frame, else
/// the census's owner for one held in a heap box or driven as a set
/// child. Under a future root this is the holder, which bare `task`
/// answers with, not a move.
pub(crate) fn cursor_task<T: proc::Target>(session: &Session<'_, T>) -> Option<usize> {
    match session.cursor.borrow().root? {
        TraceTarget::Task(id) => task_index(session, id).ok(),
        TraceTarget::Future(addr) => match session.extents().locate(addr) {
            Some((index, _)) => Some(index),
            None => {
                let census = session.census();
                match root_future(session, addr).ok()? {
                    trace::FutureAt::Held(i) => Some(census.held[i].owner),
                    trace::FutureAt::Child { set, .. } => Some(census.sets[set].owner),
                }
            }
        },
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

/// Move the cursor to a task: by id at frame #0 — the most recently
/// polled frame — or by an address inside its allocation at the frame
/// that claims the address (`whatis` semantics). Selecting a running
/// task selects the lwp polling it; selecting an idle one clears any
/// thread cursor.
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
    let (frame, last_addr) = match session.task_chain(task) {
        Some(chain) => {
            // Selection lands on the leaf — displayed #0, the most
            // recently polled frame. An address deeper than the header
            // lands on the deepest chain frame containing it, the way
            // `whatis` attributes it; anything no frame claims is #0.
            let leaf = (
                0,
                chain
                    .frames
                    .last()
                    .map(|f| f.future.addr)
                    .unwrap_or(task.addr.0),
            );
            match target {
                TraceTarget::Future(addr) if addr != task.addr.0 => {
                    match claiming_frame(&chain, addr) {
                        Some(i) => (chain.frames.len() - 1 - i, chain.frames[i].future.addr),
                        None => leaf,
                    }
                }
                _ => leaf,
            }
        }
        // A complete task has no stage to stand on; its allocation is
        // still an address worth having in hand.
        _ => (0, task.addr.0),
    };
    *session.cursor.borrow_mut() = Cursor {
        lwp: polling_worker(&session.workers, task),
        root: Some(root),
        future: None,
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

/// `future`: select a lone future, or print the cursor's — either way
/// the block `futures` tallies it in, with the census's finds inside
/// it, and under `verbose` its await chain after that.
pub(crate) fn exec_future<T: proc::Target>(
    session: &Session<'_, T>,
    addr: Option<u64>,
    verbose: bool,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let at = match addr {
        Some(addr) => select_future(session, addr)?,
        None => {
            // Bare `future` reprints the cursor's lone future. A
            // `Future` root inside a task's allocation is a task cursor
            // in address clothing (an id-less task), not a lone future.
            let addr = match session.cursor.borrow().root {
                Some(TraceTarget::Future(addr)) if !task_rooted(session, addr) => addr,
                _ => return Err(anyhow!("no future selected")),
            };
            root_future(session, addr)?
        }
    };
    futures::print_future(session, at, session.fit_width(theme), out)?;
    if verbose {
        print_root_chain(session, theme, out)?;
    }
    Ok(())
}

/// What the census says `addr` is.
fn future_at<T: proc::Target>(session: &Session<'_, T>, addr: u64) -> Result<trace::FutureAt> {
    trace::future_at(
        &session.ctx.view,
        &session.tasks,
        session.extents(),
        session.census(),
        &session.impl_fold,
        addr,
    )
}

/// The census future a `Future` root at `addr` stands for: the one the
/// cursor was scoped to, where it was scoped to one there, else what
/// the address resolves to. Only an omitted target is the root's — an
/// address typed out resolves afresh.
fn root_future<T: proc::Target>(session: &Session<'_, T>, addr: u64) -> Result<trace::FutureAt> {
    let pinned = session.cursor.borrow().future;
    match pinned {
        Some(at) if at.addr(session.census()) == addr => Ok(at),
        _ => future_at(session, addr),
    }
}

/// The cursor's pinned census future, when the root is one — what an
/// omitted `trace` target follows instead of resolving the root's
/// address again.
pub(crate) fn cursor_future<T: proc::Target>(session: &Session<'_, T>) -> Option<trace::FutureAt> {
    let cursor = *session.cursor.borrow();
    match (cursor.root, cursor.future) {
        (Some(TraceTarget::Future(addr)), Some(at)) if at.addr(session.census()) == addr => {
            Some(at)
        }
        _ => None,
    }
}

/// Move the cursor to the future at `addr`, answering what the census
/// says it is. The root is the future itself, at frame #0 of its own
/// chain, whether a task holds it or a set drives it: `trace`, `frame`
/// and `locals` then follow the future's chain and `$_` is its frame
/// #0's address, and the holder is one explicit `task` away — bare `task`
/// names it without moving. A set child roots at its node: that is the
/// address every listing prints for the child and every address command
/// resolves back to it, where the chain's own root — a boxed child's
/// heap referent — sits in no allocation the census can name.
pub(crate) fn select_future<T: proc::Target>(
    session: &Session<'_, T>,
    addr: u64,
) -> Result<trace::FutureAt> {
    let found = future_at(session, addr)?;
    scope_to_future(session, found);
    Ok(found)
}

/// Frame `n`'s base address in a task's chain, where the task has
/// one. `n` is display-numbered: #0 the most recently polled frame.
fn frame_base<T: proc::Target>(
    session: &Session<'_, T>,
    task: &bundle::Task,
    n: usize,
) -> Option<u64> {
    let chain = session.task_chain(task)?;
    let i = chain.frames.len().checked_sub(n + 1)?;
    chain.frames.get(i).map(|f| f.future.addr)
}

/// Scope the cursor to one task at frame #0 — the most recently
/// polled frame — what `tasks --exec` sets before each surviving
/// task's run, so the command's omitted target and `$_` are that
/// task's.
pub(crate) fn scope_to<T: proc::Target>(session: &Session<'_, T>, index: usize) {
    let task = &session.tasks.tasks[index];
    let last_addr = frame_base(session, task, 0).unwrap_or(task.addr.0);
    *session.cursor.borrow_mut() = Cursor {
        lwp: polling_worker(&session.workers, task),
        root: Some(task_root(task)),
        future: None,
        frame: 0,
        last_addr: Some(last_addr),
    };
}

/// Scope the cursor to one census future at frame #0 of its own chain
/// — what `future 0x…` selects, and what `futures --exec` sets before
/// each surviving future's run. The root is the future itself even
/// when a task holds it: `trace` under it follows the future's own
/// chain, and `$_` is frame #0's base — the leaf's, as a task selection
/// sets it, or the future's own address where its chain cannot be
/// walked. The lwp is the holding task's where it is mid-poll, as
/// selecting the task would set it.
pub(crate) fn scope_to_future<T: proc::Target>(session: &Session<'_, T>, at: trace::FutureAt) {
    let census = session.census();
    let (addr, lwp) = match at {
        trace::FutureAt::Held(i) => {
            let h = &census.held[i];
            (
                h.addr,
                polling_worker(&session.workers, &session.tasks.tasks[h.owner]),
            )
        }
        trace::FutureAt::Child { set, child } => (census.sets[set].children[child].node, None),
    };
    *session.cursor.borrow_mut() = Cursor {
        lwp,
        root: Some(TraceTarget::Future(addr)),
        future: Some(at),
        frame: 0,
        last_addr: Some(addr),
    };
    // The leaf is the chain's to say, and the chain is the root's just
    // set.
    if let Some(leaf) = chain_of(session, TraceTarget::Future(addr))
        .ok()
        .and_then(|resolved| resolved.chain.frames.last().map(|f| f.future.addr))
    {
        session.cursor.borrow_mut().last_addr = Some(leaf);
    }
}

/// Whether a `Future` root is a task's in address clothing: rooted at
/// the task's header, the way an id-less task roots and a `future`
/// selection collapses. Anything else — a set child's node, or a held
/// future's own address under `futures --exec` — is a chain the
/// census answers for, even where its bytes sit inside a task's
/// allocation.
fn task_rooted<T: proc::Target>(session: &Session<'_, T>, addr: u64) -> bool {
    matches!(session.extents().locate(addr), Some((_, 0)))
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
    let render = RenderOpts::from_settings(&session.settings.borrow());
    let heap = session.heap_view();
    let opts = TraceOpts {
        verbose: false,
        native: false,
        limit: None,
        render,
        theme,
        fit: session.fit_width(theme),
        heap: heap.as_ref().map(|view| view as &dyn reify::Heap),
        source: session.source_lines,
        context: None,
    };
    exec_trace_root(session, root, &opts, out)
}

/// Trace the cursor's `root`: the census future the cursor was scoped
/// to, where it was scoped to one, rather than whatever its address
/// resolves to afresh.
pub(crate) fn exec_trace_root<T: proc::Target>(
    session: &Session<'_, T>,
    root: TraceTarget,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    match cursor_future(session) {
        Some(at) => trace::exec_trace_at(session, at, opts, out),
        None => trace::exec_trace(session, root, opts, out),
    }
}

/// `thread`: select an lwp, or print the cursor's — either way the
/// block `threads` tallies it in: its tokio context and its scheduler
/// state.
pub(crate) fn exec_thread<T: proc::Target>(
    session: &Session<'_, T>,
    lwp: Option<u32>,
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
    threads::print_thread(session, tid, render, out)
}

/// Move the cursor to an lwp: the thread alone. No task root comes
/// with it — even for a thread mid-poll — so the task-taking commands
/// answer `no task selected` until `task` moves on, and a bare
/// `trace` walks the native stack; the hybrid trace is the task
/// cursor's. `$_` becomes the lwp's stack pointer.
pub(crate) fn select_thread<T: proc::Target>(session: &Session<'_, T>, tid: u32) -> Result<()> {
    let Some(lwp) = session.lwps.iter().find(|l| l.tid == tid) else {
        return Err(threads::no_such_thread(session.lwps.len(), tid));
    };
    *session.cursor.borrow_mut() = Cursor {
        lwp: Some(tid),
        root: None,
        future: None,
        frame: 0,
        last_addr: Some(lwp.regs.rsp),
    };
    Ok(())
}

/// `frame`: move within the root's await chain — or name the current
/// frame with no index — and print the frame line landed on. What
/// stands at the frame is the trailing command's to ask (`frame 7
/// locals`), the same way `up` and `down` compose.
pub(crate) fn exec_frame<T: proc::Target>(
    session: &Session<'_, T>,
    index: Option<usize>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let cursor = *session.cursor.borrow();
    let root = cursor.root.ok_or_else(|| anyhow!("no task selected"))?;
    let resolved = chain_of(session, root)?;
    let n = index.unwrap_or(cursor.frame);
    // The number is the displayed one — #0 the most recently polled —
    // and the chain is stored root first, so the index flips here.
    let Some(i) = resolved.chain.frames.len().checked_sub(n + 1) else {
        return Err(refuse_frame(n, resolved.chain.frames.len()));
    };
    if index.is_some() {
        let mut c = session.cursor.borrow_mut();
        c.frame = n;
        c.last_addr = Some(resolved.chain.frames[i].future.addr);
    }
    print_cursor_frame(session, &resolved, i, theme, out)
}

/// `up`: one frame outward, toward the chain's root — the bottom of
/// the listing — landing with the frame line alone; `up locals` asks
/// for more. A future's chain ends at its own root: the frame holding
/// it belongs to another chain, so the refusal there names the holder
/// and the `task` that selects it rather than crossing over.
pub(crate) fn exec_up<T: proc::Target>(
    session: &Session<'_, T>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let frame = cursor_frame(session)?;
    let root = session.cursor.borrow().root;
    let root = root.ok_or_else(|| anyhow!("no task selected"))?;
    let resolved = chain_of(session, root)?;
    if frame + 1 >= resolved.chain.frames.len() {
        let past = match resolved.origin {
            Some(via) => format!("; {}", past_the_root(session, resolved.owner, via)),
            None => String::new(),
        };
        return Err(anyhow!("already at frame #{frame}, the chain's root{past}"));
    }
    exec_frame(session, Some(frame + 1), theme, out)
}

/// What stands past a future's root frame, for the `up` refusal: the
/// task and frame holding it, or the set driving it, and the `task`
/// selection that moves there — by id, or by header address for an
/// id-less task.
fn past_the_root<T: proc::Target>(
    session: &Session<'_, T>,
    owner: usize,
    via: census::Via,
) -> String {
    let census = session.census();
    let task = &session.tasks.tasks[owner];
    let label = tasks::task_label(&session.tasks, owner);
    let select = match task.task_id {
        Some(id) => format!("`task {id}`"),
        None => format!("`task {:#x}`", task.addr.0),
    };
    match via {
        census::Via::Held(i) => {
            let h = &census.held[i];
            format!(
                "{label} holds this future at its frame #{} (`{}`), and {select} selects it",
                h.frame, h.local
            )
        }
        census::Via::SetChild { set, .. } => format!(
            "this future is a child of the set at {:#x}, which {label} drives, and {select} \
             selects it",
            census.sets[set].addr
        ),
    }
}

/// `down`: one frame inward, toward #0, the most recently polled
/// frame, landing with the frame line alone — `down locals` asks for
/// more.
pub(crate) fn exec_down<T: proc::Target>(
    session: &Session<'_, T>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let frame = cursor_frame(session)?;
    if frame == 0 {
        return Err(anyhow!(
            "already at frame #0, the most recently polled frame"
        ));
    }
    exec_frame(session, Some(frame - 1), theme, out)
}

/// `locals`: list the variables the cursor frame holds live — the
/// live state's locals, or a plain leaf future's own fields — each
/// rendered the way a verbose `trace` renders it, flat at the margin.
pub(crate) fn exec_locals<T: proc::Target>(
    session: &Session<'_, T>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let payload = frame_value(session)?;
    let render = RenderOpts::from_settings(&session.settings.borrow());
    let heap = session.heap_view();
    let opts = TraceOpts {
        verbose: false,
        native: false,
        limit: None,
        render,
        theme,
        fit: session.fit_width(theme),
        heap: heap.as_ref().map(|view| view as &dyn reify::Heap),
        source: session.source_lines,
        context: None,
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
    /// What the chain's leaf verifiably waits on, as its detail line
    /// prints it: the task's assessment for a task's own chain, the
    /// observed resource for a lone root's; `None` where the chain
    /// ends in no resource.
    pub(crate) wait: Option<String>,
}

/// Resolve the cursor root to its await chain. A `Future` root at a
/// task's header address is that task's chain (an id-less task roots
/// there); any other is the census future the cursor was scoped to,
/// else what the census says the address is, the way `trace 0x…` asks
/// — a held future's own chain, inside its task's allocation or not.
pub(crate) fn chain_of<'b, T: proc::Target>(
    session: &Session<'b, T>,
    root: TraceTarget,
) -> Result<ResolvedChain<'b>> {
    let task_chain = |index: usize| -> Result<ResolvedChain<'b>> {
        let task = &session.tasks.tasks[index];
        match session.read_with(|read| session.ctx.inspect_task(task, read))? {
            Some(inspection) => Ok(ResolvedChain {
                chain: inspection.chain,
                owner: index,
                origin: None,
                wait: trace::assessed_wait(session, index),
            }),
            None => Err(anyhow!("no await chain ({})", task.state.lifecycle())),
        }
    };
    match root {
        TraceTarget::Task(id) => task_chain(task_index(session, id)?),
        TraceTarget::Future(addr) => {
            if let Some((index, 0)) = session.extents().locate(addr) {
                return task_chain(index);
            }
            let census = session.census();
            let (root, owner, origin) = match root_future(session, addr)? {
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
            let (chain, wait) = session.read_with(|read| {
                let inspection = session
                    .ctx
                    .inspect_future(value, InspectionMode::Held, read);
                let wait = trace::observed_wait(&session.ctx, &inspection, &session.tasks, read);
                (inspection.chain, wait)
            });
            Ok(ResolvedChain {
                chain,
                owner,
                origin: Some(origin),
                wait,
            })
        }
    }
}

/// The refusal an out-of-range frame number earns, measured against
/// the chain. The native continuation is unnumbered, so no number a
/// listing printed can land past the chain.
/// What the cursor frame can be read as: the active variant of its
/// future, whose members are the locals, or the future itself where no
/// state decodes. Frame `#n` counts from the leaf, as `trace` numbers
/// them and `frame` selects them.
pub(crate) fn frame_value<'b, T: proc::Target>(
    session: &Session<'b, T>,
) -> Result<reify::Value<'b>> {
    let cursor = *session.cursor.borrow();
    let root = cursor.root.ok_or_else(|| anyhow!("no task selected"))?;
    let resolved = chain_of(session, root)?;
    let frames = &resolved.chain.frames;
    let n = cursor.frame;
    let Some(frame) = frames.len().checked_sub(n + 1).and_then(|i| frames.get(i)) else {
        return Err(refuse_frame(n, frames.len()));
    };
    Ok(match &frame.state {
        Some(state) => state.payload,
        None => frame.future,
    })
}

fn refuse_frame(n: usize, len: usize) -> anyhow::Error {
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
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let chain = &resolved.chain;
    let render = RenderOpts::from_settings(&session.settings.borrow());
    let heap = session.heap_view();
    let opts = TraceOpts {
        verbose: false,
        native: false,
        limit: None,
        render,
        theme,
        fit: session.fit_width(theme),
        heap: heap.as_ref().map(|view| view as &dyn reify::Heap),
        source: session.source_lines,
        context: None,
    };
    let wait = match Some(n) == chain.frames.len().checked_sub(1) {
        true => resolved.wait.as_deref(),
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
        wait,
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
            future: None,
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

    /// The out-of-range refusal is measured against the chain: the
    /// native continuation is unnumbered, so no number a listing
    /// printed can land past it.
    #[test]
    fn test_the_frame_refusals_name_what_stands_past_the_chain() {
        assert_eq!(
            refuse_frame(9, 4).to_string(),
            "no frame #9: the chain has 4 frames"
        );
        assert_eq!(
            refuse_frame(1, 1).to_string(),
            "no frame #1: the chain has 1 frame"
        );
    }

    /// The selectors over a fixture pair: `task` roots the cursor and
    /// stamps `$_`, an address inside the task selects the same task,
    /// one outside every task points at `future`, `thread` selects the
    /// lwp (and no task on a parked capture), and `task` again clears
    /// it. A listing moves nothing.
    #[test]
    fn test_the_selectors_move_the_cursor() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "nested-await");
        let args = session_args(testkit::set_or_any("linux"), "nested-await");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let task = session
            .tasks
            .tasks
            .first()
            .expect("the fixture owns a task");
        let id = task.task_id.expect("the fixture's tasks carry ids");

        let mut out = Vec::new();
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut out)
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
            None,
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
            None,
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
        assert!(
            traced.lines().any(|line| line.starts_with("#0")),
            "{traced}"
        );

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
            RenderOpts::from_settings(&session.settings.borrow()),
            &mut Vec::new(),
        )
        .expect("an lwp selects");
        {
            let c = session.cursor.borrow();
            assert_eq!(c.lwp, Some(lwp));
            assert!(c.root.is_none(), "a parked lwp brings no task");
            assert!(c.last_addr.is_some(), "$_ is the lwp's stack pointer");
        }
        // A bare `trace` under the taskless thread cursor answers
        // with the lwp's native backtrace rather than refusing.
        let command = repl::parse_line("trace").expect("trace parses");
        let mut walked = Vec::new();
        dispatch(
            &session,
            command,
            crate::output::Theme::plain(),
            &mut walked,
        )
        .expect("a bare trace answers under a thread cursor");
        let walked = String::from_utf8(walked).expect("trace output is UTF-8");
        assert!(
            walked.starts_with(&format!("lwp {lwp} native stack:")),
            "{walked}"
        );

        // `task` moves back and replaces the thread.
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
            .expect("the task selects again");
        assert_eq!(session.cursor.borrow().lwp, None);
    }

    /// `frame` moves within the chain and `$_` moves with it; `up`
    /// refuses at the root, and an index past the chain names it.
    #[test]
    fn test_frame_moves_within_the_chain() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "nested-await");
        let args = session_args(testkit::set_or_any("linux"), "nested-await");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let id = session.tasks.tasks[0].task_id.expect("ids are recorded");
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
            .expect("the task selects");
        let at_zero = session.cursor.borrow().last_addr;
        let len = chain_of(&session, TraceTarget::Task(id))
            .expect("the chain resolves")
            .chain
            .frames
            .len();
        assert!(len >= 2, "nested-await nests");

        let theme = crate::output::Theme::plain();
        exec_frame(&session, Some(1), theme, &mut Vec::new()).expect("the chain nests");
        {
            let c = session.cursor.borrow();
            assert_eq!(c.frame, 1);
            assert_ne!(c.last_addr, at_zero, "$_ moved with the frame");
        }
        exec_down(&session, theme, &mut Vec::new()).expect("down moves toward the leaf");
        assert_eq!(session.cursor.borrow().frame, 0);
        let err = exec_down(&session, theme, &mut Vec::new()).expect_err("the leaf is the front");
        assert_eq!(
            err.to_string(),
            "already at frame #0, the most recently polled frame"
        );

        let err = exec_frame(&session, Some(99), theme, &mut Vec::new()).expect_err("out of range");
        assert!(err.to_string().starts_with("no frame #99: "), "{err}");
        assert_eq!(session.cursor.borrow().frame, 0, "a refusal moves nothing");

        exec_up(&session, theme, &mut Vec::new()).expect("up moves toward the root");
        assert_eq!(session.cursor.borrow().frame, 1);
        exec_frame(&session, Some(len - 1), theme, &mut Vec::new()).expect("the root selects");
        let err = exec_up(&session, theme, &mut Vec::new()).expect_err("the root is the bottom");
        assert_eq!(
            err.to_string(),
            format!("already at frame #{}, the chain's root", len - 1)
        );
    }

    /// A held future roots the cursor at itself — frame #0 of its own
    /// chain, `$_` that frame's address (the chain's leaf, as a task
    /// selection sets it), the prompt naming it — and the
    /// holder is one explicit `task` away: bare `task` prints the
    /// holder's block without moving, and `up` past the future's root
    /// refuses, naming the holding frame and the selection, rather
    /// than crossing into the holder's chain.
    #[test]
    fn test_a_held_future_roots_the_cursor() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "futurelock");
        let args = session_args(testkit::set_or_any("linux"), "futurelock");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();
        let (addr, owner, frame, local) = {
            let census = session.census();
            let h = census.held.first().expect("futurelock holds a future");
            (h.addr, h.owner, h.frame, h.local.clone())
        };
        let mut out = Vec::new();
        exec_future(&session, Some(addr), false, theme, &mut out).expect("a held future selects");
        let block = String::from_utf8(out).expect("the block is UTF-8");
        assert!(block.starts_with(&format!("future {addr:#x}\n")), "{block}");
        assert!(block.contains("\n    held by: "), "{block}");

        let leaf = chain_of(&session, TraceTarget::Future(addr))
            .expect("the future's chain resolves")
            .chain
            .frames
            .last()
            .map(|f| f.future.addr)
            .expect("the chain has a frame");
        assert_ne!(leaf, addr, "the chain runs deeper than its root");
        let at_root = |c: &Cursor| {
            matches!(c.root, Some(TraceTarget::Future(a)) if a == addr)
                && c.frame == 0
                && c.last_addr == Some(leaf)
        };
        let c = *session.cursor.borrow();
        assert!(
            at_root(&c),
            "{:?} #{} $_={:?}",
            c.root,
            c.frame,
            c.last_addr
        );
        assert_eq!(prompt_label(&c), format!("hansei : future {addr:#x} #0"));

        // Bare `task` answers with the holder; the cursor stays.
        let id = session.tasks.tasks[owner]
            .task_id
            .expect("the holder has an id");
        let mut out = Vec::new();
        exec_task(&session, None, None, &mut out).expect("bare task prints the holder");
        let text = String::from_utf8(out).expect("the block is UTF-8");
        assert!(text.starts_with(&format!("task {id}\n")), "{text}");
        assert!(at_root(&session.cursor.borrow()));

        // `up` walks the future's own chain to its root and refuses
        // there, naming what stands past it and the move that goes.
        let len = chain_of(&session, TraceTarget::Future(addr))
            .expect("the future's chain resolves")
            .chain
            .frames
            .len();
        for _ in 1..len {
            exec_up(&session, theme, &mut Vec::new()).expect("up moves within the chain");
        }
        let err = exec_up(&session, theme, &mut Vec::new()).expect_err("the root is the end");
        assert_eq!(
            err.to_string(),
            format!(
                "already at frame #{}, the chain's root; task {id} holds this future at its \
                 frame #{frame} (`{local}`), and `task {id}` selects it",
                len - 1
            )
        );
        assert!(matches!(
            session.cursor.borrow().root,
            Some(TraceTarget::Future(a)) if a == addr
        ));
        // And the explicit move lands on the holder as ever.
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
            .expect("the holder selects");
        assert!(matches!(
            session.cursor.borrow().root,
            Some(TraceTarget::Task(t)) if t == id
        ));
    }

    /// A future held in a heap box sits in no task's allocation, so the
    /// holder is the census's to name: bare `task` under such a root
    /// still answers with the task holding it.
    #[test]
    fn test_bare_task_names_the_holder_of_a_boxed_future() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "watch-stream");
        let args = session_args(testkit::set_or_any("linux"), "watch-stream");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let (addr, owner) = {
            let census = session.census();
            let h = census
                .held
                .iter()
                .find(|h| session.extents().locate(h.addr).is_none())
                .expect("watch-stream holds a boxed future");
            (h.addr, h.owner)
        };
        exec_future(
            &session,
            Some(addr),
            false,
            crate::output::Theme::plain(),
            &mut Vec::new(),
        )
        .expect("the boxed future selects");
        assert_eq!(cursor_task(&session), Some(owner));
        let id = session.tasks.tasks[owner]
            .task_id
            .expect("the holder has an id");
        let mut out = Vec::new();
        exec_task(&session, None, None, &mut out).expect("bare task prints the holder");
        let text = String::from_utf8(out).expect("the block is UTF-8");
        assert!(text.starts_with(&format!("task {id}\n")), "{text}");
    }

    /// A scoped prefix runs its command under a temporary cursor and
    /// puts the session's back; `$_` resolves against the scope, and
    /// the shell half of a line is never substituted.
    #[test]
    fn test_a_scoped_prefix_does_not_move_the_cursor() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "sleep-join");
        let args = session_args(testkit::set_or_any("linux"), "sleep-join");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let ids: Vec<u64> = session
            .tasks
            .tasks
            .iter()
            .filter_map(|t| t.task_id)
            .collect();
        assert!(ids.len() >= 2, "sleep-join spawns a second task: {ids:?}");

        // No cursor stands, and the `$_` sits after the `!`: it is the
        // shell's text, never substituted, so nothing refuses.
        repl::execute(&session, repl::Mode::Scripted, "config ! head -c 0 # $_")
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
            None,
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
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "sleep-join");
        let args = session_args(testkit::set_or_any("linux"), "sleep-join");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
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
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "nested-await");
        let args = session_args(testkit::set_or_any("linux"), "nested-await");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let task = &session.tasks.tasks[0];
        let chain = session
            .task_chain(task)
            .expect("the fixture's task is suspended mid-chain");
        assert!(chain.frames.len() >= 2, "nested-await nests");
        let f0 = chain.frames[0].future.addr;
        let f0_end = f0 + chain.frames[0].future.ty.size();
        let f1 = chain.frames[1].future.addr;
        let f1_end = f1 + chain.frames[1].future.ty.size();

        exec_task(
            &session,
            Some(TraceTarget::Future(f1)),
            None,
            &mut Vec::new(),
        )
        .expect("an inner frame's base selects");
        {
            let c = session.cursor.borrow();
            assert_eq!(
                c.frame,
                chain.frames.len() - 2,
                "the inner frame claims its own base"
            );
            assert_eq!(c.last_addr, Some(f1));
        }
        exec_task(
            &session,
            Some(TraceTarget::Future(f0)),
            None,
            &mut Vec::new(),
        )
        .expect("the root frame's base selects");
        {
            let c = session.cursor.borrow();
            assert_eq!(c.frame, chain.frames.len() - 1);
            assert_eq!(c.last_addr, Some(f0), "$_ is the stage, not the header");
        }
        // A byte past the inner frame but inside the outer one is the
        // outer frame's.
        if f1_end < f0_end {
            exec_task(
                &session,
                Some(TraceTarget::Future(f1_end)),
                None,
                &mut Vec::new(),
            )
            .expect("a byte past the inner frame selects");
            assert_eq!(session.cursor.borrow().frame, chain.frames.len() - 1);
        }
    }

    /// Bare `task` prints the task the cursor stands on — whichever
    /// one was selected, not a fixed row.
    #[test]
    fn test_bare_task_prints_the_cursor_task() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "sleep-join");
        let args = session_args(testkit::set_or_any("linux"), "sleep-join");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let ids: Vec<u64> = session
            .tasks
            .tasks
            .iter()
            .filter_map(|t| t.task_id)
            .collect();
        assert!(ids.len() >= 2, "sleep-join spawns a second task");
        for &id in ids.iter().take(2) {
            exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
                .expect("the task selects");
            let mut out = Vec::new();
            exec_task(&session, None, None, &mut out).expect("bare task prints the cursor's");
            let text = String::from_utf8(out).expect("the summary is UTF-8");
            assert!(text.starts_with(&format!("task {id}\n")), "{id}: {text}");
            // Under the heading, one labelled line per field, the state,
            // thread and type always there; a single-group target
            // carries no owner line.
            let labels: Vec<&str> = text
                .lines()
                .skip(1)
                .map(|line| line.trim_start())
                .map(|line| line.split_once(": ").map(|(l, _)| l).unwrap_or(line))
                .map(|label| label.trim_end_matches(':'))
                .collect();
            // Every line under the heading is set in four columns.
            assert!(
                text.lines().skip(1).all(|l| l.starts_with("    ")),
                "{text}"
            );
            assert!(labels.starts_with(&["state", "thread", "type"]), "{text}");
            assert!(!labels.contains(&"owner"), "{text}");
            // The selection carries the task's source anchors, its
            // wait, and the census's counts — the last always, since
            // their empty spellings are answers.
            assert!(text.contains("\n    spawned at: "), "{text}");
            assert!(text.contains("\n    type defined at: "), "{text}");
            assert!(labels.contains(&"awaiting on"), "{text}");
            assert!(labels.contains(&"held futures"), "{text}");
            assert!(labels.ends_with(&["held futures", "join sets"]), "{text}");
        }

        // `children` lists the finds under the counts, at the margin
        // and without the block: a task holding nothing prints the
        // two count rows and nothing more.
        let mut out = Vec::new();
        exec_children(&session, None, &mut out).expect("children prints under a task cursor");
        let listed = String::from_utf8(out).expect("the listing is UTF-8");
        assert_eq!(listed, "held futures: 0\njoin sets: 0\n");
    }

    /// A set child roots as a lone future, at the node address the
    /// listings print for it: its block prints on selection, bare
    /// `future` reprints it, and a task cursor answers `no future
    /// selected`.
    #[test]
    fn test_bare_future_prints_only_a_lone_root() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "unordered");
        let args = session_args(testkit::set_or_any("linux"), "unordered");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();
        let addr = {
            let census = session.census();
            let set = census.sets.first().expect("unordered drives a set");
            let child = set
                .children
                .iter()
                .find(|c| c.root.is_some())
                .expect("a child is in flight");
            child.node
        };

        let mut out = Vec::new();
        exec_future(&session, Some(addr), false, theme, &mut out).expect("a set child selects");
        let sel = String::from_utf8(out).expect("the block is UTF-8");
        assert!(sel.starts_with(&format!("future {addr:#x}\n")), "{sel}");
        // The fields sit four columns in, every one of them.
        assert!(sel.lines().skip(1).all(|l| l.starts_with("    ")), "{sel}");
        assert!(sel.contains("\n    child of: "), "{sel}");
        assert!(sel.contains("\n    depth: "), "{sel}");
        assert!(sel.ends_with("\n    join sets: 0\n"), "{sel}");

        let mut out = Vec::new();
        exec_future(&session, None, false, theme, &mut out).expect("bare future reprints it");
        let again = String::from_utf8(out).expect("the block is UTF-8");
        assert_eq!(again, sel, "bare future reprints the block");

        // `-v` prints the chain under the block.
        let mut out = Vec::new();
        exec_future(&session, None, true, theme, &mut out).expect("future -v prints the chain");
        let chained = String::from_utf8(out).expect("the chain is UTF-8");
        assert!(chained.starts_with(&sel), "{chained}");
        assert!(
            chained.len() > sel.len(),
            "the chain prints under the block"
        );

        let id = session
            .tasks
            .tasks
            .iter()
            .find_map(|t| t.task_id)
            .expect("ids are recorded");
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
            .expect("a task selects");
        let err = exec_future(&session, None, false, theme, &mut Vec::new())
            .expect_err("a task cursor holds no lone future");
        assert_eq!(err.to_string(), "no future selected");

        // A task rooted by its header address — the id-less spelling —
        // is a task cursor too, refused with the same words rather
        // than asked of the census.
        let header = session
            .tasks
            .tasks
            .iter()
            .find(|t| t.task_id == Some(id))
            .expect("the selected task is listed")
            .addr
            .0;
        *session.cursor.borrow_mut() = Cursor {
            root: Some(TraceTarget::Future(header)),
            ..Cursor::default()
        };
        let err = exec_future(&session, None, false, theme, &mut Vec::new())
            .expect_err("a header-rooted cursor holds no lone future");
        assert_eq!(err.to_string(), "no future selected");
    }

    /// `children` follows the cursor's root: under a lone future — a
    /// set child at its node — it lists what the census found inside
    /// that future, the tail of its block moved to the margin; under
    /// a task, by id or by the header address an id-less task roots
    /// at, the task's finds; and with no cursor it refuses.
    #[test]
    fn test_children_follows_the_cursor_root() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "unordered");
        let args = session_args(testkit::set_or_any("linux"), "unordered");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();

        let err = exec_children(&session, None, &mut Vec::new())
            .expect_err("no cursor holds nothing to list");
        assert_eq!(err.to_string(), "no task or future selected");

        // Every set child in flight holds one future of its own: the
        // block's tail says so under its counts, and `children` says
        // the same four columns to the left, and nothing else.
        let (node, driver) = {
            let census = session.census();
            let set = census.sets.first().expect("unordered drives a set");
            let child = set
                .children
                .iter()
                .find(|c| c.root.is_some())
                .expect("a child is in flight");
            (child.node, set.owner)
        };
        let mut out = Vec::new();
        exec_future(&session, Some(node), false, theme, &mut out).expect("a set child selects");
        let block = String::from_utf8(out).expect("the block is UTF-8");
        let mut out = Vec::new();
        exec_children(&session, None, &mut out).expect("children lists the lone future's finds");
        let listed = String::from_utf8(out).expect("the listing is UTF-8");
        assert!(
            listed.starts_with("held futures: 1\n    (frame 1, `held`): 0x"),
            "{listed}"
        );
        let tail: String = block
            .lines()
            .skip_while(|l| !l.starts_with("    held futures: "))
            .map(|l| format!("{}\n", &l[4..]))
            .collect();
        assert_eq!(listed, tail);

        // The task driving the set, selected by id, lists its own
        // finds — and rooted by its header address, the id-less
        // spelling, lists the same, rather than asking the census what
        // future the header is.
        let task = &session.tasks.tasks[driver];
        let id = task.task_id.expect("the driver has an id");
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
            .expect("the driver selects");
        let mut out = Vec::new();
        exec_children(&session, None, &mut out).expect("children lists the task's finds");
        let by_id = String::from_utf8(out).expect("the listing is UTF-8");
        assert!(by_id.starts_with("held futures: 7\n"), "{by_id}");
        assert!(by_id.contains("\njoin sets: 1 (3 futures)\n"), "{by_id}");
        *session.cursor.borrow_mut() = Cursor {
            root: Some(TraceTarget::Future(task.addr.0)),
            ..Cursor::default()
        };
        let mut out = Vec::new();
        exec_children(&session, None, &mut out).expect("a header-rooted cursor is the task's");
        let by_header = String::from_utf8(out).expect("the listing is UTF-8");
        assert_eq!(by_header, by_id);
    }

    /// The polling join, apart from a session: only a task the
    /// runtime still calls running names an lwp, and only through the
    /// worker whose current word matches its id.
    #[test]
    fn test_only_a_running_task_names_the_lwp_polling_it() {
        use hansei_runtime::tokio::bundle::{FutureInfo, OwnerResolution, Task, TaskKind, Worker};
        use hansei_runtime::tokio::{TaskAddr, TaskState};

        let task = |state: u64, task_id: Option<u64>| Task {
            addr: TaskAddr(0x2000),
            state: TaskState(state),
            owner_id: None,
            task_id,
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            kind: TaskKind::Async,
            owner: OwnerResolution::Unknown,
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
    }

    /// The thread selector: an unknown lwp refuses, the block's heading
    /// names the selected lwp, its fields sit four columns in, and
    /// `$_` is exactly its stack pointer.
    #[test]
    fn test_thread_blocks_spell_the_selected_lwp() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "nested-await");
        let args = session_args(testkit::set_or_any("linux"), "nested-await");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let lwp = session.lwps.first().expect("the fixture has lwps");
        let (tid, rsp) = (lwp.tid, lwp.regs.rsp);
        let render = RenderOpts::from_settings(&session.settings.borrow());

        let err = exec_thread(&session, Some(999_999), render, &mut Vec::new())
            .expect_err("an unknown lwp refuses");
        assert!(err.to_string().starts_with("no lwp 999999"), "{err}");

        let mut out = Vec::new();
        exec_thread(&session, Some(tid), render, &mut out).expect("the lwp selects");
        let text = String::from_utf8(out).expect("the block is UTF-8");
        assert!(text.starts_with(&format!("lwp {tid}  ")), "{text}");
        assert!(
            text.lines().skip(1).all(|l| l.starts_with("    ")),
            "{text}"
        );
        // The stack is `trace`'s under the cursor, not the block's.
        assert!(!text.contains("stack:"), "{text}");
        assert_eq!(session.cursor.borrow().last_addr, Some(rsp));
    }

    /// `frame` prints the selected frame's line the way a plain trace
    /// prints it: numbered, and — on the leaf — carrying the decoded
    /// wait target, with no locals block below it.
    #[test]
    fn test_frame_prints_the_bare_frame_line() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "sleep-join");
        let args = session_args(testkit::set_or_any("linux"), "sleep-join");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();
        // A task whose chain nests and bottoms out in a decoded wait.
        let mut picked = None;
        for t in &session.tasks.tasks {
            let Some(id) = t.task_id else { continue };
            let Ok(resolved) = chain_of(&session, TraceTarget::Task(id)) else {
                continue;
            };
            if resolved.chain.frames.len() >= 2 && resolved.wait.is_some() {
                picked = Some((id, resolved.chain.frames.len()));
                break;
            }
        }
        let (id, len) = picked.expect("sleep-join parks a chain on a decoded wait");
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
            .expect("the task selects");

        let mut out = Vec::new();
        exec_frame(&session, Some(0), theme, &mut out).expect("the leaf prints");
        let leaf = String::from_utf8(out).expect("the frame is UTF-8");
        assert!(leaf.starts_with("#0"), "{leaf}");
        assert!(leaf.contains("waiting on"), "{leaf}");

        let mut out = Vec::new();
        exec_frame(&session, Some(len - 1), theme, &mut out).expect("the root prints");
        let root = String::from_utf8(out).expect("the frame is UTF-8");
        assert!(root.starts_with(&format!("#{}", len - 1)), "{root}");
        assert!(!root.contains("waiting on"), "{root}");
    }

    /// `locals` lists the cursor frame's live variables and only
    /// them — the values a verbose trace nests under the frame line,
    /// flat at the margin, with no frame line and no heading.
    #[test]
    fn test_locals_lists_the_cursor_frames_variables() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "simple-await");
        let args = session_args(testkit::set_or_any("linux"), "simple-await");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
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
                    found = Some((id, resolved.chain.frames.len() - 1 - i));
                }
            }
        }
        let (id, i) = found.expect("the capture parks work's frame");
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
            .expect("the task selects");
        exec_frame(&session, Some(i), theme, &mut Vec::new()).expect("the frame selects");

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

    /// A scope that does not select fails the command rather than
    /// silently running it under whatever cursor stood before.
    #[test]
    fn test_a_scope_that_does_not_select_fails_the_command() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "sleep-join");
        let args = session_args(testkit::set_or_any("linux"), "sleep-join");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let id = session
            .tasks
            .tasks
            .iter()
            .find_map(|t| t.task_id)
            .expect("ids are recorded");
        exec_task(&session, Some(TraceTarget::Task(id)), None, &mut Vec::new())
            .expect("a cursor stands");
        let err = repl::execute(
            &session,
            repl::Mode::Scripted,
            "task 999999 trace ! head -c 0",
        )
        .expect_err("a bad scope fails the command");
        assert!(err.to_string().contains("no task 999999"), "{err}");
    }

    /// A cursor scoped to a future that shares its address with the
    /// future it holds — held as its first member — stays on that
    /// future: bare `future`, `children` and the chain are its own,
    /// although the address alone resolves to the inner one.
    #[test]
    fn test_a_scoped_future_is_not_resolved_again_by_address() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "unordered");
        let args = session_args(testkit::set_or_any("linux"), "unordered");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();
        let census = session.census();
        let size = |i: usize| session.ctx.view.ty(census.held[i].ty).map(|ty| ty.size());
        let (outer, inner) = (0..census.held.len())
            .flat_map(|o| (0..census.held.len()).map(move |i| (o, i)))
            .find(|&(o, i)| {
                o != i && census.held[o].addr == census.held[i].addr && size(o) > size(i)
            })
            .expect("unordered holds a future as another's first member");
        let addr = census.held[outer].addr;
        assert_eq!(
            future_at(&session, addr).expect("the address resolves"),
            trace::FutureAt::Held(inner),
            "the address alone names the inner future"
        );

        scope_to_future(&session, trace::FutureAt::Held(outer));
        assert_eq!(cursor_future(&session), Some(trace::FutureAt::Held(outer)));
        let chain = chain_of(&session, TraceTarget::Future(addr)).expect("the chain resolves");
        assert_eq!(
            chain.chain.frames[0].future.ty.id(),
            census.held[outer].ty,
            "the chain is the outer future's"
        );
        let mut out = Vec::new();
        exec_future(&session, None, false, theme, &mut out).expect("bare future prints");
        let block = String::from_utf8(out).expect("the block is UTF-8");
        assert!(block.contains("    held futures: 1\n"), "{block}");
        let mut out = Vec::new();
        exec_children(&session, None, &mut out).expect("children lists");
        let listing = String::from_utf8(out).expect("the listing is UTF-8");
        assert!(listing.starts_with("held futures: 1\n"), "{listing}");

        // A typed address resolves afresh, to the inner future.
        exec_future(&session, Some(addr), false, theme, &mut Vec::new())
            .expect("the typed address selects");
        assert_eq!(cursor_future(&session), Some(trace::FutureAt::Held(inner)));
    }

    /// The command a move carries reads `$_` at the frame the move
    /// landed on, not the one the cursor stood on when the line was
    /// typed: `frame 1 whatis $_` answers what `whatis` of frame #1's
    /// address does.
    #[test]
    fn test_a_moves_carried_command_reads_the_new_frame() {
        let (bundle, core) = testkit::load(testkit::set_or_any("linux"), "futurelock");
        let args = session_args(testkit::set_or_any("linux"), "futurelock");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let theme = crate::output::Theme::plain();
        let run = |line: &str| {
            let command = repl::parse_line(line).expect("the line parses");
            let mut out = Vec::new();
            dispatch(&session, command, theme, &mut out).expect("the line answers");
            String::from_utf8(out).expect("the output is UTF-8")
        };
        let (id, frames) = session
            .tasks
            .tasks
            .iter()
            .find_map(|task| {
                let frames: Vec<u64> = session
                    .task_chain(task)?
                    .frames
                    .iter()
                    .rev()
                    .map(|f| f.future.addr)
                    .collect();
                (frames.len() > 1 && frames[0] != frames[1]).then_some((task.task_id?, frames))
            })
            .expect("futurelock has a task two frames deep");

        run(&format!("task {id}"));
        let carried = run("frame 1 whatis $_");
        let direct = run(&format!("whatis {:#x}", frames[1]));
        assert!(carried.ends_with(&direct), "{carried}\n---\n{direct}");
        assert_ne!(direct, run(&format!("whatis {:#x}", frames[0])));
    }
}

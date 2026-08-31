//! The `trace` command: await chains rendered one line per future,
//! for a task by id or a lone future by address.

use crate::tasks::{future_name, no_such_task, task_label};
use crate::whatis::via_suffix;
use crate::{Session, TraceOpts, TraceTarget, output};

use anyhow::{Context as _, Result};
use hansei_bundle::names;
use hansei_bundle::{BundleMember, BundleType, BundleTypeId, BundleView, SymbolLookup};
use hansei_runtime::tokio::{Lifecycle, bundle, census, stackjoin};
use reify::Value;

use std::fmt;
use std::io::{self, Write};

pub(crate) fn exec_trace<T: proc::Target>(
    session: &Session<'_, T>,
    target: TraceTarget,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    match target {
        TraceTarget::Task(id) => exec_trace_task(session, id, opts, out),
        TraceTarget::Future(addr) => exec_trace_future(session, addr, opts, out),
    }
}

fn exec_trace_task<T: proc::Target>(
    session: &Session<'_, T>,
    task_id: u64,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    let list = &session.tasks;

    let Some((index, task)) = list
        .tasks
        .iter()
        .enumerate()
        .find(|(_, t)| t.task_id == Some(task_id))
    else {
        return Err(no_such_task(list, task_id));
    };

    let name = future_name(&task.future, &session.impl_fold);
    writeln!(
        out,
        "Task {task_id}: {} ({})",
        opts.theme.type_name(&name),
        task.state.lifecycle()
    )?;
    if let Some(loc) = &task.spawn_location {
        writeln!(out, "Spawned at: {loc}")?;
    }
    if let bundle::FutureInfo::Known(known) = &task.future
        && let Some((file, line)) = &known.decl
    {
        writeln!(out, "Defined at: {file}:{line}")?;
    }

    // A mid-poll task is being mutated while we read it; anything below
    // may be torn.
    if task.state.lifecycle() == Lifecycle::Running {
        let lwp = polling_lwp(&session.workers, Some(task_id));
        writeln!(
            io::stderr(),
            "warning: task {task_id} is running{lwp}; its state may be torn"
        )?;
    }

    match ctx.task_stage(task)? {
        bundle::TaskStage::Running(future) => {
            let chain = ctx.await_chain(future);
            print_trace_chain(session, &chain, index, None, opts, out)?;
            // A mid-poll task's chain stops at the last *committed*
            // await; the truth of what the poll is doing right now is
            // on the polling thread's native stack, joined below.
            if task.state.lifecycle() == Lifecycle::Running {
                print_native_continuation(session, task, task_id, &chain, opts, out)?;
            }
        }
        bundle::TaskStage::Finished(result) => {
            // Result<T::Output, JoinError>: Ok is a normal return, Err a
            // panic or cancellation.
            writeln!(out)?;
            writeln!(
                out,
                "The task has finished; its output has not been consumed:"
            )?;
            let mut value = result
                .display_from_target(ctx.proc, opts.render.depth)
                .max_str_len(Some(opts.render.max_string_len))
                .max_array_len(Some(opts.render.max_array_values));
            if let Some(heap) = opts.heap {
                value = value.heap(heap);
            }
            if opts.render.ugly {
                value = value.ugly();
            }
            writeln!(out, "  {:#}", value)?;
        }
        bundle::TaskStage::Consumed => {
            writeln!(out)?;
            writeln!(out, "The task has finished and its output was consumed.")?;
        }
    }
    Ok(())
}

/// Trace one future by address: resolve the address against the census
/// (`tasks --futures` prints the addresses this accepts), say where the
/// future lives, and render its await chain the way a task's is rendered.
fn exec_trace_future<T: proc::Target>(
    session: &Session<'_, T>,
    addr: u64,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    let list = &session.tasks;
    let census = session.census();

    let found = future_at(
        &ctx.view,
        list,
        session.extents(),
        census,
        &session.impl_fold,
        addr,
    )?;
    let (root, owner, origin) = match found {
        FutureAt::Held(index) => {
            let h = &census.held[index];
            let via = via_suffix(census, h.via);
            writeln!(
                out,
                "Future {:#x}: {}",
                h.addr,
                opts.theme
                    .type_name(&names::display_future_name(&h.future, &session.impl_fold))
            )?;
            writeln!(
                out,
                "Held by: {} — {} (frame {}, `{}`{via})",
                task_label(list, h.owner),
                future_name(&list.tasks[h.owner].future, &session.impl_fold),
                h.frame,
                h.local
            )?;
            (
                census::FutureRoot {
                    addr: h.addr,
                    ty: h.ty,
                },
                h.owner,
                census::Via::Held(index),
            )
        }
        FutureAt::Child { set, child } => {
            let s = &census.sets[set];
            let c = &s.children[child];
            let via = via_suffix(census, s.via);
            let future = match &c.future {
                Some(future) => names::display_future_name(future, &session.impl_fold),
                None => "<undecoded>".to_string(),
            };
            writeln!(
                out,
                "Future {:#x}: {}",
                c.node,
                opts.theme.type_name(&future)
            )?;
            writeln!(
                out,
                "Child of: {} at {:#x} (frame {}, `{}`{via}), polled by {} — {}",
                names::fold_type_name(&s.ty, &session.impl_fold),
                s.addr,
                s.frame,
                s.local,
                task_label(list, s.owner),
                future_name(&list.tasks[s.owner].future, &session.impl_fold)
            )?;
            let root = c
                .root
                .expect("future_at returns only children still in flight");
            (root, s.owner, census::Via::SetChild { set, child })
        }
    };

    // The owning task mid-poll is mutating its frames — and this future
    // with them — while we read; anything below may be torn.
    let task = &list.tasks[owner];
    if task.state.lifecycle() == Lifecycle::Running {
        let lwp = polling_lwp(&session.workers, task.task_id);
        writeln!(
            io::stderr(),
            "warning: {} is running{lwp}; the future's state may be torn",
            task_label(list, owner)
        )?;
    }

    let ty = ctx
        .view
        .ty(root.ty)
        .context("the census recorded a type the bundle does not carry")?;
    let value = Value::read(ctx.proc, ty, root.addr)
        .with_context(|| format!("failed to read the future at {:#x}", root.addr))?;

    let chain = ctx.await_chain(value);
    print_trace_chain(session, &chain, owner, Some(origin), opts, out)
}

/// What a future address resolved to: the census row that names it, as
/// the indices the census records it under.
#[derive(Debug)]
pub(crate) enum FutureAt {
    /// Index into [`census::FutureCensus::held`].
    Held(usize),
    /// Indices into [`census::FutureCensus::sets`] and that set's
    /// children.
    Child { set: usize, child: usize },
}

/// Resolve `addr` to the census future it names: a held future's
/// address, a set child's node address, or any pointer into either —
/// an interior pointer picks the tightest containing future, since a
/// by-value awaitee sits inside the future holding it. A miss says
/// what the address *is* whenever that can be said: a set itself, a
/// completed child, a task's own allocation.
pub(crate) fn future_at(
    view: &BundleView<'_>,
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &census::FutureCensus,
    impls: &names::ImplFold,
    addr: u64,
) -> Result<FutureAt> {
    if let Some(index) = census.held.iter().position(|h| h.addr == addr) {
        return Ok(FutureAt::Held(index));
    }
    if let Some((set_index, child_index, _)) = census.locate(addr) {
        let set = &census.sets[set_index];
        let child = &set.children[child_index];
        if child.root.is_none() {
            anyhow::bail!(
                "the child at {:#x} of the {} at {:#x} has completed; \
                 there is no future left to trace",
                child.node,
                names::fold_type_name(&set.ty, impls),
                set.addr
            );
        }
        return Ok(FutureAt::Child {
            set: set_index,
            child: child_index,
        });
    }
    if let Some(set) = census.sets.iter().find(|s| s.addr == addr) {
        anyhow::bail!(
            "{addr:#x} is the {} polled by {}, not one future; \
             trace one of its {} child node(s) (`tasks --futures` lists them)",
            names::fold_type_name(&set.ty, impls),
            task_label(list, set.owner),
            set.children.len()
        );
    }
    let containing = census
        .held
        .iter()
        .enumerate()
        .filter_map(|(index, h)| {
            let size = view.ty(h.ty)?.size();
            (h.addr <= addr && addr < h.addr + size).then_some((size, index))
        })
        .min_by_key(|&(size, _)| size);
    if let Some((_, index)) = containing {
        return Ok(FutureAt::Held(index));
    }
    if let Some((index, offset)) = extents.locate(addr) {
        anyhow::bail!(
            "no census future contains {addr:#x}; it is in {} at offset {offset:#x} \
             — `trace <id>` prints a task's own chain",
            task_label(list, index)
        );
    }
    anyhow::bail!(
        "nothing the census found contains {addr:#x}; \
         `tasks --futures` lists what can be traced"
    )
}

/// Render an await chain the way `trace` prints one: the `Waiting on:`
/// summary line, then the flat frame list. Values shown under --verbose
/// may hold raw pointers into task allocations (wakers, JoinHandles);
/// name those with the task id so the reader knows what to trace next.
/// The traced task itself is named like any other: a wake-queue entry
/// resolving back to it is a finding (the futurelock shape), not noise.
/// A pointer into a sub-executor's child node instead names the task
/// that polls the set — the task a wake there would ultimately run.
///
/// `owner` and `origin` say which chain this is the way the census
/// records it — the owning task's index, and `None` for the task's own
/// chain or the held-future/set-child origin for a `trace 0x…` chain —
/// so each frame can carry the tally of futures the census found parked
/// beside it.
fn print_trace_chain<'b, T: proc::Target>(
    session: &Session<'b, T>,
    chain: &bundle::AwaitChain<'b>,
    owner: usize,
    origin: Option<census::Via>,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let list = &session.tasks;
    let wait = wait_line(&session.ctx, chain, list)?;
    let holds = frame_holds(session.census(), owner, origin, chain.frames.len());
    let lookups = opts.verbose.then(|| (session.extents(), session.census()));
    let annotate = lookups.map(|(extents, census)| {
        move |ptr: u64| {
            if let Some((index, _)) = extents.locate(ptr) {
                return Some(task_label(list, index));
            }
            let (set, _, _) = census.locate(ptr)?;
            Some(format!(
                "{} via FuturesUnordered",
                task_label(list, census.sets[set].owner)
            ))
        }
    });
    let annotate = annotate.as_ref().map(|a| a as &reify::AddrAnnotator<'_>);
    print_await_chain(
        &session.ctx,
        chain,
        opts,
        wait.as_deref(),
        &holds,
        &session.impl_fold,
        annotate,
        out,
    )
}

/// The deepest frame's decoded wait target, formatted once: it prints
/// twice, in the header's `Waiting on:` line and again as the leaf
/// frame's detail, and reading the target twice for that would be
/// waste. A leaf that was recognized but failed to read warns on stderr
/// rather than failing the trace.
pub(crate) fn wait_line<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    chain: &bundle::AwaitChain<'_>,
    list: &bundle::TaskList,
) -> Result<Option<String>> {
    match ctx.wait_target(chain, list) {
        Some(Ok(target)) => Ok(Some(target.to_string())),
        Some(Err(e)) => {
            writeln!(
                io::stderr(),
                "warning: failed to read what the leaf future waits on: {e:#}"
            )?;
            Ok(None)
        }
        None => Ok(None),
    }
}

/// How many census-found futures each frame of this chain holds beside
/// it: futures parked in a frame's live state that the chain does not
/// run through — the shape a futurelock grows from. `origin` matches
/// [`census::HeldFuture::via`]: `None` counts the finds in `owner`'s
/// own frames, an origin those in the chain it names.
pub(crate) fn frame_holds(
    census: &census::FutureCensus,
    owner: usize,
    origin: Option<census::Via>,
    frames: usize,
) -> Vec<usize> {
    let mut holds = vec![0; frames];
    for h in &census.held {
        if h.owner == owner
            && h.via == origin
            && let Some(count) = holds.get_mut(h.frame)
        {
            *count += 1;
        }
    }
    holds
}

/// Render an await chain flat, root-first: a blank line, the decoded
/// wait target as a `Waiting on:` summary when there is one, then one
/// `#N` frame line per future with a detail line under each saying what
/// the target's memory says about that frame — its live state, or the
/// wait target again on the leaf. Under `--verbose` each frame also
/// lists its live locals and its other suspend points.
///
/// Reading convention: frame N is the future stored in frame N−1's live
/// state. The frame line ends with the type name, so a terminal
/// soft-wrap belongs to the name and triple-click still copies the
/// whole logical line.
#[allow(clippy::too_many_arguments)]
fn print_await_chain<'b, T: proc::Target>(
    ctx: &bundle::Context<'b, T>,
    chain: &bundle::AwaitChain<'b>,
    opts: &TraceOpts<'_>,
    wait: Option<&str>,
    holds: &[usize],
    impls: &names::ImplFold,
    annotate: Option<&reify::AddrAnnotator<'_>>,
    out: &mut dyn io::Write,
) -> Result<()> {
    writeln!(out)?;
    if let Some(wait) = wait {
        writeln!(out, "Waiting on: {}", opts.theme.bold(wait))?;
        writeln!(out)?;
    }

    let num_width = chain_num_width(chain);
    for i in 0..chain.frames.len() {
        print_frame(
            ctx, chain, i, num_width, wait, holds, opts, impls, annotate, out,
        )?;
    }
    print_chain_end(chain, impls, out)
}

/// The width the chain's frame numbers align at: that of the last —
/// the widest — `#N`.
pub(crate) fn chain_num_width(chain: &bundle::AwaitChain<'_>) -> usize {
    format!("#{}", chain.frames.len().saturating_sub(1)).len()
}

/// Print one frame of a chain the way the chain listing prints it: the
/// `#N` line, the detail line under it — the leaf frame's is the wait
/// target — and, under `--verbose`, the locals and suspend points.
/// Factored from the chain loop so the cursor's `frame` command prints
/// the selected frame identically.
#[allow(clippy::too_many_arguments)]
pub(crate) fn print_frame<'b, T: proc::Target>(
    ctx: &bundle::Context<'b, T>,
    chain: &bundle::AwaitChain<'b>,
    i: usize,
    num_width: usize,
    wait: Option<&str>,
    holds: &[usize],
    opts: &TraceOpts<'_>,
    impls: &names::ImplFold,
    annotate: Option<&reify::AddrAnnotator<'_>>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let frame = &chain.frames[i];
    let last = chain.frames.len().checked_sub(1);
    let kind = async_kind(
        frame.future.ty.name(),
        frame.state.as_ref().map(|state| state.name),
    );
    let dyn_marker = if frame.dyn_symbol.is_some() {
        " [dyn]"
    } else {
        ""
    };
    let name = names::fold_type_name(frame.future.ty.name(), impls);
    let number = format!("#{i}");
    writeln!(
        out,
        "{number:<num_width$}  {kind:<13} {}",
        opts.theme.type_name(&format!("{name}{dyn_marker}"))
    )?;

    let held = holds.get(i).copied().unwrap_or(0);
    match wait {
        Some(wait) if Some(i) == last => {
            writeln!(out, "{DETAIL_INDENT}waiting on {}", opts.theme.bold(wait))?;
        }
        _ => {
            if let Some(detail) = frame_detail(frame, held, &opts.theme) {
                writeln!(out, "{DETAIL_INDENT}{detail}")?;
            }
        }
    }

    if opts.verbose {
        print_frame_verbose(ctx, frame, Some(i) == last, opts, impls, annotate, out)?;
    }
    Ok(())
}

/// Everything under a frame line sits at this indent; entries in a
/// sub-block one step deeper, their values one more.
const DETAIL_INDENT: &str = "      ";
const ENTRY_INDENT: &str = "        ";

/// The detail line under a frame: the frame's target state, in one of
/// three spellings making three distinct claims. `awaiting at <loc>
/// (SuspendN…)` is a coroutine's resume point — the frame is awaiting
/// the next one at that source line; `state <Name>[ — <loc>]` is a
/// coroutine's terminal state; `state: <Name>` is a plain enum's
/// decoded variant on a non-coroutine wrapper, which makes no
/// resume-point claim. `held` futures the census found parked in the
/// frame ride along as a tally. `None` when there is nothing to say.
fn frame_detail(
    frame: &bundle::AwaitFrame<'_>,
    held: usize,
    theme: &output::Theme,
) -> Option<String> {
    let holds = match held {
        0 => String::new(),
        1 => "holds 1 pending future".to_string(),
        n => format!("holds {n} pending futures"),
    };
    let Some(state) = &frame.state else {
        return (!holds.is_empty()).then_some(holds);
    };
    let loc = state
        .await_loc
        .map(|(file, line)| theme.loc(&format!("{file}:{line}")).into_owned());
    if frame.future.ty.is_coroutine() && state.name.starts_with("Suspend") {
        let mut quals = state.name.to_string();
        match state_locals(state.payload.ty).len() {
            0 => {}
            1 => quals.push_str(", 1 local"),
            n => {
                quals.push_str(&format!(", {n} locals"));
            }
        }
        if !holds.is_empty() {
            quals.push_str("; ");
            quals.push_str(&holds);
        }
        let at = loc.map(|loc| format!("at {loc} ")).unwrap_or_default();
        return Some(format!("awaiting {at}({quals})"));
    }
    let mut detail = if frame.future.ty.is_coroutine() {
        match loc {
            Some(loc) => format!("state {} — {loc}", state.name),
            None => format!("state {}", state.name),
        }
    } else {
        format!("state: {}", state.name)
    };
    if !holds.is_empty() {
        detail.push_str(&format!(" ({holds})"));
    }
    Some(detail)
}

/// The `--verbose` blocks under one frame, in order: the live state's
/// locals (a plain leaf's fields), then the frame's other suspend
/// points — the inventory of where else the coroutine could park.
/// The inventory is type information, which is why it stays out of the
/// default view: interleaving "where could this park" with "where is it
/// parked" is what made the nested layout ambiguous.
fn print_frame_verbose<'b, T: proc::Target>(
    ctx: &bundle::Context<'b, T>,
    frame: &bundle::AwaitFrame<'b>,
    leaf: bool,
    opts: &TraceOpts<'_>,
    impls: &names::ImplFold,
    annotate: Option<&reify::AddrAnnotator<'_>>,
    out: &mut dyn io::Write,
) -> Result<()> {
    if frame.state.is_some() || leaf {
        let payload = match &frame.state {
            Some(state) => state.payload,
            None => frame.future,
        };
        let locals = state_locals(payload.ty);
        if !locals.is_empty() {
            let heading = if frame.state.is_some() {
                "locals:"
            } else {
                "fields:"
            };
            writeln!(out, "{DETAIL_INDENT}{heading}")?;
        }
        // print_variable's contract: the value's lines after the first
        // open with the variable's indent plus two spaces.
        let value_prefix = format!("{ENTRY_INDENT}  ");
        for m in locals {
            let start = m.offset() as usize;
            let end = start + m.ty().size() as usize;
            match payload.bytes.get(start..end) {
                Some(bytes) => {
                    let v = reify::Value::new(m.ty(), payload.addr + m.offset(), bytes).peel();
                    let mut disp = v
                        .display_from_target(ctx.proc, opts.render.depth)
                        .max_str_len(Some(opts.render.max_string_len))
                        .max_array_len(Some(opts.render.max_array_values))
                        .elide_override(opts.elide)
                        .line_prefix(&value_prefix);
                    if let Some(heap) = opts.heap {
                        disp = disp.heap(heap);
                    }
                    if let Some(annotate) = annotate {
                        disp = disp.annotate_addrs(annotate);
                    }
                    if opts.render.ugly {
                        disp = disp.ugly();
                    }
                    print_variable(out, ENTRY_INDENT, m.name(), &format_args!("{disp:#}"))?;
                }
                None => writeln!(out, "{ENTRY_INDENT}{}: <unreadable>", m.name())?,
            }
        }
    }

    let rows: Vec<SuspendRow<'_>> = suspend_rows(frame)
        .into_iter()
        .filter(|row| !row.active)
        .collect();
    if rows.is_empty() {
        return Ok(());
    }
    // Dimmed whole, inner spans unstyled: the inventory is inactive
    // material, and a styled span inside a dimmed line would end the
    // dimming at its own reset.
    let theme = &opts.theme;
    writeln!(out, "{DETAIL_INDENT}{}", theme.dim("other suspend points:"))?;
    for row in rows {
        let mut line = row.name.to_string();
        if let Some((file, lineno)) = row.loc {
            line.push_str(&format!(" — {file}:{lineno}"));
        }
        match row.locals {
            0 => {}
            1 => line.push_str(" (1 local)"),
            n => line.push_str(&format!(" ({n} locals)")),
        }
        if let Some(awaitee) = row.awaitee {
            line.push_str(&format!(
                " → {}",
                names::display_future_name(awaitee, impls)
            ));
        }
        writeln!(out, "{ENTRY_INDENT}{}", theme.dim(&line))?;
    }
    Ok(())
}

/// Why the chain stopped, printed after the last frame — nothing for a
/// chain that bottomed out in its leaf normally.
fn print_chain_end(
    chain: &bundle::AwaitChain<'_>,
    impls: &names::ImplFold,
    out: &mut dyn io::Write,
) -> Result<()> {
    match &chain.end {
        bundle::ChainEnd::Leaf => {}
        bundle::ChainEnd::UnknownDyn {
            pointee,
            poll_symbol,
        } => {
            writeln!(
                out,
                "the chain continues into a {} whose concrete type is not in the bundle",
                names::fold_type_name(pointee, impls)
            )?;
            if let Some(sym) = poll_symbol {
                writeln!(
                    out,
                    "     its poll fn is {:#} ({sym})",
                    rustc_demangle::demangle(sym)
                )?;
            }
        }
        bundle::ChainEnd::AmbiguousDyn {
            pointee,
            symbol,
            candidates,
        } => {
            writeln!(
                out,
                "the chain continues into a {}, but its normalized poll symbol is ambiguous",
                names::fold_type_name(pointee, impls)
            )?;
            writeln!(out, "     poll fn: {symbol}")?;
            for candidate in candidates {
                writeln!(
                    out,
                    "     candidate: {} (type {})",
                    names::fold_type_name(&candidate.name, impls),
                    candidate.ty.0
                )?;
            }
        }
        bundle::ChainEnd::DepthLimit => {
            writeln!(
                out,
                "await chain truncated after {} futures (depth bound); corrupt memory?",
                chain.frames.len()
            )?;
        }
        bundle::ChainEnd::Cycle { addr } => {
            writeln!(
                out,
                "await chain truncated: it loops back to {addr:#x}; corrupt memory?"
            )?;
        }
        bundle::ChainEnd::Error(e) => {
            writeln!(out, "await chain truncated: {e:#}")?;
        }
    }
    Ok(())
}

/// Append a mid-poll task's native continuation to its printed chain:
/// find the thread polling it (the corroborated claim `threads`
/// makes), unwind it, and classify its stack against the task's
/// resolved poll symbol and the committed chain's future types. When
/// any join fails — no claim, no unwind, no resolved poll symbol, no
/// frame inside it — nothing native is glued on: the section says why
/// and names `threads` for the raw stack.
fn print_native_continuation<T: proc::Target>(
    session: &Session<'_, T>,
    task: &bundle::Task,
    task_id: u64,
    chain: &bundle::AwaitChain<'_>,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    // The task is running here, so a worker whose context names it is
    // believed the way the `threads` heading believes it; a stale
    // claim (the id of a task that is *not* running) never gets this
    // far.
    let Some(worker) = polling_worker(&session.workers, task_id) else {
        return refuse_join(out, "no thread's context claims the task", None);
    };
    let lwp = worker.tid;

    // The anchor: the address range of this task's own poll symbol —
    // the bundle's task-join key, never a spelling match. A task whose
    // poll did not resolve (a --force attach) refuses here.
    let poll = match ctx.poll_symbol_range(task) {
        Ok(Some(range)) => range,
        Ok(None) => {
            return refuse_join(out, "no symbol covers the task's poll fn", Some(lwp));
        }
        Err(e) => {
            let why = format!("the task's poll fn cannot be resolved: {e:#}");
            return refuse_join(out, &why, Some(lwp));
        }
    };

    // Unwinding reads the CFI of every mapped object; the join pays
    // for it only once it has a thread and an anchor to use it on.
    let unwound = match unwind::load_frames(session.proc) {
        Ok(unwound) => unwound,
        Err(e) => {
            let why = format!("the target's threads cannot be unwound: {e:#}");
            return refuse_join(out, &why, Some(lwp));
        }
    };
    let Some(backtrace) = unwound.stacks.get(&lwp) else {
        let why = format!("lwp {lwp}'s stack was not unwound");
        return refuse_join(out, &why, Some(lwp));
    };

    let frames = native_frames(&ctx.view, &backtrace.frames);
    let chain_ids: Vec<BundleTypeId> = chain.frames.iter().map(|f| f.future.ty.id()).collect();
    let Some(joined) = stackjoin::classify(&frames, &poll, &chain_ids) else {
        // A walk that ended early explains its own miss better than
        // the generic suspicion can.
        let why = match &backtrace.truncated {
            Some(ended) => format!(
                "lwp {lwp}'s walked stack holds no frame in the task's \
                 poll symbol (its walk ended: {ended})"
            ),
            None => format!(
                "lwp {lwp}'s stack holds no frame in the task's poll symbol \
                 (a stale claim, or a torn stack)"
            ),
        };
        return refuse_join(out, &why, Some(lwp));
    };

    let fatal = session.proc.fatal_signal();
    print_native_section(
        &frames,
        &joined,
        lwp,
        chain.frames.len(),
        fatal.as_ref(),
        &|pc| ctx.mappings.contains_addr(pc),
        opts,
        out,
    )?;

    // The registers are the innermost printed frame's live state —
    // "the poll is currently at" made concrete — and they print only
    // under the corroborated join above: on a refusal the regs may
    // belong to some other poll, and `threads <lwp> --registers`
    // shows them without the task attribution.
    writeln!(out)?;
    crate::registers::print_lwp_registers(session, lwp, "", out)
}

/// The refusal path: the joined section's place says why there is
/// nothing native under the chain, and where the raw stack is.
fn refuse_join(out: &mut dyn io::Write, why: &str, lwp: Option<u32>) -> Result<()> {
    let threads = match lwp {
        Some(tid) => format!("threads {tid}"),
        None => "threads".to_string(),
    };
    writeln!(out)?;
    writeln!(out, "mid-poll, but {why}; `{threads}` shows the raw stack")?;
    Ok(())
}

/// Lay the unwinder's frames out for the classifier: the demangled
/// name (for display and the plumbing predicate) and the future types
/// the *mangled* symbol resolves to through the bundle's poll-symbol
/// join. Matching the seam by resolved type id is what bridges the
/// coroutine spellings — the frame demangles to `{closure#0}` where
/// the bundle's type says `{async_fn_env#0}` — with no string
/// comparison anywhere.
fn native_frames(view: &BundleView<'_>, frames: &[unwind::Frame]) -> Vec<stackjoin::NativeFrame> {
    frames
        .iter()
        .map(|f| {
            let mangled = f.symbol.as_ref().map(|s| s.name.as_str());
            let name = mangled
                .map(|m| format!("{:#}", rustc_demangle::demangle(m)))
                .unwrap_or_default();
            let futures = match mangled.map(|m| view.dyn_future_ids_for_symbol(m)) {
                Some(SymbolLookup::Unique(id)) => vec![id],
                Some(SymbolLookup::Ambiguous(ids)) => ids,
                Some(SymbolLookup::Missing) | None => Vec::new(),
            };
            stackjoin::NativeFrame {
                pc: f.pc,
                name,
                futures,
            }
        })
        .collect()
}

/// One printed line of the native section, after the plumbing-fold and
/// signal-row decisions.
enum NativeLine {
    /// One native frame, by index into the classifier's input frames.
    Frame(usize),
    /// A folded plumbing run, as its half-open input-index range.
    Fold(std::ops::Range<usize>),
    /// The synthesized signal row's text.
    Signal(String),
}

/// Render the native continuation: the section below the seam, in
/// chain order, numbered on from `start` (the count of chain frames
/// already printed) with the kind words `native` and `signal`.
/// `fatal` is the target's fatal signal — only when *this* lwp took
/// it does the section end with the signal row, since another
/// thread's signal has nothing to do with this poll. `mapped` says
/// whether an address falls inside any mapping, which is what turns
/// the wild frame a bad call pushes into the signal attribution
/// instead of a frame row.
#[allow(clippy::too_many_arguments)]
fn print_native_section(
    frames: &[stackjoin::NativeFrame],
    joined: &stackjoin::Continuation,
    lwp: u32,
    start: usize,
    fatal: Option<&proc::FatalSignal>,
    mapped: &dyn Fn(u64) -> bool,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut lines: Vec<NativeLine> = Vec::new();
    for row in &joined.rows {
        match row {
            stackjoin::Row::Frame(i) => lines.push(NativeLine::Frame(*i)),
            stackjoin::Row::Fold(r) => {
                if opts.verbose {
                    // The run whole, outermost first: descending index.
                    lines.extend(r.clone().rev().map(NativeLine::Frame));
                } else {
                    lines.push(NativeLine::Fold(r.clone()));
                }
            }
        }
    }

    if let Some(sig) = fatal.filter(|sig| sig.lwp == Some(lwp)) {
        // A call through a bad pointer pushes the unmapped pc itself
        // as the innermost frame; the frame under it is the caller the
        // unwinder hand-popped. The wild frame *is* the signal, so it
        // prints as the attribution, not as a frame.
        let wild = match lines.last() {
            Some(NativeLine::Frame(i)) if !mapped(frames[*i].pc) => Some(frames[*i].pc),
            _ => None,
        };
        let text = if let Some(pc) = wild {
            lines.pop();
            let caller = start + lines.len() - 1;
            format!(
                "{} — the call from #{caller} landed at {pc:#x}, unmapped",
                crate::summary::signal_name(sig)
            )
        } else if matches!(joined.rows.last(), Some(stackjoin::Row::Fold(_))) {
            format!(
                "{} — raised by the panic above",
                crate::summary::signal_name(sig)
            )
        } else {
            crate::summary::fatal_signal_line(sig)
        };
        lines.push(NativeLine::Signal(text));
    }

    writeln!(out)?;
    if lines.is_empty() {
        // The seam sat at the innermost frame: execution is exactly at
        // the committed leaf, and there is nothing novel to print.
        writeln!(
            out,
            "mid-poll on lwp {lwp} — the poll is at the chain's leaf frame; \
             nothing deeper is on the native stack"
        )?;
    } else {
        writeln!(out, "mid-poll on lwp {lwp} — the poll is currently at:")?;
        let num_width = format!("#{}", start + lines.len() - 1).len();
        for (n, line) in lines.iter().enumerate() {
            let number = format!("#{}", start + n);
            match line {
                NativeLine::Frame(i) => {
                    let f = &frames[*i];
                    let text = if f.name.is_empty() {
                        format!("<no symbol> at {:#x}", f.pc)
                    } else {
                        f.name.clone()
                    };
                    writeln!(out, "{number:<num_width$}  {:<13} {text}", "native")?;
                }
                NativeLine::Fold(r) => {
                    writeln!(
                        out,
                        "{number:<num_width$}  {:<13} panic plumbing: {} … {} \
                         ({} frames; -v shows each)",
                        "native",
                        frames[r.end - 1].name,
                        frames[r.start].name,
                        r.len(),
                    )?;
                }
                NativeLine::Signal(text) => {
                    writeln!(out, "{number:<num_width$}  {:<13} {text}", "signal")?;
                }
            }
        }
    }
    // The provenance footer: what anchored the join, and that the
    // scheduler frames outward of it never print.
    writeln!(
        out,
        "{}",
        opts.theme.dim(&format!(
            "(below {}; scheduler frames above it omitted — \
             `threads {lwp}` shows the raw stack)",
            frames[joined.anchor].name
        ))
    )?;
    Ok(())
}

/// One row of a coroutine frame's suspend-point inventory: somewhere the
/// future can park, read from its type rather than from the target.
struct SuspendRow<'b> {
    /// `Suspend0`, `Suspend1`, …, or a terminal state (`Unresumed`,
    /// `Returned`, `Panicked`) when that is the one the frame is in.
    name: &'b str,
    /// The awaited expression's source coordinates.
    loc: Option<(&'b str, u32)>,
    /// How many source-level locals the state holds live. Every variant
    /// of a coroutine shares the same storage, so only the active
    /// state's *values* can be read; for the rest a count is the most
    /// the type alone can say.
    locals: usize,
    /// What the state awaits, from its `__awaitee` member.
    awaitee: Option<&'b str>,
    /// Whether this is the state the frame is parked in.
    active: bool,
}

/// A coroutine frame's suspend points, in the order the debug info lists
/// its variants.
///
/// Empty for a frame that is not a coroutine — a plain leaf future, or
/// an ordinary enum whose variants are alternatives rather than parking
/// spots — and for one whose state did not decode: with nothing to mark,
/// an inventory would say where the future *could* be without saying
/// where it is.
fn suspend_rows<'b>(frame: &bundle::AwaitFrame<'b>) -> Vec<SuspendRow<'b>> {
    let Some(state) = &frame.state else {
        return Vec::new();
    };
    if !frame.future.ty.is_coroutine() {
        return Vec::new();
    }
    frame
        .future
        .ty
        .variants()
        .filter_map(|variant| {
            let name = variant.state_name();
            let active = name == state.name;
            // A terminal state is not a suspend point; it earns a row
            // only by being the one the frame is actually in, which it
            // is for a task parked before its first poll or holding an
            // unconsumed result.
            if !active && !name.starts_with("Suspend") {
                return None;
            }
            Some(SuspendRow {
                name,
                loc: variant.await_loc(),
                locals: state_locals(variant.ty).len(),
                awaitee: variant.ty.member("__awaitee").map(|m| m.ty().name()),
                active,
            })
        })
        .collect()
}

/// The source-level locals a coroutine state holds live.
///
/// `__…` members are compiler-generated (the awaitee itself and
/// liveness slots), not source-level locals. A coroutine state may hold
/// the same name twice (a captured upvar and a saved local), so members
/// are sliced positionally, never looked up by name.
fn state_locals(ty: BundleType<'_>) -> Vec<BundleMember<'_>> {
    let mut seen = std::collections::HashSet::new();
    ty.members()
        .filter(|m| {
            m.ty().size() > 0 && !m.name().starts_with("__") && seen.insert((m.name(), m.offset()))
        })
        .collect()
}

/// Classify the outer future type from rustc's generated DWARF basename.
/// The names are an implementation detail, so an unrecognized state
/// machine deliberately receives the neutral `async` label. Always
/// judged on the *raw* name, before display folding removes the very
/// marker this reads.
fn async_kind(name: &str, state: Option<&str>) -> &'static str {
    if let Some(kind) = names::coroutine_kind(name) {
        return kind;
    }
    if state.is_some_and(|state| {
        state.starts_with("Suspend") || matches!(state, "Unresumed" | "Returned" | "Panicked")
    }) {
        "async"
    } else {
        "future"
    }
}

/// Print a named variable compactly when it fits on one line, or as a
/// `name:` heading with the value's lines beneath it when the value is
/// multi-line.
///
/// The value's own lines arrive final-form: a multi-line value must be
/// rendered with a reify line prefix of this `indent` plus two spaces
/// (see [`reify::DisplayValue::line_prefix`]), so this function
/// lays out only the heading and the first line, and everything after
/// the first newline passes through to the sink untouched — no per-line
/// scan or re-copy, on values that run to gigabytes.
pub(crate) fn print_variable(
    out: &mut dyn io::Write,
    indent: &str,
    name: &str,
    value: &dyn fmt::Display,
) -> Result<()> {
    /// Small pieces batch up to this much before a sink write. The
    /// renderer writes a few bytes at a time — a member name, a brace —
    /// so accepting one must cost what a `String` append does.
    const CHUNK: usize = 64 << 10;
    /// A piece at least this big skips the batch and goes to the sink
    /// whole: the parallel renderer hands over entire chunk buffers,
    /// and staging those would only re-copy them.
    const BIG: usize = 4 << 10;

    struct Stream<'w> {
        sink: &'w mut dyn io::Write,
        /// Small pieces batched between sink writes.
        staged: String,
        indent: &'w str,
        name: &'w str,
        /// The first line so far; `None` once a newline committed the
        /// heading layout.
        first: Option<String>,
        /// The io error behind a `fmt::Error`, which cannot carry it.
        error: Option<io::Error>,
    }

    impl Stream<'_> {
        fn put(&mut self, mut text: &str) -> io::Result<()> {
            if self.first.is_some() {
                match text.split_once('\n') {
                    None => {
                        self.first.as_mut().unwrap().push_str(text);
                        return Ok(());
                    }
                    // The first newline commits the heading layout. The
                    // lines after it open with the renderer's prefix, so
                    // only this one needs its margin laid in here.
                    Some((head, rest)) => {
                        let first = self.first.take().unwrap();
                        self.staged.push_str(self.indent);
                        self.staged.push_str(self.name);
                        self.staged.push_str(":\n");
                        self.staged.push_str(self.indent);
                        self.staged.push_str("  ");
                        self.staged.push_str(&first);
                        self.staged.push_str(head);
                        self.staged.push('\n');
                        text = rest;
                    }
                }
            }
            if text.len() >= BIG {
                self.flush()?;
                return self.sink.write_all(text.as_bytes());
            }
            self.staged.push_str(text);
            if self.staged.len() >= CHUNK {
                self.flush()?;
            }
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.sink.write_all(self.staged.as_bytes())?;
            self.staged.clear();
            Ok(())
        }

        fn finish(&mut self) -> io::Result<()> {
            // No newline ever came: the single-line layout.
            if let Some(value) = self.first.take() {
                self.staged.push_str(self.indent);
                self.staged.push_str(self.name);
                self.staged.push_str(": ");
                self.staged.push_str(&value);
            }
            self.staged.push('\n');
            self.flush()
        }
    }

    impl fmt::Write for Stream<'_> {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            self.put(text).map_err(|e| {
                self.error = Some(e);
                fmt::Error
            })
        }
    }

    let mut stream = Stream {
        sink: out,
        staged: String::new(),
        indent,
        name,
        first: Some(String::new()),
        error: None,
    };
    use fmt::Write as _;
    let outcome = write!(stream, "{value}");
    match stream.error.take() {
        Some(error) => Err(error.into()),
        None => {
            outcome.map_err(|_| anyhow::anyhow!("failed to render {name}"))?;
            stream.finish()?;
            Ok(())
        }
    }
}

/// The worker mid-poll in the task: the one whose thread-local
/// context names it.
fn polling_worker(workers: &[bundle::Worker], id: u64) -> Option<&bundle::Worker> {
    workers.iter().find(|w| w.current_task_id == Some(id))
}

/// The ` on lwp N` suffix of a torn-state warning, when some worker is
/// mid-poll in the task.
fn polling_lwp(workers: &[bundle::Worker], id: Option<u64>) -> String {
    id.and_then(|id| polling_worker(workers, id))
        .map(|w| format!(" on lwp {}", w.tid))
        .unwrap_or_default()
}

#[cfg(test)]
mod polling_lwp_tests {
    use super::polling_lwp;
    use hansei_runtime::tokio::bundle;

    /// The suffix names the worker mid-poll in the task — only a worker
    /// whose thread-local names that very task, and nothing otherwise.
    #[test]
    fn test_the_suffix_names_the_polling_worker() {
        let worker = |tid, id| bundle::Worker {
            tid,
            context_addr: 0x100,
            current_task_id: id,
        };
        let workers = [worker(11, Some(7)), worker(12, Some(9))];
        assert_eq!(polling_lwp(&workers, Some(9)), " on lwp 12");
        assert_eq!(polling_lwp(&workers, Some(8)), "");
        assert_eq!(polling_lwp(&workers, None), "");
    }
}

#[cfg(test)]
mod state_locals_tests {
    use super::state_locals;
    use hansei_bundle::{
        Bundle, BundleTypeId, BundleView, Encoding, FORMAT_VERSION, InfraTypes, MemberDef, Meta,
        StringInterner, TypeDef, TypeTable,
    };

    /// Source-level locals are the sized, non-compiler members, one per
    /// (name, offset): ZSTs, `__` slots and positional repeats stay out.
    #[test]
    fn test_state_locals_are_the_sized_named_members() {
        let mut strings = StringInterner::new();
        let n_u64 = strings.intern("u64");
        let n_state = strings.intern("State");
        let n_ghost = strings.intern("Ghost");
        let n_value = strings.intern("value");
        let n_marker = strings.intern("marker");
        let n_awaitee = strings.intern("__awaitee");
        let strings = strings.finish();
        let member = |name, ty, offset| MemberDef {
            name,
            ty: BundleTypeId(ty),
            offset,
        };
        let types = vec![
            TypeDef::Base {
                name: n_u64,
                size: 8,
                encoding: Encoding::Unsigned,
            },
            // A PhantomData-shaped marker: named, sized zero.
            TypeDef::Struct {
                name: n_ghost,
                size: 0,
                members: vec![],
            },
            TypeDef::Struct {
                name: n_state,
                size: 24,
                members: vec![
                    member(n_value, 0, 0),
                    // The same name at the same offset: a captured
                    // upvar recorded beside the saved local.
                    member(n_value, 0, 0),
                    member(n_marker, 1, 8),
                    member(n_awaitee, 0, 16),
                ],
            },
        ];
        let ty = BundleTypeId(0);
        let bundle = Bundle {
            meta: Meta {
                format_version: FORMAT_VERSION,
                ..Default::default()
            },
            strings,
            types: TypeTable {
                types,
                ..Default::default()
            },
            tasks: Default::default(),
            dyn_futures: Default::default(),
            statics: Default::default(),
            walks: Default::default(),
            infra: InfraTypes {
                header: ty,
                vtable: ty,
                trailer: ty,
                context: ty,
                scheduler_handle: ty,
                mt_handle: ty,
                ct_handle: ty,
                location: ty,
                raw_waker_vtable: ty,
            },
            provenance: Default::default(),
            impls: Default::default(),
            vtables: Default::default(),
        };
        let view = BundleView::new(&bundle);
        let state = view.ty(BundleTypeId(2)).expect("the state type resolves");

        let locals = state_locals(state);
        let names: Vec<&str> = locals.iter().map(|m| m.name()).collect();
        assert_eq!(names, ["value"], "{names:?}");
    }
}

#[cfg(test)]
mod chain_end_tests {
    use super::print_chain_end;
    use hansei_bundle::names::ImplFold;
    use hansei_runtime::tokio::bundle::{AwaitChain, ChainEnd, TypeCandidate};

    fn rendered(end: ChainEnd) -> String {
        let chain = AwaitChain {
            frames: Vec::new(),
            end,
        };
        let mut out = Vec::new();
        print_chain_end(&chain, &ImplFold::default(), &mut out).expect("the message renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// A leaf ended the chain normally: there is nothing to explain.
    #[test]
    fn test_a_leaf_prints_nothing() {
        assert_eq!(rendered(ChainEnd::Leaf), "");
    }

    /// The dyn continuations name the pointee — display-folded like
    /// every printed name — and what is known about the poll fn:
    /// the demangled symbol for an unknown type, the candidate list
    /// (folded, no kind word: they are lookup handles) for an
    /// ambiguous one. Each candidate carries its type id — the folded
    /// names often agree exactly, and the id is the handle that does
    /// not.
    #[test]
    fn test_dyn_ends_name_the_pointee_and_the_poll_fn() {
        let out = rendered(ChainEnd::UnknownDyn {
            pointee: "core::pin::Pin<alloc::boxed::Box<dyn core::future::future::Future>>"
                .to_string(),
            poll_symbol: Some("_ZN4core3fut4pollE".to_string()),
        });
        assert_eq!(
            out,
            "the chain continues into a Pin<Box<dyn Future>> \
             whose concrete type is not in the bundle\n     \
             its poll fn is core::fut::poll (_ZN4core3fut4pollE)\n"
        );

        let out = rendered(ChainEnd::AmbiguousDyn {
            pointee: "dyn core::future::future::Future".to_string(),
            symbol: "poll_sym".to_string(),
            candidates: vec![TypeCandidate {
                name: "work::step::{async_fn_env#0}".to_string(),
                ty: hansei_bundle::BundleTypeId(41),
            }],
        });
        assert_eq!(
            out,
            "the chain continues into a dyn Future, \
             but its normalized poll symbol is ambiguous\n     \
             poll fn: poll_sym\n     candidate: work::step (type 41)\n"
        );
    }

    /// The truncation messages say why the walk stopped and, for the
    /// depth bound, how far it got.
    #[test]
    fn test_truncations_say_why_the_walk_stopped() {
        assert_eq!(
            rendered(ChainEnd::DepthLimit),
            "await chain truncated after 0 futures (depth bound); corrupt memory?\n"
        );
        assert_eq!(
            rendered(ChainEnd::Cycle { addr: 0x40 }),
            "await chain truncated: it loops back to 0x40; corrupt memory?\n"
        );
        assert_eq!(
            rendered(ChainEnd::Error(anyhow::anyhow!("torn read"))),
            "await chain truncated: torn read\n"
        );
    }
}

/// The native continuation as `trace` renders it, over hand-laid
/// frames: the classifier is pure and covered in `hansei-runtime`, so
/// these fix the printed layout — numbering on from the chain, the
/// kind words, the fold line, the signal attributions, the footer and
/// the refusal spelling.
#[cfg(test)]
mod native_section_tests {
    use super::{TraceOpts, print_native_section, refuse_join};
    use crate::{RenderOpts, output};
    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::stackjoin::{self, NativeFrame};

    fn frame(pc: u64, name: &str) -> NativeFrame {
        NativeFrame {
            pc,
            name: name.to_owned(),
            futures: Vec::new(),
        }
    }

    fn poll_frame(pc: u64, name: &str, futures: &[u32]) -> NativeFrame {
        NativeFrame {
            futures: futures.iter().map(|&id| BundleTypeId(id)).collect(),
            ..frame(pc, name)
        }
    }

    const POLL: std::ops::Range<u64> = 0x5000..0x5100;

    /// Classify and render one section the way the command does.
    fn section(
        frames: &[NativeFrame],
        chain: &[BundleTypeId],
        lwp: u32,
        start: usize,
        fatal: Option<&proc::FatalSignal>,
        mapped: &dyn Fn(u64) -> bool,
        verbose: bool,
    ) -> String {
        let joined = stackjoin::classify(frames, &POLL, chain).expect("the poll frame anchors");
        let mut out = Vec::new();
        let elide = Default::default();
        let opts = TraceOpts {
            verbose,
            render: RenderOpts {
                depth: 4,
                ugly: false,
                max_string_len: reify::DEFAULT_MAX_STRING_LEN,
                max_array_values: reify::DEFAULT_MAX_ARRAY_VALUES,
            },
            elide: &elide,
            theme: output::Theme::plain(),
            heap: None,
        };
        print_native_section(frames, &joined, lwp, start, fatal, mapped, &opts, &mut out)
            .expect("the section renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    fn segv() -> proc::FatalSignal {
        proc::FatalSignal {
            name: "SIGSEGV",
            signo: 11,
            code: 1,
            code_name: Some("SEGV_MAPERR"),
            fault_addr: Some(0),
            lwp: Some(115),
            sender: None,
        }
    }

    fn abrt() -> proc::FatalSignal {
        proc::FatalSignal {
            name: "SIGABRT",
            signo: 6,
            code: 0,
            code_name: None,
            fault_addr: None,
            lwp: Some(7),
            sender: None,
        }
    }

    /// The healthy-capture shape: every novel frame below the seam
    /// prints as a `native` row, numbered on from the chain's frames,
    /// under the neutral header and over the provenance footer — and a
    /// capture that took no signal ends at its innermost frame with no
    /// signal row.
    #[test]
    fn test_the_section_numbers_on_from_the_chain() {
        let chain = [BundleTypeId(10), BundleTypeId(11), BundleTypeId(12)];
        let frames = [
            frame(0x9000, "__lwp_park"),
            frame(0x9010, "mutex_lock"),
            frame(0x9020, "vmem_xalloc"),
            frame(0x9030, "memalign"),
            poll_frame(0x9040, "reqwest::connect::{closure#0}", &[77]),
            poll_frame(0x9050, "<FuturesUnordered as Future>::poll_next", &[12]),
            poll_frame(0x9060, "nexus::saga::{closure#0}", &[10]),
            frame(0x9070, "tokio::runtime::task::harness::poll"),
            frame(0x5010, "tokio::runtime::task::raw::poll"),
            frame(0x9090, "tokio::runtime::scheduler::run"),
        ];
        assert_eq!(
            section(&frames, &chain, 115, 3, None, &|_| true, false),
            "
mid-poll on lwp 115 — the poll is currently at:
#3  native        reqwest::connect::{closure#0}
#4  native        memalign
#5  native        vmem_xalloc
#6  native        mutex_lock
#7  native        __lwp_park
(below tokio::runtime::task::raw::poll; scheduler frames above it omitted \
— `threads 115` shows the raw stack)
"
        );
    }

    /// The panic-abort shape: the plumbing run folds to one counted
    /// line, and the fatal signal — this lwp's — ends the section
    /// attributed to the panic above it.
    #[test]
    fn test_a_panic_abort_folds_and_ends_with_the_signal_row() {
        let chain = [BundleTypeId(20)];
        let frames = [
            frame(0x9000, "_lwp_kill"),
            frame(0x9010, "raise"),
            frame(0x9020, "abort"),
            frame(0x9030, "std::sys::pal::unix::abort_internal"),
            frame(0x9040, "std::panicking::rust_panic"),
            frame(0x9050, "std::panicking::rust_panic_with_hook"),
            frame(0x9060, "std::panicking::begin_panic_handler::{closure#0}"),
            frame(0x9070, "std::sys::backtrace::__rust_end_short_backtrace"),
            frame(0x9080, "std::panicking::begin_panic_handler"),
            frame(0x9090, "core::panicking::panic_fmt"),
            frame(0x90a0, "panic_join::boom"),
            poll_frame(0x90b0, "panic_join::main::{closure#0}", &[20]),
            frame(0x90c0, "core::panic::unwind_safe::AssertUnwindSafe"),
            frame(0x5020, "tokio::runtime::task::raw::poll"),
            frame(0x90e0, "tokio::runtime::scheduler::run"),
        ];
        let sig = abrt();
        assert_eq!(
            section(&frames, &chain, 7, 1, Some(&sig), &|_| true, false),
            "
mid-poll on lwp 7 — the poll is currently at:
#1  native        panic_join::boom
#2  native        panic plumbing: core::panicking::panic_fmt … _lwp_kill \
(10 frames; -v shows each)
#3  signal        SIGABRT — raised by the panic above
(below tokio::runtime::task::raw::poll; scheduler frames above it omitted \
— `threads 7` shows the raw stack)
"
        );

        // -v prints the run whole, outermost first, each frame taking
        // its own number; the signal row keeps its attribution.
        let verbose = section(&frames, &chain, 7, 1, Some(&sig), &|_| true, true);
        assert_eq!(verbose.matches(" native ").count(), 11, "{verbose}");
        assert!(!verbose.contains("panic plumbing:"), "{verbose}");
        assert!(
            verbose.contains("#2   native        core::panicking::panic_fmt\n"),
            "{verbose}"
        );
        assert!(
            verbose.contains("#11  native        _lwp_kill\n"),
            "{verbose}"
        );
        assert!(
            verbose.contains("#12  signal        SIGABRT — raised by the panic above\n"),
            "{verbose}"
        );
    }

    /// The release-crash shape: the wild frame a bad call pushes — an
    /// unmapped pc with no symbol — prints as the signal attribution
    /// naming its caller, not as a frame row.
    #[test]
    fn test_a_wild_pc_becomes_the_signal_attribution() {
        let chain = [BundleTypeId(30), BundleTypeId(31)];
        let frames = [
            frame(0x0, ""),
            frame(0x9010, "rama::service::dispatch"),
            frame(0x9020, "rama::stream::next"),
            frame(0x5000, "tokio::runtime::task::raw::poll"),
            poll_frame(0x9040, "other::task::{closure#0}", &[30]),
        ];
        let sig = segv();
        // `start` deliberately differs from the section's row count, so
        // the caller's number is wrong unless computed as start + rows.
        assert_eq!(
            section(&frames, &chain, 115, 3, Some(&sig), &|pc| pc != 0, false),
            "
mid-poll on lwp 115 — the poll is currently at:
#3  native        rama::stream::next
#4  native        rama::service::dispatch
#5  signal        SIGSEGV (SEGV_MAPERR) — the call from #4 landed at 0x0, unmapped
(below tokio::runtime::task::raw::poll; scheduler frames above it omitted \
— `threads 115` shows the raw stack)
"
        );
    }

    /// Another thread's fatal signal has nothing to do with this poll:
    /// only the section's own lwp earns the signal row.
    #[test]
    fn test_another_lwps_signal_earns_no_row() {
        let frames = [
            frame(0x9000, "app::handler"),
            frame(0x5000, "tokio::runtime::task::raw::poll"),
        ];
        let mut sig = segv();
        sig.lwp = Some(116);
        let rendered = section(&frames, &[], 115, 1, Some(&sig), &|_| true, false);
        assert!(!rendered.contains("signal"), "{rendered}");
        sig.lwp = None;
        let rendered = section(&frames, &[], 115, 1, Some(&sig), &|_| true, false);
        assert!(!rendered.contains("signal"), "{rendered}");
    }

    /// A fault at a mapped pc is neither the wild-call shape nor a
    /// panic: the signal row carries the full spelling, fault address
    /// and all, with no attribution to invent.
    #[test]
    fn test_a_mapped_fault_keeps_the_full_signal_spelling() {
        let frames = [
            frame(0x9000, "app::handler"),
            frame(0x5000, "tokio::runtime::task::raw::poll"),
        ];
        let sig = segv();
        let rendered = section(&frames, &[], 115, 1, Some(&sig), &|_| true, false);
        assert!(
            rendered.contains("#2  signal        SIGSEGV (SEGV_MAPERR), fault address 0x0\n"),
            "{rendered}"
        );
    }

    /// A seam at the innermost frame means execution is exactly at the
    /// committed leaf: the header says so instead of opening an empty
    /// list, and the footer still says what anchored the join.
    #[test]
    fn test_an_execution_at_the_committed_leaf_prints_the_quiet_header() {
        let chain = [BundleTypeId(10), BundleTypeId(11)];
        let frames = [
            poll_frame(0x9000, "leaf::{closure#0}", &[11]),
            frame(0x5000, "task::raw::poll"),
        ];
        assert_eq!(
            section(&frames, &chain, 12, 2, None, &|_| true, false),
            "
mid-poll on lwp 12 — the poll is at the chain's leaf frame; \
nothing deeper is on the native stack
(below task::raw::poll; scheduler frames above it omitted \
— `threads 12` shows the raw stack)
"
        );
    }

    /// A frame the unwinder found no symbol for still prints — by
    /// address, since a nameless row would claim nothing — when no
    /// signal turns it into an attribution.
    #[test]
    fn test_a_nameless_frame_prints_its_address() {
        let frames = [
            frame(0x4242, ""),
            frame(0x5000, "tokio::runtime::task::raw::poll"),
        ];
        let rendered = section(&frames, &[], 3, 1, None, &|_| true, false);
        assert!(
            rendered.contains("#1  native        <no symbol> at 0x4242\n"),
            "{rendered}"
        );
    }

    /// The unwinder's frames laid out for the classifier: the
    /// demangled name for display and the plumbing predicate, and the
    /// future ids the *mangled* symbol resolves to through the
    /// bundle's own poll-symbol join — while a frame with no symbol
    /// claims nothing.
    #[test]
    fn test_native_frames_resolve_futures_through_the_bundle_join() {
        let (bundle, _snapshot) = hansei_runtime::testkit::load_any("unordered");
        let view = hansei_bundle::BundleView::new(&bundle);
        let (symbol, ty) = bundle
            .dyn_futures
            .by_symbol
            .iter()
            .next()
            .expect("the fixture records dyn futures");
        let sym = proc::SymbolBuf {
            name: symbol.clone(),
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: 0x7000,
            st_size: 0x40,
        };
        let frames = [
            unwind::Frame {
                pc: 0x7004,
                regs: proc::Regs::default(),
                symbol: Some(sym),
                heuristic: false,
            },
            unwind::Frame {
                pc: 0x9000,
                regs: proc::Regs::default(),
                symbol: None,
                heuristic: false,
            },
        ];
        let laid = super::native_frames(&view, &frames);
        assert_eq!(laid.len(), 2);
        assert_eq!(laid[0].pc, 0x7004);
        assert_eq!(laid[0].futures, vec![*ty]);
        assert_eq!(
            laid[0].name,
            format!("{:#}", rustc_demangle::demangle(symbol))
        );
        assert!(laid[1].name.is_empty());
        assert!(laid[1].futures.is_empty());
    }

    /// The refusal path glues nothing on: one line saying why, naming
    /// `threads` — narrowed to the lwp when the join got far enough to
    /// have one.
    #[test]
    fn test_the_refusal_says_why_and_names_threads() {
        let mut out = Vec::new();
        refuse_join(&mut out, "no thread's context claims the task", None)
            .expect("the refusal renders");
        assert_eq!(
            String::from_utf8(out).expect("rendered output is UTF-8"),
            "\nmid-poll, but no thread's context claims the task; \
             `threads` shows the raw stack\n"
        );

        let mut out = Vec::new();
        refuse_join(&mut out, "lwp 9's stack was not unwound", Some(9))
            .expect("the refusal renders");
        assert_eq!(
            String::from_utf8(out).expect("rendered output is UTF-8"),
            "\nmid-poll, but lwp 9's stack was not unwound; `threads 9` shows the raw stack\n"
        );
    }
}

#[cfg(test)]
mod variable_format_tests {
    use super::{async_kind, print_variable};

    #[test]
    fn scalar_stays_on_the_name_line() {
        let mut out = Vec::new();
        print_variable(&mut out, "  ", "count", &"42").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "  count: 42\n");
    }

    /// A multi-line value arrives with its lines after the first already
    /// prefixed (the renderer's `line_prefix` is the indent plus two
    /// spaces), so the heading and first line get their margin laid in
    /// here and the rest passes through byte for byte.
    #[test]
    fn aggregate_is_indented_below_the_name() {
        let mut out = Vec::new();
        print_variable(
            &mut out,
            "  ",
            "point",
            &"Point {\n        x: 1,\n        y: 2,\n    }",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "  point:\n    Point {\n        x: 1,\n        y: 2,\n    }\n"
        );
    }

    /// Streaming decides the layout at the first newline however the text
    /// is chunked, so a value whose `Display` writes a piece at a time
    /// must land exactly where a single-write one does — including a
    /// piece big enough to take the direct-to-sink path.
    #[test]
    fn chunked_writes_land_like_whole_ones() {
        struct Chunked<'a>(&'a [&'a str]);
        impl std::fmt::Display for Chunked<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.iter().try_for_each(|piece| f.write_str(piece))
            }
        }
        let big = format!("    x: {},", "9".repeat(8 << 10));
        let pieces = ["Point {", "\n    x", ": 1,", "\n", &big, "\n", "}"];
        let mut chunked = Vec::new();
        print_variable(&mut chunked, "  ", "v", &Chunked(&pieces)).unwrap();
        let mut whole = Vec::new();
        print_variable(&mut whole, "  ", "v", &pieces.concat().as_str()).unwrap();
        assert_eq!(chunked, whole);
        assert_eq!(
            String::from_utf8(whole).unwrap(),
            format!("  v:\n    Point {{\n    x: 1,\n{big}\n}}\n")
        );
    }

    #[test]
    fn classifies_rustc_async_environment_names() {
        assert_eq!(
            async_kind("crate::work::{async_fn_env#0}<T>", Some("Suspend0")),
            "async fn"
        );
        assert_eq!(
            async_kind("crate::work::{async_block_env#2}", Some("Suspend0")),
            "async block"
        );
        assert_eq!(
            async_kind("crate::work::{async_closure_env#1}", Some("Suspend0")),
            "async closure"
        );
        assert_eq!(async_kind("crate::unknown", Some("Suspend3")), "async");
        assert_eq!(async_kind("crate::MaybeDone", Some("Done")), "future");
    }

    #[test]
    fn classifies_the_outer_future_not_its_type_arguments() {
        assert_eq!(
            async_kind("core::future::PollFn<crate::work::{async_fn_env#0}>", None),
            "future"
        );
        assert_eq!(
            async_kind(
                "crate::Wrapper<T>::work::{async_fn_env#0}<U>",
                Some("Suspend0")
            ),
            "async fn"
        );
    }

    /// The closure spelling needs both delimiters: a component that
    /// only starts like one, or only ends like one, is no closure.
    #[test]
    fn test_half_spelled_closure_names_stay_futures() {
        assert_eq!(
            async_kind("crate::{async_closure_env#1}tail", None),
            "future"
        );
        assert_eq!(
            async_kind("crate::not_{async_closure_env#1}", None),
            "future"
        );
    }
}

/// Offline future-trace tests: what `trace <0x-address>` resolves an
/// address to, and the chain it renders from there, over a real
/// extracted bundle joined against a real captured snapshot.
#[cfg(test)]
mod future_trace_tests {
    use super::{FutureAt, TraceOpts, frame_holds, future_at, print_await_chain, wait_line};
    use crate::tasks::{future_name, print_tasks};
    use crate::{RenderOpts, output};
    use crate::{TraceTarget, parse_trace_target};
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::TaskState;
    use hansei_runtime::tokio::bundle::{self, Context, TaskExtents, TaskList};
    use hansei_runtime::tokio::census::{self, FutureCensus};
    use proc::snapshot::Snapshot;
    use reify::Value;

    use std::collections::HashMap;

    fn with_target(
        program: &str,
        check: impl FnOnce(&Context<'_, Snapshot>, &TaskList, &TaskExtents, &FutureCensus),
    ) {
        let (bundle, snapshot) = testkit::load_any(program);
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        check(&ctx, &list, &extents, &census);
    }

    /// The two spellings split on the `0x` prefix and nothing else —
    /// the contract the command's help text states.
    #[test]
    fn test_trace_targets_parse_by_prefix() {
        assert!(matches!(
            parse_trace_target("42"),
            Ok(TraceTarget::Task(42))
        ));
        assert!(matches!(
            parse_trace_target("0x7fffb1c26100"),
            Ok(TraceTarget::Future(0x7fffb1c26100))
        ));
        assert!(matches!(
            parse_trace_target("0XFF"),
            Ok(TraceTarget::Future(0xff))
        ));
        // Hex digits without the prefix are not silently a huge id.
        assert!(parse_trace_target("7fffb1c26100").is_err());
        assert!(parse_trace_target("0x").is_err());
        assert!(parse_trace_target("-3").is_err());
    }

    /// A held future's printed address resolves to that future, and an
    /// interior pointer resolves to a future containing it.
    #[test]
    fn test_future_addresses_resolve_to_the_held_future() {
        with_target("futurelock", |ctx, list, extents, census| {
            let future1 = census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));

            let found = future_at(
                &ctx.view,
                list,
                extents,
                census,
                &hansei_bundle::names::ImplFold::default(),
                future1.addr,
            )
            .expect("the printed address resolves");
            let FutureAt::Held(index) = found else {
                panic!("future1 did not resolve as a held future");
            };
            assert_eq!(census.held[index].addr, future1.addr);

            let found = future_at(
                &ctx.view,
                list,
                extents,
                census,
                &hansei_bundle::names::ImplFold::default(),
                future1.addr + 1,
            )
            .expect("an interior pointer resolves");
            let FutureAt::Held(index) = found else {
                panic!("the interior pointer did not resolve as a held future");
            };
            let h = &census.held[index];
            let size = ctx.view.ty(h.ty).expect("the root type resolves").size();
            assert!(
                h.addr <= future1.addr + 1 && future1.addr + 1 < h.addr + size,
                "resolved to {:#x} (size {size:#x}), which does not contain {:#x}",
                h.addr,
                future1.addr + 1
            );
        });
    }

    /// The containment check is half-open: an address one past a held
    /// future's end belongs to whatever strictly contains *it*, never
    /// to the future it borders.
    #[test]
    fn test_one_past_a_futures_end_is_outside_it() {
        with_target("futurelock", |ctx, list, extents, census| {
            let future1 = census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));
            let size = ctx.view.ty(future1.ty).expect("the type resolves").size();
            let end = future1.addr + size;

            if let Ok(FutureAt::Held(index)) = future_at(
                &ctx.view,
                list,
                extents,
                census,
                &hansei_bundle::names::ImplFold::default(),
                end,
            ) {
                let h = &census.held[index];
                assert_ne!(h.addr, future1.addr, "the future claims its own end");
                let hsize = ctx.view.ty(h.ty).expect("the type resolves").size();
                assert!(
                    h.addr <= end && end < h.addr + hsize,
                    "resolved to {:#x} (size {hsize:#x}), which does not contain {end:#x}",
                    h.addr
                );
            }
        });
    }

    /// A set's own address is refused with the set named: it is not one
    /// future, and its children are what `trace` can follow.
    #[test]
    fn test_a_sets_address_names_the_set() {
        with_target("unordered", |_ctx, list, extents, census| {
            let set = census.sets.first().expect("the fixture holds a set");
            let err = future_at(
                &_ctx.view,
                list,
                extents,
                census,
                &hansei_bundle::names::ImplFold::default(),
                set.addr,
            )
            .expect_err("a set is not one future");
            // The *queried* set, not another one the census holds: its
            // type — display-folded like every printed name — and its
            // own child count.
            assert!(
                err.to_string()
                    .contains(&*hansei_bundle::names::fold_type_name(
                        &set.ty,
                        &hansei_bundle::names::ImplFold::default()
                    )),
                "{err}"
            );
            assert!(
                err.to_string()
                    .contains(&format!("its {} child node(s)", set.children.len())),
                "{err}"
            );
        });
    }

    /// A miss says what the address is when that can be said: a task's
    /// own allocation points back at `trace <id>`, and an address
    /// nothing contains points at `tasks --futures`.
    #[test]
    fn test_future_misses_explain_the_address() {
        with_target("futurelock", |ctx, list, extents, census| {
            let header = list.tasks[0].addr.0;
            let err = future_at(
                &ctx.view,
                list,
                extents,
                census,
                &hansei_bundle::names::ImplFold::default(),
                header,
            )
            .expect_err("a task header is not a census future")
            .to_string();
            assert!(err.contains("trace <id>"), "{err}");
            assert!(err.contains("task"), "{err}");

            let err = future_at(
                &ctx.view,
                list,
                extents,
                census,
                &hansei_bundle::names::ImplFold::default(),
                0x10,
            )
            .expect_err("nothing contains 0x10")
            .to_string();
            assert!(err.contains("`tasks --futures`"), "{err}");
        });
    }

    /// The chain rendered from a held future's recorded root: the
    /// futurelock fixture's abandoned `future1`, traced on its own,
    /// shows the lock acquisition it is parked in — the very chain the
    /// task listing hides.
    #[test]
    fn test_held_future_renders_its_own_chain() {
        with_target("futurelock", |ctx, list, _extents, census| {
            let index = census
                .held
                .iter()
                .position(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));
            let future1 = &census.held[index];

            let ty = ctx
                .view
                .ty(future1.ty)
                .expect("the root type is in the bundle");
            let root =
                Value::read(ctx.proc, ty, future1.addr).expect("the recorded root reads back");
            let chain = ctx.await_chain(root);
            let holds = frame_holds(
                census,
                future1.owner,
                Some(census::Via::Held(index)),
                chain.frames.len(),
            );
            let wait = wait_line(ctx, &chain, list).expect("the wait target reads");

            let mut out = Vec::new();
            let elide = Default::default();
            let opts = TraceOpts {
                verbose: false,
                render: RenderOpts {
                    depth: 4,
                    ugly: false,
                    max_string_len: reify::DEFAULT_MAX_STRING_LEN,
                    max_array_values: reify::DEFAULT_MAX_ARRAY_VALUES,
                },
                elide: &elide,
                theme: output::Theme::plain(),
                heap: None,
            };
            print_await_chain(
                ctx,
                &chain,
                &opts,
                wait.as_deref(),
                &holds,
                &hansei_bundle::names::ImplFold::default(),
                None,
                &mut out,
            )
            .expect("the chain renders");
            let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
            assert!(
                rendered.contains("async fn      futurelock::do_async_thing"),
                "{rendered}"
            );
            assert!(
                rendered.contains("tokio::sync::batch_semaphore::Acquire"),
                "{rendered}"
            );
        });
    }

    /// Render the task listing the way `tasks` does, with no worker
    /// polling anything: what lwp holds a task is the session's to say,
    /// and no listing test turns on it.
    fn render(
        list: &TaskList,
        held: &[census::HeldFuture],
        sets: &[census::FutureSet],
        futures: bool,
        tasks: &[u64],
    ) -> String {
        render_joining(list, held, sets, &[], futures, tasks)
    }

    /// The same, for the tests that lay out join sets: no fixture
    /// spawns onto one, so they are built by hand.
    fn render_joining(
        list: &TaskList,
        held: &[census::HeldFuture],
        sets: &[census::FutureSet],
        join_sets: &[census::JoinSet],
        futures: bool,
        tasks: &[u64],
    ) -> String {
        // The narrowing print_tasks takes is by index now — the
        // filters' shape — so the ids these tests select by resolve
        // here.
        let selected: Option<std::collections::BTreeSet<usize>> = (!tasks.is_empty()).then(|| {
            list.tasks
                .iter()
                .enumerate()
                .filter(|(_, t)| t.task_id.is_some_and(|id| tasks.contains(&id)))
                .map(|(i, _)| i)
                .collect()
        });
        let rows = crate::tasks::build_rows(
            list,
            &[],
            &[],
            &HashMap::new(),
            &hansei_bundle::names::ImplFold::default(),
            &Default::default(),
            &Default::default(),
        );
        let mut out: Vec<u8> = Vec::new();
        print_tasks(
            list,
            &rows,
            &hansei_bundle::names::ImplFold::default(),
            &[],
            &HashMap::new(),
            &HashMap::new(),
            held,
            sets,
            join_sets,
            futures,
            None,
            selected.as_ref(),
            true,
            &mut out,
        )
        .expect("the listing renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// `tasks --futures` narrowed to the task that owns the fixture's
    /// one held future prints that future under it.
    #[test]
    fn test_futures_narrowed_to_the_owner_prints_its_futures() {
        with_target("futurelock", |_ctx, list, _extents, census| {
            let owner = census
                .held
                .first()
                .unwrap_or_else(|| panic!("the fixture holds a future"))
                .owner;
            let id = list.tasks[owner].task_id.expect("the owner has an id");

            let narrowed = render(list, &census.held, &census.sets, true, &[id]);
            assert!(narrowed.contains(&format!("Task {id}:")), "{narrowed}");
            // The row names the local it was found in and nothing more:
            // under `Held futures`, `held` would only repeat the
            // heading.
            assert!(narrowed.contains(", `future1`): 0x"), "{narrowed}");
            assert!(!narrowed.contains("held (frame"), "{narrowed}");
            // Narrowing narrows the listing itself, not just its
            // futures — and the footer counts the survivors, since a
            // filter's population is not the command line's to know.
            assert_eq!(narrowed.matches("\nTask ").count() + 1, 1, "{narrowed}");
            assert!(narrowed.ends_with("\n1 task\n"), "{narrowed}");
            assert!(narrowed.contains("    Held futures: 1\n"), "{narrowed}");

            // The whole listing carries every task, and the same find
            // under the same block: what the census found is all this
            // task's.
            let all = render(list, &census.held, &census.sets, true, &[]);
            for task in &list.tasks {
                let id = task.task_id.expect("every fixture task has an id");
                assert!(all.contains(&format!("Task {id}: ")), "{all}");
            }
            assert!(all.contains(", `future1`): 0x"), "{all}");
        });
    }

    /// Several ids print several blocks, in the listing's order rather
    /// than the order asked for, and an id asked for twice prints once.
    #[test]
    fn test_tasks_narrowed_to_several_ids() {
        with_target("channels", |_ctx, list, _extents, census| {
            let ids: Vec<u64> = list
                .tasks
                .iter()
                .map(|t| t.task_id.expect("every fixture task has an id"))
                .collect();
            assert!(ids.len() >= 2, "the fixture owns several tasks: {ids:?}");
            let (first, second) = (ids[0], ids[1]);

            let rendered = render(
                list,
                &census.held,
                &census.sets,
                false,
                &[second, first, second],
            );
            assert!(
                rendered.starts_with(&format!("Task {first}: ")),
                "{rendered}"
            );
            assert_eq!(rendered.matches("\nTask ").count() + 1, 2, "{rendered}");
            assert!(
                rendered.contains(&format!("\nTask {second}: ")),
                "{rendered}"
            );
            // The footer counts the narrowed listing's own population.
            assert!(rendered.ends_with("\n2 tasks\n"), "{rendered}");
        });
    }

    /// A future the census reached through a set child is printed under
    /// that child, and counted as being inside it — the distinction the
    /// summary exists to draw, since a flat listing of the two
    /// populations reads as twice as many futures as there are. No
    /// fixture nests this way, so the shape is laid out by hand.
    #[test]
    fn test_futures_prints_a_nested_find_under_what_holds_it() {
        with_target("futurelock", |_ctx, list, _extents, census| {
            let owner = census.held[0].owner;
            let ty = census.held[0].ty;
            let sets = vec![census::FutureSet {
                owner,
                frame: 0,
                local: "pending".to_string(),
                via: None,
                addr: 0x1000,
                ty: "FuturesUnordered<step::{async_fn_env#0}>".to_string(),
                children: vec![
                    census::SetChild {
                        depth: 1,
                        node: 0x2000,
                        future: Some("step::{async_fn_env#0}".to_string()),
                        root: None,
                        state: Some("Suspend0 — step.rs:9".to_string()),
                        waiting_on: None,
                        wait: None,
                        leaf: None,
                    },
                    census::SetChild {
                        depth: 1,
                        node: 0x2100,
                        future: None,
                        root: None,
                        state: None,
                        waiting_on: None,
                        wait: None,
                        leaf: None,
                    },
                ],
            }];
            let held = vec![census::HeldFuture {
                depth: 1,
                owner,
                frame: 1,
                local: "lock".to_string(),
                via: Some(census::Via::SetChild { set: 0, child: 0 }),
                slot: 0x3000,
                addr: 0x3000,
                ty,
                future: "Mutex::lock::{async_fn_env#0}".to_string(),
                state: None,
                waiting_on: None,
                wait: None,
                leaf: None,
            }];

            let rendered = render(list, &held, &sets, true, &[]);

            // The set sits under the owning task's `Join sets` row, the
            // held row two columns right of the child it was found in,
            // which is itself two right of the set. The task holds
            // nothing in its own frames, so `Held futures` is zero and
            // its listing empty: the one held future is inside the
            // child, which the child's own row counts.
            assert!(
                rendered.contains(
                    "    Held futures: 0\n    Join sets: 1 (1 future)\n        \
                     - FuturesUnordered<step> at 0x1000 (frame 0, `pending`): \
                     1 child in flight, 1 completed and not yet reaped\n            \
                     0x2000  async fn step  Suspend0 — step.rs:9\n                \
                     held (frame 1, `lock`): 0x3000  async fn Mutex::lock\n"
                ),
                "{rendered}"
            );
            // The reaped slot is not a future in flight, so the rows say
            // one child, not two — and they say it with or without the
            // listing under them.
            let counted = render(list, &held, &sets, false, &[]);
            assert!(counted.contains("    Held futures: 0\n"), "{counted}");
            assert!(
                counted.contains("    Join sets: 1 (1 future)\n"),
                "{counted}"
            );
            assert!(!counted.contains("FuturesUnordered"), "{counted}");
        });
    }

    /// A join set lists the tasks it holds by the ids `trace` takes,
    /// under a count of its own — its members are tasks the listing
    /// already carries. No fixture spawns onto a join set, so the shape
    /// is laid out by hand.
    #[test]
    fn test_futures_lists_a_join_set_by_task() {
        with_target("channels", |_ctx, list, _extents, _census| {
            // The set holds two of the fixture's own tasks and one the
            // runtime no longer owns, which is what a complete-but-not
            // yet-joined member looks like.
            let joined: Vec<&bundle::Task> = list.tasks.iter().take(2).collect();
            let owner = list.tasks.len() - 1;
            let mut children: Vec<census::JoinedTask> = joined
                .iter()
                .map(|task| census::JoinedTask {
                    entry: task.addr.0 + 0x40,
                    task: task.addr.0,
                    id: task.task_id,
                    state: task.state,
                    listed: true,
                })
                .collect();
            children.push(census::JoinedTask {
                entry: 0x5040,
                task: 0x5000,
                id: Some(99),
                state: TaskState(0b0010),
                listed: false,
            });
            let join_sets = vec![census::JoinSet {
                owner,
                frame: 0,
                local: "set".to_string(),
                via: None,
                addr: 0x4000,
                ty: "JoinSet<()>".to_string(),
                length: 3,
                children,
            }];

            let rendered = render_joining(list, &[], &[], &join_sets, true, &[]);
            let expected = format!(
                "    Held futures: 0\n    Join sets: 1 (3 tasks)\n        \
                 - JoinSet<()> at 0x4000 (frame 0, `set`): 3 tasks\n            \
                 task {}  {}  {}\n            task {}  {}  {}\n            \
                 task 99  <complete, awaiting join>\n",
                joined[0].task_id.expect("the fixture's tasks have ids"),
                future_name(
                    &joined[0].future,
                    &hansei_bundle::names::ImplFold::default()
                ),
                joined[0].state.lifecycle(),
                joined[1].task_id.expect("the fixture's tasks have ids"),
                future_name(
                    &joined[1].future,
                    &hansei_bundle::names::ImplFold::default()
                ),
                joined[1].state.lifecycle(),
            );
            assert!(rendered.contains(&expected), "{rendered}");
        });
    }

    /// A task the census found nothing for still prints its block, with
    /// every count zero — silence would read as a listing that failed.
    #[test]
    fn test_futures_narrowed_to_a_task_holding_none() {
        with_target("channels", |_ctx, list, _extents, census| {
            // Any task with no finds serves; which tasks hold something
            // legitimately grows as the census learns to see more.
            let empty = (0..list.tasks.len())
                .find(|i| {
                    !census.held.iter().any(|h| h.owner == *i)
                        && !census.sets.iter().any(|s| s.owner == *i)
                        && !census.join_sets.iter().any(|s| s.owner == *i)
                })
                .expect("some task holds nothing");
            let id = list.tasks[empty].task_id.expect("the task has an id");
            let rendered = render(list, &census.held, &census.sets, true, &[id]);
            assert!(rendered.starts_with(&format!("Task {id}: ")), "{rendered}");
            assert!(rendered.contains("    Held futures: 0\n"), "{rendered}");
            // A task that drives no set says so with a bare zero: what
            // the sets it does not have would hold is noise.
            assert!(rendered.contains("    Join sets: 0\n"), "{rendered}");
        });
    }
}

/// Offline trace-rendering tests: the flat await chain as `trace`
/// prints it, driven from a real extracted bundle joined against a real
/// captured snapshot.
///
/// The acceptance suite covers the same rendering end to end, but only
/// where a process can be cored; these run in plain `cargo test` on any
/// platform, which is what keeps the layout — the frame and detail
/// lines, the verbose blocks, the wait-target placement — under test
/// while it is being changed.
#[cfg(test)]
mod trace_render_tests {
    use super::{TraceOpts, frame_holds, print_await_chain, wait_line};
    use crate::{RenderOpts, output};
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::bundle::TaskStage;
    use hansei_runtime::tokio::census;

    /// Render the named task's await chain the way `trace` prints it —
    /// wait target and per-frame holds computed like the command's own
    /// path — with heap addresses masked so expectations compare
    /// exactly.
    fn trace(program: &str, future: &str, verbose: bool) -> String {
        trace_with(program, future, verbose, output::Theme::plain())
    }

    fn trace_with(program: &str, future: &str, verbose: bool, theme: output::Theme) -> String {
        let (bundle, snapshot) = testkit::load_any(program);
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);

        let (index, task) = list
            .tasks
            .iter()
            .enumerate()
            .find(|(_, t)| match &t.future {
                hansei_runtime::tokio::bundle::FutureInfo::Known(known) => {
                    known.display_name == future
                }
                _ => false,
            })
            .unwrap_or_else(|| panic!("no task running {future}"));
        let TaskStage::Running(root) = ctx.task_stage(task).expect("the task's stage decodes")
        else {
            panic!("{future} is not running");
        };

        let chain = ctx.await_chain(root);
        let census = census::census(&ctx, &list);
        let holds = frame_holds(&census, index, None, chain.frames.len());
        let wait = wait_line(&ctx, &chain, &list).expect("the wait target reads");
        let mut out = Vec::new();
        let elide = Default::default();
        let opts = TraceOpts {
            verbose,
            render: RenderOpts {
                depth: 4,
                ugly: false,
                max_string_len: reify::DEFAULT_MAX_STRING_LEN,
                max_array_values: reify::DEFAULT_MAX_ARRAY_VALUES,
            },
            elide: &elide,
            theme,
            heap: None,
        };
        print_await_chain(
            &ctx,
            &chain,
            &opts,
            wait.as_deref(),
            &holds,
            // The fixture bundle's own substitutions, like a session's:
            // the tokio frames of these chains print impl-folded.
            &hansei_bundle::names::ImplFold::for_bundle(&bundle),
            None,
            &mut out,
        )
        .expect("the chain renders");
        let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
        regex::Regex::new(r"0x[0-9a-f]+")
            .unwrap()
            .replace_all(&rendered, "0xADDR")
            .into_owned()
    }

    /// A frame parked in a terminal state reports the state and its
    /// source site with the `state` spelling — no resume-point claim —
    /// and the suspend inventory, being type information, is out of the
    /// default view entirely.
    #[test]
    fn test_a_terminal_state_reports_itself_without_inventory() {
        assert_eq!(
            trace(
                "walk-shapes",
                "walk_shapes::side_parker::{async_fn_env#0}",
                false
            ),
            "
#0  async fn      walk_shapes::side_parker
      state Unresumed — src/bin/walk-shapes.rs:204
"
        );
    }

    /// The three detail spellings in one chain: a coroutine's live
    /// state is `awaiting at` its resume point, a wrapper frame with no
    /// decoded state has no detail at all — the reading convention
    /// (frame N sits in frame N−1's live state) carries the chain — and
    /// a plain enum's decoded variant is `state:`, which claims no
    /// resume point. Frame 0 also holds `wz` — a future the chain does
    /// not run through — which its detail line tallies.
    #[test]
    fn test_wrapper_frames_read_by_position() {
        assert_eq!(
            trace(
                "walk-shapes",
                "walk_shapes::chained::{async_fn_env#0}",
                false
            ),
            "
#0  async fn      walk_shapes::chained
      awaiting at src/bin/walk-shapes.rs:103 (Suspend0, 1 local; holds 1 pending future)
#1  future        walk_shapes::WrapS<walk_shapes::WrapE<walk_shapes::deep>>
#2  future        walk_shapes::WrapE<walk_shapes::deep>
      state: Running
#3  async fn      walk_shapes::deep
      awaiting at src/bin/walk-shapes.rs:88 (Suspend0, 1 local)
#4  future        tokio::sync::notify::Notified
"
        );
    }

    /// The live state is the frame's one default detail: the other
    /// suspend point (line 38 and what it would await) is type
    /// information and stays out until `--verbose` asks for it.
    #[test]
    fn test_the_live_state_is_the_frames_one_detail() {
        assert_eq!(
            trace(
                "simple-await",
                "simple_await::work::{async_fn_env#0}",
                false
            ),
            "
#0  async fn      simple_await::work
      awaiting at src/bin/simple-await.rs:40 (Suspend1, 12 locals)
#1  future        tokio::sync::oneshot::Receiver<u32>
"
        );
    }

    /// The whole flat layout on a deep chain: the decoded wait target
    /// leads as the `Waiting on:` summary and lands again on the leaf
    /// frame, every frame keeps the same two-line shape at the same
    /// indent, and the frame holding a future the chain does not run
    /// through — the futurelock tell — carries the tally on its detail
    /// line.
    #[test]
    fn test_the_wait_target_leads_and_the_leaf_repeats_it() {
        let rendered = trace(
            "futurelock",
            "futurelock::main::{async_block#0}::{async_block_env#0}",
            false,
        );
        assert_eq!(
            rendered,
            "
Waiting on: a tokio::sync::Mutex (semaphore 0xADDR): 1 permit requested, 0 available; wake queue: task 5

#0  async block   futurelock::main::{async_block#0}
      awaiting at src/bin/futurelock.rs:28 (Suspend1, 1 local)
#1  async fn      futurelock::do_stuff
      awaiting at src/bin/futurelock.rs:70 (Suspend1, 3 locals; holds 1 pending future)
#2  async fn      futurelock::do_async_thing
      awaiting at src/bin/futurelock.rs:78 (Suspend0, 2 locals)
#3  async fn      tokio::sync::mutex::Mutex::lock<()>
      awaiting at tokio-1.52.4/src/sync/mutex.rs:455 (Suspend0)
#4  async block   tokio::sync::mutex::Mutex::lock::{async_fn#0}<()>
      awaiting at tokio-1.52.4/src/sync/mutex.rs:436 (Suspend0)
#5  async fn      tokio::sync::mutex::Mutex::acquire<()>
      awaiting at tokio-1.52.4/src/sync/mutex.rs:658 (Suspend1)
#6  future        tokio::sync::batch_semaphore::Acquire
      waiting on a tokio::sync::Mutex (semaphore 0xADDR): 1 permit requested, 0 available; wake queue: task 5
"
        );
    }

    /// A dyn frame keeps its ` [dyn]` marker as part of the name's
    /// identity — the one thing allowed after a type name — and a
    /// suspend point listed after the live one stays out of the default
    /// view like any other.
    #[test]
    fn test_dyn_frames_keep_their_marker() {
        assert_eq!(
            trace("dyn-future", "dyn_future::driver::{async_fn_env#0}", false),
            "
#0  async fn      dyn_future::driver
      awaiting at src/bin/dyn-future.rs:36 (Suspend0, 1 local)
#1  async fn      dyn_future::boxed_leaf [dyn]
      awaiting at src/bin/dyn-future.rs:12 (Suspend0)
#2  future        tokio::sync::oneshot::Receiver<u32>
"
        );
    }

    /// Under `--verbose` a pointer into another task's allocation is
    /// labelled with that task's id, the way `exec_trace` wires it up:
    /// the joiner's `JoinHandle` holds the sleeper's `Header` pointer,
    /// which must name the task a reader would trace next.
    #[test]
    fn test_verbose_labels_pointers_into_other_tasks() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);

        let joiner = list
            .tasks
            .iter()
            .find(|t| t.task_id == Some(4))
            .expect("the joiner is task 4");
        let TaskStage::Running(root) = ctx.task_stage(joiner).expect("the joiner's stage decodes")
        else {
            panic!("the joiner is not running");
        };

        let extents = ctx.task_extents(&list);
        let annotate = |ptr: u64| {
            let (index, _) = extents.locate(ptr)?;
            list.tasks[index].task_id.map(|id| format!("task {id}"))
        };

        let chain = ctx.await_chain(root);
        let wait = wait_line(&ctx, &chain, &list).expect("the wait target reads");
        let mut out = Vec::new();
        let elide = Default::default();
        let opts = TraceOpts {
            verbose: true,
            render: RenderOpts {
                depth: 4,
                ugly: false,
                max_string_len: reify::DEFAULT_MAX_STRING_LEN,
                max_array_values: reify::DEFAULT_MAX_ARRAY_VALUES,
            },
            elide: &elide,
            theme: output::Theme::plain(),
            heap: None,
        };
        print_await_chain(
            &ctx,
            &chain,
            &opts,
            wait.as_deref(),
            &[],
            &hansei_bundle::names::ImplFold::default(),
            Some(&annotate),
            &mut out,
        )
        .expect("the chain renders");
        let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
        assert!(rendered.contains("(task 3)"), "{rendered}");
    }

    /// `--verbose` adds the frame's blocks in order — the live state's
    /// locals, then the other suspend points — at the fixed indent
    /// ladder: sub-blocks at 6, entries at 8, values at 10. The detail
    /// line keeps its tally, and the inactive row keeps its count:
    /// every variant shares the enum's storage, so its locals cannot be
    /// read at all — and names its would-be awaitee.
    #[test]
    fn test_verbose_adds_locals_then_the_inventory() {
        let rendered = trace("simple-await", "simple_await::work::{async_fn_env#0}", true);
        assert!(
            rendered.contains(
                "      awaiting at src/bin/simple-await.rs:40 (Suspend1, 12 locals)\
                 \n      locals:\n        count: 3\n"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "      other suspend points:\n        Suspend0 — src/bin/simple-await.rs:38 \
                 (13 locals) → async fn simple_await::ready_value\n"
            ),
            "{rendered}"
        );
        // The blocks keep their order: locals, then the inventory.
        let locals = rendered.find("locals:").expect("a locals block");
        let inventory = rendered
            .find("other suspend points:")
            .expect("an inventory block");
        assert!(locals < inventory, "{rendered}");
    }

    /// A terminal theme styles without saying anything new: the wait
    /// target is bold in both its places, a frame's type name carries
    /// the name hue, a detail line's source location the location hue —
    /// and the plain theme, which every non-terminal sink gets, emits
    /// not one escape byte.
    #[test]
    fn test_a_terminal_theme_styles_and_the_plain_one_stays_bytes() {
        let future = "futurelock::main::{async_block#0}::{async_block_env#0}";
        let styled = trace_with("futurelock", future, false, output::Theme::forced());
        let target = "a tokio::sync::Mutex (semaphore 0xADDR): \
                      1 permit requested, 0 available; wake queue: task 5";
        assert!(
            styled.contains(&format!("Waiting on: \x1b[1m{target}\x1b[0m\n")),
            "{styled}"
        );
        assert!(
            styled.contains(&format!("      waiting on \x1b[1m{target}\x1b[0m\n")),
            "{styled}"
        );
        assert!(
            styled.contains("#0  async block   \x1b[36mfuturelock::main::{async_block#0}\x1b[0m\n"),
            "{styled}"
        );
        assert!(
            styled.contains(
                "      awaiting at \x1b[32msrc/bin/futurelock.rs:28\x1b[0m (Suspend1, 1 local)\n"
            ),
            "{styled}"
        );
        assert!(!trace("futurelock", future, false).contains('\x1b'));
    }

    /// The inventory is dimmed whole — the heading and each row — with
    /// no styled span inside it, whose reset would end the dimming
    /// mid-line.
    #[test]
    fn test_the_inventory_dims_whole_lines() {
        let styled = trace_with(
            "simple-await",
            "simple_await::work::{async_fn_env#0}",
            true,
            output::Theme::forced(),
        );
        assert!(
            styled.contains(
                "      \x1b[2mother suspend points:\x1b[0m\n        \
                 \x1b[2mSuspend0 — src/bin/simple-await.rs:38 (13 locals) \
                 → async fn simple_await::ready_value\x1b[0m\n"
            ),
            "{styled}"
        );
    }
}

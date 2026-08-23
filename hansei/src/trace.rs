//! The `trace` command: await chains rendered one line per future,
//! for a task by id or a lone future by address.

use crate::tasks::{future_name, no_such_task, task_label};
use crate::whatis::via_suffix;
use crate::{Session, TraceOpts, TraceTarget, output};

use anyhow::{Context as _, Result};
use hansei_bundle::names;
use hansei_bundle::{BundleMember, BundleType, BundleView};
use hansei_runtime::tokio::{Lifecycle, bundle, census};
use reify::Value;

use std::fmt;
use std::io::{self, Write};

pub(crate) fn exec_trace(
    session: &Session<'_>,
    target: TraceTarget,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    match target {
        TraceTarget::Task(id) => exec_trace_task(session, id, opts, out),
        TraceTarget::Future(addr) => exec_trace_future(session, addr, opts, out),
    }
}

fn exec_trace_task(
    session: &Session<'_>,
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
        }
        bundle::TaskStage::Finished(result) => {
            // Result<T::Output, JoinError>: Ok is a normal return, Err a
            // panic or cancellation.
            writeln!(out)?;
            writeln!(
                out,
                "The task has finished; its output has not been consumed:"
            )?;
            let mut value = result.display_from_target(ctx.proc, opts.render.depth);
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
fn exec_trace_future(
    session: &Session<'_>,
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
enum FutureAt {
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
fn future_at(
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
fn print_trace_chain<'b>(
    session: &Session<'b>,
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
fn wait_line<T: proc::Target>(
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
fn frame_holds(
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

    let last = chain.frames.len().checked_sub(1);
    let num_width = format!("#{}", last.unwrap_or(0)).len();
    for (i, frame) in chain.frames.iter().enumerate() {
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
    }
    print_chain_end(chain, impls, out)
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
                        .elide_override(opts.elide)
                        .line_prefix(&value_prefix);
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

/// The ` on lwp N` suffix of a torn-state warning, when some worker is
/// mid-poll in the task.
fn polling_lwp(workers: &[bundle::Worker], id: Option<u64>) -> String {
    id.and_then(|id| workers.iter().find(|w| w.current_task_id == Some(id)))
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
                },
                elide: &elide,
                theme: output::Theme::plain(),
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
        let mut out: Vec<u8> = Vec::new();
        print_tasks(
            list,
            &hansei_bundle::names::ImplFold::default(),
            &[],
            &HashMap::new(),
            held,
            sets,
            join_sets,
            futures,
            tasks,
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
            // futures — and the block it leaves is the whole answer, so
            // there is no count under it restating the ids asked for.
            assert_eq!(narrowed.matches("\nTask ").count() + 1, 1, "{narrowed}");
            assert!(!narrowed.contains("\n1 task\n"), "{narrowed}");
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
            // Two blocks are still not a listing, so nothing counts them.
            assert!(!rendered.contains("\n2 tasks\n"), "{rendered}");
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

    /// An id the runtime does not own is an error naming the ids it
    /// does, not an empty listing.
    #[test]
    fn test_futures_rejects_an_unknown_task_id() {
        with_target("futurelock", |_ctx, list, _extents, census| {
            let unknown = list
                .tasks
                .iter()
                .filter_map(|t| t.task_id)
                .max()
                .expect("some task has an id")
                + 1;
            let mut out = Vec::new();
            let err = print_tasks(
                list,
                &hansei_bundle::names::ImplFold::default(),
                &[],
                &HashMap::new(),
                &census.held,
                &census.sets,
                &census.join_sets,
                true,
                &[unknown],
                &mut out,
            )
            .expect_err("no task owns that id")
            .to_string();
            assert!(err.contains(&format!("id {unknown}")), "{err}");
            assert!(out.is_empty(), "printed {out:?} before failing");
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
            },
            elide: &elide,
            theme,
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
    /// suspend point (line 33 and what it would await) is type
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
      awaiting at src/bin/simple-await.rs:35 (Suspend1, 10 locals)
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
            },
            elide: &elide,
            theme: output::Theme::plain(),
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
                "      awaiting at src/bin/simple-await.rs:35 (Suspend1, 10 locals)\
                 \n      locals:\n        count: 3\n"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "      other suspend points:\n        Suspend0 — src/bin/simple-await.rs:33 \
                 (11 locals) → async fn simple_await::ready_value\n"
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
                 \x1b[2mSuspend0 — src/bin/simple-await.rs:33 (11 locals) \
                 → async fn simple_await::ready_value\x1b[0m\n"
            ),
            "{styled}"
        );
    }
}

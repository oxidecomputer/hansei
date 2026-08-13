//! The `trace` command: await chains rendered one line per future,
//! for a task by id or a lone future by address.

use crate::tasks::{future_name, no_such_task, task_label};
use crate::whatis::via_suffix;
use crate::{Session, TraceOpts, TraceTarget};

use anyhow::{Context as _, Result};
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

    let Some(task) = list.tasks.iter().find(|t| t.task_id == Some(task_id)) else {
        return Err(no_such_task(list, task_id));
    };

    let name = future_name(&task.future);
    writeln!(out, "Task {task_id}: {name} ({})", task.state.lifecycle())?;
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
        let lwp = polling_lwp(session, Some(task_id));
        writeln!(
            io::stderr(),
            "warning: task {task_id} is running{lwp}; its state may be torn"
        )?;
    }

    writeln!(out)?;
    match ctx.task_stage(task)? {
        bundle::TaskStage::Running(future) => {
            let chain = ctx.await_chain(future);
            print_trace_chain(session, &chain, opts, out)?;
        }
        bundle::TaskStage::Finished(result) => {
            // Result<T::Output, JoinError>: Ok is a normal return, Err a
            // panic or cancellation.
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

    let found = future_at(&ctx.view, list, session.extents(), census, addr)?;
    let (root, owner) = match found {
        FutureAt::Held(h) => {
            let via = via_suffix(census, h.via);
            writeln!(out, "Future {:#x}: {}", h.addr, h.future)?;
            writeln!(
                out,
                "Held by: {} — {} (frame {}, `{}`{via})",
                task_label(list, h.owner),
                future_name(&list.tasks[h.owner].future),
                h.frame,
                h.local
            )?;
            (
                census::FutureRoot {
                    addr: h.addr,
                    ty: h.ty,
                },
                h.owner,
            )
        }
        FutureAt::Child { set, child, root } => {
            let via = via_suffix(census, set.via);
            let future = child.future.as_deref().unwrap_or("<undecoded>");
            writeln!(out, "Future {:#x}: {future}", child.node)?;
            writeln!(
                out,
                "Child of: {} at {:#x} (frame {}, `{}`{via}), polled by {} — {}",
                set.ty,
                set.addr,
                set.frame,
                set.local,
                task_label(list, set.owner),
                future_name(&list.tasks[set.owner].future)
            )?;
            (root, set.owner)
        }
    };

    // The owning task mid-poll is mutating its frames — and this future
    // with them — while we read; anything below may be torn.
    let task = &list.tasks[owner];
    if task.state.lifecycle() == Lifecycle::Running {
        let lwp = polling_lwp(session, task.task_id);
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

    writeln!(out)?;
    let chain = ctx.await_chain(value);
    print_trace_chain(session, &chain, opts, out)
}

/// What a future address resolved to: the census row that names it,
/// and — for a set child — the chain root to trace it from.
#[derive(Debug)]
enum FutureAt<'c> {
    Held(&'c census::HeldFuture),
    Child {
        set: &'c census::FutureSet,
        child: &'c census::SetChild,
        root: census::FutureRoot,
    },
}

/// Resolve `addr` to the census future it names: a held future's
/// address, a set child's node address, or any pointer into either —
/// an interior pointer picks the tightest containing future, since a
/// by-value awaitee sits inside the future holding it. A miss says
/// what the address *is* whenever that can be said: a set itself, a
/// completed child, a task's own allocation.
fn future_at<'c>(
    view: &BundleView<'_>,
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &'c census::FutureCensus,
    addr: u64,
) -> Result<FutureAt<'c>> {
    if let Some(h) = census.held.iter().find(|h| h.addr == addr) {
        return Ok(FutureAt::Held(h));
    }
    if let Some((set_index, child_index, _)) = census.locate(addr) {
        let set = &census.sets[set_index];
        let child = &set.children[child_index];
        let Some(root) = child.root else {
            anyhow::bail!(
                "the child at {:#x} of the {} at {:#x} has completed; \
                 there is no future left to trace",
                child.node,
                set.ty,
                set.addr
            );
        };
        return Ok(FutureAt::Child { set, child, root });
    }
    if let Some(set) = census.sets.iter().find(|s| s.addr == addr) {
        anyhow::bail!(
            "{addr:#x} is the {} polled by {}, not one future; \
             trace one of its {} child node(s) (`tasks --futures` lists them)",
            set.ty,
            task_label(list, set.owner),
            set.children.len()
        );
    }
    let containing = census
        .held
        .iter()
        .filter_map(|h| {
            let size = view.ty(h.ty)?.size();
            (h.addr <= addr && addr < h.addr + size).then_some((size, h))
        })
        .min_by_key(|&(size, _)| size);
    if let Some((_, h)) = containing {
        return Ok(FutureAt::Held(h));
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

/// Render an await chain the way `trace` prints one. Values shown
/// under --verbose may hold raw pointers into task allocations
/// (wakers, JoinHandles); name those with the task id so the reader
/// knows what to trace next. The traced task itself is named like any
/// other: a wake-queue entry resolving back to it is a finding (the
/// futurelock shape), not noise. A pointer into a sub-executor's child
/// node instead names the task that polls the set — the task a wake
/// there would ultimately run.
fn print_trace_chain<'b>(
    session: &Session<'b>,
    chain: &bundle::AwaitChain<'b>,
    opts: &TraceOpts<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let list = &session.tasks;
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
    print_await_chain(&session.ctx, list, chain, opts, annotate, out)
}

/// Render an await chain, one line per future, each coroutine frame
/// followed by every place it can park with the one it is parked at
/// marked, and the live locals of that state when verbose.
///
/// A frame's child hangs from its active suspend row, so how far each
/// frame indents follows from its predecessors' inventories rather than
/// from its depth alone, and a state listed after the active one is
/// printed once the subtree that grew out of the active one is closed.
fn print_await_chain<'b, T: proc::Target>(
    ctx: &bundle::Context<'b, T>,
    list: &bundle::TaskList,
    chain: &bundle::AwaitChain<'b>,
    opts: &TraceOpts<'_>,
    annotate: Option<&reify::AddrAnnotator<'_>>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let active_frame = chain.frames.len().checked_sub(1);
    let mut node_indent = FRAME_ROOT_INDENT;
    let mut detail_indent = frame_detail_indent(node_indent);
    // One per frame, kept so the states listed after each active row can
    // be printed — in the columns their whole inventory was laid out
    // in — once the chain below them is done.
    let mut tables: Vec<SuspendTable<'b>> = Vec::new();
    for (i, frame) in chain.frames.iter().enumerate() {
        let active = Some(i) == active_frame;
        let marker = if active { '*' } else { ' ' };
        let kind = async_kind(
            frame.future.ty.name(),
            frame.state.as_ref().map(|state| state.name),
        );
        let dyn_marker = if frame.dyn_symbol.is_some() {
            " [dyn]"
        } else {
            ""
        };
        if i == 0 {
            writeln!(
                out,
                "  {i}  {kind:<13} {}{dyn_marker}",
                frame.future.ty.name()
            )?;
        } else {
            let indent = " ".repeat(node_indent);
            writeln!(
                out,
                "{indent}└─{marker} {i}  {kind:<13} {}{dyn_marker}",
                frame.future.ty.name()
            )?;
        }

        detail_indent = frame_detail_indent(node_indent);
        let table = SuspendTable::new(suspend_rows(frame), opts.verbose, detail_indent.clone());
        let rows_empty = table.is_empty();
        tables.push(table);

        if rows_empty {
            // Not a coroutine: a leaf future has no states at all, and an
            // ordinary enum's variants are not suspend points, so the one
            // it decoded to is reported on its own.
            if let Some(state) = &frame.state {
                let loc = state
                    .await_loc
                    .map(|(file, line)| format!(" — {file}:{line}"))
                    .unwrap_or_default();
                // Align the state value with the type name above it. Child
                // nodes have a frame-number column between the tree branch
                // and the kind label; the state line must account for it.
                let label_width = state_label_width(i);
                writeln!(
                    out,
                    "{detail_indent}{:<label_width$} {}{loc}",
                    "state", state.name
                )?;
            }
        } else {
            writeln!(out, "{detail_indent}suspends:")?;
            tables.last().expect("just pushed").print_to_active(out)?;
        }

        if opts.verbose && (frame.state.is_some() || active) {
            let payload = match &frame.state {
                Some(state) => state.payload,
                None => frame.future,
            };
            let locals = state_locals(payload.ty);
            // The locals belong to the marked row, so they hang from it
            // rather than from the frame; a frame with no inventory keeps
            // them against its own detail column.
            let heading_indent = if rows_empty {
                detail_indent.clone()
            } else {
                format!("{detail_indent}  ")
            };
            if !locals.is_empty() {
                let heading = if frame.state.is_some() {
                    "locals:"
                } else {
                    "fields:"
                };
                writeln!(out, "{heading_indent}{heading}")?;
            }
            let value_indent = format!("{heading_indent}  ");
            // print_variable's contract: the value's lines after the
            // first open with the variable's indent plus two spaces.
            let value_prefix = format!("{value_indent}  ");
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
                        print_variable(out, &value_indent, m.name(), &format_args!("{disp:#}"))?;
                    }
                    None => writeln!(out, "{value_indent}{}: <unreadable>", m.name())?,
                }
            }
        }

        // An inventory introduces the child itself: the marked row *is*
        // the await that produced it, and the branch descends from there.
        if rows_empty {
            if !active {
                writeln!(out, "{detail_indent}awaits:")?;
            }
            node_indent += FRAME_DETAIL_STEP;
        } else {
            node_indent += FRAME_DETAIL_STEP + SUSPEND_ROW_STEP;
        }
    }

    match &chain.end {
        bundle::ChainEnd::Leaf => {}
        bundle::ChainEnd::UnknownDyn {
            pointee,
            poll_symbol,
        } => {
            writeln!(
                out,
                "the chain continues into a {pointee} whose concrete type is not in the bundle"
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
                "the chain continues into a {pointee}, but its normalized poll symbol is ambiguous"
            )?;
            writeln!(out, "     poll fn: {symbol}")?;
            for candidate in candidates {
                writeln!(out, "     candidate: {candidate}")?;
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

    // Name what the task is actually waiting on when the leaf is a
    // known primitive. It belongs to the deepest frame, so it goes out
    // before any inventory closes back over it.
    match ctx.wait_target(chain, list) {
        Some(Ok(target)) => writeln!(out, "{detail_indent}waiting on {target}")?,
        Some(Err(e)) => writeln!(
            io::stderr(),
            "warning: failed to read what the leaf future waits on: {e:#}"
        )?,
        None => {}
    }

    // The states each frame lists after the one it is parked in. They
    // are printed here, innermost frame first, because the subtree that
    // grew out of the active row sits between them and their own block.
    for table in tables.iter().rev() {
        table.print_after_active(out)?;
    }
    Ok(())
}

/// The column the outermost future's node line starts at.
const FRAME_ROOT_INDENT: usize = 2;

/// How far a frame's detail sits inside its node line.
const FRAME_DETAIL_STEP: usize = 3;

/// How far a suspend row's text sits inside the detail column, leaving
/// room for the marker in front of it.
const SUSPEND_ROW_STEP: usize = 2;

/// Marks the state a coroutine is parked in. Distinct from the `*` the
/// tree puts on the leaf frame, which says where the chain ends rather
/// than which of a frame's suspend points is live.
const SUSPEND_MARKER: char = '▸';

fn frame_detail_indent(node_indent: usize) -> String {
    " ".repeat(node_indent + FRAME_DETAIL_STEP)
}

fn state_label_width(frame: usize) -> usize {
    if frame == 0 {
        13
    } else {
        frame.to_string().len() + 16
    }
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

/// A frame's suspend rows laid out in columns, printable in two pieces.
///
/// The child frame is printed between them — it hangs from the marked
/// row — so the widths are settled once, over the whole inventory, and
/// both pieces are written against them. An empty column is omitted
/// rather than padded, so a frame whose states hold nothing does not
/// carry a blank gutter down the trace.
struct SuspendTable<'b> {
    rows: Vec<SuspendRow<'b>>,
    /// `(location, locals, awaitee)`, already reduced to what each row
    /// shows: the marked row drops its awaitee, which the child frame
    /// beneath it names anyway, and under `verbose` drops its locals
    /// count, since those values are about to be listed in full.
    cells: Vec<(String, String, &'b str)>,
    detail_indent: String,
    name_width: usize,
    loc_width: usize,
    locals_width: usize,
}

impl<'b> SuspendTable<'b> {
    fn new(rows: Vec<SuspendRow<'b>>, verbose: bool, detail_indent: String) -> Self {
        let cells: Vec<(String, String, &'b str)> = rows
            .iter()
            .map(|row| {
                let loc = row
                    .loc
                    .map(|(file, line)| format!("{file}:{line}"))
                    .unwrap_or_default();
                let locals = match row.locals {
                    0 => String::new(),
                    _ if row.active && verbose => String::new(),
                    1 => "1 local".to_string(),
                    n => format!("{n} locals"),
                };
                let awaitee = if row.active {
                    ""
                } else {
                    row.awaitee.unwrap_or_default()
                };
                (loc, locals, awaitee)
            })
            .collect();
        let width =
            |f: fn(&(String, String, &str)) -> usize| cells.iter().map(f).max().unwrap_or(0);
        Self {
            name_width: rows.iter().map(|row| row.name.len()).max().unwrap_or(0),
            loc_width: width(|c| c.0.len()),
            locals_width: width(|c| c.1.len()),
            rows,
            cells,
            detail_indent,
        }
    }

    fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Where the marked row sits, or the end of the table when no row is
    /// marked — a state that matched no variant, which leaves nothing to
    /// hang a child from.
    fn active(&self) -> usize {
        self.rows
            .iter()
            .position(|row| row.active)
            .unwrap_or(self.rows.len().saturating_sub(1))
    }

    /// The states up to and including the one the frame is parked in.
    fn print_to_active(&self, out: &mut dyn io::Write) -> Result<()> {
        self.print_range(0, self.active() + 1, out)
    }

    /// The states the frame lists after the one it is parked in.
    fn print_after_active(&self, out: &mut dyn io::Write) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        self.print_range(self.active() + 1, self.rows.len(), out)
    }

    fn print_range(&self, from: usize, to: usize, out: &mut dyn io::Write) -> Result<()> {
        let (name_width, loc_width, locals_width) =
            (self.name_width, self.loc_width, self.locals_width);
        for (row, (loc, locals, awaitee)) in self.rows[from..to].iter().zip(&self.cells[from..to]) {
            let marker = if row.active { SUSPEND_MARKER } else { ' ' };
            let mut line = format!("{}{marker} {:<name_width$}", self.detail_indent, row.name);
            if loc_width > 0 {
                line.push_str(&format!("  {loc:<loc_width$}"));
            }
            if locals_width > 0 {
                line.push_str(&format!("  {locals:<locals_width$}"));
            }
            if !awaitee.is_empty() {
                line.push_str(&format!("  {awaitee}"));
            }
            writeln!(out, "{}", line.trim_end())?;
        }
        Ok(())
    }
}

/// Classify the outer future type from rustc's generated DWARF basename.
/// The names are an implementation detail, so an unrecognized state
/// machine deliberately receives the neutral `async` label.
fn async_kind(name: &str, state: Option<&str>) -> &'static str {
    // Ignore generic arguments: an ordinary wrapper such as
    // `PollFn<foo::{async_fn_env#0}>` is not itself an async fn.
    let mut outer = String::with_capacity(name.len());
    let mut generic_depth = 0usize;
    for c in name.chars() {
        match c {
            '<' => generic_depth += 1,
            '>' => generic_depth = generic_depth.saturating_sub(1),
            _ if generic_depth == 0 => outer.push(c),
            _ => {}
        }
    }
    if outer.rsplit("::").next().is_some_and(|component| {
        component.starts_with("{async_fn_env#") && component.ends_with('}')
    }) {
        "async fn"
    } else if outer.rsplit("::").next().is_some_and(|component| {
        component.starts_with("{async_block_env#") && component.ends_with('}')
    }) {
        "async block"
    } else if outer.rsplit("::").next().is_some_and(|component| {
        component.starts_with("{async_closure_env#") && component.ends_with('}')
    }) {
        "async closure"
    } else if state.is_some_and(|state| {
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

/// The ` on LWP N` suffix of a torn-state warning, when some worker is
/// mid-poll in the task.
fn polling_lwp(session: &Session<'_>, id: Option<u64>) -> String {
    id.and_then(|id| {
        session
            .workers
            .iter()
            .find(|w| w.current_task_id == Some(id))
    })
    .map(|w| format!(" on LWP {}", w.tid))
    .unwrap_or_default()
}

#[cfg(test)]
mod variable_format_tests {
    use super::{async_kind, print_variable, state_label_width};

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

    #[test]
    fn state_alignment_accounts_for_frame_number_width() {
        assert_eq!(state_label_width(0), 13);
        assert_eq!(state_label_width(1), 17);
        assert_eq!(state_label_width(10), 18);
    }
}

/// Offline future-trace tests: what `trace <0x-address>` resolves an
/// address to, and the chain it renders from there, over a real
/// extracted bundle joined against a real captured snapshot.
#[cfg(test)]
mod future_trace_tests {
    use super::{FutureAt, TraceOpts, future_at, print_await_chain};
    use crate::RenderOpts;
    use crate::tasks::{future_name, print_tasks};
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
        let (bundle, snapshot) = testkit::load(program);
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

            let found = future_at(&ctx.view, list, extents, census, future1.addr)
                .expect("the printed address resolves");
            let FutureAt::Held(h) = found else {
                panic!("future1 did not resolve as a held future");
            };
            assert_eq!(h.addr, future1.addr);

            let found = future_at(&ctx.view, list, extents, census, future1.addr + 1)
                .expect("an interior pointer resolves");
            let FutureAt::Held(h) = found else {
                panic!("the interior pointer did not resolve as a held future");
            };
            let size = ctx.view.ty(h.ty).expect("the root type resolves").size();
            assert!(
                h.addr <= future1.addr + 1 && future1.addr + 1 < h.addr + size,
                "resolved to {:#x} (size {size:#x}), which does not contain {:#x}",
                h.addr,
                future1.addr + 1
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
            let err = future_at(&ctx.view, list, extents, census, header)
                .expect_err("a task header is not a census future")
                .to_string();
            assert!(err.contains("trace <id>"), "{err}");
            assert!(err.contains("task"), "{err}");

            let err = future_at(&ctx.view, list, extents, census, 0x10)
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
            let future1 = census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));

            let ty = ctx
                .view
                .ty(future1.ty)
                .expect("the root type is in the bundle");
            let root =
                Value::read(ctx.proc, ty, future1.addr).expect("the recorded root reads back");
            let chain = ctx.await_chain(root);

            let mut out = Vec::new();
            let elide = Default::default();
            let opts = TraceOpts {
                verbose: false,
                render: RenderOpts {
                    depth: 4,
                    ugly: false,
                },
                elide: &elide,
            };
            print_await_chain(ctx, list, &chain, &opts, None, &mut out).expect("the chain renders");
            let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
            assert!(
                rendered.contains("futurelock::do_async_thing::{async_fn_env#0}"),
                "{rendered}"
            );
            assert!(
                rendered.contains("tokio::sync::batch_semaphore::Acquire"),
                "{rendered}"
            );
        });
    }

    /// Render the task listing the way `tasks` does, with no worker
    /// polling anything: what LWP holds a task is the session's to say,
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
                     - FuturesUnordered<step::{async_fn_env#0}> at 0x1000 (frame 0, `pending`): \
                     1 child in flight, 1 completed and not yet reaped\n            \
                     0x2000  step::{async_fn_env#0}  Suspend0 — step.rs:9\n                \
                     held (frame 1, `lock`): 0x3000  Mutex::lock::{async_fn_env#0}\n"
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
                future_name(&joined[0].future),
                joined[0].state.lifecycle(),
                joined[1].task_id.expect("the fixture's tasks have ids"),
                future_name(&joined[1].future),
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

/// Offline trace-rendering tests: the await tree as `trace` prints it,
/// driven from a real extracted bundle joined against a real captured
/// snapshot.
///
/// The acceptance suite covers the same rendering end to end, but only
/// where a process can be cored; these run in plain `cargo test` on any
/// platform, which is what keeps the tree's shape — the suspend
/// inventories and the indent that accumulates through them — under test
/// while it is being changed.
#[cfg(test)]
mod trace_render_tests {
    use super::{TraceOpts, print_await_chain};
    use crate::RenderOpts;
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::bundle::TaskStage;

    /// Render task `task_id`'s await chain from the named fixture pair,
    /// with heap addresses masked so the expectation compares exactly.
    fn trace(program: &str, future: &str, verbose: bool) -> String {
        let (bundle, snapshot) = testkit::load(program);
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);

        let task = list
            .tasks
            .iter()
            .find(|t| match &t.future {
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
        let mut out = Vec::new();
        let elide = Default::default();
        let opts = TraceOpts {
            verbose,
            render: RenderOpts {
                depth: 4,
                ugly: false,
            },
            elide: &elide,
        };
        print_await_chain(&ctx, &list, &chain, &opts, None, &mut out).expect("the chain renders");
        let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
        regex::Regex::new(r"0x[0-9a-f]+")
            .unwrap()
            .replace_all(&rendered, "0xADDR")
            .into_owned()
    }

    /// Two suspend points, parked at the second: the row order is the
    /// enum's, the marked row drops the awaitee its child already names,
    /// and the child hangs from it.
    #[test]
    fn test_inventory_marks_the_active_state() {
        assert_eq!(
            trace(
                "simple-await",
                "simple_await::work::{async_fn_env#0}",
                false
            ),
            "  0  async fn      simple_await::work::{async_fn_env#0}
     suspends:
       Suspend0  src/bin/simple-await.rs:32  11 locals  simple_await::ready_value::{async_fn_env#0}
     ▸ Suspend1  src/bin/simple-await.rs:34  10 locals
       └─* 1  future        tokio::sync::oneshot::Receiver<u32>
"
        );
    }

    /// A frame whose states hold nothing carries no locals column, and
    /// the indent accumulates through each frame's inventory rather than
    /// by a fixed step per level.
    #[test]
    fn test_deep_chain_indents_through_its_inventories() {
        let rendered = trace(
            "futurelock",
            "futurelock::main::{async_block#0}::{async_block_env#0}",
            false,
        );
        assert_eq!(
            rendered,
            "  0  async block   futurelock::main::{async_block#0}::{async_block_env#0}
     suspends:
       Suspend0  src/bin/futurelock.rs:22  1 local  futurelock::start_background_task::{async_fn_env#0}
     ▸ Suspend1  src/bin/futurelock.rs:25  1 local
       └─  1  async fn      futurelock::do_stuff::{async_fn_env#0}
          suspends:
            Suspend0  src/bin/futurelock.rs:59  4 locals  core::future::poll_fn::PollFn<futurelock::do_stuff::{async_fn#0}::{closure_env#0}>
          ▸ Suspend1  src/bin/futurelock.rs:64  3 locals
            └─  2  async fn      futurelock::do_async_thing::{async_fn_env#0}
               suspends:
               ▸ Suspend0  src/bin/futurelock.rs:72  2 locals
                 └─  3  async fn      tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}<()>
                    suspends:
                    ▸ Suspend0  tokio-1.52.4/src/sync/mutex.rs:455
                      └─  4  async block   tokio::sync::mutex::{impl#10}::lock::{async_fn#0}::{async_block_env#0}<()>
                         suspends:
                         ▸ Suspend0  tokio-1.52.4/src/sync/mutex.rs:436
                           └─  5  async fn      tokio::sync::mutex::{impl#10}::acquire::{async_fn_env#0}<()>
                              suspends:
                                Suspend0  tokio-1.52.4/src/sync/mutex.rs:656  1 local  tokio::trace::async_trace_leaf::{async_fn_env#0}
                              ▸ Suspend1  tokio-1.52.4/src/sync/mutex.rs:658
                                └─* 6  future        tokio::sync::batch_semaphore::Acquire
                                   waiting on a tokio::sync::Mutex (semaphore 0xADDR): 1 permit requested, 0 available; wake queue: task 5
"
        );
    }

    /// A frame parked at a state its inventory lists others after: the
    /// rows keep the enum's order, so the one below the active row is
    /// printed once the subtree hanging off the active row is closed.
    #[test]
    fn test_states_after_the_active_one_close_over_the_subtree() {
        assert_eq!(
            trace("dyn-future", "dyn_future::driver::{async_fn_env#0}", false),
            "  0  async fn      dyn_future::driver::{async_fn_env#0}
     suspends:
     ▸ Suspend0  src/bin/dyn-future.rs:29  1 local
       └─  1  async fn      dyn_future::boxed_leaf::{async_fn_env#0} [dyn]
          suspends:
          ▸ Suspend0  src/bin/dyn-future.rs:11
            └─* 2  future        tokio::sync::oneshot::Receiver<u32>
       Suspend1  src/bin/dyn-future.rs:30  2 locals  tokio::task::join_set::{impl#1}::join_next::{async_fn_env#0}<u32>
"
        );
    }

    /// Under `--verbose` a pointer into another task's allocation is
    /// labelled with that task's id, the way `exec_trace` wires it up:
    /// the joiner's `JoinHandle` holds the sleeper's `Header` pointer,
    /// which must name the task a reader would trace next.
    #[test]
    fn test_verbose_labels_pointers_into_other_tasks() {
        let (bundle, snapshot) = testkit::load("sleep-join");
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
        let mut out = Vec::new();
        let elide = Default::default();
        let opts = TraceOpts {
            verbose: true,
            render: RenderOpts {
                depth: 4,
                ugly: false,
            },
            elide: &elide,
        };
        print_await_chain(&ctx, &list, &chain, &opts, Some(&annotate), &mut out)
            .expect("the chain renders");
        let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
        assert!(rendered.contains("(task 3)"), "{rendered}");
    }

    /// Under `--verbose` the marked row drops its count — the values it
    /// counted are listed right below it — and the listing hangs from
    /// the row rather than from the frame.
    #[test]
    fn test_verbose_lists_the_active_states_locals_under_its_row() {
        let rendered = trace("simple-await", "simple_await::work::{async_fn_env#0}", true);
        assert!(
            rendered.contains("     ▸ Suspend1  src/bin/simple-await.rs:34\n       locals:\n"),
            "{rendered}"
        );
        // The inactive row keeps its count: every variant shares the
        // enum's storage, so its locals cannot be read at all.
        assert!(
            rendered.contains("       Suspend0  src/bin/simple-await.rs:32  11 locals  "),
            "{rendered}"
        );
        assert!(rendered.contains("\n         count: 3\n"), "{rendered}");
    }
}

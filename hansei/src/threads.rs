//! The `threads` command: every thread the runtime is running on, as
//! the runtime sees it and as the stack sees it.

use crate::tasks::{EMPTY_BUCKET, alternatives, listing_footer};
use crate::trace::print_variable;
use crate::{RenderOpts, Session, repl, summary};

use anyhow::{Context as _, Result};
use hansei_runtime::tokio::bundle::{self, ParkState};
use reify::Value;

use std::collections::{BTreeMap, HashMap};
use std::io;

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
    /// The kind of that role — what `--group role` buckets by: every
    /// worker one `worker` whatever its index and park state, the
    /// pool's threads `blocking` idle or running, the rest their own
    /// spelling.
    pub(crate) role_kind: &'static str,
    /// The task it is polling, believed only when the listing agrees.
    pub(crate) task: Option<u64>,
    /// The function at the top of the unwound stack — the symbol, or
    /// the pc where there is none — and `None` where no stack could be
    /// walked.
    pub(crate) frame0: Option<String>,
}

/// The table's rows, built on first use and cached on the session.
pub(crate) fn rows<'s, T: proc::Target>(session: &'s Session<'_, T>) -> &'s [ThreadRow] {
    session.thread_rows.get_or_init(|| build_rows(session))
}

fn build_rows<T: proc::Target>(session: &Session<'_, T>) -> Vec<ThreadRow> {
    let stacks = session.stacks();
    // One parker-array read per runtime, shared by its workers' rows.
    let mut parks: HashMap<usize, Option<bundle::ParkStates>> = HashMap::new();
    let mut rows: Vec<ThreadRow> = session
        .lwps
        .iter()
        .map(|lwp| {
            let worker = session.workers.iter().find(|w| w.tid == lwp.tid);
            let stack = stacks.get(&lwp.tid);
            let names = stack_names(stack);
            let role = role_of(session, lwp.tid, worker, &names, &mut parks);
            ThreadRow {
                lwp: lwp.tid,
                name: session.proc.lwp_name(lwp.tid),
                role: role.spelled,
                role_kind: role.kind,
                task: worker
                    .and_then(|w| crate::tasks::polled_task(w.current_task_id, &session.tasks)),
                frame0: names.into_iter().next(),
            }
        })
        .collect();
    rows.sort_by_key(|row| row.lwp);
    rows
}

/// A thread's place in a runtime: the `ROLE` cell as spelled, and the
/// kind it is one of.
struct Role {
    spelled: String,
    kind: &'static str,
}

impl Role {
    /// A role whose spelling is its kind: nothing varies within it.
    fn plain(word: &'static str) -> Role {
        Role {
            spelled: word.to_string(),
            kind: word,
        }
    }
}

/// The `ROLE` cell for one lwp, and its kind. `frames` is the unwound
/// stack's symbols, the only witness to a blocking-pool thread.
fn role_of<T: proc::Target>(
    session: &Session<'_, T>,
    tid: u32,
    worker: Option<&bundle::Worker>,
    frames: &[String],
    parks: &mut HashMap<usize, Option<bundle::ParkStates>>,
) -> Role {
    // No tokio context at all: nothing of the runtime's to say.
    let Some(worker) = worker else {
        return Role::plain("no runtime");
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
            let scoped = scoped_worker(
                index,
                session.runtimes.len() > 1,
                session.runtime_of(tid).map(|(rt_index, _)| rt_index),
            );
            Role {
                spelled: format!("{scoped}, {}", park_word(park, polling)),
                kind: "worker",
            }
        }
        Ok(SchedulerState::BlockOn(_)) => Role::plain("block_on caller"),
        // A thread inside the runtime without a scheduler context:
        // the blocking pool's, if its stack says so — the runtime
        // keeps only counters about the pool, so the stack is the
        // only witness — else a thread that merely entered.
        Ok(SchedulerState::None) => match blocking_role(frames) {
            Some(spelled) => Role {
                spelled: spelled.to_string(),
                kind: "blocking",
            },
            None => Role::plain("entered runtime"),
        },
        // A context that could not be read is not a thread that
        // merely entered; say what happened instead of guessing.
        Err(_) => Role::plain("context unreadable"),
    }
}

/// The name half of a worker's role: `worker N` — `worker ?` when the
/// index could not be read — scoped `rt R worker N` when the target
/// holds several runtimes, since a worker index means nothing without
/// the scheduler that numbered it.
fn scoped_worker(index: Option<u64>, several: bool, rt: Option<usize>) -> String {
    let worker = match index {
        Some(index) => format!("worker {index}"),
        None => "worker ?".to_string(),
    };
    match (several, rt) {
        (true, Some(rt_index)) => format!("rt {rt_index} {worker}"),
        _ => worker,
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
/// role classifier matches on and the `FRAME 0` cell prints.
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

/// The row's cells short of `FRAME 0`: the line the cursor's `thread`
/// selector prints and the heading `--exec` opens each thread's output
/// with. The top frame stays out of it: a bare `trace` under the
/// thread cursor walks the whole stack.
fn row_cells(row: &ThreadRow) -> [String; 4] {
    let dash = || "—".to_string();
    [
        row.lwp.to_string(),
        row.name.clone().unwrap_or_else(dash),
        row.role.clone(),
        row.task.map(|id| id.to_string()).unwrap_or_else(dash),
    ]
}

/// Print the table: one row per selected lwp, in lwp order, nothing
/// truncated, and the count under it.
fn print_thread_table<'r>(
    rows: impl ExactSizeIterator<Item = &'r ThreadRow>,
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let total = rows.len();
    // The frame is a symbol, as long as any type name: what a terminal
    // cuts to keep a row on one line.
    let mut table = crate::output::Table::new(5)
        .header(["LWP", "NAME", "ROLE", "TASK", "FRAME 0"])
        .truncatable(4)
        .fit(fit);
    for row in rows {
        let [lwp, name, role, task] = row_cells(row);
        table.row([
            lwp,
            name,
            role,
            task,
            row.frame0.clone().unwrap_or_else(|| "—".to_string()),
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "[{}]", summary::counted(total, "thread"))?;
    Ok(())
}

/// Everything the `threads` command was asked. The filter grammar
/// rides in as the raw flag values and is parsed here, so the errors
/// name the flag they came from.
pub(crate) struct ThreadsCmd {
    /// The lwp ids the old grammar took, kept so the refusal can name
    /// the way forward.
    pub(crate) lwp: Vec<String>,
    pub(crate) with: Vec<String>,
    pub(crate) without: Vec<String>,
    pub(crate) group: Option<String>,
    pub(crate) exec: Vec<String>,
}

/// One filterable field of the thread population — what `--with`,
/// `--without` and `--group` name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    /// The recorded thread name.
    Name,
    /// The `ROLE` cell as spelled; grouped by its kind.
    Role,
    /// The id of the task being polled — exact.
    Task,
    /// Whether a task is being polled: `yes` or `no`.
    HasTask,
    /// The function at the top of the stack.
    Function,
    /// The lwp id — exact.
    Lwp,
}

impl Field {
    const NAMES: [(&'static str, Field); 6] = [
        ("name", Field::Name),
        ("role", Field::Role),
        ("task", Field::Task),
        ("has-task", Field::HasTask),
        ("function", Field::Function),
        ("lwp", Field::Lwp),
    ];

    /// Every field name, in the order the errors list them — what the
    /// prompt offers after `--group`, `--with` and `--without`.
    pub(crate) fn names() -> impl Iterator<Item = &'static str> {
        Self::NAMES.iter().map(|(n, _)| *n)
    }

    /// The field a flag named, or an error listing what it could have.
    fn parse(name: &str) -> Result<Field> {
        Self::NAMES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, f)| *f)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no field {name:?}; the fields are {}",
                    Self::NAMES.map(|(n, _)| n).join(", ")
                )
            })
    }

    fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, f)| *f == self)
            .map(|(n, _)| *n)
            .expect("every field is named")
    }

    /// Whether the field's argument is a pattern rather than an exact
    /// value.
    fn is_pattern(self) -> bool {
        matches!(self, Field::Name | Field::Role | Field::Function)
    }

    /// The distinct values the rows hold for the field — the role at
    /// its kind level, as `--group` buckets it, since every spelled
    /// role starts with its kind and a target has as many spellings
    /// as it has workers.
    fn values(self, rows: &[ThreadRow]) -> Vec<String> {
        let column =
            |f: fn(&ThreadRow) -> Option<String>| crate::tasks::distinct_values(rows.iter().map(f));
        match self {
            Field::Name => column(|r| r.name.clone()),
            Field::Role => column(|r| Some(r.role_kind.to_string())),
            Field::Task => column(|r| r.task.map(|id| id.to_string())),
            Field::HasTask => vec!["yes".to_string(), "no".to_string()],
            Field::Function => column(|r| r.frame0.clone()),
            Field::Lwp => column(|r| Some(r.lwp.to_string())),
        }
    }
}

/// The values the target holds for `field`, for the prompt to offer
/// after `--with FIELD` (see `tasks::field_values`).
pub(crate) fn field_values<T: proc::Target>(
    session: &Session<'_, T>,
    field: &str,
) -> Option<(Vec<String>, bool)> {
    let field = Field::parse(field).ok()?;
    Some((field.values(rows(session)), field.is_pattern()))
}

/// How one clause matches its field's value.
#[derive(Debug)]
enum Matcher {
    /// A case-insensitive regex over the spelled value.
    Pattern(crate::pattern::Pattern),
    /// Exact task id: `task`.
    Task(u64),
    /// Exact lwp: `lwp`.
    Lwp(u32),
    /// Whether a task is polled: `has-task`.
    HasTask(bool),
}

/// One `--with`/`--without` clause.
#[derive(Debug)]
struct Clause {
    field: Field,
    /// The argument's alternatives (`2,3`): the clause matches a row
    /// when any one of them does.
    matchers: Vec<Matcher>,
    /// `--without`: the clause keeps the rows it does *not* match.
    negate: bool,
}

/// Parse the flag pairs into clauses. clap delivered FIELD/ARG pairs
/// (`num_args = 2`), so the chunks are exact.
fn parse_clauses(with: &[String], without: &[String]) -> Result<Vec<Clause>> {
    let mut clauses = Vec::new();
    for (specs, negate) in [(with, false), (without, true)] {
        let flag = if negate { "--without" } else { "--with" };
        for [name, spec] in specs.as_chunks::<2>().0 {
            let field = Field::parse(name).with_context(|| flag.to_string())?;
            let matchers = alternatives(spec)
                .and_then(|alts| alts.iter().map(|alt| matcher(field, alt)).collect())
                .with_context(|| format!("{flag} {}", field.name()))?;
            clauses.push(Clause {
                field,
                matchers,
                negate,
            });
        }
    }
    Ok(clauses)
}

/// The matcher one field's argument compiles to.
fn matcher(field: Field, arg: &str) -> Result<Matcher> {
    Ok(match field {
        Field::Task => Matcher::Task(
            arg.parse()
                .map_err(|_| anyhow::anyhow!("a task is a decimal id, got {arg:?}"))?,
        ),
        Field::Lwp => Matcher::Lwp(
            arg.parse()
                .map_err(|_| anyhow::anyhow!("an lwp is a decimal id, got {arg:?}"))?,
        ),
        Field::HasTask => Matcher::HasTask(match arg {
            "yes" => true,
            "no" => false,
            _ => anyhow::bail!("has-task is yes or no, got {arg:?}"),
        }),
        Field::Name | Field::Role | Field::Function => {
            Matcher::Pattern(crate::pattern::Pattern::new(arg)?)
        }
    })
}

/// Whether one row survives one clause: any alternative matching is
/// a hit, and `--without` keeps the misses.
fn survives(clause: &Clause, row: &ThreadRow) -> bool {
    let hit = clause.matchers.iter().any(|matcher| match matcher {
        Matcher::Pattern(p) => field_text(clause.field, row).is_some_and(|t| p.is_match(t)),
        Matcher::Task(id) => row.task == Some(*id),
        Matcher::Lwp(lwp) => row.lwp == *lwp,
        Matcher::HasTask(has) => row.task.is_some() == *has,
    });
    hit != clause.negate
}

/// The spelled value a regex field matches — `None`, nothing to
/// match, where the row has nothing to say.
fn field_text(field: Field, row: &ThreadRow) -> Option<&str> {
    match field {
        Field::Name => row.name.as_deref(),
        Field::Role => Some(&row.role),
        Field::Function => row.frame0.as_deref(),
        _ => unreachable!("{field:?} is not a regex field"),
    }
}

/// What a bucket is named for one row: the field's spelled value, or
/// `None` for [`EMPTY_BUCKET`]. A role is grouped by its kind — every
/// worker one bucket, not one per index and park state.
fn group_value(field: Field, row: &ThreadRow) -> Option<String> {
    match field {
        Field::Name => row.name.clone(),
        Field::Role => Some(row.role_kind.to_string()),
        Field::Task => row.task.map(|id| id.to_string()),
        Field::HasTask => Some(if row.task.is_some() { "yes" } else { "no" }.to_string()),
        Field::Function => row.frame0.clone(),
        Field::Lwp => Some(row.lwp.to_string()),
    }
}

/// Up to three member lwps and `…` — the sample a bucket row carries.
fn member_sample(rows: &[ThreadRow], members: &[usize]) -> String {
    let lwps: Vec<String> = members
        .iter()
        .take(3)
        .map(|&i| rows[i].lwp.to_string())
        .collect();
    match members.len() > lwps.len() {
        true => format!("{}, …", lwps.join(", ")),
        false => lwps.join(", "),
    }
}

/// Every thread the target holds, one table row each: its place in a
/// runtime, the task it is polling, the top of its stack. The filter
/// clauses narrow the listing; one thread's insides — its tokio
/// context, the worker core it holds, its whole stack — are
/// [`print_thread`]'s, under `thread`.
pub(crate) fn exec_threads<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: ThreadsCmd,
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    if let Some(first) = cmd.lwp.first() {
        anyhow::bail!("threads takes no lwp ids; `thread {first}` selects that one thread");
    }
    let group = cmd
        .group
        .as_deref()
        .map(Field::parse)
        .transpose()
        .context("--group")?;
    let clauses = parse_clauses(&cmd.with, &cmd.without)?;

    // The selection, as indices into the rows: the named lwps, or every
    // thread, narrowed by the clauses.
    let rows = rows(session);
    let survivors: Vec<usize> = (0..rows.len())
        .filter(|&i| clauses.iter().all(|c| survives(c, &rows[i])))
        .collect();

    if !cmd.exec.is_empty() {
        // clap refuses `--group` beside `--exec`; the filters have
        // already chosen who the command runs against.
        return exec_exec(session, &cmd, &survivors, theme, out);
    }
    if let Some(field) = group {
        return exec_group(session, field, &survivors, session.fit_width(theme), out);
    }
    print_thread_table(
        survivors.iter().map(|&i| &rows[i]),
        session.fit_width(theme),
        out,
    )
}

/// `--group FIELD`: bucket the surviving rows by the field's spelled
/// value and print `COUNT VALUE` rows, most numerous first (ties in
/// value order), each with up to three member lwps.
fn exec_group<T: proc::Target>(
    session: &Session<'_, T>,
    field: Field,
    survivors: &[usize],
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let rows = rows(session);
    let mut grouped: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &index in survivors {
        let value = group_value(field, &rows[index]).unwrap_or_else(|| EMPTY_BUCKET.to_string());
        grouped.entry(value).or_default().push(index);
    }
    let mut buckets: Vec<(String, Vec<usize>)> = grouped.into_iter().collect();
    // Count descending; the map already ordered ties by value, and the
    // sort is stable.
    buckets.sort_by_key(|(_, members)| std::cmp::Reverse(members.len()));

    let heading = field.name().replace('-', " ").to_uppercase();
    let mut table = crate::output::Table::new(3)
        .align_right(0)
        .header(["COUNT".to_string(), heading, "LWPS".to_string()])
        .truncatable(1)
        .fit(fit);
    for (value, members) in &buckets {
        table.row([
            members.len().to_string(),
            value.clone(),
            member_sample(rows, members),
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(
        out,
        "{}",
        listing_footer(buckets.len(), buckets.len(), "group")
    )?;
    Ok(())
}

/// `--exec COMMAND`: run the command once per surviving thread under a
/// cursor on that thread, each run's output under a `thread N`
/// heading — unless the command is `thread` itself, whose block opens
/// by naming the lwp. One thread's failure never stops the loop — the failed run
/// shows its error in place, the summary line counts them, and the
/// command fails after the loop when any run did, so a script sees one
/// failure with nothing skipped.
fn exec_exec<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: &ThreadsCmd,
    survivors: &[usize],
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    // Parse once up front: a command that does not parse is the
    // command line's mistake, not any thread's, and fails before the
    // loop prints a heading.
    let parsed = repl::parse_exec_command(&cmd.exec).context("--exec")?;
    let headed = !matches!(parsed, crate::Command::Thread { lwp: None });
    let rows = rows(session);
    let mut failed = 0usize;
    // Each run goes under a cursor on its thread — the command's
    // omitted target and `$_` are that thread's — and the session's
    // own cursor comes back once the loop is done.
    let saved = *session.cursor.borrow();
    for (n, &index) in survivors.iter().enumerate() {
        let label = format!("thread {}", rows[index].lwp);
        write!(out, "{}", exec_heading(n, headed.then_some(&label)))?;
        let command = repl::parse_exec_command(&cmd.exec).expect("parsed above");
        // `quit` is not a per-thread answer, so a Quit flow is ignored
        // and the loop runs on.
        let run = crate::cursor::select_thread(session, rows[index].lwp)
            .and_then(|()| crate::dispatch(session, command, theme, out));
        if let Err(e) = run {
            failed += 1;
            writeln!(out, "error: {e:#}")?;
        }
    }
    *session.cursor.borrow_mut() = saved;
    writeln!(
        out,
        "Executed against {}, {failed} failed",
        summary::counted(survivors.len(), "thread")
    )?;
    if failed > 0 {
        anyhow::bail!(
            "--exec failed against {failed} of {}",
            summary::counted(survivors.len(), "thread")
        );
    }
    Ok(())
}

/// The heading `--exec` opens thread `n`'s output with: a blank line
/// between one thread's output and the next, then the thread's lwp
/// the way `thread` takes it — or no name, when the command is
/// `thread` and opens with the lwp itself.
fn exec_heading(n: usize, label: Option<&str>) -> String {
    let sep = if n > 0 { "\n" } else { "" };
    match label {
        Some(label) => format!("{sep}{label}\n"),
        None => sep.to_string(),
    }
}

/// One thread as `thread` prints it: its heading — the lwp, what it is
/// polling, its runtime where the listings tag groups, and the fatal
/// signal where it took one — then, four columns in, its tokio
/// context, its scheduler state, its registers where it took the
/// fatal signal (that is exactly when they matter; `regs` prints them
/// otherwise), and its stack, fifty frames deep at most (`trace -l`
/// prints it to any depth).
pub(crate) fn print_thread<T: proc::Target>(
    session: &Session<'_, T>,
    tid: u32,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    const FRAMES: usize = 50;

    if !session.lwps.iter().any(|l| l.tid == tid) {
        return Err(no_such_thread(session.lwps.len(), tid));
    }
    let stacks = session.stacks();
    let fatal = session.proc.fatal_signal();
    let print_stack = |out: &mut dyn io::Write| -> Result<()> {
        match stacks.get(&tid) {
            Some(backtrace) => {
                writeln!(out, "    stack:")?;
                for line in backtrace.stack_trace(FRAMES) {
                    writeln!(out, "        {line}")?;
                }
            }
            None => writeln!(out, "    stack: unavailable")?,
        }
        Ok(())
    };

    // A thread holding no tokio context has only its stack to show;
    // everything below the heading is the runtime's.
    let Some(worker) = session.workers.iter().find(|w| w.tid == tid) else {
        let took = fatal_tag(fatal.as_ref(), tid);
        writeln!(out, "lwp {tid}  no runtime{took}")?;
        if took_fatal(fatal.as_ref(), tid) {
            crate::registers::print_lwp_registers(session, tid, "    ", out)?;
        }
        return print_stack(out);
    };
    // Which runtime the thread runs is only worth a tag when the
    // listings tag their groups at all — more than one runtime, or a
    // local set sharing the population.
    let tag = if session.group_tags().is_empty() {
        String::new()
    } else {
        match session.runtime_of(tid) {
            Some((index, rt)) => format!("  {}", crate::runtimes::runtime_label(index, rt)),
            None => String::new(),
        }
    };
    let took = fatal_tag(fatal.as_ref(), tid);
    writeln!(out, "lwp {tid}  {}{tag}{took}", polling(session, worker))?;

    if let Err(e) = print_thread_context(session, worker, opts, out) {
        writeln!(out, "    thread context unreadable: {e:#}")?;
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
        Ok(SchedulerState::None) => writeln!(out, "    not in the scheduler's run loop")?,
        Err(e) => writeln!(out, "    scheduler context unreadable: {e:#}")?,
    }

    // Frame 0 of the stack below, so it prints just above it.
    if took_fatal(fatal.as_ref(), tid) {
        crate::registers::print_lwp_registers(session, tid, "    ", out)?;
    }
    print_stack(out)
}

/// The error for an lwp the target does not hold. It counts the lwps
/// there are rather than naming them — `threads` is the listing, and
/// on a real target it is long.
pub(crate) fn no_such_thread(lwps: usize, tid: u32) -> anyhow::Error {
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

/// Whether the thread took the fatal signal — what earns its block the
/// register lines, since that is exactly when they matter, and healthy
/// captures stay unaffected.
fn took_fatal(fatal: Option<&proc::FatalSignal>, tid: u32) -> bool {
    fatal.is_some_and(|sig| sig.lwp == Some(tid))
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

/// Print one named value the way `thread` indents its fields: four
/// columns in, with a nested render's lines set under the value's
/// first line, which [`print_variable`] opens two columns past the
/// label.
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
        "    ",
        name,
        None,
        &format_args!(
            "{:#}",
            render(session, value, opts, heap).line_prefix("      ")
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
    writeln!(out, "    worker {}", session.ctx.worker_index(worker_ctx)?)?;

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
    writeln!(out, "    block_on thread of its current_thread runtime")?;
    if let Some((_, rt)) = session.runtime_of(worker.tid) {
        match session.ctx.ct_park_state(rt.handle, ct_ctx) {
            Ok(state) => {
                let woken = if state.woken {
                    ", a wakeup pending"
                } else {
                    ""
                };
                writeln!(out, "    {}{woken}", state.activity)?;
            }
            Err(e) => writeln!(out, "    park state unreadable: {e:#}")?,
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
        writeln!(out, "    core: {absent}")?;
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
        .max_str_len(Some(opts.max_string_len))
        .max_array_len(Some(opts.max_array_values));
    if let Some(heap) = heap {
        display = display.heap(heap);
    }
    if opts.ugly { display.ugly() } else { display }
}

#[cfg(test)]
mod tests {
    use super::{
        Clause, Field, ParkState, ThreadRow, blocking_role, exec_heading, fatal_tag, group_value,
        matcher, member_sample, no_such_thread, park_word, parse_clauses, polling_line, survives,
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
            sender: None,
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
    /// capture, nobody when the core did not say which lwp took it.
    #[test]
    fn test_registers_print_for_the_faulting_lwp() {
        use super::took_fatal;
        let sig = segv(Some(7));
        assert!(took_fatal(Some(&sig), 7));
        assert!(!took_fatal(Some(&sig), 8));
        assert!(!took_fatal(None, 7));
        assert!(!took_fatal(Some(&segv(None)), 7));
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

    /// A worker is scoped to its runtime exactly when there are
    /// several: the common one-runtime table never says `rt 0`, and a
    /// worker whose runtime is unknown stays unscoped rather than
    /// claiming one.
    #[test]
    fn test_a_worker_is_scoped_only_among_several_runtimes() {
        use super::scoped_worker;
        assert_eq!(scoped_worker(Some(3), false, Some(0)), "worker 3");
        assert_eq!(scoped_worker(Some(3), true, Some(1)), "rt 1 worker 3");
        assert_eq!(scoped_worker(Some(3), true, None), "worker 3");
        assert_eq!(scoped_worker(None, true, Some(1)), "rt 1 worker ?");
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

    /// A row as the table would build it, with the fields the filters
    /// read.
    fn row(
        lwp: u32,
        name: Option<&str>,
        role: &str,
        role_kind: &'static str,
        task: Option<u64>,
        frame0: Option<&str>,
    ) -> ThreadRow {
        ThreadRow {
            lwp,
            name: name.map(String::from),
            role: role.to_string(),
            role_kind,
            task,
            frame0: frame0.map(String::from),
        }
    }

    /// A worker mid-poll, a parked worker, an idle pool thread, and a
    /// thread outside any runtime with no stack to show.
    fn population() -> Vec<ThreadRow> {
        vec![
            row(
                2,
                Some("tokio-rt-worker"),
                "worker 0, polling",
                "worker",
                Some(129),
                Some("app::handle"),
            ),
            row(
                3,
                Some("tokio-rt-worker"),
                "worker 1, parked",
                "worker",
                None,
                Some("__lwp_park"),
            ),
            row(
                4,
                Some("tokio-blocking"),
                "blocking, idle",
                "blocking",
                None,
                Some("__lwp_park"),
            ),
            row(9, None, "no runtime", "no runtime", None, None),
        ]
    }

    fn clause(field: &str, arg: &str, negate: bool) -> Clause {
        let field = Field::parse(field).expect("a field name");
        Clause {
            field,
            matchers: vec![matcher(field, arg).expect("a valid argument")],
            negate,
        }
    }

    /// The lwps a clause keeps from the population.
    fn kept(field: &str, arg: &str, negate: bool) -> Vec<u32> {
        let clause = clause(field, arg, negate);
        population()
            .iter()
            .filter(|row| survives(&clause, row))
            .map(|row| row.lwp)
            .collect()
    }

    /// Each string field reads its own column, as a case-insensitive
    /// regex; a row with nothing in the column matches nothing.
    #[test]
    fn test_each_string_field_reads_its_own_column() {
        assert_eq!(kept("name", "RT-WORKER", false), [2, 3]);
        assert_eq!(kept("name", ".", false), [2, 3, 4]);
        assert_eq!(kept("role", "^worker", false), [2, 3]);
        assert_eq!(kept("role", "idle|polling", false), [2, 4]);
        assert_eq!(kept("function", "park", false), [3, 4]);
        assert_eq!(kept("function", ".", false), [2, 3, 4]);
    }

    /// The ids are exact — a prefix is not a match — and has-task is
    /// the yes/no of the TASK column.
    #[test]
    fn test_the_exact_fields_are_exact() {
        assert_eq!(kept("task", "129", false), [2]);
        assert_eq!(kept("task", "12", false), Vec::<u32>::new());
        assert_eq!(kept("lwp", "3", false), [3]);
        assert_eq!(kept("has-task", "yes", false), [2]);
        assert_eq!(kept("has-task", "no", false), [3, 4, 9]);
    }

    /// `--without` keeps what does not match, and clauses AND.
    #[test]
    fn test_without_negates_and_clauses_and() {
        assert_eq!(kept("role", "^worker", true), [4, 9]);
        assert_eq!(kept("function", ".", true), [9]);
        let clauses = parse_clauses(
            &["name".into(), "worker".into()],
            &["has-task".into(), "yes".into()],
        )
        .expect("both pairs parse");
        let kept: Vec<u32> = population()
            .iter()
            .filter(|row| clauses.iter().all(|c| survives(c, row)))
            .map(|row| row.lwp)
            .collect();
        assert_eq!(kept, [3]);
    }

    /// A clause argument lists alternatives: `lwp 2,3` keeps either,
    /// `--without` drops both, and each alternative of a string field
    /// is a regex of its own.
    #[test]
    fn test_alternatives_or_within_a_clause() {
        let lwps = |with: &[&str], without: &[&str]| -> Vec<u32> {
            let with: Vec<String> = with.iter().map(|s| s.to_string()).collect();
            let without: Vec<String> = without.iter().map(|s| s.to_string()).collect();
            let clauses = parse_clauses(&with, &without).expect("the clauses parse");
            population()
                .iter()
                .filter(|row| clauses.iter().all(|c| survives(c, row)))
                .map(|row| row.lwp)
                .collect()
        };
        assert_eq!(lwps(&["lwp", "2,3"], &[]), [2, 3]);
        assert_eq!(lwps(&[], &["lwp", "2,3"]), [4, 9]);
        assert_eq!(lwps(&["has-task", "yes,no"], &[]), [2, 3, 4, 9]);
        assert_eq!(lwps(&["role", "^worker,idle$"], &[]), [2, 3, 4]);
        assert_eq!(lwps(&["role", "^worker,idle$"], &["lwp", "3"]), [2, 4]);
        let err = format!(
            "{:#}",
            parse_clauses(&["has-task".into(), "yes,maybe".into()], &[]).expect_err("yes or no")
        );
        assert!(err.contains("--with has-task"), "{err}");
    }

    /// A bad field or argument names the flag it came from and what
    /// it could have been.
    #[test]
    fn test_filter_errors_name_their_flag() {
        let err = parse_clauses(&["colour".into(), "x".into()], &[])
            .expect_err("no such field")
            .to_string();
        assert!(err.contains("--with"), "{err}");
        let err = format!(
            "{:#}",
            parse_clauses(&[], &["has-task".into(), "maybe".into()]).expect_err("yes or no")
        );
        assert!(err.contains("--without has-task"), "{err}");
        assert!(err.contains("yes or no"), "{err}");
        let err = format!(
            "{:#}",
            parse_clauses(&["task".into(), "0x10".into()], &[]).expect_err("decimal")
        );
        assert!(err.contains("--with task"), "{err}");
        let err = format!(
            "{:#}",
            parse_clauses(&["lwp".into(), "three".into()], &[]).expect_err("decimal")
        );
        assert!(err.contains("--with lwp"), "{err}");
        let err = Field::parse("colour")
            .expect_err("no such field")
            .to_string();
        assert!(
            err.contains("name, role, task, has-task, function, lwp"),
            "{err}"
        );
    }

    /// A bucket is the field's spelled value — a role by its kind, so
    /// every worker lands together — and a row with nothing in the
    /// field is the empty bucket.
    #[test]
    fn test_group_values_and_the_empty_bucket() {
        let rows = population();
        let values = |field: &str| -> Vec<Option<String>> {
            let field = Field::parse(field).expect("a field name");
            rows.iter().map(|row| group_value(field, row)).collect()
        };
        let some = |list: &[&str]| -> Vec<Option<String>> {
            list.iter().map(|s| Some(s.to_string())).collect()
        };
        assert_eq!(
            values("name"),
            [
                Some("tokio-rt-worker".to_string()),
                Some("tokio-rt-worker".to_string()),
                Some("tokio-blocking".to_string()),
                None
            ]
        );
        assert_eq!(
            values("role"),
            some(&["worker", "worker", "blocking", "no runtime"])
        );
        assert_eq!(values("task"), [Some("129".to_string()), None, None, None]);
        assert_eq!(values("has-task"), some(&["yes", "no", "no", "no"]));
        assert_eq!(
            values("function"),
            [
                Some("app::handle".to_string()),
                Some("__lwp_park".to_string()),
                Some("__lwp_park".to_string()),
                None
            ]
        );
        assert_eq!(values("lwp"), some(&["2", "3", "4", "9"]));
    }

    /// Each field's values are its column's distinct spellings, most
    /// frequent first, the fixed yes/no for has-task; a thread with
    /// nothing in the column contributes nothing.
    #[test]
    fn test_field_values_are_the_columns_distinct_spellings() {
        let rows = population();
        let values = |field: &str| Field::parse(field).expect("a field name").values(&rows);
        assert_eq!(values("name"), ["tokio-rt-worker", "tokio-blocking"]);
        assert_eq!(values("role"), ["worker", "blocking", "no runtime"]);
        assert_eq!(values("task"), ["129"]);
        assert_eq!(values("has-task"), ["yes", "no"]);
        assert_eq!(values("function"), ["__lwp_park", "app::handle"]);
        assert_eq!(values("lwp"), ["2", "3", "4", "9"]);
        assert!(Field::Role.is_pattern() && Field::Function.is_pattern());
        assert!(!Field::Task.is_pattern() && !Field::HasTask.is_pattern());
    }

    /// A bucket's sample is three lwps and an ellipsis for the rest.
    #[test]
    fn test_a_bucket_samples_three_members() {
        let rows = population();
        assert_eq!(member_sample(&rows, &[0, 1]), "2, 3");
        assert_eq!(member_sample(&rows, &[0, 1, 2]), "2, 3, 4");
        assert_eq!(member_sample(&rows, &[0, 1, 2, 3]), "2, 3, 4, …");
    }

    /// The exec heading names the thread as `thread` takes it, and a
    /// blank line separates one thread's output from the next but not
    /// the first — the blank line alone when the command names the
    /// thread itself.
    #[test]
    fn test_exec_headings_separate_threads_with_one_blank_line() {
        assert_eq!(exec_heading(0, Some("thread 2")), "thread 2\n");
        assert_eq!(exec_heading(1, Some("thread 9")), "\nthread 9\n");
        assert_eq!(exec_heading(0, None), "");
        assert_eq!(exec_heading(1, None), "\n");
    }
}

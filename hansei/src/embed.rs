// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! hansei inside another program: a session over a [`Target`] the host
//! brings, answering the same commands the prompt does.
//!
//! The command line opens a core and owns the session for the life of
//! the process. A host — a debugger module reading the target through
//! its own debugger, say — has a target already, and wants to attach to
//! it, ask questions, and print the answers wherever its own output
//! goes. That is the whole surface here:
//!
//! - [`Options::parse`] reads the session flags (`--tokio-info`,
//!   `--debug-info`, `--best-effort`, `--config`, …) exactly as the
//!   command line spells them, so a host need not invent its own.
//! - [`Options::load_bundle`] reads or extracts the tokio info they name.
//! - [`attach`] attaches a session to the host's target and bundle.
//! - [`run`] answers a command line (`tasks --with state idle`,
//!   `trace 12 ; graph`) into a writer, unstyled.
//! - [`tasks`] selects tasks with the `tasks` filters and hands back
//!   what a host needs to name each one itself — above all its address,
//!   which is what a debugger pipes between commands.
//!
//! The session borrows the target, the bundle and the options, so the
//! host owns all three and keeps them alive at least as long as it.

use crate::{BundleSource, Cli, Session, SessionArgs, bundle_cmd, repl, tasks as task_rows};

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use hansei_bundle::Bundle;
use proc::Target;

use std::io;
use std::path::Path;

/// The session flags, parsed.
pub struct Options {
    args: SessionArgs,
}

impl Options {
    /// Parse session flags as the `hansei` command line takes them.
    /// `name` stands where `--core` would: it is only what the session
    /// calls its target (`info` prints it), since the host's target is
    /// already open. One of `--tokio-info` or `--debug-info` is
    /// required, as on the command line.
    pub fn parse<S: AsRef<str>>(name: &str, flags: &[S]) -> Result<Self> {
        let argv = ["hansei", "--core", name]
            .into_iter()
            .chain(flags.iter().map(AsRef::as_ref));
        let cli = Cli::try_parse_from(argv).map_err(|e| anyhow!("{}", e.render()))?;
        let args = cli
            .session
            .ok_or_else(|| anyhow!("the flags name no session"))?;
        Ok(Options { args })
    }

    /// The tokio info the flags name: the `--tokio-info` file read, or
    /// a bundle extracted from `--debug-info` now (with `--binary`
    /// beside it where the debug info was split from its program).
    pub fn load_bundle(&self) -> Result<Bundle> {
        match self.args.bundle_source() {
            BundleSource::File(path) => Bundle::load(path)
                .with_context(|| format!("failed to load tokio info {}", path.display())),
            BundleSource::Extracted(path) => bundle_cmd::extract_for_session_with(
                path,
                self.args.binary.as_deref(),
                self.args.allow_unsupported,
                |bundle, _| bundle,
            ),
        }
    }

    /// The file the tokio info comes from, as the flags name it.
    pub fn bundle_path(&self) -> &Path {
        match self.args.bundle_source() {
            BundleSource::File(path) | BundleSource::Extracted(path) => path,
        }
    }
}

/// Attach a session to `proc`, reading its types from `bundle`.
///
/// What the command line prints at attach — an unsupported toolchain,
/// a degraded walk — is printed on stderr here too.
pub fn attach<'b, T: Target>(
    proc: &'b T,
    bundle: &'b Bundle,
    options: &'b Options,
) -> Result<Session<'b, T>> {
    if let Some(warning) = crate::unsupported_warning(&bundle.meta) {
        use io::Write as _;
        let _ = writeln!(io::stderr(), "{warning}");
    }
    Session::attach(proc, bundle, &options.args)
}

/// Answer a command line — one command or several, `;` between them —
/// into `out`. Returns `false` when a command asked the session to end
/// (`quit`), which a host may take or ignore.
pub fn run<T: Target>(
    session: &Session<'_, T>,
    line: &str,
    out: &mut dyn io::Write,
) -> Result<bool> {
    Ok(matches!(
        repl::execute_into(session, line, out)?,
        crate::Flow::Continue
    ))
}

/// One task, as a host needs to name it and pass it on.
#[derive(Clone, Debug)]
pub struct TaskRef {
    /// tokio's own id, where the target records one.
    pub id: Option<u64>,
    /// The task's header: the address every command that takes a task
    /// accepts (`task 0x…`), and the start of its allocation.
    pub addr: u64,
    /// The lifecycle, as `tasks` spells it.
    pub state: String,
    /// The root future's display name.
    pub future: String,
    /// The leaf await site, where there is one.
    pub awaiting_at: Option<String>,
    /// What would wake the task, as the `WAITING ON` column says it.
    pub waiting_on: String,
    /// Where the task was spawned, where the target records it
    /// (`tokio_unstable` task instrumentation).
    pub spawned: Option<String>,
}

/// The tasks `tasks --with … --without …` would list, in its order.
/// Each clause is a `FIELD ARG` pair spelled as on the `tasks` line
/// (`["state", "idle"]`); no clauses selects every task.
pub fn tasks<T: Target>(
    session: &Session<'_, T>,
    with: &[String],
    without: &[String],
) -> Result<Vec<TaskRef>> {
    let indices = task_rows::select(session, with, without)?;
    let rows = task_rows::rows(session);
    Ok(indices
        .into_iter()
        .map(|i| {
            let task = &session.tasks.tasks[i];
            let row = &rows[i];
            TaskRef {
                id: task.task_id,
                addr: task.addr.0,
                state: row.state.clone(),
                future: row.future.clone(),
                awaiting_at: row.awaiting_at.clone(),
                waiting_on: row.waiting_on.clone(),
                spawned: row.spawned.clone(),
            }
        })
        .collect())
}

pub use crate::workers::{InjectInfo, Queues, WorkerInfo};

/// Every multi_thread worker, by runtime and index: its thread, state,
/// the task it polls, its tick, and the tasks in its LIFO slot and
/// local run queue.
pub fn workers<T: Target>(session: &Session<'_, T>) -> Vec<WorkerInfo> {
    crate::workers::workers(session)
}

/// Each multi_thread runtime's inject queue: the tasks spawned from
/// outside its workers, waiting for one.
pub fn injects<T: Target>(session: &Session<'_, T>) -> Vec<InjectInfo> {
    crate::workers::injects(session)
}

/// The task whose header is at `addr`, as [`tasks`] names it.
pub fn task_at<T: Target>(session: &Session<'_, T>, addr: u64) -> Option<TaskRef> {
    tasks(session, &[], &[])
        .ok()?
        .into_iter()
        .find(|t| t.addr == addr)
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Dbg;
use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use debugdb::model::TypeWithDb;
use hansei_types::tokio::TokioRuntime;
use hansei_types::tokio::dwarf::{resolve_task_type, task_await_trace};
use std::io::Write;
use subprocess::Exec;
use swrite::{SWrite, swriteln};

#[derive(Parser)]
#[command(name = "", disable_help_flag = true, no_binary_name = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show corefile and ELF binary paths.
    Info,
    /// Lookup the type given its exact name
    Type { name: String },
    /// Search for types that contain the given substring
    FindTypes { needle: String },
    /// Show all tokio related threads along with their internal worker cores
    Threads,
    /// Show the tokio scheduler state shared across workers
    SharedState,
    /// Show the tokio drivers
    Drivers,
    /// Show all spawned tasks with their concrete future types
    Tasks,
    /// Show the logical await trace for a task by its ID
    TaskTrace { task_id: u64 },
    /// Exit the REPL.
    Quit,
    /// Exit the REPL.
    #[command(hide = true)]
    Exit,
}

impl Cli {
    pub fn commands() -> Vec<String> {
        Cli::command()
            .get_subcommands()
            .map(|sc| sc.get_name().into())
            .collect()
    }
}

/// Dispatch a command line. Returns Ok(true) to continue, Ok(false) to quit.
pub fn dispatch(runtime: &TokioRuntime, dbg: &Dbg, line: &str) -> Result<bool> {
    // Split on the first `!` character if it exists. Use the first
    // element of the iterator as the REPL command to parse via clap. Use the
    // second element, if it exists, as the shell command to pipe the output of
    // the REPL command into.
    let mut split = line.splitn(2, '!');

    // Parse the line of input before any `!` as a REPL command.
    //
    // Using `split_whitespace()` like this is going to be a problem if we ever
    // want to support arguments with whitespace in them (using quotes).  But
    // it's good enough for now.
    //
    // SAFETY: There is always at least one element in the iterator.
    let parts = split.next().expect("element exists").split_whitespace();

    let cli = match Cli::try_parse_from(parts) {
        Ok(cli) => cli,
        Err(e) => {
            eprint!("{e}");
            return Ok(true);
        }
    };

    let mut s = String::new();
    match cli.command {
        Command::Quit | Command::Exit => return Ok(false),
        Command::Info => {
            swriteln!(s, "core file: {}", dbg.core_path);
            swriteln!(s, "ELF binary: {}", dbg.elf_path);
        }
        Command::Type { name } => match dbg.db.types_by_name(&name).next() {
            Some((_, ty)) => {
                swriteln!(s, "{}", TypeWithDb(ty, &dbg.db));
            }
            None => swriteln!(s, "not found"),
        },
        Command::FindTypes { needle } => {
            let type_ids = dbg.db.find_types_by_name_substring(&needle);
            swriteln!(s, "{}", dbg.db.format_types(&type_ids));
        }
        Command::Threads => {
            show_threads(runtime, &mut s);
        }
        Command::SharedState => {
            swriteln!(s, "{:#?}", runtime.scheduler.shared);
        }
        Command::Drivers => {
            swriteln!(s, "{:#?}", runtime.scheduler.driver);
        }
        Command::Tasks => {
            show_tasks(runtime, dbg, &mut s);
        }
        Command::TaskTrace { task_id } => {
            let owned = &runtime.scheduler.shared.owned;
            let task_entry = owned.tasks.iter().find(|(_, h)| h.id == task_id);

            match task_entry {
                Some((addr, _)) => match task_await_trace(dbg, *addr) {
                    Ok(trace) => s.push_str(&trace),
                    Err(e) => swriteln!(s, "error: {e:#}"),
                },
                None => {
                    swriteln!(s, "task with id {task_id} not found");
                    swriteln!(s, "known task ids:");
                    for (addr, h) in &owned.tasks {
                        swriteln!(s, "  id={} addr={addr:?}", h.id);
                    }
                }
            }
        }
    }

    if let Some(shell_cmd) = split.next() {
        let mut child_stdin =
            Exec::shell(shell_cmd).stream_stdin().expect("stdin opened");

        // Using `write_all` doesn't play nicely with the shell group
        // leader, likely due to blocking/signal behavior. We therefore
        // manually loop over calls to `write`.
        let mut written_bytes = 0;
        let to_write = s.len();
        while written_bytes < to_write {
            match child_stdin.write(&s.as_bytes()[written_bytes..]) {
                Ok(0) => break,
                Ok(n) => written_bytes += n,
                Err(_) => {
                    // Broken pipe is a normal condition reflecting
                    // that the child process exited early (e.g., as
                    // `head(1)` does).
                    break;
                }
            }
        }
    } else {
        println!("{s}");
    }

    Ok(true)
}

fn show_tasks(runtime: &TokioRuntime, dbg: &Dbg, s: &mut String) {
    let owned = &runtime.scheduler.shared.owned;
    swriteln!(
        s,
        "Spawned tasks: {} (count: {})",
        owned.tasks.len(),
        owned.count
    );
    swriteln!(s, "");

    for (addr, header) in &owned.tasks {
        let concrete_type = resolve_task_type(dbg, *addr)
            .unwrap_or_else(|_| "<unknown>".to_string());

        swriteln!(s, "  {addr:?}  id={:<4}  {concrete_type}", header.id);
        swriteln!(
            s,
            "    spawned at {}:{}:{}",
            header.spawn_location.filename,
            header.spawn_location.line,
            header.spawn_location.col
        );
    }
}

// Print a user friendly thread display
fn show_threads(runtime: &TokioRuntime, s: &mut String) {
    for (tid, worker_state) in &runtime.workers {
        swriteln!(s, "Thread ID: {tid}");
        swriteln!(s, "====================");

        // Print the stack trace
        let max_frames = 50;
        let stack = worker_state
            .backtrace
            .as_ref()
            .map(|bt| bt.stack_trace(max_frames));
        if let Some(trace) = stack {
            for line in trace {
                swriteln!(s, "{line}");
            }
        }

        // Print the thread context
        swriteln!(s, "\n{:#?}\n", worker_state.thd_ctx);
    }
}

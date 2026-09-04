// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The session's one interface: a target is attached, and then asked.
//!
//! One target attached once and asked many questions is the shape the
//! analysis wants anyway — opening a core, loading a bundle, and walking
//! the runtime's workers and tasks costs the same whether one command
//! follows or twenty, and a core does not change underneath them. So
//! there is no per-command form of hansei: a session is attached once
//! and then asked, and only the asking differs:
//!
//! - a terminal gets [`reedline`]: a prompt, history, completion, and
//!   errors that end the command rather than the session;
//! - a pipe gets a plain line reader, and the first failure is fatal, so
//!   a script that asks for something impossible does not carry on and
//!   exit 0;
//! - `--exec` carries the commands on the command line under those same
//!   rules, for a caller with one question to ask and no stdin to spare.

use crate::output::Theme;
use crate::{Command, Flow, Session, dispatch};

use anyhow::{Context as _, Result, anyhow};
use clap::{CommandFactory, Parser};
use reedline::{
    ColumnarMenu, Completer, CompletionResult, DefaultPrompt, DefaultPromptSegment, Direction,
    EditCommand, Emacs, FileBackedHistory, Granularity, KeyCode, KeyModifiers, Keybindings,
    MenuBuilder, MotionTarget, Reedline, ReedlineEvent, ReedlineMenu, Signal, Span, Suggestion,
    WordEdge, WordKind, default_emacs_keybindings,
};
use subprocess::Exec;

use std::collections::HashMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

// One line of input. `no_binary_name` is what lets a clap grammar read a
// typed line: without it clap would take the first word for the
// executable and drop it. `about` is set explicitly because clap would
// otherwise lift this crate-internal note into the user's `help`.
// `infer_subcommands` accepts any leading substring that names one
// command and no other, so `ce` runs `census` — what a prompt is for.
#[derive(Parser)]
#[command(
    name = "",
    about = "Commands a hansei session accepts.",
    no_binary_name = true,
    disable_help_flag = true,
    infer_subcommands = true
)]
struct Line {
    #[command(subcommand)]
    command: Command,
}

pub fn run<T: proc::Target>(session: &Session<'_, T>, exec: &[String]) -> Result<()> {
    if !exec.is_empty() {
        from_command_line(session, exec)
    } else if io::stdin().is_terminal() {
        interactive(session)
    } else {
        scripted(session)
    }
}

/// Where the commands come from. The one command that cares is
/// `history`: a prompt has one, a pipe or `--exec` does not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    Interactive,
    Scripted,
}

/// Answer what `--exec` asked for and stop, without reading stdin.
///
/// The rules are a script's: the commands run in order and the first
/// failure is fatal, since a caller that put them on one command line
/// meant them as one question.
fn from_command_line<T: proc::Target>(session: &Session<'_, T>, exec: &[String]) -> Result<()> {
    for commands in exec {
        match execute(session, Mode::Scripted, commands)
            .with_context(|| format!("--exec {commands:?}"))?
        {
            Flow::Continue => continue,
            Flow::Quit => break,
        }
    }
    Ok(())
}

/// Read commands from a terminal until asked to stop. A command that
/// fails is reported and the session carries on: at a prompt the useful
/// response to a typo is another prompt.
fn interactive<T: proc::Target>(session: &Session<'_, T>) -> Result<()> {
    // The editor reads the terminal on a thread of its own, so the
    // session — which cannot leave this one — is free to answer the
    // completer while a line is still being typed: `tasks --with state
    // <Tab>` asks which states the target holds, and the rows that
    // answer are the session's, built once and cached on it.
    let (events_tx, events) = mpsc::channel();
    let (prompts_tx, prompts) = mpsc::channel::<String>();
    let editor = thread::spawn(move || edit_loop(events_tx, prompts));
    let prompt = || crate::cursor::prompt_label(&session.cursor.borrow());

    // A prompt the editor cannot take is an editor that has stopped,
    // and the events channel says why.
    let _ = prompts_tx.send(prompt());
    loop {
        match events.recv() {
            // The completer's question, asked mid-line: answer it and
            // leave the editor on the line it is reading.
            Ok(Event::Ask { ask, reply }) => {
                let _ = reply.send(answer(session, &ask));
                continue;
            }
            Ok(Event::Line(line)) => match execute(session, Mode::Interactive, &line) {
                Ok(Flow::Continue) => {}
                Ok(Flow::Quit) => break,
                Err(e) => eprintln!("error: {e:#}"),
            },
            Ok(Event::Interrupt) => {}
            Ok(Event::Eof) | Err(_) => break,
            Ok(Event::Failed(e)) => {
                eprintln!("input error: {e}");
                break;
            }
        }
        // Rebuilt per line: the prompt is the cursor's account of
        // where the session stands, and the last command may have
        // moved it.
        if prompts_tx.send(prompt()).is_err() {
            break;
        }
    }
    // No more prompts ends the editor's loop, and joining it drops the
    // editor — which is when reedline writes the history file.
    drop(prompts_tx);
    let _ = editor.join();
    Ok(())
}

/// What the editor's thread tells the session's: a line to run, the
/// signal that ended one, a terminal that failed, or the completer's
/// question with the channel its answer goes back on.
enum Event {
    Line(String),
    Interrupt,
    Eof,
    Failed(String),
    Ask {
        ask: Ask,
        reply: mpsc::Sender<Vec<TargetValue>>,
    },
}

/// A question only the session can answer, asked by the completer
/// mid-line.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Ask {
    /// Which values the target holds for a listing's field: what can
    /// stand after `--with FIELD`.
    Values { command: String, field: String },
    /// Which names a `print` path could take next: `args` are
    /// `print`'s arguments up to and including the `.` under the
    /// cursor, or none for the local being typed.
    Members { args: Vec<String> },
    /// Which recorded type names start with `prefix`: what can stand
    /// after `print`'s address.
    Types { prefix: String },
}

/// The session's answer to a question.
fn answer<T: proc::Target>(session: &Session<'_, T>, ask: &Ask) -> Vec<TargetValue> {
    match ask {
        Ask::Values { command, field } => target_values(session, command, field),
        // A path that does not resolve offers nothing: the error is
        // `print`'s to report once the line runs.
        Ask::Members { args } => crate::print::path_members(session, args)
            .unwrap_or_default()
            .into_iter()
            .map(|name| TargetValue {
                insert: name.clone(),
                spelled: name,
            })
            .collect(),
        Ask::Types { prefix } => crate::types::names_with_prefix(&session.ctx.view, prefix)
            .into_iter()
            .map(|name| TargetValue {
                insert: line_spelling(&name, false),
                spelled: name,
            })
            .collect(),
    }
}

/// The editor's thread: one `read_line` per prompt the session sends,
/// each answered with what was read. It ends when the session stops
/// sending prompts.
fn edit_loop(events: mpsc::Sender<Event>, prompts: mpsc::Receiver<String>) {
    let asker = events.clone();
    let mut editor = line_editor(Box::new(move |ask: Ask| {
        let (reply, answer) = mpsc::channel();
        if asker.send(Event::Ask { ask, reply }).is_err() {
            return Vec::new();
        }
        answer.recv().unwrap_or_default()
    }));
    while let Ok(label) = prompts.recv() {
        let prompt = DefaultPrompt::new(
            DefaultPromptSegment::Basic(label),
            DefaultPromptSegment::Empty,
        );
        let event = match editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
                // reedline writes the file only when the editor is
                // dropped; writing it per line is what lets `history`
                // read this session's lines back, and lets a second
                // session running beside this one see them too.
                if let Err(e) = editor.sync_history() {
                    eprintln!("warning: command history not saved: {e}");
                }
                Event::Line(line)
            }
            Ok(Signal::CtrlC) => Event::Interrupt,
            Ok(Signal::CtrlD) => Event::Eof,
            // Nothing here binds a host command or a break signal,
            // so neither arrives.
            Ok(_) => continue,
            Err(e) => Event::Failed(e.to_string()),
        };
        if events.send(event).is_err() {
            break;
        }
    }
}

/// One value the target holds — for a listing's field, or a type name
/// it records: as the listing spells it, which is what a typed prefix
/// is matched against, and as the line must carry it — regex-escaped
/// where the field reads a pattern, so the metacharacters a type name
/// is full of match themselves, and quoted where it holds a space or
/// a `;`, so the tokenizer keeps it one word and the command split
/// leaves it whole.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TargetValue {
    spelled: String,
    insert: String,
}

/// The values the target holds for one field of a listing — what can
/// stand after `--with FIELD` — or nothing for a command or field that
/// enumerates none. The rows this reads are cached on the session, so
/// the first question may pay for the census or an unwind of every
/// stack and the rest are free.
fn target_values<T: proc::Target>(
    session: &Session<'_, T>,
    command: &str,
    field: &str,
) -> Vec<TargetValue> {
    let found = match command {
        "tasks" => crate::tasks::field_values(session, field),
        "futures" => crate::futures::field_values(session, field),
        "threads" => crate::threads::field_values(session, field),
        "runtimes" => crate::runtimes::field_values(session, field),
        _ => None,
    };
    let Some((values, pattern)) = found else {
        return Vec::new();
    };
    values
        .into_iter()
        .map(|spelled| TargetValue {
            insert: clause_spelling(&spelled, pattern),
            spelled,
        })
        .collect()
}

/// How a value is spelled into a `--with FIELD ARG` word: as
/// [`line_spelling`] has it, with a comma the value holds escaped,
/// since ARG reads an unescaped one as separating alternatives.
fn clause_spelling(value: &str, pattern: bool) -> String {
    let text = if pattern {
        regex::escape(value)
    } else {
        value.to_string()
    };
    quoted_for_line(text.replace(',', "\\,"))
}

/// How a value is spelled back into the line: see [`TargetValue`].
fn line_spelling(value: &str, pattern: bool) -> String {
    let text = if pattern {
        regex::escape(value)
    } else {
        value.to_string()
    };
    quoted_for_line(text)
}

/// `text` as one word of the line: quoted where the tokenizer would
/// otherwise split it or read a quote of its own.
fn quoted_for_line(text: String) -> String {
    if !text
        .chars()
        .any(|c| c.is_whitespace() || c == ';' || c == '"' || c == '\'')
    {
        text
    } else if !text.contains('"') {
        format!("\"{text}\"")
    } else {
        format!("'{text}'")
    }
}

/// Read commands from a pipe or a file, one per line, and stop at the
/// first one that fails. Blank lines and `#` comments are skipped so a
/// stored script can be annotated.
fn scripted<T: proc::Target>(session: &Session<'_, T>) -> Result<()> {
    let stdin = io::stdin();
    for (n, line) in stdin.lock().lines().enumerate() {
        let line = line.context("failed to read a command from stdin")?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // The line number is the only handle a script has on which
        // command went wrong, since nothing echoes them.
        match execute(session, Mode::Scripted, &line)
            .with_context(|| format!("stdin line {}", n + 1))?
        {
            Flow::Continue => continue,
            Flow::Quit => break,
        }
    }
    Ok(())
}

/// Answer a line, which may hold several commands separated by `;`.
///
/// They run in order and stop at the first failure, so `tasks ; graph`
/// asks two questions of one target and a failure part-way through does
/// not go on to ask the rest. The separator binds looser than anything
/// else — a `;` ends the command it follows even inside the shell text
/// after a `!` — with two ways out: double quotes, which is how an
/// array type (`"[usize; 4]"`) crosses the split, and `\;` for a
/// literal `;`. That pair is the whole escape grammar; every other
/// backslash is itself.
pub(crate) fn execute<T: proc::Target>(
    session: &Session<'_, T>,
    mode: Mode,
    line: &str,
) -> Result<Flow> {
    let commands = split_commands(line);
    for command in &commands {
        let flow = match command_frame(commands.len(), command) {
            None => execute_one(session, mode, command)?,
            Some(frame) => execute_one(session, mode, command).with_context(|| frame)?,
        };
        if let Flow::Quit = flow {
            return Ok(Flow::Quit);
        }
    }
    Ok(Flow::Continue)
}

/// Split a line at every bare `;`. A `;` inside double quotes is part
/// of the word, the way an array type's name (`"[usize; 4]"`) needs —
/// the quotes are kept for the tokenizer, which is what drops them —
/// and `\;` is a literal `;` too, unescaped here. Exactly that
/// two-character sequence is special; any other backslash passes
/// through untouched, so nothing else needs escaping and no name grows
/// a second spelling. Only double quotes shelter a `;`: a single quote
/// is a lifetime's mark in a type name, and treating it as a quote
/// would swallow the rest of the line.
fn split_commands(line: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(';') => current.push(';'),
                Some(other) => {
                    current.push('\\');
                    current.push(other);
                }
                None => current.push('\\'),
            },
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            ';' if !quoted => commands.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    commands.push(current);
    commands
}

/// Split one command's text into words. Whitespace separates; a
/// double- or single-quoted stretch joins into one word with the
/// quotes dropped, so a name holding spaces (`"Vec<(u64, u64)>"`) is
/// one token. That is the whole grammar: backslash is a literal
/// character everywhere — the regex arguments this surface carries
/// escape with it, and eating those escapes shell-style would quietly
/// turn `foo\.bar` into a different pattern. An unclosed quote is an
/// error rather than a guess at what was meant.
fn split_tokens(command: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    // Distinct from `current.is_empty()` so `""` stands as an empty
    // word rather than vanishing.
    let mut in_word = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some(close) if close == c => break,
                        Some(inner) => current.push(inner),
                        None => return Err(anyhow!("unclosed {c} quote")),
                    }
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                current.push(c);
            }
        }
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

/// How a failure names the command it came from. Which command failed
/// is only a question when the line held more than one; on a
/// single-command line, the line itself is the answer.
fn command_frame(count: usize, command: &str) -> Option<String> {
    (count > 1).then(|| format!("in `{}`", command.trim()))
}

/// Parse one command and answer it, sending the output to a shell
/// pipeline if it asked for one.
///
/// Two rewrites run on the command half — never on the shell half —
/// before clap sees it: a leading `task X` / `future X` / `thread X`
/// with more words after it scopes the rest to that cursor without
/// moving the session's, and a `$_` token becomes the (scoped)
/// cursor's current-frame address.
fn execute_one<T: proc::Target>(session: &Session<'_, T>, mode: Mode, line: &str) -> Result<Flow> {
    // Everything after the first `!` is a shell command to pipe into,
    // so `tasks ! grep foo` filters the listing.
    let (command, shell) = match line.split_once('!') {
        Some((command, shell)) => (command, Some(shell)),
        None => (line, None),
    };

    if command.trim().is_empty() {
        return Ok(Flow::Continue);
    }

    let words = split_tokens(command)?;
    let (saved, words) = match peel_scope(&words) {
        Some((scope, rest)) => {
            let saved = *session.cursor.borrow();
            // A scope that does not select (a bad id, a wild address)
            // fails the command; the selectors leave the cursor
            // untouched unless they succeed.
            apply_scope(session, scope)?;
            (Some(saved), rest.to_vec())
        }
        None => (None, words),
    };
    let result = answer_words(session, mode, &words, shell);
    if let Some(saved) = saved {
        *session.cursor.borrow_mut() = saved;
    }
    result
}

/// Answer the already-scoped words: substitute `$_`, parse, dispatch,
/// stream. Split from [`execute_one`] so the scope above is restored
/// whichever way this returns.
fn answer_words<T: proc::Target>(
    session: &Session<'_, T>,
    mode: Mode,
    words: &[String],
    shell: Option<&str>,
) -> Result<Flow> {
    let words = substitute_last_addr(words, session.cursor.borrow().last_addr)?;
    let parsed = match parse_words(&words)? {
        Some(parsed) => parsed,
        None => return Ok(Flow::Continue),
    };
    // `history` is the repl's own to answer — it is about the prompt,
    // not the target — so it is peeled off before the target is asked.
    let answer = move |theme: Theme, out: &mut dyn Write| -> Result<Flow> {
        match parsed.command {
            Command::History { last } => {
                print_history(mode, last, out)?;
                Ok(Flow::Continue)
            }
            command => dispatch(session, command, theme, out),
        }
    };

    // Either way the answer streams: a trace's output can run to
    // gigabytes, and holding it whole just to copy it out doubles the
    // traffic and the resident set. The writer buffers small pieces (a
    // heading line) and passes big ones through; a command that fails
    // mid-answer has printed what it printed.
    // The theme is where the output is going: a `!` pipe is a program's
    // input however the session was started, so only the plain stdout
    // path may style — but the pipeline inherits stdout, so its last
    // command writes to the same terminal, and the pipe's theme keeps
    // that terminal's width.
    match shell {
        Some(shell) => {
            let sink = ShellSink {
                stdin: Some(Box::new(Exec::shell(shell.trim()).stream_stdin()?)),
            };
            let mut out = io::BufWriter::new(sink);
            let flow = answer(Theme::for_pipe(), &mut out)?;
            out.flush()?;
            Ok(flow)
        }
        None => {
            let stdout = io::stdout();
            let mut out = io::BufWriter::new(stdout.lock());
            let flow = answer(Theme::for_stdout(), &mut out)?;
            out.flush()?;
            Ok(flow)
        }
    }
}

/// Parse one command line, split by [`split_tokens`]. The session
/// path goes through [`parse_words`] after the scope and `$_`
/// rewrites; this spelling serves the suites.
#[cfg(test)]
fn parse_command(command: &str) -> Result<Option<Line>> {
    let words = split_tokens(command)?;
    parse_words(&words)
}

/// Parse one command's words, or answer it on the spot: `None` means
/// the command was already answered with printed output rather than
/// parsed into something to dispatch.
fn parse_words(words: &[String]) -> Result<Option<Line>> {
    match Line::try_parse_from(words) {
        Ok(parsed) => Ok(Some(parsed)),
        // A one-word help request is bare `help` however abbreviated,
        // and its listing is rendered here rather than by clap, which
        // lists subcommands as one flat block and has no way to head
        // groups of them. `help COMMAND` is still clap's.
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp && words.len() == 1 => {
            print!("{}", help_listing(&Theme::for_stdout()));
            Ok(None)
        }
        // `use_stderr` is clap's own split between a real parse failure
        // and output that was asked for: `help tasks` renders as an
        // error but is a successful command, and must not fail a script.
        Err(e) if !e.use_stderr() => {
            print!("{e}");
            Ok(None)
        }
        Err(e) => Err(anyhow!("{}", clap_message(e))),
    }
}

/// The sections bare `help` lists the commands under, each in the
/// order it is read: the target's overview first, then what selects
/// a cursor and what asks about it. Every visible command is filed
/// exactly once (`test_help_sections_file_every_visible_command_once`
/// holds a new one to that), and the hidden ones are not filed at
/// all, since clap would not list them either.
const HELP_SECTIONS: &[(&str, &[&str])] = &[
    ("Overview", &["info", "census"]),
    (
        "Listings",
        &["tasks", "futures", "threads", "runtimes", "graph"],
    ),
    ("Selection", &["task", "future", "thread"]),
    ("Frame navigation", &["frame", "up", "down"]),
    (
        "Inspection",
        &["trace", "locals", "print", "regs", "runtime", "whatis"],
    ),
    (
        "Other commands",
        &["config", "history", "save-tokio-info", "help", "quit"],
    ),
];

/// The width help wraps at: the terminal's, capped where clap caps
/// its own so `help` and `help COMMAND` flow alike, and that cap
/// outright where the output is not a terminal.
const HELP_WIDTH: usize = 100;

/// The listing bare `help` prints: every command clap would list,
/// under [`HELP_SECTIONS`]' headings. The text beside each command is
/// its own first paragraph — what clap would have printed — so this
/// and `help COMMAND` never disagree.
fn help_listing(theme: &Theme) -> String {
    let mut root = Line::command();
    root.build();
    let width = theme.width().map_or(HELP_WIDTH, |w| w.min(HELP_WIDTH));
    // One column for every section, as clap pads one listing: the
    // longest name sets it, a two-space indent before and gap after.
    let column = HELP_SECTIONS
        .iter()
        .flat_map(|(_, names)| names.iter())
        .map(|name| name.len())
        .max()
        .unwrap_or(0)
        + 4;

    let mut out = root.get_about().map(|a| a.to_string()).unwrap_or_default();
    out.push('\n');
    for (heading, names) in HELP_SECTIONS {
        out.push('\n');
        out.push_str(&theme.bold(&format!("{heading}:")));
        out.push('\n');
        for name in names.iter() {
            let about = root
                .find_subcommand(name)
                .and_then(|c| c.get_about())
                .map(|a| a.to_string())
                .unwrap_or_default();
            out.push_str(&format!("  {name:<w$}", w = column - 2));
            for (i, line) in wrap_words(&about, width.saturating_sub(column))
                .iter()
                .enumerate()
            {
                if i > 0 {
                    out.push_str(&" ".repeat(column));
                }
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// `text` flowed into lines of at most `width` characters, broken at
/// spaces; a word longer than the width stands alone on its line.
/// Empty text is one empty line, so a caller always ends the line it
/// started.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split_whitespace() {
        let line = lines.last_mut().expect("one line always stands");
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(word.to_string());
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    lines
}

/// Parse the words a frame move carries after it (`up locals`), for
/// dispatch at the new frame. The words arrive already tokenized by
/// the line they came in on; `None` means they were answered in print
/// (`help`) rather than parsed into something to dispatch.
pub(crate) fn parse_trailing(words: &[String]) -> Result<Option<crate::Command>> {
    Ok(parse_words(words)?.map(|line| line.command))
}

/// What a scoped prefix selects: `task 129 trace -v` runs `trace -v`
/// under a cursor on task 129 without moving the session's own —
/// delve's `goroutine 42 bt`. This is also what `tasks --exec` runs
/// each surviving task's command under.
enum Scope {
    Task(crate::TraceTarget),
    Future(u64),
    Thread(u32),
}

/// Peel a leading `task X` / `future X` / `thread X` when more words
/// follow. A bare selector is a command, not a scope, and so is a
/// selector with only flags after its argument (`task 129 -v`): the
/// peel requires the word after the argument to start a command. An
/// argument the selector would not parse (so, a mistyped line) is
/// left whole for clap to refuse with the selector's own error.
fn peel_scope(words: &[String]) -> Option<(Scope, &[String])> {
    if words.len() < 3 || words[2].starts_with('-') {
        return None;
    }
    Some((parse_scope(&words[0], &words[1])?, &words[2..]))
}

/// The scope a selector word and its argument name, if they parse as
/// one. Shared with the completer, which sees the scope before the
/// command it applies to has been typed.
fn parse_scope(selector: &str, arg: &str) -> Option<Scope> {
    Some(match selector {
        "task" => Scope::Task(crate::parse_trace_target(arg).ok()?),
        "future" => Scope::Future(crate::parse_hex_addr(arg).ok()?),
        "thread" => Scope::Thread(arg.parse().ok()?),
        _ => return None,
    })
}

/// Point the cursor where a scope says, silently: the selection line
/// belongs to the selector commands, not to a prefix that exists to
/// run something else.
fn apply_scope<T: proc::Target>(session: &Session<'_, T>, scope: Scope) -> Result<()> {
    match scope {
        Scope::Task(target) => crate::cursor::select_task(session, target).map(|_| ()),
        Scope::Future(addr) => crate::cursor::select_future(session, addr).map(|_| ()),
        Scope::Thread(lwp) => crate::cursor::select_thread(session, lwp),
    }
}

/// Substitute `$_` — the cursor's current-frame address — wherever it
/// stands as a whole word. Only the exact token: anything it is
/// embedded in is somebody's name, not a reference to the cursor.
fn substitute_last_addr(words: &[String], last: Option<u64>) -> Result<Vec<String>> {
    words
        .iter()
        .map(|word| match word == "$_" {
            true => last.map(|addr| format!("{addr:#x}")).ok_or_else(|| {
                anyhow!("$_ is unset: no cursor stands; `task`, `future` or `thread` selects one")
            }),
            false => Ok(word.clone()),
        })
        .collect()
}

/// clap renders a parse failure with an `error: ` prefix of its own.
/// Both callers frame the failure themselves, so strip it rather than
/// print the word twice.
fn clap_message(e: clap::Error) -> String {
    let rendered = e.to_string();
    rendered
        .strip_prefix("error: ")
        .unwrap_or(&rendered)
        .trim_end()
        .to_string()
}

/// A command's output on its way into a shell pipeline's stdin,
/// written as the command renders. The first write failure quietly
/// ends the feed — a broken pipe is normal, the child exiting early as
/// `head(1)` does — and the rest of the answer is discarded rather
/// than failing the command that produced it. Dropping this closes the
/// pipe, which is the child's end-of-input.
struct ShellSink {
    /// The child's stdin; `None` once a write failed.
    stdin: Option<Box<dyn Write>>,
}

impl Write for ShellSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(stdin) = &mut self.stdin {
            // `write_all` does not play nicely with the shell's group
            // leader here, so the writes are looped by hand.
            let mut written = 0;
            while written < buf.len() {
                match stdin.write(&buf[written..]) {
                    Ok(0) | Err(_) => {
                        self.stdin = None;
                        break;
                    }
                    Ok(n) => written += n,
                }
            }
        }
        // The feed never errors: a dead pipe swallows what remains.
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(stdin) = &mut self.stdin
            && stdin.flush().is_err()
        {
            self.stdin = None;
        }
        Ok(())
    }
}

/// Tab completion that knows where in the line the cursor stands: on
/// the command word, on a flag, or on the value a flag or positional
/// takes — so `tasks --group <Tab>` offers the field names and `info
/// <Tab>` the sections, not the command list.
///
/// The grammar it reads is the command tree itself: subcommands and
/// their flags come from [`Line`], a value's choices from the arg's
/// declared possible values (every `ValueEnum`), and the few value
/// sets clap cannot see — the `FIELD` of a `--with FIELD ARG` pair,
/// whose second value is free-form, and `config`'s keys — from the
/// modules that parse them; what only the target knows — a clause's
/// argument, a selector's id — is asked of the session. A word the
/// grammar does not recognize completes to nothing rather than to a
/// guess.
struct LineCompleter {
    /// Where the answers only the session has come from: its thread,
    /// asked over a channel while the prompt waits. Tests pass a
    /// closure over fixed rows.
    source: ValueSource,
    /// Each field's values, and each type prefix's names, asked once.
    /// A core does not change under a session, and the first answer
    /// may have cost the census or an unwind of every stack. Member
    /// names are not cached: they depend on where the cursor stands,
    /// and cost one frame read.
    cache: HashMap<Ask, Vec<TargetValue>>,
}

type ValueSource = Box<dyn FnMut(Ask) -> Vec<TargetValue> + Send>;

impl LineCompleter {
    fn new(source: ValueSource) -> Self {
        LineCompleter {
            source,
            cache: HashMap::new(),
        }
    }

    /// The session's answer to `ask`, from the cache where it keeps.
    fn answer(&mut self, ask: Ask) -> Vec<TargetValue> {
        if let Some(values) = self.cache.get(&ask) {
            return values.clone();
        }
        let values = (self.source)(ask.clone());
        if !matches!(ask, Ask::Members { .. }) {
            self.cache.insert(ask, values.clone());
        }
        values
    }
}

/// One thing the cursor's word could become: as spelled, which the
/// typed prefix is matched against; as inserted, which differs only
/// for a target's value that needs escaping or quoting; with the
/// description the menu shows beside it; and whether a space follows
/// it — a path step does not end the word, since the next step
/// continues it.
struct Candidate {
    spelled: String,
    insert: String,
    description: Option<String>,
    space: bool,
}

impl Candidate {
    /// A word of the grammar's own: inserted as spelled, a space after.
    fn word(spelled: impl Into<String>, description: Option<String>) -> Candidate {
        let spelled = spelled.into();
        Candidate {
            insert: spelled.clone(),
            spelled,
            description,
            space: true,
        }
    }
}

impl Completer for LineCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> CompletionResult {
        CompletionResult::fresh(self.suggest(line, pos))
    }
}

impl LineCompleter {
    /// The suggestions for the word under the cursor at `pos`: what
    /// the grammar and the session offer there, narrowed to the
    /// prefix typed.
    fn suggest(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let Some(prefix) = line.get(..pos) else {
            return Vec::new();
        };
        let Some((words, current, start)) = words_before(prefix) else {
            return Vec::new();
        };
        // Built, so every arg's value count is filled in and clap's own
        // `help` command stands beside the declared ones.
        let mut root = Line::command();
        root.build();
        let mut answer = |ask: Ask| self.answer(ask);
        candidates(&root, &words, &current, &mut answer)
            .into_iter()
            .filter(|c| c.spelled.starts_with(&current))
            .map(|c| Suggestion {
                value: c.insert,
                description: c.description,
                span: Span::new(start, pos),
                append_whitespace: c.space,
                ..Suggestion::default()
            })
            .collect()
    }
}

/// The complete words before the cursor, the word under it (empty when
/// the cursor follows a space), and the byte offset that word starts
/// at. `None` when there is nothing to complete: the cursor stands on
/// the shell's side of a `!`, inside an unclosed quote, or on a word a
/// quote touched — nothing this completes contains a space, so a
/// quoted word is somebody's name.
fn words_before(prefix: &str) -> Option<(Vec<String>, String, usize)> {
    if prefix.contains('!') {
        return None;
    }
    let mut words = split_tokens(prefix).ok()?;
    let start = prefix
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_whitespace())
        .map_or(0, |(i, c)| i + c.len_utf8());
    let raw = &prefix[start..];
    if raw.contains(['"', '\'']) {
        return None;
    }
    if raw.is_empty() {
        return Some((words, String::new(), prefix.len()));
    }
    // Unquoted, so the raw text and the token it split to are the same.
    let current = words.pop()?;
    Some((words, current, start))
}

/// Everything that could stand at the cursor, before the typed prefix
/// narrows it. `root` is the built grammar the line is read against;
/// `answer` is the session's, for what only it knows.
fn candidates(
    root: &clap::Command,
    words: &[String],
    current: &str,
    answer: &mut dyn FnMut(Ask) -> Vec<TargetValue>,
) -> Vec<Candidate> {
    // A scope prefix is peeled as `execute_one` peels it, except that
    // the word after the selector's argument may be the one being
    // typed. `task 129 -v` is the selector's own flag, not a scope.
    let words = match words {
        [selector, arg, rest @ ..]
            if parse_scope(selector, arg).is_some()
                && !rest
                    .first()
                    .map_or(current, String::as_str)
                    .starts_with('-') =>
        {
            rest
        }
        _ => words,
    };
    let Some((word, rest)) = words.split_first() else {
        return root
            .get_subcommands()
            .filter(|sub| !sub.is_hide_set())
            .map(|sub| Candidate::word(sub.get_name(), None))
            .collect();
    };
    let Some(cmd) = find_command(root, word) else {
        return Vec::new();
    };
    // `print`'s arguments are a grammar of their own: a local, then
    // path steps, of which the name steps complete.
    if cmd.get_name() == "print" {
        return path_candidates(rest, current, answer);
    }

    // Walk the words to learn what the cursor's word is: the value of a
    // flag still owed values (with the values it has so far, since the
    // second word of a `--with FIELD ARG` pair depends on the first),
    // or the next positional.
    let mut pending: Option<(&clap::Arg, Vec<&str>)> = None;
    let mut positional_words: Vec<&str> = Vec::new();
    for word in rest {
        // `pending` is cleared once its option has every value it can
        // take, so a pending option is always owed this word — unless
        // the word is a flag and the option does not take those.
        if let Some((opt, taken)) = &mut pending {
            if !looks_like_flag(word) || opt.is_allow_hyphen_values_set() {
                taken.push(word);
                if taken.len() >= opt.get_num_args().expect("built").max_values() {
                    pending = None;
                }
                continue;
            }
            pending = None;
        }
        if let Some(flag) = word.strip_prefix("--") {
            let (name, inline) = match flag.split_once('=') {
                Some((name, _)) => (name, true),
                None => (flag, false),
            };
            pending = cmd
                .get_arguments()
                .find(|a| a.get_long() == Some(name))
                .filter(|a| !inline && a.get_num_args().expect("built").takes_values())
                .map(|a| (a, Vec::new()));
        } else if looks_like_flag(word) {
            // A cluster `-vl`: the first short that takes a value owns
            // the rest of the word, or the words after it when there
            // is no rest.
            let mut chars = word[1..].chars();
            while let Some(c) = chars.next() {
                let Some(arg) = cmd.get_arguments().find(|a| a.get_short() == Some(c)) else {
                    continue;
                };
                if arg.get_num_args().expect("built").takes_values() {
                    pending = chars.next().is_none().then_some((arg, Vec::new()));
                    break;
                }
            }
        } else {
            positional_words.push(word);
        }
    }

    // A dash under the cursor, alone or not, is a flag being typed.
    if let Some((opt, taken)) = &pending
        && (!current.starts_with('-') || opt.is_allow_hyphen_values_set())
    {
        return values_of(cmd, opt, taken, &positional_words, current, answer);
    }
    if current.starts_with('-') {
        // Only the long spellings: `-` alone expands to them, and a
        // positional has none to offer.
        return cmd
            .get_arguments()
            .filter(|a| !a.is_hide_set())
            .filter_map(|a| {
                a.get_long()
                    .map(|l| Candidate::word(format!("--{l}"), None))
            })
            .collect();
    }
    // The positional the cursor's word would become: the next by
    // index, or the trailing many-valued one when the index runs past
    // the last.
    let index = positional_words.len() + 1;
    let positional = cmd
        .get_positionals()
        .find(|a| a.get_index() == Some(index))
        .or_else(|| {
            cmd.get_positionals()
                .last()
                .filter(|a| a.get_num_args().expect("built").max_values() > 1)
        });
    match positional {
        Some(arg) => values_of(
            cmd,
            arg,
            &positional_words,
            &positional_words,
            current,
            answer,
        ),
        None => Vec::new(),
    }
}

/// The names a `print` path could continue with. The word under the
/// cursor completes at its last `.` — the member being typed, the
/// steps before it kept — and a first word with no `.` is the local
/// being typed, offered from the frame's own members. The word after
/// an address is the type to read it as, offered from the recorded
/// names with the typed prefix and quoted where the line needs. An
/// index or a dereference under the cursor, or a later word with no
/// `.`, completes nothing.
fn path_candidates(
    rest: &[String],
    current: &str,
    answer: &mut dyn FnMut(Ask) -> Vec<TargetValue>,
) -> Vec<Candidate> {
    if let [addr] = rest
        && crate::print::is_address(addr)
    {
        return answer(Ask::Types {
            prefix: current.to_string(),
        })
        .into_iter()
        .map(|t| Candidate {
            spelled: t.spelled,
            insert: t.insert,
            description: None,
            space: true,
        })
        .collect();
    }
    let (stem, partial) = match current.rfind('.') {
        Some(dot) => current.split_at(dot + 1),
        None if rest.is_empty() => ("", current),
        None => return Vec::new(),
    };
    if partial.contains(['[', '*']) {
        return Vec::new();
    }
    let mut args: Vec<String> = rest.to_vec();
    if !stem.is_empty() {
        args.push(stem.to_string());
    }
    answer(Ask::Members { args })
        .into_iter()
        .map(|name| Candidate {
            spelled: format!("{stem}{}", name.spelled),
            insert: format!("{stem}{}", name.insert),
            description: None,
            space: false,
        })
        .collect()
}

/// The subcommand `word` names, by the rule the grammar's
/// `infer_subcommands` applies: its name exactly, else the one command
/// it is a prefix of. The grammar declares no aliases, for commands or
/// flags, so neither lookup here nor the flag lookup above reads them.
fn find_command<'c>(root: &'c clap::Command, word: &str) -> Option<&'c clap::Command> {
    root.get_subcommands()
        .find(|c| c.get_name() == word)
        .or_else(|| {
            let mut prefixed = root
                .get_subcommands()
                .filter(|c| c.get_name().starts_with(word));
            let one = prefixed.next()?;
            prefixed.next().is_none().then_some(one)
        })
}

/// Whether clap would read `word` as a flag rather than a value: a
/// dash and something after it. A lone `-` is a value.
fn looks_like_flag(word: &str) -> bool {
    word.len() > 1 && word.starts_with('-')
}

/// The values `arg` accepts next, given the values it has so far
/// (`taken`: `--with FIELD ARG` has two, and the second depends on
/// the first), with each value's help where the grammar declares one.
/// `positional_words` are the positionals already typed, for a value
/// whose choices depend on an earlier one (`config ugly <Tab>`);
/// `answer` is the session's, for what the target holds.
fn values_of(
    cmd: &clap::Command,
    arg: &clap::Arg,
    taken: &[&str],
    positional_words: &[&str],
    current: &str,
    answer: &mut dyn FnMut(Ask) -> Vec<TargetValue>,
) -> Vec<Candidate> {
    let declared = arg.get_possible_values();
    if !declared.is_empty() {
        return declared
            .iter()
            .filter(|v| !v.is_hide_set())
            .map(|v| Candidate::word(v.get_name(), v.get_help().map(|h| h.to_string())))
            .collect();
    }
    let command = cmd.get_name();
    let names: Vec<&str> = match (command, arg.get_id().as_str(), taken) {
        ("tasks", "with" | "without" | "group", []) => crate::tasks::Field::names().collect(),
        ("futures", "with" | "without" | "group", []) => crate::futures::Field::names().collect(),
        ("threads", "with" | "without" | "group", []) => crate::threads::Field::names().collect(),
        ("runtimes", "with" | "without" | "group", []) => crate::runtimes::Field::names().collect(),
        // The clause's argument: what the target holds for the field
        // the first word named. The argument is a comma list of
        // alternatives, so the word completes at its last unescaped
        // comma — the alternatives before it kept, the one being
        // typed offered.
        ("tasks" | "futures" | "threads" | "runtimes", "with" | "without", [field]) => {
            let ask = Ask::Values {
                command: command.to_string(),
                field: field.to_string(),
            };
            let (head, _) = current.split_at(last_alternative(current));
            return answer(ask)
                .into_iter()
                .map(|v| Candidate {
                    spelled: format!("{head}{}", v.spelled),
                    insert: format!("{head}{}", v.insert),
                    description: None,
                    space: true,
                })
                .collect();
        }
        // A selector's argument: the ids its listing holds, which are
        // the same values `--with id` / `--with lwp` complete to.
        ("task", "target", _) | ("thread", "lwp", _) | ("runtime", "scope", _) => {
            let (listing, field) = match command {
                "task" => ("tasks", "id"),
                "thread" => ("threads", "lwp"),
                _ => ("runtimes", "id"),
            };
            return answer(Ask::Values {
                command: listing.to_string(),
                field: field.to_string(),
            })
            .into_iter()
            .map(|v| Candidate::word(v.spelled, None))
            .collect();
        }
        ("config", "key", _) => crate::settings::KEYS.to_vec(),
        ("config", "value", _) => positional_words
            .first()
            .map_or(&[][..], |key| crate::settings::word_values(key))
            .to_vec(),
        _ => Vec::new(),
    };
    names
        .into_iter()
        .map(|n| Candidate::word(n, None))
        .collect()
}

/// Where the alternative under the cursor starts in a clause argument:
/// just past the last comma no backslash escapes, or 0 for a word
/// with none — the split `tasks::alternatives` makes.
fn last_alternative(word: &str) -> usize {
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in word.char_indices() {
        match c {
            '\\' => escaped = !escaped,
            ',' if !escaped => start = i + 1,
            _ => escaped = false,
        }
    }
    start
}

/// readline's word motions, over reedline's own: a word is a run of
/// alphanumerics and `_`, so `sled.time_deleted` is two words with
/// the `.` a word of its own between them, and `M-b` from its end
/// stops at `time`. reedline's emacs bindings segment by the Unicode
/// rules instead, which keep a `.` between letters inside the word
/// and carry `M-b` back to `sled`. `C-w` stays whitespace-delimited,
/// as readline's unix-word-rubout is.
fn bind_readline_words(kb: &mut Keybindings) {
    use KeyCode::{Backspace, Char, Delete, Left, Right};
    const ALT: KeyModifiers = KeyModifiers::ALT;
    const CONTROL: KeyModifiers = KeyModifiers::CONTROL;
    let word = |edge, direction| MotionTarget::Word {
        kind: WordKind::Word,
        edge,
        direction,
    };
    let go = |target| ReedlineEvent::Edit(vec![EditCommand::Move(target)]);
    let cut = |target| {
        ReedlineEvent::Edit(vec![EditCommand::Cut {
            target,
            granularity: Granularity::CharWise,
        }])
    };
    let back = word(WordEdge::Start, Direction::Backward);
    let ahead = word(WordEdge::End, Direction::Forward);
    for (modifiers, key) in [(ALT, Char('b')), (ALT, Left), (CONTROL, Left)] {
        kb.add_binding(modifiers, key, go(back));
    }
    for (modifiers, key) in [(ALT, Char('f')), (ALT, Right), (CONTROL, Right)] {
        // The history hint completes a word first, as the default does.
        kb.add_binding(
            modifiers,
            key,
            ReedlineEvent::UntilFound(vec![ReedlineEvent::HistoryHintWordComplete, go(ahead)]),
        );
    }
    for (modifiers, key) in [(ALT, Char('d')), (ALT, Delete), (CONTROL, Delete)] {
        kb.add_binding(modifiers, key, cut(ahead));
    }
    for (modifiers, key) in [(ALT, Backspace), (CONTROL, Backspace)] {
        kb.add_binding(modifiers, key, cut(back));
    }
    kb.add_binding(
        CONTROL,
        Char('w'),
        cut(MotionTarget::Word {
            kind: WordKind::LongWord,
            edge: WordEdge::Start,
            direction: Direction::Backward,
        }),
    );
}

/// Tab opens the completion menu and then walks it forward; Shift+Tab
/// walks it back. The terminal reports Shift+Tab as `BackTab` with the
/// shift modifier still set, so that is the key it binds.
fn bind_completion_menu(kb: &mut Keybindings) {
    kb.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu(COMPLETION_MENU.to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    kb.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::MenuPrevious,
    );
}

/// The name the completion menu is registered under, which is how the
/// Tab binding refers to it.
const COMPLETION_MENU: &str = "commands";

/// The editor: Tab completes through [`LineCompleter`], whose target
/// values come from `source`.
fn line_editor(source: ValueSource) -> Reedline {
    let mut keybindings = default_emacs_keybindings();
    bind_readline_words(&mut keybindings);
    bind_completion_menu(&mut keybindings);

    let editor = Reedline::create()
        .with_completer(Box::new(LineCompleter::new(source)))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(
            ColumnarMenu::default().with_name(COMPLETION_MENU),
        )))
        .with_edit_mode(Box::new(Emacs::new(keybindings)));

    // History is a convenience, not a requirement: a session where it
    // cannot be opened is still worth having.
    match history_path().map(|path| FileBackedHistory::with_file(10_000, path)) {
        Some(Ok(history)) => editor.with_history(Box::new(history)),
        Some(Err(e)) => {
            eprintln!("warning: no command history: {e}");
            editor
        }
        None => editor,
    }
}

fn history_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".hansei_history"))
}

/// Print the history file — every session's lines, since reedline
/// merges them there — oldest first, or only the last `last` of them.
fn print_history(mode: Mode, last: Option<usize>, out: &mut dyn Write) -> Result<()> {
    if mode == Mode::Scripted {
        return Err(anyhow!("no history in a scripted session"));
    }
    let path = history_path().ok_or_else(|| anyhow!("no history: HOME is not set"))?;
    for line in history_lines(&read_history(&path)?, last) {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// The history file's text. A file that does not exist yet is an
/// empty history, not an error: nothing has been typed at a prompt on
/// this machine before, which `history` answers with nothing.
fn read_history(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// The history file's entries as the lines `history` prints: each
/// numbered by its position in the file, oldest first, so the numbers
/// mean the same under `history` and `history N`. Entries are one per
/// line in the file, so the file's line is the entry.
fn history_lines(text: &str, last: Option<usize>) -> Vec<String> {
    let entries: Vec<&str> = text.lines().collect();
    let skip = last.map_or(0, |n| entries.len().saturating_sub(n));
    entries
        .iter()
        .enumerate()
        .skip(skip)
        .map(|(i, entry)| format!("{:>5}  {entry}", i + 1))
        .collect()
}

/// Parse one command from the words `tasks --exec` carries, for
/// running it under a per-task scope. The words usually arrive
/// already split — `--exec` takes the rest of its line — but a
/// quoted command (`--exec 'trace -v'`) lands as one word holding
/// whitespace, and is split here the way the prompt would have split
/// it unquoted. Output-only parses (`help`) are errors here: an exec
/// loop wants a command to run.
///
/// Because `--exec` takes the rest of the line, it has to be the
/// listing's last flag: a `--with` typed after it is handed to the
/// exec command, which does not know it. That misplacement is
/// refused here in the rule's own words, whether the command was
/// quoted (so the listing's flag follows a whitespace-holding word)
/// or not (so the exec command's parse trips over it).
pub(crate) fn parse_exec_command(words: &[String]) -> Result<Command> {
    let resplit;
    let words = match words {
        [one] if one.chars().any(char::is_whitespace) => {
            resplit = split_tokens(one)?;
            &resplit
        }
        [one, rest @ ..] if one.chars().any(char::is_whitespace) => {
            anyhow::bail!(
                "{}: `{}` follows the quoted command; --exec takes the rest of the line, so \
                 the listing's other flags go before it",
                EXEC_COMES_LAST,
                rest.join(" ")
            );
        }
        words => words,
    };
    match Line::try_parse_from(words) {
        Ok(line) => Ok(line.command),
        Err(e) => {
            let message = clap_message(e);
            match words
                .iter()
                .skip(1)
                .find(|w| LISTING_FLAGS.contains(&w.as_str()))
            {
                Some(flag) => Err(anyhow!(
                    "{message}\n\n  {EXEC_COMES_LAST}: `{flag}` was handed to the exec command; \
                     the listing's other flags go before --exec"
                )),
                None => Err(anyhow!("{message}")),
            }
        }
    }
}

/// The rule a misplaced `--exec` is refused with.
const EXEC_COMES_LAST: &str = "--exec must be the last flag";

/// The flags the listing commands own that an exec command does not:
/// one of these among the exec words means `--exec` was not last.
const LISTING_FLAGS: &[&str] = &["--with", "-w", "--without", "-W", "--group", "-g"];

/// Parse one command line the way the prompt does, handing back the
/// grammar's own `Command` for suites that drive `dispatch` directly.
#[cfg(test)]
pub(crate) fn parse_line(command: &str) -> Result<crate::Command> {
    Ok(parse_command(command)?
        .expect("the offline suites drive complete commands, not `help`")
        .command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeScope;

    /// The grammar is built only once a session has attached, so a
    /// command that declares the same short flag twice would panic
    /// against a real core and nowhere else. clap's own check says so
    /// here instead.
    #[test]
    fn test_the_command_grammar_is_well_formed() {
        Line::command().debug_assert();
    }

    /// `info` takes nothing: it prints everything the target records,
    /// so there is no section to pick and no verbosity to raise.
    #[test]
    fn test_info_takes_no_arguments() {
        let Command::Info = Line::try_parse_from(["info"])
            .expect("bare info parses")
            .command
        else {
            panic!("info parsed as another command");
        };
        assert!(Line::try_parse_from(["info", "process"]).is_err());
        assert!(Line::try_parse_from(["info", "-v"]).is_err());
    }

    /// The census sections are flags rather than a value, so several of
    /// them can be asked for at once — including bundled behind one `-`.
    #[test]
    fn test_census_takes_several_sections_at_once() {
        let Command::Census {
            threads,
            tasks,
            futures,
            limit,
        } = Line::try_parse_from(["census", "-Tf", "--limit", "9"])
            .expect("census takes its section flags")
            .command
        else {
            panic!("census parsed as another command");
        };
        assert!(threads && futures && !tasks);
        assert_eq!(limit, 9);
    }

    /// Which command failed is framed only on a multi-command line; a
    /// single command's failure is already named by the line itself.
    #[test]
    fn test_only_multi_command_lines_frame_their_failures() {
        assert_eq!(command_frame(1, " tasks "), None);
        assert_eq!(command_frame(2, " tasks "), Some("in `tasks`".to_string()));
    }

    /// The split honors exactly one escape: `\;` is a literal `;` and
    /// never a separator, a bare `;` always is one, and every other
    /// backslash — mid-name, before another character, ending the
    /// line — passes through untouched.
    #[test]
    fn test_the_split_honors_the_escaped_separator() {
        assert_eq!(split_commands("tasks ; graph"), ["tasks ", " graph"]);
        assert_eq!(
            split_commands(r"type [usize\; 4]; graph"),
            ["type [usize; 4]", " graph"]
        );
        assert_eq!(split_commands(r"type [u8\; 2]"), ["type [u8; 2]"]);
        assert_eq!(split_commands(r"a \x b"), [r"a \x b"]);
        assert_eq!(split_commands(r"a \"), [r"a \"]);
        assert_eq!(split_commands("tasks"), ["tasks"]);
        assert_eq!(split_commands("a;;b"), ["a", "", "b"]);
    }

    /// A `;` inside double quotes is part of the word, quotes kept for
    /// the tokenizer; a single quote shelters nothing, since a type
    /// name holds one for a lifetime; an unclosed double quote runs to
    /// the end of the line.
    #[test]
    fn test_the_split_leaves_a_double_quoted_separator_alone() {
        assert_eq!(
            split_commands(r#"print 0x10 "[usize; 4]"; graph"#),
            [r#"print 0x10 "[usize; 4]""#, " graph"]
        );
        assert_eq!(
            split_commands(r#"print 0x10 "Foo<&'a [u8; 2]>" .x; tasks"#),
            [r#"print 0x10 "Foo<&'a [u8; 2]>" .x"#, " tasks"]
        );
        assert_eq!(split_commands("a '[u8; 2]'; b"), ["a '[u8", " 2]'", " b"]);
        assert_eq!(split_commands(r#"a "b; c"#), [r#"a "b; c"#]);
    }

    /// A shared sink that remembers what reached it, for standing in
    /// as a shell child's stdin.
    #[derive(Clone, Default)]
    struct Recorded(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    /// Accepts one byte per call, so the sink's hand-rolled loop has to
    /// advance through several partial writes.
    impl Write for Recorded {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            match buf.first() {
                Some(byte) => {
                    self.0.borrow_mut().push(*byte);
                    Ok(1)
                }
                None => Ok(0),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Dead;

    impl Write for Dead {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    /// The feed claims the whole buffer written and delivers all of it,
    /// through as many partial writes as the child takes — and stays
    /// open for the next buffer, which arrives whole too.
    #[test]
    fn test_the_feed_delivers_whole_buffers() {
        let child = Recorded::default();
        let mut sink = ShellSink {
            stdin: Some(Box::new(child.clone())),
        };
        assert_eq!(sink.write(b"abc").expect("the feed never errors"), 3);
        assert_eq!(sink.write(b"def").expect("the feed never errors"), 3);
        assert_eq!(*child.0.borrow(), b"abcdef");
    }

    /// A failing flush ends the feed the way a failing write does — and
    /// reports success, since a dead pipe is normal.
    #[test]
    fn test_a_failing_flush_ends_the_feed() {
        let mut sink = ShellSink {
            stdin: Some(Box::new(Dead)),
        };
        sink.flush().expect("the feed never errors");
        assert!(sink.stdin.is_none(), "a failed flush ends the feed");
    }

    /// What Tab offers for a line with the cursor at its end, as the
    /// replacement texts in menu order.
    fn completions(line: &str) -> Vec<String> {
        LineCompleter::new(Box::new(|_| Vec::new()))
            .suggest(line, line.len())
            .into_iter()
            .map(|s| s.value)
            .collect()
    }

    /// A completer over a target whose `tasks` rows hold two states
    /// and one lwp, counting how often it is asked.
    fn stateful_completer() -> (LineCompleter, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = asked.clone();
        let completer = LineCompleter::new(Box::new(move |ask: Ask| {
            let Ask::Values { command, field } = ask else {
                return Vec::new();
            };
            log.lock().unwrap().push(format!("{command} {field}"));
            let (values, pattern) = match (command.as_str(), field.as_str()) {
                ("tasks", "state") => (vec!["idle", "idle (cancelled)", "running"], true),
                ("tasks", "type") => (vec!["Vec<(u64, u64)>"], true),
                ("tasks", "lwp") => (vec!["7"], false),
                ("tasks", "id") => (vec!["129", "130", "2001"], false),
                ("threads", "lwp") => (vec!["1", "7", "12"], false),
                ("threads", "has-task") => (vec!["yes", "no"], false),
                _ => (Vec::new(), false),
            };
            values
                .into_iter()
                .map(|v| TargetValue {
                    spelled: v.to_string(),
                    insert: clause_spelling(v, pattern),
                })
                .collect()
        }));
        (completer, asked)
    }

    fn complete_with(completer: &mut LineCompleter, line: &str) -> Vec<String> {
        completer
            .suggest(line, line.len())
            .into_iter()
            .map(|s| s.value)
            .collect()
    }

    /// The second word of a `--with FIELD ARG` pair is what the target
    /// holds for FIELD, spelled for the line: a pattern field's values
    /// escaped and, holding a space, quoted; an exact field's as they
    /// are. A typed prefix is matched against the listing's spelling,
    /// not the escaped one.
    #[test]
    fn test_completion_offers_the_targets_values_for_a_filter() {
        let (mut c, _) = stateful_completer();
        assert_eq!(
            complete_with(&mut c, "tasks --with state "),
            ["idle", "\"idle \\(cancelled\\)\"", "running"]
        );
        assert_eq!(
            complete_with(&mut c, "tasks --without state ru"),
            ["running"]
        );
        // A comma in the value is escaped: ARG reads a bare one as
        // separating alternatives.
        assert_eq!(
            complete_with(&mut c, "tasks --with type Vec<("),
            ["\"Vec<\\(u64\\, u64\\)>\""]
        );
        assert_eq!(complete_with(&mut c, "tasks --with lwp "), ["7"]);
        assert_eq!(complete_with(&mut c, "threads --with has-task y"), ["yes"]);
        assert!(complete_with(&mut c, "tasks --with holds ").is_empty());
        // The pair complete, the flags come back, and `--group` takes
        // no second word.
        assert_eq!(
            complete_with(&mut c, "tasks --with state idle --gr"),
            ["--group"]
        );
        assert!(complete_with(&mut c, "tasks --group state ").is_empty());
    }

    /// A selector's argument is offered from the ids its listing
    /// holds: `task` the task ids, `thread` the lwps. `future` takes an
    /// address no listing field spells, so it offers nothing.
    #[test]
    fn test_completion_offers_the_targets_ids_to_a_selector() {
        let (mut c, _) = stateful_completer();
        assert_eq!(complete_with(&mut c, "task "), ["129", "130", "2001"]);
        assert_eq!(complete_with(&mut c, "task 1"), ["129", "130"]);
        assert_eq!(complete_with(&mut c, "thread "), ["1", "7", "12"]);
        assert_eq!(complete_with(&mut c, "thread 1"), ["1", "12"]);
        // The argument once typed, the word after it is a command.
        assert_eq!(
            complete_with(&mut c, "thread 7 "),
            complete_with(&mut c, "")
        );
        assert!(complete_with(&mut c, "future ").is_empty());
    }

    /// A clause argument completes at its last unescaped comma: the
    /// alternatives already typed stay, and the one under the cursor
    /// is offered from the field's values — quoted on its own where
    /// it needs to be, which the tokenizer joins to what precedes it.
    #[test]
    fn test_completion_continues_a_clauses_alternatives() {
        let (mut c, _) = stateful_completer();
        assert_eq!(
            complete_with(&mut c, "tasks --with state idle,ru"),
            ["idle,running"]
        );
        assert_eq!(
            complete_with(&mut c, "tasks --without state idle,"),
            ["idle,idle", "idle,\"idle \\(cancelled\\)\"", "idle,running"]
        );
        assert_eq!(
            complete_with(&mut c, "tasks --with state running,idle,ru"),
            ["running,idle,running"]
        );
        // An escaped comma is part of the alternative, so nothing
        // starts over after it.
        assert!(complete_with(&mut c, "tasks --with state a\\,ru").is_empty());
        assert_eq!(last_alternative("a,b"), 2);
        assert_eq!(last_alternative("a\\,b"), 0);
        assert_eq!(last_alternative("a\\\\,b"), 4);
        assert_eq!(last_alternative("abc"), 0);
        assert_eq!(last_alternative("a,"), 2);
    }

    /// Each (command, field) is asked of the target once; a second
    /// Tab, or a different prefix, reads the cached answer.
    #[test]
    fn test_completion_caches_the_targets_values_per_field() {
        let (mut c, asked) = stateful_completer();
        complete_with(&mut c, "tasks --with state ");
        complete_with(&mut c, "tasks --with state ru");
        complete_with(&mut c, "tasks --without state ");
        complete_with(&mut c, "tasks --with lwp ");
        complete_with(&mut c, "tasks --with state ");
        assert_eq!(*asked.lock().unwrap(), ["tasks state", "tasks lwp"]);
        // Field names and flags never ask.
        complete_with(&mut c, "tasks --with ");
        complete_with(&mut c, "tasks --group ");
        complete_with(&mut c, "tasks -");
        assert_eq!(asked.lock().unwrap().len(), 2);
    }

    /// A completer over a frame holding `foo: Foo { x: Bar { a, b }, y }`
    /// and `baz`, recording the arguments each question carries.
    fn frame_completer() -> (
        LineCompleter,
        std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>,
    ) {
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = asked.clone();
        let completer = LineCompleter::new(Box::new(move |ask: Ask| {
            let args = match ask {
                Ask::Members { args } => args,
                // The types recorded, spelled for the line.
                Ask::Types { prefix } => {
                    return [
                        "alloc::string::String",
                        "alloc::vec::Vec<(u64, u64)>",
                        "core::option::Option<&'static str>",
                        "[u8; 4]",
                    ]
                    .into_iter()
                    .filter(|n| n.starts_with(&prefix))
                    .map(|n| TargetValue {
                        spelled: n.to_string(),
                        insert: line_spelling(n, false),
                    })
                    .collect();
                }
                Ask::Values { .. } => return Vec::new(),
            };
            log.lock().unwrap().push(args.clone());
            // The path is the words joined, from the frame.
            let path: String = args.concat();
            let names: &[&str] = match path.trim_start_matches('.') {
                "" => &["baz", "foo"],
                "foo." => &["x", "y"],
                "foo.x." => &["a", "b"],
                _ => &[],
            };
            names
                .iter()
                .map(|n| TargetValue {
                    spelled: n.to_string(),
                    insert: n.to_string(),
                })
                .collect()
        }));
        (completer, asked)
    }

    /// An empty `print` offers the frame's locals, and a `.` what the
    /// path holds there, the steps so far kept and no space after: the
    /// locals, then each local's members, then theirs. A typed prefix
    /// narrows the names; a separate path word continues the path.
    #[test]
    fn test_completion_walks_a_print_path() {
        let (mut c, asked) = frame_completer();
        let suggest = |c: &mut LineCompleter, line: &str| -> Vec<(String, bool)> {
            c.suggest(line, line.len())
                .into_iter()
                .map(|s| (s.value, s.append_whitespace))
                .collect()
        };
        assert_eq!(
            suggest(&mut c, "print "),
            [("baz".to_string(), false), ("foo".to_string(), false)]
        );
        assert_eq!(complete_with(&mut c, "print f"), ["foo"]);
        assert_eq!(complete_with(&mut c, "print foo."), ["foo.x", "foo.y"]);
        assert_eq!(
            complete_with(&mut c, "print foo.x."),
            ["foo.x.a", "foo.x.b"]
        );
        assert_eq!(complete_with(&mut c, "print foo.x.b"), ["foo.x.b"]);
        assert_eq!(complete_with(&mut c, "print foo .x."), [".x.a", ".x.b"]);
        // The spelled-out `.` roots at the frame the same way.
        assert_eq!(complete_with(&mut c, "print ."), [".baz", ".foo"]);
        assert_eq!(complete_with(&mut c, "print .foo."), [".foo.x", ".foo.y"]);
        let asked = asked.lock().unwrap();
        // The local being typed asks with no path at all.
        assert!(asked.contains(&Vec::new()), "{asked:?}");
        // The step before the cursor's is sent as typed, the partial
        // name left off.
        assert!(
            asked.contains(&vec!["foo".to_string(), ".x.".to_string()]),
            "{asked:?}"
        );
    }

    /// Only a name completes: an index or a dereference under the
    /// cursor, or a later word with no `.`, asks nothing.
    #[test]
    fn test_completion_leaves_the_other_print_steps_alone() {
        let (mut c, asked) = frame_completer();
        assert!(complete_with(&mut c, "print foo[").is_empty());
        assert!(complete_with(&mut c, "print foo[0]").is_empty());
        assert!(complete_with(&mut c, "print foo*").is_empty());
        assert!(complete_with(&mut c, "print [").is_empty());
        assert!(complete_with(&mut c, "print foo [0").is_empty());
        assert!(complete_with(&mut c, "print foo bar").is_empty());
        assert!(asked.lock().unwrap().is_empty());
        // A member step after an index asks with the index kept.
        complete_with(&mut c, "print foo[0].");
        assert_eq!(*asked.lock().unwrap(), [vec!["foo[0].".to_string()]]);
        // Member names are not cached: the cursor may have moved.
        complete_with(&mut c, "print foo[0].");
        assert_eq!(asked.lock().unwrap().len(), 2);
    }

    /// After an address the word being typed is a type, offered from
    /// the recorded names with that prefix — a space after, and quoted
    /// where a space or a `;` would otherwise split it — and the steps
    /// behind the type ask the address's value what it holds. An
    /// address being typed is offered no local, since none starts
    /// with `0x`, and asks nothing else.
    #[test]
    fn test_completion_offers_types_after_an_address() {
        let (mut c, asked) = frame_completer();
        let suggest = |c: &mut LineCompleter, line: &str| -> Vec<(String, bool)> {
            c.suggest(line, line.len())
                .into_iter()
                .map(|s| (s.value, s.append_whitespace))
                .collect()
        };
        assert!(complete_with(&mut c, "print 0x").is_empty());
        assert_eq!(
            suggest(&mut c, "print 0x7f10 "),
            [
                ("alloc::string::String".to_string(), true),
                ("\"alloc::vec::Vec<(u64, u64)>\"".to_string(), true),
                ("\"core::option::Option<&'static str>\"".to_string(), true),
                ("\"[u8; 4]\"".to_string(), true),
            ]
        );
        assert_eq!(
            complete_with(&mut c, "print 0x7f10 alloc::"),
            ["alloc::string::String", "\"alloc::vec::Vec<(u64, u64)>\""]
        );
        assert_eq!(
            complete_with(&mut c, "print 0x7f10 core::o"),
            ["\"core::option::Option<&'static str>\""]
        );
        assert!(complete_with(&mut c, "print 0x7f10 std::").is_empty());
        // A later word with no `.` is no type: nothing is offered.
        assert!(complete_with(&mut c, "print 0x7f10 u64 foo").is_empty());
        // The steps ask with the address and type kept.
        complete_with(&mut c, "print 0x7f10 u64 .");
        complete_with(&mut c, "print 0x7f10 u64 .x.");
        assert_eq!(
            *asked.lock().unwrap(),
            [
                Vec::new(),
                vec!["0x7f10".to_string(), "u64".to_string(), ".".to_string()],
                vec!["0x7f10".to_string(), "u64".to_string(), ".x.".to_string()],
            ]
        );
    }

    /// A value goes back into the line escaped where the field would
    /// read it as a regex, and quoted where the tokenizer would split
    /// it; a plain word goes back as it is.
    #[test]
    fn test_line_spelling_escapes_patterns_and_quotes_spaces() {
        assert_eq!(line_spelling("idle", true), "idle");
        assert_eq!(
            line_spelling("Vec<(u64, u64)>", true),
            "\"Vec<\\(u64, u64\\)>\""
        );
        assert_eq!(
            line_spelling("dyn Future + Send", true),
            "\"dyn Future \\+ Send\""
        );
        assert_eq!(
            line_spelling("io 0xf9c3d00 (readable)", false),
            "\"io 0xf9c3d00 (readable)\""
        );
        assert_eq!(line_spelling("[u8;4]", false), "\"[u8;4]\"");
        assert_eq!(line_spelling("say \"hi\"", false), "'say \"hi\"'");
        assert_eq!(line_spelling("a\"b", false), "'a\"b'");
        assert_eq!(line_spelling("a'b", false), "\"a'b\"");
        assert_eq!(line_spelling("7", false), "7");
    }

    /// Over a fixture pair, each listing answers for its own fields —
    /// the states the tasks are in, the kinds of role the threads
    /// hold, the fixed kinds a future can be — spelled for the line,
    /// and nothing for a count field, an unknown field, or a command
    /// without a population.
    #[test]
    fn test_target_values_read_each_listings_rows() {
        use crate::offline::session_args;
        use hansei_runtime::testkit;
        let (bundle, snapshot) = testkit::load("illumos", "blocking-pool");
        let args = session_args("illumos", "blocking-pool");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let spelled = |command: &str, field: &str| -> Vec<(String, String)> {
            let ask = Ask::Values {
                command: command.to_string(),
                field: field.to_string(),
            };
            answer(&session, &ask)
                .into_iter()
                .map(|v| (v.spelled, v.insert))
                .collect()
        };
        let plain = |list: &[&str]| -> Vec<(String, String)> {
            list.iter()
                .map(|s| (s.to_string(), s.to_string()))
                .collect()
        };

        let states = spelled("tasks", "state");
        assert!(states.iter().any(|(s, _)| s == "idle"), "{states:?}");
        assert!(
            states.iter().any(|(s, _)| s.starts_with("blocking")),
            "{states:?}"
        );
        // A pattern field's value with a space goes back quoted and
        // escaped; the parenthesised lwp is the escaping's witness.
        let blocking = states
            .iter()
            .find(|(s, _)| s.starts_with("blocking"))
            .expect("a task is blocking");
        assert!(blocking.1.starts_with("\"blocking"), "{blocking:?}");
        assert!(blocking.1.contains("\\("), "{blocking:?}");
        assert_eq!(
            spelled("threads", "role"),
            [
                (
                    "entered runtime".to_string(),
                    "\"entered runtime\"".to_string()
                ),
                ("worker".to_string(), "worker".to_string()),
            ]
        );
        assert_eq!(spelled("threads", "has-task"), plain(&["yes", "no"]));
        assert_eq!(spelled("threads", "task"), plain(&["3"]));
        assert_eq!(spelled("futures", "kind"), plain(&["held", "child"]));
        assert!(spelled("tasks", "holds").is_empty());
        assert!(spelled("tasks", "colour").is_empty());
        assert!(spelled("config", "key").is_empty());

        // A member question is `print`'s: nothing without a cursor,
        // what `print` itself would offer — as typed back — once a task
        // is selected, and nothing for a path that does not resolve.
        let members = |path: &str| -> Vec<String> {
            let ask = Ask::Members {
                args: vec![path.to_string()],
            };
            answer(&session, &ask)
                .into_iter()
                .map(|v| {
                    assert_eq!(v.spelled, v.insert);
                    v.spelled
                })
                .collect()
        };
        assert!(members(".").is_empty());
        let id = session.tasks.tasks[0]
            .task_id
            .expect("the fixture's tasks carry ids");
        crate::cursor::select_task(&session, crate::TraceTarget::Task(id)).expect("selects");
        assert_eq!(
            members("."),
            crate::print::path_members(&session, &[".".to_string()]).expect("the frame resolves")
        );
        assert!(members(".no_such.").is_empty());
    }

    /// Completion advertises what `help` lists: a hidden command —
    /// still parseable, still runnable — is offered by neither.
    #[test]
    fn test_completion_offers_only_the_help_listing() {
        let names = completions("");
        for visible in ["tasks", "trace", "print", "config"] {
            assert!(names.iter().any(|n| n == visible), "{names:?}");
        }
        for hidden in ["type", "find-types", "exit"] {
            assert!(!names.iter().any(|n| n == hidden), "{names:?}");
        }
        assert_eq!(completions("tas"), ["task", "tasks"]);
        assert_eq!(completions("cen"), ["census"]);
    }

    /// Tab opens the menu (or steps forward through it) and Shift+Tab
    /// steps back.
    #[test]
    fn test_tab_and_shift_tab_walk_the_completion_menu() {
        let mut kb = default_emacs_keybindings();
        bind_completion_menu(&mut kb);
        assert_eq!(
            kb.find_binding(KeyModifiers::NONE, KeyCode::Tab),
            Some(ReedlineEvent::UntilFound(vec![
                ReedlineEvent::Menu(COMPLETION_MENU.to_string()),
                ReedlineEvent::MenuNext,
            ]))
        );
        assert_eq!(
            kb.find_binding(KeyModifiers::SHIFT, KeyCode::BackTab),
            Some(ReedlineEvent::MenuPrevious)
        );
    }

    /// The word motions stop where readline's do: `M-b` from the end
    /// of `sled.time_deleted` lands on `time`, then on the `.`, then
    /// on `sled`; `M-f` walks the same stops forward; `M-d` cuts one
    /// such word and `C-w` cuts back to whitespace.
    #[test]
    fn test_word_motions_break_at_punctuation() {
        let mut kb = default_emacs_keybindings();
        bind_readline_words(&mut kb);
        let commands = |modifiers, key| -> Vec<EditCommand> {
            let mut event = kb.find_binding(modifiers, key).expect("bound");
            // A forward move first offers the history hint a word,
            // which no editor here has; the edit is the fallback.
            while let ReedlineEvent::UntilFound(events) = event {
                event = events.into_iter().last().expect("a fallback");
            }
            match event {
                ReedlineEvent::Edit(commands) => commands,
                other => panic!("{other:?} is not an edit"),
            }
        };
        let mut editor = Reedline::create();
        editor.run_edit_commands(&[EditCommand::InsertString(
            "print sled.time_deleted".to_string(),
        )]);
        let mut at = |modifiers, key| {
            editor.run_edit_commands(&commands(modifiers, key));
            editor.current_insertion_point()
        };
        let back = |at: &mut dyn FnMut(KeyModifiers, KeyCode) -> usize| {
            at(KeyModifiers::ALT, KeyCode::Char('b'))
        };
        assert_eq!(back(&mut at), "print sled.".len());
        assert_eq!(back(&mut at), "print sled".len());
        assert_eq!(back(&mut at), "print ".len());
        assert_eq!(back(&mut at), 0);
        let forward = |at: &mut dyn FnMut(KeyModifiers, KeyCode) -> usize| {
            at(KeyModifiers::ALT, KeyCode::Char('f'))
        };
        assert_eq!(forward(&mut at), "print".len());
        assert_eq!(forward(&mut at), "print sled".len());
        assert_eq!(forward(&mut at), "print sled.".len());
        assert_eq!(forward(&mut at), "print sled.time_deleted".len());
        // The arrow spellings are the same motions.
        assert_eq!(
            at(KeyModifiers::CONTROL, KeyCode::Left),
            "print sled.".len()
        );
        assert_eq!(at(KeyModifiers::ALT, KeyCode::Left), "print sled".len());
        assert_eq!(at(KeyModifiers::ALT, KeyCode::Right), "print sled.".len());
        assert_eq!(
            at(KeyModifiers::CONTROL, KeyCode::Right),
            "print sled.time_deleted".len()
        );

        // `M-d` after `print ` eats `sled` alone; `C-w` at the end eats
        // back to the space.
        editor.run_edit_commands(&[EditCommand::MoveToPosition {
            position: "print ".len(),
            select: false,
        }]);
        editor.run_edit_commands(&commands(KeyModifiers::ALT, KeyCode::Char('d')));
        assert_eq!(editor.current_buffer_contents(), "print .time_deleted");
        editor.run_edit_commands(&[EditCommand::MoveToEnd { select: false }]);
        editor.run_edit_commands(&commands(KeyModifiers::CONTROL, KeyCode::Char('w')));
        assert_eq!(editor.current_buffer_contents(), "print ");
        editor.run_edit_commands(&[EditCommand::InsertString("a.b".to_string())]);
        editor.run_edit_commands(&commands(KeyModifiers::ALT, KeyCode::Backspace));
        assert_eq!(editor.current_buffer_contents(), "print a.");
    }

    /// The suggestion replaces the word under the cursor and nothing
    /// before it, and closes with a space so the next word can start.
    #[test]
    fn test_completion_spans_the_word_under_the_cursor() {
        let line = "tasks --group wa";
        let suggestions = LineCompleter::new(Box::new(|_| Vec::new())).suggest(line, line.len());
        let waker = suggestions
            .iter()
            .find(|s| s.value == "waker")
            .expect("waker is a task field");
        assert_eq!(waker.span, Span::new(line.len() - 2, line.len()));
        assert!(waker.append_whitespace);
    }

    /// `--group`, `--with` and `--without` take a field name, and the
    /// two commands have different fields: a task has an id and a
    /// waker, a future a kind and a local.
    #[test]
    fn test_completion_offers_field_names_to_the_filters() {
        let tasks: Vec<String> = crate::tasks::Field::names().map(String::from).collect();
        let futures: Vec<String> = crate::futures::Field::names().map(String::from).collect();
        assert_eq!(completions("tasks --group "), tasks);
        assert_eq!(completions("tasks --with "), tasks);
        assert_eq!(completions("tasks --without "), tasks);
        assert_eq!(completions("futures --group "), futures);
        assert_eq!(completions("futures --with "), futures);
        let threads: Vec<String> = crate::threads::Field::names().map(String::from).collect();
        assert_eq!(completions("threads --group "), threads);
        assert_eq!(completions("threads --without "), threads);
        let runtimes: Vec<String> = crate::runtimes::Field::names().map(String::from).collect();
        assert_eq!(completions("runtimes --group "), runtimes);
        assert_eq!(completions("runtimes --with "), runtimes);
        assert_eq!(
            completions("runtimes -w f"),
            ["flavor", "futures", "found-via"]
        );
        assert_eq!(completions("tasks --group wa"), ["waiting-on", "waker"]);
        assert_eq!(completions("futures --with k"), ["kind"]);
        assert_eq!(completions("threads --with has"), ["has-task"]);
        // The short spellings reach the same fields.
        assert_eq!(completions("tasks -g "), tasks);
        assert_eq!(completions("tasks -w "), tasks);
        assert_eq!(completions("futures -W "), futures);
        assert_eq!(completions("threads -w has"), ["has-task"]);
        assert!(tasks.contains(&"id".to_string()) && !futures.contains(&"id".to_string()));
    }

    /// The second word of a `--with FIELD ARG` pair is the user's
    /// pattern, so nothing is offered for it; once the pair is complete
    /// the flags come back.
    #[test]
    fn test_completion_leaves_the_filter_argument_free() {
        assert!(completions("tasks --with type ").is_empty());
        assert!(completions("tasks --with type Ve").is_empty());
        assert_eq!(completions("tasks --with type foo --gr"), ["--group"]);
        assert_eq!(
            completions("tasks --with type foo --with "),
            completions("tasks --with ")
        );
    }

    /// A dash starts a flag: the command's long flags are offered, the
    /// hidden ones and the positionals left out.
    #[test]
    fn test_completion_offers_a_commands_flags() {
        let flags = completions("tasks -");
        for expected in ["--group", "--with", "--without", "--limit", "--exec"] {
            assert!(flags.iter().any(|f| f == expected), "{flags:?}");
        }
        assert!(flags.iter().all(|f| f.starts_with("--")), "{flags:?}");
        assert_eq!(completions("tasks --gr"), ["--group"]);
        assert_eq!(completions("task 129 -"), completions("task -"));
        assert_eq!(completions("task --fu"), ["--futures"]);
    }

    /// A short flag that takes a value owes it as the next word (`-l
    /// 10`) unless the value rides in the same word (`-l10`); either
    /// way the walk lands on the right side of it.
    #[test]
    fn test_completion_follows_short_flags_that_take_values() {
        assert!(completions("tasks -l ").is_empty());
        assert_eq!(completions("tasks -l 10 --gr"), ["--group"]);
        assert_eq!(completions("tasks -l10 --gr"), ["--group"]);
        assert_eq!(completions("trace -vl 3 --na"), ["--native"]);
        assert_eq!(completions("tasks --limit=10 --gr"), ["--group"]);
        assert!(completions("tasks -w type ").is_empty());
        assert_eq!(completions("tasks -w type foo --gr"), ["--group"]);
    }

    /// A `ValueEnum` argument offers its declared values, with the
    /// declared help beside each.
    #[test]
    fn test_completion_offers_declared_value_enums() {
        assert_eq!(completions("sync --kind se"), ["semaphore", "set"]);
        let line = "sync --kind sem";
        let semaphore = LineCompleter::new(Box::new(|_| Vec::new()))
            .suggest(line, line.len())
            .remove(0);
        assert!(
            semaphore
                .description
                .as_deref()
                .is_some_and(|d| d.starts_with("Contended semaphores")),
            "{semaphore:?}"
        );
    }

    /// `config` offers its keys, then the word values the named key
    /// takes; a key that takes only a count offers nothing.
    #[test]
    fn test_completion_offers_config_keys_and_word_values() {
        assert_eq!(completions("config "), crate::settings::KEYS);
        assert_eq!(
            completions("config max-"),
            ["max-array-values", "max-string-len"]
        );
        assert_eq!(completions("config ugly "), ["on", "off"]);
        assert_eq!(completions("config limit "), ["off"]);
        assert!(completions("config depth ").is_empty());
        assert!(completions("config ugly on ").is_empty());
    }

    /// A scope prefix is peeled as `execute_one` peels it: what follows
    /// `task 129` is a fresh command line, an abbreviated command word
    /// resolves by the grammar's unique-prefix rule, and a word that
    /// names no command completes to nothing.
    #[test]
    fn test_completion_sees_through_a_scope_and_an_abbreviation() {
        assert_eq!(completions("task 129 futu"), ["future", "futures"]);
        assert_eq!(
            completions("task 129 tasks --group "),
            completions("tasks --group ")
        );
        assert_eq!(
            completions("future 0x10 tasks --group "),
            completions("tasks --group ")
        );
        assert_eq!(completions("cen --"), completions("census --"));
        assert!(!completions("census --").is_empty());
        assert!(completions("nosuch --").is_empty());
        assert!(
            completions("futu --").is_empty(),
            "`futu` names future and futures"
        );
    }

    /// Nothing is offered on the shell's side of a `!`, inside an
    /// unclosed quote, or on a word a quote touched; a closed quote
    /// earlier in the line is one word like any other.
    #[test]
    fn test_completion_declines_where_the_grammar_is_not_its_own() {
        assert!(completions("tasks ! gr").is_empty());
        assert!(completions("print \"Vec<(u64").is_empty());
        assert!(completions("print \"Vec<(u64, u64)>\"").is_empty());
        assert_eq!(
            completions("print 0x1 \"Vec<(u64, u64)>\" --"),
            completions("print 0x1 T --")
        );
    }

    /// A grammar with the shapes hansei's own lacks — a short flag with
    /// declared values, a two-value option whose second slot has
    /// values, a trailing many-valued positional, a hidden option, and
    /// a command that is an exact name and another's prefix at once —
    /// so the walk is pinned on every branch and not only the ones
    /// today's commands reach.
    fn toy_grammar() -> clap::Command {
        use clap::{Arg, ArgAction, Command};
        let mut root = Command::new("")
            .no_binary_name(true)
            .disable_help_flag(true)
            .subcommand(
                Command::new("paint")
                    .arg(
                        Arg::new("color")
                            .long("color")
                            .short('c')
                            .value_parser(["red", "green"]),
                    )
                    .arg(
                        Arg::new("pair")
                            .long("pair")
                            .num_args(2)
                            .value_parser(["a", "b"]),
                    )
                    .arg(
                        Arg::new("verbose")
                            .long("verbose")
                            .short('v')
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("secret")
                            .long("secret")
                            .hide(true)
                            .action(ArgAction::SetTrue),
                    )
                    .arg(Arg::new("shape").value_parser(["circle", "square"]))
                    .arg(
                        Arg::new("sizes")
                            .num_args(1..)
                            .value_parser(["s", "m", "l"]),
                    ),
            )
            .subcommand(
                Command::new("pain").arg(Arg::new("dull").long("dull").action(ArgAction::SetTrue)),
            );
        root.build();
        root
    }

    /// What Tab offers on the toy grammar for a line ending at the
    /// cursor.
    fn toy(line: &str) -> Vec<String> {
        let (words, current, _) = words_before(line).expect("the toy lines are plain words");
        candidates(&toy_grammar(), &words, &current, &mut |_| Vec::new())
            .into_iter()
            .filter(|c| c.spelled.starts_with(&current))
            .map(|c| c.insert)
            .collect()
    }

    /// An option owed values gets them until its count is met — one
    /// for `--color`, two for `--pair` — and then the walk moves on to
    /// the positionals. A value given inline (`--color=red`) is
    /// already counted.
    #[test]
    fn test_toy_completion_counts_an_options_values() {
        assert_eq!(toy("paint --color "), ["red", "green"]);
        assert_eq!(toy("paint --color red "), ["circle", "square"]);
        assert_eq!(toy("paint --color=red "), ["circle", "square"]);
        assert_eq!(toy("paint --pair a "), ["a", "b"]);
        assert_eq!(toy("paint --pair a b "), ["circle", "square"]);
        assert_eq!(toy("paint --verbose "), ["circle", "square"]);
        assert_eq!(
            toy("paint --pair a --color "),
            ["red", "green"],
            "a flag ends the pair"
        );
    }

    /// A short flag that takes a value owes it as the next word or
    /// takes the rest of its own; a cluster's earlier shorts are
    /// flags in passing. A lone `-` is a value, not a flag.
    #[test]
    fn test_toy_completion_reads_short_flags() {
        assert_eq!(toy("paint -c "), ["red", "green"]);
        assert_eq!(toy("paint -cred "), ["circle", "square"]);
        assert_eq!(toy("paint -vc "), ["red", "green"]);
        assert_eq!(toy("paint -v "), ["circle", "square"]);
        assert_eq!(toy("paint - "), ["s", "m", "l"], "`-` filled the shape");
        assert_eq!(toy("paint --color - "), ["circle", "square"]);
    }

    /// Positionals go by index, and past the last one the trailing
    /// many-valued positional keeps taking words.
    #[test]
    fn test_toy_completion_follows_positionals() {
        assert_eq!(toy("paint "), ["circle", "square"]);
        assert_eq!(toy("paint circle "), ["s", "m", "l"]);
        assert_eq!(toy("paint circle s m "), ["s", "m", "l"]);
        assert_eq!(toy("paint circle s --"), ["--color", "--pair", "--verbose"]);
    }

    /// A dash under the cursor offers the long flags, the hidden one
    /// left out — whether or not an option is still owed a value.
    #[test]
    fn test_toy_completion_offers_visible_long_flags() {
        assert_eq!(toy("paint -"), ["--color", "--pair", "--verbose"]);
        assert_eq!(toy("paint --color -"), ["--color", "--pair", "--verbose"]);
        assert_eq!(toy("paint --p"), ["--pair"]);
    }

    /// An exact command name wins even when it is another's prefix;
    /// a prefix of two commands names neither.
    #[test]
    fn test_toy_completion_resolves_the_command_word_exactly_first() {
        assert_eq!(toy("pain -"), ["--dull"]);
        assert_eq!(toy("paint -"), ["--color", "--pair", "--verbose"]);
        assert!(toy("pai -").is_empty());
        assert_eq!(toy("pai"), ["paint", "pain"]);
    }

    /// Bare `help` files every command clap would list under exactly
    /// one section, and files nothing clap would not list: a new
    /// command fails here until it is filed, a hidden or renamed one
    /// until it is unfiled. The listing itself heads each section and
    /// pads every name to one column.
    #[test]
    fn test_help_sections_file_every_visible_command_once() {
        let mut root = Line::command();
        root.build();
        let visible: Vec<&str> = root
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .map(|c| c.get_name())
            .collect();
        let filed: Vec<&str> = HELP_SECTIONS
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        for name in &visible {
            let times = filed.iter().filter(|n| n == &name).count();
            assert_eq!(times, 1, "{name} is filed {times} times");
        }
        for name in &filed {
            assert!(
                visible.contains(name),
                "{name} is filed but not a listed command"
            );
        }

        let listing = help_listing(&Theme::plain());
        assert!(
            listing.starts_with("Commands a hansei session accepts.\n\n"),
            "{listing}"
        );
        for (heading, _) in HELP_SECTIONS {
            assert!(listing.contains(&format!("\n{heading}:\n  ")), "{listing}");
        }
        assert!(
            listing.contains("\n  frame            Move the cursor"),
            "{listing}"
        );
        assert!(listing.contains("\n  save-tokio-info  Write"), "{listing}");
        assert!(
            listing.contains("\n  quit             Leave the session\n"),
            "{listing}"
        );
        for line in listing.lines() {
            assert!(line.chars().count() <= HELP_WIDTH, "{line}");
        }
    }

    /// Words flow greedily, break at spaces, and a word wider than the
    /// line stands alone rather than being cut.
    #[test]
    fn test_wrap_words_flows_and_breaks_at_spaces() {
        assert_eq!(wrap_words("", 10), [""]);
        assert_eq!(wrap_words("foo bar baz", 10), ["foo bar", "baz"]);
        assert_eq!(wrap_words("foo bar baz", 5), ["foo", "bar", "baz"]);
        assert_eq!(
            wrap_words("a verylongword b", 6),
            ["a", "verylongword", "b"]
        );
    }

    /// `help` is a successful command that clap renders as an error;
    /// a real parse failure is one, with clap's prefix stripped since
    /// the caller frames it.
    #[test]
    fn test_help_is_answered_and_nonsense_is_refused() {
        assert!(matches!(parse_command("help"), Ok(None)));
        assert!(matches!(parse_command("hel"), Ok(None)));
        assert!(matches!(parse_command("help tasks"), Ok(None)));
        assert!(matches!(parse_command("tasks"), Ok(Some(_))));
        let Err(err) = parse_command("no-such-command") else {
            panic!("nonsense parsed as a command");
        };
        assert!(!err.to_string().starts_with("error: "), "{err}");
    }

    /// The history lives beside the home directory; a session without
    /// one simply has no history rather than a made-up path.
    #[test]
    fn test_history_lives_under_home() {
        // HOME is set wherever tests run; the path is derived from it.
        let path = history_path().expect("HOME is set in a test environment");
        assert!(path.ends_with(".hansei_history"), "{path:?}");
        assert!(path.parent().is_some(), "{path:?}");
    }

    /// A write failure quietly ends the feed: the rest of the answer is
    /// swallowed, and the command producing it never sees an error.
    #[test]
    fn test_a_dead_pipe_swallows_the_rest() {
        let mut sink = ShellSink {
            stdin: Some(Box::new(Dead)),
        };
        assert_eq!(sink.write(b"abc").expect("the feed never errors"), 3);
        assert!(sink.stdin.is_none(), "the first failure ends the feed");
        assert_eq!(sink.write(b"more").expect("the feed never errors"), 4);
    }

    /// `type`'s name is the rest of the line the way `print`'s is: the
    /// words are joined back into one name, so a name whose generic
    /// arguments hold spaces pastes in whole, with the flags still
    /// parsed out from among them.
    #[test]
    fn test_type_takes_the_rest_of_the_line_as_one_name() {
        let Command::Type {
            name,
            recursive,
            depth,
        } = Line::try_parse_from(["type", "Vec<(u64,", "u64)>", "-r", "-d", "2"])
            .expect("type takes a name and its flags")
            .command
        else {
            panic!("type parsed as another command");
        };
        assert_eq!(name.join(" "), "Vec<(u64, u64)>");
        assert!(recursive);
        assert_eq!(depth, 2);
    }

    /// `print`'s positionals are a local plus path tokens, split
    /// apart by the command itself — clap only collects them — and
    /// nothing else — the retired render flags are refused.
    #[test]
    fn test_print_collects_local_and_path_tokens() {
        let Command::Print { args } = Line::try_parse_from(["print", "values[..10]", ".a"])
            .expect("print takes a local and path tokens")
            .command
        else {
            panic!("print parsed as another command");
        };
        assert_eq!(args, ["values[..10]", ".a"]);
        assert!(Line::try_parse_from(["print", "values", "-u"]).is_err());

        // Bare `print` is the cursor frame: nothing is required.
        let Command::Print { args, .. } = Line::try_parse_from(["print"])
            .expect("bare print parses")
            .command
        else {
            panic!("print parsed as another command");
        };
        assert!(args.is_empty());
    }

    /// `runtime` is pointed at one runtime, named by its index in the
    /// listing or by the handle address printed beside it, and the
    /// two spellings cannot be confused for one another. Naming none
    /// parses too: the dispatch answers with the one runtime, or
    /// refuses.
    #[test]
    fn test_runtime_is_pointed_at_the_runtime_named() {
        let scope = |line: &[&str]| {
            let Command::Runtime { scope } = Line::try_parse_from(line)
                .expect("runtime takes a scope")
                .command
            else {
                panic!("runtime parsed as another command");
            };
            scope
        };
        assert_eq!(
            scope(&["runtime", "0x7f11c0"]),
            Some(RuntimeScope::Handle(0x7f11c0))
        );
        // A label spells the handle `@ 0x…`, so the address still works
        // with the `@` stuck to it.
        assert_eq!(
            scope(&["runtime", "@0x7f11c0"]),
            Some(RuntimeScope::Handle(0x7f11c0))
        );
        assert_eq!(scope(&["runtime", "2"]), Some(RuntimeScope::Index(2)));
        assert_eq!(scope(&["runtime"]), None);

        // An address without its prefix would be an index; one that is
        // neither is refused rather than guessed at, as is an `@` on
        // anything but an address. One runtime at a time: the block
        // form is one runtime's.
        assert!(Line::try_parse_from(["runtime", "7f11c0"]).is_err());
        assert!(Line::try_parse_from(["runtime", "@2"]).is_err());
        assert!(Line::try_parse_from(["runtime", "0", "1"]).is_err());
        // The old section flags are gone: the block is the whole
        // runtime.
        assert!(Line::try_parse_from(["runtime", "-D"]).is_err());
        assert!(Line::try_parse_from(["runtime", "--shared"]).is_err());
    }

    /// `runtimes` is the listing: it takes the filter grammar and no
    /// section flags, and a runtime named to it parses only so the
    /// dispatch can refuse it with the `runtime N` spelling.
    #[test]
    fn test_runtimes_takes_the_filter_grammar() {
        let Command::Runtimes {
            scope,
            with,
            without,
            group,
        } = Line::try_parse_from(["runtimes", "--with", "threads", ">0", "-g", "flavor"])
            .expect("runtimes takes the filter grammar")
            .command
        else {
            panic!("runtimes parsed as another command");
        };
        assert!(scope.is_empty());
        assert_eq!(with, ["threads", ">0"]);
        assert!(without.is_empty());
        assert_eq!(group.as_deref(), Some("flavor"));

        let Command::Runtimes { scope, .. } = Line::try_parse_from(["runtimes", "0"])
            .expect("a named runtime parses, to be refused by name")
            .command
        else {
            panic!("runtimes parsed as another command");
        };
        assert_eq!(scope, ["0"]);
        assert!(Line::try_parse_from(["runtimes", "--list"]).is_err());
        assert!(Line::try_parse_from(["runtimes", "-D"]).is_err());
        assert!(Line::try_parse_from(["runtimes", "-s"]).is_err());
        assert!(Line::try_parse_from(["runtimes", "--exec", "runtime"]).is_err());
    }

    /// The filter grammar: `--with`/`--without` take FIELD ARG pairs,
    /// repeatable, and `--group` one field; a field with no argument
    /// is refused by the grammar itself, so no clause parses by half.
    #[test]
    fn test_tasks_takes_filter_clauses_in_pairs() {
        let Command::Tasks {
            with,
            without,
            group,
            task,
            ..
        } = Line::try_parse_from([
            "tasks",
            "--with",
            "state",
            "idle",
            "--with",
            "waiting-on",
            "^timer",
            "--without",
            "type",
            "qorb",
            "--group",
            "state",
        ])
        .expect("the filter grammar parses")
        .command
        else {
            panic!("tasks parsed as another command");
        };
        assert_eq!(with, ["state", "idle", "waiting-on", "^timer"]);
        assert_eq!(without, ["type", "qorb"]);
        assert_eq!(group.as_deref(), Some("state"));
        assert!(task.is_empty());
        assert!(Line::try_parse_from(["tasks", "--with", "state"]).is_err());
        assert!(Line::try_parse_from(["tasks", "--group"]).is_err());

        // The short spellings: `-w`/`-W` for the pairs, `-g` for the
        // field, on every listing command.
        for listing in ["tasks", "futures", "threads", "runtimes"] {
            let words = [listing, "-w", "a", "b", "-W", "c", "d", "-g", "e"];
            let line = Line::try_parse_from(words).expect("the short filter spellings parse");
            let (with, without, group) = match line.command {
                Command::Tasks {
                    with,
                    without,
                    group,
                    ..
                }
                | Command::Futures {
                    with,
                    without,
                    group,
                    ..
                }
                | Command::Threads {
                    with,
                    without,
                    group,
                    ..
                }
                | Command::Runtimes {
                    with,
                    without,
                    group,
                    ..
                } => (with, without, group),
                _ => panic!("{listing} parsed as another command"),
            };
            assert_eq!(with, ["a", "b"]);
            assert_eq!(without, ["c", "d"]);
            assert_eq!(group.as_deref(), Some("e"));
        }
    }

    /// `--exec` takes the rest of the line as one command, flags and
    /// all, and refuses to share the line with `--group`.
    #[test]
    fn test_tasks_exec_takes_the_rest_of_the_line() {
        let Command::Tasks { exec, with, .. } =
            Line::try_parse_from(["tasks", "--with", "state", "idle", "--exec", "trace", "-v"])
                .expect("the exec grammar parses")
                .command
        else {
            panic!("tasks parsed as another command");
        };
        assert_eq!(with, ["state", "idle"]);
        assert_eq!(exec, ["trace", "-v"]);
        assert!(Line::try_parse_from(["tasks", "--group", "state", "--exec", "trace"]).is_err());
        assert!(Line::try_parse_from(["tasks", "--exec"]).is_err());
        // `-e` is the same flag, on every listing command.
        for listing in ["tasks", "futures", "threads"] {
            let line = Line::try_parse_from([listing, "-e", "trace", "-l", "3"])
                .expect("the short exec spelling parses");
            let exec = match line.command {
                Command::Tasks { exec, .. }
                | Command::Futures { exec, .. }
                | Command::Threads { exec, .. } => exec,
                _ => panic!("{listing} parsed as another command"),
            };
            assert_eq!(exec, ["trace", "-l", "3"]);
            assert!(Line::try_parse_from([listing, "-g", "state", "-e", "trace"]).is_err());
        }
    }

    /// A bare `trace` parses without a target: the refusal is the
    /// dispatch's, where an `--exec` scope can fill the target first.
    #[test]
    fn test_trace_target_is_optional_in_the_grammar() {
        let Command::Trace { target, .. } = Line::try_parse_from(["trace"])
            .expect("a bare trace parses")
            .command
        else {
            panic!("trace parsed as another command");
        };
        assert!(target.is_none());
    }

    /// A positional id still parses — the refusal that teaches the
    /// filter spelling is the command's own, not clap's bare
    /// "unexpected argument".
    #[test]
    fn test_tasks_still_carries_a_positional_to_refuse() {
        let Command::Tasks { task, .. } = Line::try_parse_from(["tasks", "129"])
            .expect("a positional reaches the command's refusal")
            .command
        else {
            panic!("tasks parsed as another command");
        };
        assert_eq!(task, ["129"]);
    }

    /// A scoped prefix is a selector, its argument, and a command to
    /// run: a bare selector, a selector followed only by flags, and a
    /// non-selector all stay whole, and an argument the selector
    /// would not parse is left for clap's own refusal.
    #[test]
    fn test_a_scope_peels_only_a_selector_with_a_command() {
        let w = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();

        let words = w("task 129 trace -v");
        let (scope, rest) = peel_scope(&words).expect("a task scope peels");
        assert!(matches!(scope, Scope::Task(crate::TraceTarget::Task(129))));
        assert_eq!(rest, ["trace", "-v"]);

        let words = w("task 0x20 whatis");
        assert!(matches!(
            peel_scope(&words),
            Some((Scope::Task(crate::TraceTarget::Future(0x20)), _))
        ));
        let words = w("future 0x10 trace");
        assert!(matches!(peel_scope(&words), Some((Scope::Future(0x10), _))));
        let words = w("thread 3 print self");
        assert!(matches!(peel_scope(&words), Some((Scope::Thread(3), _))));

        assert!(peel_scope(&w("task 129")).is_none());
        assert!(peel_scope(&w("task 129 -v")).is_none());
        assert!(peel_scope(&w("tasks 129 trace")).is_none());
        assert!(peel_scope(&w("task nonsense trace")).is_none());
        assert!(peel_scope(&w("thread 0x10 trace")).is_none());
        assert!(peel_scope(&w("trace 129 x")).is_none());
    }

    /// Quotes join one word and drop themselves; backslash is a
    /// literal everywhere, so a typed regex escape survives the split.
    #[test]
    fn test_split_tokens_quotes_join_and_backslash_is_literal() {
        let split = |line| split_tokens(line).expect("splits");
        assert_eq!(
            split(r#"whatis 0x1 "Vec<(u64, u64)>" .a"#),
            ["whatis", "0x1", "Vec<(u64, u64)>", ".a"]
        );
        assert_eq!(
            split("tasks --with type 'a b' --limit 3"),
            ["tasks", "--with", "type", "a b", "--limit", "3"]
        );
        // Backslash passes through untouched, quoted or not.
        assert_eq!(split(r"find-types foo\.bar"), ["find-types", r"foo\.bar"]);
        assert_eq!(split(r#"type "a\.b""#), ["type", r"a\.b"]);
        // A quoted stretch glues to the characters beside it, and an
        // empty pair stands as an empty word.
        assert_eq!(split(r#"type Vec<"a b">"#), ["type", "Vec<a b>"]);
        assert_eq!(split(r#"type """#), ["type", ""]);
        // The other quote kind is an ordinary character inside.
        assert_eq!(split(r#"type "it's""#), ["type", "it's"]);
        assert_eq!(split(""), Vec::<String>::new());
    }

    /// An unclosed quote is refused, naming the quote kind.
    #[test]
    fn test_split_tokens_refuses_an_unclosed_quote() {
        let err = split_tokens(r#"type "Vec<"#).unwrap_err();
        assert_eq!(err.to_string(), "unclosed \" quote");
        let err = split_tokens("type 'Vec<").unwrap_err();
        assert_eq!(err.to_string(), "unclosed ' quote");
    }

    /// A quoted `--exec` command lands as one word holding whitespace
    /// and is re-split before parsing; an already-split command is
    /// taken as it stands.
    #[test]
    fn test_exec_command_resplits_a_quoted_word() {
        let w = |words: &[&str]| words.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(matches!(
            parse_exec_command(&w(&["trace -v"])).expect("resplits"),
            Command::Trace { .. }
        ));
        assert!(matches!(
            parse_exec_command(&w(&["trace", "-v"])).expect("parses"),
            Command::Trace { .. }
        ));
        // A single word without whitespace is not re-split — quote
        // characters inside one are somebody's name, not grouping.
        assert!(matches!(
            parse_exec_command(&w(&["census"])).expect("parses"),
            Command::Census { .. }
        ));
        assert!(parse_exec_command(&w(&["cen\"sus\""])).is_err());
    }

    /// `--exec` takes the rest of the line, so a listing flag typed
    /// after it is refused with the rule rather than the exec
    /// command's bare "unexpected argument" — whether the command was
    /// quoted, so the flag follows the whitespace-holding word, or
    /// split, so the flag sits among the command's own words.
    #[test]
    fn test_exec_command_refuses_a_listing_flag_after_it() {
        let w = |words: &[&str]| words.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let refusal = |words: &[&str]| match parse_exec_command(&w(words)) {
            Ok(_) => panic!("{words:?} parsed"),
            Err(e) => e.to_string(),
        };
        let err = refusal(&["trace -l 3", "--with", "state", "running"]);
        assert!(err.starts_with("--exec must be the last flag"), "{err}");
        assert!(
            err.contains("`--with state running` follows the quoted command"),
            "{err}"
        );

        let err = refusal(&["trace", "-l", "3", "--with", "state", "running"]);
        assert!(err.contains("unexpected argument '--with'"), "{err}");
        assert!(
            err.contains("--exec must be the last flag: `--with`"),
            "{err}"
        );

        // An exec command's own failure carries no such note.
        let err = refusal(&["trace", "--bogus"]);
        assert!(!err.contains("must be the last flag"), "{err}");
    }

    /// `$_` substitutes only where it stands as a whole word, spells
    /// the address the way every command reads one back, and refuses
    /// when no cursor stands.
    #[test]
    fn test_last_addr_substitutes_whole_tokens_only() {
        let w = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert_eq!(
            substitute_last_addr(&w("whatis $_"), Some(0x1f)).expect("$_ resolves"),
            ["whatis", "0x1f"]
        );
        // An embedded `$_` is somebody's name, not the cursor.
        assert_eq!(
            substitute_last_addr(&w("type a$_b"), Some(0x1f)).expect("names pass through"),
            ["type", "a$_b"]
        );
        // No `$_` on the line: the cursor's absence costs nothing.
        assert_eq!(
            substitute_last_addr(&w("tasks"), None).expect("no reference, no refusal"),
            ["tasks"]
        );
        let err = substitute_last_addr(&w("whatis $_"), None).unwrap_err();
        assert!(err.to_string().contains("no cursor"), "{err}");
    }

    /// The singular selectors are exact spellings beside their
    /// plurals: `task 5` selects, `tasks` lists — clap's inference
    /// must not swallow one into the other — and the movement
    /// commands parse bare.
    #[test]
    fn test_the_selectors_stand_beside_their_plurals() {
        assert!(matches!(
            Line::try_parse_from(["task", "5"])
                .expect("task selects")
                .command,
            Command::Task {
                target: Some(crate::TraceTarget::Task(5)),
                futures: false
            }
        ));
        assert!(matches!(
            Line::try_parse_from(["task", "0x1f"])
                .expect("an address selects")
                .command,
            Command::Task {
                target: Some(crate::TraceTarget::Future(0x1f)),
                ..
            }
        ));
        assert!(matches!(
            Line::try_parse_from(["tasks"])
                .expect("tasks lists")
                .command,
            Command::Tasks { .. }
        ));
        assert!(matches!(
            Line::try_parse_from(["futures", "--with", "kind", "child"])
                .expect("futures lists")
                .command,
            Command::Futures { .. }
        ));
        assert!(matches!(
            Line::try_parse_from(["thread", "3"])
                .expect("thread selects")
                .command,
            Command::Thread { lwp: Some(3) }
        ));
        assert!(matches!(
            Line::try_parse_from(["threads"])
                .expect("threads lists")
                .command,
            Command::Threads { .. }
        ));
        assert!(matches!(
            Line::try_parse_from(["future", "0x10"])
                .expect("future selects")
                .command,
            Command::Future {
                addr: Some(0x10),
                verbose: false
            }
        ));
        assert!(matches!(
            Line::try_parse_from(["frame", "2"])
                .expect("frame moves")
                .command,
            Command::Frame {
                index: Some(2),
                then
            } if then.is_empty()
        ));
        assert!(matches!(
            Line::try_parse_from(["frame"])
                .expect("bare frame prints")
                .command,
            Command::Frame { index: None, then } if then.is_empty()
        ));
        let Command::Frame { index, then } = Line::try_parse_from(["frame", "7", "print", "self"])
            .expect("frame carries a trailing command")
            .command
        else {
            panic!("frame parses");
        };
        assert_eq!(index, Some(7));
        assert_eq!(then, ["print", "self"]);
        assert!(matches!(
            Line::try_parse_from(["up"]).expect("up parses").command,
            Command::Up { then } if then.is_empty()
        ));
        assert!(matches!(
            Line::try_parse_from(["down"]).expect("down parses").command,
            Command::Down { then } if then.is_empty()
        ));
        // A frame move carries the rest of the line as the command to
        // run after it, flags and all.
        let Command::Down { then } = Line::try_parse_from(["down", "locals"])
            .expect("down carries a trailing command")
            .command
        else {
            panic!("down parses");
        };
        assert_eq!(then, ["locals"]);
        let Command::Up { then } = Line::try_parse_from(["up", "trace", "-n"])
            .expect("the trailing command keeps its own flags")
            .command
        else {
            panic!("up parses");
        };
        assert_eq!(then, ["trace", "-n"]);
        assert!(matches!(
            Line::try_parse_from(["locals"])
                .expect("locals parses")
                .command,
            Command::Locals
        ));
        assert!(matches!(
            Line::try_parse_from(["regs"]).expect("regs parses").command,
            Command::Regs
        ));
        // `whatis` still takes an address, and now none at all.
        assert!(matches!(
            Line::try_parse_from(["whatis"])
                .expect("bare whatis parses")
                .command,
            Command::Whatis { addr: None }
        ));
    }

    /// `config` takes a key alone, a key and a value, or nothing — and
    /// the values are plain words, so `config limit off` parses whole.
    /// The old `set` spelling no longer parses.
    #[test]
    fn test_config_takes_a_key_and_value_or_less() {
        let parse = |line: &[&str]| {
            let Command::Config { key, value } =
                Line::try_parse_from(line).expect("config parses").command
            else {
                panic!("config parsed as another command");
            };
            (key, value)
        };
        assert_eq!(parse(&["config"]), (None, None));
        assert_eq!(
            parse(&["config", "depth"]),
            (Some("depth".to_string()), None)
        );
        assert_eq!(
            parse(&["config", "limit", "off"]),
            (Some("limit".to_string()), Some("off".to_string()))
        );
        assert!(Line::try_parse_from(["config", "depth", "4", "5"]).is_err());
        assert!(Line::try_parse_from(["set", "depth", "4"]).is_err());
    }

    /// The render knobs are the session's (`config`): the retired flags
    /// are refused wherever they used to parse.
    #[test]
    fn test_render_flags_are_refused() {
        for line in [
            ["print", "-d", "6"].as_slice(),
            &["print", "--ugly"],
            &["print", "--max-string-len", "4"],
            &["print", "--max-array-values", "4"],
            &["trace", "-u"],
            &["threads", "--ugly"],
        ] {
            assert!(Line::try_parse_from(line).is_err(), "{line:?}");
        }
    }

    /// `history` takes an optional count and nothing else.
    #[test]
    fn test_history_takes_a_count_or_nothing() {
        let last = |line: &[&str]| {
            let Command::History { last } =
                Line::try_parse_from(line).expect("history parses").command
            else {
                panic!("history parsed as another command");
            };
            last
        };
        assert_eq!(last(&["history"]), None);
        assert_eq!(last(&["history", "20"]), Some(20));
        assert!(Line::try_parse_from(["history", "x"]).is_err());
        assert!(Line::try_parse_from(["history", "1", "2"]).is_err());
    }

    /// The numbers are positions in the file, so `history 2` shows the
    /// same numbers beside the same lines that `history` does.
    #[test]
    fn test_history_lines_are_numbered_by_file_position() {
        let text = "tasks\ngraph\ntrace 42 -v\n";
        assert_eq!(
            history_lines(text, None),
            ["    1  tasks", "    2  graph", "    3  trace 42 -v"]
        );
        assert_eq!(
            history_lines(text, Some(2)),
            ["    2  graph", "    3  trace 42 -v"]
        );
        assert_eq!(history_lines(text, Some(0)), Vec::<String>::new());
        assert_eq!(history_lines(text, Some(10)).len(), 3);
        assert_eq!(history_lines("", None), Vec::<String>::new());
    }

    /// No file yet is an empty history; a file that cannot be read is
    /// an error that names it.
    #[test]
    fn test_a_missing_history_file_is_empty_and_an_unreadable_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("hansei-history-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch dir");
        assert_eq!(
            read_history(&dir.join("absent")).expect("missing is empty"),
            ""
        );
        let err = read_history(&dir).expect_err("a directory is not readable as text");
        assert!(err.to_string().contains("reading "), "{err}");
        std::fs::write(dir.join("present"), "tasks\n").expect("write");
        assert_eq!(read_history(&dir.join("present")).expect("read"), "tasks\n");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// A pipe or `--exec` has no prompt and so no history to show.
    #[test]
    fn test_history_is_refused_without_a_prompt() {
        let mut out = Vec::new();
        let err = print_history(Mode::Scripted, None, &mut out).unwrap_err();
        assert_eq!(err.to_string(), "no history in a scripted session");
        assert!(out.is_empty());
    }
}

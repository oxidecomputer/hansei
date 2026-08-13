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

use crate::{Command, Flow, Session, dispatch};

use anyhow::{Context as _, Result, anyhow};
use clap::{CommandFactory, Parser};
use reedline::{
    ColumnarMenu, DefaultCompleter, DefaultPrompt, DefaultPromptSegment, Emacs, FileBackedHistory,
    KeyCode, KeyModifiers, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Signal,
    default_emacs_keybindings,
};
use subprocess::Exec;

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

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

pub fn run(session: &Session<'_>, exec: &[String]) -> Result<()> {
    if !exec.is_empty() {
        from_command_line(session, exec)
    } else if io::stdin().is_terminal() {
        interactive(session)
    } else {
        scripted(session)
    }
}

/// Answer what `--exec` asked for and stop, without reading stdin.
///
/// The rules are a script's: the commands run in order and the first
/// failure is fatal, since a caller that put them on one command line
/// meant them as one question.
fn from_command_line(session: &Session<'_>, exec: &[String]) -> Result<()> {
    for commands in exec {
        match execute(session, commands).with_context(|| format!("--exec {commands:?}"))? {
            Flow::Continue => continue,
            Flow::Quit => break,
        }
    }
    Ok(())
}

/// Read commands from a terminal until asked to stop. A command that
/// fails is reported and the session carries on: at a prompt the useful
/// response to a typo is another prompt.
fn interactive(session: &Session<'_>) -> Result<()> {
    let mut editor = line_editor();
    let prompt = DefaultPrompt::new(
        DefaultPromptSegment::Basic("hansei".to_string()),
        DefaultPromptSegment::Empty,
    );

    loop {
        match editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => match execute(session, &line) {
                Ok(Flow::Continue) => continue,
                Ok(Flow::Quit) => break,
                Err(e) => eprintln!("error: {e:#}"),
            },
            Ok(Signal::CtrlC) => continue,
            Ok(Signal::CtrlD) => break,
            Err(e) => {
                eprintln!("input error: {e}");
                break;
            }
        }
    }
    Ok(())
}

/// Read commands from a pipe or a file, one per line, and stop at the
/// first one that fails. Blank lines and `#` comments are skipped so a
/// stored script can be annotated.
fn scripted(session: &Session<'_>) -> Result<()> {
    let stdin = io::stdin();
    for (n, line) in stdin.lock().lines().enumerate() {
        let line = line.context("failed to read a command from stdin")?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // The line number is the only handle a script has on which
        // command went wrong, since nothing echoes them.
        match execute(session, &line).with_context(|| format!("stdin line {}", n + 1))? {
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
/// not go on to ask the rest. The separator binds looser than nothing
/// else does: a `;` ends the command it follows even inside the shell
/// text after a `!`, which is the price of not having a quoting
/// grammar.
fn execute(session: &Session<'_>, line: &str) -> Result<Flow> {
    let commands: Vec<&str> = line.split(';').collect();
    for command in &commands {
        // Which command failed is only a question when the line held
        // more than one; below, the line itself is the answer.
        let flow = match commands.len() {
            1 => execute_one(session, command)?,
            _ => {
                execute_one(session, command).with_context(|| format!("in `{}`", command.trim()))?
            }
        };
        if let Flow::Quit = flow {
            return Ok(Flow::Quit);
        }
    }
    Ok(Flow::Continue)
}

/// Parse one command and answer it, sending the output to a shell
/// pipeline if it asked for one.
fn execute_one(session: &Session<'_>, line: &str) -> Result<Flow> {
    // Everything after the first `!` is a shell command to pipe into,
    // so `tasks ! grep foo` filters the listing.
    let (command, shell) = match line.split_once('!') {
        Some((command, shell)) => (command, Some(shell)),
        None => (line, None),
    };

    if command.trim().is_empty() {
        return Ok(Flow::Continue);
    }

    // Splitting on whitespace means an argument cannot itself contain a
    // space; no command takes one today.
    let parsed = match Line::try_parse_from(command.split_whitespace()) {
        Ok(parsed) => parsed,
        // `use_stderr` is clap's own split between a real parse failure
        // and output that was asked for: `help` renders as an error but
        // is a successful command, and must not fail a script.
        Err(e) if !e.use_stderr() => {
            print!("{e}");
            return Ok(Flow::Continue);
        }
        Err(e) => return Err(anyhow!("{}", clap_message(e))),
    };

    // Either way the answer streams: a trace's output can run to
    // gigabytes, and holding it whole just to copy it out doubles the
    // traffic and the resident set. The writer buffers small pieces (a
    // heading line) and passes big ones through; a command that fails
    // mid-answer has printed what it printed.
    match shell {
        Some(shell) => {
            let sink = ShellSink {
                stdin: Some(Box::new(Exec::shell(shell.trim()).stream_stdin()?)),
            };
            let mut out = io::BufWriter::new(sink);
            let flow = dispatch(session, parsed.command, &mut out)?;
            out.flush()?;
            Ok(flow)
        }
        None => {
            let stdout = io::stdout();
            let mut out = io::BufWriter::new(stdout.lock());
            let flow = dispatch(session, parsed.command, &mut out)?;
            out.flush()?;
            Ok(flow)
        }
    }
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

fn line_editor() -> Reedline {
    let names: Vec<String> = Line::command()
        .get_subcommands()
        .map(|sub| sub.get_name().to_string())
        .collect();
    // `-` counts as part of a word, so a half-typed `--val` is one token
    // to complete against rather than two.
    let mut completer = Box::new(DefaultCompleter::with_inclusions(&['-']));
    completer.insert(names);

    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("commands".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );

    let editor = Reedline::create()
        .with_completer(completer)
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(
            ColumnarMenu::default().with_name("commands"),
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

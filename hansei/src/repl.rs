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
        let flow = match command_frame(commands.len(), command) {
            None => execute_one(session, command)?,
            Some(frame) => execute_one(session, command).with_context(|| frame)?,
        };
        if let Flow::Quit = flow {
            return Ok(Flow::Quit);
        }
    }
    Ok(Flow::Continue)
}

/// How a failure names the command it came from. Which command failed
/// is only a question when the line held more than one; on a
/// single-command line, the line itself is the answer.
fn command_frame(count: usize, command: &str) -> Option<String> {
    (count > 1).then(|| format!("in `{}`", command.trim()))
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

    let parsed = match parse_command(command)? {
        Some(parsed) => parsed,
        None => return Ok(Flow::Continue),
    };

    // Either way the answer streams: a trace's output can run to
    // gigabytes, and holding it whole just to copy it out doubles the
    // traffic and the resident set. The writer buffers small pieces (a
    // heading line) and passes big ones through; a command that fails
    // mid-answer has printed what it printed.
    // The theme is where the output is going: a `!` pipe is a script's
    // input however the session was started, so only the plain stdout
    // path may style.
    match shell {
        Some(shell) => {
            let sink = ShellSink {
                stdin: Some(Box::new(Exec::shell(shell.trim()).stream_stdin()?)),
            };
            let mut out = io::BufWriter::new(sink);
            let flow = dispatch(session, parsed.command, Theme::plain(), &mut out)?;
            out.flush()?;
            Ok(flow)
        }
        None => {
            let stdout = io::stdout();
            let mut out = io::BufWriter::new(stdout.lock());
            let flow = dispatch(session, parsed.command, Theme::for_stdout(), &mut out)?;
            out.flush()?;
            Ok(flow)
        }
    }
}

/// Parse one command, or answer it on the spot: `None` means the
/// command was already answered with printed output rather than parsed
/// into something to dispatch.
///
/// Splitting on whitespace means an argument cannot itself contain a
/// space; no command takes one today.
fn parse_command(command: &str) -> Result<Option<Line>> {
    match Line::try_parse_from(command.split_whitespace()) {
        Ok(parsed) => Ok(Some(parsed)),
        // `use_stderr` is clap's own split between a real parse failure
        // and output that was asked for: `help` renders as an error but
        // is a successful command, and must not fail a script.
        Err(e) if !e.use_stderr() => {
            print!("{e}");
            Ok(None)
        }
        Err(e) => Err(anyhow!("{}", clap_message(e))),
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

    /// The census sections are flags rather than a value, so several of
    /// them can be asked for at once — including bundled behind one `-`.
    #[test]
    fn test_census_takes_several_sections_at_once() {
        let Command::Census {
            threads,
            tasks,
            futures,
            top,
        } = Line::try_parse_from(["census", "-Tf", "--top", "9"])
            .expect("census takes its section flags")
            .command
        else {
            panic!("census parsed as another command");
        };
        assert!(threads && futures && !tasks);
        assert_eq!(top, 9);
    }

    /// Which command failed is framed only on a multi-command line; a
    /// single command's failure is already named by the line itself.
    #[test]
    fn test_only_multi_command_lines_frame_their_failures() {
        assert_eq!(command_frame(1, " tasks "), None);
        assert_eq!(command_frame(2, " tasks "), Some("in `tasks`".to_string()));
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

    /// `help` is a successful command that clap renders as an error;
    /// a real parse failure is one, with clap's prefix stripped since
    /// the caller frames it.
    #[test]
    fn test_help_is_answered_and_nonsense_is_refused() {
        assert!(matches!(parse_command("help"), Ok(None)));
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

    /// `runtime` and `runtimes` are two commands whose names are a
    /// prefix apart, so an exact name has to beat inference — and every
    /// shorter prefix now fits both, which is the price of the listing
    /// being named after what it lists.
    #[test]
    fn test_runtime_and_runtimes_are_told_apart_by_their_exact_names() {
        let parsed = |line: &[&str]| Line::try_parse_from(line).map(|l| l.command);
        assert!(matches!(parsed(&["runtimes"]), Ok(Command::Runtimes)));
        assert!(matches!(parsed(&["runtime"]), Ok(Command::Runtime { .. })));
        let ambiguous = parsed(&["runtim"])
            .err()
            .expect("a shared prefix is refused");
        let message = ambiguous.to_string();
        for candidate in ["runtime", "runtimes"] {
            assert!(
                message.contains(candidate),
                "{candidate} missing: {message}"
            );
        }
    }

    /// The runtime's sections are flags rather than a value, the way
    /// the census's are, so both can be asked for at once and naming
    /// neither asks for the whole runtime.
    #[test]
    fn test_runtime_takes_its_sections_as_flags() {
        let sections = |line: &[&str]| {
            let Command::Runtime {
                drivers, shared, ..
            } = Line::try_parse_from(line)
                .expect("runtime takes its section flags")
                .command
            else {
                panic!("runtime parsed as another command");
            };
            (drivers, shared)
        };
        assert_eq!(sections(&["runtime", "-D"]), (true, false));
        assert_eq!(sections(&["runtime", "--shared"]), (false, true));
        assert_eq!(sections(&["runtime", "-Ds"]), (true, true));
    }

    /// The runtime a command is pointed at is named by its index in the
    /// listing or by the handle address printed beside it, and the two
    /// spellings cannot be confused for one another.
    #[test]
    fn test_runtime_is_pointed_at_one_runtime() {
        let scope = |line: &[&str]| {
            let Command::Runtime { scope, .. } = Line::try_parse_from(line)
                .expect("runtime takes a scope")
                .command
            else {
                panic!("runtime parsed as another command");
            };
            scope
        };
        assert!(matches!(
            scope(&["runtime", "0x7f11c0"]),
            Some(RuntimeScope::Handle(0x7f11c0))
        ));
        assert!(matches!(
            scope(&["runtime", "2"]),
            Some(RuntimeScope::Index(2))
        ));
        assert!(scope(&["runtime"]).is_none());

        // An address without its prefix would be an index; one that is
        // neither is refused rather than guessed at.
        assert!(Line::try_parse_from(["runtime", "7f11c0"]).is_err());
    }
}

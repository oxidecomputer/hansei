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
use std::path::{Path, PathBuf};

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
enum Mode {
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
    let mut editor = line_editor();
    let prompt = DefaultPrompt::new(
        DefaultPromptSegment::Basic("hansei".to_string()),
        DefaultPromptSegment::Empty,
    );

    loop {
        match editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
                // reedline writes the file only when the editor is
                // dropped; writing it per line is what lets `history`
                // read this session's lines back, and lets a second
                // session running beside this one see them too.
                if let Err(e) = editor.sync_history() {
                    eprintln!("warning: command history not saved: {e}");
                }
                match execute(session, Mode::Interactive, &line) {
                    Ok(Flow::Continue) => continue,
                    Ok(Flow::Quit) => break,
                    Err(e) => eprintln!("error: {e:#}"),
                }
            }
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
/// after a `!` — with one way out: `\;` is a literal `;`, which is how
/// an array type (`[usize\; 4]`) crosses the split. That pair is the
/// whole escape grammar; every other backslash is itself.
fn execute<T: proc::Target>(session: &Session<'_, T>, mode: Mode, line: &str) -> Result<Flow> {
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

/// Split a line at every unescaped `;`, unescaping `\;` to a literal
/// `;` in each piece. Exactly the two-character sequence `\;` is
/// special; any other backslash passes through untouched, so nothing
/// else needs escaping and no name grows a second spelling.
fn split_commands(line: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current = String::new();
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
            ';' => commands.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    commands.push(current);
    commands
}

/// How a failure names the command it came from. Which command failed
/// is only a question when the line held more than one; on a
/// single-command line, the line itself is the answer.
fn command_frame(count: usize, command: &str) -> Option<String> {
    (count > 1).then(|| format!("in `{}`", command.trim()))
}

/// Parse one command and answer it, sending the output to a shell
/// pipeline if it asked for one.
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

    let parsed = match parse_command(command)? {
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
    // The theme is where the output is going: a `!` pipe is a script's
    // input however the session was started, so only the plain stdout
    // path may style.
    match shell {
        Some(shell) => {
            let sink = ShellSink {
                stdin: Some(Box::new(Exec::shell(shell.trim()).stream_stdin()?)),
            };
            let mut out = io::BufWriter::new(sink);
            let flow = answer(Theme::plain(), &mut out)?;
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

    /// The split honors exactly one escape: `\;` is a literal `;` and
    /// never a separator, an unescaped `;` always is one, and every
    /// other backslash — mid-name, before another character, ending
    /// the line — passes through untouched.
    #[test]
    fn test_the_split_honors_the_escaped_separator() {
        assert_eq!(split_commands("tasks ; graph"), ["tasks ", " graph"]);
        assert_eq!(
            split_commands(r"print 0x10 [usize\; 4]; graph"),
            ["print 0x10 [usize; 4]", " graph"]
        );
        assert_eq!(split_commands(r"type [u8\; 2]"), ["type [u8; 2]"]);
        assert_eq!(split_commands(r"a \x b"), [r"a \x b"]);
        assert_eq!(split_commands(r"a \"), [r"a \"]);
        assert_eq!(split_commands("tasks"), ["tasks"]);
        assert_eq!(split_commands("a;;b"), ["a", "", "b"]);
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

    /// `print`'s type is the rest of the line: the words are joined
    /// back into one name, so a name whose generic arguments hold
    /// spaces pastes in whole, with the render flags still parsed out
    /// from among them.
    #[test]
    fn test_print_takes_the_rest_of_the_line_as_one_type() {
        let Command::Print { addr, ty, render } =
            Line::try_parse_from(["print", "0x7f10", "Vec<(u64,", "u64)>", "-u"])
                .expect("print takes an address and a type")
                .command
        else {
            panic!("print parsed as another command");
        };
        assert_eq!(addr, 0x7f10);
        assert_eq!(ty.join(" "), "Vec<(u64, u64)>");
        assert!(render.ugly);

        // The address keeps its required prefix, so it can never be
        // read as the leading word of a type name.
        assert!(Line::try_parse_from(["print", "7f10", "u64"]).is_err());
        assert!(Line::try_parse_from(["print", "0x7f10"]).is_err());
    }

    /// The runtimes' sections are flags rather than a value, the way
    /// the census's are, so both can be asked for at once and naming
    /// neither asks for the whole runtime.
    #[test]
    fn test_runtimes_takes_its_sections_as_flags() {
        let sections = |line: &[&str]| {
            let Command::Runtimes {
                drivers, shared, ..
            } = Line::try_parse_from(line)
                .expect("runtimes takes its section flags")
                .command
            else {
                panic!("runtimes parsed as another command");
            };
            (drivers, shared)
        };
        assert_eq!(sections(&["runtimes", "-D"]), (true, false));
        assert_eq!(sections(&["runtimes", "--shared"]), (false, true));
        assert_eq!(sections(&["runtimes", "-Ds"]), (true, true));
    }

    /// The runtimes a command is pointed at are named by their index in
    /// the listing or by the handle address printed beside them, as
    /// many as the reader cares to name, and the two spellings cannot
    /// be confused for one another.
    #[test]
    fn test_runtimes_is_pointed_at_the_runtimes_named() {
        let scope = |line: &[&str]| {
            let Command::Runtimes { scope, .. } = Line::try_parse_from(line)
                .expect("runtimes takes scopes")
                .command
            else {
                panic!("runtimes parsed as another command");
            };
            scope
        };
        assert_eq!(
            scope(&["runtimes", "0x7f11c0"]),
            [RuntimeScope::Handle(0x7f11c0)]
        );
        // The listing spells the handle `@0x…`, so a pasted cell works
        // with the `@` still on it.
        assert_eq!(
            scope(&["runtimes", "@0x7f11c0"]),
            [RuntimeScope::Handle(0x7f11c0)]
        );
        assert_eq!(scope(&["runtimes", "2"]), [RuntimeScope::Index(2)]);
        // Several at once, since the question "what are these two
        // doing" is the one several runtimes raise.
        assert_eq!(
            scope(&["runtimes", "2", "@0x7f11c0"]),
            [RuntimeScope::Index(2), RuntimeScope::Handle(0x7f11c0)]
        );
        assert!(scope(&["runtimes"]).is_empty());

        // An address without its prefix would be an index; one that is
        // neither is refused rather than guessed at, as is an `@` on
        // anything but an address.
        assert!(Line::try_parse_from(["runtimes", "7f11c0"]).is_err());
        assert!(Line::try_parse_from(["runtimes", "@2"]).is_err());
    }

    /// `--list` asks a different question than the state views, so it
    /// is refused alongside anything that narrows one: a section flag,
    /// or a named runtime.
    #[test]
    fn test_the_listing_is_asked_for_on_its_own() {
        let listing = |line: &[&str]| {
            let Command::Runtimes { list, .. } = Line::try_parse_from(line)
                .expect("runtimes takes --list")
                .command
            else {
                panic!("runtimes parsed as another command");
            };
            list
        };
        assert!(listing(&["runtimes", "-l"]));
        assert!(!listing(&["runtimes"]));
        assert!(Line::try_parse_from(["runtimes", "-l", "-D"]).is_err());
        assert!(Line::try_parse_from(["runtimes", "--list", "--shared"]).is_err());
        assert!(Line::try_parse_from(["runtimes", "-l", "0"]).is_err());
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

/// Parse one command from the words `tasks --exec` carries — already
/// split, so nothing here re-splits — for running it under a per-task
/// scope. Output-only parses (`help`) are errors here: an exec loop
/// wants a command to run.
pub(crate) fn parse_exec_command(words: &[String]) -> Result<Command> {
    match Line::try_parse_from(words) {
        Ok(line) => Ok(line.command),
        Err(e) => Err(anyhow!("{}", clap_message(e))),
    }
}

/// Parse one command line the way the prompt does, handing back the
/// grammar's own `Command` for suites that drive `dispatch` directly.
#[cfg(test)]
pub(crate) fn parse_line(command: &str) -> Result<crate::Command> {
    Ok(parse_command(command)?
        .expect("the offline suites drive complete commands, not `help`")
        .command)
}

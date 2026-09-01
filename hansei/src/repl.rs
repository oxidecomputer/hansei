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
    let mut editor = line_editor();

    loop {
        // Rebuilt per line: the prompt is the cursor's account of
        // where the session stands, and the last command may have
        // moved it.
        let prompt = DefaultPrompt::new(
            DefaultPromptSegment::Basic(crate::cursor::prompt_label(&session.cursor.borrow())),
            DefaultPromptSegment::Empty,
        );
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
    // `print` resolves `$_` itself: its bare-`$_` form defaults the
    // type from the cursor frame, which a pre-substituted hex address
    // could no longer ask for.
    let substituted;
    let words = match words.first().is_some_and(|w| names_print(w)) {
        true => words,
        false => {
            substituted = substitute_last_addr(words, session.cursor.borrow().last_addr)?;
            &substituted
        }
    };
    let parsed = match parse_words(words)? {
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
    let arg = &words[1];
    let scope = match words[0].as_str() {
        "task" => Scope::Task(crate::parse_trace_target(arg).ok()?),
        "future" => Scope::Future(crate::parse_hex_addr(arg).ok()?),
        "thread" => Scope::Thread(arg.parse().ok()?),
        _ => return None,
    };
    Some((scope, &words[2..]))
}

/// Point the cursor where a scope says, silently: the selection line
/// belongs to the selector commands, not to a prefix that exists to
/// run something else.
fn apply_scope<T: proc::Target>(session: &Session<'_, T>, scope: Scope) -> Result<()> {
    match scope {
        Scope::Task(target) => crate::cursor::select_task(session, target).map(|_| ()),
        Scope::Future(addr) => crate::cursor::select_future(session, addr, &mut io::sink()),
        Scope::Thread(lwp) => crate::cursor::select_thread(session, lwp),
    }
}

/// Whether `word` names the `print` command, exactly or by the
/// unique-prefix rule the grammar's `infer_subcommands` applies. The
/// one command whose `$_` stays a token: see [`answer_words`].
fn names_print(word: &str) -> bool {
    !word.is_empty()
        && "print".starts_with(word)
        && Line::command()
            .get_subcommands()
            .filter(|c| c.get_name().starts_with(word))
            .count()
            == 1
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

    /// `info` takes one section, or `-v` for all of them — never both,
    /// which would leave it ambiguous how much was asked for.
    #[test]
    fn test_info_takes_a_section_or_verbose() {
        let Command::Info { section, verbose } = Line::try_parse_from(["info"])
            .expect("bare info parses")
            .command
        else {
            panic!("info parsed as another command");
        };
        assert_eq!(section, None);
        assert!(!verbose);

        let Command::Info { section, verbose } = Line::try_parse_from(["info", "fds"])
            .expect("info takes a section")
            .command
        else {
            panic!("info parsed as another command");
        };
        assert_eq!(section, Some(crate::info::Section::Fds));
        assert!(!verbose);

        let Command::Info { section, verbose } = Line::try_parse_from(["info", "-v"])
            .expect("info takes -v")
            .command
        else {
            panic!("info parsed as another command");
        };
        assert_eq!(section, None);
        assert!(verbose);

        assert!(Line::try_parse_from(["info", "fds", "-v"]).is_err());
        assert!(Line::try_parse_from(["info", "panic"]).is_err());
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

    /// `print`'s positionals are one root spelling plus path tokens,
    /// split apart by the command itself — clap only collects them —
    /// with the render flags still parsed out from among them.
    #[test]
    fn test_print_collects_root_and_path_tokens() {
        let Command::Print { args, render } =
            Line::try_parse_from(["print", "0x7f10", "Vec<(u64, u64)>", ".a", "-u"])
                .expect("print takes a root and path tokens")
                .command
        else {
            panic!("print parsed as another command");
        };
        assert_eq!(args, ["0x7f10", "Vec<(u64, u64)>", ".a"]);
        assert!(render.ugly);

        // Bare `print` is the cursor frame: nothing is required.
        let Command::Print { args, .. } = Line::try_parse_from(["print"])
            .expect("bare print parses")
            .command
        else {
            panic!("print parsed as another command");
        };
        assert!(args.is_empty());
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
        let words = w("thread 3 print $_");
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
            split(r#"print 0x1 "Vec<(u64, u64)>" .a"#),
            ["print", "0x1", "Vec<(u64, u64)>", ".a"]
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

    /// `print` — under any prefix that names it alone — is exempt
    /// from `$_` substitution; everything else is not.
    #[test]
    fn test_print_alone_keeps_its_last_addr_token() {
        for word in ["print", "prin", "pri", "pr", "p"] {
            assert!(names_print(word), "{word}");
        }
        for word in ["", "tasks", "printx", "trace", "t"] {
            assert!(!names_print(word), "{word}");
        }
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
                verbose: false
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
            Line::try_parse_from(["thread", "3", "-v"])
                .expect("thread selects")
                .command,
            Command::Thread {
                lwp: Some(3),
                verbose: true,
                ..
            }
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
        let Command::Frame { index, then } = Line::try_parse_from(["frame", "7", "print", ".self"])
            .expect("frame carries a trailing command")
            .command
        else {
            panic!("frame parses");
        };
        assert_eq!(index, Some(7));
        assert_eq!(then, ["print", ".self"]);
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
        let Command::Up { then } = Line::try_parse_from(["up", "print", ".count", "--ugly"])
            .expect("the trailing command keeps its own flags")
            .command
        else {
            panic!("up parses");
        };
        assert_eq!(then, ["print", ".count", "--ugly"]);
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

    /// `set` takes a key alone, a key and a value, or nothing — and
    /// the values are plain words, so `set limit off` parses whole.
    #[test]
    fn test_set_takes_a_key_and_value_or_less() {
        let parse = |line: &[&str]| {
            let Command::Set { key, value } =
                Line::try_parse_from(line).expect("set parses").command
            else {
                panic!("set parsed as another command");
            };
            (key, value)
        };
        assert_eq!(parse(&["set"]), (None, None));
        assert_eq!(parse(&["set", "depth"]), (Some("depth".to_string()), None));
        assert_eq!(
            parse(&["set", "limit", "off"]),
            (Some("limit".to_string()), Some("off".to_string()))
        );
        assert!(Line::try_parse_from(["set", "depth", "4", "5"]).is_err());
    }

    /// The render flags default to nothing so the session's own
    /// values show through; a flag given on the line is carried.
    #[test]
    fn test_render_flags_carry_only_what_was_given() {
        let Command::Trace { render, .. } = Line::try_parse_from(["trace", "42", "-d", "6"])
            .expect("trace takes render flags")
            .command
        else {
            panic!("trace parsed as another command");
        };
        assert_eq!(render.depth, Some(6));
        assert_eq!(render.max_string_len, None);
        assert_eq!(render.max_array_values, None);
        assert!(!render.ugly);
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

/// Parse one command from the words `tasks --exec` carries, for
/// running it under a per-task scope. The words usually arrive
/// already split — `--exec` takes the rest of its line — but a
/// quoted command (`--exec 'trace -v'`) lands as one word holding
/// whitespace, and is split here the way the prompt would have split
/// it unquoted. Output-only parses (`help`) are errors here: an exec
/// loop wants a command to run.
pub(crate) fn parse_exec_command(words: &[String]) -> Result<Command> {
    let resplit;
    let words = match words {
        [one] if one.chars().any(char::is_whitespace) => {
            resplit = split_tokens(one)?;
            &resplit
        }
        words => words,
    };
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

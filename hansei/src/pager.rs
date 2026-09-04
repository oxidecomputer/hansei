// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The pager a prompt's answers page through, as git pages its own:
//! the session spawns it, feeds it the answer, and waits for it to be
//! quit before the next prompt.
//!
//! Only a prompt's answer pages — never a script's, `--exec`'s or a
//! `!` pipeline's, whose bytes are a program's input — and only when
//! stdout is a terminal, since the pager is for reading there. The
//! pipe to the pager ends on that terminal, so the answer is styled as
//! it would be written there directly.
//!
//! The pager starts on the answer's first byte, not before it, so a
//! command that prints nothing — `config ugly on`, `quit` — never
//! opens one, and a pager that would wait for `q` over an empty
//! screen never gets the chance.

use anyhow::{Context, Result};
use subprocess::{Exec, Job, Redirection};

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The pager a session starts with when nothing names one: less, with
/// the flags on its command line rather than in `LESS`, since a
/// `LESS` in the environment — or in a lesskey file, which overrides
/// the environment — would replace them. `F` quits when the answer
/// fits one screen, `R` shows the answer's styling rather than the
/// escapes that carry it, and `X` keeps the answer on the terminal
/// after quitting rather than on an alternate screen that vanishes
/// with it.
pub(crate) const DEFAULT: &str = "less -FRX";

/// The pager to start a session with: what `HANSEI_PAGER` names, else
/// [`DEFAULT`] where less is on the `PATH`, else none. The variable
/// set to nothing, or to `cat`, asks for no pager at all — `None`,
/// which `config pager off` spells at the prompt. `PAGER` is not
/// consulted: a pager chosen for other programs comes without the
/// flags hansei wants, and `config pager` or the variable is the way
/// to name one.
pub(crate) fn from_env() -> Option<String> {
    default_command(std::env::var_os("HANSEI_PAGER"), less_on_path().is_some())
}

/// [`from_env`] over the variable's value and whether less is found,
/// for the tests.
fn default_command(hansei_pager: Option<OsString>, less_found: bool) -> Option<String> {
    match hansei_pager {
        Some(named) => match named.to_string_lossy().trim() {
            "" | "cat" => None,
            command => Some(command.to_string()),
        },
        None => less_found.then(|| DEFAULT.to_string()),
    }
}

/// Where `less` is on the `PATH`, if it is: the first directory
/// holding an executable file of that name.
fn less_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("less"))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Whether an answer pages: only a prompt's, only onto a terminal, and
/// only with a pager to page through.
pub(crate) fn pages(interactive: bool, stdout_is_terminal: bool, pager: Option<&str>) -> bool {
    interactive && stdout_is_terminal && pager.is_some()
}

/// The answer's way to the pager: the command to run, started on the
/// first write and fed every write after it. A write the pager will
/// not take — it was quit — is swallowed, and everything after it too:
/// the reader has left, and the answer has nowhere else to go.
pub(crate) struct PagerSink {
    command: String,
    state: State,
}

enum State {
    /// Nothing written yet, so nothing started.
    Unstarted,
    /// The pager is running and reading from the file. The fields
    /// drop in this order, so leaving the state — quit, or gone — ends
    /// the answer before the pager is waited for, and gives the
    /// interrupts back once it has been.
    Running {
        stdin: File,
        job: Job,
        interrupts: Interrupts,
    },
    /// The pager is gone — quit, or never startable — and the rest of
    /// the answer goes nowhere.
    Gone,
}

impl PagerSink {
    pub(crate) fn new(command: &str) -> Self {
        Self {
            command: command.to_string(),
            state: State::Unstarted,
        }
    }

    /// Start the pager: through the shell, so the command may carry
    /// its own flags, reading the answer from a pipe. An interrupt
    /// from here until the pager is waited for is the pager's to
    /// handle.
    fn start(&self) -> io::Result<State> {
        let interrupts = Interrupts::deferred();
        let mut job = Exec::shell(&self.command)
            .stdin(Redirection::Pipe)
            .start()?;
        let stdin = job
            .stdin
            .take()
            .expect("a job started with a piped stdin has one");
        Ok(State::Running {
            stdin,
            job,
            interrupts,
        })
    }

    /// Whether the pager was ever started: whether the answer had a
    /// first byte.
    #[cfg(test)]
    fn started(&self) -> bool {
        !matches!(self.state, State::Unstarted)
    }

    /// Close the answer and wait for the pager to be quit, so the
    /// prompt comes back to a terminal the pager has given up. An
    /// answer that never started the pager has nothing to wait for.
    pub(crate) fn finish(self) -> Result<()> {
        if let State::Running {
            stdin,
            job,
            interrupts,
        } = self.state
        {
            drop(stdin);
            job.wait()
                .with_context(|| format!("waiting for the pager {:?}", self.command))?;
            drop(interrupts);
        }
        Ok(())
    }
}

impl Write for PagerSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let State::Unstarted = self.state {
            self.state = match self.start() {
                Ok(running) => running,
                Err(e) => {
                    // The answer still prints — to stderr, where the
                    // reader is — so a mistyped `config pager` is one
                    // warning and not a session that says nothing.
                    eprintln!("warning: cannot start the pager {:?}: {e}", self.command);
                    State::Gone
                }
            };
        }
        if let State::Running { stdin, .. } = &mut self.state {
            // `write_all` does not play nicely with the shell's group
            // leader here, so the writes are looped by hand.
            let mut written = 0;
            while written < buf.len() {
                match stdin.write(&buf[written..]) {
                    Ok(0) | Err(_) => {
                        self.state = State::Gone;
                        break;
                    }
                    Ok(n) => written += n,
                }
            }
        }
        // The feed never errors: a quit pager swallows what remains.
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let State::Running { stdin, .. } = &mut self.state
            && stdin.flush().is_err()
        {
            self.state = State::Gone;
        }
        Ok(())
    }
}

/// SIGINT parked for as long as this lives. The pager shares the
/// terminal's foreground group with the session, so a `^C` meant for
/// it — less uses one to stop a search — reaches both, and the
/// session's default disposition would end the session under a pager
/// still holding the terminal. A handler that does nothing, rather
/// than `SIG_IGN`: an ignored signal is inherited across `exec`, and
/// the pager must still receive its own.
struct Interrupts {
    previous: libc::sigaction,
}

extern "C" fn disregard(_: libc::c_int) {}

impl Interrupts {
    fn deferred() -> Self {
        // SAFETY: a zeroed `sigaction` is the empty mask with no flags,
        // to which a handler and `SA_RESTART` are added — so a write to
        // the pager's pipe, or the wait for it, resumes rather than
        // failing with EINTR — and the disposition it replaces is
        // kept to be restored by `drop`.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = disregard as extern "C" fn(libc::c_int) as usize;
            action.sa_flags = libc::SA_RESTART;
            let mut previous: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGINT, &action, &mut previous);
            Self { previous }
        }
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        // SAFETY: `previous` is what `sigaction` filled in when the
        // handler was installed, and is restored whole.
        unsafe {
            libc::sigaction(libc::SIGINT, &self.previous, std::ptr::null_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    /// `HANSEI_PAGER` names the pager whatever is on the `PATH`; set
    /// to nothing or to `cat` it asks for none rather than falling
    /// through to less; unset, less is the pager where it is found,
    /// with hansei's flags on its command line, and nothing is where
    /// it is not.
    #[test]
    fn test_the_variable_names_the_pager_else_less_where_found() {
        assert_eq!(default_command(None, true).as_deref(), Some("less -FRX"));
        assert_eq!(default_command(None, false), None);
        assert_eq!(default_command(env("moor"), false).as_deref(), Some("moor"));
        assert_eq!(
            default_command(env("less -S"), true).as_deref(),
            Some("less -S")
        );
        assert_eq!(default_command(env(""), true), None);
        assert_eq!(default_command(env(" cat "), true), None);
    }

    /// The `PATH` lookup finds an executable file by name and nothing
    /// else: a directory, or a file that cannot be run, is not less.
    #[test]
    fn test_less_is_found_only_as_an_executable_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("less")).unwrap();
        assert!(!is_executable(&dir.path().join("less")));
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "").unwrap();
        assert!(!is_executable(&plain));
        let runnable = dir.path().join("runnable");
        std::fs::write(&runnable, "#!/bin/sh\n").unwrap();
        let mut perms = std::fs::metadata(&runnable).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&runnable, perms).unwrap();
        assert!(is_executable(&runnable));
    }

    /// Only a prompt's answer pages, only onto a terminal, and only
    /// with a pager configured.
    #[test]
    fn test_only_a_prompts_answer_on_a_terminal_pages() {
        assert!(pages(true, true, Some("less")));
        assert!(!pages(false, true, Some("less")));
        assert!(!pages(true, false, Some("less")));
        assert!(!pages(true, true, None));
    }

    /// The pager is started on the first byte and fed the rest; a
    /// finished answer is whole in the pager's hands before `finish`
    /// returns, since it waited for the pager to exit.
    #[test]
    fn test_the_answer_reaches_the_pager_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paged");
        let mut sink = PagerSink::new(&format!("cat > {}", path.display()));
        assert!(!sink.started());
        sink.write_all(b"ID  STATE\n").unwrap();
        assert!(sink.started());
        sink.write_all(b"1   idle\n").unwrap();
        sink.flush().unwrap();
        sink.finish().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "ID  STATE\n1   idle\n"
        );
    }

    /// An answer with no bytes never starts the pager, so a command
    /// that prints nothing opens no screen to quit.
    #[test]
    fn test_an_empty_answer_starts_no_pager() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("touched");
        let sink = PagerSink::new(&format!("touch {}", path.display()));
        sink.finish().unwrap();
        assert!(!path.exists());
    }

    /// A pager that quits early swallows the rest of the answer, and
    /// `finish` still returns: the reader left, and nothing waits on
    /// them.
    #[test]
    fn test_a_quit_pager_swallows_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("first");
        let mut sink = PagerSink::new(&format!("head -c 4 > {}", path.display()));
        sink.write_all(b"abcd").unwrap();
        // The pager exits after its four bytes. Each write here either
        // lands in the pipe's buffer, blocks until the pager has read
        // or gone, or fails because it has gone — so the loop ends
        // without a sleep, once the pipe is dead.
        let filler = vec![b'x'; 1 << 16];
        while !matches!(sink.state, State::Gone) {
            sink.write_all(&filler).unwrap();
        }
        sink.finish().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "abcd");
    }
}

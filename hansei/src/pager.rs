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

/// The pager to start a session with, from the environment: what
/// `HANSEI_PAGER` names, else what `PAGER` names, else `less`. Either
/// variable set to nothing, or to `cat`, asks for no pager at all —
/// `None`, which `config pager off` spells at the prompt.
pub(crate) fn from_env() -> Option<String> {
    default_command(std::env::var_os("HANSEI_PAGER"), std::env::var_os("PAGER"))
}

/// [`from_env`] over the two variables' values, for the tests.
fn default_command(hansei_pager: Option<OsString>, pager: Option<OsString>) -> Option<String> {
    let named = hansei_pager
        .or(pager)
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_else(|| "less".to_string());
    match named.trim() {
        "" | "cat" => None,
        command => Some(command.to_string()),
    }
}

/// Whether an answer pages: only a prompt's, only onto a terminal, and
/// only with a pager to page through.
pub(crate) fn pages(interactive: bool, stdout_is_terminal: bool, pager: Option<&str>) -> bool {
    interactive && stdout_is_terminal && pager.is_some()
}

/// The `LESS` flags the pager is given when the environment sets none,
/// as git gives them: `F` quits when the answer fits one screen, `R`
/// shows the answer's styling rather than the escapes that carry it,
/// and `X` keeps the answer in the terminal's scrollback after quitting
/// rather than on an alternate screen that vanishes with it. A `LESS`
/// the environment does set is left alone, whatever it says.
const LESS_DEFAULT: &str = "FRX";

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
    /// its own flags, with `LESS` supplied where the environment has
    /// none, and reading the answer from a pipe. An interrupt from
    /// here until the pager is waited for is the pager's to handle.
    fn start(&self) -> io::Result<State> {
        let interrupts = Interrupts::deferred();
        let mut exec = Exec::shell(&self.command).stdin(Redirection::Pipe);
        if std::env::var_os("LESS").is_none() {
            exec = exec.env("LESS", LESS_DEFAULT);
        }
        let mut job = exec.start()?;
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

    /// `HANSEI_PAGER` names the pager, else `PAGER`, else `less`; set
    /// to nothing or to `cat`, either asks for no pager rather than
    /// falling through to the next.
    #[test]
    fn test_the_environment_names_the_pager_in_order() {
        assert_eq!(default_command(None, None).as_deref(), Some("less"));
        assert_eq!(default_command(None, env("moor")).as_deref(), Some("moor"));
        assert_eq!(
            default_command(env("less -S"), env("moor")).as_deref(),
            Some("less -S")
        );
        assert_eq!(default_command(env(""), env("moor")), None);
        assert_eq!(default_command(env("cat"), env("moor")), None);
        assert_eq!(default_command(None, env("")), None);
        assert_eq!(default_command(None, env(" cat ")), None);
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

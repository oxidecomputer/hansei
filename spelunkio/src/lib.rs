// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Our repl entrypoint

mod commands;
mod tokio;

use anyhow::Result;
pub use commands::dispatch as dispatch_command;
pub use hansei_types::debugger::Dbg;
use reedline::{
    ColumnarMenu, DefaultCompleter, DefaultPrompt, DefaultPromptSegment, Emacs,
    FileBackedHistory, KeyCode, KeyModifiers, MenuBuilder, Reedline,
    ReedlineEvent, Signal, default_emacs_keybindings,
};
pub use tokio::load_tokio_runtime;

pub fn run(dbg: Dbg) -> Result<()> {
    let mut line_editor = new_line_editor();
    let prompt = DefaultPrompt::new(
        DefaultPromptSegment::Basic("spelunkio".to_string()),
        DefaultPromptSegment::Empty,
    );
    let runtime = load_tokio_runtime(&dbg)?;

    loop {
        let sig = line_editor.read_line(&prompt);
        match sig {
            Ok(Signal::Success(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match commands::dispatch(&runtime, &dbg, line) {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => eprintln!("error: {e:#}"),
                }
            }
            Ok(Signal::CtrlD | Signal::CtrlC) => {
                break;
            }
            Err(e) => {
                eprintln!("input error: {e}");
                break;
            }
        }
    }

    Ok(())
}

fn new_line_editor() -> Reedline {
    let mut completer = Box::new(DefaultCompleter::with_inclusions(&['-']));
    completer.insert(commands::Cli::commands());
    let completion_menu =
        Box::new(ColumnarMenu::default().with_name("commands"));
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("commands".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    let edit_mode = Box::new(Emacs::new(keybindings));

    let history = Box::new(
        FileBackedHistory::with_file(10000, "/tmp/.tqdb-history.txt".into())
            .expect("Error configuring history with file"),
    );

    Reedline::create()
        .with_history(history)
        .with_completer(completer)
        .with_menu(reedline::ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode)
}

//! Offline command goldens: a session over each checked-in fixture
//! pair (`hansei-runtime/tests/fixtures/<set>/`), answering the
//! commands the snapshot capture feeds, through hansei's own printers.
//! This is the suite that runs on any platform — the acceptance suite
//! exercises the same commands against real cores, remotes only.
//!
//! A snapshot holds only what its capture touched: task enumeration
//! and every await chain. A command that reads memory the capture
//! never did sees `unreadable` there, and the golden records exactly
//! that. A command that fails outright goldens its error text instead
//! — either way the recorded behavior is the reviewed surface.
//!
//! Snapshots carry no lwp names and no umem heap, so anything read
//! from those goldens as absent.

use crate::output::Theme;
use crate::{Session, SessionArgs, dispatch, repl};

use hansei_runtime::testkit::{self, FIXTURE_SETS, PROGRAMS, mask};
use hansei_runtime::tokio::census;

use std::path::Path;

/// The session flags an offline pair is opened under: the pair's two
/// files and every default a command line would fill in.
fn session_args(set: &str, program: &str) -> SessionArgs {
    SessionArgs {
        core: testkit::fixture(set, &format!("{program}.snapshot")),
        tokio_info: Some(testkit::fixture(set, &format!("{program}.tinfo"))),
        debug_info: None,
        binary: None,
        force: false,
        best_effort: false,
        runtime: None,
        search_depth: census::Bounds::default().scan_depth,
        audit: false,
    }
}

/// The command list every pair answers. The single-target commands
/// aim at the first task — the listing is sorted by id, so the target
/// is as stable as the fixture — and each entry carries the label its
/// golden file is named with.
fn commands(session: &Session<'_, proc::snapshot::Snapshot>) -> Vec<(&'static str, String)> {
    let mut list = vec![
        ("tasks", "tasks".to_owned()),
        ("tasks-v", "tasks -v".to_owned()),
        ("graph", "graph".to_owned()),
        ("sync", "sync".to_owned()),
        ("census", "census".to_owned()),
        ("runtimes-list", "runtimes --list".to_owned()),
    ];
    if let Some(task) = session.tasks.tasks.first() {
        if let Some(id) = task.task_id {
            list.push(("trace-first", format!("trace {id}")));
        }
        list.push(("whatis-first", format!("whatis {:#x}", task.addr.0)));
    }
    list
}

/// Attach a session over one pair and golden every command's output,
/// one snapshot per (program, set, command).
fn golden(program: &str) {
    for set in FIXTURE_SETS {
        let (bundle, snapshot) = testkit::load(set, program);
        let args = session_args(set, program);
        let session = Session::attach(&snapshot, &bundle, &args)
            .unwrap_or_else(|e| panic!("[{set}] {program}: attach failed: {e:#}"));
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path(Path::new("../tests/offline").join(set));
        settings.set_prepend_module_to_snapshot(false);
        settings.set_omit_expression(true);
        for (label, line) in commands(&session) {
            let command = repl::parse_line(&line)
                .unwrap_or_else(|e| panic!("`{line}` does not parse: {e:#}"));
            let mut out = Vec::new();
            // A command that fails over a snapshot is a fact about
            // what a snapshot can answer, not a broken test: the
            // error text is the golden.
            let text = match dispatch(&session, command, Theme::plain(), &mut out) {
                Ok(_) => String::from_utf8(out).expect("command output is UTF-8"),
                Err(e) => format!("error: {e:#}"),
            };
            settings.set_description(format!("`{line}` over {set}/{program}"));
            settings.bind(|| {
                insta::assert_snapshot!(format!("{program}-{label}"), mask(text.trim_end()));
            });
        }
    }
}

macro_rules! offline_commands {
    ($($name:ident: $program:literal,)*) => {
        $(
            #[test]
            fn $name() {
                golden($program);
            }
        )*
    };
}

// One test per fixture program, over every set — the same population
// `two_binary.rs` reads, inventoried by `testkit::PROGRAMS`.
offline_commands! {
    test_simple_await_commands: "simple-await",
    test_nested_await_commands: "nested-await",
    test_dyn_future_commands: "dyn-future",
    test_futurelock_commands: "futurelock",
    test_sleep_join_commands: "sleep-join",
    test_channels_commands: "channels",
    test_unordered_commands: "unordered",
    test_joinset_commands: "joinset",
    test_ct_runtime_commands: "ct-runtime",
    test_local_set_commands: "local-set",
    test_local_set_timer_commands: "local-set-timer",
    test_local_set_io_commands: "local-set-io",
    test_foreign_runtime_commands: "foreign-runtime",
    test_gen_0007_commands: "gen-0007",
    test_walk_shapes_commands: "walk-shapes",
}

/// The macro above and [`testkit::PROGRAMS`] name the same population:
/// a program added to the capture without a test here would golden
/// nothing, silently.
#[test]
fn test_every_program_has_a_command_golden() {
    const COVERED: &[&str] = &[
        "simple-await",
        "nested-await",
        "dyn-future",
        "futurelock",
        "sleep-join",
        "channels",
        "unordered",
        "joinset",
        "ct-runtime",
        "local-set",
        "local-set-timer",
        "local-set-io",
        "foreign-runtime",
        "gen-0007",
        "walk-shapes",
    ];
    assert_eq!(COVERED, PROGRAMS);
}

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
use hansei_runtime::tokio::{bundle, census};

use std::path::Path;

/// The session flags an offline pair is opened under: the pair's two
/// files and every default a command line would fill in.
pub(crate) fn session_args(set: &str, program: &str) -> SessionArgs {
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
fn commands(
    session: &Session<'_, proc::snapshot::Snapshot>,
    program: &str,
) -> Vec<(&'static str, String)> {
    let mut list = vec![
        ("tasks", "tasks".to_owned()),
        ("tasks-v", "tasks -v".to_owned()),
        // The filter path over a stable field, the grouping path over
        // a value-bearing field, and a grouping whose every row lands
        // in `<empty>` (a parked capture polls nothing, so no task
        // has an lwp).
        ("tasks-with-state", "tasks --with state idle".to_owned()),
        ("tasks-group-waiting", "tasks --group waiting-on".to_owned()),
        ("tasks-group-lwp", "tasks --group lwp".to_owned()),
        // A count field pays the census on the table path; the grouped
        // block form prints each bucket's blocks under its line.
        ("tasks-with-holds", "tasks --with holds >0".to_owned()),
        ("tasks-group-state-v", "tasks --group state -v".to_owned()),
        // The exec loop: each task's heading over the scoped command's
        // output, and — with a command that fails per task — the error
        // in place, the summary line, and the loop's own failure.
        ("tasks-exec-trace", "tasks --exec trace".to_owned()),
        (
            "tasks-exec-fail",
            "tasks --exec type no::such::Type".to_owned(),
        ),
        ("threads", "threads".to_owned()),
        ("threads-v", "threads -v".to_owned()),
        // A frame budget alone implies the block form; both spellings
        // pin the flag plumbing the table/block split rides on.
        ("threads-f", "threads -f 3".to_owned()),
        ("graph", "graph".to_owned()),
        ("sync", "sync".to_owned()),
        ("census", "census".to_owned()),
        ("runtimes-list", "runtimes --list".to_owned()),
    ];
    if let Some(lwp) = session.lwps.first() {
        list.push(("threads-one", format!("threads {}", lwp.tid)));
    }
    if let Some(task) = session.tasks.tasks.first() {
        if let Some(id) = task.task_id {
            list.push(("trace-first", format!("trace {id}")));
        }
        list.push(("whatis-first", format!("whatis {:#x}", task.addr.0)));
        // The cursor commands: select the first task, then drive
        // `print`'s cursor root — the frame itself, one member path,
        // and the missing-member refusal. The selection persists for
        // the commands after it, so these stay in this order.
        if let Some(id) = task.task_id {
            list.push(("task-first", format!("task {id}")));
            list.push(("print-frame", "print".to_owned()));
            if let Some(member) = first_frame_member(session, task) {
                list.push(("print-path", format!("print .{member}")));
            }
            list.push(("print-missing", "print .no_such_member".to_owned()));
            // The fixture whose frame carries containers drives the
            // element steps: a range keeps its [i] heading even one
            // element wide, and a step after a range applies to each
            // map entry.
            if program == "simple-await" {
                list.push(("print-range", "print .values[1..2]".to_owned()));
                list.push(("print-map-values", "print .labels[..2].1".to_owned()));
            }
        }
    }
    list
}

/// The first sized member of the first task's frame-0 payload — a
/// path target every fixture has, whatever its futures hold.
fn first_frame_member(
    session: &Session<'_, proc::snapshot::Snapshot>,
    task: &hansei_runtime::tokio::bundle::Task,
) -> Option<String> {
    let bundle::TaskStage::Running(future) = session.ctx.task_stage(task).ok()? else {
        return None;
    };
    let chain = session.ctx.await_chain(future);
    let frame = chain.frames.first()?;
    let payload = match &frame.state {
        Some(state) => state.payload,
        None => frame.future,
    };
    payload
        .ty
        .members()
        .find(|m| m.ty().size() > 0)
        .map(|m| m.name().to_string())
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
        for (label, line) in commands(&session, program) {
            let command = repl::parse_line(&line)
                .unwrap_or_else(|e| panic!("`{line}` does not parse: {e:#}"));
            let mut out = Vec::new();
            // A command that fails over a snapshot is a fact about
            // what a snapshot can answer, not a broken test: the
            // error text joins whatever the command printed first
            // (`--exec` prints its loop before failing), and the
            // whole is the golden.
            let error = dispatch(&session, command, Theme::plain(), &mut out).err();
            let mut text = String::from_utf8(out).expect("command output is UTF-8");
            if let Some(e) = error {
                text.push_str(&format!("error: {e:#}\n"));
            }
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

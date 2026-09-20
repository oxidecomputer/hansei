// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
        config: Vec::new(),
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
        // The filter path over a stable field, the grouping path over
        // a value-bearing field, and a grouping whose every row lands
        // in `<empty>` (a parked capture polls nothing, so no task
        // has an lwp).
        ("tasks-with-state", "tasks --with state idle".to_owned()),
        // A clause whose argument lists alternatives: either id keeps
        // its row.
        ("tasks-with-ids", "tasks --with id 3,6".to_owned()),
        ("tasks-group-waiting", "tasks --group waiting-on".to_owned()),
        ("tasks-group-lwp", "tasks --group lwp".to_owned()),
        // The waker field: the wakeup overview, with the slot
        // spellings as bucket values and the armed-nothing rows in
        // `<empty>`.
        ("tasks-group-waker", "tasks --group waker".to_owned()),
        // A count field pays the census on the table path.
        ("tasks-with-holds", "tasks --with holds >0".to_owned()),
        // The exec loop: each task's heading over the scoped command's
        // output, and — with a command that fails per task — the error
        // in place, the summary line, and the loop's own failure.
        ("tasks-exec-trace", "tasks --exec trace -n".to_owned()),
        (
            "tasks-exec-fail",
            "tasks --exec type no::such::Type".to_owned(),
        ),
        // The future listing over the same census: the table, the
        // blocks, a grouping at the wait's kind level, a filter on the
        // exact field that splits the two populations, and the exec
        // loop under a cursor scoped to each future's own chain.
        ("futures", "futures".to_owned()),
        (
            "futures-group-waiting",
            "futures --group waiting-on".to_owned(),
        ),
        ("futures-with-kind", "futures --with kind set".to_owned()),
        ("futures-exec-trace", "futures --exec trace -l 1".to_owned()),
        // A run that fails: the error in place, the counting summary,
        // and the loop's own failure — one future is enough to pin it.
        (
            "futures-exec-fail",
            "futures -l 1 --exec type no::such::Type".to_owned(),
        ),
        ("threads", "threads".to_owned()),
        // The thread filters: a grouping at the role's kind level, a
        // grouping with the yes/no split of the polling threads under
        // a negated clause, and the exec loop under a cursor on each
        // surviving thread: succeeding, and failing per thread with
        // the error in place and the counting summary.
        ("threads-group-role", "threads --group role".to_owned()),
        (
            "threads-group-has-task",
            "threads --without role ^worker --group has-task".to_owned(),
        ),
        (
            "threads-exec-trace",
            "threads --with has-task yes --exec trace -l 1".to_owned(),
        ),
        (
            "threads-exec-fail",
            "threads --with has-task yes --exec type no::such::Type".to_owned(),
        ),
        ("graph", "graph".to_owned()),
        ("sync", "sync".to_owned()),
        // One block family alone: the join view of the same listing.
        ("sync-join", "sync --kind join".to_owned()),
        // The by-value fallback's refusal: nothing maps 0x1, so the
        // scan is never entered and the miss names what sync lists.
        ("sync-miss", "sync 0x1".to_owned()),
        // `--kind address` is one address's reading and combines with
        // no block family: refused before the address is looked up.
        ("sync-mixed", "sync 0x1 --kind address,mpsc".to_owned()),
        // The channel families alone: every oneshot, mpsc and watch a
        // parked waker names, with the owner on each side.
        ("channels", "channels".to_owned()),
        ("census", "census".to_owned()),
        // The runtime listing, a grouping over its one string column
        // every fixture fills, and the block of the one runtime — or
        // the refusal, on a fixture holding two.
        ("runtimes", "runtimes".to_owned()),
        (
            "runtimes-group-flavor",
            "runtimes --group flavor".to_owned(),
        ),
        ("runtime", "runtime".to_owned()),
        // The info summary and each section. A snapshot records no
        // process notes and no fd table, so the goldens pin the
        // degraded spellings; objects rows come from the recorded
        // mappings, with every CFI read declined by the capture.
        ("info", "info".to_owned()),
    ];
    // The by-value fallback's hit: a joined task's header is held
    // inside its awaiter's JoinHandle frame, so it is an address every
    // such capture proves the scan can find; --kind address forces the
    // referenced-by reading past the task-allocation answer.
    if let Some(joined) =
        session
            .analysis()
            .waits
            .iter()
            .find_map(|w| match w.verified().map(|v| v.target()) {
                Some(bundle::WaitTarget::Task { addr, .. }) => Some(*addr),
                _ => None,
            })
    {
        list.push(("sync-ref", format!("sync {joined:#x} --kind address")));
    }
    // The future selector, on a set child in flight and on a held
    // future: each roots the cursor at itself and prints its own block.
    if let Some(node) = session
        .census()
        .sets
        .iter()
        .flat_map(|set| &set.children)
        .find(|child| child.root.is_some())
        .map(|child| child.node)
    {
        list.push(("future-child", format!("future {node:#x}")));
    }
    if let Some(held) = session.census().held.first() {
        list.push(("future-held", format!("future {:#x}", held.addr)));
    }
    if let Some(lwp) = session.lwps.first() {
        list.push(("thread-one", format!("thread {}", lwp.tid)));
    }
    if let Some(task) = session.tasks.tasks.first() {
        if let Some(id) = task.task_id {
            list.push(("trace-first", format!("trace {id} -n")));
            // The cut keeps the most recent frame and earns the
            // counting footer.
            list.push(("trace-limit", format!("trace {id} -l 1")));
        }
        list.push(("whatis-first", format!("whatis {:#x}", task.addr.0)));
        // The cursor commands: select the first task, then drive
        // `print` over its frame — the frame itself, one local, and
        // the missing-local refusal. The selection persists for
        // the commands after it, so these stay in this order.
        if let Some(id) = task.task_id {
            list.push(("task-first", format!("task {id}")));
            // The census's finds under the counts the block above
            // carries: what each fixture's first task holds and drives.
            list.push(("children", "children".to_owned()));
            list.push(("print-frame", "print".to_owned()));
            // The same frame's variables, flat: what `locals` lists
            // is what the print above nests as members.
            list.push(("locals", "locals".to_owned()));
            if let Some(member) = first_frame_member(session, task) {
                list.push(("print-path", format!("print {member}")));
            }
            list.push(("print-missing", "print no_such_member".to_owned()));
            // The cursor-scoped sync: every relation the selected
            // task is party to, under the cursor the commands above
            // set.
            list.push(("sync-scoped", "sync".to_owned()));
            if program == "simple-await" {
                // Frame moves carrying a trailing command: `down` at
                // #0 — the leaf, where selection lands — is refused,
                // so its command must not run; `up` lands on #1 and
                // runs it there. `up` moves the cursor the commands
                // above share, so these come after them.
                list.push(("down-locals", "down locals".to_owned()));
                list.push(("up-locals", "up locals".to_owned()));
                // The frame `up` landed on carries the containers that
                // drive the element steps: a range keeps its [i]
                // heading even one element wide, and a step after a
                // range applies to each map entry.
                list.push(("print-range", "print values[1..2]".to_owned()));
                list.push(("print-map-values", "print labels[..2].1".to_owned()));
                // `frame` composes the same way, and the move back to
                // #0 restores the cursor for the commands below.
                list.push(("frame-locals", "frame 0 locals".to_owned()));
            }
        }
    }
    // The holder's three receivers through the mpsc formatter: a channel
    // with messages queued, one whose senders dropped with a message
    // still ahead of the close slot, and one drained before the close.
    // The last two pin that the queued walk stops at the close slot
    // rather than showing its bytes as a message.
    if program == "channels" {
        let holder = session.tasks.tasks.iter().find(|task| {
            matches!(&task.future, bundle::FutureInfo::Known(known)
                if known.display_name.starts_with("channels::hold::"))
        });
        if let Some(id) = holder.and_then(|task| task.task_id) {
            list.push(("task-holder", format!("task {id}")));
            // The cursor lands on the leaf, the parked oneshot; the
            // receivers are locals of the holder's own frame above it.
            list.push(("holder-up", "up".to_owned()));
            list.push(("print-rx", "print _rx".to_owned()));
            list.push(("print-closed-rx", "print _closed_rx".to_owned()));
            list.push(("print-drained-rx", "print _drained_rx".to_owned()));
        }
        // The sender parked in a `select!`: its block lists the three
        // branches — the `send` armed by its acquire, two disabled —
        // and the trace header says the same under the cell.
        let sender = session.tasks.tasks.iter().find(|task| {
            matches!(&task.future, bundle::FutureInfo::Known(known)
                if known.display_name.starts_with("channels::send_waiter::"))
        });
        if let Some(id) = sender.and_then(|task| task.task_id) {
            list.push(("task-sender", format!("task {id}")));
            list.push(("trace-sender", format!("trace {id} -n")));
        }
    }
    // The task polling a `StreamMap` through a `select!` branch: its
    // block lists the map's entries under the branch, each headed by
    // its key — the `&str` the fixture inserted it under.
    if program == "watch-stream" {
        let mapper = session.tasks.tasks.iter().find(|task| {
            matches!(&task.future, bundle::FutureInfo::Known(known)
                if known.display_name.starts_with("watch_stream::mapper"))
        });
        if let Some(id) = mapper.and_then(|task| task.task_id) {
            list.push(("task-mapper", format!("task {id}")));
        }
    }
    // The hyper formatters over every connection the fixture parks:
    // the curated `Conn` record and the role's dispatch under each h1
    // dispatcher the census holds — the idle and the busy client, the
    // idle and the in-flight server — and the version-choosing read on
    // the connection that never spoke.
    if program == "http-conns" {
        // A connection's dispatcher is the leaf of its task's own chain
        // on either side — the wrappers hyper and hyper-util put around
        // it forward to it — so a fresh task cursor stands on it; the
        // connection still choosing its version ends one frame up, at
        // the wrapper reading the first bytes, where the cursor stands
        // on the selected state's payload and the read is its member.
        let client = |member: &str| format!("tasks --with type execute<Pin --exec print {member}");
        let server = |member: &str| {
            format!(
                "tasks --with type http_conns::serve --with waiting-on http1.server --exec print \
                 {member}"
            )
        };
        list.push(("client-conn", client("conn")));
        list.push(("client-dispatch", client("dispatch")));
        list.push(("server-conn", server("conn")));
        list.push(("server-dispatch", server("dispatch")));
        list.push((
            "read-version",
            "tasks --with waiting-on negotiating --exec print read_version".to_owned(),
        ));
        // The connection verdicts in the task blocks on both sides, and
        // a filter matching the `via:` detail line under a client's —
        // text the label line does not carry, so it reaches a filter
        // only because the detail lines do.
        list.push((
            "client-tasks",
            "tasks --with type execute<Pin --exec task".to_owned(),
        ));
        list.push((
            "server-tasks",
            "tasks --with type http_conns::serve --exec task".to_owned(),
        ));
        list.push(("tasks-with-via", "tasks --with waiting-on via:".to_owned()));
    }
    // The register readout under whatever cursor the commands above
    // left: a task no thread is polling refuses, and a thread cursor
    // answers with the lwp's annotated block. One program pins the
    // semantics; they do not vary by fixture.
    if program == "simple-await" {
        list.push(("regs-cursor", "regs".to_owned()));
        if let Some(lwp) = session.lwps.first() {
            list.push(("thread-select", format!("thread {}", lwp.tid)));
            list.push(("regs-thread", "regs".to_owned()));
            // A bare `trace` under the same thread cursor answers
            // with the lwp's native backtrace.
            list.push(("trace-thread", "trace".to_owned()));
        }
    }
    list
}

/// The first member of the first task's frame-0 payload — the leaf,
/// where a fresh task cursor stands — a path target every fixture has,
/// whatever its futures hold. Any member will do, a zero-sized one
/// included: the golden pins that the step lands, not what it finds.
fn first_frame_member(
    session: &Session<'_, proc::snapshot::Snapshot>,
    task: &hansei_runtime::tokio::bundle::Task,
) -> Option<String> {
    let chain = session.task_chain(task)?;
    let frame = chain.frames.last()?;
    let payload = match &frame.state {
        Some(state) => state.payload,
        None => frame.future,
    };
    payload.ty.members().next().map(|m| m.name().to_string())
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
            // `info` prints the fixture pair's absolute paths, which
            // are this machine's; the golden records their roles.
            text = text
                .replace(&args.core.display().to_string(), "<snapshot>")
                .replace(
                    &args.tokio_info.as_deref().unwrap().display().to_string(),
                    "<tokio info>",
                );
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
    test_blocking_pool_commands: "blocking-pool",
    test_delegation_cases_commands: "delegation-cases",
    test_armed_select_commands: "armed-select",
    test_watch_stream_commands: "watch-stream",
    test_http_conns_commands: "http-conns",
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
        "blocking-pool",
        "delegation-cases",
        "armed-select",
        "watch-stream",
        "http-conns",
    ];
    assert_eq!(COVERED, PROGRAMS);
}

/// The wakers the audit holds to the sweep are the ones the registries
/// and the analysis decoded, each with its slot and its task: over
/// sleep-join, the sleeper's wheel entry and the joiner's trailer — and
/// the sweep over the same pair admits every one of them.
#[test]
fn test_registered_wakers_name_the_registries_and_the_joins() {
    let (bundle, snapshot) = testkit::load("illumos", "sleep-join");
    let args = session_args("illumos", "sleep-join");
    let session = Session::attach(&snapshot, &bundle, &args).unwrap();
    let registered: Vec<(&str, u64, u64)> = crate::registered_wakers(&session).collect();
    let of = |what: &str| registered.iter().filter(|r| r.0 == what).count();
    assert_eq!(
        (of("wheel entry"), of("trailer")),
        (1, 1),
        "{registered:#?}"
    );
    let entry = session
        .registries
        .timers
        .iter()
        .find(|t| t.task.is_some())
        .expect("the sleeper's entry");
    assert!(registered.contains(&("wheel entry", entry.waker_at.unwrap(), entry.task.unwrap())));
    let join = &session.analysis().join_wakers[0];
    assert!(registered.contains(&("trailer", join.waker_at.unwrap(), join.waiter.addr.0)));
    assert_eq!(
        session.wakers().audit(registered.iter().copied()),
        Vec::<String>::new()
    );
}

/// A snapshot that claims an allocator index its reads cannot rebuild
/// does not attach: the claim means the capture's discovery and census
/// were gated by that index, and a session that read the same pair
/// ungated would see a population the capture never established. The
/// refusal is the attach's, before anything is gated.
#[test]
fn test_a_snapshot_claiming_an_index_it_cannot_rebuild_does_not_attach() {
    use hansei_bundle::BundleView;
    use proc::snapshot::{RecordedHeapEvidence, Recorder};

    let (bundle, snapshot) = testkit::load("linux", "simple-await");
    // Everything the attach reads, recorded — except an allocator walk,
    // which this capture never made — under the claim that one was.
    let recorder = Recorder::new(&snapshot);
    let ctx = bundle::Context::new(&recorder, BundleView::new(&bundle)).unwrap();
    let list = testkit::tasks(&ctx, &recorder);
    let _ = testkit::census(&ctx, &list);
    let claimed = recorder.snapshot(RecordedHeapEvidence::Available).unwrap();

    let args = session_args("linux", "simple-await");
    let err = match Session::attach(&claimed, &bundle, &args) {
        Ok(_) => panic!("the claim is not honored"),
        Err(e) => e,
    };
    assert!(
        format!("{err:#}").contains("records an allocator index its replay cannot rebuild"),
        "{err:#}"
    );
    // The same reads under the neutral policy attach as the fixture
    // itself does.
    let neutral = {
        let recorder = Recorder::new(&snapshot);
        let ctx = bundle::Context::new(&recorder, BundleView::new(&bundle)).unwrap();
        let list = testkit::tasks(&ctx, &recorder);
        let _ = testkit::census(&ctx, &list);
        recorder
            .snapshot(RecordedHeapEvidence::Unavailable)
            .unwrap()
    };
    let session = Session::attach(&neutral, &bundle, &args).expect("the neutral pair attaches");
    assert!(session.umem().is_none());
}

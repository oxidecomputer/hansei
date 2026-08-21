// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `walk-shapes` fixture pair: hand-written wrapper futures in
//! chain position, a by-value abandoned acquire, a hidden runtime
//! reachable only through a wake queue, and a `LocalSet` anchored in
//! TLS alone. Each test here pins a walk behavior no other fixture
//! reaches; the pair is quarantined from the golden, matrix, and
//! acceptance lists (see the fixture's header).

use hansei_bundle::{Bundle, WalkRole};
use hansei_runtime::testkit::{self, load_any, tasks as tasks_of};
use hansei_runtime::tokio::bundle::{ChainEnd, DiscoveryRoute, FutureInfo, TaskList, TaskStage};
use hansei_runtime::tokio::graph;
use proc::snapshot::Snapshot;

/// The fixture pair, attached the way every offline suite attaches.
fn pair() -> (Bundle, Snapshot) {
    load_any("walk-shapes")
}

/// The one task whose future name contains `name`.
fn task_by_name(list: &TaskList, name: &str) -> usize {
    let hits: Vec<usize> = list
        .tasks
        .iter()
        .enumerate()
        .filter(|(_, t)| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "one task named {name}: {hits:?}");
    hits[0]
}

/// The chain must step through both hand-written wrappers — the plain
/// struct and the named-variant enum — and each step lands at the
/// member's own place: the struct's `inner` past its tag, the enum's
/// `Running` payload past its `repr(C, u8)` discriminant. A step that
/// stops at a wrapper, classifies the named variant as a coroutine
/// state, or mis-adds an offset changes the frames this walks.
#[test]
fn test_the_chain_steps_through_hand_written_wrappers() {
    let (bundle, snapshot) = pair();
    let ctx = testkit::context(&bundle, &snapshot);
    let list = tasks_of(&ctx, &snapshot);
    let chained = &list.tasks[task_by_name(&list, "chained")];
    let TaskStage::Running(root) = ctx.task_stage(chained).unwrap() else {
        panic!("the chained task is parked");
    };
    let chain = ctx.await_chain(root);
    assert!(matches!(chain.end, ChainEnd::Leaf), "{:?}", chain.end);
    let names: Vec<&str> = chain.frames.iter().map(|f| f.future.ty.name()).collect();
    assert_eq!(names.len(), 5, "{names:#?}");
    assert!(names[1].starts_with("walk_shapes::WrapS<"), "{names:#?}");
    assert!(names[2].starts_with("walk_shapes::WrapE<"), "{names:#?}");
    assert!(names[3].contains("::deep::"), "{names:#?}");
    assert!(names[4].contains("Notified"), "{names:#?}");

    // The struct wrapper: a plain frame whose `inner` member is the
    // next frame, one tag past the start.
    let wrap_s = &chain.frames[1];
    assert_eq!(wrap_s.inner, Some("inner"));
    assert!(wrap_s.state.is_none());
    let inner = wrap_s
        .future
        .ty
        .members()
        .find(|m| m.name() == "inner")
        .expect("WrapS declares inner");
    assert!(
        inner.offset() > 0,
        "the witness member must not sit at zero"
    );
    assert_eq!(
        chain.frames[2].future.addr,
        wrap_s.future.addr + inner.offset()
    );

    // The enum wrapper: a named variant, decoded as a frame state.
    // rustc lays every variant payload at the enum's own address and
    // gives the members enum-relative offsets — so the payload starts
    // where the future does, and the discriminant shows up as the
    // members starting past zero instead.
    let wrap_e = &chain.frames[2];
    assert_eq!(wrap_e.inner, Some("inner"));
    let state = wrap_e.state.as_ref().expect("a decoded variant");
    assert_eq!(state.name, "Running");
    assert_eq!(state.payload.addr, wrap_e.future.addr);
    let inner = state
        .payload
        .ty
        .members()
        .find(|m| m.name() == "inner")
        .expect("Running declares inner");
    assert!(
        inner.offset() > 0,
        "the witness member must not sit at zero"
    );
    assert_eq!(
        chain.frames[3].future.addr,
        state.payload.addr + inner.offset()
    );
}

/// The abandoned acquire held *by value*: the analysis derives its
/// waiter node from the frame member's own address, and that node must
/// be the same one a walk from the member reaches independently.
#[test]
fn test_a_by_value_abandoned_acquire_names_its_own_node() {
    let (bundle, snapshot) = pair();
    let ctx = testkit::context(&bundle, &snapshot);
    let list = tasks_of(&ctx, &snapshot);
    let analysis = graph::analyze(&ctx, &list);
    assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);
    let fl = analysis
        .futurelocks
        .iter()
        .find(|fl| fl.acquire.local == "fut")
        .expect("the by-value abandoned acquire is diagnosed");

    // Re-reach the same waiter node from the frame member itself.
    let abandoner = &list.tasks[task_by_name(&list, "abandoner")];
    let TaskStage::Running(root) = ctx.task_stage(abandoner).unwrap() else {
        panic!("the abandoner is parked");
    };
    let chain = ctx.await_chain(root);
    let frame = &chain.frames[0];
    let payload = &frame.state.as_ref().expect("a suspended frame").payload;
    let member = payload
        .ty
        .members()
        .find(|m| m.name() == "fut")
        .expect("the frame holds fut");
    let start = member.offset() as usize;
    let bytes = &payload.bytes[start..start + member.ty().size() as usize];
    let fut = reify::Value::new(member.ty(), payload.addr + member.offset(), bytes);
    let lock_chain = ctx.await_chain(fut);
    assert!(
        matches!(lock_chain.end, ChainEnd::Leaf),
        "{:?}",
        lock_chain.end
    );
    let leaf = lock_chain.frames.last().expect("the acquire leaf");
    let node = ctx
        .walk(WalkRole::AcquireNode)
        .walk_at(leaf.future)
        .expect("the acquire holds its waiter node");
    assert_eq!(fl.acquire.node, node.addr);
}

/// Two local blocks in one population: the `run_until` set and the
/// TLS-anchored side set. Their tasks' groups sit past every
/// runtime's, and apart from each other — misnumbering either folds a
/// local block into a runtime's group.
#[test]
fn test_local_blocks_group_past_the_runtimes() {
    let (bundle, snapshot) = pair();
    let ctx = testkit::context(&bundle, &snapshot);
    let list = tasks_of(&ctx, &snapshot);
    let parker = &list.tasks[task_by_name(&list, "local_parker")];
    let side = &list.tasks[task_by_name(&list, "side_parker")];
    // Two runtimes (the main one and the hidden one), then the local
    // blocks in discovery order.
    let mut groups = [parker.group, side.group];
    groups.sort();
    assert_eq!(groups, [2, 3], "{:#?}", (parker, side));
}

/// The side set is anchored in its thread's TLS and nowhere else: no
/// JoinHandle crosses out of it and it never ran. Its never-polled
/// local task in the listing is the TLS probe's doing, end to end.
#[test]
fn test_the_tls_anchored_set_is_discovered() {
    let (bundle, snapshot) = pair();
    let ctx = testkit::context(&bundle, &snapshot);
    let list = tasks_of(&ctx, &snapshot);
    task_by_name(&list, "side_parker");
}

/// The registry diff, audit, and outcome plumbing hold for this pair
/// the same way `two_binary.rs` holds them for every listed pair; the
/// dedicated assertion here is only that the fixture's census is
/// healthy at all, so the tests above rest on a walk that reported no
/// problems.
#[test]
fn test_the_walk_shapes_census_is_healthy() {
    let (bundle, snapshot) = pair();
    let run = testkit::run(&bundle, &snapshot);
    let problems = run.healthy_problems();
    assert!(problems.is_empty(), "{problems:#?}");
}

/// The hidden runtime is invisible to enumeration — no thread inside,
/// no handle out — and its task arrives only when discovery follows
/// the shared semaphore's wake queue. The registry diff would already
/// fail on the missing task; this pins the route it came through.
#[test]
fn test_the_wake_queue_is_the_hidden_runtimes_only_edge() {
    let (bundle, snapshot) = pair();
    let ctx = testkit::context(&bundle, &snapshot);
    let mut e = testkit::enumerate(&ctx, &snapshot);
    let enumerated = e.runtimes.len();
    assert!(
        !e.list
            .tasks
            .iter()
            .any(|t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains("hidden_blocked"))),
        "the hidden task is enumerated before discovery"
    );
    e.discover(&ctx, &[]);
    let x = &e.list.tasks[task_by_name(&e.list, "hidden_blocked")];
    let rt = &e.runtimes[x.group];
    assert!(x.group >= enumerated, "{:#?}", (x.group, enumerated));
    assert!(
        matches!(rt.route, DiscoveryRoute::QueuedWaker),
        "{:?}",
        rt.route
    );
}

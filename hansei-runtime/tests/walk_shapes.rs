// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `walk-shapes` fixture pair: hand-written wrapper futures in
//! chain position, a by-value abandoned acquire, a hidden runtime
//! reachable only through a wake queue, and a `LocalSet` anchored in
//! TLS alone. Each test here pins a walk behavior no other fixture
//! reaches; the pair is quarantined from the golden, matrix, and
//! acceptance lists (see the fixture's header).

use hansei_bundle::{
    Bundle, BundleType, BundleTypeId, BundleView, FutureTarget, SemanticIssueKind, WalkRole,
};
use hansei_runtime::testkit::Fixture;
use hansei_runtime::testkit::{self, load_any, tasks as tasks_of};
use hansei_runtime::tokio::assess::{ContinuationStatus, WaitAssessment};
use hansei_runtime::tokio::bundle::{
    AwaitChain, ChainEnd, Context, DiscoveryRoute, FutureInfo, OwnerIndex, Registries, Task,
    TaskList, TaskStage, WaitTarget,
};
use hansei_runtime::tokio::chain::InspectionMode;
use hansei_runtime::tokio::graph::{self, BarrierRelation};
use hansei_runtime::tokio::observe::{ReadContext, ReferenceSource, ResourceObservation};

/// The fixture pair, attached the way every offline suite attaches.
fn pair() -> (Bundle, Fixture) {
    load_any("walk-shapes")
}

/// The one task whose future name contains `name`.
fn task_by_name(list: &TaskList, view: BundleView<'_>, name: &str) -> usize {
    let hits: Vec<usize> = list
        .tasks
        .iter()
        .enumerate()
        .filter(|(_, t)| matches!(&t.future, FutureInfo::Known(k) if k.name(view).contains(name)))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "one task named {name}: {hits:?}");
    hits[0]
}

/// The type whose name satisfies `pred`, once.
fn type_by_name<'a>(bundle: &'a Bundle, pred: impl Fn(&str) -> bool) -> BundleType<'a> {
    let view = BundleView::new(bundle);
    let hits: Vec<BundleType<'a>> = (0..bundle.types.types.len() as u32)
        .filter_map(|i| view.ty(BundleTypeId(i)))
        .filter(|ty| pred(ty.name()))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "one such type: {:?}",
        hits.iter().map(|t| t.name()).collect::<Vec<_>>()
    );
    hits[0]
}

/// A listed task's own chain, walked by its programs.
fn chain_of<'a>(ctx: &Context<'a, Fixture>, task: &Task) -> AwaitChain<'a> {
    let TaskStage::Running(root) = ctx.task_root(task, &ReadContext::none()).unwrap() else {
        panic!("the task is parked");
    };
    let lifecycle = task.state.lifecycle();
    ctx.inspect_future(
        root,
        InspectionMode::Task { lifecycle },
        &ReadContext::none(),
    )
    .chain
}

/// The hand-written wrappers, `WrapS` (a plain struct) and `WrapE` (a
/// named-variant enum), are no reviewed implementation: the production
/// context ends the chain at the first with its continuation unknown,
/// and its `inner` — the enum, and the coroutine inside that — stays
/// discoverable rather than being stepped into by shape.
///
/// Under explicit test bindings for the two — a direct delegation
/// through the struct's `inner`, a variant match on the enum whose
/// `Running` case delegates through its `inner` — the same engine
/// steps through both, and each step lands at the member's own place:
/// the struct's `inner` past its tag, the enum's `Running` payload past
/// its `repr(C, u8)` discriminant. The bindings go through the bundle's
/// own validator; a route landing off its recorded target would refuse.
#[test]
fn test_the_chain_steps_through_hand_written_wrappers() {
    let (bundle, core) = pair();
    let ctx = testkit::context(&bundle, &core);
    let list = tasks_of(&ctx, &core);
    let chained = &list.tasks[task_by_name(&list, ctx.view, "chained")];

    // Production: the chain ends at the struct wrapper, unknown.
    let chain = chain_of(&ctx, chained);
    let names: Vec<&str> = chain.frames.iter().map(|f| f.future.ty.name()).collect();
    assert_eq!(names.len(), 2, "{names:#?}");
    assert!(names[1].starts_with("walk_shapes::WrapS<"), "{names:#?}");
    assert!(
        matches!(
            chain.end,
            ChainEnd::UnknownContinuation {
                reason: SemanticIssueKind::NoRule,
                ..
            }
        ),
        "{:?}",
        chain.end
    );
    // What the wrapper holds is still discoverable: the census lists
    // the coroutine inside it, under the wrapper's frame.
    let census = testkit::census(&ctx, &list);
    let owner = task_by_name(&list, ctx.view, "chained");
    assert!(
        census.held.iter().any(|h| h.owner == owner
            && ctx.view.ty(h.future).unwrap().name().contains("::deep::")
            && h.local == "inner"),
        "{:#?}",
        census.held
    );

    // The bindings: one rule of a reviewed forwarding kind under the
    // bundle's compiler origin, and the two records naming it.
    let (bindings, rules) = testkit::walk_shapes_bindings(&bundle);
    let wrap_s = type_by_name(&bundle, |n| {
        n.starts_with("walk_shapes::WrapS<") && !n.contains(">::")
    });
    let deep = type_by_name(&bundle, |n| n.contains("::deep::") && n.ends_with('}'));
    let bound = Context::with_test_bindings(&core, BundleView::new(&bundle), &bindings, &rules)
        .expect("the test bindings validate");
    let chain = chain_of(&bound, chained);
    // Through both wrappers to the coroutine inside, and on to the
    // `Notified` it awaits, the primitive its rule makes of it.
    assert!(matches!(chain.end, ChainEnd::Primitive), "{:?}", chain.end);
    let names: Vec<&str> = chain.frames.iter().map(|f| f.future.ty.name()).collect();
    assert_eq!(names.len(), 5, "{names:#?}");
    assert_eq!(names[4], "tokio::sync::notify::Notified", "{names:#?}");
    assert!(names[1].starts_with("walk_shapes::WrapS<"), "{names:#?}");
    assert!(names[2].starts_with("walk_shapes::WrapE<"), "{names:#?}");
    assert!(names[3].contains("::deep::"), "{names:#?}");
    assert!(names[4].contains("Notified"), "{names:#?}");
    assert_eq!(chain.edges.len(), 4);
    assert!(chain.edges.iter().skip(1).take(2).all(|e| !e.exclusive));

    // The struct wrapper: a plain frame whose `inner` member is the
    // next frame, one tag past the start.
    let wrap_s_frame = &chain.frames[1];
    assert!(wrap_s_frame.state.is_none());
    let inner = wrap_s.member("inner").expect("WrapS declares inner");
    assert!(
        inner.offset() > 0,
        "the witness member must not sit at zero"
    );
    assert_eq!(
        chain.frames[2].future.addr,
        wrap_s_frame.future.addr + inner.offset()
    );

    // The enum wrapper: a named variant, decoded as a frame state.
    // rustc lays every variant payload at the enum's own address and
    // gives the members enum-relative offsets — so the payload starts
    // where the future does, and the discriminant shows up as the
    // members starting past zero instead.
    let wrap_e_frame = &chain.frames[2];
    let state = wrap_e_frame.state.as_ref().expect("a decoded variant");
    assert_eq!(state.name, "Running");
    assert_eq!(state.payload.addr, wrap_e_frame.future.addr);
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

    // A binding whose route lands off its recorded target is refused by
    // the validator, not run.
    use hansei_bundle::{
        Continuation, FutureFacts, MemberRef, PollAction, PollProgram, Step, TypedPath,
    };
    let s_inner = wrap_s
        .member("inner")
        .expect("WrapS declares inner")
        .name_ref();
    let mut wrong = bindings.clone();
    let Some(FutureFacts {
        continuation:
            Continuation::Bound {
                program: PollProgram::Direct(PollAction::Delegate { target, .. }),
                ..
            },
        ..
    }) = &mut wrong[0].future
    else {
        unreachable!()
    };
    *target = FutureTarget::Value(TypedPath {
        steps: vec![Step::Member(MemberRef::Named(s_inner))],
        target: deep.id(),
    });
    assert!(Context::with_test_bindings(&core, BundleView::new(&bundle), &wrong, &rules).is_err());
}

/// The acquire held *by value* in the abandoner's frame is a polling
/// barrier: the abandoner's own chain ends at a `Notified`, complete
/// under its rule with every edge exclusive, so within that chain the
/// acquire — polled once against a waker that wakes nobody, queued and
/// ungranted — is not polled before the `Notify` wakes the task. The
/// victim, queued on the same mutex after it, is behind it in wake
/// order and nothing more. The acquire is also there to inspect: the
/// census lists it under the frame's `fut`, and a held inspection
/// observes it queued on the semaphore, at the node a walk from the
/// member reaches independently.
#[test]
fn test_a_by_value_acquire_behind_a_notified_chain_is_a_barrier() {
    let (bundle, core) = pair();
    let ctx = testkit::context(&bundle, &core);
    let list = tasks_of(&ctx, &core);
    let analysis = graph::analyze(&ctx, &list, &Registries::default(), &ReadContext::none());
    assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);
    let abandoner = &list.tasks[task_by_name(&list, ctx.view, "abandoner")];
    let barrier = analysis
        .barriers
        .iter()
        .position(|b| b.holder == abandoner.addr)
        .unwrap_or_else(|| panic!("{:#?}", analysis.barriers));
    let held_off = &analysis.barriers[barrier];
    assert_eq!(held_off.local, "fut");
    assert_eq!(held_off.owner, Some("tokio::sync::Mutex"));
    assert!(!held_off.granted());
    assert!(held_off.acquire.queued);
    assert_eq!(held_off.acquire.needed, 1);
    assert_eq!(held_off.acquire.queue_position, Some(0));
    assert!(held_off.edges.iter().all(|e| e.exclusive));
    let wait = analysis
        .waits
        .iter()
        .find(|w| w.task.addr == abandoner.addr)
        .unwrap();
    let WaitAssessment::Waiting(verified) = &wait.assessment else {
        panic!("{wait:#?}");
    };
    assert!(
        matches!(verified.target(), WaitTarget::Notify { .. }),
        "{wait:#?}"
    );
    let victim = task_by_name(&list, ctx.view, "victim");
    let behind: Vec<_> = analysis
        .behind()
        .into_iter()
        .map(|b| (b.waiter, b.barrier, b.relation))
        .collect();
    assert_eq!(
        behind,
        vec![(
            analysis
                .waits
                .iter()
                .position(|w| w.task.addr == list.tasks[victim].addr)
                .unwrap(),
            barrier,
            BarrierRelation::QueueOrder
        )]
    );

    // The frame member itself, inspected as a held value.
    let chain = chain_of(&ctx, abandoner);
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
    let held = ctx.inspect_future(fut, InspectionMode::Held, &ReadContext::none());
    assert!(
        matches!(held.chain.end, ChainEnd::Primitive),
        "{:?}",
        held.chain.end
    );
    let Some(ResourceObservation::Acquire(acquire)) = held.primitive.value else {
        panic!(
            "the held future is parked on an acquire: {:?}",
            held.primitive
        );
    };
    assert!(acquire.queued);
    let leaf = held.chain.frames.last().expect("the acquire leaf");
    let node = ctx
        .walk(WalkRole::AcquireNode)
        .walk_at(leaf.future)
        .expect("the acquire holds its waiter node");
    assert_eq!(acquire.node, node.addr);

    // And the census lists it where it is held.
    let census = testkit::census(&ctx, &list);
    let owner = task_by_name(&list, ctx.view, "abandoner");
    let found = census
        .held
        .iter()
        .find(|h| h.owner == owner && h.local == "fut")
        .unwrap_or_else(|| panic!("the census lists `fut`: {:#?}", census.held));
    assert!(
        matches!(found.continuation, ContinuationStatus::Primitive),
        "{found:#?}"
    );
    assert!(
        found
            .waiting_on
            .as_deref()
            .is_some_and(|w| w.contains("semaphore")),
        "{found:#?}"
    );
}

/// Two local blocks in one population: the `run_until` set and the
/// TLS-anchored side set. Their tasks' groups sit past every
/// runtime's, and apart from each other — misnumbering either folds a
/// local block into a runtime's group.
#[test]
fn test_local_blocks_group_past_the_runtimes() {
    let (bundle, core) = pair();
    let ctx = testkit::context(&bundle, &core);
    let mut e = testkit::enumerate(&ctx, &core);
    let sets = e.discover(&ctx, &[]);
    let index = OwnerIndex::new(&e.runtimes, &sets);
    let list = &e.list;
    let parker = &list.tasks[task_by_name(list, ctx.view, "local_parker")];
    let side = &list.tasks[task_by_name(list, ctx.view, "side_parker")];
    // Two runtimes (the main one and the hidden one), then the local
    // blocks in discovery order.
    let mut groups = [index.group_of(parker), index.group_of(side)];
    groups.sort();
    assert_eq!(groups, [Some(2), Some(3)], "{:#?}", (parker, side));
    assert_eq!((index.runtimes(), index.len()), (2, 4));
}

/// The side set is anchored in its thread's TLS and nowhere else: no
/// JoinHandle crosses out of it and it never ran. Its never-polled
/// local task in the listing is the TLS probe's doing, end to end.
#[test]
fn test_the_tls_anchored_set_is_discovered() {
    let (bundle, core) = pair();
    let ctx = testkit::context(&bundle, &core);
    let list = tasks_of(&ctx, &core);
    task_by_name(&list, ctx.view, "side_parker");
}

/// The registry diff, audit, and outcome plumbing hold for this pair
/// the same way `two_binary.rs` holds them for every listed pair; the
/// dedicated assertion here is only that the fixture's census is
/// healthy at all, so the tests above rest on a walk that reported no
/// problems.
#[test]
fn test_the_walk_shapes_census_is_healthy() {
    let (bundle, core) = pair();
    let run = testkit::run(&bundle, &core);
    let problems = run.healthy_problems();
    assert!(problems.is_empty(), "{problems:#?}");
}

/// The hidden runtime is invisible to enumeration — no thread inside,
/// no handle out — and its task arrives only when discovery follows
/// the shared semaphore's wake queue. The registry diff would already
/// fail on the missing task; this pins the route it came through.
#[test]
fn test_the_wake_queue_is_the_hidden_runtimes_only_edge() {
    let (bundle, core) = pair();
    let ctx = testkit::context(&bundle, &core);
    let mut e = testkit::enumerate(&ctx, &core);
    let enumerated = e.runtimes.len();
    assert!(
        !e.list
            .tasks
            .iter()
            .any(|t| matches!(&t.future, FutureInfo::Known(k) if k.name(ctx.view).contains("hidden_blocked"))),
        "the hidden task is enumerated before discovery"
    );
    e.discover(&ctx, &[]);
    let x = &e.list.tasks[task_by_name(&e.list, ctx.view, "hidden_blocked")];
    let owner = x
        .owner
        .known()
        .expect("the hidden task's owner is established");
    let (position, rt) = e
        .runtimes
        .iter()
        .enumerate()
        .find(|(_, r)| r.owner_key() == owner)
        .expect("the owner is an admitted runtime");
    assert!(position >= enumerated, "{:#?}", (position, enumerated));
    assert!(
        matches!(
            rt.route,
            DiscoveryRoute::Scanned(ReferenceSource::SemaphoreWaker)
        ),
        "{:?}",
        rt.route
    );
}

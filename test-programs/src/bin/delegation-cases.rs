// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use tracing::Instrument;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::mpsc::{self, Sender};
use std::task::{Context, Poll, Waker};

const CASES: usize = 12;

// A separate registry records poll behavior independently of the legacy
// census's containment/continuation interpretation. Each row contains root
// address/size, child address/size, parent polls, child polls, expected child
// polls, and the post-poll acknowledgement. testkit reads this exact layout.
#[unsafe(no_mangle)]
static HANSEI_DELEGATION_CASES: [[AtomicU64; 8]; CASES] =
    [const { [const { AtomicU64::new(0) }; 8] }; CASES];

struct Probe<const TAG: u64> {
    case: usize,
    ready: Option<Sender<usize>>,
    tag: u64,
}

impl<const TAG: u64> Future for Probe<TAG> {
    type Output = ();

    #[inline(never)]
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        assert_eq!(self.tag, TAG);
        HANSEI_DELEGATION_CASES[self.case][5].fetch_add(1, SeqCst);
        if let Some(ready) = &self.ready {
            acknowledge(self.case, ready);
        }
        Poll::Pending
    }
}

fn acknowledge(case: usize, ready: &Sender<usize>) {
    HANSEI_DELEGATION_CASES[case][4].fetch_add(1, SeqCst);
    ready.send(case).unwrap();
}

// A non-Future gate leaves exactly one actual future in this wrapper.
struct Gate {
    open: bool,
}

#[repr(C)]
struct Gated<const TAG: u64> {
    gate: Gate,
    child: Probe<TAG>,
    ready: Sender<usize>,
}

impl<const TAG: u64> Future for Gated<TAG> {
    type Output = ();
    #[inline(never)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.gate.open {
            assert!(Pin::new(&mut self.child).poll(cx).is_pending());
        }
        acknowledge(self.child.case, &self.ready);
        Poll::Pending
    }
}

#[repr(C, u8)]
enum Retained {
    Parked {
        child: Probe<3>,
        ready: Sender<usize>,
    },
    #[allow(dead_code)]
    Complete,
}

impl Future for Retained {
    type Output = ();
    #[inline(never)]
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if let Self::Parked { child, ready } = &*self {
            acknowledge(child.case, ready);
        }
        Poll::Pending
    }
}

struct RawHolder {
    child: *mut Probe<4>,
    ready: Sender<usize>,
}

// SAFETY: the pointee is leaked and never accessed through this pointer.
unsafe impl Send for RawHolder {}

impl Future for RawHolder {
    type Output = ();
    #[inline(never)]
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        std::hint::black_box(self.child);
        acknowledge(3, &self.ready);
        Poll::Pending
    }
}

// A hand-written future holding a boxed future it never polls, beside
// a zero-sized one. The box is an owned adapter and no future of its
// own (its pointee is not `Unpin`), so what the census lists is the
// pointee, where the box points; the zero-sized member is storage the
// scan must not offer as a local.
struct Holder<F> {
    held: Box<F>,
    idle: std::future::Pending<()>,
    ready: Sender<usize>,
}

impl<F: Future> Future for Holder<F> {
    type Output = ();
    #[inline(never)]
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        // Name the pointee's `poll` without calling it: a future nothing
        // ever polls has no `poll` in the binary, and the box over it
        // would then wrap no known future at all.
        std::hint::black_box(
            <F as Future>::poll as fn(Pin<&mut F>, &mut Context<'_>) -> Poll<F::Output>,
        );
        std::hint::black_box(&self.idle);
        acknowledge(8, &self.ready);
        Poll::Pending
    }
}

// A hand-written future holding another task's `JoinHandle` behind a
// pinned box of `dyn Future`: a resource reached only through an
// adapter, never by value.
struct Handle {
    handle: Pin<Box<dyn Future<Output = Result<(), tokio::task::JoinError>> + Send>>,
    ready: Sender<usize>,
}

impl Future for Handle {
    type Output = ();
    #[inline(never)]
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        // Name the pin's `poll` without calling it, as `Holder` does.
        std::hint::black_box(
            <Pin<Box<dyn Future<Output = Result<(), tokio::task::JoinError>> + Send>> as Future>::poll
                as fn(_, &mut Context<'_>) -> Poll<Result<(), tokio::task::JoinError>>,
        );
        std::hint::black_box(&self.handle);
        acknowledge(9, &self.ready);
        Poll::Pending
    }
}

// The probe behind a second dyn hop. `Probe`'s drop glue is one function
// for every `TAG`, and the linker folds identical glue into one symbol,
// so a `Probe` here would join its vtable's drop slot to `Probe<7>`'s
// and the hop would be ambiguous; a member with a drop of its own keeps
// this glue distinct.
struct Leaf {
    case: usize,
    ready: Sender<usize>,
    name: String,
}

impl Future for Leaf {
    type Output = ();

    #[inline(never)]
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        std::hint::black_box(&self.name);
        HANSEI_DELEGATION_CASES[self.case][5].fetch_add(1, SeqCst);
        acknowledge(self.case, &self.ready);
        Poll::Pending
    }
}

fn register<F: Future<Output = ()> + Send + 'static>(
    rt: &tokio::runtime::Runtime,
    case: usize,
    root: Pin<Box<F>>,
    child: (u64, u64),
    expected: u64,
) -> tokio::task::JoinHandle<()> {
    let row = &HANSEI_DELEGATION_CASES[case];
    row[0].store((&*root as *const F) as u64, SeqCst);
    row[1].store(std::mem::size_of::<F>() as u64, SeqCst);
    row[2].store(child.0, SeqCst);
    row[3].store(child.1, SeqCst);
    row[6].store(expected, SeqCst);
    rt.spawn(root)
}

fn location<T>(value: &T) -> (u64, u64) {
    (value as *const T as u64, std::mem::size_of::<T>() as u64)
}

fn main() {
    test_programs::allow_any_tracer();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (ready, receive) = mpsc::channel();
    let mut tasks = Vec::new();

    let gated = Box::pin(Gated {
        gate: Gate { open: false },
        child: Probe::<1> {
            case: 0,
            ready: None,
            tag: 1,
        },
        ready: ready.clone(),
    });
    let child = location(&gated.child);
    // Ground truth for the census diff: no rule covers the gate, so its
    // chain ends there and the initialized child inside it is a held
    // find of the task's root frame — discoverable, never polled.
    test_programs::census_expect::held(child.0, "delegation_cases::Probe");
    tasks.push(register(&rt, 0, gated, child, 0));

    let mut previous = Box::pin(Gated {
        gate: Gate { open: true },
        child: Probe::<2> {
            case: 1,
            ready: None,
            tag: 2,
        },
        ready: ready.clone(),
    });
    // Poll at the final pinned address, then close the gate. The scheduled
    // poll retains the initialized child without polling it again.
    assert!(
        previous
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(receive.recv().unwrap(), 1);
    previous.gate.open = false;
    let child = location(&previous.child);
    test_programs::census_expect::held(child.0, "delegation_cases::Probe");
    tasks.push(register(&rt, 1, previous, child, 1));

    let retained = Box::pin(Retained::Parked {
        child: Probe::<3> {
            case: 2,
            ready: None,
            tag: 3,
        },
        ready: ready.clone(),
    });
    let child = match &*retained {
        Retained::Parked { child, .. } => location(child),
        _ => unreachable!(),
    };
    tasks.push(register(&rt, 2, retained, child, 0));

    let raw = Box::leak(Box::new(Probe::<4> {
        case: 3,
        ready: None,
        tag: 4,
    }));
    let child = location(raw);
    tasks.push(register(
        &rt,
        3,
        Box::pin(RawHolder {
            child: raw,
            ready: ready.clone(),
        }),
        child,
        0,
    ));

    let reference = Box::leak(Box::new(Probe::<5> {
        case: 4,
        ready: Some(ready.clone()),
        tag: 5,
    }));
    let child = location(reference);
    tasks.push(register(&rt, 4, Box::pin(reference), child, 1));

    let boxed = Box::new(Probe::<6> {
        case: 5,
        ready: Some(ready.clone()),
        tag: 6,
    });
    let child = location(&*boxed);
    tasks.push(register(&rt, 5, Box::pin(boxed), child, 1));

    let dynamic = Box::pin(Probe::<7> {
        case: 6,
        ready: Some(ready.clone()),
        tag: 7,
    });
    let child = location(&*dynamic);
    let dynamic: Pin<Box<dyn Future<Output = ()> + Send>> = dynamic;
    tasks.push(register(&rt, 6, Box::pin(dynamic), child, 1));

    let instrumented = Box::pin(
        Probe::<8> {
            case: 7,
            ready: Some(ready.clone()),
            tag: 8,
        }
        .instrument(tracing::Span::none()),
    );
    let child = location(instrumented.inner());
    tasks.push(register(&rt, 7, instrumented, child, 1));

    // A never-polled async block behind a plain box: listed where the
    // box points, and its one capture is a local the layout cannot
    // vouch for until the block is first polled.
    let tag = 8u64;
    let holder = Holder {
        held: Box::new(async move {
            std::hint::black_box(tag);
            std::future::pending::<()>().await;
        }),
        idle: std::future::pending(),
        ready: ready.clone(),
    };
    let child = location(&*holder.held);
    test_programs::census_expect::held(child.0, "delegation_cases::main::{async_block");
    let holder = register(&rt, 8, Box::pin(holder), child, 0);

    // The holder's own `JoinHandle`, behind a pinned box of `dyn
    // Future`: a held find whose chain ends in the handle.
    let joined = Box::pin(holder);
    let child = location(&*joined);
    let handle = Box::pin(Handle {
        handle: joined,
        ready: ready.clone(),
    });
    // A find held by value is keyed by its slot: the pin in the frame,
    // not the handle it points at.
    test_programs::census_expect::held(
        &handle.handle as *const _ as u64,
        "tokio::runtime::task::join::JoinHandle",
    );
    tasks.push(register(&rt, 9, handle, child, 0));

    // An async block reached only through a dyn hop — nothing delegates
    // to it statically — awaiting the pinned box of `dyn Future` it
    // captured. The block's own states are all that prove the box a
    // future, so the box carries a record and the chain crosses it to
    // the probe behind it.
    let boxed: Pin<Box<dyn Future<Output = ()> + Send + Sync>> = Box::pin(Leaf {
        case: 11,
        ready: ready.clone(),
        name: String::from("leaf"),
    });
    let dynamic = Box::pin(async move { boxed.await });
    let child = location(&*dynamic);
    let dynamic: Pin<Box<dyn Future<Output = ()> + Send>> = dynamic;
    tasks.push(register(&rt, 11, Box::pin(dynamic), child, 1));

    // A pinned box awaited through `as_mut()`: the awaitee is a `Pin`
    // reference to the boxed block, and the box itself sits in the
    // root's locals pointing at a frame of the root's own chain — an
    // alias of the chain, not a future held beside it. It is rebound
    // as a body local because a capture, once the block is polled, is
    // storage the layout cannot vouch for and the census does not
    // read. The zero-sized future carried across the await is a
    // layout local the scan must not offer.
    let tag = 10u64;
    let inner = Box::pin(async move {
        std::hint::black_box(tag);
        std::future::pending::<()>().await;
    });
    let child = location(&*inner);
    let alias = async move {
        let mut inner = inner;
        let idle = std::future::pending::<()>();
        acknowledge(10, &ready);
        inner.as_mut().await;
        let _ = std::hint::black_box(idle);
    };
    tasks.push(register(&rt, 10, Box::pin(alias), child, 0));

    let handle = rt.handle().clone();
    std::thread::spawn(move || rt.block_on(std::future::pending::<()>()));
    let mut seen = [false; CASES];
    for _ in 0..CASES {
        let case = receive.recv().unwrap();
        assert!(!seen[case]);
        seen[case] = true;
    }
    // This task cannot run on the sole executor until every poll that sent
    // readiness has returned. A retained, unfinished task then proves Pending;
    // a send from inside poll alone would not establish that transition.
    let (after, polled) = mpsc::channel();
    handle.spawn(async move {
        after.send(()).unwrap();
    });
    polled.recv().unwrap();
    assert!(tasks.iter().all(|task| !task.is_finished()));
    for (case, row) in HANSEI_DELEGATION_CASES.iter().enumerate() {
        assert_eq!(row[4].load(SeqCst), if case == 1 { 2 } else { 1 });
        assert_eq!(row[5].load(SeqCst), row[6].load(SeqCst));
        row[7].store(1, SeqCst);
    }
    test_programs::census_expect::task("delegation_cases::Gated<1>");
    println!("READY");
    let (_hold, park) = mpsc::channel::<()>();
    park.recv().unwrap();
}

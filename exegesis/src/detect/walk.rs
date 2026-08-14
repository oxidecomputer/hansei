//! The walk-contract binder: resolve every navigation hansei's runtime
//! walk executes against this target's own DWARF, at extraction, and
//! record the bound paths in the bundle's [`WalksTable`] as data.
//!
//! The declarative table here is the walk contract's spelling problem —
//! which member chains reach tokio's runtime data, per tokio version —
//! solved once, beside the formatter detectors that encode the same
//! layout facts and with the same [`Family`]/[`Row`] dispatch. Binding
//! happens where the layout is ground truth: each role's spelling is
//! tried against the target's DWARF with the [`Emitter`]'s own
//! navigation, lowered to fully explicit name-addressed [`Step`]s (every
//! wrapper level a step — the runtime walker executes them literally),
//! verified against the role's terminal shape, and recorded with its
//! outcome. Failure is recorded, never fatal: a non-tokio binary or an
//! `--allow-missing-infra` extraction records absent/broken outcomes and
//! extraction proceeds; refusing is the consumer's decision, applied
//! against the recorded outcomes at attach time.
//!
//! A spelling that changes here means re-extracting to re-diagnose a
//! target — the same loop formatter work already uses (`--explain-walk`
//! is the walk's `--explain-format`).

use super::ReachStep::{Deref, FindParam, Named, PeelTo, Variant};
use super::{
    Family, Reach, Row, WORD, aggregate_members, raw_variants, reach, step_into, tokio_v1_47,
    tokio_v1_49, tokio_v1_53, trace, type_label,
};
use crate::bundle::{
    BundleTypeId, Selector, Shape, Step, StringInterner, WalkBinding, WalkOutcome, WalkRole,
    WalksTable,
};
use crate::extract::Emitter;
use crate::raw_types::{Encoding, RawType};
use crate::{DwReader, TypeId};

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Leaf keys
// ---------------------------------------------------------------------------

/// `tokio::time::Sleep`'s leaf future.
const SLEEP: &str = "tokio::time::sleep::Sleep";
/// A join edge to another task.
const JOIN_HANDLE: &str = "tokio::runtime::task::join::JoinHandle<";
/// The future queued on the semaphore backing Mutex/RwLock/Semaphore.
const ACQUIRE: &str = "tokio::sync::batch_semaphore::Acquire";
/// The by-value type every `FuturesUnordered` is recognized as.
const FUTURES_UNORDERED: &str = "futures_util::stream::futures_unordered::FuturesUnordered<";
/// The by-value type every join set is recognized as.
const JOIN_SET: &str = "tokio::task::join_set::JoinSet<";
/// A `LocalSet`'s shared state — the root of its own task list. Reached
/// transitively from local task cells (whose scheduler `S` is
/// `Arc<Shared>`) and emitted by name for a set nothing was spawned onto.
const LOCAL_SHARED: &str = "tokio::task::local::Shared";
/// The `task::local::CURRENT` thread-local's payload, emitted by name —
/// nothing else references it.
const LOCAL_DATA: &str = "tokio::task::local::LocalData";
/// The two-word waker pair every registered waker in the walk lands on,
/// wherever it was registered.
const RAW_WAKER: &str = "core::task::wake::RawWaker";

/// Whether `name` is a type a leaf key names. A key ending in `<` is a
/// generic: the prefix of every monomorphization's name. Any other key
/// is an exact fully-qualified name — a bare prefix match would take
/// lookalike siblings with it (`batch_semaphore::Acquire` is one
/// character away from `AcquireError`).
fn leaf_matches(key: &str, name: &str) -> bool {
    if key.ends_with('<') {
        name.starts_with(key)
    } else {
        name == key
    }
}

// ---------------------------------------------------------------------------
// The declarative table
// ---------------------------------------------------------------------------

/// The shape a bound navigation's terminal type must have. Coarse on
/// purpose: byte offsets differ across versions and are not the contract;
/// the name chain and the terminal shape are.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Terminal {
    /// An integer of at most a machine word (bools included).
    Word,
    /// A pointer (data or function).
    Pointer,
    /// A Rust enum.
    Enum,
    /// A struct or union.
    Aggregate,
    /// A boxed slice: a `data_ptr` pointer and a `length`, walkable
    /// element by element.
    Slice,
    /// A fixed-size array, walkable element by element.
    Array,
    /// No shape requirement; the consumer's parsing decides.
    Any,
}

/// A build capability a role's datum exists under. When the capability is
/// recorded off in the bundle's meta, the role failing to bind is the
/// expected shape of that target (recorded [`WalkOutcome::Absent`]), not
/// drift. An unrecorded capability keeps breakage loud.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Capability {
    /// `--cfg tokio_unstable` task instrumentation.
    TokioUnstable,
    /// The multi_thread scheduler (`rt-multi-thread`), probed
    /// structurally: whether its `Handle` type is in the DWARF.
    MultiThreadScheduler,
    /// The current_thread scheduler, probed the same way. Always
    /// compiled with tokio's `rt` feature, so an absence in practice
    /// means a very old or unusual tokio.
    CurrentThreadScheduler,
}

/// The infra roots the table navigates below.
#[derive(Copy, Clone, Debug)]
enum InfraRoot {
    Context,
    Header,
    Trailer,
    Vtable,
    Location,
    MtHandle,
    CtHandle,
}

/// Where a role's navigation starts.
#[derive(Copy, Clone, Debug)]
enum WalkRoot {
    /// One of the types extraction located as infrastructure.
    Infra(InfraRoot),
    /// Every scheduler-flavor `Handle` the target compiled in — the
    /// union root for the rows both flavors spell identically
    /// (`shared`, the blocking-pool chain). The present subset resolves
    /// with a note naming any absent flavor; a target with neither is
    /// broken the way a missing infra root is.
    AnyHandle,
    /// Every emitted type a leaf key names ([`leaf_matches`]). None in
    /// the bundle is an expected absence — the target does not use the
    /// primitive — not a breakage.
    Leaf(&'static str),
    /// The (non-opaque) `Cell<T, S>` of every entry in the task table.
    TaskCells,
    /// Where another role's binding landed.
    End(WalkRole),
    /// The pointee of the pointer another role's binding landed on.
    Pointee(WalkRole),
    /// The element of the sequence another role's binding landed on — a
    /// boxed slice's `data_ptr` target, or a fixed-size array's element.
    /// The read side iterates either with the same `elements()` call, so
    /// both root a child row here.
    Elem(WalkRole),
}

/// The ordered alternative spellings of one role, produced on demand.
/// A function rather than data so a [`Row`] over it can live in a static —
/// exactly how the detector tables dispatch — with the versioned entries'
/// spellings declared in the family modules beside the formatter reaches
/// that navigate the same layouts.
type Spellings = fn() -> Vec<Reach<'static>>;

/// One declared navigation: a role, where it roots, the family-dispatched
/// spellings (ordered alternatives are reserved for divergence a version
/// cannot select — a build-feature or cfg difference within one release),
/// and the shape the landing type must have.
struct WalkDecl {
    role: WalkRole,
    root: WalkRoot,
    spellings: Row<Spellings>,
    terminal: Terminal,
    /// The capability the datum exists under, for the ones that are
    /// build-conditional; `None` for the paths every build has.
    needs: Option<Capability>,
}

fn decl(role: WalkRole, root: WalkRoot, terminal: Terminal, spellings: Spellings) -> WalkDecl {
    WalkDecl {
        role,
        root,
        terminal,
        spellings: Row::All(spellings),
        needs: None,
    }
}

/// A [`decl`] whose datum exists only under one scheduler flavor: its
/// breakage is the expected shape of a target that did not compile the
/// flavor in. Rows chained below one inherit the absence through their
/// root, so only the top of each flavor-specific chain declares it.
fn flavor_decl(
    role: WalkRole,
    root: WalkRoot,
    terminal: Terminal,
    needs: Capability,
    spellings: Spellings,
) -> WalkDecl {
    WalkDecl {
        role,
        root,
        terminal,
        spellings: Row::All(spellings),
        needs: Some(needs),
    }
}

/// The one versioned row: tokio restructured where `Sleep` keeps its
/// deadline in 1.49 and again in 1.53, and each family module declares
/// its spelling beside its timer formatter builders.
static SLEEP_DEADLINE_SPELLINGS: [(Family, Spellings); 3] = [
    (Family::V1_47, tokio_v1_47::sleep_deadline_walk),
    (Family::V1_49, tokio_v1_49::sleep_deadline_walk),
    (Family::V1_53, tokio_v1_53::sleep_deadline_walk),
];

/// The other versioned row: `time::Inner` became an enum over the driver
/// flavor in 1.49, so the chain from a scheduler handle to the timer
/// wheel's levels crosses one step more from that release on. Two entries
/// rather than three because 1.53 left the driver chain alone and a
/// versioned row takes the highest floor at or below the target — a
/// `v1_53` entry here would only restate `v1_49`'s spelling, and a future
/// release that does move the chain is the one that earns a third.
/// Everything below this row — `Level`, its slots, and the `TimerShared`
/// nodes they link — has held identically across the supported range.
static WHEEL_LEVELS_SPELLINGS: [(Family, Spellings); 2] = [
    (Family::V1_47, tokio_v1_47::wheel_levels_walk),
    (Family::V1_49, tokio_v1_49::wheel_levels_walk),
];

/// Every walk declaration, in [`WalkRole::ALL`] order — the report's
/// order, which a test pins.
///
/// Spellings are literal: every wrapper level the old runtime interpreter
/// peeled implicitly is a step here (`value`/`__0` cell chains, `Arc`'s
/// `ptr.pointer`), with [`PeelTo`]/[`FindParam`] where the wrappers vary
/// by build (atomic shims, the loom mutex flavors).
fn decls() -> Vec<WalkDecl> {
    use Terminal::{Aggregate, Any, Array, Enum, Pointer, Slice, Word};
    use WalkRoot::{Elem, End, Infra, Leaf, Pointee, TaskCells};

    vec![
        // Runtime discovery: the thread-local `Context` down to the
        // multi_thread scheduler's shared state.
        decl(
            WalkRole::CurrentTaskId,
            Infra(InfraRoot::Context),
            Any,
            || {
                vec![reach![
                    Named("current_task_id"),
                    Named("value"),
                    Named("value"),
                ]]
            },
        ),
        // Which thread the runtime takes this one for — tokio's own
        // NonZeroU64 counter, the same `Cell<Option<…>>` shape as the
        // task id above. It is what joins a `LocalSet`'s recorded owner
        // to an LWP.
        decl(
            WalkRole::ContextThreadId,
            Infra(InfraRoot::Context),
            Any,
            || vec![reach![Named("thread_id"), Named("value"), Named("value")]],
        ),
        flavor_decl(
            WalkRole::WorkerHandle,
            Infra(InfraRoot::Context),
            Aggregate,
            Capability::MultiThreadScheduler,
            || {
                vec![reach![
                    Named("current"),
                    Named("handle"),
                    Named("value"),
                    Named("value"),
                    Variant("Some"),
                    Named("__0"),
                    Variant("MultiThread"),
                    Named("__0"),
                    Named("ptr"),
                    Named("pointer"),
                    Deref,
                    Named("data"),
                ]]
            },
        ),
        // The current_thread sibling: the same chain crossing the other
        // flavor's variant. A separate role because the variant step
        // names differ; everything below the flavor handles is shared.
        flavor_decl(
            WalkRole::CtWorkerHandle,
            Infra(InfraRoot::Context),
            Aggregate,
            Capability::CurrentThreadScheduler,
            || {
                vec![reach![
                    Named("current"),
                    Named("handle"),
                    Named("value"),
                    Named("value"),
                    Variant("Some"),
                    Named("__0"),
                    Variant("CurrentThread"),
                    Named("__0"),
                    Named("ptr"),
                    Named("pointer"),
                    Deref,
                    Named("data"),
                ]]
            },
        ),
        flavor_decl(
            WalkRole::WorkerContext,
            Infra(InfraRoot::Context),
            Aggregate,
            Capability::MultiThreadScheduler,
            || {
                vec![reach![
                    Named("scheduler"),
                    Named("inner"),
                    Named("value"),
                    Named("value"),
                    Deref,
                    Variant("MultiThread"),
                    Named("__0"),
                ]]
            },
        ),
        // The CT analog of "this thread is inside the scheduler": the
        // `block_on` thread's `current_thread::Context`.
        flavor_decl(
            WalkRole::CtWorkerContext,
            Infra(InfraRoot::Context),
            Aggregate,
            Capability::CurrentThreadScheduler,
            || {
                vec![reach![
                    Named("scheduler"),
                    Named("inner"),
                    Named("value"),
                    Named("value"),
                    Deref,
                    Variant("CurrentThread"),
                    Named("__0"),
                ]]
            },
        ),
        decl(
            WalkRole::WorkerIndex,
            End(WalkRole::WorkerContext),
            Word,
            || {
                vec![reach![
                    Named("worker"),
                    Named("ptr"),
                    Named("pointer"),
                    Deref,
                    Named("data"),
                    Named("index"),
                ]]
            },
        ),
        // The CT scheduler's core, when it is checked *in*: the run loop
        // stores it in the context's `RefCell` while it parks the driver
        // or polls the `block_on` future, and takes it back out to run
        // tasks — so an inactive `Some` here means the thread is inside
        // the scheduler with the core on its stack.
        decl(
            WalkRole::CtWorkerCore,
            End(WalkRole::CtWorkerContext),
            Aggregate,
            || {
                vec![reach![
                    Named("core"),
                    Named("value"),
                    Named("value"),
                    Variant("Some"),
                    Named("__0"),
                    Deref,
                ]]
            },
        ),
        // The driver is moved out of the core for exactly as long as the
        // thread parks in it, so this member's presence distinguishes
        // "polling the block_on future" from "parked in the driver" when
        // the core above is checked in.
        decl(
            WalkRole::CtCoreDriver,
            End(WalkRole::CtWorkerCore),
            Aggregate,
            || vec![reach![Named("driver"), Variant("Some"), Named("__0")]],
        ),
        // Both flavor handles spell `shared` — one binding serves every
        // handle the target compiled in, and the task walk below roots
        // at whichever `Shared` a discovered handle actually has.
        decl(
            WalkRole::HandleShared,
            WalkRoot::AnyHandle,
            Aggregate,
            || vec![reach![Named("shared")]],
        ),
        // Parkers: every worker's state word and the io driver's lock,
        // reached through the `Unparker`s hanging off the shared state.
        // MT-only, so rooted at the MT handle rather than at
        // `HandleShared`, whose union root also lands on the CT `Shared`
        // (which has no `remotes` to bind).
        flavor_decl(
            WalkRole::SharedRemotes,
            Infra(InfraRoot::MtHandle),
            Slice,
            Capability::MultiThreadScheduler,
            || vec![reach![Named("shared"), Named("remotes")]],
        ),
        decl(
            WalkRole::RemoteUnpark,
            Elem(WalkRole::SharedRemotes),
            Aggregate,
            || {
                vec![reach![
                    Named("unpark"),
                    Named("inner"),
                    Named("ptr"),
                    Named("pointer"),
                    Deref,
                    Named("data"),
                ]]
            },
        ),
        decl(
            WalkRole::ParkerState,
            End(WalkRole::RemoteUnpark),
            Word,
            || vec![reach![Named("state"), PeelTo(WORD)]],
        ),
        decl(
            WalkRole::ParkerDriverLock,
            End(WalkRole::RemoteUnpark),
            Word,
            || {
                vec![reach![
                    Named("shared"),
                    Named("ptr"),
                    Named("pointer"),
                    Deref,
                    Named("data"),
                    Named("driver"),
                    Named("locked"),
                    PeelTo(Shape::Uint(1)),
                ]]
            },
        ),
        // Whether the CT runtime's `block_on` future has a wakeup
        // pending — the CT sibling of the parker states, rooted at the
        // CT handle because only its `Shared` carries the member.
        flavor_decl(
            WalkRole::CtSharedWoken,
            Infra(InfraRoot::CtHandle),
            Word,
            Capability::CurrentThreadScheduler,
            || {
                vec![reach![
                    Named("shared"),
                    Named("woken"),
                    PeelTo(Shape::Uint(1)),
                ]]
            },
        ),
        // The blocking pool's own counters. Both flavor handles spell
        // the whole chain identically, so the union root serves here too.
        decl(
            WalkRole::BlockingMetrics,
            WalkRoot::AnyHandle,
            Aggregate,
            || {
                vec![reach![
                    Named("blocking_spawner"),
                    Named("inner"),
                    Named("ptr"),
                    Named("pointer"),
                    Deref,
                    Named("data"),
                    Named("metrics"),
                ]]
            },
        ),
        decl(
            WalkRole::BlockingThreads,
            End(WalkRole::BlockingMetrics),
            Any,
            || vec![reach![Named("num_threads"), PeelTo(WORD)]],
        ),
        decl(
            WalkRole::BlockingIdle,
            End(WalkRole::BlockingMetrics),
            Any,
            || vec![reach![Named("num_idle_threads"), PeelTo(WORD)]],
        ),
        decl(
            WalkRole::BlockingQueueDepth,
            End(WalkRole::BlockingMetrics),
            Any,
            || vec![reach![Named("queue_depth"), PeelTo(WORD)]],
        ),
        // Task enumeration: `Shared.owned`'s sharded intrusive lists, the
        // `Header` each node is, and the `Trailer.owned` link to the next.
        decl(
            WalkRole::OwnedLists,
            End(WalkRole::HandleShared),
            Slice,
            || vec![reach![Named("owned"), Named("list"), Named("lists")]],
        ),
        // The id the global owned-list counter gave this scheduler's
        // list — what `Header.owner_id` joins, exactly as
        // `LocalOwnedId` is for a `LocalSet`'s list. It sits beside
        // `owned.list`, so a runtime reached from a task's own cell can
        // be held to claiming that task.
        decl(
            WalkRole::SchedulerOwnedId,
            End(WalkRole::HandleShared),
            Word,
            || vec![reach![Named("owned"), Named("id"), PeelTo(WORD)]],
        ),
        decl(
            WalkRole::ShardHead,
            Elem(WalkRole::OwnedLists),
            Pointer,
            || {
                vec![reach![
                    FindParam,
                    Named("head"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(
            WalkRole::HeaderState,
            Infra(InfraRoot::Header),
            Word,
            || vec![reach![Named("state"), PeelTo(WORD)]],
        ),
        // `owner_id` is a loom cell over `Option<NonZero<u64>>`: the cell
        // levels are spelled (a peel cannot cross the niche enum inside),
        // and the walk lands on the `Option` itself.
        decl(
            WalkRole::HeaderOwnerId,
            Infra(InfraRoot::Header),
            Any,
            || vec![reach![Named("owner_id"), Named("__0"), Named("value")]],
        ),
        decl(
            WalkRole::HeaderVtable,
            Infra(InfraRoot::Header),
            Pointer,
            || vec![reach![Named("vtable")]],
        ),
        decl(
            WalkRole::TrailerNext,
            Infra(InfraRoot::Trailer),
            Pointer,
            || {
                vec![reach![
                    Named("owned"),
                    Named("inner"),
                    Named("value"),
                    Named("next"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        // The task `Vtable` — `#[repr(Rust)]`, so every offset the walk
        // uses must be read from the target through this layout.
        decl(
            WalkRole::VtablePoll,
            Infra(InfraRoot::Vtable),
            Pointer,
            || vec![reach![Named("poll")]],
        ),
        decl(
            WalkRole::VtableTrailerOffset,
            Infra(InfraRoot::Vtable),
            Word,
            || vec![reach![Named("trailer_offset")]],
        ),
        decl(
            WalkRole::VtableIdOffset,
            Infra(InfraRoot::Vtable),
            Word,
            || vec![reach![Named("id_offset")]],
        ),
        decl(
            WalkRole::VtableDealloc,
            Infra(InfraRoot::Vtable),
            Pointer,
            || vec![reach![Named("dealloc")]],
        ),
        decl(
            WalkRole::VtableTryReadOutput,
            Infra(InfraRoot::Vtable),
            Pointer,
            || vec![reach![Named("try_read_output")]],
        ),
        decl(
            WalkRole::VtableDropJoinHandleSlow,
            Infra(InfraRoot::Vtable),
            Pointer,
            || vec![reach![Named("drop_join_handle_slow")]],
        ),
        decl(
            WalkRole::VtableDropAbortHandle,
            Infra(InfraRoot::Vtable),
            Pointer,
            || vec![reach![Named("drop_abort_handle")]],
        ),
        decl(
            WalkRole::VtableShutdown,
            Infra(InfraRoot::Vtable),
            Pointer,
            || vec![reach![Named("shutdown")]],
        ),
        WalkDecl {
            role: WalkRole::VtableSpawnLocationOffset,
            root: Infra(InfraRoot::Vtable),
            terminal: Word,
            spellings: Row::All(|| vec![reach![Named("spawn_location_offset")]]),
            needs: Some(Capability::TokioUnstable),
        },
        // `core::panic::Location`, for spawn locations. The file member
        // varies by toolchain — `filename: NonNull<str>` on current std,
        // a bare `&str` before that, `file` before the rename — which no
        // tokio version can select, so it stays ordered alternatives.
        // Every spelling lands on the fat pointer (`data_ptr` +
        // `length`), the shape the string reader parses; the Slice
        // terminal is what rejects a landing that stops on a wrapper.
        decl(
            WalkRole::LocationFile,
            Infra(InfraRoot::Location),
            Slice,
            || {
                vec![
                    reach![Named("filename"), Named("pointer")],
                    reach![Named("filename")],
                    reach![Named("file")],
                ]
            },
        ),
        decl(
            WalkRole::LocationLine,
            Infra(InfraRoot::Location),
            Word,
            || vec![reach![Named("line")]],
        ),
        decl(
            WalkRole::LocationCol,
            Infra(InfraRoot::Location),
            Word,
            || vec![reach![Named("col")]],
        ),
        // The stage decode, over every task entry's `Cell<T, S>`.
        decl(WalkRole::CellStage, TaskCells, Enum, || {
            vec![reach![
                Named("core"),
                Named("stage"),
                Named("stage"),
                Named("__0"),
                Named("value"),
            ]]
        }),
        decl(WalkRole::CellStageRunning, TaskCells, Any, || {
            vec![reach![
                Named("core"),
                Named("stage"),
                Named("stage"),
                Named("__0"),
                Named("value"),
                Variant("Running"),
                Named("__0"),
            ]]
        }),
        decl(WalkRole::CellStageFinished, TaskCells, Any, || {
            vec![reach![
                Named("core"),
                Named("stage"),
                Named("stage"),
                Named("__0"),
                Named("value"),
                Variant("Finished"),
                Named("__0"),
            ]]
        }),
        decl(WalkRole::CellStageConsumed, TaskCells, Any, || {
            vec![reach![
                Named("core"),
                Named("stage"),
                Named("stage"),
                Named("__0"),
                Named("value"),
                Variant("Consumed"),
            ]]
        }),
        decl(WalkRole::CellTrailer, TaskCells, Aggregate, || {
            vec![reach![Named("trailer")]]
        }),
        decl(WalkRole::CellTaskId, TaskCells, Any, || {
            vec![reach![Named("core"), Named("task_id"), PeelTo(WORD)]]
        }),
        // The scheduler `S` stored in every cell — the way home from a
        // task found outside every enumerated list: a local task's `S`
        // is the `Arc<local::Shared>` that owns its whole set. One
        // recorded path serves every cell because only the *type* of
        // the member differs per entry, never its spelling.
        decl(WalkRole::CellScheduler, TaskCells, Aggregate, || {
            vec![reach![Named("core"), Named("scheduler")]]
        }),
        // Leaf readers: what a recognized wait primitive is waiting on.
        WalkDecl {
            role: WalkRole::SleepDeadline,
            root: Leaf(SLEEP),
            terminal: Aggregate,
            spellings: Row::Versioned(&SLEEP_DEADLINE_SPELLINGS),
            needs: None,
        },
        decl(
            WalkRole::DeadlineTvSec,
            End(WalkRole::SleepDeadline),
            Word,
            || vec![reach![Named("tv_sec")]],
        ),
        decl(
            WalkRole::DeadlineTvNsec,
            End(WalkRole::SleepDeadline),
            Word,
            || vec![reach![Named("tv_nsec"), Named("__0")]],
        ),
        decl(WalkRole::JoinHandleRaw, Leaf(JOIN_HANDLE), Pointer, || {
            vec![reach![Named("raw"), Named("ptr"), Named("pointer")]]
        }),
        decl(WalkRole::AcquireSemaphore, Leaf(ACQUIRE), Pointer, || {
            vec![reach![Named("semaphore")]]
        }),
        decl(WalkRole::AcquireNumPermits, Leaf(ACQUIRE), Word, || {
            vec![reach![Named("num_permits")]]
        }),
        decl(WalkRole::AcquireNode, Leaf(ACQUIRE), Aggregate, || {
            vec![reach![Named("node")]]
        }),
        decl(WalkRole::AcquireNeeded, Leaf(ACQUIRE), Word, || {
            vec![reach![Named("node"), Named("state"), PeelTo(WORD)]]
        }),
        decl(WalkRole::AcquireQueued, Leaf(ACQUIRE), Word, || {
            vec![reach![Named("queued")]]
        }),
        decl(
            WalkRole::SemaphorePermits,
            Pointee(WalkRole::AcquireSemaphore),
            Word,
            || vec![reach![Named("permits"), PeelTo(WORD)]],
        ),
        decl(
            WalkRole::SemaphoreQueueHead,
            Pointee(WalkRole::AcquireSemaphore),
            Pointer,
            || {
                vec![reach![
                    Named("waiters"),
                    FindParam,
                    Named("queue"),
                    Named("head"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(
            WalkRole::WaiterNeeded,
            Pointee(WalkRole::SemaphoreQueueHead),
            Word,
            || vec![reach![Named("state"), PeelTo(WORD)]],
        ),
        decl(
            WalkRole::WaiterNext,
            Pointee(WalkRole::SemaphoreQueueHead),
            Pointer,
            || {
                vec![reach![
                    Named("pointers"),
                    Named("inner"),
                    Named("value"),
                    Named("next"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(
            WalkRole::WaiterWaker,
            Pointee(WalkRole::SemaphoreQueueHead),
            Aggregate,
            || {
                vec![reach![
                    Named("waker"),
                    Named("__0"),
                    Named("value"),
                    Variant("Some"),
                    Named("__0"),
                    Named("waker"),
                ]]
            },
        ),
        // The waker pair itself, rooted at the type rather than at any
        // one place a waker is registered: a semaphore's wait queue was
        // the first, but the timer wheel and the io driver register the
        // same `RawWaker`, and rooting on the queue made these two rows
        // absent — and so every registry harvest blind — on a target
        // that happens not to instantiate `Acquire`.
        decl(WalkRole::WakerData, Leaf(RAW_WAKER), Pointer, || {
            vec![reach![Named("data")]]
        }),
        decl(WalkRole::WakerVtable, Leaf(RAW_WAKER), Pointer, || {
            vec![reach![Named("vtable")]]
        }),
        // The census's set walks: a `FuturesUnordered`'s intrusive child
        // list, and a `JoinSet`'s two entry lists.
        decl(
            WalkRole::SetHeadAll,
            Leaf(FUTURES_UNORDERED),
            Pointer,
            || vec![reach![Named("head_all"), PeelTo(Shape::Pointer)]],
        ),
        decl(
            WalkRole::SetNodeFuture,
            Pointee(WalkRole::SetHeadAll),
            Enum,
            || vec![reach![Named("future"), Named("value")]],
        ),
        decl(
            WalkRole::SetNodeNext,
            Pointee(WalkRole::SetHeadAll),
            Pointer,
            || vec![reach![Named("next_all"), PeelTo(Shape::Pointer)]],
        ),
        decl(WalkRole::JoinSetLength, Leaf(JOIN_SET), Word, || {
            vec![reach![Named("inner"), Named("length")]]
        }),
        // The two intrusive entry lists, behind an `Arc` to a loom mutex;
        // [`FindParam`] crosses whichever mutex flavor the build linked to
        // reach the `ListsInner` the mutex declares.
        decl(WalkRole::JoinSetLists, Leaf(JOIN_SET), Aggregate, || {
            vec![reach![
                Named("inner"),
                Named("lists"),
                Named("ptr"),
                Named("pointer"),
                Deref,
                Named("data"),
                FindParam,
            ]]
        }),
        decl(
            WalkRole::JoinSetNotifiedHead,
            End(WalkRole::JoinSetLists),
            Pointer,
            || {
                vec![reach![
                    Named("notified"),
                    Named("head"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(
            WalkRole::JoinSetIdleHead,
            End(WalkRole::JoinSetLists),
            Pointer,
            || {
                vec![reach![
                    Named("idle"),
                    Named("head"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(
            WalkRole::JoinSetEntryValue,
            Pointee(WalkRole::JoinSetNotifiedHead),
            Pointer,
            || {
                vec![reach![
                    Named("value"),
                    Named("__0"),
                    Named("value"),
                    Named("value"),
                    Named("__0"),
                    Named("raw"),
                    Named("ptr"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(
            WalkRole::JoinSetEntryNext,
            Pointee(WalkRole::JoinSetNotifiedHead),
            Pointer,
            || {
                vec![reach![
                    Named("pointers"),
                    Named("inner"),
                    Named("value"),
                    Named("next"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        // A `LocalSet`'s own task list, rooted at its shared state: the
        // id the global owned-list counter gave it (what `Header.owner_id`
        // joins), the intrusive list head — the nodes are ordinary task
        // Headers, so `TrailerNext` walks below it unchanged — and the
        // thread the set is pinned to. `owned.inner` is a loom
        // `UnsafeCell`, spelled `__0.value` like `Header.owner_id`'s.
        decl(WalkRole::LocalOwnedId, Leaf(LOCAL_SHARED), Word, || {
            vec![reach![
                Named("local_state"),
                Named("owned"),
                Named("id"),
                PeelTo(WORD),
            ]]
        }),
        decl(
            WalkRole::LocalOwnedHead,
            Leaf(LOCAL_SHARED),
            Pointer,
            || {
                vec![reach![
                    Named("local_state"),
                    Named("owned"),
                    Named("inner"),
                    Named("__0"),
                    Named("value"),
                    Named("list"),
                    Named("head"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(WalkRole::LocalSetOwner, Leaf(LOCAL_SHARED), Word, || {
            vec![reach![Named("local_state"), Named("owner"), PeelTo(WORD)]]
        }),
        // The `task::local::CURRENT` thread-local: its `ctx` slot holds
        // an `Rc<local::Context>` only while the set is being polled (or
        // under a user-held `enter` guard) — the scoped anchor the TLS
        // probe reads per LWP. `ctx.inner` is a loom `UnsafeCell` over
        // the niche `Option<Rc>`; the path lands on the `Rc`'s raw
        // pointer to its `RcInner`.
        decl(WalkRole::LocalTlsCtx, Leaf(LOCAL_DATA), Pointer, || {
            vec![reach![
                Named("ctx"),
                Named("inner"),
                Named("__0"),
                Named("value"),
                Variant("Some"),
                Named("__0"),
                Named("ptr"),
                Named("pointer"),
            ]]
        }),
        // From the `RcInner<local::Context>` behind that pointer to the
        // `Shared` every discovery route converges on: across the Rc
        // header's `value`, then the `Arc<Shared>` deref to the
        // `ArcInner`'s `data`.
        decl(
            WalkRole::LocalCtxShared,
            Pointee(WalkRole::LocalTlsCtx),
            Aggregate,
            || {
                vec![reach![
                    Named("value"),
                    Named("shared"),
                    Named("ptr"),
                    Named("pointer"),
                    Deref,
                    Named("data"),
                ]]
            },
        ),
        // The timer wheel, as a registry of parked tasks: whatever list
        // owns a task, a `Sleep` it awaits registers a `TimerShared` in
        // the runtime's wheel and arms it with the task's own waker. Both
        // flavor handles spell the driver chain identically, so the union
        // root serves; the six levels and each level's 64 slots are read
        // as arrays, element by element, rather than fanned out here.
        WalkDecl {
            role: WalkRole::WheelLevels,
            root: WalkRoot::AnyHandle,
            terminal: Array,
            spellings: Row::Versioned(&WHEEL_LEVELS_SPELLINGS),
            needs: None,
        },
        decl(
            WalkRole::LevelSlots,
            Elem(WalkRole::WheelLevels),
            Array,
            || vec![reach![Named("slot")]],
        ),
        // A slot is the intrusive list itself — no lock above it, so
        // unlike `ShardHead` there is no parameter to search for.
        decl(
            WalkRole::SlotHead,
            Elem(WalkRole::LevelSlots),
            Pointer,
            || {
                vec![reach![
                    Named("head"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        // The nodes are `TimerShared`s linked through their own
        // `linked_list::Pointers`, not through `Trailer.owned`: the same
        // spelling the semaphore's waiters use.
        decl(
            WalkRole::TimerSharedNext,
            Pointee(WalkRole::SlotHead),
            Pointer,
            || {
                vec![reach![
                    Named("pointers"),
                    Named("inner"),
                    Named("value"),
                    Named("next"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        // The entry's registered waker, landing on the same `RawWaker`
        // the wait-queue readers (`WakerData`/`WakerVtable`) take over
        // from — one `AtomicWaker` level above the `UnsafeCell<Option>`
        // pair `WaiterWaker` starts at.
        decl(
            WalkRole::TimerSharedWaker,
            Pointee(WalkRole::SlotHead),
            Aggregate,
            || {
                vec![reach![
                    Named("state"),
                    Named("waker"),
                    Named("waker"),
                    Named("__0"),
                    Named("value"),
                    Variant("Some"),
                    Named("__0"),
                    Named("waker"),
                ]]
            },
        ),
        // The io driver's registrations, the wheel's argument applied to
        // sockets: whatever list owns a task, awaiting readiness on an
        // io resource leaves the task's own waker on that resource's
        // `ScheduledIo`. Every registered resource is in one intrusive
        // list behind the io handle's mutex — there has never been a
        // slab — and both flavor handles spell `driver` alike, so the
        // union root serves here too. `driver.io` is the driver's own
        // flavor enum rather than an `Option`: a runtime built without
        // io holds `Disabled`, which the walk reports as an inactive
        // variant, the same "nothing here" the wheel's `None` gives.
        decl(
            WalkRole::IoRegistrations,
            WalkRoot::AnyHandle,
            Pointer,
            || {
                vec![reach![
                    Named("driver"),
                    Named("io"),
                    Variant("Enabled"),
                    Named("__0"),
                    Named("synced"),
                    FindParam,
                    Named("registrations"),
                    Named("head"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        // A `ScheduledIo`'s link to the next registration. Its
        // `linked_list::Pointers` sits inside an `UnsafeCell` of its
        // own, which the other intrusive lists' nodes do not have, so
        // the spelling opens with one cell level `WaiterNext`'s does
        // not — everything after it is that same chain.
        decl(
            WalkRole::ScheduledIoNext,
            Pointee(WalkRole::IoRegistrations),
            Pointer,
            || {
                vec![reach![
                    Named("linked_list_pointers"),
                    Named("value"),
                    Named("inner"),
                    Named("value"),
                    Named("next"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        // Everything parked on one resource, behind that resource's own
        // mutex — the second lock of this chain, crossed the same way.
        decl(
            WalkRole::ScheduledIoWaiters,
            Pointee(WalkRole::IoRegistrations),
            Aggregate,
            || vec![reach![Named("waiters"), FindParam]],
        ),
        // Three waker sites per resource, not one. `list` holds the
        // `Waiter` nodes an `Interest`-based readiness await pushes,
        // while `reader`/`writer` are the bare `Option<Waker>`s the
        // `AsyncRead`/`AsyncWrite` paths park in — appearing in no list
        // at all, and the commoner shape of the two.
        decl(
            WalkRole::IoWaiterHead,
            End(WalkRole::ScheduledIoWaiters),
            Pointer,
            || {
                vec![reach![
                    Named("list"),
                    Named("head"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(
            WalkRole::IoReaderWaker,
            End(WalkRole::ScheduledIoWaiters),
            Aggregate,
            || {
                vec![reach![
                    Named("reader"),
                    Variant("Some"),
                    Named("__0"),
                    Named("waker"),
                ]]
            },
        ),
        decl(
            WalkRole::IoWriterWaker,
            End(WalkRole::ScheduledIoWaiters),
            Aggregate,
            || {
                vec![reach![
                    Named("writer"),
                    Variant("Some"),
                    Named("__0"),
                    Named("waker"),
                ]]
            },
        ),
        // The list nodes: `WaiterNext`'s spelling exactly, and a waker
        // that is a bare `Option<Waker>` rather than a cell over one.
        decl(
            WalkRole::IoWaiterNext,
            Pointee(WalkRole::IoWaiterHead),
            Pointer,
            || {
                vec![reach![
                    Named("pointers"),
                    Named("inner"),
                    Named("value"),
                    Named("next"),
                    Variant("Some"),
                    Named("__0"),
                    Named("pointer"),
                ]]
            },
        ),
        decl(
            WalkRole::IoWaiterWaker,
            Pointee(WalkRole::IoWaiterHead),
            Aggregate,
            || {
                vec![reach![
                    Named("waker"),
                    Variant("Some"),
                    Named("__0"),
                    Named("waker"),
                ]]
            },
        ),
    ]
}

// ---------------------------------------------------------------------------
// The binder
// ---------------------------------------------------------------------------

/// The DWARF roots extraction has already located, handed to the binder.
pub(crate) struct WalkRoots<'a> {
    /// Infra root types, `None` where extraction found no type (an
    /// `--allow-missing-infra` placeholder).
    pub context: Option<TypeId>,
    pub header: Option<TypeId>,
    pub trailer: Option<TypeId>,
    pub vtable: Option<TypeId>,
    pub location: Option<TypeId>,
    pub mt_handle: Option<TypeId>,
    pub ct_handle: Option<TypeId>,
    /// Each task entry's display label and its `Cell<T, S>`; `None` for a
    /// cell extraction could not recover.
    pub cells: &'a [(String, Option<TypeId>)],
    /// Whether the target was built `--cfg tokio_unstable`, as the meta
    /// will record it — what classifies capability-expected absence.
    pub tokio_unstable: Option<bool>,
}

/// One role's binder trace, for `--explain-walk`: what was tried against
/// which roots and why the misses missed. The verdict is read back out of
/// the recorded binding, which travels in the bundle.
#[derive(Debug)]
pub struct WalkExplanation {
    pub role: WalkRole,
    pub trace: Vec<String>,
}

/// Where children of a role root: its bound terminals (labeled), or why
/// there are none.
enum Chained {
    /// Terminal types of the bound path, one per root × variant fan-out,
    /// plus the parent's root note for the child's report line.
    Terminals(Vec<(String, TypeId)>, Option<String>),
    Absent(String),
    Broken(Vec<String>),
}

/// A resolved root set, or why there is none.
enum Roots {
    Types {
        types: Vec<(String, TypeId)>,
        note: Option<String>,
    },
    Absent(String),
    Broken(Vec<String>),
}

/// Bind every walk declaration against the target's DWARF, recording one
/// [`WalkBinding`] per role. Runs after the task table and infra exist and
/// before the emitter is finished — the binder interns names and reads the
/// emitted-type map, but emits nothing itself.
pub(crate) fn bind_walks(
    em: &mut Emitter<'_>,
    roots: &WalkRoots<'_>,
    explain: Option<&str>,
) -> (WalksTable, Vec<WalkExplanation>) {
    let mut walks = WalksTable::default();
    let mut explanations = Vec::new();
    let mut chained: BTreeMap<WalkRole, Chained> = BTreeMap::new();
    for decl in decls() {
        let (binding, terminals, trace) = bind_decl(em, roots, &chained, &decl);
        chained.insert(decl.role, terminals);
        if explain.is_some_and(|want| decl.role.name().contains(want)) {
            explanations.push(WalkExplanation {
                role: decl.role,
                trace,
            });
        }
        walks.entries.insert(decl.role, binding);
    }
    (walks, explanations)
}

fn unbound(outcome: WalkOutcome) -> WalkBinding {
    WalkBinding {
        roots: Vec::new(),
        steps: Vec::new(),
        outcome,
    }
}

fn bind_decl(
    em: &mut Emitter<'_>,
    roots: &WalkRoots<'_>,
    chained: &BTreeMap<WalkRole, Chained>,
    decl: &WalkDecl,
) -> (WalkBinding, Chained, Vec<String>) {
    let mut trace: Vec<String> = Vec::new();
    let (types, root_note) = match resolve_root(em, roots, chained, &decl.root) {
        Roots::Types { types, note } => (types, note),
        Roots::Absent(reason) => {
            trace.push(format!("no roots: {reason}"));
            return (
                unbound(WalkOutcome::Absent {
                    reason: reason.clone(),
                }),
                Chained::Absent(reason),
                trace,
            );
        }
        Roots::Broken(errors) => {
            // A flavor-specific row whose root type the target never
            // compiled is the expected shape of that target, not
            // breakage — the same judgment the spelling-miss path makes
            // below.
            if let Some(reason) = expected_absence(decl, roots) {
                trace.push(format!("absence is expected: {reason}"));
                return (
                    unbound(WalkOutcome::Absent {
                        reason: reason.clone(),
                    }),
                    Chained::Absent(reason),
                    trace,
                );
            }
            trace.push(format!("roots broken: {}", errors.join("; ")));
            return (
                unbound(WalkOutcome::Broken {
                    errors: errors.clone(),
                }),
                Chained::Broken(errors),
                trace,
            );
        }
    };

    em.versioned_dispatch |= decl.spellings.is_versioned();
    let Some((family, spellings)) = decl.spellings.select(em.family) else {
        let errors = vec![format!("no spelling as old as family {}", em.family.name())];
        return (
            unbound(WalkOutcome::Broken {
                errors: errors.clone(),
            }),
            Chained::Absent(format!("path {} did not resolve", decl.role.name())),
            trace,
        );
    };
    if let Some(family) = family {
        trace.push(format!("family {} selected", family.name()));
    }
    let alts = spellings();

    // Try the alternatives in order against every root; the first whose
    // spelling matches binds, and every root must bind it identically —
    // a binding is one path, and roots that demand different spellings
    // (two tokio copies in one image) are recorded broken rather than
    // served separately.
    let mut bound: Option<(usize, Selector, String)> = None;
    let mut errors: Vec<String> = Vec::new();
    let mut terminals: Vec<(String, TypeId)> = Vec::new();
    for (label, root_ty) in &types {
        let mut misses: Vec<String> = Vec::new();
        let mut hit: Option<(usize, Selector)> = None;
        for (index, alt) in alts.iter().enumerate() {
            let (walked, lines) = trace::capture(|| em.walk(*root_ty, alt));
            match walked {
                Some((sel, _)) => {
                    trace.push(format!("{label}: [{}] bound", spell(alt)));
                    hit = Some((index, sel));
                    break;
                }
                None => {
                    let why = lines
                        .first()
                        .map(|line| line.trim().to_owned())
                        .unwrap_or_else(|| "did not resolve".to_owned());
                    trace.push(format!("{label}: [{}] missed: {why}", spell(alt)));
                    misses.push(if alts.len() > 1 {
                        format!("[{}] {why}", spell(alt))
                    } else {
                        why
                    });
                }
            }
        }
        match hit {
            Some((index, sel)) => {
                match &bound {
                    None => bound = Some((index, sel.clone(), label.clone())),
                    Some((_, first_sel, first_label)) => {
                        if *first_sel != sel {
                            errors.push(format!(
                                "{first_label} and {label} demand different spellings, \
                                 which one recorded binding cannot serve"
                            ));
                            continue;
                        }
                    }
                }
                match step_targets(em.reader, &em.interner, *root_ty, &sel.0) {
                    Some(landed) => {
                        for ty in landed {
                            if let Err(e) = terminal_ok(em.reader, ty, decl.terminal) {
                                errors.push(format!("{label}: {e}"));
                            }
                            terminals.push((format!("{label}: {}", type_label(em.reader, ty)), ty));
                        }
                    }
                    None => errors.push(format!(
                        "{label}: the lowered steps did not re-resolve against the layout"
                    )),
                }
            }
            None => errors.push(format!("{label}: {}", misses.join("; "))),
        }
    }

    if bound.is_none() || !errors.is_empty() {
        if let Some(reason) = expected_absence(decl, roots) {
            trace.push(format!("absence is expected: {reason}"));
            return (
                unbound(WalkOutcome::Absent {
                    reason: reason.clone(),
                }),
                Chained::Absent(reason),
                trace,
            );
        }
        return (
            unbound(WalkOutcome::Broken {
                errors: errors.clone(),
            }),
            Chained::Absent(format!("path {} did not resolve", decl.role.name())),
            trace,
        );
    }
    let (spelling, sel, _) = bound.expect("checked above");

    let mut root_ids: Vec<BundleTypeId> = Vec::new();
    for (label, ty) in &types {
        match em.bundle_id_of(*ty) {
            Some(bid) => root_ids.push(bid),
            None => errors.push(format!("{label}: the root type was never emitted")),
        }
    }
    if !errors.is_empty() {
        return (
            unbound(WalkOutcome::Broken {
                errors: errors.clone(),
            }),
            Chained::Absent(format!("path {} did not resolve", decl.role.name())),
            trace,
        );
    }
    root_ids.sort_unstable();
    root_ids.dedup();

    // The family annotation belongs to this binding alone; only the root
    // note (a type or cell count) travels to the rows rooted below it.
    let mut notes: Vec<String> = Vec::new();
    if let Some(family) = family {
        notes.push(format!("family {}", family.name()));
    }
    notes.extend(root_note.clone());
    let note = (!notes.is_empty()).then(|| notes.join("; "));

    (
        WalkBinding {
            roots: root_ids,
            steps: sel.0.clone(),
            outcome: WalkOutcome::Bound {
                spelling: spelling as u32,
                spellings: alts.len() as u32,
                note,
            },
        },
        Chained::Terminals(terminals, root_note),
        trace,
    )
}

/// Why breakage on this role is the expected shape of the target rather
/// than drift: the capability its datum exists under is recorded as off.
fn expected_absence(decl: &WalkDecl, roots: &WalkRoots<'_>) -> Option<String> {
    match decl.needs? {
        Capability::TokioUnstable => match roots.tokio_unstable {
            Some(false) => Some("the target was built without tokio_unstable".to_owned()),
            Some(true) | None => None,
        },
        Capability::MultiThreadScheduler => roots
            .mt_handle
            .is_none()
            .then(|| "the target has no multi_thread scheduler compiled in".to_owned()),
        Capability::CurrentThreadScheduler => roots
            .ct_handle
            .is_none()
            .then(|| "the target has no current_thread scheduler compiled in".to_owned()),
    }
}

fn resolve_root(
    em: &Emitter<'_>,
    roots: &WalkRoots<'_>,
    chained: &BTreeMap<WalkRole, Chained>,
    root: &WalkRoot,
) -> Roots {
    let reader = em.reader;
    match root {
        WalkRoot::Infra(infra) => {
            let (name, id) = match infra {
                InfraRoot::Context => ("tokio::runtime::context::Context", roots.context),
                InfraRoot::Header => ("the task Header", roots.header),
                InfraRoot::Trailer => ("the task Trailer", roots.trailer),
                InfraRoot::Vtable => ("the task Vtable", roots.vtable),
                InfraRoot::Location => ("core::panic::Location", roots.location),
                InfraRoot::MtHandle => ("the multi_thread Handle", roots.mt_handle),
                InfraRoot::CtHandle => ("the current_thread Handle", roots.ct_handle),
            };
            let Some(id) = id else {
                return Roots::Broken(vec![format!(
                    "the bundle has no layout for {name} \
                     (was it extracted with --allow-missing-infra?)"
                )]);
            };
            Roots::Types {
                types: vec![(type_label(reader, id), id)],
                note: None,
            }
        }
        WalkRoot::AnyHandle => {
            let mut types = Vec::new();
            let mut absent = Vec::new();
            for (flavor, id) in [
                ("multi_thread", roots.mt_handle),
                ("current_thread", roots.ct_handle),
            ] {
                match id {
                    Some(id) => types.push((type_label(reader, id), id)),
                    None => absent.push(flavor),
                }
            }
            if types.is_empty() {
                return Roots::Broken(vec![
                    "the bundle has no layout for either scheduler flavor's Handle \
                     (was it extracted with --allow-missing-infra?)"
                        .to_owned(),
                ]);
            }
            let note = (!absent.is_empty()).then(|| format!("no {} Handle", absent.join(" or ")));
            Roots::Types { types, note }
        }
        WalkRoot::Leaf(key) => {
            let types: Vec<(String, TypeId)> = em
                .emitted_named()
                .filter(|(_, name)| leaf_matches(key, name))
                .map(|(tid, name)| (name.to_owned(), tid))
                .collect();
            if types.is_empty() {
                return Roots::Absent(format!(
                    "no {key}\u{2026} type in the bundle (the target does not reach one)"
                ));
            }
            let note = (types.len() > 1).then(|| format!("{} types", types.len()));
            Roots::Types { types, note }
        }
        WalkRoot::TaskCells => {
            let mut types = Vec::new();
            let mut opaque = 0usize;
            for (label, cell) in roots.cells {
                match cell {
                    Some(id) if reader.canonical_type(*id).is_some() => {
                        types.push((label.clone(), *id));
                    }
                    _ => opaque += 1,
                }
            }
            if types.is_empty() {
                return Roots::Absent(format!(
                    "the task table has no bound cells ({opaque} opaque of {})",
                    roots.cells.len()
                ));
            }
            let note = Some(if opaque > 0 {
                format!("{} cells, {opaque} opaque skipped", types.len())
            } else {
                format!("{} cells", types.len())
            });
            Roots::Types { types, note }
        }
        WalkRoot::End(parent) => match chained.get(parent) {
            Some(Chained::Terminals(terminals, note)) => Roots::Types {
                types: terminals.clone(),
                note: note.clone(),
            },
            Some(Chained::Absent(reason)) => Roots::Absent(reason.clone()),
            Some(Chained::Broken(errors)) => Roots::Broken(errors.clone()),
            None => Roots::Broken(vec![format!(
                "internal: role {:?} was not bound before its children",
                parent
            )]),
        },
        WalkRoot::Pointee(parent) => {
            match resolve_root(em, roots, chained, &WalkRoot::End(*parent)) {
                Roots::Types { types, note } => {
                    let mut out = Vec::new();
                    for (label, ty) in types {
                        let Some(RawType::Pointer(pointer)) = reader.canonical_type(ty) else {
                            return Roots::Broken(vec![format!(
                                "{label}: {} is not a pointer",
                                type_label(reader, ty)
                            )]);
                        };
                        out.push((label, reader.canonicalize(pointer.target_type_id)));
                    }
                    Roots::Types { types: out, note }
                }
                other => other,
            }
        }
        WalkRoot::Elem(parent) => match resolve_root(em, roots, chained, &WalkRoot::End(*parent)) {
            Roots::Types { types, note } => {
                let mut out = Vec::new();
                for (label, ty) in types {
                    // An inline array declares its element type; a boxed
                    // slice keeps it behind the `data_ptr` half of the fat
                    // pointer.
                    let target = match reader.canonical_type(ty) {
                        Some(RawType::Array(array)) => Some(array.elem_type_id),
                        _ => aggregate_members(reader, ty)
                            .and_then(|members| {
                                members.iter().find(|m| {
                                    m.name.map(|n| reader.strings.get(n)) == Some("data_ptr")
                                })
                            })
                            .and_then(|m| match reader.canonical_type(m.type_id) {
                                Some(RawType::Pointer(pointer)) => Some(pointer.target_type_id),
                                _ => None,
                            }),
                    };
                    let Some(target) = target else {
                        return Roots::Broken(vec![format!(
                            "{label}: {} is neither an array nor a data_ptr fat pointer \
                             to walk elements of",
                            type_label(reader, ty)
                        )]);
                    };
                    out.push((label, reader.canonicalize(target)));
                }
                Roots::Types { types: out, note }
            }
            other => other,
        },
    }
}

/// Every type the lowered steps can land on from `root` — one per variant
/// crossed by a [`Step::ActiveVariant`] — the DWARF sibling of the
/// walk-binding validation's fan-out. `None` means the steps the emitter
/// just lowered do not re-resolve, which is the binder's own bug; the
/// caller records it loudly.
fn step_targets(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    root: TypeId,
    steps: &[Step],
) -> Option<Vec<TypeId>> {
    let cur = reader.canonicalize(root);
    let [step, rest @ ..] = steps else {
        return Some(vec![cur]);
    };
    if matches!(step, Step::ActiveVariant) {
        let Some(RawType::Enum(en)) = reader.canonical_type(cur) else {
            return None;
        };
        let mut out = Vec::new();
        for member in raw_variants(en)? {
            out.extend(step_targets(reader, strings, member.type_id, rest)?);
        }
        return (!out.is_empty()).then_some(out);
    }
    let (landed, _) = step_into(reader, strings, cur, step)?;
    step_targets(reader, strings, landed, rest)
}

/// Whether the DWARF type meets the declared terminal shape.
fn terminal_ok(reader: &DwReader<'_>, id: TypeId, terminal: Terminal) -> Result<(), String> {
    let ok = match terminal {
        Terminal::Word => matches!(
            reader.canonical_type(id),
            Some(RawType::Base(base)) if (1..=8).contains(&base.size)
                && base.encoding != Encoding::Float
        ),
        Terminal::Pointer => matches!(reader.canonical_type(id), Some(RawType::Pointer(_))),
        Terminal::Enum => matches!(reader.canonical_type(id), Some(RawType::Enum(_))),
        Terminal::Aggregate => matches!(
            reader.canonical_type(id),
            Some(RawType::Struct(_) | RawType::Union(_))
        ),
        Terminal::Slice => slice_shaped(reader, id),
        Terminal::Array => matches!(reader.canonical_type(id), Some(RawType::Array(_))),
        Terminal::Any => true,
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "landed on {} ({}), which is not {terminal:?}-shaped",
            type_label(reader, id),
            kind_label(reader, id),
        ))
    }
}

/// A boxed slice's fat layout: a `data_ptr` pointer and a `length`.
fn slice_shaped(reader: &DwReader<'_>, id: TypeId) -> bool {
    let Some(members) = aggregate_members(reader, id) else {
        return false;
    };
    let named = |want: &str| {
        members
            .iter()
            .find(|m| m.name.map(|n| reader.strings.get(n)) == Some(want))
    };
    named("data_ptr")
        .is_some_and(|m| matches!(reader.canonical_type(m.type_id), Some(RawType::Pointer(_))))
        && named("length").is_some()
}

/// The coarse kind of a DWARF type, for a terminal mismatch message.
fn kind_label(reader: &DwReader<'_>, id: TypeId) -> &'static str {
    match reader.canonical_type(id) {
        Some(RawType::Base(base)) => match base.encoding {
            Encoding::Float => "float",
            _ => "integer",
        },
        Some(RawType::Pointer(_)) => "pointer",
        Some(RawType::Array(_)) => "array",
        Some(RawType::Struct(_)) => "struct",
        Some(RawType::Union(_)) => "union",
        Some(RawType::Enum(_)) => "enum",
        None => "unmodeled",
    }
}

/// Whether a role's navigation roots (transitively) at a leaf type.
///
/// Which leaf types exist in a binary is the target's call — the linker
/// keeps or drops monomorphizations per platform — so a leaf-rooted
/// row's presence is a fact about the build, not about the contract.
/// The portable golden summary skips these rows for the same reason its
/// dyn-future list skips `futures_util` adapters; the per-cell matrix
/// goldens, which are single-target, keep them.
pub fn leaf_rooted(role: WalkRole) -> bool {
    let mut rooted: BTreeMap<WalkRole, bool> = BTreeMap::new();
    for decl in decls() {
        let is_leaf = match decl.root {
            WalkRoot::Leaf(_) => true,
            WalkRoot::Infra(_) | WalkRoot::AnyHandle | WalkRoot::TaskCells => false,
            WalkRoot::End(parent) | WalkRoot::Pointee(parent) | WalkRoot::Elem(parent) => {
                rooted.get(&parent).copied().unwrap_or(false)
            }
        };
        rooted.insert(decl.role, is_leaf);
    }
    rooted.get(&role).copied().unwrap_or(false)
}

/// A human spelling of one alternative's steps, for diagnostics:
/// `entry.<active variant>.deadline`, `unpark.*.data`.
fn spell(steps: &[super::ReachStep<'_>]) -> String {
    use super::ReachStep;
    steps
        .iter()
        .map(|step| match step {
            ReachStep::Named(name) => (*name).to_owned(),
            ReachStep::Deref => "*".to_owned(),
            ReachStep::Variant(name) => format!("<{name}>"),
            ReachStep::ActiveVariant => "<active variant>".to_owned(),
            ReachStep::PeelTo(shape) => format!("<peel to {shape}>"),
            ReachStep::PeelToParam | ReachStep::FindParam => "<T>".to_owned(),
            ReachStep::Resolved(_) => "<resolved>".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The declaration table covers every role, in report order — a role
    /// added to the schema without a declaration here fails immediately.
    #[test]
    fn test_decls_cover_every_role_in_report_order() {
        let declared: Vec<WalkRole> = decls().iter().map(|d| d.role).collect();
        assert_eq!(declared, WalkRole::ALL);
    }

    /// An exact leaf key must not take lookalike siblings with it —
    /// `AcquireError` shares `Acquire`'s prefix — while a `<`-terminated
    /// key spans its monomorphizations.
    #[test]
    fn test_leaf_matching_is_exact_unless_generic() {
        assert!(leaf_matches(
            ACQUIRE,
            "tokio::sync::batch_semaphore::Acquire"
        ));
        assert!(!leaf_matches(
            ACQUIRE,
            "tokio::sync::batch_semaphore::AcquireError"
        ));
        assert!(leaf_matches(SLEEP, "tokio::time::sleep::Sleep"));
        assert!(!leaf_matches(SLEEP, "tokio::time::sleep::Sleeper"));
        assert!(leaf_matches(
            JOIN_HANDLE,
            "tokio::runtime::task::join::JoinHandle<()>"
        ));
        assert!(!leaf_matches(
            JOIN_HANDLE,
            "tokio::runtime::task::join::JoinHandleFoo"
        ));
    }

    #[test]
    fn test_spelling_alternatives() {
        use super::super::ReachStep::{ActiveVariant, Deref, Named, Variant};
        assert_eq!(
            spell(&[Named("entry"), ActiveVariant, Named("deadline")]),
            "entry.<active variant>.deadline"
        );
        assert_eq!(
            spell(&[Named("unpark"), Deref, Named("data")]),
            "unpark.*.data"
        );
        assert_eq!(spell(&[Named("head"), Variant("Some")]), "head.<Some>");
    }
}

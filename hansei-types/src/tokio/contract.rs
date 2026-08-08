// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The runtime walk's navigational contract, as data.
//!
//! Everything the walk navigates *by declaration* — the member chains
//! below the bundle's infra roots, and the leaf readers rooted at
//! name-keyed types (`Sleep`, `JoinHandle`, `Acquire`, the census's
//! `FuturesUnordered` and `JoinSet`) — is a named [`WalkPath`] in the
//! table here. The walk's accessors execute these paths rather than
//! spelling member names inline, so the table cannot drift from the
//! code; [`verify_walk_contract`] resolves every path against a
//! bundle's type graph alone — no target, no memory reads — so a tokio
//! or toolchain release that moves a layout produces one comprehensive
//! up-front report instead of a mid-walk failure on the first task.
//!
//! What is *not* here is the await-chain recursion: it walks arbitrary
//! coroutine types whose conventions (`__awaitee` naming, variant
//! encoding, what survives inlining) cannot be a static path. Its
//! cross-version coverage is behavioral, not declarative.
//!
//! **Divergence is ordered alternatives, never a version check.** When
//! a release respells a navigation, the fix is a second entry in the
//! path's `alts`, tried in structural order; the report says which one
//! bound. The recorded tokio version appears in diagnostics only.

use anyhow::{Context as _, Result, anyhow, bail};
use exegesis::bundle::{BundleType, BundleView, StaticRole, TypeDef, TypeKind};
use reify::{ParseCtx, ParseWithDbgInfo, TypeInfo, TypeInfoRef};

use std::fmt;

// ---------------------------------------------------------------------------
// Name keys shared by the walk and the table
// ---------------------------------------------------------------------------

/// `tokio::time::Sleep`'s leaf future.
pub const SLEEP: &str = "tokio::time::sleep::Sleep";
/// A join edge to another task.
pub const JOIN_HANDLE: &str = "tokio::runtime::task::join::JoinHandle<";
/// The future queued on the semaphore backing Mutex/RwLock/Semaphore.
pub const ACQUIRE: &str = "tokio::sync::batch_semaphore::Acquire";
/// The by-value type every `FuturesUnordered` is recognized as.
pub const FUTURES_UNORDERED: &str = "futures_util::stream::futures_unordered::FuturesUnordered<";
/// The by-value type every join set is recognized as.
pub const JOIN_SET: &str = "tokio::task::join_set::JoinSet<";

/// Whether `name` is a type a leaf key names. A key ending in `<` is a
/// generic: the prefix of every monomorphization's name. Any other key
/// is an exact fully-qualified name — a bare prefix match would take
/// lookalike siblings with it (`batch_semaphore::Acquire` is one
/// character away from `AcquireError`).
pub fn leaf_matches(key: &str, name: &str) -> bool {
    if key.ends_with('<') {
        name.starts_with(key)
    } else {
        name == key
    }
}

/// `Stage<T>`'s variant names, as [`CELL_STAGE`]'s decode matches them.
pub const STAGE_RUNNING: &str = "Running";
pub const STAGE_FINISHED: &str = "Finished";
pub const STAGE_CONSUMED: &str = "Consumed";

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

/// One navigation step. Each mirrors exactly what the walk's runtime
/// executor does with a [`TypeInfoRef`], wrapper-peeling included, so
/// static resolution and the walk agree about where a path lands.
#[derive(Copy, Clone, Debug)]
pub enum Nav {
    /// The named member, peeling single-member wrappers off what it
    /// lands on (the [`TypeInfoRef::member`] semantics).
    Member(&'static str),
    /// The named variant of a Rust enum. At walk time an inactive
    /// variant is a normal outcome ([`Walked::Inactive`]), not an
    /// error; statically the variant must exist.
    Variant(&'static str),
    /// Whichever variant is active. Statically *every* variant must
    /// satisfy the remaining steps, since the walk takes the one it
    /// finds.
    ActiveVariant,
    /// Follow the pointer reached so far (peeling the pointee). A null
    /// word is [`Walked::Null`], not a read failure.
    Deref,
}

/// The shape a path's terminal type must have. Coarse on purpose: the
/// byte offsets differ across versions and are not the contract; the
/// name chain and the terminal shape are.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Terminal {
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
    /// No shape requirement; parsing decides.
    Any,
}

/// A build capability a path's datum exists under. A path that `needs`
/// one is checked normally when the bundle records the capability as
/// present — but when the bundle records it *off*, the path failing to
/// resolve is the expected shape of that target
/// ([`Outcome::Absent`]), not drift. An unrecorded capability keeps
/// breakage loud: absence is only expected when the bundle can say so.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Capability {
    /// `--cfg tokio_unstable` task instrumentation, recorded by the
    /// bundle's `Meta::tokio_unstable`.
    TokioUnstable,
}

/// What a path failing means for the walk.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Class {
    /// The walk cannot function without it: runtime discovery, task
    /// enumeration, the stage decode. Broken always refuses to attach.
    Required,
    /// Supporting output the walk can degrade without — park states,
    /// leaf readers, the census walks. Broken refuses to attach under
    /// [`WalkPolicy::Strict`] and degrades under
    /// [`WalkPolicy::BestEffort`].
    Optional,
}

/// Where a path starts.
#[derive(Copy, Clone, Debug)]
pub enum Root {
    /// One of the bundle's infra types.
    Infra(InfraRoot),
    /// Every type a leaf key names ([`leaf_matches`]). None in the
    /// bundle is an expected absence — the target does not use the
    /// primitive — not a breakage.
    Leaf(&'static str),
    /// The (non-opaque) `Cell<T, S>` of every entry in the task table.
    TaskCells,
    /// Where another path landed.
    End(&'static WalkPath),
    /// The pointee of the pointer another path landed on.
    Pointee(&'static WalkPath),
    /// The element of the boxed slice another path landed on.
    Elem(&'static WalkPath),
}

/// The infra roots the table navigates below. (The other infra types —
/// `scheduler::Handle`, `RawWakerVTable` — anchor no fixed navigation.)
#[derive(Copy, Clone, Debug)]
pub enum InfraRoot {
    Context,
    Header,
    Trailer,
    Vtable,
    Location,
    MtHandle,
}

/// One declared navigation: a root, ordered alternative spellings (the
/// first that structurally matches binds — the `read_sleep` pattern,
/// generalized), and the shape the landing type must have.
#[derive(Debug)]
pub struct WalkPath {
    pub name: &'static str,
    pub root: Root,
    pub alts: &'static [&'static [Nav]],
    pub terminal: Terminal,
    pub class: Class,
    /// The capability the datum exists under, for the ones that are
    /// build-conditional; `None` for the paths every build has.
    pub needs: Option<Capability>,
}

use Class::{Optional, Required};
use Nav::{ActiveVariant, Deref, Member as M, Variant as V};

macro_rules! path {
    ($(#[$meta:meta])* $vis:vis $ident:ident = $name:literal, $root:expr, $terminal:ident, $class:ident, needs $cap:ident, $($alt:expr),+ $(,)?) => {
        $(#[$meta])*
        $vis static $ident: WalkPath = WalkPath {
            name: $name,
            root: $root,
            alts: &[$(&$alt),+],
            terminal: Terminal::$terminal,
            class: $class,
            needs: Some(Capability::$cap),
        };
    };
    ($(#[$meta:meta])* $vis:vis $ident:ident = $name:literal, $root:expr, $terminal:ident, $class:ident, $($alt:expr),+ $(,)?) => {
        $(#[$meta])*
        $vis static $ident: WalkPath = WalkPath {
            name: $name,
            root: $root,
            alts: &[$(&$alt),+],
            terminal: Terminal::$terminal,
            class: $class,
            needs: None,
        };
    };
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------
//
// Runtime discovery: the thread-local `Context` down to the
// multi_thread scheduler's shared state.

path!(pub CURRENT_TASK_ID = "Context.current_task_id",
    Root::Infra(InfraRoot::Context), Any, Required,
    [M("current_task_id")]);

path!(pub WORKER_HANDLE = "Context.handle",
    Root::Infra(InfraRoot::Context), Aggregate, Required,
    [M("current"), M("handle"), M("value"), V("Some"), V("MultiThread"), Deref, M("data")]);

path!(pub WORKER_CONTEXT = "Context.scheduler",
    Root::Infra(InfraRoot::Context), Aggregate, Optional,
    [M("scheduler"), Deref, V("MultiThread")]);

path!(pub WORKER_INDEX = "worker::Context.index",
    Root::End(&WORKER_CONTEXT), Word, Optional,
    [M("worker"), Deref, M("data"), M("index")]);

path!(pub HANDLE_SHARED = "Handle.shared",
    Root::Infra(InfraRoot::MtHandle), Aggregate, Required,
    [M("shared")]);

// Parkers: every worker's state word and the io driver's lock, reached
// through the `Unparker`s hanging off the shared scheduler state.

path!(pub SHARED_REMOTES = "Shared.remotes",
    Root::End(&HANDLE_SHARED), Slice, Optional,
    [M("remotes")]);

path!(pub REMOTE_UNPARK = "Remote.unpark",
    Root::Elem(&SHARED_REMOTES), Aggregate, Optional,
    [M("unpark"), Deref, M("data")]);

path!(pub PARKER_STATE = "parker::Inner.state",
    Root::End(&REMOTE_UNPARK), Word, Optional,
    [M("state")]);

// The parkers' `Shared` holds the driver's lock and nothing else, so
// reaching for it may land *past* it, on the lock — a single-member
// struct is peeled away by the member that names it. The two
// alternatives are the two ways that peel can land.
path!(pub PARKER_DRIVER_LOCK = "parker::Inner.driver_lock",
    Root::End(&REMOTE_UNPARK), Word, Optional,
    [M("shared"), Deref, M("data"), M("driver"), M("locked")],
    [M("shared"), Deref, M("data"), M("locked")]);

// The blocking pool's own counters.

path!(pub BLOCKING_METRICS = "Handle.blocking_metrics",
    Root::Infra(InfraRoot::MtHandle), Aggregate, Optional,
    [M("blocking_spawner"), Deref, M("data"), M("metrics")]);

path!(pub BLOCKING_THREADS = "SpawnerMetrics.num_threads",
    Root::End(&BLOCKING_METRICS), Any, Optional,
    [M("num_threads")]);

path!(pub BLOCKING_IDLE = "SpawnerMetrics.num_idle_threads",
    Root::End(&BLOCKING_METRICS), Any, Optional,
    [M("num_idle_threads")]);

path!(pub BLOCKING_QUEUE_DEPTH = "SpawnerMetrics.queue_depth",
    Root::End(&BLOCKING_METRICS), Any, Optional,
    [M("queue_depth")]);

// Task enumeration: `Shared.owned`'s sharded intrusive lists, the
// `Header` each node is, and the `Trailer.owned` link to the next.

path!(pub OWNED_LISTS = "Shared.owned_lists",
    Root::End(&HANDLE_SHARED), Slice, Required,
    [M("owned"), M("list"), M("lists")]);

path!(pub SHARD_HEAD = "Shard.head",
    Root::Elem(&OWNED_LISTS), Pointer, Required,
    [M("data"), M("head"), V("Some")]);

path!(pub HEADER_STATE = "Header.state",
    Root::Infra(InfraRoot::Header), Word, Required,
    [M("state")]);

path!(pub HEADER_OWNER_ID = "Header.owner_id",
    Root::Infra(InfraRoot::Header), Any, Required,
    [M("owner_id")]);

path!(pub HEADER_VTABLE = "Header.vtable",
    Root::Infra(InfraRoot::Header), Pointer, Required,
    [M("vtable")]);

path!(pub TRAILER_NEXT = "Trailer.owned_next",
    Root::Infra(InfraRoot::Trailer), Pointer, Required,
    [M("owned"), M("next"), V("Some")]);

// The task `Vtable` — `#[repr(Rust)]`, so every offset the walk uses
// must be read from the target through this layout, never assumed.

path!(pub VTABLE_POLL = "Vtable.poll",
    Root::Infra(InfraRoot::Vtable), Pointer, Required,
    [M("poll")]);

path!(pub VTABLE_TRAILER_OFFSET = "Vtable.trailer_offset",
    Root::Infra(InfraRoot::Vtable), Word, Required,
    [M("trailer_offset")]);

path!(pub VTABLE_ID_OFFSET = "Vtable.id_offset",
    Root::Infra(InfraRoot::Vtable), Word, Required,
    [M("id_offset")]);

path!(pub VTABLE_DEALLOC = "Vtable.dealloc",
    Root::Infra(InfraRoot::Vtable), Pointer, Optional,
    [M("dealloc")]);

path!(pub VTABLE_TRY_READ_OUTPUT = "Vtable.try_read_output",
    Root::Infra(InfraRoot::Vtable), Pointer, Optional,
    [M("try_read_output")]);

path!(pub VTABLE_DROP_JOIN_HANDLE_SLOW = "Vtable.drop_join_handle_slow",
    Root::Infra(InfraRoot::Vtable), Pointer, Optional,
    [M("drop_join_handle_slow")]);

path!(pub VTABLE_DROP_ABORT_HANDLE = "Vtable.drop_abort_handle",
    Root::Infra(InfraRoot::Vtable), Pointer, Optional,
    [M("drop_abort_handle")]);

path!(pub VTABLE_SHUTDOWN = "Vtable.shutdown",
    Root::Infra(InfraRoot::Vtable), Pointer, Optional,
    [M("shutdown")]);

path!(
    /// Present only under `tokio_unstable` task instrumentation; the
    /// walk `try_read`s it, and a bundle recording the cfg as off makes
    /// its absence expected rather than broken.
pub VTABLE_SPAWN_LOCATION_OFFSET = "Vtable.spawn_location_offset",
    Root::Infra(InfraRoot::Vtable), Word, Optional, needs TokioUnstable,
    [M("spawn_location_offset")]);

// `core::panic::Location`, for spawn locations.

path!(pub LOCATION_FILE = "Location.file",
    Root::Infra(InfraRoot::Location), Any, Required,
    [M("filename")],
    // Pre-rename std spells the field `file`.
    [M("file")]);

path!(pub LOCATION_LINE = "Location.line",
    Root::Infra(InfraRoot::Location), Word, Required,
    [M("line")]);

path!(pub LOCATION_COL = "Location.col",
    Root::Infra(InfraRoot::Location), Word, Required,
    [M("col")]);

// The stage decode, over every task entry's `Cell<T, S>`.

path!(pub CELL_STAGE = "Cell.stage",
    Root::TaskCells, Enum, Required,
    [M("core"), M("stage")]);

path!(pub CELL_STAGE_RUNNING = "Cell.stage_running",
    Root::TaskCells, Any, Required,
    [M("core"), M("stage"), V(STAGE_RUNNING)]);

path!(pub CELL_STAGE_FINISHED = "Cell.stage_finished",
    Root::TaskCells, Any, Required,
    [M("core"), M("stage"), V(STAGE_FINISHED)]);

path!(pub CELL_STAGE_CONSUMED = "Cell.stage_consumed",
    Root::TaskCells, Any, Required,
    [M("core"), M("stage"), V(STAGE_CONSUMED)]);

path!(
    /// The bundle-side half of the vtable offset cross-check: the `Cell`'s
    /// own `trailer` offset must equal the target's `trailer_offset`.
pub CELL_TRAILER = "Cell.trailer",
    Root::TaskCells, Aggregate, Required,
    [M("trailer")]);

path!(
    /// The other half: `Cell.core` + `Core.task_id` against `id_offset`.
pub CELL_TASK_ID = "Cell.task_id",
    Root::TaskCells, Any, Required,
    [M("core"), M("task_id")]);

// Leaf readers (§3.6): what a recognized wait primitive is waiting on.

path!(
    /// The registered deadline: on a `TimerEntry` member directly, or —
    /// since tokio 1.52's `runtime::Timer` enum over the two timer
    /// implementations — on whichever variant is live, both of which carry
    /// it. Lands on the `Timespec` tokio's `Instant` peels to.
pub SLEEP_DEADLINE = "Sleep.deadline",
    Root::Leaf(SLEEP), Aggregate, Optional,
    [M("entry"), M("deadline")],
    [M("entry"), ActiveVariant, M("deadline")]);

path!(pub DEADLINE_TV_SEC = "Sleep.deadline.tv_sec",
    Root::End(&SLEEP_DEADLINE), Word, Optional,
    [M("tv_sec")]);

path!(pub DEADLINE_TV_NSEC = "Sleep.deadline.tv_nsec",
    Root::End(&SLEEP_DEADLINE), Word, Optional,
    [M("tv_nsec")]);

path!(
    /// `JoinHandle.raw` peels down to the joined task's `Header` pointer.
pub JOIN_HANDLE_RAW = "JoinHandle.raw",
    Root::Leaf(JOIN_HANDLE), Pointer, Optional,
    [M("raw")]);

path!(pub ACQUIRE_SEMAPHORE = "Acquire.semaphore",
    Root::Leaf(ACQUIRE), Pointer, Optional,
    [M("semaphore")]);

path!(pub ACQUIRE_NUM_PERMITS = "Acquire.num_permits",
    Root::Leaf(ACQUIRE), Word, Optional,
    [M("num_permits")]);

path!(pub ACQUIRE_NODE = "Acquire.node",
    Root::Leaf(ACQUIRE), Aggregate, Optional,
    [M("node")]);

path!(pub ACQUIRE_NEEDED = "Acquire.node.state",
    Root::Leaf(ACQUIRE), Word, Optional,
    [M("node"), M("state")]);

path!(pub ACQUIRE_QUEUED = "Acquire.queued",
    Root::Leaf(ACQUIRE), Word, Optional,
    [M("queued")]);

path!(pub SEMAPHORE_PERMITS = "Semaphore.permits",
    Root::Pointee(&ACQUIRE_SEMAPHORE), Word, Optional,
    [M("permits")]);

path!(
    /// The wait queue's head; its pointee is the `Waiter` layout every
    /// node decodes with.
pub SEMAPHORE_QUEUE_HEAD = "Semaphore.queue_head",
    Root::Pointee(&ACQUIRE_SEMAPHORE), Pointer, Optional,
    [M("waiters"), M("data"), M("queue"), M("head"), V("Some")]);

path!(pub WAITER_NEEDED = "Waiter.state",
    Root::Pointee(&SEMAPHORE_QUEUE_HEAD), Word, Optional,
    [M("state")]);

path!(pub WAITER_NEXT = "Waiter.next",
    Root::Pointee(&SEMAPHORE_QUEUE_HEAD), Pointer, Optional,
    [M("pointers"), M("next"), V("Some")]);

path!(pub WAITER_WAKER = "Waiter.waker",
    Root::Pointee(&SEMAPHORE_QUEUE_HEAD), Aggregate, Optional,
    [M("waker"), V("Some")]);

path!(pub WAKER_DATA = "RawWaker.data",
    Root::End(&WAITER_WAKER), Pointer, Optional,
    [M("data")]);

path!(pub WAKER_VTABLE = "RawWaker.vtable",
    Root::End(&WAITER_WAKER), Pointer, Optional,
    [M("vtable")]);

// The census's set walks: a `FuturesUnordered`'s intrusive child list,
// and a `JoinSet`'s two entry lists.

path!(
    /// Peels the atomic shims off the `head_all` word; the pointee is the
    /// node layout the list is walked with.
pub SET_HEAD_ALL = "FuturesUnordered.head_all",
    Root::Leaf(FUTURES_UNORDERED), Pointer, Optional,
    [M("head_all")]);

path!(
    /// `Task.future`: `UnsafeCell<Option<Fut>>`; `None` is a completed
    /// child the set has not reaped.
pub SET_NODE_FUTURE = "SetNode.future",
    Root::Pointee(&SET_HEAD_ALL), Enum, Optional,
    [M("future")]);

path!(pub SET_NODE_NEXT = "SetNode.next_all",
    Root::Pointee(&SET_HEAD_ALL), Pointer, Optional,
    [M("next_all")]);

path!(pub JOIN_SET_LENGTH = "JoinSet.length",
    Root::Leaf(JOIN_SET), Word, Optional,
    [M("inner"), M("length")]);

path!(
    /// The two intrusive entry lists, behind an `Arc` to a mutex whose
    /// payload member both loom shims spell `data`.
pub JOIN_SET_LISTS = "JoinSet.lists",
    Root::Leaf(JOIN_SET), Aggregate, Optional,
    [M("inner"), M("lists"), Deref, M("data"), M("data")]);

path!(pub JOIN_SET_NOTIFIED_HEAD = "JoinSet.notified_head",
    Root::End(&JOIN_SET_LISTS), Pointer, Optional,
    [M("notified"), M("head"), V("Some")]);

path!(pub JOIN_SET_IDLE_HEAD = "JoinSet.idle_head",
    Root::End(&JOIN_SET_LISTS), Pointer, Optional,
    [M("idle"), M("head"), V("Some")]);

path!(
    /// `ListEntry.value` peels through the cell and the `ManuallyDrop` to
    /// the held `JoinHandle`'s `Header` pointer — the same word a
    /// `JoinHandle` leaf is read through.
pub JOIN_SET_ENTRY_VALUE = "ListEntry.value",
    Root::Pointee(&JOIN_SET_NOTIFIED_HEAD), Pointer, Optional,
    [M("value")]);

path!(pub JOIN_SET_ENTRY_NEXT = "ListEntry.next",
    Root::Pointee(&JOIN_SET_NOTIFIED_HEAD), Pointer, Optional,
    [M("pointers"), M("next"), V("Some")]);

/// Every path in the table, in report order. A path missing from here
/// still walks, but is invisible to [`verify_walk_contract`] — so a
/// new path is not done until it is also a row here.
pub static PATHS: &[&WalkPath] = &[
    &CURRENT_TASK_ID,
    &WORKER_HANDLE,
    &WORKER_CONTEXT,
    &WORKER_INDEX,
    &HANDLE_SHARED,
    &SHARED_REMOTES,
    &REMOTE_UNPARK,
    &PARKER_STATE,
    &PARKER_DRIVER_LOCK,
    &BLOCKING_METRICS,
    &BLOCKING_THREADS,
    &BLOCKING_IDLE,
    &BLOCKING_QUEUE_DEPTH,
    &OWNED_LISTS,
    &SHARD_HEAD,
    &HEADER_STATE,
    &HEADER_OWNER_ID,
    &HEADER_VTABLE,
    &TRAILER_NEXT,
    &VTABLE_POLL,
    &VTABLE_TRAILER_OFFSET,
    &VTABLE_ID_OFFSET,
    &VTABLE_DEALLOC,
    &VTABLE_TRY_READ_OUTPUT,
    &VTABLE_DROP_JOIN_HANDLE_SLOW,
    &VTABLE_DROP_ABORT_HANDLE,
    &VTABLE_SHUTDOWN,
    &VTABLE_SPAWN_LOCATION_OFFSET,
    &LOCATION_FILE,
    &LOCATION_LINE,
    &LOCATION_COL,
    &CELL_STAGE,
    &CELL_STAGE_RUNNING,
    &CELL_STAGE_FINISHED,
    &CELL_STAGE_CONSUMED,
    &CELL_TRAILER,
    &CELL_TASK_ID,
    &SLEEP_DEADLINE,
    &DEADLINE_TV_SEC,
    &DEADLINE_TV_NSEC,
    &JOIN_HANDLE_RAW,
    &ACQUIRE_SEMAPHORE,
    &ACQUIRE_NUM_PERMITS,
    &ACQUIRE_NODE,
    &ACQUIRE_NEEDED,
    &ACQUIRE_QUEUED,
    &SEMAPHORE_PERMITS,
    &SEMAPHORE_QUEUE_HEAD,
    &WAITER_NEEDED,
    &WAITER_NEXT,
    &WAITER_WAKER,
    &WAKER_DATA,
    &WAKER_VTABLE,
    &SET_HEAD_ALL,
    &SET_NODE_FUTURE,
    &SET_NODE_NEXT,
    &JOIN_SET_LENGTH,
    &JOIN_SET_LISTS,
    &JOIN_SET_NOTIFIED_HEAD,
    &JOIN_SET_IDLE_HEAD,
    &JOIN_SET_ENTRY_VALUE,
    &JOIN_SET_ENTRY_NEXT,
];

// ---------------------------------------------------------------------------
// The runtime executor
// ---------------------------------------------------------------------------

/// Where a walk ended: at the terminal, or at one of the two outcomes
/// that are runtime states rather than failures.
pub enum Walked<'b> {
    At(TypeInfo<'b>),
    /// A [`Nav::Variant`] step found some other variant active; the
    /// name is the variant the step asked for.
    Inactive(&'static str),
    /// A [`Nav::Deref`] step found a null pointer.
    Null,
}

impl<'b> Walked<'b> {
    /// The terminal, for callers to whom an inactive variant (a `None`
    /// head, an unarmed waker) and a null pointer both mean "nothing
    /// here".
    pub fn optional(self) -> Option<TypeInfo<'b>> {
        match self {
            Walked::At(info) => Some(info),
            Walked::Inactive(_) | Walked::Null => None,
        }
    }

    /// The terminal, treating the runtime outcomes as errors — for
    /// paths whose steps admit neither.
    fn at(self, name: &str) -> Result<TypeInfo<'b>> {
        match self {
            Walked::At(info) => Ok(info),
            Walked::Inactive(v) => bail!("{name}: variant {v} is not active"),
            Walked::Null => bail!("{name}: null pointer"),
        }
    }
}

/// Why one alternative did not walk.
enum StepFail {
    /// The spelling does not match this layout (a member the type does
    /// not have): try the next alternative.
    Structural(String),
    /// A real failure — unreadable memory, a shape the static check
    /// would have rejected: no other alternative gets a try.
    Fatal(anyhow::Error),
}

impl WalkPath {
    /// Execute the path from `root`, trying the alternatives in order;
    /// the first whose spelling matches the layout binds.
    pub fn walk<'b, Ctx: ParseCtx>(
        &self,
        ctx: &Ctx,
        root: TypeInfoRef<'_, 'b>,
    ) -> Result<Walked<'b>> {
        match self.walk_inner(ctx, root)? {
            Ok(w) => Ok(w),
            Err(misses) => bail!("walk path {}: {}", self.name, misses.join("; ")),
        }
    }

    /// Like [`WalkPath::walk`], but a structural mismatch of every
    /// alternative is `None` — for [`Class::Optional`] members whose
    /// absence is an expected shape.
    pub fn try_walk<'b, Ctx: ParseCtx>(
        &self,
        ctx: &Ctx,
        root: TypeInfoRef<'_, 'b>,
    ) -> Result<Option<Walked<'b>>> {
        Ok(self.walk_inner(ctx, root)?.ok())
    }

    /// `Ok(Err(misses))` when no alternative's spelling matched the
    /// layout; the outer error is a real failure mid-walk.
    fn walk_inner<'b, Ctx: ParseCtx>(
        &self,
        ctx: &Ctx,
        root: TypeInfoRef<'_, 'b>,
    ) -> Result<std::result::Result<Walked<'b>, Vec<String>>> {
        let mut misses = Vec::new();
        for alt in self.alts {
            match walk_navs(ctx, root.clone(), alt) {
                Ok(w) => return Ok(Ok(w)),
                Err(StepFail::Structural(msg)) => misses.push(msg),
                Err(StepFail::Fatal(e)) => {
                    return Err(e.context(format!("walk path {}", self.name)));
                }
            }
        }
        Ok(Err(misses))
    }

    /// Walk to the terminal, where the steps admit no variant or null
    /// outcome (or where either would be a hard error anyway).
    pub fn walk_at<'b, Ctx: ParseCtx>(
        &self,
        ctx: &Ctx,
        root: TypeInfoRef<'_, 'b>,
    ) -> Result<TypeInfo<'b>> {
        self.walk(ctx, root)?.at(self.name)
    }

    /// Walk to the terminal and parse a value out of it.
    pub fn read<'b, V, Ctx>(&self, ctx: &Ctx, root: TypeInfoRef<'_, 'b>) -> Result<V>
    where
        Ctx: ParseCtx,
        V: ParseWithDbgInfo<'b, Ctx>,
    {
        let info = self.walk_at(ctx, root)?;
        info.parse(ctx)
            .with_context(|| format!("walk path {}", self.name))
    }

    /// [`WalkPath::read`] for a member whose absence is expected.
    pub fn try_read<'b, V, Ctx>(&self, ctx: &Ctx, root: TypeInfoRef<'_, 'b>) -> Result<Option<V>>
    where
        Ctx: ParseCtx,
        V: ParseWithDbgInfo<'b, Ctx>,
    {
        match self.try_walk(ctx, root)? {
            Some(w) => {
                let info = w.at(self.name)?;
                let v = info
                    .parse(ctx)
                    .with_context(|| format!("walk path {}", self.name))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    /// Resolve just this path against a bundle's type graph — what
    /// [`verify_walk_contract`] does for every table row.
    pub fn check(&self, view: &BundleView<'_>) -> Outcome {
        check_path(view, self)
    }

    /// The byte offset the path's first alternative reaches within
    /// `root` — for cross-checking a bundle layout against offsets the
    /// target itself records. Only member steps carry an offset; `None`
    /// where the navigation does not apply to this type.
    pub(crate) fn member_offset(&self, root: BundleType<'_>) -> Option<u64> {
        let mut ty = root;
        let mut offset = 0;
        for nav in *self.alts.first()? {
            let Nav::Member(name) = nav else { return None };
            let member = ty.member(name)?;
            offset += member.offset();
            let (peeled, inside) = peel_with_offset(member.ty());
            offset += inside;
            ty = peeled;
        }
        Some(offset)
    }
}

fn walk_navs<'b, Ctx: ParseCtx>(
    ctx: &Ctx,
    cur: TypeInfoRef<'_, 'b>,
    navs: &[Nav],
) -> std::result::Result<Walked<'b>, StepFail> {
    let [nav, rest @ ..] = navs else {
        return Ok(Walked::At(cur.to_owned()));
    };
    match nav {
        Nav::Member(name) => match cur.try_member(name) {
            Ok(Some(member)) => walk_navs(ctx, member, rest),
            Ok(None) => Err(StepFail::Structural(no_member(cur.ty, name))),
            Err(e) => Err(StepFail::Fatal(
                anyhow!(e).context(format!("member {name} of {}", cur.ty.name())),
            )),
        },
        Nav::Variant(name) => match cur.try_select_variant(name) {
            Ok(Some(payload)) => walk_navs(ctx, payload, rest),
            Ok(None) => Ok(Walked::Inactive(name)),
            Err(e) => Err(StepFail::Fatal(
                anyhow!(e).context(format!("variant {name} of {}", cur.ty.name())),
            )),
        },
        Nav::ActiveVariant => match cur.active_variant() {
            Ok((_name, payload)) => walk_navs(ctx, payload, rest),
            Err(e) => Err(StepFail::Fatal(
                anyhow!(e).context(format!("decoding the variant of {}", cur.ty.name())),
            )),
        },
        Nav::Deref => {
            let peeled = cur.clone().peel();
            let Some(&bytes) = peeled.bytes.first_chunk::<8>() else {
                return Err(StepFail::Fatal(anyhow!(
                    "{} is {} bytes, not a pointer",
                    peeled.ty.name(),
                    peeled.bytes.len()
                )));
            };
            if u64::from_le_bytes(bytes) == 0 {
                return Ok(Walked::Null);
            }
            match peeled.deref_ptr(ctx) {
                Ok(pointee) => walk_navs(ctx, pointee.as_ref(), rest),
                Err(e) => Err(StepFail::Fatal(
                    anyhow!(e).context(format!("dereferencing {}", peeled.ty.name())),
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Static verification
// ---------------------------------------------------------------------------

/// Resolve every path in the table against the bundle's type graph —
/// no target process, no memory reads — so a layout the walk cannot
/// navigate is one comprehensive report before the walk starts, not a
/// failure on the first task that hits it.
pub fn verify_walk_contract(view: &BundleView<'_>) -> ContractReport {
    let meta = &view.bundle().meta;
    let target = format!(
        "tokio {}, rustc {}",
        meta.tokio_version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned()),
        meta.rustc_version,
    );

    let mut entries = Vec::new();
    for (name, role, class) in [
        (
            "statics.tls_context_key",
            StaticRole::TlsContextKey,
            Required,
        ),
        (
            "statics.task_waker_vtable",
            StaticRole::TaskWakerVtable,
            Optional,
        ),
    ] {
        let outcome = if view.bundle().statics.entries.contains_key(&role) {
            Outcome::Resolved {
                alternative: 0,
                alternatives: 1,
                note: None,
            }
        } else {
            Outcome::Broken {
                errors: vec![format!(
                    "the bundle records no {role:?} static \
                     (was it extracted with --allow-missing-infra?)"
                )],
            }
        };
        entries.push(ContractEntry {
            name,
            class,
            outcome,
        });
    }

    for path in PATHS {
        entries.push(ContractEntry {
            name: path.name,
            class: path.class,
            outcome: check_path(view, path),
        });
    }
    ContractReport { target, entries }
}

/// One rooting of a path: a diagnostic label and the type to walk from.
type Rooted<'a> = (String, BundleType<'a>);

/// A resolved root set, or why there is none.
enum Roots<'a> {
    Types {
        types: Vec<Rooted<'a>>,
        note: Option<String>,
    },
    Absent(String),
    Broken(Vec<String>),
}

fn check_path(view: &BundleView<'_>, path: &WalkPath) -> Outcome {
    let (types, root_note) = match resolve_root(view, &path.root) {
        Roots::Types { types, note } => (types, note),
        Roots::Absent(reason) => return Outcome::Absent { reason },
        Roots::Broken(errors) => return Outcome::Broken { errors },
    };

    let mut bound: Option<usize> = None;
    let mut mixed = false;
    let mut errors = Vec::new();
    for (label, root) in &types {
        match resolve_alts(path, *root) {
            Ok((alt, terminals)) => {
                mixed |= bound.is_some_and(|prev| prev != alt);
                bound.get_or_insert(alt);
                for terminal in terminals {
                    if let Err(e) = terminal_ok(terminal, path.terminal) {
                        errors.push(format!("{label}: {e}"));
                    }
                }
            }
            Err(alt_errors) => {
                errors.push(format!("{label}: {}", alt_errors.join("; ")));
            }
        }
    }
    if !errors.is_empty() {
        if let Some(reason) = expected_absence(view, path) {
            return Outcome::Absent { reason };
        }
        return Outcome::Broken { errors };
    }
    let mut note = root_note;
    if mixed {
        let mixed_note = "different roots bound different alternatives".to_owned();
        note = Some(match note {
            Some(n) => format!("{n}; {mixed_note}"),
            None => mixed_note,
        });
    }
    Outcome::Resolved {
        alternative: bound.unwrap_or(0),
        alternatives: path.alts.len(),
        note,
    }
}

/// Why breakage on this path is the expected shape of the target
/// rather than drift: the capability its datum exists under is
/// recorded as off. An unrecorded capability returns `None` — absence
/// is only expected when the bundle can vouch for it.
fn expected_absence(view: &BundleView<'_>, path: &WalkPath) -> Option<String> {
    match path.needs? {
        Capability::TokioUnstable => match view.bundle().meta.tokio_unstable {
            Some(false) => Some("the target was built without tokio_unstable".to_owned()),
            Some(true) | None => None,
        },
    }
}

/// Resolve a path all the way to its terminal types (of the bound
/// alternative), for roots derived from other paths.
fn resolve_terminals<'a>(view: &BundleView<'a>, path: &WalkPath) -> Roots<'a> {
    let (types, note) = match resolve_root(view, &path.root) {
        Roots::Types { types, note } => (types, note),
        other => return other,
    };
    let mut out = Vec::new();
    for (label, root) in types {
        match resolve_alts(path, root) {
            Ok((_alt, terminals)) => {
                for terminal in terminals {
                    out.push((format!("{label}: {}", terminal.name()), terminal));
                }
            }
            Err(_) => {
                // The parent path reports its own breakage; a child
                // rooted at it has nothing to add.
                return Roots::Absent(format!("path {} did not resolve", path.name));
            }
        }
    }
    Roots::Types { types: out, note }
}

fn resolve_root<'a>(view: &BundleView<'a>, root: &Root) -> Roots<'a> {
    match root {
        Root::Infra(infra) => {
            let (name, id) = infra_id(view, *infra);
            let Some(ty) = view.ty(id) else {
                return Roots::Broken(vec![format!("the bundle has no type entry for {name}")]);
            };
            if matches!(ty.def(), TypeDef::Opaque { .. }) {
                return Roots::Broken(vec![format!(
                    "the bundle has no layout for {name} \
                     (was it extracted with --allow-missing-infra?)"
                )]);
            }
            Roots::Types {
                types: vec![(ty.name().to_owned(), ty)],
                note: None,
            }
        }
        Root::Leaf(prefix) => {
            let mut seen = std::collections::BTreeSet::new();
            let mut types = Vec::new();
            for (name, ty) in view.named_types() {
                if leaf_matches(prefix, name) && seen.insert(ty.id()) {
                    types.push((name.to_owned(), ty));
                }
            }
            if types.is_empty() {
                return Roots::Absent(format!(
                    "no {prefix}\u{2026} type in the bundle (the target does not reach one)"
                ));
            }
            let note = (types.len() > 1).then(|| format!("{} types", types.len()));
            Roots::Types { types, note }
        }
        Root::TaskCells => {
            let entries = &view.bundle().tasks.entries;
            let mut types = Vec::new();
            let mut opaque = 0usize;
            for entry in entries {
                let Some(cell) = view.ty(entry.cell) else {
                    opaque += 1;
                    continue;
                };
                if matches!(cell.def(), TypeDef::Opaque { .. }) {
                    opaque += 1;
                    continue;
                }
                let label = view.str(entry.display_name).unwrap_or("<anon>").to_owned();
                types.push((label, cell));
            }
            if types.is_empty() {
                return Roots::Absent(format!(
                    "the task table has no bound cells ({opaque} opaque of {})",
                    entries.len()
                ));
            }
            let note = Some(if opaque > 0 {
                format!("{} cells, {opaque} opaque skipped", types.len())
            } else {
                format!("{} cells", types.len())
            });
            Roots::Types { types, note }
        }
        Root::End(parent) => resolve_terminals(view, parent),
        Root::Pointee(parent) => match resolve_terminals(view, parent) {
            Roots::Types { types, note } => {
                let mut out = Vec::new();
                for (label, ty) in types {
                    let Some(target) = ty.pointer_target() else {
                        return Roots::Broken(vec![format!(
                            "{label}: {} is not a pointer",
                            ty.name()
                        )]);
                    };
                    out.push((label, peel(target)));
                }
                Roots::Types { types: out, note }
            }
            other => other,
        },
        Root::Elem(parent) => match resolve_terminals(view, parent) {
            Roots::Types { types, note } => {
                let mut out = Vec::new();
                for (label, ty) in types {
                    let Some(target) = ty.member("data_ptr").and_then(|m| m.ty().pointer_target())
                    else {
                        return Roots::Broken(vec![format!(
                            "{label}: {} has no data_ptr pointer to walk elements of",
                            ty.name()
                        )]);
                    };
                    out.push((label, peel(target)));
                }
                Roots::Types { types: out, note }
            }
            other => other,
        },
    }
}

fn infra_id(
    view: &BundleView<'_>,
    infra: InfraRoot,
) -> (&'static str, exegesis::bundle::BundleTypeId) {
    let roots = &view.bundle().infra;
    match infra {
        InfraRoot::Context => ("tokio::runtime::context::Context", roots.context),
        InfraRoot::Header => ("the task Header", roots.header),
        InfraRoot::Trailer => ("the task Trailer", roots.trailer),
        InfraRoot::Vtable => ("the task Vtable", roots.vtable),
        InfraRoot::Location => ("core::panic::Location", roots.location),
        InfraRoot::MtHandle => ("the multi_thread Handle", roots.mt_handle),
    }
}

/// Try the alternatives in order against one root; the first whose
/// spelling matches binds. `Ok` is the bound index and every terminal
/// type it can land on (one per variant, under [`Nav::ActiveVariant`]);
/// `Err` is one message per alternative.
fn resolve_alts<'a>(
    path: &WalkPath,
    root: BundleType<'a>,
) -> std::result::Result<(usize, Vec<BundleType<'a>>), Vec<String>> {
    let mut errors = Vec::new();
    for (i, alt) in path.alts.iter().enumerate() {
        match resolve_navs(root, alt) {
            Ok(terminals) => return Ok((i, terminals)),
            Err(e) => errors.push(if path.alts.len() > 1 {
                format!("[{}] {e}", spell(alt))
            } else {
                e
            }),
        }
    }
    Err(errors)
}

fn resolve_navs<'a>(
    ty: BundleType<'a>,
    navs: &[Nav],
) -> std::result::Result<Vec<BundleType<'a>>, String> {
    let [nav, rest @ ..] = navs else {
        return Ok(vec![ty]);
    };
    match nav {
        Nav::Member(name) => match ty.member(name) {
            Some(member) => resolve_navs(peel(member.ty()), rest),
            None => Err(no_member(ty, name)),
        },
        Nav::Variant(name) => {
            if ty.variant_shape().is_none() {
                return Err(format!("{} is not an enum", ty.name()));
            }
            match ty.variant(name) {
                Some((payload, _offset)) => resolve_navs(peel(payload), rest),
                None => Err(format!(
                    "no variant {name} in {} (has: {})",
                    ty.name(),
                    ty.variants().map(|v| v.name).collect::<Vec<_>>().join(", ")
                )),
            }
        }
        Nav::ActiveVariant => {
            let variants: Vec<_> = ty.variants().collect();
            if variants.is_empty() {
                return Err(format!("{} is not an enum", ty.name()));
            }
            let mut terminals = Vec::new();
            for variant in variants {
                let landed = resolve_navs(peel(variant.ty), rest)
                    .map_err(|e| format!("variant {} of {}: {e}", variant.name, ty.name()))?;
                terminals.extend(landed);
            }
            Ok(terminals)
        }
        Nav::Deref => match ty.pointer_target() {
            Some(target) => resolve_navs(peel(target), rest),
            None => Err(format!("{} is not a pointer", ty.name())),
        },
    }
}

/// The static mirror of [`TypeInfoRef::peel`]: descend the
/// single-sized-member wrapper chain, stopping at display leaves —
/// exactly where the walk's buffers stop.
fn peel(ty: BundleType<'_>) -> BundleType<'_> {
    peel_with_offset(ty).0
}

fn peel_with_offset(ty: BundleType<'_>) -> (BundleType<'_>, u64) {
    let mut ty = ty;
    let mut offset = 0;
    loop {
        if ty.is_display_leaf() || ty.kind() != TypeKind::Struct {
            return (ty, offset);
        }
        let mut sized = ty.members().filter(|m| m.ty().size() > 0);
        match (sized.next(), sized.next()) {
            (Some(member), None) => {
                offset += member.offset();
                ty = member.ty();
            }
            _ => return (ty, offset),
        }
    }
}

fn terminal_ok(ty: BundleType<'_>, terminal: Terminal) -> std::result::Result<(), String> {
    let ok = match terminal {
        Terminal::Word => ty.kind() == TypeKind::Integer && ty.size() <= 8,
        Terminal::Pointer => ty.kind() == TypeKind::Pointer,
        Terminal::Enum => ty.kind() == TypeKind::Enum,
        Terminal::Aggregate => matches!(ty.kind(), TypeKind::Struct | TypeKind::Union),
        Terminal::Slice => {
            ty.kind() == TypeKind::Struct
                && ty
                    .member("data_ptr")
                    .is_some_and(|m| m.ty().kind() == TypeKind::Pointer)
                && ty.member("length").is_some()
        }
        Terminal::Any => true,
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "landed on {} ({}), which is not {terminal:?}-shaped",
            ty.name(),
            ty.kind(),
        ))
    }
}

fn no_member(ty: BundleType<'_>, name: &str) -> String {
    let members: Vec<&str> = ty.members().map(|m| m.name()).collect();
    if members.is_empty() {
        format!("no member {name} in {} (which has no members)", ty.name())
    } else {
        format!(
            "no member {name} in {} (has: {})",
            ty.name(),
            members.join(", ")
        )
    }
}

/// A human spelling of one alternative's steps, for diagnostics:
/// `entry.<active variant>.deadline`, `unpark.*.data`.
fn spell(navs: &[Nav]) -> String {
    navs.iter()
        .map(|nav| match nav {
            Nav::Member(name) => (*name).to_owned(),
            Nav::Variant(name) => format!("<{name}>"),
            Nav::ActiveVariant => "<active variant>".to_owned(),
            Nav::Deref => "*".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// How [`ContractReport::check`] treats breakage below
/// [`Class::Required`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WalkPolicy {
    /// Any broken path refuses to attach. The default: a silently
    /// degraded walk is how drift goes unnoticed.
    Strict,
    /// Only [`Class::Required`] breakage refuses; everything else
    /// degrades at the site that walks it, for looking at a target
    /// whose inessential layouts have moved.
    BestEffort,
}

/// What became of one table entry.
#[derive(Clone, Debug)]
pub enum Outcome {
    Resolved {
        /// Which alternative bound (0-based) of how many. Anything but
        /// the first is a fallback worth noticing in a report diff.
        alternative: usize,
        alternatives: usize,
        note: Option<String>,
    },
    /// Nothing to verify, expectedly: a leaf the target does not use,
    /// an instrumentation member of a plain build.
    Absent {
        reason: String,
    },
    Broken {
        errors: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub struct ContractEntry {
    pub name: &'static str,
    pub class: Class,
    pub outcome: Outcome,
}

impl ContractEntry {
    pub fn is_broken(&self) -> bool {
        matches!(self.outcome, Outcome::Broken { .. })
    }

    fn line(&self) -> String {
        match &self.outcome {
            Outcome::Resolved {
                alternative,
                alternatives,
                note,
            } => {
                let mut extras = Vec::new();
                if *alternatives > 1 {
                    extras.push(format!("alternative {} of {alternatives}", alternative + 1));
                }
                if let Some(note) = note {
                    extras.push(note.clone());
                }
                if extras.is_empty() {
                    format!("ok      {}", self.name)
                } else {
                    format!("ok      {} ({})", self.name, extras.join("; "))
                }
            }
            Outcome::Absent { reason } => format!("absent  {} — {reason}", self.name),
            Outcome::Broken { errors } => {
                format!("BROKEN  {} — {}", self.name, errors.join("; "))
            }
        }
    }
}

/// The result of resolving the whole table against one bundle.
#[derive(Clone, Debug)]
pub struct ContractReport {
    /// "tokio 1.50.0, rustc …" — the versions the bundle records, for
    /// diagnostics only. Nothing branches on them.
    pub target: String,
    pub entries: Vec<ContractEntry>,
}

impl ContractReport {
    pub fn is_clean(&self) -> bool {
        !self.entries.iter().any(ContractEntry::is_broken)
    }

    /// The broken entries the given policy walks past — what a caller
    /// in best-effort mode should warn about.
    pub fn degraded(&self, policy: WalkPolicy) -> Vec<String> {
        match policy {
            WalkPolicy::Strict => Vec::new(),
            WalkPolicy::BestEffort => self
                .entries
                .iter()
                .filter(|e| e.is_broken() && e.class != Class::Required)
                .map(ContractEntry::line)
                .collect(),
        }
    }

    /// Enforce the policy: an error naming every path that refuses the
    /// attach, or `Ok` — possibly with degraded paths left for
    /// [`ContractReport::degraded`] to report.
    pub fn check(&self, policy: WalkPolicy) -> Result<()> {
        let fatal: Vec<&ContractEntry> = self
            .entries
            .iter()
            .filter(|e| {
                e.is_broken() && (e.class == Class::Required || policy == WalkPolicy::Strict)
            })
            .collect();
        if fatal.is_empty() {
            return Ok(());
        }
        let lines: Vec<String> = fatal.iter().map(|e| format!("  {}", e.line())).collect();
        bail!(
            "the bundle's walk contract does not hold against this tokio ({}):\n{}",
            self.target,
            lines.join("\n")
        );
    }

    /// The entry for a path, by its table name.
    pub fn entry(&self, name: &str) -> Option<&ContractEntry> {
        self.entries.iter().find(|e| e.name == name)
    }
}

impl fmt::Display for ContractReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let broken = self.entries.iter().filter(|e| e.is_broken()).count();
        let absent = self
            .entries
            .iter()
            .filter(|e| matches!(e.outcome, Outcome::Absent { .. }))
            .count();
        writeln!(
            f,
            "walk contract ({}): {} entries, {} broken, {} absent",
            self.target,
            self.entries.len(),
            broken,
            absent
        )?;
        for entry in &self.entries {
            writeln!(f, "  {}", entry.line())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &'static str, class: Class, outcome: Outcome) -> ContractEntry {
        ContractEntry {
            name,
            class,
            outcome,
        }
    }

    fn ok() -> Outcome {
        Outcome::Resolved {
            alternative: 0,
            alternatives: 1,
            note: None,
        }
    }

    fn broken(msg: &str) -> Outcome {
        Outcome::Broken {
            errors: vec![msg.to_owned()],
        }
    }

    fn report(entries: Vec<ContractEntry>) -> ContractReport {
        ContractReport {
            target: "tokio 1.50.0, rustc test".to_owned(),
            entries,
        }
    }

    /// Required breakage refuses the attach under either policy.
    #[test]
    fn test_required_breakage_always_refuses() {
        let r = report(vec![entry(
            "Header.state",
            Class::Required,
            broken("no member state"),
        )]);
        for policy in [WalkPolicy::Strict, WalkPolicy::BestEffort] {
            let err = r.check(policy).expect_err("required breakage refuses");
            let text = format!("{err:#}");
            assert!(text.contains("Header.state"), "{text}");
            assert!(text.contains("tokio 1.50.0"), "{text}");
        }
    }

    /// Optional breakage refuses under Strict and degrades under
    /// BestEffort — where it is reported, not swallowed.
    #[test]
    fn test_optional_breakage_degrades_under_best_effort() {
        let r = report(vec![
            entry("Header.state", Class::Required, ok()),
            entry("Sleep.deadline", Class::Optional, broken("no member entry")),
        ]);
        assert!(r.check(WalkPolicy::Strict).is_err());
        r.check(WalkPolicy::BestEffort)
            .expect("optional breakage degrades");
        let degraded = r.degraded(WalkPolicy::BestEffort);
        assert_eq!(degraded.len(), 1);
        assert!(degraded[0].contains("Sleep.deadline"), "{degraded:?}");
        assert!(r.degraded(WalkPolicy::Strict).is_empty());
        assert!(!r.is_clean());
    }

    /// Expected absences — an unused leaf, a plain build's missing
    /// instrumentation member — are not breakage under any policy.
    #[test]
    fn test_absence_is_not_breakage() {
        let r = report(vec![
            entry("Header.state", Class::Required, ok()),
            entry(
                "Sleep.deadline",
                Class::Optional,
                Outcome::Absent {
                    reason: "no tokio::time::sleep::Sleep… type in the bundle".to_owned(),
                },
            ),
        ]);
        r.check(WalkPolicy::Strict).expect("absence is expected");
        assert!(r.is_clean());
        let shown = r.to_string();
        assert!(shown.contains("absent  Sleep.deadline"), "{shown}");
    }

    /// The report names which alternative bound, so "1.55 silently
    /// started taking the fallback" is a reviewable diff.
    #[test]
    fn test_report_names_the_bound_alternative() {
        let r = report(vec![entry(
            "Sleep.deadline",
            Class::Optional,
            Outcome::Resolved {
                alternative: 1,
                alternatives: 2,
                note: None,
            },
        )]);
        assert!(
            r.to_string().contains("alternative 2 of 2"),
            "{}",
            r.to_string()
        );
    }

    /// An exact leaf key must not take lookalike siblings with it —
    /// `AcquireError` shares `Acquire`'s prefix in a real sled-agent
    /// bundle — while a `<`-terminated key spans its monomorphizations.
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
        assert_eq!(
            spell(&[M("entry"), ActiveVariant, M("deadline")]),
            "entry.<active variant>.deadline"
        );
        assert_eq!(spell(&[M("unpark"), Deref, M("data")]), "unpark.*.data");
        assert_eq!(spell(&[M("head"), V("Some")]), "head.<Some>");
    }
}

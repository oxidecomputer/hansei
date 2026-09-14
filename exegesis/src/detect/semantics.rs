// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The reviewed compiler conventions semantic bindings may rely on.
//!
//! A convention here is a statement about what a compiler's debuginfo
//! *means* — which variant of a coroutine's state enum is which stage,
//! which fields of a suspended state are live — reviewed against the
//! compiler sources for an inclusive version range. It is separate from
//! the display detectors' family dispatch on purpose: a renderer's
//! fallback to its newest family produces a best-guess picture, while a
//! semantic rule authorizes reading storage or following a poll, and a
//! version outside every reviewed range gets no rule at all, however
//! familiar its layout looks.

use crate::bundle::{LayoutSelection, ResourceKind, SemanticRuleKind};
use crate::provenance::rustc_version;

/// One reviewed rustc convention: its name, as the bundle's `Rustc`
/// origin records it, and the inclusive `(major, minor)` range of
/// compiler versions it was reviewed against.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RustcConvention {
    pub family: &'static str,
    pub floor: (u64, u64),
    pub ceiling: (u64, u64),
}

impl RustcConvention {
    fn covers(&self, version: (u64, u64)) -> bool {
        version >= self.floor && version <= self.ceiling
    }
}

/// The coroutine state-machine convention rustc 1.97 and 1.98 emit,
/// reviewed against `rustc_codegen_llvm::debuginfo::metadata::enums`'
/// coroutine variant naming and `rustc_mir_transform::coroutine`'s
/// layout: the env is an enum whose variant members are numbered in
/// declaration order, variant 0 is `Unresumed` and holds the arguments,
/// 1 is `Returned`, 2 is `Panicked` (both empty once the arguments
/// listed on them are recognized as stale), and every variant from 3
/// on is `Suspend<n - 3>` whose payload lists exactly the locals live
/// across that await, `__awaitee` among them. An async block's suspend
/// states also list its captures, moved or not.
///
/// The ceiling is the newest toolchain in `test-programs/matrix.toml`;
/// it advances by hand when a release is onboarded and its cells'
/// goldens have been read. A newer compiler emitting the same shape
/// stays unbound: identical fields do not prove identical meaning.
pub const RUSTC_COROUTINE_V1_97: RustcConvention = RustcConvention {
    family: "rustc-coroutine-1.97",
    floor: (1, 97),
    ceiling: (1, 98),
};

/// The standard pointer adapters rustc 1.97 and 1.98 build, reviewed
/// against `library/core/src/future/future.rs` and
/// `library/alloc/src/boxed.rs` (identical across the three matrix
/// toolchains), and the layouts their debuginfo spells: `Pin<Ptr>` is a
/// struct whose one member `pointer` is its `Ptr`; a sized `Box<F, Global>`
/// and a `&mut F` are thin pointers named in full; their unsized forms
/// over a trait object are `{ pointer, vtable }` wide pointers. Each
/// adapter's `Future::poll` forwards one poll to exactly the value it
/// points at — `F::poll(Pin::new(&mut **self))` for the reference,
/// `F::poll(Pin::new(&mut *self))` for the box, `<P::Target as
/// Future>::poll(self.as_deref_mut())` for `Pin` — and does nothing
/// else, which is what lets these rules carry the exclusive bit.
pub const RUSTC_STD_ADAPTERS_V1_97: RustcConvention = RustcConvention {
    family: "rustc-std-adapters-1.97",
    floor: (1, 97),
    ceiling: (1, 98),
};

/// The `dyn Future` vtable rustc 1.97 and 1.98 lay out: the drop-in-place
/// pointer, the size and the alignment words, then the trait's methods
/// in declaration order — `poll` alone for `Future` — so a wide pointer's
/// metadata is at least four words and slot 3 is the poll. Reviewed
/// against `rustc_middle::ty::vtable` (`COMMON_VTABLE_ENTRIES`) for the
/// same range; the matching debuginfo spells the vtable pointer as a
/// `&[usize; N]`.
pub const RUSTC_DYN_FUTURE_ABI_V1_97: RustcConvention = RustcConvention {
    family: "rustc-dyn-future-abi-1.97",
    floor: (1, 97),
    ceiling: (1, 98),
};

fn rustc_convention(
    producer: &str,
    reviewed: &[&'static RustcConvention],
) -> Option<&'static RustcConvention> {
    let version = rustc_version(producer)?;
    let version = (version.major, version.minor);
    reviewed.iter().copied().find(|c| c.covers(version))
}

/// The coroutine convention a producer string is covered by, if any:
/// rustc's own producer grammar, a parseable version, inside one
/// reviewed range. Any other producer — another compiler, a version
/// outside every range, an unparseable token — has none.
pub fn rustc_coroutine_convention(producer: &str) -> Option<&'static RustcConvention> {
    rustc_convention(producer, &[&RUSTC_COROUTINE_V1_97])
}

/// The std adapter convention covering a producer, selected like
/// [`rustc_coroutine_convention`].
pub fn rustc_std_adapter_convention(producer: &str) -> Option<&'static RustcConvention> {
    rustc_convention(producer, &[&RUSTC_STD_ADAPTERS_V1_97])
}

/// The `dyn Future` ABI convention covering a producer, selected like
/// [`rustc_coroutine_convention`].
pub fn rustc_dyn_future_abi_convention(producer: &str) -> Option<&'static RustcConvention> {
    rustc_convention(producer, &[&RUSTC_DYN_FUTURE_ABI_V1_97])
}

/// One reviewed third-party implementation: the crate, the family name
/// the bundle's delegation origin records, the inclusive version range
/// the implementation was read at, and the checksums of its reviewed
/// source file — a corroborating check when a line table carries one,
/// which rustc's DWARF 4 output never does.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct LibraryConvention {
    pub package: &'static str,
    pub family: &'static str,
    pub floor: (u64, u64, u64),
    pub ceiling: (u64, u64, u64),
    /// `(file, md5)` for every reviewed revision of the implementing file.
    pub checksums: &'static [(&'static str, [u8; 16])],
}

impl LibraryConvention {
    /// The version's place against the reviewed range: reviewed inside
    /// it, or which side it falls on. A delegation rule binds only
    /// inside; the other two are the decline's reason.
    pub fn select(&self, version: &semver::Version) -> LayoutSelection {
        let version = (version.major, version.minor, version.patch);
        if version < self.floor {
            LayoutSelection::BelowFloor
        } else if version > self.ceiling {
            LayoutSelection::AboveReviewedRange
        } else {
            LayoutSelection::ReviewedRange
        }
    }

    /// Whether a checksum the line table carried is one of the reviewed
    /// revisions of the implementing file.
    pub fn reviewed_checksum(&self, md5: &[u8; 16]) -> bool {
        self.checksums.iter().any(|(_, reviewed)| reviewed == md5)
    }

    /// The range as a decline reason spells it: `0.1.40–0.1.44`.
    pub fn range(&self) -> String {
        let (a, b, c) = self.floor;
        let (x, y, z) = self.ceiling;
        format!("{a}.{b}.{c}–{x}.{y}.{z}")
    }
}

/// `tracing::Instrumented<T>` as tracing 0.1.40 through 0.1.44 implement
/// it, reviewed in `src/instrument.rs` of each release (0.1.42–0.1.44
/// differ from 0.1.40–0.1.41 only in a doc link and a `crate::` path
/// spelling): the struct is `{ inner: ManuallyDrop<T>, span: Span }`
/// and its `Future::poll` enters `span`, then polls `inner` and nothing
/// else. Entering a span runs the subscriber's `enter`/`exit`
/// callbacks, which the review does not bound, so the rule forwards
/// without the exclusive bit. `ManuallyDrop` is std's, navigated by the
/// binder under the compiler's reviewed range.
///
/// The ceiling is the newest release reviewed; a newer tracing with the
/// same shape stays unbound until read.
pub const TRACING_INSTRUMENTED_V0_1_40: LibraryConvention = LibraryConvention {
    package: "tracing",
    family: "tracing-instrumented-0.1.40",
    floor: (0, 1, 40),
    ceiling: (0, 1, 44),
    checksums: &[
        // 0.1.40 and 0.1.41.
        (
            "src/instrument.rs",
            [
                0xd3, 0xe1, 0xa1, 0x87, 0xc6, 0x25, 0x37, 0xd0, 0xbc, 0x26, 0x3d, 0x97, 0x2f, 0x8e,
                0xaf, 0xe5,
            ],
        ),
        // 0.1.42 through 0.1.44.
        (
            "src/instrument.rs",
            [
                0x0d, 0x91, 0xbb, 0x22, 0x90, 0x0f, 0x9a, 0x5d, 0xaa, 0xe4, 0x71, 0x7a, 0x21, 0x96,
                0xfa, 0x56,
            ],
        ),
    ],
};

/// futures-util's `map`, `map_err` and `into_future` combinators as
/// 0.3.30 through 0.3.34 implement them — the newest release at the
/// review, with 0.3.30's `map.rs` differing only in writing
/// `Map::Complete` where the others write `Self::Complete`.
///
/// `map::Map<Fut, F>` (`src/future/future/map.rs`) is the enum
/// `Incomplete { future, f } | Complete`, and its `poll` polls `future`
/// in the `Incomplete` state and nothing else, replacing the state with
/// `Complete` and calling `f` only on the output; polling a `Complete`
/// panics, so that state means the output was already produced. The
/// public `Map` (`src/future/future/mod.rs`), `MapErr`
/// (`src/future/try_future/mod.rs`) and every other `delegate_all!`
/// newtype hold their subject in one member `inner` and forward one
/// poll to it through `delegate_future!` (`src/lib.rs`), which is the
/// macro's whole `Future` impl. `IntoFuture<Fut>`
/// (`src/future/try_future/into_future.rs`) holds `future` and forwards
/// `try_poll`, which for a `TryFuture` blanket impl is that future's
/// own poll. All four therefore poll exactly their delegate.
///
/// `stream::Next<'_, St>` (`src/stream/stream/next.rs`, byte-identical
/// across the range) is `{ stream: &mut St }` and its `poll` is
/// `self.stream.poll_next_unpin(cx)` and nothing else: one poll of the
/// stream it borrows, so it forwards exclusively too — to a stream,
/// which the route names without claiming it a future.
///
/// The checksums are the reviewed revisions of every file a `poll`
/// declaration in this set can name — the four implementations, the
/// two `delegate_all!` invocation sites and the macro's own file — so
/// a build whose line table carries one is checked against the
/// revision that was read.
pub const FUTURES_UTIL_ADAPTERS_V0_3_30: LibraryConvention = LibraryConvention {
    package: "futures-util",
    family: "futures-util-adapters-0.3.30",
    floor: (0, 3, 30),
    ceiling: (0, 3, 34),
    checksums: &[
        // src/lib.rs, 0.3.30
        (
            "src/lib.rs",
            [
                0xc9, 0xa1, 0xf7, 0xa2, 0xfd, 0x98, 0xbc, 0x0f, 0x4e, 0x58, 0x6f, 0x9f, 0x7e, 0xf3,
                0x18, 0x8a,
            ],
        ),
        // src/lib.rs, 0.3.31
        (
            "src/lib.rs",
            [
                0xf3, 0x73, 0xdd, 0x95, 0x27, 0xd2, 0xcf, 0x96, 0x66, 0x47, 0x26, 0x71, 0x1c, 0x95,
                0x81, 0x6d,
            ],
        ),
        // src/lib.rs, 0.3.32
        (
            "src/lib.rs",
            [
                0xc1, 0x00, 0x20, 0xe3, 0x65, 0x1d, 0xd5, 0xb5, 0x80, 0xad, 0x57, 0xca, 0x10, 0x15,
                0x3c, 0xdb,
            ],
        ),
        // src/lib.rs, 0.3.33 and 0.3.34
        (
            "src/lib.rs",
            [
                0x10, 0xf5, 0xe2, 0x30, 0x8f, 0x4c, 0x3c, 0xc9, 0x04, 0xd2, 0x4a, 0x76, 0xcb, 0x36,
                0x73, 0x13,
            ],
        ),
        // src/future/future/mod.rs, 0.3.30 and 0.3.31
        (
            "src/future/future/mod.rs",
            [
                0xa2, 0x39, 0x97, 0xb2, 0x50, 0x9f, 0x94, 0x24, 0x22, 0xf4, 0x7b, 0x21, 0x63, 0x84,
                0xc2, 0xaa,
            ],
        ),
        // src/future/future/mod.rs, 0.3.32 through 0.3.34
        (
            "src/future/future/mod.rs",
            [
                0x1b, 0xf8, 0x2c, 0x15, 0x76, 0x85, 0x3d, 0x4d, 0x1c, 0x3c, 0x8f, 0xe0, 0xd8, 0x39,
                0x2c, 0x4f,
            ],
        ),
        // src/future/future/map.rs, 0.3.30
        (
            "src/future/future/map.rs",
            [
                0x4a, 0x4c, 0x01, 0x20, 0x27, 0xb6, 0xbf, 0x41, 0xb2, 0x61, 0xb0, 0xb9, 0x7b, 0x18,
                0x0e, 0x17,
            ],
        ),
        // src/future/future/map.rs, 0.3.31 through 0.3.34
        (
            "src/future/future/map.rs",
            [
                0xbe, 0x7a, 0x88, 0xd9, 0xfa, 0x47, 0x03, 0x88, 0xe4, 0x94, 0x9e, 0x84, 0x90, 0xbf,
                0x08, 0x7f,
            ],
        ),
        // src/future/try_future/mod.rs, 0.3.30 through 0.3.32
        (
            "src/future/try_future/mod.rs",
            [
                0x93, 0xa1, 0xdb, 0xc4, 0xb7, 0x19, 0x86, 0x40, 0x88, 0x6b, 0x1b, 0x9d, 0x91, 0x33,
                0xae, 0x4b,
            ],
        ),
        // src/future/try_future/mod.rs, 0.3.33 and 0.3.34
        (
            "src/future/try_future/mod.rs",
            [
                0x54, 0x58, 0x00, 0xee, 0xf2, 0x0a, 0x5c, 0x6f, 0x93, 0xe2, 0x21, 0x12, 0x6b, 0xb7,
                0xdf, 0x27,
            ],
        ),
        // src/future/try_future/into_future.rs, 0.3.30 through 0.3.34
        (
            "src/future/try_future/into_future.rs",
            [
                0x2e, 0x11, 0x59, 0xc1, 0xd4, 0x4e, 0x02, 0x07, 0x2d, 0xb7, 0xb6, 0xd4, 0x35, 0xc8,
                0xa0, 0xc6,
            ],
        ),
        // src/stream/stream/next.rs, 0.3.30 through 0.3.34
        (
            "src/stream/stream/next.rs",
            [
                0x1b, 0xd8, 0x24, 0x3a, 0xe6, 0x0b, 0x46, 0xb4, 0x36, 0x7e, 0x8a, 0x1f, 0xfa, 0x0b,
                0x0b, 0x1d,
            ],
        ),
    ],
};

/// hyper-util's `TokioSleep` as 0.1.10 through 0.1.20 implement it
/// (`src/rt/tokio.rs`, whose `struct TokioSleep { inner:
/// tokio::time::Sleep }` and `Future` impl are identical across the
/// range): the newtype exists to give tokio's `!Unpin` sleep a trait
/// object, and its `poll` is `self.project().inner.poll(cx)` and
/// nothing else. `reset` writes a new deadline through the same
/// member, which the sleep's own state protocol reads.
pub const HYPER_UTIL_TOKIO_SLEEP_V0_1_10: LibraryConvention = LibraryConvention {
    package: "hyper-util",
    family: "hyper-util-tokio-sleep-0.1.10",
    floor: (0, 1, 10),
    ceiling: (0, 1, 20),
    checksums: &[
        // src/rt/tokio.rs, 0.1.10
        (
            "src/rt/tokio.rs",
            [
                0x1c, 0xd3, 0x1e, 0x4f, 0x80, 0xb7, 0x5a, 0x9a, 0xe8, 0xfd, 0x45, 0x30, 0xe1, 0x9d,
                0x43, 0x5d,
            ],
        ),
        // src/rt/tokio.rs, 0.1.11 through 0.1.16
        (
            "src/rt/tokio.rs",
            [
                0x5b, 0x0e, 0x28, 0xad, 0xea, 0xfd, 0xa6, 0x44, 0x6e, 0x58, 0x42, 0x4d, 0x18, 0x18,
                0x51, 0x51,
            ],
        ),
        // src/rt/tokio.rs, 0.1.17
        (
            "src/rt/tokio.rs",
            [
                0x4a, 0x0f, 0xe6, 0x73, 0xd1, 0x7f, 0x35, 0xf0, 0xed, 0x2d, 0xa3, 0x3f, 0x9a, 0x2b,
                0xc4, 0x27,
            ],
        ),
        // src/rt/tokio.rs, 0.1.18 through 0.1.20
        (
            "src/rt/tokio.rs",
            [
                0xf2, 0x23, 0xf4, 0x72, 0x6f, 0xff, 0x7b, 0x25, 0xdb, 0xfd, 0x94, 0xfc, 0x45, 0x3f,
                0xad, 0xf6,
            ],
        ),
    ],
};

/// tokio's `select!` as 1.47 through 1.53 expand it (`src/macros/select.rs`;
/// the releases differ only in doc comments and in spelling `Poll`,
/// `Pin` and `ready!` through `$crate::macros::support`). The macro
/// stores the branch futures in a tuple on the enclosing frame, keeps a
/// `disabled` bit mask beside it — `u8` up to eight branches, then
/// `u16`, `u32`, `u64`, tokio-macros' choice by branch count — sets bit
/// `i` before the first poll when branch `i`'s precondition is false,
/// and awaits a `poll_fn` whose closure captures exactly those two by
/// unique borrow (`_ref__disabled`, `_ref__futures`). Each poll walks
/// the tuple from a random (or, under `biased;`, zero) start, skips the
/// members whose bit is set, polls the rest, and sets the bit of one
/// that completed with an output missing its pattern. Neither `biased;`
/// nor an `else` branch adds a capture. Every other capture is the
/// user's, evaluated outside the closure: preconditions before it,
/// handlers after it.
///
/// The closure environment is declared under the user's function, so
/// the rule keys on its declaration file rather than its name; tokio's
/// version is read off that file's registry path the way a third-party
/// rule's is, not from the layout family.
pub const TOKIO_SELECT_V1_47: LibraryConvention = LibraryConvention {
    package: "tokio",
    family: "tokio-select-1.47",
    floor: (1, 47, 0),
    ceiling: (1, 53, 1),
    checksums: &[
        // src/macros/select.rs, 1.47.0 through 1.47.5
        (
            "src/macros/select.rs",
            [
                0x28, 0x0b, 0xf9, 0x6d, 0xd4, 0xe7, 0x0d, 0xd5, 0x88, 0xdb, 0x17, 0xda, 0x06, 0x6e,
                0xcf, 0xc0,
            ],
        ),
        // src/macros/select.rs, 1.48.0 and 1.49.0
        (
            "src/macros/select.rs",
            [
                0x37, 0x45, 0xb7, 0x7b, 0xf6, 0xb0, 0x12, 0x2c, 0x6c, 0xb2, 0x8b, 0xca, 0x26, 0x12,
                0x59, 0x6f,
            ],
        ),
        // src/macros/select.rs, 1.50.0
        (
            "src/macros/select.rs",
            [
                0xc4, 0x36, 0x6c, 0xb2, 0xaf, 0x3e, 0xfa, 0xa2, 0xd9, 0x28, 0xbb, 0x8d, 0x92, 0xc8,
                0x75, 0x5d,
            ],
        ),
        // src/macros/select.rs, 1.51.4 through 1.52.4
        (
            "src/macros/select.rs",
            [
                0x7d, 0xa7, 0x40, 0x76, 0xc7, 0x0a, 0xb9, 0x7d, 0x76, 0xe5, 0x98, 0xb2, 0x2d, 0x57,
                0x38, 0x50,
            ],
        ),
        // src/macros/select.rs, 1.53.0 and 1.53.1
        (
            "src/macros/select.rs",
            [
                0xc9, 0xe7, 0xff, 0xf5, 0xf8, 0x88, 0x9c, 0xe2, 0x55, 0x88, 0x62, 0x1c, 0x40, 0x18,
                0xb0, 0xf5,
            ],
        ),
    ],
};

/// tokio's `task::coop::Coop<F>` as 1.47 through 1.53 implement it
/// (`src/task/coop/mod.rs`; 1.48 rewrote the module's docs and budget
/// helpers around an unchanged wrapper): the struct is `{ fut: F }`,
/// and its `Future::poll` asks the budget for a unit with
/// `poll_proceed`, returning `Pending` without touching `fut` when the
/// budget is spent, else polls `fut` and nothing else, marking the
/// unit consumed when that poll is ready. So the wrapper forwards one
/// poll exclusively: the budget check runs no other future. tokio's
/// own `cooperative()` puts this around every leaf a `Receiver::changed`
/// awaits, which is why every watch chain crosses it.
///
/// tokio's version is read off the poll's declaration file the way the
/// `select!` rule reads it, not from the layout family: the reviewed
/// evidence is the poll body, and the checksum is of that file.
pub const TOKIO_COOP_V1_47: LibraryConvention = LibraryConvention {
    package: "tokio",
    family: "tokio-coop-1.47",
    floor: (1, 47, 0),
    ceiling: (1, 53, 1),
    checksums: &[
        // src/task/coop/mod.rs, 1.47.0 through 1.47.5
        (
            "src/task/coop/mod.rs",
            [
                0xee, 0xfb, 0xbb, 0xdf, 0xee, 0xf4, 0x0a, 0xc3, 0x53, 0xd4, 0xb6, 0x42, 0x28, 0x7c,
                0x6b, 0x36,
            ],
        ),
        // src/task/coop/mod.rs, 1.48.0 through 1.53.1
        (
            "src/task/coop/mod.rs",
            [
                0x83, 0x7d, 0x88, 0xd2, 0x07, 0x3f, 0xc3, 0xa5, 0x44, 0x45, 0x6d, 0x1d, 0x49, 0x0d,
                0xbe, 0x45,
            ],
        ),
    ],
};

/// tokio-stream's `WatchStream<T>` as 0.1.14 through 0.1.19 implement
/// it (`src/wrappers/watch.rs`; the revisions differ in docs, in where
/// the `from_changes` constructor sits, and in 0.1.19 re-arming the
/// stream after a closed channel): the struct is `{ inner:
/// ReusableBoxFuture<'static, (Result<(), RecvError>, Receiver<T>)> }`
/// and its `poll_next` is `ready!(self.inner.poll(cx))`, then a fresh
/// `make_future(rx)` set into the same box. So polling the stream polls
/// the one box it owns and nothing else — a storage route, not a
/// future: the stream has no `poll`, and the rule is read off the
/// type's own method declarations.
pub const TOKIO_STREAM_WATCH_V0_1_14: LibraryConvention = LibraryConvention {
    package: "tokio-stream",
    family: "tokio-stream-watch-0.1.14",
    floor: (0, 1, 14),
    ceiling: (0, 1, 19),
    checksums: &[
        // src/wrappers/watch.rs, 0.1.14
        (
            "src/wrappers/watch.rs",
            [
                0xda, 0x55, 0x51, 0x47, 0x0d, 0xf7, 0x61, 0x1c, 0xd2, 0xbb, 0xce, 0x32, 0x39, 0x30,
                0xd4, 0x93,
            ],
        ),
        // src/wrappers/watch.rs, 0.1.15
        (
            "src/wrappers/watch.rs",
            [
                0xf7, 0xc7, 0x13, 0x36, 0xb1, 0xbb, 0x26, 0x87, 0xfe, 0xf7, 0x63, 0xf7, 0xda, 0x5d,
                0x14, 0xe6,
            ],
        ),
        // src/wrappers/watch.rs, 0.1.16 and 0.1.17
        (
            "src/wrappers/watch.rs",
            [
                0x35, 0xef, 0x04, 0x87, 0x66, 0xb0, 0xe6, 0x94, 0x96, 0x6a, 0x7c, 0x46, 0x7e, 0x4a,
                0xa7, 0x95,
            ],
        ),
        // src/wrappers/watch.rs, 0.1.18 and 0.1.19
        (
            "src/wrappers/watch.rs",
            [
                0x31, 0x0c, 0x15, 0xb6, 0x8d, 0x82, 0xfe, 0xec, 0x95, 0x0d, 0x54, 0xfb, 0xdc, 0x30,
                0xb0, 0xf3,
            ],
        ),
    ],
};

/// tokio-util's `ReusableBoxFuture<'a, T>` as 0.7.11 through 0.7.19
/// implement it (`src/sync/reusable_box.rs`, byte-identical across the
/// range): the struct is `{ boxed: Pin<Box<dyn Future<Output = T> +
/// Send + 'a>> }`, its inherent `poll` is `self.get_pin().poll(cx)` over
/// that box, and its `Future` impl is that same `poll`. `set` and
/// `try_set` replace the box's contents in place, never the box. So
/// every poll goes through `boxed` and nothing else — a storage route
/// to the trait object, whose resolution is the dyn join's. The route
/// is what matters; whether the `Future` impl was instantiated is the
/// caller's business (`WatchStream` calls the inherent one), so the
/// rule is read off the type's method declarations, not a `poll`'s.
pub const TOKIO_UTIL_REUSABLE_BOX_V0_7_11: LibraryConvention = LibraryConvention {
    package: "tokio-util",
    family: "tokio-util-reusable-box-0.7.11",
    floor: (0, 7, 11),
    ceiling: (0, 7, 19),
    checksums: &[
        // src/sync/reusable_box.rs, 0.7.11 through 0.7.19
        (
            "src/sync/reusable_box.rs",
            [
                0xd9, 0x44, 0xcc, 0x7b, 0x66, 0xde, 0x9d, 0xde, 0xde, 0x3f, 0x8e, 0xe1, 0x29, 0x03,
                0x0c, 0xc9,
            ],
        ),
    ],
};

/// tokio-stream's `StreamMap<K, V>` as 0.1.14 through 0.1.19 implement
/// it (`src/stream_map.rs`): the struct is `{ entries: Vec<(K, V)> }`,
/// and `poll_next_entry` picks a random start index and polls every
/// entry in turn **with the task's own context** until one is ready,
/// removing an exhausted entry and leaving a pending one registered.
/// So every pending entry holds the polling task's waker directly —
/// there is no per-child waker as in a `FuturesUnordered` — and the
/// map is a container whose children are the task's own branches.
/// The file's checksum moves every release (docs, iterators, the
/// `rand` shim), while the struct and that poll body are the same
/// text in all six, up to 0.1.14's `use Poll::*`. The type is no
/// future and has no poll, so the rule is read off its own method
/// declarations, like the watch stream's.
pub const TOKIO_STREAM_MAP_V0_1_14: LibraryConvention = LibraryConvention {
    package: "tokio-stream",
    family: "tokio-stream-map-0.1.14",
    floor: (0, 1, 14),
    ceiling: (0, 1, 19),
    checksums: &[
        // src/stream_map.rs, 0.1.14
        (
            "src/stream_map.rs",
            [
                0xb3, 0x78, 0x51, 0xf6, 0xd0, 0x31, 0xf1, 0x2d, 0x47, 0xd7, 0x32, 0x83, 0x08, 0x74,
                0x2b, 0xd9,
            ],
        ),
        // src/stream_map.rs, 0.1.15
        (
            "src/stream_map.rs",
            [
                0xb6, 0x8c, 0x3c, 0x31, 0x81, 0x2d, 0x8a, 0xc2, 0x71, 0x31, 0x56, 0xab, 0xbd, 0x86,
                0xa4, 0x1f,
            ],
        ),
        // src/stream_map.rs, 0.1.16 and 0.1.17
        (
            "src/stream_map.rs",
            [
                0xe9, 0xce, 0x97, 0x95, 0x32, 0x43, 0xbf, 0x95, 0x17, 0xb0, 0x74, 0x45, 0x5e, 0xf4,
                0x81, 0x81,
            ],
        ),
        // src/stream_map.rs, 0.1.18
        (
            "src/stream_map.rs",
            [
                0xb5, 0x1b, 0x28, 0x7a, 0x6d, 0x3c, 0x9c, 0x22, 0x07, 0x64, 0x99, 0xed, 0x8c, 0xb2,
                0xd4, 0xb7,
            ],
        ),
        // src/stream_map.rs, 0.1.19
        (
            "src/stream_map.rs",
            [
                0xc8, 0x04, 0x84, 0x60, 0xb5, 0x3e, 0x98, 0xa3, 0x14, 0x17, 0xef, 0xa9, 0x54, 0xec,
                0x6c, 0xa2,
            ],
        ),
    ],
};

/// The reviewed implementation a version selects, or which side of the
/// reviewed range it falls on. A version outside gets no rule, however
/// familiar the layout looks: a delegation authorizes following a poll,
/// and only the read decides that the poll goes where the rule says.
pub fn library_convention(
    convention: &'static LibraryConvention,
    version: &semver::Version,
) -> Result<&'static LibraryConvention, LayoutSelection> {
    match convention.select(version) {
        LayoutSelection::ReviewedRange => Ok(convention),
        outside => Err(outside),
    }
}

/// One reviewed tokio state protocol: how a bound resource's raw words
/// are to be read as readiness or a wait, reviewed against the tokio
/// sources for an inclusive `(major, minor)` range. A layout binding
/// says where the words are; only a protocol says what they mean, and
/// the read side's assessor refuses to call a resource ready or waited
/// on without one. Separate from the layout families on purpose: a
/// family is selected for every version, newest as a guess, while a
/// protocol binds inside its reviewed range and nowhere else.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct StateProtocol {
    pub kind: SemanticRuleKind,
    pub floor: (u64, u64),
    pub ceiling: (u64, u64),
}

impl StateProtocol {
    fn covers(&self, version: &semver::Version) -> bool {
        let version = (version.major, version.minor);
        version >= self.floor && version <= self.ceiling
    }
}

/// `batch_semaphore::Acquire`'s protocol, tokio 1.47 through 1.53
/// (`sync/batch_semaphore.rs`, unchanged across the range but for the
/// queue's type alias, the closed bit surviving `forget_permits`'
/// compare-exchange from 1.53, and the trace hook's signature):
/// `Acquire::poll` forwards to `poll_acquire` with the node embedded in
/// the future; a `Pending` sets `queued` and a `Ready(Ok)` clears it,
/// so `queued` records that a poll linked the node and outlives the
/// grant. `poll_acquire` returns the closed error on the permit word's
/// low bit or the wait list's own flag, takes what the permit word
/// holds, and — with permits still needed — stores the task's waker
/// in the node and pushes it at the list's front, under the list's
/// lock. `add_permits_locked` assigns released permits to the list's
/// back node, pops it and takes its waker once its counter reaches
/// zero, and hands leftovers back to the permit word only when the
/// list is empty; `close` sets both closed flags and pops every node.
/// Hence: a node whose counter is zero has been granted whole and
/// left the queue; a node still needing permits is queued exactly when
/// `queued` is set and the semaphore is open; and a nonzero permit
/// word beside a nonempty quiescent queue is a state the protocol
/// never produces.
pub const TOKIO_ACQUIRE_STATE_V1_47: StateProtocol = StateProtocol {
    kind: SemanticRuleKind::TokioAcquireState,
    floor: (1, 47),
    ceiling: (1, 53),
};

/// `JoinHandle<T>`'s protocol, tokio 1.47 through 1.53
/// (`runtime/task/join.rs` and `runtime/task/harness.rs`, the harness
/// byte-identical across the range): `poll` calls the raw task's
/// `try_read_output`, which reads the output only once the header's
/// `COMPLETE` bit is set, and otherwise stores the polling task's waker
/// in the trailer — setting `JOIN_WAKER` — and returns `Pending`. The
/// cooperative budget check precedes it, so a task can also park with
/// nothing stored and a deferred wake pending.
pub const TOKIO_JOIN_HANDLE_STATE_V1_47: StateProtocol = StateProtocol {
    kind: SemanticRuleKind::TokioJoinHandleState,
    floor: (1, 47),
    ceiling: (1, 53),
};

/// `time::Sleep`'s protocol, tokio 1.47 through 1.53 (`time/sleep.rs`
/// and `runtime/time/entry.rs`; 1.53 moved the entry's registration
/// into the state word's cache and the layout family follows it, but
/// `StateCell::poll`, `read_state`, `mark_pending` and `fire` are the
/// same across the range): `poll_elapsed` registers the entry on its
/// first poll, then registers the waker and reads the state word —
/// `Ready` exactly when the word is the deregistered sentinel, which
/// the driver's `fire` writes after `mark_pending` has moved it from
/// the deadline tick to the pending-fire sentinel. A word below the
/// sentinels is the tick the entry sits in the wheel for.
pub const TOKIO_SLEEP_STATE_V1_47: StateProtocol = StateProtocol {
    kind: SemanticRuleKind::TokioSleepState,
    floor: (1, 47),
    ceiling: (1, 53),
};

/// The io operations' protocol, tokio 1.47 through 1.53
/// (`runtime/io/scheduled_io.rs`, `runtime/io/registration.rs`,
/// `runtime/io/driver.rs`, `io/util/read.rs`, `io/util/write_all.rs`,
/// unchanged across the range but for a list type alias): the
/// registration's readiness word packs the delivered `Ready` bits in
/// its low sixteen, a tick above them and the shutdown flag at bit 31.
/// A reviewed stream's `poll_read`/`poll_write` goes through
/// `Registration::poll_io`, which polls readiness before touching the
/// buffer — so an empty read buffer parks like any other — and
/// `poll_readiness` returns `Pending` only when the direction's mask
/// (readable or read-closed; writable or write-closed) finds no
/// delivered bit and shutdown is clear, having stored the task's
/// waker in that direction's slot under the waiters lock. `WriteAll`
/// returns before polling when its buffer is exhausted. `Readiness`
/// moves from `Init` to `Done` when its interest is already delivered
/// or the resource is shut down, else pushes its own node at the
/// list's front and enters `Waiting`; in `Waiting` it returns `Ready`
/// once the node's `is_ready` flag is set, which the resource's wake
/// path sets under the lock while taking the waker of every node whose
/// interest the event satisfies. Shutdown wakes every node.
pub const TOKIO_IO_STATE_V1_47: StateProtocol = StateProtocol {
    kind: SemanticRuleKind::TokioIoState,
    floor: (1, 47),
    ceiling: (1, 53),
};

/// The bounded mpsc receiver's `recv` protocol, tokio 1.47 through 1.53
/// (`sync/mpsc/chan.rs`, `sync/mpsc/list.rs`, `sync/mpsc/block.rs` and
/// `sync/task/atomic_waker.rs`; across the range `chan.rs` differs only
/// in the trace hook's signature and a `take_waker` on the receiver's
/// drop, `list.rs` and `block.rs` only in `len`'s closed-marker
/// accounting and `unsafe` block reflows — `pop`, `try_advancing_head`
/// and `Block::read` are byte-identical — and `atomic_waker.rs` not at
/// all): `Receiver::recv` awaits `poll_fn(|cx| self.chan.recv(cx))`,
/// and `Rx::recv` checks the cooperative budget, then pops: the head
/// block is advanced to the one whose `start_index` is the read index's
/// block (a missing successor reads as nothing), and in that block the
/// slot's bit in `ready_slots` yields the value, the `TX_CLOSED` flag
/// yields `Closed`, and neither yields nothing. On nothing, the task's
/// waker is stored by reference in `rx_waker` — an `AtomicWaker`, whose
/// cell is written under its `REGISTERING` bit and taken under `WAKING`,
/// both clear at rest — the pop is retried, and the receiver parks
/// unless it closed itself (`rx_closed`) with the semaphore idle, every
/// permit back, in which case it returns `None`. The last `Sender` to
/// drop counts `tx_count` down to zero, claims one more slot with
/// `TX_CLOSED` set on its block, and wakes the receiver.
pub const TOKIO_MPSC_RECV_STATE_V1_47: StateProtocol = StateProtocol {
    kind: SemanticRuleKind::TokioMpscRecvState,
    floor: (1, 47),
    ceiling: (1, 53),
};

/// `Notified`'s protocol, tokio 1.47 through 1.53 (`sync/notify.rs`;
/// across the range the wait list's type alias changed, `notify_waiters`
/// gained a guard type, and 1.53 re-checks the `notify_waiters` count
/// under the lock in the `Waiting` arm): in `Init`, `poll_notified`
/// consumes a stored `notify_one` — the state word's `NOTIFIED` — or a
/// `notify_waiters` that ran since the future was created — the count
/// above the state bits differs from the future's copy — and is `Done`;
/// otherwise, under the waiters lock, it stores the task's waker in the
/// `Waiter` embedded in the future, pushes that node at the list's
/// front, moves the state word to `WAITING`, becomes `Waiting` and
/// returns `Pending`. In `Waiting` it is `Ready` once the node's
/// `notification` word is set, which `notify_one` (popping the back),
/// `notify_last` (the front) and `notify_waiters` (every node) do under
/// the lock after unlinking the node and taking its waker — the state
/// word returns to `EMPTY` with the last node — and otherwise replaces
/// a changed waker under the lock and stays `Pending`. `Done` is
/// `Ready`.
pub const TOKIO_NOTIFIED_STATE_V1_47: StateProtocol = StateProtocol {
    kind: SemanticRuleKind::TokioNotifiedState,
    floor: (1, 47),
    ceiling: (1, 53),
};

/// The oneshot receiver's protocol, tokio 1.47 through 1.53
/// (`sync/oneshot.rs`, unchanged across the range but for the trace
/// hook's signature and a `MaybeDangling` the standard library put
/// around the task slots): `Receiver::poll` forwards to
/// `Inner::poll_recv`, which checks the cooperative budget and loads
/// the shared state word. `VALUE_SENT` is `Ready` — the value if the
/// sender wrote one, the error if it dropped without — and so is
/// `CLOSED`, which only the receiver sets. Otherwise, with `RX_TASK_SET`
/// clear, or set but holding a waker that would not wake this task, it
/// stores the task's waker in `rx_task`, sets the bit, re-reads the
/// word for a completion that raced the store, and returns `Pending`.
/// `Sender::send` writes the value and `complete` sets `VALUE_SENT`,
/// waking `rx_task` when its bit is set; `Sender::drop` runs `complete`
/// with the value left `None`. So a parked receiver reads `RX_TASK_SET`
/// with neither completion bit, and the task bit set beside `VALUE_SENT`
/// is a wakeup owed and not yet polled.
pub const TOKIO_ONESHOT_RECV_STATE_V1_47: StateProtocol = StateProtocol {
    kind: SemanticRuleKind::TokioOneshotRecvState,
    floor: (1, 47),
    ceiling: (1, 53),
};

/// The reviewed state protocol for a resource kind at a recovered tokio
/// version: `None` when no version was recovered or it falls outside
/// the protocol's range. A layout family is selected regardless; a
/// protocol is not.
pub fn tokio_state_protocol(
    kind: ResourceKind,
    version: Option<&semver::Version>,
) -> Option<&'static StateProtocol> {
    let protocol = match kind {
        ResourceKind::Sleep => &TOKIO_SLEEP_STATE_V1_47,
        ResourceKind::JoinHandle => &TOKIO_JOIN_HANDLE_STATE_V1_47,
        ResourceKind::SemaphoreAcquire => &TOKIO_ACQUIRE_STATE_V1_47,
        ResourceKind::IoOperation(_) => &TOKIO_IO_STATE_V1_47,
        ResourceKind::MpscRecv => &TOKIO_MPSC_RECV_STATE_V1_47,
        ResourceKind::Notified => &TOKIO_NOTIFIED_STATE_V1_47,
        ResourceKind::OneshotRecv => &TOKIO_ONESHOT_RECV_STATE_V1_47,
    };
    protocol.covers(version?).then_some(protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coroutine_convention_covers_exactly_the_reviewed_range() {
        for producer in [
            "clang LLVM (rustc version 1.97.0 (2d8144b78 2026-07-07))",
            "rustc version 1.97.1 (ccdd 2026-07-08)",
            "rustc version 1.98.0 (88d9e12ae 2026-08-18)",
            "rustc version 1.98.3-nightly (eeff 2026-09-01)",
        ] {
            assert_eq!(
                rustc_coroutine_convention(producer).map(|c| c.family),
                Some("rustc-coroutine-1.97"),
                "{producer}"
            );
        }
        for producer in [
            "rustc version 1.96.0 (aabb 2026-05-01)",
            "rustc version 1.99.0 (aabb 2026-10-01)",
            "rustc version 2.0.0 (aabb 2027-01-01)",
            "GNU C17 14.2.0 -mtune=generic -g",
            "clang version 19.1.0",
            "rustc version 1.98",
        ] {
            assert!(rustc_coroutine_convention(producer).is_none(), "{producer}");
            assert!(
                rustc_std_adapter_convention(producer).is_none(),
                "{producer}"
            );
            assert!(
                rustc_dyn_future_abi_convention(producer).is_none(),
                "{producer}"
            );
        }
    }

    /// The adapter and ABI conventions are separate reviews with their
    /// own names, covering the same toolchains as the coroutine one.
    #[test]
    fn test_std_adapter_and_dyn_abi_conventions_cover_the_reviewed_toolchains() {
        let producer = "clang LLVM (rustc version 1.98.0 (88d9e12ae 2026-08-18))";
        assert_eq!(
            rustc_std_adapter_convention(producer).map(|c| c.family),
            Some("rustc-std-adapters-1.97")
        );
        assert_eq!(
            rustc_dyn_future_abi_convention(producer).map(|c| c.family),
            Some("rustc-dyn-future-abi-1.97")
        );
        let producer = "clang LLVM (rustc version 1.97.0 (2d8144b78 2026-07-07))";
        assert!(rustc_std_adapter_convention(producer).is_some());
        assert!(rustc_dyn_future_abi_convention(producer).is_some());
    }

    /// Every delegation family binds at both edges of its range
    /// inclusive and names the side a version outside falls on; a
    /// checksum is reviewed only if it is one of the listed revisions.
    #[test]
    fn test_delegation_families_select_by_exact_version_and_checksum() {
        let v = |s: &str| semver::Version::parse(s).unwrap();
        for (family, inside, below, above) in [
            (
                &TRACING_INSTRUMENTED_V0_1_40,
                ["0.1.40", "0.1.41", "0.1.42", "0.1.43", "0.1.44"].as_slice(),
                "0.1.39",
                "0.1.45",
            ),
            (
                &FUTURES_UTIL_ADAPTERS_V0_3_30,
                ["0.3.30", "0.3.31", "0.3.32", "0.3.33", "0.3.34"].as_slice(),
                "0.3.29",
                "0.3.35",
            ),
            (
                &HYPER_UTIL_TOKIO_SLEEP_V0_1_10,
                ["0.1.10", "0.1.15", "0.1.20"].as_slice(),
                "0.1.9",
                "0.1.21",
            ),
            (
                &TOKIO_COOP_V1_47,
                ["1.47.0", "1.47.5", "1.48.0", "1.52.4", "1.53.1"].as_slice(),
                "1.46.1",
                "1.53.2",
            ),
            (
                &TOKIO_STREAM_WATCH_V0_1_14,
                ["0.1.14", "0.1.15", "0.1.16", "0.1.17", "0.1.18", "0.1.19"].as_slice(),
                "0.1.13",
                "0.1.20",
            ),
            (
                &TOKIO_UTIL_REUSABLE_BOX_V0_7_11,
                ["0.7.11", "0.7.12", "0.7.15", "0.7.19"].as_slice(),
                "0.7.10",
                "0.7.20",
            ),
            (
                &TOKIO_STREAM_MAP_V0_1_14,
                ["0.1.14", "0.1.15", "0.1.16", "0.1.17", "0.1.18", "0.1.19"].as_slice(),
                "0.1.13",
                "0.1.20",
            ),
        ] {
            for version in inside {
                assert_eq!(
                    library_convention(family, &v(version)).map(|c| c.family),
                    Ok(family.family),
                    "{version}"
                );
            }
            assert_eq!(
                library_convention(family, &v(below)),
                Err(LayoutSelection::BelowFloor),
                "{below}"
            );
            // A pre-release past the ceiling sorts below that release
            // and is still above the range.
            let prerelease = format!("{above}-alpha");
            for version in [above, prerelease.as_str()] {
                assert_eq!(
                    library_convention(family, &v(version)),
                    Err(LayoutSelection::AboveReviewedRange),
                    "{version}"
                );
            }
            for (_, checksum) in family.checksums {
                assert!(family.reviewed_checksum(checksum));
            }
            assert!(!family.reviewed_checksum(&[0; 16]));
        }
        assert_eq!(TRACING_INSTRUMENTED_V0_1_40.range(), "0.1.40–0.1.44");
        assert_eq!(FUTURES_UTIL_ADAPTERS_V0_3_30.range(), "0.3.30–0.3.34");
        assert_eq!(HYPER_UTIL_TOKIO_SLEEP_V0_1_10.range(), "0.1.10–0.1.20");
        assert_eq!(TOKIO_COOP_V1_47.range(), "1.47.0–1.53.1");
        assert_eq!(TOKIO_STREAM_WATCH_V0_1_14.range(), "0.1.14–0.1.19");
        assert_eq!(TOKIO_UTIL_REUSABLE_BOX_V0_7_11.range(), "0.7.11–0.7.19");
    }

    /// A state protocol binds inside its reviewed tokio range and for
    /// no other version — not below the floor, not above the ceiling,
    /// and never for a target whose version was not recovered, however
    /// its layouts bound.
    #[test]
    fn test_state_protocols_bind_only_inside_the_reviewed_tokio_range() {
        use crate::bundle::IoOperationKind;
        let v = |s: &str| semver::Version::parse(s).unwrap();
        let kinds = [
            (ResourceKind::Sleep, SemanticRuleKind::TokioSleepState),
            (
                ResourceKind::JoinHandle,
                SemanticRuleKind::TokioJoinHandleState,
            ),
            (
                ResourceKind::SemaphoreAcquire,
                SemanticRuleKind::TokioAcquireState,
            ),
            (
                ResourceKind::IoOperation(IoOperationKind::Read),
                SemanticRuleKind::TokioIoState,
            ),
            (
                ResourceKind::IoOperation(IoOperationKind::WriteAll),
                SemanticRuleKind::TokioIoState,
            ),
            (
                ResourceKind::IoOperation(IoOperationKind::Readiness),
                SemanticRuleKind::TokioIoState,
            ),
            (ResourceKind::MpscRecv, SemanticRuleKind::TokioMpscRecvState),
            (ResourceKind::Notified, SemanticRuleKind::TokioNotifiedState),
            (
                ResourceKind::OneshotRecv,
                SemanticRuleKind::TokioOneshotRecvState,
            ),
        ];
        for (kind, rule) in kinds {
            for version in ["1.47.0", "1.47.5", "1.49.0", "1.52.4", "1.53.1", "1.53.9"] {
                assert_eq!(
                    tokio_state_protocol(kind, Some(&v(version))).map(|p| p.kind),
                    Some(rule),
                    "{kind:?} at {version}"
                );
            }
            for version in ["1.46.9", "1.54.0", "2.0.0"] {
                assert_eq!(
                    tokio_state_protocol(kind, Some(&v(version))),
                    None,
                    "{kind:?} at {version}"
                );
            }
            assert_eq!(tokio_state_protocol(kind, None), None, "{kind:?}");
        }
    }
}

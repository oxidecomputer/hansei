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

use crate::bundle::{IoOperationKind, LayoutSelection, ResourceKind, SemanticRuleKind};
use crate::provenance::rustc_version;

/// One release: `(major, minor, patch)`.
pub type Release = (u64, u64, u64);

/// The releases a review read, as inclusive spans in ascending order.
/// A crate that only ever releases forward needs one span. One that
/// ships patches into older minors — tokio's LTS lines, rustc's point
/// releases — gets a span per minor, ending at the newest patch read:
/// a patch released into that minor afterwards falls between two
/// spans, outside the review, instead of inside one long range that
/// would vouch for it unread.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Releases(pub &'static [(Release, Release)]);

impl Releases {
    pub fn floor(&self) -> Release {
        self.0
            .first()
            .expect("a review reads at least one release")
            .0
    }

    pub fn ceiling(&self) -> Release {
        self.0
            .last()
            .expect("a review reads at least one release")
            .1
    }

    /// Whether a span holds the version. A pre-release — a nightly or
    /// beta rustc, a crate's release candidate — is none of the
    /// releases a review read, however close its number.
    pub fn covers(&self, version: &semver::Version) -> bool {
        let release = release(version);
        version.pre.is_empty()
            && self
                .0
                .iter()
                .any(|&(floor, ceiling)| release >= floor && release <= ceiling)
    }

    /// The span the review read of the version's own minor, if any: of
    /// a minor split in two — tokio 1.52, whose 1.52.0 is a layout
    /// family of its own — the last that starts at or before it, else
    /// the minor's first.
    fn span_of(&self, version: &semver::Version) -> Option<(Release, Release)> {
        let minor: Vec<(Release, Release)> = self
            .0
            .iter()
            .copied()
            .filter(|&((major, minor, _), _)| (major, minor) == (version.major, version.minor))
            .collect();
        minor
            .iter()
            .rev()
            .find(|&&(floor, _)| at(floor) <= *version)
            .or(minor.first())
            .copied()
    }

    /// The version's place against the spans, in semver order, so a
    /// pre-release sorts before its release: reviewed inside one; else
    /// placed against what was read of its own minor — below that span
    /// for a patch older than its first release, above it for one newer
    /// than its last — or, for a minor no span reads, against the whole
    /// range.
    pub fn select(&self, version: &semver::Version) -> LayoutSelection {
        if self.covers(version) {
            return LayoutSelection::ReviewedRange;
        }
        let floor = match self.span_of(version) {
            Some((floor, _)) => floor,
            None => self.floor(),
        };
        if *version < at(floor) {
            LayoutSelection::BelowFloor
        } else {
            LayoutSelection::AboveReviewedRange
        }
    }

    /// The whole range as a warning names it: `1.47.0-1.53.1`.
    pub fn range(&self) -> String {
        release_range(self.floor(), self.ceiling())
    }

    /// The range a version outside the review is told it misses: what
    /// was read of its own minor — `1.51.0-1.51.5` for an unread 1.51.6,
    /// `1.52.1-1.52.4` for a 1.52.0 left out — else, past every span,
    /// the whole range, and between two spans of other minors the one
    /// below it.
    pub fn range_for(&self, version: &semver::Version) -> String {
        if let Some((floor, ceiling)) = self.span_of(version) {
            return release_range(floor, ceiling);
        }
        if *version < at(self.floor()) || *version > at(self.ceiling()) {
            return self.range();
        }
        let &(floor, ceiling) = self
            .0
            .iter()
            .rev()
            .find(|&&(floor, _)| at(floor) <= *version)
            .expect("a version at or above the floor has a span below it");
        release_range(floor, ceiling)
    }
}

/// A release as a semver version, to compare with one in semver order.
fn at((major, minor, patch): Release) -> semver::Version {
    semver::Version::new(major, minor, patch)
}

impl std::fmt::Display for Releases {
    /// Every span, a one-release span as that release:
    /// `1.47.0-1.47.5,1.48.0,1.49.0`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let spans: Vec<String> = self
            .0
            .iter()
            .map(|&(floor, ceiling)| match floor == ceiling {
                true => dotted(floor),
                false => release_range(floor, ceiling),
            })
            .collect();
        f.write_str(&spans.join(","))
    }
}

fn release(version: &semver::Version) -> Release {
    (version.major, version.minor, version.patch)
}

fn dotted((major, minor, patch): Release) -> String {
    format!("{major}.{minor}.{patch}")
}

fn release_range(floor: Release, ceiling: Release) -> String {
    format!("{}-{}", dotted(floor), dotted(ceiling))
}

/// The rustc releases every rustc convention was reviewed at: each
/// minor from `.0` through the newest patch the version matrix
/// (`test-programs/matrix.toml`) builds. A span advances by hand when a
/// toolchain is onboarded, after its cells' goldens and the files each
/// convention names have been read; the matrix suite holds each span's
/// newest patch to the matrix's.
pub const RUSTC_RELEASES: Releases =
    Releases(&[((1, 97, 0), (1, 97, 1)), ((1, 98, 0), (1, 98, 1))]);

/// One reviewed rustc convention: its name, as the bundle's `Rustc`
/// origin records it, the compiler releases it was reviewed at, and
/// the checksums of the standard library files it read, as `rust-src`
/// ships them (`library/…`). A convention about what the compiler
/// itself emits reads compiler sources, which no toolchain ships, and
/// lists none: its releases alone gate it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RustcConvention {
    pub family: &'static str,
    pub releases: Releases,
    /// `(file, md5)` for every reviewed revision of each library file.
    pub checksums: &'static [(&'static str, [u8; 16])],
}

impl RustcConvention {
    fn subject(&self) -> &'static str {
        subject(self.family)
    }

    /// The range as a warning names it: `1.97.0-1.98.0`.
    pub fn range(&self) -> String {
        self.releases.range()
    }
}

/// What a review is about, its family name without the version the
/// review starts at: `rustc-coroutine` for `rustc-coroutine-1.97`.
/// Two reviews of one subject share it, and a git review's subject is
/// its family without the revision it was named for:
/// `sprockets-tls-stream` for `sprockets-tls-stream-d2b68e4`.
pub(crate) fn subject(family: &'static str) -> &'static str {
    family
        .rsplit_once('-')
        .map_or(family, |(subject, _)| subject)
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
/// Its releases are [`RUSTC_RELEASES`]. A newer compiler emitting the
/// same shape stays unbound: identical fields do not prove identical
/// meaning.
pub const RUSTC_COROUTINE_V1_97: RustcConvention = RustcConvention {
    family: "rustc-coroutine-1.97",
    releases: RUSTC_RELEASES,
    checksums: &[],
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
    releases: RUSTC_RELEASES,
    checksums: &[
        // library/core/src/future/future.rs, 1.97.0 through 1.98.1
        (
            "library/core/src/future/future.rs",
            [
                0x51, 0xc8, 0x9e, 0xd2, 0x1e, 0x52, 0xa7, 0x8e, 0x60, 0x5a, 0xd8, 0x46, 0xee, 0x1a,
                0x13, 0xf2,
            ],
        ),
        // library/alloc/src/boxed.rs, 1.97.0 and 1.97.1
        (
            "library/alloc/src/boxed.rs",
            [
                0xab, 0x31, 0x10, 0xed, 0xd6, 0xf8, 0xce, 0x3c, 0xea, 0x85, 0x72, 0xce, 0x2a, 0x68,
                0x72, 0xf1,
            ],
        ),
        // library/alloc/src/boxed.rs, 1.98.0 and 1.98.1
        (
            "library/alloc/src/boxed.rs",
            [
                0x5d, 0x44, 0x4a, 0xcb, 0x5e, 0xae, 0x77, 0xea, 0xc4, 0x89, 0xba, 0x4a, 0xd0, 0x24,
                0xdb, 0x1b,
            ],
        ),
    ],
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
    releases: RUSTC_RELEASES,
    checksums: &[],
};

fn rustc_convention(
    producer: &str,
    reviewed: &[&'static RustcConvention],
) -> Option<&'static RustcConvention> {
    let version = rustc_version(producer)?;
    reviewed
        .iter()
        .copied()
        .find(|c| c.releases.covers(&version))
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

/// core's `future::pending::Pending<T>` as rustc 1.97 and 1.98 ship it,
/// reviewed against `library/core/src/future/pending.rs` (identical
/// across the three matrix toolchains): a zero-sized struct whose one
/// member is a `PhantomData`, and a `Future::poll` that returns
/// `Poll::Pending` without touching its `Context` — no waker
/// registered, nothing polled, never `Ready`. The source ships with
/// the toolchain, so the producer version says which source was read,
/// and the releases advance by hand with the others.
pub const RUSTC_CORE_PENDING_V1_97: RustcConvention = RustcConvention {
    family: "rustc-core-pending-1.97",
    releases: RUSTC_RELEASES,
    checksums: &[
        // library/core/src/future/pending.rs, 1.97.0 through 1.98.1
        (
            "library/core/src/future/pending.rs",
            [
                0x62, 0xc4, 0xbb, 0xc3, 0xc5, 0x71, 0x3e, 0x4e, 0x87, 0x26, 0xa2, 0x19, 0x35, 0x73,
                0x65, 0xc3,
            ],
        ),
    ],
};

/// The `Pending` convention covering a producer, selected like
/// [`rustc_coroutine_convention`].
pub fn rustc_core_pending_convention(producer: &str) -> Option<&'static RustcConvention> {
    rustc_convention(producer, &[&RUSTC_CORE_PENDING_V1_97])
}

/// The `dyn Future` ABI convention covering a producer, selected like
/// [`rustc_coroutine_convention`].
pub fn rustc_dyn_future_abi_convention(producer: &str) -> Option<&'static RustcConvention> {
    rustc_convention(producer, &[&RUSTC_DYN_FUTURE_ABI_V1_97])
}

/// std's refcounted allocation headers as rustc 1.97 and 1.98 ship
/// them, reviewed against `library/alloc/src/sync.rs` and `rc.rs` (the
/// two headers identical across the range but for comments):
/// `ArcInner<T> { strong, weak, data: T }` and `RcInner<T> { strong,
/// weak, value: T }`, the counts first and the value after them — what
/// an `Arc<T>` or `Rc<T>` points at, and what a path through one names
/// a member of.
pub const RUSTC_STD_REFCOUNT_V1_97: RustcConvention = RustcConvention {
    family: "rustc-std-refcount-1.97",
    releases: RUSTC_RELEASES,
    checksums: &[
        // library/alloc/src/sync.rs, 1.97.0 and 1.97.1
        (
            "library/alloc/src/sync.rs",
            [
                0x20, 0x55, 0x38, 0xb2, 0x45, 0x18, 0x49, 0xa3, 0xc6, 0x90, 0xf0, 0x1d, 0x0b, 0xb8,
                0x25, 0xf1,
            ],
        ),
        // library/alloc/src/sync.rs, 1.98.0 and 1.98.1
        (
            "library/alloc/src/sync.rs",
            [
                0x09, 0x22, 0x59, 0x34, 0x38, 0x84, 0x84, 0xc2, 0x24, 0xb4, 0x57, 0x12, 0xd0, 0xc1,
                0x5c, 0xde,
            ],
        ),
        // library/alloc/src/rc.rs, 1.97.0 and 1.97.1
        (
            "library/alloc/src/rc.rs",
            [
                0x9a, 0xcd, 0x46, 0xdc, 0x14, 0xa1, 0xa2, 0x96, 0x43, 0x5f, 0x86, 0x28, 0x8b, 0x48,
                0xc3, 0x4e,
            ],
        ),
        // library/alloc/src/rc.rs, 1.98.0 and 1.98.1
        (
            "library/alloc/src/rc.rs",
            [
                0x03, 0x37, 0x2b, 0xd0, 0x88, 0xf2, 0x40, 0x72, 0x1d, 0x43, 0x80, 0x34, 0xad, 0x17,
                0x9c, 0x4b,
            ],
        ),
    ],
};

/// The refcount header convention covering a producer, selected like
/// [`rustc_coroutine_convention`].
pub fn rustc_std_refcount_convention(producer: &str) -> Option<&'static RustcConvention> {
    rustc_convention(producer, &[&RUSTC_STD_REFCOUNT_V1_97])
}

/// std's futex mutex as rustc 1.97 and 1.98 ship it, reviewed against
/// `library/std/src/sys/sync/mutex/futex.rs` (identical across the
/// range): `Mutex { futex }`, one futex word that reads `UNLOCKED` (0)
/// while no thread holds the lock, `LOCKED` (1) or `CONTENDED` (2)
/// while one does — held whenever the word is nonzero, whatever width
/// the platform's futex word is.
pub const RUSTC_STD_FUTEX_MUTEX_V1_97: RustcConvention = RustcConvention {
    family: "rustc-std-futex-mutex-1.97",
    releases: RUSTC_RELEASES,
    checksums: &[
        // library/std/src/sys/sync/mutex/futex.rs, 1.97.0 through 1.98.1
        (
            "library/std/src/sys/sync/mutex/futex.rs",
            [
                0x28, 0xfe, 0x35, 0xba, 0xd6, 0xff, 0x34, 0x0a, 0xf7, 0x07, 0xb9, 0x97, 0xfc, 0xc6,
                0xda, 0x8c,
            ],
        ),
    ],
};

/// The futex mutex convention covering a producer, selected like
/// [`rustc_coroutine_convention`].
pub fn rustc_std_futex_mutex_convention(producer: &str) -> Option<&'static RustcConvention> {
    rustc_convention(producer, &[&RUSTC_STD_FUTEX_MUTEX_V1_97])
}

/// Every reviewed rustc convention.
pub const RUSTC_CONVENTIONS: [&RustcConvention; 6] = [
    &RUSTC_COROUTINE_V1_97,
    &RUSTC_STD_ADAPTERS_V1_97,
    &RUSTC_DYN_FUTURE_ABI_V1_97,
    &RUSTC_CORE_PENDING_V1_97,
    &RUSTC_STD_REFCOUNT_V1_97,
    &RUSTC_STD_FUTEX_MUTEX_V1_97,
];

/// The producer's rustc version and the conventions it is newer than
/// every review of: each binds nothing the compiler emitted, however
/// familiar its output looks, and an extraction says so. `None` where
/// it outgrows none, including a producer with no parseable rustc
/// version.
pub fn rustc_conventions_outgrown(
    producer: &str,
) -> Option<(semver::Version, Vec<&'static RustcConvention>)> {
    outgrown(producer, &RUSTC_CONVENTIONS)
}

/// The rustc versions the compiler convention reviews span between
/// them, as a warning names it: `1.97.0-1.98.0`.
pub fn rustc_reviewed_range() -> String {
    let floor = RUSTC_CONVENTIONS.iter().map(|c| c.releases.floor()).min();
    let ceiling = RUSTC_CONVENTIONS.iter().map(|c| c.releases.ceiling()).max();
    release_range(
        floor.expect("at least one convention"),
        ceiling.expect("at least one convention"),
    )
}

/// The reviews in `reviewed` of every subject whose releases the
/// producer's rustc is not one of, though at or past the review's
/// first: newer than its ceiling, a patch its minor's span did not
/// read, or a nightly or beta. A subject a later review covers the
/// version of is not outgrown, and one the version predates is left to
/// the floor's own warning.
fn outgrown(
    producer: &str,
    reviewed: &[&'static RustcConvention],
) -> Option<(semver::Version, Vec<&'static RustcConvention>)> {
    let version = rustc_version(producer)?;
    let outgrown: Vec<&'static RustcConvention> = reviewed
        .iter()
        .copied()
        .filter(|c| {
            reviewed
                .iter()
                .filter(|other| other.subject() == c.subject())
                .all(|other| !other.releases.covers(&version))
                && version >= at(c.releases.floor())
        })
        .collect();
    (!outgrown.is_empty()).then_some((version, outgrown))
}

/// One reviewed third-party implementation: the crate, the family name
/// the bundle's delegation origin records, the releases the
/// implementation was read at, and the checksums of its reviewed
/// source file — a corroborating check when a line table carries one,
/// which rustc's DWARF 4 output never does, and the matrix suite's
/// check of every release it builds.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct LibraryConvention {
    pub package: &'static str,
    pub family: &'static str,
    pub releases: Releases,
    /// `(file, md5)` for every reviewed revision of the implementing file.
    pub checksums: &'static [(&'static str, [u8; 16])],
}

impl LibraryConvention {
    /// The version's place against the reviewed releases: reviewed
    /// inside them, or which side it falls on. A delegation rule binds
    /// only inside; the other two are the decline's reason.
    pub fn select(&self, version: &semver::Version) -> LayoutSelection {
        self.releases.select(version)
    }

    /// Whether a checksum the line table carried is one of the reviewed
    /// revisions of the implementing file.
    pub fn reviewed_checksum(&self, md5: &[u8; 16]) -> bool {
        self.checksums.iter().any(|(_, reviewed)| reviewed == md5)
    }

    /// The range as a decline reason writes it: `0.1.40-0.1.44`.
    pub fn range(&self) -> String {
        self.releases.range()
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
    releases: Releases(&[((0, 1, 40), (0, 1, 44))]),
    checksums: &[
        // 0.1.40 and 0.1.41.
        (
            "src/instrument.rs",
            [
                0xd3, 0xe1, 0xa1, 0x87, 0xc6, 0x25, 0x37, 0xd0, 0xdb, 0xc2, 0x63, 0xd9, 0x72, 0xf8,
                0xea, 0xfe,
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

/// parking_lot's `raw_mutex::RawMutex` as 0.11.0 through 0.12.5 — the
/// newest release at the review — implement it: `RawMutex { state:
/// AtomicU8 }`, whose `LOCKED_BIT` (`0b01`) is set exactly while a
/// thread holds the lock — `is_locked` reads it alone — and whose
/// `PARKED_BIT` (`0b10`) says only that a thread waits for it. The
/// origin is the type's own method declarations, which name
/// `src/raw_mutex.rs`, byte-identical within each minor; 0.11's differs
/// from 0.12's only in taking `Instant` (used for timed locks alone)
/// from the `instant` crate rather than `std::time`.
pub const PARKING_LOT_RAW_MUTEX_V0_11_0: LibraryConvention = LibraryConvention {
    package: "parking_lot",
    family: "parking_lot-raw-mutex-0.11.0",
    releases: Releases(&[((0, 11, 0), (0, 11, 2)), ((0, 12, 0), (0, 12, 5))]),
    checksums: &[
        // 0.11.0 through 0.11.2.
        (
            "src/raw_mutex.rs",
            [
                0x59, 0x48, 0xba, 0x45, 0x74, 0xa0, 0x23, 0xc1, 0xf3, 0xb2, 0x9c, 0x4c, 0x16, 0x10,
                0xd5, 0xbf,
            ],
        ),
        // 0.12.0 through 0.12.5.
        (
            "src/raw_mutex.rs",
            [
                0xc6, 0x3f, 0xda, 0xbc, 0x3c, 0x51, 0xef, 0x4b, 0x58, 0x5a, 0x91, 0xdb, 0xef, 0xbe,
                0x8c, 0x52,
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
/// `future::Either<A, B>` (`src/future/either.rs`; 0.3.31 rewrote the
/// projections' matches in `Self::` form, projecting the same way) is
/// the enum `Left(A) | Right(B)`, and its `poll` is `as_pin_mut()`
/// matched to the active variant's poll and nothing else: it forwards
/// exclusively to whichever side it holds.
///
/// The checksums are the reviewed revisions of every file a `poll`
/// declaration in this set can name — the five implementations, the
/// two `delegate_all!` invocation sites and the macro's own file — so
/// a build whose line table carries one is checked against the
/// revision that was read.
pub const FUTURES_UTIL_ADAPTERS_V0_3_30: LibraryConvention = LibraryConvention {
    package: "futures-util",
    family: "futures-util-adapters-0.3.30",
    releases: Releases(&[((0, 3, 30), (0, 3, 34))]),
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
        // src/future/either.rs, 0.3.30
        (
            "src/future/either.rs",
            [
                0x9a, 0x47, 0xed, 0xe8, 0x20, 0x89, 0x4a, 0x11, 0x37, 0x6d, 0xf3, 0xd7, 0xb0, 0xa8,
                0x61, 0xd8,
            ],
        ),
        // src/future/either.rs, 0.3.31 through 0.3.34
        (
            "src/future/either.rs",
            [
                0xe4, 0xde, 0x5f, 0xe8, 0x82, 0x0b, 0xfc, 0x44, 0x8e, 0x48, 0x7f, 0x0d, 0x52, 0xf6,
                0x5e, 0x4a,
            ],
        ),
    ],
};

/// hyper-util's version-choosing server connection as 0.1.10 through
/// 0.1.20 implement it, reviewed in `src/server/conn/auto/mod.rs` and
/// `src/common/rewind.rs` of every release in the range. The
/// declarations the rule addresses are the same text in all of them:
/// `UpgradeableConnection { state: UpgradeableConnState }` with
/// `UpgradeableConnState { ReadVersion { read_version, builder,
/// service }, H1 { conn: hyper::server::conn::http1::
/// UpgradeableConnection<Rewind<I>, S> }, H2 { conn } }`, and `Rewind
/// { inner, pre }`, the io the chosen connection is handed. The
/// releases differ in builder methods, docs, a `Default` impl and
/// where `ready!` is imported from (the auto module), and in two
/// local buffer helpers the rewind gave up for the cursor's own
/// (0.1.12) — none of which changes what a state means.
///
/// What the states mean, from the wrapper's `poll`: `ReadVersion`
/// polls the `read_version` future, which reads the connection's first
/// bytes off the socket to tell an HTTP/2 preface from an HTTP/1
/// request line and registers the task's waker on that read alone;
/// once it is ready the wrapper builds the connection for the version
/// it saw — the HTTP/1 one with upgrades, over the bytes rewound — and
/// sets `H1` or `H2`. In `H1` the poll is `conn.poll(cx)` on the
/// HTTP/1 connection and nothing else, acting only on its output; `H2`
/// polls the HTTP/2 connection the same way.
///
/// The ceiling is the newest release the cores on hand build; it
/// advances by hand when a newer one is read.
pub const HYPER_UTIL_AUTO_CONN_V0_1_10: LibraryConvention = LibraryConvention {
    package: "hyper-util",
    family: "hyper-util-auto-conn-0.1.10",
    releases: Releases(&[((0, 1, 10), (0, 1, 20))]),
    checksums: &[
        // src/server/conn/auto/mod.rs, 0.1.10
        (
            "src/server/conn/auto/mod.rs",
            [
                0xef, 0xca, 0x84, 0x6d, 0x33, 0x62, 0xa0, 0xa3, 0x70, 0xae, 0x7d, 0x8d, 0x0f, 0x8b,
                0x01, 0xff,
            ],
        ),
        // src/server/conn/auto/mod.rs, 0.1.11
        (
            "src/server/conn/auto/mod.rs",
            [
                0x69, 0xbb, 0xea, 0x69, 0x79, 0x3b, 0x7e, 0x4f, 0x23, 0x36, 0x17, 0x5d, 0xaf, 0x7a,
                0x7f, 0x2c,
            ],
        ),
        // src/server/conn/auto/mod.rs, 0.1.12
        (
            "src/server/conn/auto/mod.rs",
            [
                0x9d, 0x75, 0x53, 0xed, 0x68, 0xc6, 0x9b, 0x74, 0x1f, 0x86, 0x53, 0x4f, 0x0f, 0x7e,
                0x04, 0x6c,
            ],
        ),
        // src/server/conn/auto/mod.rs, 0.1.13 through 0.1.14
        (
            "src/server/conn/auto/mod.rs",
            [
                0x2d, 0x8e, 0xd7, 0xa8, 0x5f, 0x7a, 0xb8, 0x49, 0xca, 0xe8, 0x01, 0x9c, 0x11, 0xee,
                0xad, 0xe2,
            ],
        ),
        // src/server/conn/auto/mod.rs, 0.1.15 through 0.1.19
        (
            "src/server/conn/auto/mod.rs",
            [
                0x3b, 0xf1, 0x0e, 0x4e, 0x85, 0xea, 0xc1, 0x97, 0xe9, 0x23, 0x56, 0xbb, 0x85, 0x73,
                0x09, 0xf3,
            ],
        ),
        // src/server/conn/auto/mod.rs, 0.1.20
        (
            "src/server/conn/auto/mod.rs",
            [
                0x8b, 0x3e, 0xaa, 0xe6, 0x5e, 0xfd, 0xef, 0xe3, 0x78, 0xdd, 0x91, 0x0b, 0x8a, 0x14,
                0xbf, 0xf9,
            ],
        ),
        // src/common/rewind.rs, 0.1.10 through 0.1.11
        (
            "src/common/rewind.rs",
            [
                0xc1, 0x58, 0xd7, 0xa8, 0x08, 0xbe, 0xf8, 0xa3, 0x75, 0x4f, 0x05, 0xb8, 0xa0, 0xff,
                0xb5, 0x12,
            ],
        ),
        // src/common/rewind.rs, 0.1.12 through 0.1.20
        (
            "src/common/rewind.rs",
            [
                0xac, 0x4f, 0xcb, 0x08, 0x93, 0xaa, 0x98, 0xbc, 0x0e, 0xe9, 0x38, 0x0f, 0x6e, 0x07,
                0x1c, 0x2d,
            ],
        ),
    ],
};

/// hyper-util's io adapters as 0.1.10 through 0.1.20 implement them.
/// `TokioIo<T>` (`src/rt/tokio.rs`, the struct and both directions'
/// impls identical across the range) is `{ inner: T }`, and every
/// `hyper::rt::Read`/`Write` method — and every tokio `AsyncRead`/
/// `AsyncWrite` one, the impls for the other direction — calls the same
/// method on `inner` and nothing else. `Rewind<T>` (`src/common/
/// rewind.rs`) is `{ pre: Option<Bytes>, inner: T }`: a read is served
/// from `pre` while it holds bytes, returning ready, and is `inner`'s
/// otherwise; every write is `inner`'s. So a pending read or write
/// through either is its `inner`'s, which is what a route needs. The
/// releases differ in the rewind's own buffer helpers (0.1.12), and in
/// `src/rt/tokio.rs` in its timer and executor, none of it in the
/// adapters. `src/client/legacy/connect/http.rs` holds `TokioIo`'s
/// `Connection` impl, which asks `inner` for its connection info and
/// moves nothing; it is read so a declaration there is the reviewed
/// crate's rather than a stranger's.
pub const HYPER_UTIL_IO_V0_1_10: LibraryConvention = LibraryConvention {
    package: "hyper-util",
    family: "hyper-util-io-0.1.10",
    releases: Releases(&[((0, 1, 10), (0, 1, 20))]),
    checksums: &[
        // src/common/rewind.rs, 0.1.10 and 0.1.11
        (
            "src/common/rewind.rs",
            [
                0xc1, 0x58, 0xd7, 0xa8, 0x08, 0xbe, 0xf8, 0xa3, 0x75, 0x4f, 0x05, 0xb8, 0xa0, 0xff,
                0xb5, 0x12,
            ],
        ),
        // src/common/rewind.rs, 0.1.12 through 0.1.20
        (
            "src/common/rewind.rs",
            [
                0xac, 0x4f, 0xcb, 0x08, 0x93, 0xaa, 0x98, 0xbc, 0x0e, 0xe9, 0x38, 0x0f, 0x6e, 0x07,
                0x1c, 0x2d,
            ],
        ),
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
        // src/client/legacy/connect/http.rs, 0.1.10
        (
            "src/client/legacy/connect/http.rs",
            [
                0x3b, 0x8b, 0x7c, 0xab, 0x16, 0x1f, 0xbd, 0x82, 0x78, 0xca, 0x21, 0x2a, 0xcc, 0x35,
                0xc9, 0xcb,
            ],
        ),
        // src/client/legacy/connect/http.rs, 0.1.11 and 0.1.12
        (
            "src/client/legacy/connect/http.rs",
            [
                0x92, 0xbc, 0x8b, 0x00, 0xc6, 0xe6, 0x42, 0x55, 0xab, 0xba, 0x23, 0x3a, 0x16, 0x7f,
                0xcb, 0x0f,
            ],
        ),
        // src/client/legacy/connect/http.rs, 0.1.13
        (
            "src/client/legacy/connect/http.rs",
            [
                0x51, 0x33, 0x0d, 0x55, 0xef, 0x10, 0xc6, 0xf0, 0x00, 0x46, 0x99, 0x46, 0x28, 0xca,
                0x52, 0x00,
            ],
        ),
        // src/client/legacy/connect/http.rs, 0.1.14 through 0.1.16
        (
            "src/client/legacy/connect/http.rs",
            [
                0x02, 0x83, 0xff, 0xd0, 0x81, 0x35, 0x2b, 0x62, 0xad, 0xe0, 0x35, 0xec, 0x14, 0x96,
                0xee, 0xa8,
            ],
        ),
        // src/client/legacy/connect/http.rs, 0.1.17 through 0.1.19
        (
            "src/client/legacy/connect/http.rs",
            [
                0xb3, 0x5c, 0x1f, 0xfc, 0xc5, 0x15, 0x41, 0xc4, 0xa8, 0x48, 0xd2, 0xe0, 0x92, 0x61,
                0xbc, 0x63,
            ],
        ),
        // src/client/legacy/connect/http.rs, 0.1.20
        (
            "src/client/legacy/connect/http.rs",
            [
                0x12, 0xa0, 0x22, 0xca, 0xa9, 0xed, 0xd6, 0xb5, 0xf1, 0xb9, 0x5d, 0x8c, 0x97, 0x0a,
                0xbd, 0xb7,
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
    releases: Releases(&[((0, 1, 10), (0, 1, 20))]),
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

/// hyper-util's legacy client pool as 0.1.16 through 0.1.20 lay it out,
/// reviewed in `src/client/legacy/pool.rs` and `client.rs` of each
/// release: `IdleTask { timer, duration, pool: WeakOpt<Mutex<PoolInner<
/// T, K>>>, pool_drop_notifier }` (0.1.15 and before kept a `deadline`
/// and the pinned sleep beside the pool, in a `pin_project!`),
/// `PoolInner { .., idle: HashMap<K, Vec<Idle<T>>>, .. }`, `Idle {
/// idle_at, value: T }`, `Pooled { value: Option<T>, is_reused, key: K,
/// pool }`, and the client's `PoolClient { conn_info, tx: PoolTx<B> }`
/// with `PoolTx::Http1(hyper::client::conn::http1::SendRequest<B>)`; the
/// key is `(Scheme, Authority)`. What the review establishes: a reaper
/// holds its pool weakly for as long as the pool lives, the idle map
/// holds every connection waiting to be checked out under the key it
/// was made for, and a checked-out connection keeps that key; the
/// sender's `want::Giver` (hyper's `dispatch::Sender`) shares its
/// `Arc<want::Inner>` with the one `Taker` of the receiver the
/// connection's dispatcher reads — that pointer is the connection's
/// identity on both sides.
pub const HYPER_UTIL_POOL_V0_1_16: LibraryConvention = LibraryConvention {
    package: "hyper-util",
    family: "hyper-util-pool-0.1.16",
    releases: Releases(&[((0, 1, 16), (0, 1, 20))]),
    checksums: &[
        // src/client/legacy/pool.rs, 0.1.16
        (
            "src/client/legacy/pool.rs",
            [
                0x0c, 0xd2, 0x72, 0x30, 0x99, 0x42, 0x63, 0x5c, 0xb9, 0x67, 0x9f, 0x37, 0xa3, 0x0c,
                0xd1, 0x12,
            ],
        ),
        // src/client/legacy/pool.rs, 0.1.17
        (
            "src/client/legacy/pool.rs",
            [
                0x6e, 0x25, 0x83, 0x2f, 0xe1, 0x79, 0x87, 0xf1, 0x0e, 0xb7, 0x3a, 0x85, 0x1f, 0xb6,
                0x04, 0x85,
            ],
        ),
        // src/client/legacy/pool.rs, 0.1.18 through 0.1.19
        (
            "src/client/legacy/pool.rs",
            [
                0xac, 0x50, 0x2b, 0x40, 0x37, 0xfa, 0x1d, 0x28, 0x06, 0x9a, 0x38, 0xeb, 0xeb, 0x5f,
                0x95, 0x90,
            ],
        ),
        // src/client/legacy/pool.rs, 0.1.20
        (
            "src/client/legacy/pool.rs",
            [
                0x35, 0x95, 0x25, 0x8e, 0x1b, 0x4e, 0x87, 0xe2, 0xe7, 0xe5, 0xde, 0x8b, 0x21, 0xbe,
                0xf2, 0x5c,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.16
        (
            "src/client/legacy/client.rs",
            [
                0x86, 0xe1, 0xbc, 0x92, 0x61, 0xf4, 0x9b, 0x52, 0xb4, 0x6a, 0x6c, 0x9d, 0xe6, 0x03,
                0xe5, 0x21,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.17
        (
            "src/client/legacy/client.rs",
            [
                0xb0, 0x0b, 0x75, 0xa5, 0xa7, 0xc2, 0x52, 0xbe, 0x65, 0xac, 0x88, 0x8a, 0xe0, 0xab,
                0xf2, 0x63,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.18 through 0.1.19
        (
            "src/client/legacy/client.rs",
            [
                0x9b, 0x90, 0x83, 0xd8, 0x0b, 0xb8, 0xec, 0x56, 0x4e, 0xb7, 0x70, 0x93, 0x5b, 0x36,
                0x59, 0x6d,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.20
        (
            "src/client/legacy/client.rs",
            [
                0xbe, 0x70, 0x4c, 0x6b, 0xf9, 0x58, 0x1d, 0x9a, 0xcc, 0xb4, 0x6f, 0x50, 0x80, 0xaa,
                0x70, 0x07,
            ],
        ),
    ],
};

/// hyper-util's `Connected` as 0.1.10 through 0.1.20 lay it out,
/// reviewed in `src/client/legacy/connect/mod.rs` and `connect/http.rs`
/// of each release: `Connected { alpn: Alpn, is_proxied: bool, extra:
/// Option<Extra>, poisoned }`, `Extra(Box<dyn ExtraInner>)`, the trait
/// `ExtraInner { fn clone_box(&self); fn set(&self, &mut Extensions); }`
/// implemented by `ExtraEnvelope<T>(T)` and by `ExtraChain<T>(Box<dyn
/// ExtraInner>, T)`, which a second extra wraps the first in; and
/// `HttpInfo { remote_addr: SocketAddr, local_addr: SocketAddr }`, which
/// the connector's `TcpStream` records from the socket once it connects.
/// What the review establishes: the pool keeps a connection's
/// `Connected` beside its sender for as long as the connection is
/// pooled, the extras are every value the connector recorded, and a
/// chain's own value is the later one. The releases differ in
/// documentation only.
pub const HYPER_UTIL_CONNECTED_V0_1_10: LibraryConvention = LibraryConvention {
    package: "hyper-util",
    family: "hyper-util-connected-0.1.10",
    releases: Releases(&[((0, 1, 10), (0, 1, 20))]),
    checksums: &[
        // src/client/legacy/connect/mod.rs, 0.1.10 through 0.1.11
        (
            "src/client/legacy/connect/mod.rs",
            [
                0xde, 0xbe, 0x4f, 0x51, 0x36, 0xd4, 0x06, 0x34, 0x3f, 0xeb, 0x4f, 0xbf, 0x46, 0x74,
                0x10, 0x53,
            ],
        ),
        // src/client/legacy/connect/mod.rs, 0.1.12 through 0.1.20
        (
            "src/client/legacy/connect/mod.rs",
            [
                0x2d, 0x70, 0xf2, 0x64, 0xc6, 0xdb, 0x56, 0x1f, 0x3f, 0xe6, 0x2e, 0x01, 0x40, 0x33,
                0x41, 0x98,
            ],
        ),
    ],
};

/// The slot `ExtraInner::set` holds in hyper-util's `dyn ExtraInner`
/// vtable, under [`HYPER_UTIL_CONNECTED_V0_1_10`]: after the header's
/// drop, size and alignment, and `clone_box`.
pub const EXTRA_INNER_SET_SLOT: u32 = 4;

/// hyper-util's legacy client `ResponseFuture` as 0.1.10 through 0.1.20
/// lay it out, reviewed in `src/client/legacy/client.rs` of each
/// release: `struct ResponseFuture { inner: SyncWrapper<Pin<Box<dyn
/// Future<..> + Send>>> }`, whose `poll` is
/// `self.inner.get_mut().as_mut().poll(cx)` and nothing else — the
/// crate's own `common::sync::SyncWrapper<T>(T)` only lends its one
/// member — so it forwards exclusively to the boxed future
/// `Client::request` built.
pub const HYPER_UTIL_RESPONSE_V0_1_10: LibraryConvention = LibraryConvention {
    package: "hyper-util",
    family: "hyper-util-response-0.1.10",
    releases: Releases(&[((0, 1, 10), (0, 1, 20))]),
    checksums: &[
        // src/client/legacy/client.rs, 0.1.10
        (
            "src/client/legacy/client.rs",
            [
                0x0e, 0xac, 0x23, 0x67, 0x18, 0x7c, 0xd7, 0x4b, 0xf7, 0x08, 0xa5, 0xec, 0xf2, 0xb7,
                0x3e, 0xe9,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.11
        (
            "src/client/legacy/client.rs",
            [
                0xff, 0x3b, 0x40, 0xa4, 0x0f, 0xed, 0xf6, 0x0b, 0xc3, 0xdc, 0x70, 0x9a, 0x13, 0x4a,
                0xc4, 0x3c,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.12
        (
            "src/client/legacy/client.rs",
            [
                0x6a, 0x90, 0xf1, 0x4d, 0x4f, 0x6a, 0xa6, 0x1d, 0xe1, 0x25, 0x09, 0xcf, 0x8f, 0x1e,
                0xeb, 0xfe,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.13 through 0.1.14
        (
            "src/client/legacy/client.rs",
            [
                0x90, 0x9c, 0xff, 0x58, 0x8a, 0xe2, 0x6f, 0x17, 0x72, 0x00, 0xb7, 0x9d, 0x9c, 0x4f,
                0x58, 0x93,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.15 through 0.1.16
        (
            "src/client/legacy/client.rs",
            [
                0x86, 0xe1, 0xbc, 0x92, 0x61, 0xf4, 0x9b, 0x52, 0xb4, 0x6a, 0x6c, 0x9d, 0xe6, 0x03,
                0xe5, 0x21,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.17
        (
            "src/client/legacy/client.rs",
            [
                0xb0, 0x0b, 0x75, 0xa5, 0xa7, 0xc2, 0x52, 0xbe, 0x65, 0xac, 0x88, 0x8a, 0xe0, 0xab,
                0xf2, 0x63,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.18 through 0.1.19
        (
            "src/client/legacy/client.rs",
            [
                0x9b, 0x90, 0x83, 0xd8, 0x0b, 0xb8, 0xec, 0x56, 0x4e, 0xb7, 0x70, 0x93, 0x5b, 0x36,
                0x59, 0x6d,
            ],
        ),
        // src/client/legacy/client.rs, 0.1.20
        (
            "src/client/legacy/client.rs",
            [
                0xbe, 0x70, 0x4c, 0x6b, 0xf9, 0x58, 0x1d, 0x9a, 0xcc, 0xb4, 0x6f, 0x50, 0x80, 0xaa,
                0x70, 0x07,
            ],
        ),
    ],
};

/// tower's retry `ResponseFuture` as 0.5.2 and 0.5.3 implement it,
/// reviewed in `src/retry/future.rs` of each (their `ResponseFuture`,
/// `State` and `poll` are identical): `{ request, retry, state: State<
/// F, P> }`, `State` being `Called { future } | Waiting { waiting } |
/// Retrying`. Its `poll` loops over the state: in `Called` it polls the
/// service's `future`, in `Waiting` the policy's `waiting` future, and
/// in `Retrying` it polls the service's readiness, which it holds no
/// future of. So a parked retry is parked on the one future its state
/// holds, or, retrying, on nothing a route can reach.
pub const TOWER_RETRY_V0_5_2: LibraryConvention = LibraryConvention {
    package: "tower",
    family: "tower-retry-0.5.2",
    releases: Releases(&[((0, 5, 2), (0, 5, 3))]),
    checksums: &[
        // src/retry/future.rs, 0.5.2
        (
            "src/retry/future.rs",
            [
                0x54, 0xf3, 0x51, 0xed, 0x09, 0xda, 0x3d, 0xf5, 0xd8, 0x39, 0xa2, 0x10, 0xc3, 0x48,
                0x3a, 0x38,
            ],
        ),
        // src/retry/future.rs, 0.5.3
        (
            "src/retry/future.rs",
            [
                0xfd, 0x9f, 0x09, 0x83, 0x4c, 0x00, 0x69, 0x91, 0x75, 0x1d, 0xf0, 0xec, 0x0b, 0xb0,
                0x9b, 0xa8,
            ],
        ),
    ],
};

/// reqwest's cookie layer as 0.12.24 through 0.13.4 implement it,
/// reviewed in `src/cookie.rs` of each (byte-identical): the service's
/// `ResponseFuture<S, B>` is `{ future: S::Future, cookie_store, url }`,
/// and its `poll` clones the store and the URL, then polls `future`,
/// reading the other two only once the response is in. So it forwards
/// exclusively to `future`. Before 0.12.24 the file has no `service`
/// module: the layer did not exist.
pub const REQWEST_COOKIE_V0_12_24: LibraryConvention = LibraryConvention {
    package: "reqwest",
    family: "reqwest-cookie-0.12.24",
    releases: Releases(&[((0, 12, 24), (0, 12, 28)), ((0, 13, 0), (0, 13, 4))]),
    checksums: &[
        // src/cookie.rs, 0.12.24 through 0.13.4
        (
            "src/cookie.rs",
            [
                0xb7, 0x07, 0x01, 0x0e, 0x05, 0x11, 0x1e, 0x6c, 0x25, 0xd1, 0xe6, 0xd0, 0x5c, 0x75,
                0x81, 0x1c,
            ],
        ),
    ],
};

/// dropshot's server as 0.17.0 and 0.17.1 implement it, reviewed in
/// `src/server.rs` of each release (0.17.1 differs from 0.17.0 in import
/// order and rustfmt reflow alone): the accept loop takes each
/// connection's peer address off the socket (`TcpListener::accept` for
/// plain HTTP, the `TlsConn` it wraps a TLS stream in for HTTPS) and
/// hands it to `make_http_request_handler`, which builds the
/// `ServerRequestHandler { server, remote_addr }` hyper-util's server
/// drives as its service. `remote_addr` is the accepted socket's peer
/// as `SocketAddr`, set once at construction and never changed, so a
/// server connection's peer is the word its dispatch's service holds.
/// Its `C` is the context the application built the server with
/// (`server: Arc<DropshotState<C>>`, whose `private: C` holds it), so
/// the handler's own type names which of a program's servers a
/// connection was accepted by.
///
/// `TlsConn` (the same file, identical in both releases) is `{ stream:
/// tokio_rustls::server::TlsStream<TcpStream>, remote_addr }`, and its
/// `AsyncRead`/`AsyncWrite` impls call the same method on `stream` and
/// nothing else: a stream route forwards through it.
///
/// The ceiling is the newest release the cores on hand build; it
/// advances by hand when a newer one is read.
pub const DROPSHOT_SERVER_V0_17_0: LibraryConvention = LibraryConvention {
    package: "dropshot",
    family: "dropshot-server-0.17.0",
    releases: Releases(&[((0, 17, 0), (0, 17, 1))]),
    checksums: &[
        // src/server.rs, 0.17.0
        (
            "src/server.rs",
            [
                0x94, 0x37, 0xcb, 0xa6, 0x5a, 0xa8, 0xa8, 0x47, 0xf0, 0x67, 0x90, 0x33, 0x1c, 0xa9,
                0x06, 0xe3,
            ],
        ),
        // src/server.rs, 0.17.1
        (
            "src/server.rs",
            [
                0x0b, 0x1f, 0xf0, 0xd3, 0x4f, 0x82, 0x8b, 0x7d, 0xf9, 0xce, 0x12, 0xa5, 0x76, 0x69,
                0x81, 0xa2,
            ],
        ),
    ],
};

/// reqwest's client request as 0.12.0 through 0.13.2 implement it,
/// reviewed in `src/async_impl/client.rs` of each release: `send()`
/// returns a `Pending` whose `PendingInner::Request` holds the
/// `PendingRequest` the client polls — inline through 0.12.19, behind a
/// `Pin<Box<..>>` from 0.12.20 — and that request keeps `method:
/// Method` and `url: Url` for the retries and redirects its `poll`
/// may issue, unchanged in every release. The file churns with the
/// client builder, the retry policy and the redirect handling around
/// them; the two members the binding addresses, and `PendingRequest`
/// implementing `Future` in its own right, hold across the range, so
/// the boxing is no divergence the binding sees: the request is met
/// as its own future either way. `url.serialization` is the whole URL
/// as text, which is what the `url` crate keeps its parsed form as.
///
/// The ceiling is the newest release the cores on hand build; it
/// advances by hand when a newer one is read (0.13.3 and 0.13.4 match
/// on every addressed declaration).
pub const REQWEST_PENDING_REQUEST_V0_12_0: LibraryConvention = LibraryConvention {
    package: "reqwest",
    family: "reqwest-pending-request-0.12.0",
    releases: Releases(&[((0, 12, 0), (0, 12, 28)), ((0, 13, 0), (0, 13, 2))]),
    checksums: &[
        // src/async_impl/client.rs, 0.12.0
        (
            "src/async_impl/client.rs",
            [
                0x84, 0x35, 0x9d, 0x45, 0x46, 0x6f, 0xbc, 0x6e, 0xa9, 0xb6, 0x0d, 0x9e, 0x20, 0x50,
                0xb3, 0x1d,
            ],
        ),
        // src/async_impl/client.rs, 0.12.1
        (
            "src/async_impl/client.rs",
            [
                0xfc, 0x3b, 0x79, 0xfd, 0x3a, 0x17, 0x99, 0x73, 0xad, 0xfa, 0xf8, 0xfb, 0x35, 0xa2,
                0xbf, 0x0f,
            ],
        ),
        // src/async_impl/client.rs, 0.12.2
        (
            "src/async_impl/client.rs",
            [
                0x9b, 0xb5, 0xe4, 0xa7, 0x09, 0x69, 0x11, 0x09, 0x26, 0x8f, 0x67, 0x0b, 0xa5, 0xf5,
                0x85, 0xf1,
            ],
        ),
        // src/async_impl/client.rs, 0.12.3
        (
            "src/async_impl/client.rs",
            [
                0x15, 0x9f, 0x99, 0x05, 0x86, 0x57, 0xa3, 0x72, 0x8f, 0x31, 0x6a, 0x9e, 0x72, 0xd2,
                0xcf, 0x95,
            ],
        ),
        // src/async_impl/client.rs, 0.12.4
        (
            "src/async_impl/client.rs",
            [
                0xea, 0xd0, 0x61, 0xb1, 0xbd, 0x74, 0xbc, 0xd9, 0x4b, 0xef, 0x6a, 0xe8, 0xfd, 0x93,
                0xd2, 0xbc,
            ],
        ),
        // src/async_impl/client.rs, 0.12.5
        (
            "src/async_impl/client.rs",
            [
                0x07, 0x39, 0x73, 0xfb, 0x18, 0x4b, 0x3b, 0x4c, 0x45, 0xe6, 0x38, 0xc5, 0x8b, 0x50,
                0x45, 0x60,
            ],
        ),
        // src/async_impl/client.rs, 0.12.6
        (
            "src/async_impl/client.rs",
            [
                0xfb, 0xf6, 0x70, 0x0a, 0x75, 0xac, 0x3f, 0xc1, 0xf0, 0x75, 0xce, 0x95, 0x7a, 0x35,
                0xcc, 0xbb,
            ],
        ),
        // src/async_impl/client.rs, 0.12.7
        (
            "src/async_impl/client.rs",
            [
                0x57, 0xbb, 0x08, 0xdc, 0xcf, 0xc3, 0x36, 0x03, 0xdc, 0x99, 0xe0, 0x2a, 0xb8, 0xc8,
                0xc1, 0x55,
            ],
        ),
        // src/async_impl/client.rs, 0.12.8
        (
            "src/async_impl/client.rs",
            [
                0x4d, 0xad, 0x39, 0xcc, 0x68, 0x76, 0x36, 0xd3, 0xdd, 0x9f, 0x8d, 0xa1, 0x69, 0xfc,
                0x05, 0x70,
            ],
        ),
        // src/async_impl/client.rs, 0.12.9
        (
            "src/async_impl/client.rs",
            [
                0xf0, 0x62, 0x20, 0x6e, 0x84, 0x69, 0x5a, 0x33, 0x56, 0x67, 0x8e, 0x6a, 0x6b, 0x29,
                0xf2, 0xea,
            ],
        ),
        // src/async_impl/client.rs, 0.12.10
        (
            "src/async_impl/client.rs",
            [
                0x42, 0x37, 0x18, 0x8e, 0xd3, 0x44, 0xf5, 0x67, 0x3c, 0xac, 0xa0, 0x1a, 0xef, 0x8f,
                0xcc, 0x3c,
            ],
        ),
        // src/async_impl/client.rs, 0.12.11 through 0.12.15
        (
            "src/async_impl/client.rs",
            [
                0x1e, 0xad, 0xb8, 0xc9, 0x85, 0xa7, 0xf9, 0x3a, 0x09, 0xbf, 0xee, 0x79, 0xa2, 0xa2,
                0x64, 0xdd,
            ],
        ),
        // src/async_impl/client.rs, 0.12.16
        (
            "src/async_impl/client.rs",
            [
                0x8a, 0x13, 0x6e, 0xa2, 0xd3, 0x4f, 0x69, 0x2c, 0xf8, 0xde, 0x4b, 0xc9, 0x23, 0x26,
                0x1d, 0x38,
            ],
        ),
        // src/async_impl/client.rs, 0.12.17 through 0.12.19
        (
            "src/async_impl/client.rs",
            [
                0x5e, 0xbd, 0xcb, 0xeb, 0xdd, 0xd8, 0xa0, 0x81, 0x1c, 0xd1, 0xdf, 0x44, 0x6a, 0x60,
                0x2b, 0x9d,
            ],
        ),
        // src/async_impl/client.rs, 0.12.20
        (
            "src/async_impl/client.rs",
            [
                0x11, 0x47, 0x8e, 0xc2, 0xad, 0x12, 0xb7, 0xd5, 0x87, 0x65, 0x0c, 0x4c, 0x4c, 0x69,
                0xcd, 0xda,
            ],
        ),
        // src/async_impl/client.rs, 0.12.21 through 0.12.22
        (
            "src/async_impl/client.rs",
            [
                0x1d, 0x18, 0xb9, 0x12, 0xcf, 0x8f, 0xaa, 0xd4, 0x2e, 0xd1, 0x55, 0x0f, 0x61, 0x87,
                0x82, 0xf6,
            ],
        ),
        // src/async_impl/client.rs, 0.12.23
        (
            "src/async_impl/client.rs",
            [
                0xc3, 0x9f, 0x8e, 0x00, 0xd5, 0xb6, 0x40, 0x62, 0x8c, 0xaa, 0x95, 0x02, 0x6f, 0x67,
                0x9a, 0x92,
            ],
        ),
        // src/async_impl/client.rs, 0.12.24
        (
            "src/async_impl/client.rs",
            [
                0x06, 0xbe, 0x11, 0xaf, 0xe2, 0xd6, 0xaa, 0x4a, 0xd9, 0x06, 0xdb, 0xac, 0x30, 0x3b,
                0x13, 0xa3,
            ],
        ),
        // src/async_impl/client.rs, 0.12.25
        (
            "src/async_impl/client.rs",
            [
                0xa2, 0x02, 0xb2, 0x6c, 0x6c, 0xd9, 0x65, 0x3b, 0x80, 0x53, 0x52, 0x89, 0x0e, 0x2c,
                0x43, 0x5e,
            ],
        ),
        // src/async_impl/client.rs, 0.12.26
        (
            "src/async_impl/client.rs",
            [
                0x78, 0x39, 0x38, 0x88, 0x80, 0x06, 0x83, 0xc5, 0x77, 0x62, 0x02, 0x81, 0x30, 0x7f,
                0xb3, 0xe7,
            ],
        ),
        // src/async_impl/client.rs, 0.12.27 through 0.12.28
        (
            "src/async_impl/client.rs",
            [
                0xbe, 0x74, 0x52, 0x73, 0x81, 0xbe, 0x91, 0x47, 0xdf, 0xf3, 0x0e, 0x99, 0xcc, 0x28,
                0xc9, 0x55,
            ],
        ),
        // src/async_impl/client.rs, 0.13.0
        (
            "src/async_impl/client.rs",
            [
                0x6f, 0xef, 0xab, 0x6b, 0xec, 0xd2, 0x5b, 0xca, 0x65, 0x54, 0xda, 0xbb, 0x1a, 0xd5,
                0x2b, 0x49,
            ],
        ),
        // src/async_impl/client.rs, 0.13.1
        (
            "src/async_impl/client.rs",
            [
                0xc6, 0xd9, 0x0a, 0xfa, 0x7b, 0xc6, 0x4e, 0x34, 0x06, 0xf7, 0x84, 0xb5, 0x10, 0x8e,
                0x62, 0x1f,
            ],
        ),
        // src/async_impl/client.rs, 0.13.2
        (
            "src/async_impl/client.rs",
            [
                0x14, 0x1e, 0x93, 0x91, 0x30, 0xc2, 0xa9, 0x7f, 0x54, 0x7f, 0x02, 0xfb, 0x1c, 0xc9,
                0xfa, 0xd8,
            ],
        ),
    ],
};

/// http's request as 1.0.0 through 1.4.2 implement it, reviewed in
/// `src/request.rs`, `src/method.rs`, `src/uri/mod.rs`, `src/uri/path.rs`
/// and `src/byte_str.rs` of each release: `Request<T> { head: Parts,
/// body: T }`, `Parts { method, uri, version, headers, extensions }`,
/// `Method(Inner)` with `Inner`'s variants naming the standard methods
/// and the two extension forms, `Uri { scheme, authority,
/// path_and_query }`, `PathAndQuery { data: ByteStr, query: u16 }` and
/// `ByteStr { bytes: Bytes }` are byte-identical across the range; the
/// files churn with parsing, validation and docs around them. A
/// server's handler holds the request it is running for as this type
/// where nothing wraps it, so the request line is read off its head.
///
/// The ceiling is the newest release the cores on hand build; it
/// advances by hand when a newer one is read (1.5.0 adds a variant to
/// `Inner`, which the binding reads by name).
pub const HTTP_REQUEST_V1_0_0: LibraryConvention = LibraryConvention {
    package: "http",
    family: "http-request-1.0.0",
    releases: Releases(&[
        ((1, 0, 0), (1, 0, 0)),
        ((1, 1, 0), (1, 1, 0)),
        ((1, 2, 0), (1, 2, 0)),
        ((1, 3, 0), (1, 3, 1)),
        ((1, 4, 0), (1, 4, 2)),
    ]),
    checksums: &[
        // src/request.rs, 1.0.0
        (
            "src/request.rs",
            [
                0xda, 0x86, 0x1a, 0x88, 0x72, 0xe3, 0x09, 0x49, 0xd7, 0x3c, 0x81, 0x30, 0xe0, 0x40,
                0xa5, 0x8f,
            ],
        ),
        // src/request.rs, 1.1.0
        (
            "src/request.rs",
            [
                0x85, 0x93, 0xd7, 0x9c, 0xc4, 0x47, 0xfa, 0x4a, 0x07, 0x8c, 0xb3, 0xf4, 0xdf, 0xfe,
                0x77, 0xf5,
            ],
        ),
        // src/request.rs, 1.2.0 through 1.3.1
        (
            "src/request.rs",
            [
                0x91, 0xb3, 0x19, 0x87, 0xbb, 0xec, 0x77, 0xe1, 0xff, 0xd4, 0xcb, 0xea, 0xf1, 0xf7,
                0x84, 0xa9,
            ],
        ),
        // src/request.rs, 1.4.0
        (
            "src/request.rs",
            [
                0x79, 0x71, 0xb6, 0xd4, 0x81, 0xf3, 0x81, 0xb3, 0x19, 0x1e, 0x80, 0x7a, 0x59, 0xa0,
                0xbc, 0x36,
            ],
        ),
        // src/request.rs, 1.4.1 through 1.4.2
        (
            "src/request.rs",
            [
                0xb8, 0x46, 0xa8, 0x29, 0xa5, 0xdf, 0x9d, 0xea, 0xa2, 0x3a, 0x43, 0x94, 0x07, 0x56,
                0xa2, 0xf9,
            ],
        ),
        // src/method.rs, 1.0.0
        (
            "src/method.rs",
            [
                0x46, 0xad, 0x2e, 0x29, 0xd6, 0xc5, 0x4b, 0xec, 0x6f, 0x08, 0xbf, 0xd2, 0x4c, 0x03,
                0xa9, 0x0f,
            ],
        ),
        // src/method.rs, 1.1.0
        (
            "src/method.rs",
            [
                0x5e, 0xe4, 0xf2, 0x47, 0x04, 0xd1, 0x00, 0x5d, 0x05, 0xd5, 0x30, 0x0c, 0x9d, 0x60,
                0x3f, 0x44,
            ],
        ),
        // src/method.rs, 1.2.0 through 1.4.0
        (
            "src/method.rs",
            [
                0x3d, 0x13, 0x02, 0x02, 0x35, 0x5e, 0x84, 0x03, 0xcf, 0xe2, 0x15, 0x49, 0x76, 0xa8,
                0x14, 0x77,
            ],
        ),
        // src/method.rs, 1.4.1
        (
            "src/method.rs",
            [
                0x7a, 0x4f, 0x16, 0x84, 0xb4, 0x5a, 0xc6, 0xc4, 0xda, 0xf4, 0xac, 0x0b, 0x25, 0x78,
                0x0c, 0xff,
            ],
        ),
        // src/method.rs, 1.4.2
        (
            "src/method.rs",
            [
                0xb8, 0x81, 0xb1, 0x5d, 0xe0, 0x80, 0x85, 0x3f, 0xb2, 0x9c, 0x22, 0xec, 0x7d, 0x21,
                0x45, 0x4e,
            ],
        ),
        // src/uri/mod.rs, 1.0.0
        (
            "src/uri/mod.rs",
            [
                0x9c, 0x28, 0xf7, 0x1d, 0xb0, 0x40, 0x27, 0x27, 0x0b, 0xd5, 0x18, 0x7b, 0xae, 0x3c,
                0x0d, 0x59,
            ],
        ),
        // src/uri/mod.rs, 1.1.0
        (
            "src/uri/mod.rs",
            [
                0x8b, 0x0e, 0x0e, 0x21, 0x1e, 0x5d, 0x1d, 0xd1, 0x4e, 0x8a, 0xed, 0xcb, 0x41, 0xa7,
                0xfe, 0x0a,
            ],
        ),
        // src/uri/mod.rs, 1.2.0 through 1.4.0
        (
            "src/uri/mod.rs",
            [
                0x84, 0xc6, 0xc1, 0x4b, 0xa2, 0xc2, 0x2e, 0xb3, 0xea, 0x59, 0x37, 0x03, 0x7d, 0x94,
                0x4f, 0xcc,
            ],
        ),
        // src/uri/mod.rs, 1.4.1 through 1.4.2
        (
            "src/uri/mod.rs",
            [
                0xe4, 0x04, 0x37, 0xc6, 0xa2, 0x08, 0xb3, 0x37, 0xe6, 0x48, 0x06, 0xa0, 0xd9, 0x41,
                0x9d, 0x82,
            ],
        ),
        // src/uri/path.rs, 1.0.0
        (
            "src/uri/path.rs",
            [
                0xe5, 0x9d, 0x05, 0xfb, 0x1f, 0x08, 0xc9, 0xce, 0x42, 0x4e, 0x95, 0x2e, 0x44, 0xac,
                0xb7, 0x72,
            ],
        ),
        // src/uri/path.rs, 1.1.0
        (
            "src/uri/path.rs",
            [
                0x02, 0xc4, 0x71, 0xdb, 0x9c, 0x3e, 0x49, 0x4b, 0x05, 0xbb, 0x93, 0xcc, 0x76, 0x9e,
                0xf5, 0x0a,
            ],
        ),
        // src/uri/path.rs, 1.2.0
        (
            "src/uri/path.rs",
            [
                0x0b, 0x84, 0x02, 0x4a, 0x3f, 0x66, 0x59, 0xf3, 0x46, 0xe7, 0x21, 0x48, 0x08, 0x1d,
                0xa5, 0x9d,
            ],
        ),
        // src/uri/path.rs, 1.3.0
        (
            "src/uri/path.rs",
            [
                0x91, 0xd6, 0x33, 0x45, 0x43, 0x35, 0x70, 0x08, 0x09, 0x4d, 0x66, 0xe3, 0x01, 0x2e,
                0x8a, 0x9a,
            ],
        ),
        // src/uri/path.rs, 1.3.1
        (
            "src/uri/path.rs",
            [
                0x86, 0xd9, 0x20, 0xdf, 0x48, 0x43, 0xb6, 0x53, 0xa6, 0x1a, 0xad, 0xe5, 0xfd, 0x0d,
                0x15, 0x0d,
            ],
        ),
        // src/uri/path.rs, 1.4.0
        (
            "src/uri/path.rs",
            [
                0x85, 0x5f, 0x94, 0x75, 0xcb, 0xe8, 0x0a, 0xec, 0xa4, 0x37, 0x6d, 0x43, 0x6d, 0x32,
                0x9a, 0xdc,
            ],
        ),
        // src/uri/path.rs, 1.4.1
        (
            "src/uri/path.rs",
            [
                0xd3, 0x5f, 0xde, 0xae, 0x0c, 0x2d, 0x34, 0xbe, 0xe3, 0x5f, 0xed, 0xb1, 0x1a, 0x0f,
                0xd9, 0x6c,
            ],
        ),
        // src/uri/path.rs, 1.4.2
        (
            "src/uri/path.rs",
            [
                0x73, 0xb5, 0x5d, 0xd5, 0x01, 0x3e, 0x85, 0x33, 0x40, 0x4f, 0xc0, 0x92, 0x0e, 0x75,
                0x1e, 0x6a,
            ],
        ),
        // src/byte_str.rs, 1.0.0
        (
            "src/byte_str.rs",
            [
                0x88, 0xf7, 0x9c, 0x06, 0xac, 0xb5, 0x1d, 0x2e, 0x9a, 0x4d, 0x6c, 0x48, 0x67, 0x39,
                0x58, 0x35,
            ],
        ),
        // src/byte_str.rs, 1.1.0
        (
            "src/byte_str.rs",
            [
                0x6e, 0x67, 0x94, 0xaf, 0xb4, 0x44, 0x48, 0x78, 0x0c, 0xb2, 0xe9, 0x12, 0x55, 0x1f,
                0x93, 0xc5,
            ],
        ),
        // src/byte_str.rs, 1.2.0 through 1.3.0
        (
            "src/byte_str.rs",
            [
                0x0a, 0x9e, 0xd1, 0x00, 0x91, 0x99, 0x21, 0x78, 0x30, 0x81, 0x22, 0x72, 0xed, 0xb7,
                0xd3, 0x4d,
            ],
        ),
        // src/byte_str.rs, 1.3.1 through 1.4.0
        (
            "src/byte_str.rs",
            [
                0x85, 0xbc, 0xfe, 0x19, 0x27, 0xcf, 0x06, 0xdd, 0xda, 0x5c, 0xa2, 0x47, 0xfc, 0x51,
                0x48, 0x5f,
            ],
        ),
        // src/byte_str.rs, 1.4.1 through 1.4.2
        (
            "src/byte_str.rs",
            [
                0x3f, 0x0e, 0x8a, 0xb2, 0x79, 0x89, 0xaa, 0x2f, 0xc0, 0xb8, 0x57, 0x42, 0x31, 0xea,
                0x57, 0x8e,
            ],
        ),
    ],
};

/// dropshot's request context as 0.17.0 and 0.17.1 implement it,
/// reviewed in `src/handler.rs` of each release (0.17.1 differs in
/// import order, rustfmt reflow and match-ergonomics spelling alone):
/// every endpoint handler runs with a `RequestContext<C> { server,
/// endpoint, request_id, log, request }`, whose `request: RequestInfo
/// { method, uri, version, headers, remote_addr }` is copied off the
/// hyper request as the handler is dispatched and never changed, so
/// the request a server connection's handler is running for is the
/// method and URI its context holds.
///
/// The ceiling is the newest release the cores on hand build; it
/// advances by hand when a newer one is read.
pub const DROPSHOT_HANDLER_V0_17_0: LibraryConvention = LibraryConvention {
    package: "dropshot",
    family: "dropshot-handler-0.17.0",
    releases: Releases(&[((0, 17, 0), (0, 17, 1))]),
    checksums: &[
        // src/handler.rs, 0.17.0
        (
            "src/handler.rs",
            [
                0xf8, 0x3e, 0x3f, 0x31, 0x28, 0x9e, 0x13, 0x5e, 0x5c, 0x02, 0xa3, 0xe8, 0x01, 0xf9,
                0x01, 0x5d,
            ],
        ),
        // src/handler.rs, 0.17.1
        (
            "src/handler.rs",
            [
                0xfd, 0xf8, 0x78, 0x0f, 0x2f, 0x71, 0x88, 0xba, 0x8d, 0x0c, 0xfa, 0xa7, 0xe6, 0xae,
                0x89, 0xce,
            ],
        ),
    ],
};

/// hyper's HTTP/1 connection as 1.6.0 through 1.10.1 implement it,
/// reviewed in `src/proto/h1/conn.rs`, `src/proto/h1/dispatch.rs`,
/// `src/proto/h1/decode.rs`, `src/proto/h1/encode.rs`,
/// `src/client/dispatch.rs`, `src/client/conn/http1.rs` and
/// `src/server/conn/http1.rs` of every release in the range. The
/// declarations the rule addresses are the same text in all of them:
/// `Dispatcher { conn, dispatch, body_tx, body_rx, is_closing }` (only
/// `body_tx`'s type moved, in 1.10.0, and nothing here names it),
/// `Conn { io, state, _marker }`, `State`, and its `KA { Idle, Busy,
/// Disabled }`, `Reading { Init, Continue(Decoder), Body(Decoder),
/// KeepAlive, Closed }`, `Writing { Init, Body(Encoder), KeepAlive,
/// Closed }` and `method: Option<Method>`; `Decoder { kind: Kind }`
/// with `Kind { Length(u64), Chunked { .. }, Eof(bool) }` and `Encoder
/// { kind: Kind, is_last }` with `Kind { Chunked(..), Length(u64),
/// CloseDelimited }` (1.9.0 changed what `Chunked` carries, not its
/// name); the client dispatch `Client { callback: Option<Callback>,
/// rx: Receiver, rx_closed }` with `Callback { Retry(Option<
/// oneshot::Sender>), NoRetry(Option<oneshot::Sender>) }` and
/// `Receiver { inner: UnboundedReceiver, taker }`; and the wrappers
/// `Connection { inner: Dispatcher }` and `UpgradeableConnection {
/// inner: Option<Connection> }` on each side. The releases differ in
/// the dispatcher's write-again loop (1.8.0, 1.10.x), the body
/// sender's drop guard (1.10.0), where a trailers frame leaves
/// `reading` (1.9.0: `KeepAlive`, before it `Closed`), h2 plumbing
/// and docs — none of which changes what a word means.
///
/// What the words mean, from `Conn` and the dispatch: `State::busy`
/// sets `KA::Busy` as a message head is read or written, and
/// `State::idle` — run by `try_keep_alive` once `reading` and
/// `writing` are both `KeepAlive` — clears `method` and sets
/// `KA::Idle`, so `Idle` is a connection between exchanges;
/// `Disabled` is set by a `Connection: close` or an HTTP/1.0 peer and
/// never cleared, and `close` puts both directions in `Closed`. The
/// client's `write_head` records the request's method in `method`
/// and moves `writing` to `Body(encoder)` when a body follows, else to
/// `KeepAlive` (or `Closed`); `reading` moves from `Init` to
/// `Body(decoder)` (or `Continue`) once the response head is parsed
/// and back through `KeepAlive` when the body ends. The client's
/// `Dispatch` keeps the response callback in `callback` from the
/// request's arrival on `rx` until the response head is delivered,
/// and its `poll_ready` registers the dispatcher's waker on that
/// callback's oneshot (`poll_canceled`) while `poll_msg` registers it
/// on `rx` (`poll_recv`) — the two primitives an idle and an in-flight
/// client connection are parked on beside the socket. `is_closing` is
/// set by the dispatcher's `close`, after which its poll only flushes.
/// `Connection::poll` and `UpgradeableConnection::poll` poll the
/// dispatcher inside them and act on its output alone. A server's
/// `State` keeps `h1_header_read_timeout: Option<Duration>` as its
/// builder set it, never changed; `poll_read_head` arms the header-read
/// timer for the monotonic clock's now plus that timeout whenever
/// `h1_header_read_timeout_running` is clear, sets the flag, and clears
/// it once a head is parsed — so while the flag is set, the timer's
/// deadline less the timeout is when the connection began waiting for
/// the head.
///
/// The ceiling is the newest release the cores on hand build; it
/// advances by hand when a newer one is read.
pub const HYPER_H1_CONN_V1_6_0: LibraryConvention = LibraryConvention {
    package: "hyper",
    family: "hyper-h1-conn-1.6.0",
    releases: Releases(&[
        ((1, 6, 0), (1, 6, 0)),
        ((1, 7, 0), (1, 7, 0)),
        ((1, 8, 0), (1, 8, 1)),
        ((1, 9, 0), (1, 9, 0)),
        ((1, 10, 0), (1, 10, 1)),
    ]),
    checksums: &[
        // src/proto/h1/conn.rs, 1.6.0
        (
            "src/proto/h1/conn.rs",
            [
                0x3d, 0x44, 0xbd, 0x56, 0xe0, 0x95, 0x0c, 0x99, 0xf5, 0x34, 0xc2, 0x50, 0xb5, 0x98,
                0xe5, 0xb1,
            ],
        ),
        // src/proto/h1/conn.rs, 1.7.0
        (
            "src/proto/h1/conn.rs",
            [
                0x08, 0xa2, 0xeb, 0x1c, 0xde, 0x95, 0x6f, 0x75, 0x9c, 0x1f, 0x31, 0xea, 0x7e, 0xa2,
                0xa5, 0x2a,
            ],
        ),
        // src/proto/h1/conn.rs, 1.8.0 and 1.8.1
        (
            "src/proto/h1/conn.rs",
            [
                0x02, 0xa6, 0x2f, 0xd9, 0x7b, 0x3d, 0x89, 0x6b, 0x6c, 0xe7, 0xa8, 0x93, 0xcc, 0x5e,
                0x8c, 0xa7,
            ],
        ),
        // src/proto/h1/conn.rs, 1.9.0
        (
            "src/proto/h1/conn.rs",
            [
                0xc2, 0x89, 0xdb, 0x9e, 0x7a, 0x0b, 0x9e, 0xaf, 0x1b, 0x94, 0xaa, 0x53, 0x50, 0x4e,
                0xbd, 0x16,
            ],
        ),
        // src/proto/h1/conn.rs, 1.10.0 and 1.10.1
        (
            "src/proto/h1/conn.rs",
            [
                0x22, 0x0a, 0xf9, 0x30, 0xeb, 0x47, 0xdc, 0x8f, 0x43, 0x56, 0xb8, 0x80, 0x26, 0xfb,
                0xe7, 0x7a,
            ],
        ),
        // src/proto/h1/dispatch.rs, 1.6.0
        (
            "src/proto/h1/dispatch.rs",
            [
                0xfc, 0xfd, 0xc6, 0x3f, 0xaf, 0x53, 0x8e, 0x7f, 0xc0, 0x7b, 0x74, 0xa5, 0x02, 0x7b,
                0x15, 0x58,
            ],
        ),
        // src/proto/h1/dispatch.rs, 1.7.0, 1.8.1 and 1.9.0
        (
            "src/proto/h1/dispatch.rs",
            [
                0x0c, 0x70, 0xa9, 0x91, 0x88, 0xae, 0xc6, 0xb1, 0x47, 0x8d, 0x44, 0x0a, 0x6b, 0x02,
                0xb7, 0xd0,
            ],
        ),
        // src/proto/h1/dispatch.rs, 1.8.0
        (
            "src/proto/h1/dispatch.rs",
            [
                0x1f, 0x1d, 0xb4, 0xb1, 0x59, 0x5d, 0x86, 0xe8, 0xbc, 0xc4, 0x22, 0xd4, 0x87, 0x05,
                0xbd, 0x76,
            ],
        ),
        // src/proto/h1/dispatch.rs, 1.10.0
        (
            "src/proto/h1/dispatch.rs",
            [
                0x21, 0x01, 0x38, 0x3b, 0x21, 0xc1, 0x16, 0xe8, 0x13, 0x5b, 0xf5, 0x7c, 0xa9, 0x67,
                0x29, 0xf3,
            ],
        ),
        // src/proto/h1/dispatch.rs, 1.10.1
        (
            "src/proto/h1/dispatch.rs",
            [
                0x57, 0x66, 0x29, 0x8d, 0x64, 0x24, 0x15, 0x7d, 0x53, 0xb3, 0x1c, 0x64, 0x97, 0x84,
                0xae, 0x41,
            ],
        ),
        // src/client/dispatch.rs, 1.6.0
        (
            "src/client/dispatch.rs",
            [
                0x0b, 0xc5, 0xe0, 0xc3, 0x36, 0x94, 0xe5, 0x26, 0x2c, 0xe2, 0x9a, 0xbd, 0xd4, 0x76,
                0xf3, 0xdc,
            ],
        ),
        // src/client/dispatch.rs, 1.7.0
        (
            "src/client/dispatch.rs",
            [
                0x39, 0xfd, 0x82, 0x23, 0x02, 0xa8, 0x1e, 0xc0, 0xd9, 0x2c, 0xe3, 0x03, 0x5d, 0x2f,
                0xd3, 0xce,
            ],
        ),
        // src/client/dispatch.rs, 1.8.0 and 1.8.1
        (
            "src/client/dispatch.rs",
            [
                0xa2, 0xdf, 0x19, 0x03, 0xef, 0xb0, 0x11, 0xd1, 0xe2, 0xff, 0x75, 0xd0, 0xa1, 0xdd,
                0x93, 0x8e,
            ],
        ),
        // src/client/dispatch.rs, 1.9.0
        (
            "src/client/dispatch.rs",
            [
                0xe5, 0x6b, 0xed, 0x79, 0xbf, 0x2c, 0xa0, 0x34, 0xd2, 0x0f, 0xf5, 0x73, 0x75, 0x90,
                0x72, 0xa9,
            ],
        ),
        // src/client/dispatch.rs, 1.10.0 and 1.10.1
        (
            "src/client/dispatch.rs",
            [
                0xfb, 0x37, 0x87, 0xcb, 0x63, 0x54, 0x6b, 0x1d, 0x63, 0xf2, 0x1d, 0xc5, 0xb7, 0x46,
                0x57, 0x32,
            ],
        ),
        // src/client/conn/http1.rs, 1.6.0
        (
            "src/client/conn/http1.rs",
            [
                0xcc, 0x38, 0x4a, 0xb5, 0xcf, 0xc5, 0x3c, 0xdd, 0x44, 0x94, 0xa4, 0xdc, 0x59, 0xaa,
                0x5a, 0x4f,
            ],
        ),
        // src/client/conn/http1.rs, 1.7.0 through 1.9.0
        (
            "src/client/conn/http1.rs",
            [
                0x24, 0xcb, 0x90, 0xdd, 0x18, 0x5f, 0x65, 0xe4, 0x62, 0x07, 0xb2, 0xdd, 0x89, 0x72,
                0x64, 0xa9,
            ],
        ),
        // src/client/conn/http1.rs, 1.10.0 and 1.10.1
        (
            "src/client/conn/http1.rs",
            [
                0x7f, 0x04, 0xed, 0x84, 0x3e, 0xd6, 0x12, 0x54, 0xfe, 0xc3, 0x7c, 0xf1, 0x73, 0x21,
                0xad, 0x27,
            ],
        ),
        // src/server/conn/http1.rs, 1.6.0
        (
            "src/server/conn/http1.rs",
            [
                0x11, 0xdf, 0x9f, 0x52, 0xaf, 0xa2, 0xe0, 0x05, 0xb8, 0x8d, 0x9a, 0x3d, 0xec, 0xf9,
                0xaf, 0xba,
            ],
        ),
        // src/server/conn/http1.rs, 1.7.0
        (
            "src/server/conn/http1.rs",
            [
                0xdf, 0xf8, 0x78, 0xf1, 0x5d, 0xbf, 0x41, 0xc1, 0xfb, 0xb6, 0x54, 0x82, 0x41, 0x48,
                0x84, 0x98,
            ],
        ),
        // src/server/conn/http1.rs, 1.8.0 and 1.8.1
        (
            "src/server/conn/http1.rs",
            [
                0x12, 0x73, 0x4d, 0xfb, 0x58, 0x77, 0xfd, 0xfa, 0x39, 0xc7, 0xa9, 0x57, 0x78, 0x8a,
                0xf7, 0xcf,
            ],
        ),
        // src/server/conn/http1.rs, 1.9.0
        (
            "src/server/conn/http1.rs",
            [
                0x20, 0xf3, 0xea, 0x38, 0xaa, 0x33, 0x29, 0x35, 0x4a, 0x2f, 0x53, 0xec, 0x50, 0xc6,
                0x50, 0xaf,
            ],
        ),
        // src/server/conn/http1.rs, 1.10.0 and 1.10.1
        (
            "src/server/conn/http1.rs",
            [
                0x56, 0xf0, 0x4a, 0xf8, 0xb7, 0x68, 0x81, 0x43, 0x05, 0x05, 0xd5, 0x6b, 0xa7, 0x77,
                0x5b, 0x75,
            ],
        ),
        // src/proto/h1/decode.rs, 1.6.0
        (
            "src/proto/h1/decode.rs",
            [
                0xf2, 0xc6, 0xdd, 0x9f, 0x51, 0xf2, 0x06, 0xd7, 0x1e, 0x45, 0xa3, 0x9a, 0xca, 0x58,
                0xba, 0x16,
            ],
        ),
        // src/proto/h1/decode.rs, 1.7.0 through 1.8.1
        (
            "src/proto/h1/decode.rs",
            [
                0x35, 0xcc, 0x59, 0xc2, 0x72, 0x8a, 0x59, 0x80, 0x55, 0x5e, 0xf7, 0x95, 0x4a, 0x85,
                0x75, 0xaa,
            ],
        ),
        // src/proto/h1/decode.rs, 1.9.0
        (
            "src/proto/h1/decode.rs",
            [
                0x38, 0xe1, 0xbb, 0xc3, 0x1b, 0xb1, 0x91, 0x7b, 0x04, 0xc2, 0x2e, 0x25, 0x05, 0x42,
                0x4d, 0x55,
            ],
        ),
        // src/proto/h1/decode.rs, 1.10.0 and 1.10.1
        (
            "src/proto/h1/decode.rs",
            [
                0x16, 0x86, 0xd1, 0xa7, 0xa7, 0x01, 0x81, 0x6e, 0xe0, 0x3d, 0x9c, 0xb2, 0xda, 0x31,
                0x89, 0xbe,
            ],
        ),
        // src/proto/h1/encode.rs, 1.6.0 through 1.8.1
        (
            "src/proto/h1/encode.rs",
            [
                0x04, 0xf6, 0xcc, 0x0d, 0x8f, 0x35, 0xfb, 0xd5, 0x1a, 0xe1, 0xe6, 0x4d, 0x96, 0x37,
                0x9f, 0xc1,
            ],
        ),
        // src/proto/h1/encode.rs, 1.9.0 through 1.10.1
        (
            "src/proto/h1/encode.rs",
            [
                0xa1, 0x03, 0xfa, 0x60, 0x2b, 0xf7, 0x71, 0xcd, 0x33, 0x61, 0x9b, 0x88, 0x0f, 0x5e,
                0x15, 0x9d,
            ],
        ),
    ],
};

/// The tokio releases every tokio review was read at — `select!`,
/// `Interval::tick`, the state protocols, the acquire owners and the
/// layout families: each minor from `.0` through the patch the version
/// matrix (`test-programs/matrix.toml`) pins it at. tokio backports
/// fixes into older minors, so each minor is its own span, and a patch
/// released into one after its review falls outside until a span is
/// raised to it. That happens by hand when the patch is onboarded,
/// after every file the reviews name has been read at it and its
/// checksum listed; the matrix suite holds each span's newest patch to
/// the matrix's pin and each listed checksum to the sources the matrix
/// builds.
///
/// A minor splits where a layout family changes inside it: 1.52.0's
/// sharded `spawn_blocking` queue, which 1.52.1 reverted, is a family
/// of its own, so 1.52.0 is a span apart, pinned by the matrix beside
/// 1.52.4.
pub const TOKIO_RELEASES: Releases = Releases(&[
    ((1, 47, 0), (1, 47, 5)),
    ((1, 48, 0), (1, 48, 0)),
    ((1, 49, 0), (1, 49, 0)),
    ((1, 50, 0), (1, 50, 0)),
    ((1, 51, 0), (1, 51, 5)),
    ((1, 52, 0), (1, 52, 0)),
    ((1, 52, 1), (1, 52, 4)),
    ((1, 53, 0), (1, 53, 1)),
]);

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
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/macros/select.rs, 1.47.0 through 1.47.5
        (
            "src/macros/select.rs",
            [
                0x28, 0x0b, 0xf9, 0x6d, 0xd4, 0xe7, 0x0d, 0xd5, 0x88, 0xdb, 0x17, 0xda, 0x06, 0x6e,
                0xfc, 0xf0,
            ],
        ),
        // src/macros/select.rs, 1.48.0 and 1.49.0
        (
            "src/macros/select.rs",
            [
                0x37, 0x45, 0xb7, 0x7f, 0xb6, 0xf0, 0x12, 0x2c, 0x6c, 0xb2, 0x8b, 0xca, 0x26, 0x12,
                0x59, 0x6f,
            ],
        ),
        // src/macros/select.rs, 1.50.0
        (
            "src/macros/select.rs",
            [
                0xc4, 0x36, 0x6c, 0xb2, 0xaf, 0x3e, 0xfa, 0xa2, 0xd9, 0x28, 0xbb, 0x8d, 0x92, 0xc8,
                0x75, 0x5f,
            ],
        ),
        // src/macros/select.rs, 1.51.0 through 1.52.4
        (
            "src/macros/select.rs",
            [
                0x7d, 0xa7, 0x40, 0x76, 0xc7, 0x0a, 0xb9, 0x7d, 0x76, 0xe5, 0x98, 0xa8, 0xd2, 0xd5,
                0x78, 0x50,
            ],
        ),
        // src/macros/select.rs, 1.53.0 and 1.53.1
        (
            "src/macros/select.rs",
            [
                0xc9, 0xe7, 0xff, 0xf5, 0xf8, 0x88, 0x9e, 0x2c, 0x55, 0x88, 0x62, 0x1c, 0x4c, 0x01,
                0x8f, 0x5a,
            ],
        ),
    ],
};

/// tokio's `Interval::tick` as 1.47 through 1.53 implement it
/// (`src/time/interval.rs`; 1.48 rewrote the module's docs, 1.53
/// renamed the `reset_without_reregister` the `Ready` path calls):
/// `tick` is `poll_fn(|cx| self.poll_tick(cx)).await`, and `poll_tick`
/// is `ready!(Pin::new(&mut self.delay).poll(cx))` before anything
/// else — the next deadline is computed and the delay reset only once
/// that `Sleep` is ready. So while the tick is pending, its `PollFn`
/// polls the `Pin<Box<Sleep>>` in the interval's `delay` and nothing
/// else. The struct is `{ delay, period, missed_tick_behavior }` in
/// every release (plus a `resource_span` under `tokio_unstable` with
/// `tracing`), and the route names its members, not their offsets.
///
/// Like the `select!` closure, the closure environment is declared
/// under `tick`'s own body, so the rule is read off that declaration
/// file's registry path, not the layout family.
pub const TOKIO_INTERVAL_TICK_V1_47: LibraryConvention = LibraryConvention {
    package: "tokio",
    family: "tokio-interval-tick-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/time/interval.rs, 1.47.0 through 1.47.5
        (
            "src/time/interval.rs",
            [
                0x47, 0x12, 0xca, 0x6c, 0xc1, 0xfa, 0xcb, 0xa8, 0x79, 0xa0, 0xf7, 0xd6, 0x63, 0x2f,
                0x15, 0x2d,
            ],
        ),
        // src/time/interval.rs, 1.48.0 through 1.52.4
        (
            "src/time/interval.rs",
            [
                0x8d, 0x47, 0xd1, 0x81, 0x44, 0x5f, 0x86, 0x17, 0x89, 0x68, 0x85, 0x86, 0xc4, 0x87,
                0xf7, 0xfa,
            ],
        ),
        // src/time/interval.rs, 1.53.0 and 1.53.1
        (
            "src/time/interval.rs",
            [
                0x64, 0xe7, 0xd7, 0x63, 0xe7, 0x46, 0xf5, 0x65, 0x7f, 0x44, 0xf3, 0xba, 0x62, 0xf6,
                0xb5, 0xaa,
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
    releases: Releases(&[((0, 1, 14), (0, 1, 19))]),
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
    releases: Releases(&[((0, 7, 11), (0, 7, 19))]),
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
    releases: Releases(&[((0, 1, 14), (0, 1, 19))]),
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

/// tokio-rustls's streams as 0.26.0 through 0.26.6 implement them. The
/// `TlsStream<T>` enum (`src/lib.rs`) is `Client(client::TlsStream<T>)
/// | Server(server::TlsStream<T>)`, and every `AsyncRead`/`AsyncWrite`
/// method matches on the variant and calls the same method on its
/// payload and nothing else. The client and server streams
/// (`src/client.rs`, `src/server.rs`) hold the socket as `io` beside
/// the rustls session and a `TlsState` in every release (`need_flush`
/// joins them at 0.26.3, `error` at 0.26.6, neither read); their
/// `poll_read` (`poll_fill_buf` from 0.26.2) returns `Pending` only
/// after reading `io` did, and otherwise wakes the task itself, and a
/// write or flush likewise parks only in a write to `io`. The one
/// exception is the client's `early-data` feature: a read in the
/// early-data state parks in the stream's own `early_waker`, which no
/// reader following the route to the socket finds holding the task, so
/// such a wait verifies nothing rather than the wrong thing. The file
/// checksums move with docs, visibility and those two members; the
/// forwarding is the same text throughout. Each type's origin is its
/// own method declarations, which name its file.
pub const TOKIO_RUSTLS_STREAM_V0_26_0: LibraryConvention = LibraryConvention {
    package: "tokio-rustls",
    family: "tokio-rustls-stream-0.26.0",
    releases: Releases(&[((0, 26, 0), (0, 26, 6))]),
    checksums: &[
        // src/lib.rs, 0.26.0
        (
            "src/lib.rs",
            [
                0x28, 0x4f, 0xe9, 0x23, 0x8e, 0x09, 0x49, 0xaa, 0x78, 0xd2, 0xbc, 0x89, 0x23, 0x1a,
                0xad, 0x8a,
            ],
        ),
        // src/lib.rs, 0.26.1
        (
            "src/lib.rs",
            [
                0x5f, 0x3e, 0xef, 0x4c, 0x6e, 0x0f, 0x4a, 0xdb, 0xd5, 0x8e, 0xed, 0x3a, 0x09, 0xb2,
                0x52, 0x88,
            ],
        ),
        // src/lib.rs, 0.26.2
        (
            "src/lib.rs",
            [
                0x2d, 0xc3, 0x9f, 0x59, 0x36, 0x0f, 0x95, 0x73, 0x3f, 0x06, 0xcc, 0xce, 0xa7, 0xe5,
                0xcd, 0xd3,
            ],
        ),
        // src/lib.rs, 0.26.3 and 0.26.4
        (
            "src/lib.rs",
            [
                0x3b, 0x15, 0x4a, 0xa2, 0xc2, 0x57, 0x2e, 0x4e, 0x67, 0x95, 0x4b, 0x86, 0x55, 0x0c,
                0x45, 0xbb,
            ],
        ),
        // src/lib.rs, 0.26.5 and 0.26.6
        (
            "src/lib.rs",
            [
                0xac, 0x67, 0x80, 0x72, 0xfd, 0x54, 0x5b, 0x73, 0x65, 0xb8, 0xc2, 0x22, 0x07, 0x4f,
                0x60, 0x09,
            ],
        ),
        // src/client.rs, 0.26.0 and 0.26.1
        (
            "src/client.rs",
            [
                0xf5, 0xe1, 0xfe, 0x9c, 0x42, 0xe3, 0x98, 0x3e, 0xa4, 0x9a, 0x9c, 0x3a, 0x57, 0x1a,
                0x01, 0xcc,
            ],
        ),
        // src/client.rs, 0.26.2
        (
            "src/client.rs",
            [
                0x52, 0xbc, 0x7a, 0x1c, 0x88, 0x1d, 0x85, 0x85, 0xdf, 0x13, 0x1c, 0x77, 0x4e, 0x80,
                0x09, 0xd5,
            ],
        ),
        // src/client.rs, 0.26.3 and 0.26.4
        (
            "src/client.rs",
            [
                0x3e, 0x02, 0x87, 0xc9, 0x9f, 0xfc, 0x6e, 0x87, 0x95, 0xb5, 0x02, 0xea, 0xca, 0x12,
                0x9d, 0xfa,
            ],
        ),
        // src/client.rs, 0.26.5
        (
            "src/client.rs",
            [
                0xa0, 0xd6, 0xb0, 0x9f, 0x53, 0xe0, 0x3a, 0x0a, 0xb9, 0x52, 0xe4, 0x9a, 0x84, 0xa6,
                0x66, 0x9d,
            ],
        ),
        // src/client.rs, 0.26.6
        (
            "src/client.rs",
            [
                0x8c, 0x55, 0x3b, 0x19, 0x44, 0xb7, 0x03, 0x55, 0x7b, 0x87, 0x93, 0xed, 0x72, 0xf6,
                0xc8, 0xcc,
            ],
        ),
        // src/server.rs, 0.26.0 and 0.26.1
        (
            "src/server.rs",
            [
                0x97, 0x30, 0xa2, 0xe6, 0xae, 0x46, 0x55, 0x69, 0x92, 0xe8, 0xb6, 0x91, 0xc1, 0xcc,
                0x36, 0x42,
            ],
        ),
        // src/server.rs, 0.26.2
        (
            "src/server.rs",
            [
                0xe6, 0x40, 0x28, 0xc6, 0x7e, 0xf7, 0x6a, 0x00, 0x83, 0x14, 0xd6, 0x4a, 0x48, 0xc0,
                0xf3, 0xe6,
            ],
        ),
        // src/server.rs, 0.26.3 and 0.26.4
        (
            "src/server.rs",
            [
                0x02, 0xd5, 0x42, 0xdf, 0x55, 0x04, 0xf0, 0xe5, 0x84, 0x77, 0xf4, 0xea, 0x0b, 0x48,
                0x29, 0x24,
            ],
        ),
        // src/server.rs, 0.26.5
        (
            "src/server.rs",
            [
                0x82, 0xcd, 0xcf, 0x02, 0x15, 0x0f, 0x7d, 0x20, 0x2b, 0x2e, 0xa5, 0x23, 0x36, 0x44,
                0x59, 0x59,
            ],
        ),
        // src/server.rs, 0.26.6
        (
            "src/server.rs",
            [
                0x19, 0x48, 0x5c, 0x7c, 0x27, 0x10, 0xe1, 0xfd, 0xdd, 0x20, 0x85, 0x47, 0xad, 0xa7,
                0x15, 0x63,
            ],
        ),
    ],
};

/// rustls's connection state as 0.23.23 through 0.23.45 lay it out,
/// read in every release of that range (`src/conn.rs`,
/// `src/common_state.rs`, `src/record_layer.rs`; 0.23.28 retypes
/// `CommonState`'s `alpn_protocol` and adds `tls13_tickets_received`,
/// neither on a route): `ConnectionCommon<Data>` holds
/// `core: ConnectionCore<Data>`, whose `state` is a `Result<Box<dyn
/// State<Data>>, Error>` that turns `Err` when the connection fails and
/// stays so, and whose `common_state: CommonState` holds `side`, the
/// `negotiated_version: Option<ProtocolVersion>`, the
/// `may_send_application_data` and `may_receive_application_data` flags
/// the handshake sets on finishing (`start_outgoing_traffic`,
/// `start_traffic`; `is_handshaking` is their conjunction negated),
/// `has_sent_close_notify` (added at 0.23.23, the floor),
/// `has_received_close_notify`, `has_seen_eof`, `sent_fatal_alert`, and
/// `record_layer: RecordLayer` with its `read_seq` and `write_seq`
/// counts. Every assignment of those flags is the same text across the
/// range, so the words mean the same thing in each release — including
/// `send_close_notify` setting `sent_fatal_alert` beside
/// `has_sent_close_notify`, the flag meaning that no further alert will
/// be sent, while a fatal alert (`send_fatal_alert`) always comes with
/// the error the state then holds. The
/// release is read off the type's own method declarations, as
/// hashbrown's is; the checksums are of every reviewed revision, which
/// rustc's DWARF 4 never records but the matrix suite checks.
pub const RUSTLS_SESSION_V0_23_23: LibraryConvention = LibraryConvention {
    package: "rustls",
    family: "rustls-session-0.23.23",
    releases: Releases(&[((0, 23, 23), (0, 23, 45))]),
    checksums: &[
        // src/conn.rs, 0.23.23
        (
            "src/conn.rs",
            [
                0x4b, 0xe9, 0xec, 0xc7, 0xda, 0xdc, 0x70, 0x0f, 0x3b, 0xbb, 0xbf, 0x90, 0xd0, 0xea,
                0x4f, 0x5f,
            ],
        ),
        // src/conn.rs, 0.23.24 through 0.23.26
        (
            "src/conn.rs",
            [
                0x15, 0x67, 0x4c, 0x26, 0xef, 0xce, 0xc4, 0xbb, 0xef, 0x99, 0xc4, 0x62, 0x63, 0x11,
                0x24, 0x1f,
            ],
        ),
        // src/conn.rs, 0.23.27
        (
            "src/conn.rs",
            [
                0x84, 0xb9, 0x87, 0x76, 0x46, 0xc0, 0x17, 0x92, 0x6e, 0x43, 0x12, 0x3c, 0xf4, 0x6a,
                0x11, 0xaf,
            ],
        ),
        // src/conn.rs, 0.23.28 and 0.23.29
        (
            "src/conn.rs",
            [
                0x94, 0xc2, 0xea, 0x9f, 0x80, 0x6b, 0xbf, 0x52, 0x0c, 0x70, 0x90, 0xa4, 0x21, 0xf3,
                0x1b, 0x6b,
            ],
        ),
        // src/conn.rs, 0.23.30
        (
            "src/conn.rs",
            [
                0xac, 0x5d, 0xec, 0x93, 0x7b, 0xd6, 0xb2, 0x71, 0x9f, 0x42, 0x91, 0x8c, 0xfa, 0x11,
                0x37, 0x8e,
            ],
        ),
        // src/conn.rs, 0.23.31 through 0.23.40
        (
            "src/conn.rs",
            [
                0x33, 0xbc, 0xb4, 0x3f, 0xae, 0x3d, 0x2c, 0xca, 0xee, 0x70, 0xda, 0xf6, 0xc5, 0xac,
                0x82, 0xb3,
            ],
        ),
        // src/conn.rs, 0.23.41 through 0.23.44
        (
            "src/conn.rs",
            [
                0x8f, 0xa3, 0x7e, 0xb2, 0x55, 0xc2, 0x79, 0xd2, 0x65, 0xeb, 0xf4, 0x55, 0x33, 0x08,
                0xf2, 0xa6,
            ],
        ),
        // src/conn.rs, 0.23.45
        (
            "src/conn.rs",
            [
                0x1e, 0x63, 0xf0, 0xda, 0x2b, 0x28, 0x4d, 0xbb, 0x5f, 0x01, 0x54, 0x0f, 0x44, 0xc8,
                0x46, 0x30,
            ],
        ),
        // src/common_state.rs, 0.23.23
        (
            "src/common_state.rs",
            [
                0x5a, 0x72, 0x91, 0xec, 0x53, 0x89, 0x47, 0x80, 0xc2, 0xf3, 0x62, 0x24, 0x52, 0x25,
                0x21, 0xf5,
            ],
        ),
        // src/common_state.rs, 0.23.24 through 0.23.26
        (
            "src/common_state.rs",
            [
                0xb9, 0xdc, 0xf7, 0x7f, 0x89, 0xdf, 0x2d, 0xc0, 0x50, 0x0d, 0x7f, 0x02, 0x90, 0x20,
                0x8e, 0x49,
            ],
        ),
        // src/common_state.rs, 0.23.27
        (
            "src/common_state.rs",
            [
                0xff, 0x03, 0x3f, 0x97, 0xb7, 0xca, 0x5f, 0x8c, 0xea, 0x86, 0xb5, 0x12, 0x5d, 0xcc,
                0x9e, 0xd8,
            ],
        ),
        // src/common_state.rs, 0.23.28 through 0.23.32
        (
            "src/common_state.rs",
            [
                0xa6, 0xab, 0xcc, 0x1e, 0xdc, 0x14, 0x48, 0x4c, 0x17, 0x3f, 0x7e, 0x8d, 0x45, 0x4a,
                0x03, 0x38,
            ],
        ),
        // src/common_state.rs, 0.23.33 through 0.23.42
        (
            "src/common_state.rs",
            [
                0x29, 0xf2, 0x08, 0xb6, 0xde, 0xf3, 0x56, 0x8a, 0xcd, 0x8d, 0x58, 0x90, 0x97, 0xa9,
                0xfa, 0x54,
            ],
        ),
        // src/common_state.rs, 0.23.43 through 0.23.45
        (
            "src/common_state.rs",
            [
                0x86, 0xdf, 0x07, 0x52, 0x5f, 0x81, 0x1f, 0x24, 0x6f, 0xcc, 0x0c, 0xa9, 0xcb, 0x5e,
                0x74, 0x7c,
            ],
        ),
        // src/record_layer.rs, 0.23.23 through 0.23.45
        (
            "src/record_layer.rs",
            [
                0x7b, 0x19, 0xf9, 0xd4, 0x00, 0x63, 0xfa, 0xe6, 0x52, 0x0b, 0xe7, 0xfe, 0x5e, 0xca,
                0x80, 0xfa,
            ],
        ),
    ],
};

/// reqwest's connection types as 0.12.14 through 0.13.5 implement them,
/// each the same text in every release (`src/connect.rs`, whose
/// checksum moves with everything else in it). `Conn` (in `sealed`) is
/// `{ inner: BoxConn, is_proxy, tls_info }`, `BoxConn` being
/// `Box<dyn AsyncConnWithInfo>`, and its `Read`/`Write` methods call
/// the same method on `inner` and nothing else. `AsyncConnWithInfo:
/// AsyncConn + TlsInfoFactory` and `AsyncConn: Read + Write +
/// Connection + Send + Sync + Unpin`, so the trait object's vtable
/// holds, past rustc's three header words, `hyper::rt::Read::poll_read`
/// first — the leftmost supertrait chain's methods lead — then
/// `Write`'s five: slot 3 is the read method, which names the concrete
/// stream. The boxes `Conn` holds are built by `Wrapper::wrap`, around
/// the connector's stream or its TLS wrapper, and — with trace logging
/// on — inside `Verbose<T> { id, inner }`, whose reads and writes are
/// `inner`'s, logged after. `RustlsTlsConn<T>` is `{ inner:
/// TokioIo<TlsStream<T>> }` and forwards every method to `inner`.
pub const REQWEST_CONN_V0_12_14: LibraryConvention = LibraryConvention {
    package: "reqwest",
    family: "reqwest-conn-0.12.14",
    releases: Releases(&[((0, 12, 14), (0, 12, 28)), ((0, 13, 0), (0, 13, 5))]),
    checksums: &[
        // src/connect.rs, 0.12.14 and 0.12.15
        (
            "src/connect.rs",
            [
                0xb6, 0xba, 0xdf, 0xfc, 0x6c, 0x57, 0xd9, 0x96, 0xf4, 0x00, 0x61, 0x68, 0xc3, 0x11,
                0xba, 0xb9,
            ],
        ),
        // src/connect.rs, 0.12.16 and 0.12.17
        (
            "src/connect.rs",
            [
                0xec, 0xa7, 0x8b, 0x95, 0x52, 0xff, 0x9a, 0x65, 0x83, 0xc9, 0xb3, 0xc0, 0x90, 0x4c,
                0x8a, 0xc1,
            ],
        ),
        // src/connect.rs, 0.12.18
        (
            "src/connect.rs",
            [
                0x09, 0xbb, 0x47, 0x0e, 0xbf, 0x38, 0x0e, 0xa5, 0x8d, 0xc4, 0xdf, 0x58, 0x0e, 0xea,
                0xef, 0x01,
            ],
        ),
        // src/connect.rs, 0.12.19
        (
            "src/connect.rs",
            [
                0xb6, 0x2c, 0x1d, 0xc1, 0x52, 0xc6, 0x3b, 0x82, 0xad, 0xcb, 0x06, 0x0c, 0x40, 0x52,
                0x1e, 0x27,
            ],
        ),
        // src/connect.rs, 0.12.20
        (
            "src/connect.rs",
            [
                0x16, 0x9d, 0xd8, 0x2d, 0x6e, 0x0c, 0x9c, 0x0d, 0xe5, 0x10, 0x6e, 0xd8, 0xb3, 0x31,
                0x07, 0x40,
            ],
        ),
        // src/connect.rs, 0.12.21
        (
            "src/connect.rs",
            [
                0x0e, 0xd0, 0xec, 0xe6, 0xaa, 0xde, 0xad, 0x82, 0x62, 0xc6, 0x99, 0x42, 0x9a, 0x7a,
                0xf3, 0xf1,
            ],
        ),
        // src/connect.rs, 0.12.22
        (
            "src/connect.rs",
            [
                0x9c, 0x49, 0xc8, 0xca, 0xa1, 0xbe, 0x8e, 0x8e, 0x50, 0x62, 0xac, 0xb4, 0x4b, 0x97,
                0xdf, 0xc1,
            ],
        ),
        // src/connect.rs, 0.12.23 through 0.12.26
        (
            "src/connect.rs",
            [
                0xc3, 0x38, 0x45, 0x3f, 0x51, 0xcb, 0x3a, 0x60, 0xba, 0x7b, 0x24, 0xca, 0xe2, 0xc4,
                0xfe, 0xa8,
            ],
        ),
        // src/connect.rs, 0.12.27
        (
            "src/connect.rs",
            [
                0xa2, 0xe8, 0xaf, 0x71, 0xa0, 0xc7, 0x59, 0x5a, 0x50, 0x4e, 0xa8, 0xfd, 0xe3, 0x89,
                0x26, 0xee,
            ],
        ),
        // src/connect.rs, 0.12.28
        (
            "src/connect.rs",
            [
                0x98, 0x8a, 0x74, 0x5f, 0x5a, 0xaf, 0x42, 0xd8, 0xc5, 0xd9, 0x6e, 0x43, 0xc9, 0x79,
                0x73, 0x31,
            ],
        ),
        // src/connect.rs, 0.13.0 through 0.13.2
        (
            "src/connect.rs",
            [
                0x2d, 0xf8, 0x1c, 0x42, 0xe5, 0xa8, 0xef, 0x7d, 0xbc, 0x48, 0xbc, 0x28, 0x13, 0xf8,
                0x56, 0xb8,
            ],
        ),
        // src/connect.rs, 0.13.3 and 0.13.4
        (
            "src/connect.rs",
            [
                0x9a, 0x6b, 0x40, 0xec, 0xfc, 0xe0, 0x9f, 0x7a, 0x91, 0xb4, 0x49, 0x90, 0x9c, 0x19,
                0x46, 0x84,
            ],
        ),
        // src/connect.rs, 0.13.5
        (
            "src/connect.rs",
            [
                0x8b, 0xea, 0x63, 0xcc, 0xaf, 0x0d, 0x36, 0x48, 0x9e, 0x44, 0x1e, 0x12, 0xa1, 0x90,
                0x85, 0x7b,
            ],
        ),
    ],
};

/// The slot `hyper::rt::Read::poll_read` holds in reqwest's
/// `dyn AsyncConnWithInfo` vtable, under [`REQWEST_CONN_V0_12_14`].
pub const REQWEST_CONN_READ_SLOT: u32 = 3;

/// hyper-rustls's `MaybeHttpsStream<T>` as 0.27.0 through 0.27.10
/// implement it (`src/stream.rs`): the enum `Http(T) | Https(TokioIo<
/// TlsStream<TokioIo<T>>>)`, the same in every release, whose every
/// `Read`/`Write` method matches on the variant and calls the same
/// method on its payload and nothing else. The releases differ in the
/// vectored write's forwards (added at 0.27.4) and in lifetime
/// annotations (0.27.10).
pub const HYPER_RUSTLS_STREAM_V0_27_0: LibraryConvention = LibraryConvention {
    package: "hyper-rustls",
    family: "hyper-rustls-stream-0.27.0",
    releases: Releases(&[((0, 27, 0), (0, 27, 10))]),
    checksums: &[
        // src/stream.rs, 0.27.0 through 0.27.3
        (
            "src/stream.rs",
            [
                0x74, 0x34, 0x2a, 0x9f, 0x99, 0x71, 0xca, 0xc0, 0x73, 0xeb, 0x56, 0x06, 0xd8, 0xb1,
                0x0c, 0x15,
            ],
        ),
        // src/stream.rs, 0.27.4 through 0.27.9
        (
            "src/stream.rs",
            [
                0xfc, 0xe1, 0x93, 0x69, 0xbb, 0xf7, 0x4b, 0xe4, 0xa5, 0x82, 0xdd, 0x71, 0xcd, 0x47,
                0xe3, 0xa2,
            ],
        ),
        // src/stream.rs, 0.27.10
        (
            "src/stream.rs",
            [
                0xbd, 0x84, 0x3b, 0x84, 0xe2, 0x61, 0x58, 0x3a, 0xd6, 0x4a, 0x0c, 0xef, 0xe7, 0xaf,
                0x64, 0x64,
            ],
        ),
    ],
};

/// tokio-rustls's handshake as 0.26.0 through 0.26.6 implement it.
/// `MidHandshake<IS>` (`src/common/handshake.rs`) is the enum
/// `Handshaking(IS) | End | SendAlert { io, alert, error } | Error { io,
/// error }`, the same in every release, and its `poll` in `Handshaking`
/// drives rustls's handshake over the stream it holds (`Stream::handshake`
/// in `src/common/mod.rs`), which returns `Pending` only when writing,
/// flushing or reading the stream would block and nothing moved that
/// round — so the task's waker is in the socket's writer slot, its
/// reader slot, or both, and nowhere else. In `SendAlert` it writes the
/// alert to the bare `io`; `Error` returns at once, and `End` is never
/// polled. The releases differ in a zero-length write's error (0.26.1)
/// and in carrying the flush flag across polls (0.26.3), neither of
/// which moves a wait. `Connect`, `Accept`, `FallibleConnect` and
/// `FallibleAccept` (`src/lib.rs` through 0.26.2, `src/client.rs` and
/// `src/server.rs` from 0.26.3) are newtypes over it whose `poll` polls
/// it and nothing else. Each type's origin is its own `poll`.
pub const TOKIO_RUSTLS_HANDSHAKE_V0_26_0: LibraryConvention = LibraryConvention {
    package: "tokio-rustls",
    family: "tokio-rustls-handshake-0.26.0",
    releases: Releases(&[((0, 26, 0), (0, 26, 6))]),
    checksums: &[
        // src/common/handshake.rs, 0.26.0 through 0.26.2
        (
            "src/common/handshake.rs",
            [
                0xc6, 0xd3, 0x73, 0xfd, 0xd6, 0x46, 0x97, 0xcd, 0x12, 0x54, 0x5f, 0xe6, 0x2a, 0xf3,
                0xee, 0x67,
            ],
        ),
        // src/common/handshake.rs, 0.26.3 through 0.26.6
        (
            "src/common/handshake.rs",
            [
                0xea, 0x26, 0x32, 0x7f, 0xd2, 0xcb, 0x60, 0x73, 0x88, 0xf1, 0x74, 0x15, 0x23, 0xf5,
                0x26, 0xb9,
            ],
        ),
        // src/lib.rs, 0.26.0
        (
            "src/lib.rs",
            [
                0x28, 0x4f, 0xe9, 0x23, 0x8e, 0x09, 0x49, 0xaa, 0x78, 0xd2, 0xbc, 0x89, 0x23, 0x1a,
                0xad, 0x8a,
            ],
        ),
        // src/lib.rs, 0.26.1
        (
            "src/lib.rs",
            [
                0x5f, 0x3e, 0xef, 0x4c, 0x6e, 0x0f, 0x4a, 0xdb, 0xd5, 0x8e, 0xed, 0x3a, 0x09, 0xb2,
                0x52, 0x88,
            ],
        ),
        // src/lib.rs, 0.26.2
        (
            "src/lib.rs",
            [
                0x2d, 0xc3, 0x9f, 0x59, 0x36, 0x0f, 0x95, 0x73, 0x3f, 0x06, 0xcc, 0xce, 0xa7, 0xe5,
                0xcd, 0xd3,
            ],
        ),
        // src/lib.rs, 0.26.3 and 0.26.4
        (
            "src/lib.rs",
            [
                0x3b, 0x15, 0x4a, 0xa2, 0xc2, 0x57, 0x2e, 0x4e, 0x67, 0x95, 0x4b, 0x86, 0x55, 0x0c,
                0x45, 0xbb,
            ],
        ),
        // src/lib.rs, 0.26.5 and 0.26.6
        (
            "src/lib.rs",
            [
                0xac, 0x67, 0x80, 0x72, 0xfd, 0x54, 0x5b, 0x73, 0x65, 0xb8, 0xc2, 0x22, 0x07, 0x4f,
                0x60, 0x09,
            ],
        ),
        // src/client.rs, 0.26.0 and 0.26.1
        (
            "src/client.rs",
            [
                0xf5, 0xe1, 0xfe, 0x9c, 0x42, 0xe3, 0x98, 0x3e, 0xa4, 0x9a, 0x9c, 0x3a, 0x57, 0x1a,
                0x01, 0xcc,
            ],
        ),
        // src/client.rs, 0.26.2
        (
            "src/client.rs",
            [
                0x52, 0xbc, 0x7a, 0x1c, 0x88, 0x1d, 0x85, 0x85, 0xdf, 0x13, 0x1c, 0x77, 0x4e, 0x80,
                0x09, 0xd5,
            ],
        ),
        // src/client.rs, 0.26.3 and 0.26.4
        (
            "src/client.rs",
            [
                0x3e, 0x02, 0x87, 0xc9, 0x9f, 0xfc, 0x6e, 0x87, 0x95, 0xb5, 0x02, 0xea, 0xca, 0x12,
                0x9d, 0xfa,
            ],
        ),
        // src/client.rs, 0.26.5
        (
            "src/client.rs",
            [
                0xa0, 0xd6, 0xb0, 0x9f, 0x53, 0xe0, 0x3a, 0x0a, 0xb9, 0x52, 0xe4, 0x9a, 0x84, 0xa6,
                0x66, 0x9d,
            ],
        ),
        // src/client.rs, 0.26.6
        (
            "src/client.rs",
            [
                0x8c, 0x55, 0x3b, 0x19, 0x44, 0xb7, 0x03, 0x55, 0x7b, 0x87, 0x93, 0xed, 0x72, 0xf6,
                0xc8, 0xcc,
            ],
        ),
        // src/server.rs, 0.26.0 and 0.26.1
        (
            "src/server.rs",
            [
                0x97, 0x30, 0xa2, 0xe6, 0xae, 0x46, 0x55, 0x69, 0x92, 0xe8, 0xb6, 0x91, 0xc1, 0xcc,
                0x36, 0x42,
            ],
        ),
        // src/server.rs, 0.26.2
        (
            "src/server.rs",
            [
                0xe6, 0x40, 0x28, 0xc6, 0x7e, 0xf7, 0x6a, 0x00, 0x83, 0x14, 0xd6, 0x4a, 0x48, 0xc0,
                0xf3, 0xe6,
            ],
        ),
        // src/server.rs, 0.26.3 and 0.26.4
        (
            "src/server.rs",
            [
                0x02, 0xd5, 0x42, 0xdf, 0x55, 0x04, 0xf0, 0xe5, 0x84, 0x77, 0xf4, 0xea, 0x0b, 0x48,
                0x29, 0x24,
            ],
        ),
        // src/server.rs, 0.26.5
        (
            "src/server.rs",
            [
                0x82, 0xcd, 0xcf, 0x02, 0x15, 0x0f, 0x7d, 0x20, 0x2b, 0x2e, 0xa5, 0x23, 0x36, 0x44,
                0x59, 0x59,
            ],
        ),
        // src/server.rs, 0.26.6
        (
            "src/server.rs",
            [
                0x19, 0x48, 0x5c, 0x7c, 0x27, 0x10, 0xe1, 0xfd, 0xdd, 0x20, 0x85, 0x47, 0xad, 0xa7,
                0x15, 0x63,
            ],
        ),
    ],
};

/// One reviewed third-party implementation fetched from git, which has
/// no release to select a range by: the crate, the repository cargo
/// names its checkout after, the crate's directory inside it, the
/// family the bundle's origin records, the implementing file every
/// declaration has to lie in, and every reviewed revision — whole,
/// since cargo's checkout directory names an abbreviation of it — with
/// that file's checksum there. A revision not in the list is
/// unreviewed, however little it changed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct GitConvention {
    pub package: &'static str,
    pub repository: &'static str,
    /// The implementing file, by its path in the repository.
    pub file: &'static str,
    pub family: &'static str,
    /// `(revision, md5)` for every reviewed revision.
    pub revisions: &'static [(&'static str, [u8; 16])],
}

impl GitConvention {
    /// The reviewed revision a checkout's abbreviation names: the one
    /// reviewed revision it is a prefix of, or `None` for an
    /// unreviewed revision or one too short to tell two reviewed
    /// revisions apart.
    pub fn reviewed_revision(
        &self,
        abbreviated: &str,
    ) -> Option<&'static (&'static str, [u8; 16])> {
        let mut named = self
            .revisions
            .iter()
            .filter(|(revision, _)| revision.starts_with(abbreviated));
        let one = named.next()?;
        named.next().is_none().then_some(one)
    }
}

/// sprockets-tls's `Stream<T>` (`tls/src/lib.rs` in oxidecomputer's
/// sprockets repository) at the four revisions omicron has pinned —
/// byte-identical in the struct and both impls: the struct is `{ inner:
/// TlsStream<T>, platform_id, corpus_appraisal_success }`, `TlsStream`
/// being tokio-rustls's enum, and every `AsyncRead`/`AsyncWrite` method
/// calls the same method on `inner` and does nothing else. The newest,
/// `02c7e54`, puts the IPCC module and its error variants behind the
/// `ipcc` feature and has the message-sending helper flush after it
/// writes; neither touches the struct or its impls. Each new revision
/// is reviewed before it joins the list; until then its streams
/// decline.
pub const SPROCKETS_TLS_STREAM_D2B68E4: GitConvention = GitConvention {
    package: "sprockets-tls",
    repository: "sprockets",
    file: "tls/src/lib.rs",
    family: "sprockets-tls-stream-d2b68e4",
    revisions: &[
        (
            "d2b68e4f47e3c22bce0455aeb4cfb2e61ad229ba",
            [
                0xfc, 0xab, 0x14, 0x9b, 0xa2, 0x50, 0xc0, 0x17, 0x2b, 0xe2, 0x66, 0x26, 0x1a, 0x2f,
                0x70, 0xbb,
            ],
        ),
        (
            "68a4b3bf819722f9f57a3f0c99e1393ed01ba392",
            [
                0x28, 0x48, 0x00, 0x27, 0xdc, 0x37, 0xaa, 0xcb, 0x18, 0xed, 0x0f, 0x06, 0x78, 0xda,
                0xce, 0x14,
            ],
        ),
        (
            "a233079e04d9688454486c452b694587a28c5257",
            [
                0x74, 0x48, 0xa3, 0x30, 0xe5, 0x4f, 0x05, 0x28, 0x6d, 0xd6, 0xd9, 0x6f, 0xfe, 0x5d,
                0xb1, 0xd6,
            ],
        ),
        (
            "02c7e5414d97c0c85d629cb76d1f6beab73d960e",
            [
                0xe7, 0x82, 0x0a, 0xc3, 0x52, 0xcf, 0xdd, 0x54, 0xab, 0x36, 0xab, 0x1c, 0x6d, 0xb5,
                0x48, 0x4c,
            ],
        ),
    ],
};

/// sprockets-tls's client handshake (`tls/src/client.rs`) at the four
/// revisions omicron has pinned: `Client::connect_with_config` dials
/// its `addr` and keeps nothing of it once `TcpStream::connect`
/// returns, so while it awaits the TLS handshake — `connector.connect`,
/// tokio-rustls's `Connect` over the socket — its frame keeps nothing of
/// the far end; from the handshake on, it holds the TLS stream in the
/// local `stream`, and from the certificates on, the server's
/// platform id in `tq_platform_id`, a `dice_mfg_msgs::PlatformId`
/// newtype over its bytes. `a233079` changes only how the nonce is
/// drawn and that the attestation is awaited; `02c7e54` only puts the
/// IPCC configuration behind the `ipcc` feature.
pub const SPROCKETS_TLS_CLIENT_D2B68E4: GitConvention = GitConvention {
    package: "sprockets-tls",
    repository: "sprockets",
    file: "tls/src/client.rs",
    family: "sprockets-tls-client-d2b68e4",
    revisions: &[
        (
            "d2b68e4f47e3c22bce0455aeb4cfb2e61ad229ba",
            [
                0x0c, 0x74, 0x29, 0x91, 0x02, 0xb2, 0xe2, 0xea, 0xc9, 0x4a, 0x67, 0x1f, 0xd3, 0x14,
                0xf6, 0xd8,
            ],
        ),
        (
            "68a4b3bf819722f9f57a3f0c99e1393ed01ba392",
            [
                0x0c, 0x74, 0x29, 0x91, 0x02, 0xb2, 0xe2, 0xea, 0xc9, 0x4a, 0x67, 0x1f, 0xd3, 0x14,
                0xf6, 0xd8,
            ],
        ),
        (
            "a233079e04d9688454486c452b694587a28c5257",
            [
                0xf0, 0x2d, 0xab, 0xb0, 0x68, 0xe8, 0x3b, 0x34, 0x51, 0xf2, 0x5e, 0xc4, 0xa7, 0x66,
                0xf6, 0xee,
            ],
        ),
        (
            "02c7e5414d97c0c85d629cb76d1f6beab73d960e",
            [
                0x50, 0x0d, 0x77, 0x30, 0x83, 0x92, 0x09, 0x2f, 0x90, 0x26, 0x58, 0xdd, 0xc4, 0x8b,
                0x59, 0xdd,
            ],
        ),
    ],
};

/// sprockets-tls's server handshake (`tls/src/server.rs`) at the same
/// four revisions: `SprocketsAcceptor::handshake` takes the acceptor
/// apart into locals, `addr` among them — the `SocketAddr` the
/// listener's `accept` returned beside the socket, which it returns
/// with the finished stream, and so holds across every await of the
/// path that finishes (the branch that refuses a client's version and
/// returns an error holds the stream without it) — the TLS handshake's
/// await among them, `tls_acceptor.accept(stream)`, tokio-rustls's
/// `Accept` over that socket; from the handshake on, its frame holds
/// the TLS stream in `stream`, and from the certificates on, the
/// client's platform id in `tq_platform_id`.
/// The later revisions differ from the earlier as the client's do.
pub const SPROCKETS_TLS_SERVER_D2B68E4: GitConvention = GitConvention {
    package: "sprockets-tls",
    repository: "sprockets",
    file: "tls/src/server.rs",
    family: "sprockets-tls-server-d2b68e4",
    revisions: &[
        (
            "d2b68e4f47e3c22bce0455aeb4cfb2e61ad229ba",
            [
                0x24, 0xf8, 0x52, 0xe7, 0x97, 0x4b, 0x93, 0x3b, 0xd8, 0x55, 0x9d, 0x53, 0x4e, 0xea,
                0x2a, 0x2d,
            ],
        ),
        (
            "68a4b3bf819722f9f57a3f0c99e1393ed01ba392",
            [
                0x24, 0xf8, 0x52, 0xe7, 0x97, 0x4b, 0x93, 0x3b, 0xd8, 0x55, 0x9d, 0x53, 0x4e, 0xea,
                0x2a, 0x2d,
            ],
        ),
        (
            "a233079e04d9688454486c452b694587a28c5257",
            [
                0x38, 0xbc, 0x84, 0x55, 0x3b, 0x8f, 0x2c, 0xd6, 0xbd, 0xc9, 0x10, 0x3a, 0xcd, 0x18,
                0xd6, 0x17,
            ],
        ),
        (
            "02c7e5414d97c0c85d629cb76d1f6beab73d960e",
            [
                0x94, 0xfa, 0xc0, 0x4a, 0xb0, 0xae, 0xa0, 0x73, 0x13, 0xba, 0x0a, 0x50, 0xcb, 0x97,
                0x6d, 0xf0,
            ],
        ),
    ],
};

/// hashbrown's `RawTable` as 0.12.3 through 0.17.1 lay it out, read in
/// every release of that range (`src/raw/mod.rs`, `src/raw.rs` from
/// 0.17.0, beside `src/map.rs` and `src/set.rs`, and `is_full` in
/// `src/control/tag.rs` from 0.15.2): `HashMap` is
/// `{ hash_builder, table: RawTable<(K, V), A> }`, `HashSet` is
/// `{ map: HashMap<T, (), S, A> }`, and a `RawTable`'s `table` is the
/// `RawTableInner` holding `bucket_mask`, `ctrl: NonNull<u8>`,
/// `growth_left` and `items` — its allocator moved out to the
/// `RawTable` at 0.14.1, which no route crosses. A table has
/// `bucket_mask + 1` buckets and a control byte for each at `ctrl`, one
/// with its top bit clear (`is_full`) for every full bucket, of which
/// `items` counts the number; `data_end` is `ctrl` itself, and bucket
/// `i` is the `T` ending `i` buckets below it (`from_base_index` takes
/// `base.sub(index)`, `as_ptr` one `T` below that). std vendors the
/// crate, so its maps follow whichever release the toolchain carries;
/// the version is read off the declarations either way. The checksums
/// are of every reviewed revision, which rustc's DWARF 4 never records
/// but the matrix suite checks.
pub const HASHBROWN_TABLE_V0_12_3: LibraryConvention = LibraryConvention {
    package: "hashbrown",
    family: "hashbrown-table-0.12.3",
    releases: Releases(&[
        ((0, 12, 3), (0, 12, 3)),
        ((0, 13, 0), (0, 13, 2)),
        ((0, 14, 0), (0, 14, 5)),
        ((0, 15, 0), (0, 15, 5)),
        ((0, 16, 0), (0, 16, 1)),
        ((0, 17, 0), (0, 17, 1)),
    ]),
    checksums: &[
        // src/map.rs, 0.12.3
        (
            "src/map.rs",
            [
                0x41, 0x62, 0x93, 0x69, 0xcf, 0xa4, 0xfe, 0x48, 0x27, 0xec, 0xbc, 0xd0, 0x0a, 0xe0,
                0x9f, 0x37,
            ],
        ),
        // src/map.rs, 0.13.0 and 0.13.1
        (
            "src/map.rs",
            [
                0x0c, 0x94, 0xab, 0x52, 0x69, 0x43, 0x13, 0x5a, 0x9a, 0x3f, 0x39, 0xf1, 0x75, 0xc5,
                0x85, 0x9a,
            ],
        ),
        // src/map.rs, 0.13.2
        (
            "src/map.rs",
            [
                0x1d, 0x6a, 0x5d, 0x74, 0xdf, 0xba, 0x52, 0x46, 0x1b, 0x40, 0xac, 0x24, 0x82, 0x6b,
                0x84, 0x32,
            ],
        ),
        // src/map.rs, 0.14.0
        (
            "src/map.rs",
            [
                0x5c, 0xc7, 0xb6, 0x07, 0x6e, 0xf6, 0x67, 0x48, 0xdf, 0x2f, 0xba, 0x5a, 0x28, 0xa2,
                0x35, 0x02,
            ],
        ),
        // src/map.rs, 0.14.1
        (
            "src/map.rs",
            [
                0x34, 0xf5, 0xd0, 0x83, 0x6d, 0x98, 0xe1, 0x59, 0x3b, 0x76, 0x07, 0x8b, 0x56, 0x81,
                0xd6, 0xea,
            ],
        ),
        // src/map.rs, 0.14.2
        (
            "src/map.rs",
            [
                0xc4, 0x06, 0x24, 0x5c, 0x4e, 0xc4, 0x97, 0x67, 0x6f, 0x29, 0x0a, 0xe1, 0x0f, 0xec,
                0x10, 0x51,
            ],
        ),
        // src/map.rs, 0.14.3
        (
            "src/map.rs",
            [
                0x90, 0x31, 0xa7, 0x89, 0xc1, 0x9c, 0x8e, 0x60, 0x7d, 0x4f, 0xec, 0x2f, 0xde, 0x97,
                0xc9, 0x1a,
            ],
        ),
        // src/map.rs, 0.14.4 and 0.14.5
        (
            "src/map.rs",
            [
                0x05, 0xfc, 0xd0, 0x83, 0xad, 0x7c, 0x6b, 0xcf, 0x07, 0xbe, 0x92, 0xdd, 0x12, 0x8f,
                0x94, 0x68,
            ],
        ),
        // src/map.rs, 0.15.0
        (
            "src/map.rs",
            [
                0xd1, 0xb1, 0x36, 0x8b, 0x60, 0xb3, 0x9d, 0xb6, 0xb8, 0x08, 0xe7, 0xc2, 0x16, 0x33,
                0x9d, 0xc0,
            ],
        ),
        // src/map.rs, 0.15.1
        (
            "src/map.rs",
            [
                0xee, 0x63, 0x6b, 0xc4, 0x3e, 0x4e, 0xf2, 0xac, 0x17, 0x9f, 0x44, 0x22, 0x6b, 0x5b,
                0x27, 0xc1,
            ],
        ),
        // src/map.rs, 0.15.2
        (
            "src/map.rs",
            [
                0xfd, 0xc2, 0x24, 0x3f, 0x81, 0x06, 0xcb, 0xdb, 0x72, 0xff, 0x32, 0xb5, 0x83, 0x3e,
                0xbe, 0x8b,
            ],
        ),
        // src/map.rs, 0.15.3
        (
            "src/map.rs",
            [
                0xe1, 0x13, 0x48, 0x38, 0x3c, 0xf5, 0xcb, 0x9a, 0xcf, 0x85, 0x5b, 0x40, 0x86, 0xc4,
                0xf0, 0xb7,
            ],
        ),
        // src/map.rs, 0.15.4
        (
            "src/map.rs",
            [
                0xf3, 0x9f, 0xc6, 0x12, 0x8f, 0x43, 0xd0, 0xe8, 0xf3, 0x1e, 0x8d, 0x5a, 0x42, 0xde,
                0xc8, 0x6f,
            ],
        ),
        // src/map.rs, 0.15.5
        (
            "src/map.rs",
            [
                0x75, 0x01, 0x9d, 0x1d, 0x6b, 0x73, 0xc8, 0x0a, 0x86, 0x84, 0x3e, 0x5b, 0xab, 0x7c,
                0xac, 0x12,
            ],
        ),
        // src/map.rs, 0.16.0
        (
            "src/map.rs",
            [
                0x30, 0xa9, 0x31, 0x8b, 0x67, 0x03, 0x17, 0xd3, 0x59, 0xb7, 0xfd, 0xbe, 0xad, 0x86,
                0x26, 0x84,
            ],
        ),
        // src/map.rs, 0.16.1
        (
            "src/map.rs",
            [
                0x1d, 0xff, 0x53, 0x18, 0xb3, 0x84, 0x1f, 0xf7, 0x36, 0x71, 0xad, 0xde, 0x53, 0x0b,
                0x5f, 0x2e,
            ],
        ),
        // src/map.rs, 0.17.0 and 0.17.1
        (
            "src/map.rs",
            [
                0x5f, 0x06, 0x4d, 0x32, 0xfe, 0x49, 0x6a, 0x8e, 0xf3, 0x19, 0x52, 0x65, 0x99, 0x24,
                0x10, 0x68,
            ],
        ),
        // src/set.rs, 0.12.3
        (
            "src/set.rs",
            [
                0x5a, 0xfc, 0xfa, 0x1b, 0xba, 0x1e, 0xc9, 0x11, 0xf3, 0xb0, 0x85, 0x33, 0xba, 0x87,
                0xe4, 0xc6,
            ],
        ),
        // src/set.rs, 0.13.0 and 0.13.1
        (
            "src/set.rs",
            [
                0x0d, 0x22, 0x7a, 0x84, 0x81, 0x16, 0x0f, 0x38, 0xf2, 0x24, 0x7d, 0xaf, 0xcd, 0x9c,
                0x8c, 0xf9,
            ],
        ),
        // src/set.rs, 0.13.2
        (
            "src/set.rs",
            [
                0xaa, 0x29, 0x2f, 0x56, 0x8c, 0xb0, 0x22, 0x2b, 0x2c, 0x17, 0x78, 0x32, 0x9c, 0x09,
                0x29, 0xab,
            ],
        ),
        // src/set.rs, 0.14.0
        (
            "src/set.rs",
            [
                0x43, 0xe6, 0x06, 0x77, 0x95, 0x61, 0x13, 0xdc, 0x28, 0xc4, 0x2d, 0xaa, 0x6e, 0x58,
                0x40, 0x8e,
            ],
        ),
        // src/set.rs, 0.14.1
        (
            "src/set.rs",
            [
                0x26, 0x4c, 0xc9, 0x38, 0x32, 0x66, 0x51, 0xdb, 0x8e, 0x92, 0x96, 0x11, 0x1c, 0xee,
                0xf4, 0x92,
            ],
        ),
        // src/set.rs, 0.14.2
        (
            "src/set.rs",
            [
                0x85, 0xa1, 0xa7, 0x40, 0x3e, 0x4f, 0x0e, 0x0f, 0xc4, 0x59, 0x73, 0x0c, 0xb4, 0x12,
                0x71, 0x8d,
            ],
        ),
        // src/set.rs, 0.14.3
        (
            "src/set.rs",
            [
                0xf3, 0xb0, 0x58, 0x40, 0x01, 0xd1, 0x3a, 0x94, 0x95, 0xdd, 0xcf, 0xd2, 0x8a, 0xef,
                0x26, 0xa0,
            ],
        ),
        // src/set.rs, 0.14.4
        (
            "src/set.rs",
            [
                0xcb, 0xb8, 0xdd, 0xb7, 0x81, 0x08, 0x34, 0xc9, 0x02, 0xf8, 0x5d, 0x77, 0x42, 0x0f,
                0x1f, 0x5d,
            ],
        ),
        // src/set.rs, 0.14.5
        (
            "src/set.rs",
            [
                0xc5, 0x12, 0x60, 0x1e, 0xae, 0x9e, 0x5f, 0xc6, 0x3f, 0xae, 0x2b, 0x33, 0xc4, 0xd7,
                0x74, 0x0e,
            ],
        ),
        // src/set.rs, 0.15.0
        (
            "src/set.rs",
            [
                0x37, 0xc3, 0xc9, 0xae, 0xbe, 0x4c, 0x59, 0xf2, 0xe1, 0xb9, 0x3a, 0x3a, 0x5c, 0x86,
                0xe1, 0x03,
            ],
        ),
        // src/set.rs, 0.15.1
        (
            "src/set.rs",
            [
                0x54, 0x52, 0x71, 0xf8, 0x80, 0x31, 0x0f, 0x3b, 0x9b, 0xe9, 0x54, 0xd6, 0xf2, 0x20,
                0xdd, 0xed,
            ],
        ),
        // src/set.rs, 0.15.2
        (
            "src/set.rs",
            [
                0xb5, 0xd4, 0x44, 0x38, 0xef, 0x1f, 0x92, 0x7a, 0x23, 0xe4, 0x1b, 0x8b, 0x27, 0xe3,
                0x8c, 0x33,
            ],
        ),
        // src/set.rs, 0.15.3
        (
            "src/set.rs",
            [
                0x2f, 0x75, 0x91, 0xa8, 0xc9, 0x7e, 0x2c, 0xb0, 0xbc, 0xf0, 0xeb, 0x87, 0x36, 0x4d,
                0x12, 0xae,
            ],
        ),
        // src/set.rs, 0.15.4 through 0.16.0
        (
            "src/set.rs",
            [
                0x83, 0xb6, 0xa5, 0xc0, 0xfe, 0x68, 0x50, 0x18, 0x1d, 0x34, 0x60, 0x65, 0x7a, 0x05,
                0x85, 0x4c,
            ],
        ),
        // src/set.rs, 0.16.1
        (
            "src/set.rs",
            [
                0x99, 0xc6, 0xb7, 0xca, 0x83, 0x2c, 0xdb, 0xa9, 0xbd, 0x8d, 0x8b, 0xb0, 0x84, 0x58,
                0xc8, 0xef,
            ],
        ),
        // src/set.rs, 0.17.0 and 0.17.1
        (
            "src/set.rs",
            [
                0x87, 0xa6, 0x02, 0xd9, 0x0a, 0x47, 0xf2, 0x6d, 0xa5, 0x01, 0xaf, 0xa2, 0x85, 0xc4,
                0x25, 0x16,
            ],
        ),
        // src/raw/mod.rs, 0.12.3
        (
            "src/raw/mod.rs",
            [
                0xf3, 0xeb, 0xca, 0x7c, 0x61, 0x98, 0x34, 0xfb, 0xc5, 0xaf, 0x49, 0x05, 0xb3, 0x4b,
                0xb2, 0x4d,
            ],
        ),
        // src/raw/mod.rs, 0.13.0
        (
            "src/raw/mod.rs",
            [
                0x9a, 0x00, 0xd3, 0xce, 0x50, 0x98, 0x06, 0x56, 0x04, 0x9c, 0xdd, 0x5b, 0xfd, 0xe9,
                0x1b, 0x99,
            ],
        ),
        // src/raw/mod.rs, 0.13.1
        (
            "src/raw/mod.rs",
            [
                0xf2, 0x71, 0x97, 0xb4, 0xa4, 0xfc, 0x1d, 0x4c, 0x94, 0xae, 0x6c, 0xa0, 0x70, 0x2e,
                0x3a, 0xe6,
            ],
        ),
        // src/raw/mod.rs, 0.13.2
        (
            "src/raw/mod.rs",
            [
                0xf4, 0x59, 0x7e, 0x1d, 0x44, 0x55, 0x25, 0x8c, 0x7c, 0x2d, 0xbc, 0x2c, 0x60, 0x9c,
                0xe2, 0x33,
            ],
        ),
        // src/raw/mod.rs, 0.14.0
        (
            "src/raw/mod.rs",
            [
                0xa5, 0xd5, 0x34, 0xa9, 0xa1, 0xa0, 0x2c, 0x1c, 0x43, 0xdd, 0xbf, 0x1f, 0x02, 0x3c,
                0x11, 0x29,
            ],
        ),
        // src/raw/mod.rs, 0.14.1
        (
            "src/raw/mod.rs",
            [
                0xa5, 0x9a, 0xa5, 0xfc, 0x96, 0xcb, 0x91, 0x97, 0x12, 0xb8, 0x53, 0x4f, 0x07, 0xe0,
                0xfc, 0xaf,
            ],
        ),
        // src/raw/mod.rs, 0.14.2
        (
            "src/raw/mod.rs",
            [
                0x05, 0x58, 0x72, 0x7e, 0x46, 0xf9, 0xf3, 0xa4, 0xc8, 0xa7, 0xd4, 0xf2, 0xea, 0x95,
                0x95, 0xb0,
            ],
        ),
        // src/raw/mod.rs, 0.14.3
        (
            "src/raw/mod.rs",
            [
                0x55, 0x1b, 0x64, 0x6f, 0x50, 0x7a, 0xf1, 0xdb, 0x8f, 0xdb, 0x7a, 0x79, 0xfb, 0x23,
                0x0b, 0x7c,
            ],
        ),
        // src/raw/mod.rs, 0.14.4
        (
            "src/raw/mod.rs",
            [
                0x05, 0x74, 0x6b, 0xaa, 0xf0, 0x20, 0x5e, 0x11, 0xde, 0x58, 0x78, 0x13, 0xc9, 0xba,
                0x07, 0xf5,
            ],
        ),
        // src/raw/mod.rs, 0.14.5
        (
            "src/raw/mod.rs",
            [
                0x39, 0x53, 0xd5, 0x31, 0xe4, 0x60, 0x6f, 0xc7, 0xb2, 0x52, 0xf4, 0xfd, 0x90, 0xa4,
                0x70, 0x79,
            ],
        ),
        // src/raw/mod.rs, 0.15.0
        (
            "src/raw/mod.rs",
            [
                0x23, 0xc5, 0xba, 0xab, 0x03, 0x46, 0x75, 0x6e, 0xdb, 0x95, 0xee, 0xa1, 0x39, 0xad,
                0xe5, 0x60,
            ],
        ),
        // src/raw/mod.rs, 0.15.1
        (
            "src/raw/mod.rs",
            [
                0x66, 0x4a, 0x30, 0xf7, 0x32, 0x53, 0xda, 0x4c, 0xce, 0xbb, 0x54, 0xab, 0x1f, 0x0e,
                0x15, 0xdc,
            ],
        ),
        // src/raw/mod.rs, 0.15.2
        (
            "src/raw/mod.rs",
            [
                0x3f, 0x78, 0x3b, 0x11, 0xaf, 0x11, 0x19, 0xf7, 0x3d, 0xc1, 0xf1, 0x8f, 0x1f, 0x19,
                0x3d, 0x5e,
            ],
        ),
        // src/raw/mod.rs, 0.15.3 through 0.16.0
        (
            "src/raw/mod.rs",
            [
                0x5d, 0x3b, 0x64, 0x71, 0x9e, 0xe6, 0x4b, 0x75, 0x78, 0xbc, 0x74, 0xbe, 0x56, 0xa5,
                0xef, 0x35,
            ],
        ),
        // src/raw/mod.rs, 0.16.1
        (
            "src/raw/mod.rs",
            [
                0xd4, 0x74, 0x3e, 0x4e, 0x52, 0x6b, 0x3c, 0xa0, 0x80, 0x4e, 0x46, 0x7d, 0xc6, 0xa5,
                0xbf, 0x88,
            ],
        ),
        // src/raw.rs, 0.17.0 and 0.17.1
        (
            "src/raw.rs",
            [
                0xda, 0x13, 0x52, 0x10, 0x4b, 0x49, 0x38, 0xbc, 0x72, 0x89, 0xa2, 0xca, 0xd1, 0xb5,
                0xe1, 0xe6,
            ],
        ),
        // src/control/tag.rs, 0.15.2 through 0.16.1
        (
            "src/control/tag.rs",
            [
                0x8d, 0x1d, 0xbc, 0x37, 0x6b, 0x4c, 0x6e, 0x81, 0xb1, 0x28, 0xda, 0xf6, 0x0e, 0xb1,
                0xea, 0xa3,
            ],
        ),
        // src/control/tag.rs, 0.17.0 and 0.17.1
        (
            "src/control/tag.rs",
            [
                0x29, 0xb0, 0x20, 0x44, 0x8e, 0x8b, 0x8a, 0xbb, 0xc2, 0x10, 0x13, 0xf0, 0x51, 0xb6,
                0x5e, 0x9a,
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
/// sources at [`TOKIO_RELEASES`]. A layout binding says where the words
/// are; only a protocol says what they mean, and the read side's
/// assessor refuses to call a resource ready or waited on without one.
/// Separate from the layout families on purpose: a family is selected
/// for every version, newest as a guess, while a protocol binds at its
/// reviewed releases and nowhere else.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct StateProtocol {
    pub kind: SemanticRuleKind,
    /// The review's name, as a warning that it declines names it.
    pub family: &'static str,
    pub releases: Releases,
    /// `(file, md5)` for every reviewed revision of each file the
    /// protocol was read from, relative to the crate root.
    pub checksums: &'static [(&'static str, [u8; 16])],
}

/// `batch_semaphore::Acquire`'s protocol, tokio 1.47 through 1.53
/// (`sync/batch_semaphore.rs`, unchanged across the range but for the
/// queue's type alias, the closed bit surviving `forget_permits`'
/// compare-exchange from 1.53, the trace hook's signature, and where
/// 1.51.5 sets `queued`): `Acquire::poll` forwards to `poll_acquire`
/// with the node embedded in the future; a `Pending` leaves `queued`
/// set and a `Ready(Ok)` clears it, so `queued` records that a poll
/// linked the node and outlives the grant. (1.51.5 sets it inside
/// `poll_acquire`, before the node is assigned permits or linked, and
/// zeroes the node's counter on an immediate grant, so that a future
/// dropped mid-poll returns what it holds; what a returned poll leaves
/// is the same.) `poll_acquire` returns the closed error on the permit
/// word's low bit or the wait list's own flag, takes what the permit
/// word holds, and — with permits still needed — stores the task's waker
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
    family: "tokio-acquire-state-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/sync/batch_semaphore.rs, 1.47.0 through 1.48.0
        (
            "src/sync/batch_semaphore.rs",
            [
                0x42, 0xfa, 0xa0, 0x59, 0xa6, 0xc9, 0xf8, 0x6c, 0x90, 0xd0, 0xd4, 0x06, 0x5d, 0x80,
                0x8c, 0xcd,
            ],
        ),
        // src/sync/batch_semaphore.rs, 1.49.0 through 1.51.0
        (
            "src/sync/batch_semaphore.rs",
            [
                0xfb, 0x27, 0xb0, 0xc9, 0x48, 0xd6, 0x42, 0x3f, 0x29, 0xb4, 0xfc, 0xa0, 0xa0, 0xa0,
                0x33, 0xf5,
            ],
        ),
        // src/sync/batch_semaphore.rs, 1.51.1 through 1.51.4, 1.52.0 through 1.52.4
        (
            "src/sync/batch_semaphore.rs",
            [
                0xda, 0x55, 0xcb, 0xcf, 0x9d, 0xdb, 0x37, 0xab, 0x8e, 0xc5, 0xf5, 0xc9, 0x4b, 0x7d,
                0x49, 0x22,
            ],
        ),
        // src/sync/batch_semaphore.rs, 1.51.5
        (
            "src/sync/batch_semaphore.rs",
            [
                0x64, 0x2f, 0x17, 0xc9, 0x3f, 0xc5, 0x1f, 0xd8, 0x84, 0x23, 0xc7, 0x52, 0x60, 0xfd,
                0x43, 0x19,
            ],
        ),
        // src/sync/batch_semaphore.rs, 1.53.0 and 1.53.1
        (
            "src/sync/batch_semaphore.rs",
            [
                0x9e, 0x5a, 0x0f, 0xbb, 0x5b, 0xd8, 0xa8, 0x02, 0x7e, 0xb5, 0x82, 0x34, 0x96, 0x8f,
                0x45, 0xed,
            ],
        ),
    ],
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
    family: "tokio-join-handle-state-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/runtime/task/join.rs, 1.47.0 through 1.47.5
        (
            "src/runtime/task/join.rs",
            [
                0x81, 0xaf, 0x8c, 0x64, 0xbf, 0xb1, 0xe9, 0x78, 0x4f, 0xb8, 0x3d, 0xf4, 0xb1, 0x9f,
                0x92, 0x3d,
            ],
        ),
        // src/runtime/task/join.rs, 1.48.0
        (
            "src/runtime/task/join.rs",
            [
                0x3f, 0x34, 0x2f, 0x97, 0x75, 0x0f, 0x67, 0x32, 0x20, 0x82, 0xf6, 0x96, 0xdd, 0x0a,
                0x62, 0x25,
            ],
        ),
        // src/runtime/task/join.rs, 1.49.0
        (
            "src/runtime/task/join.rs",
            [
                0x37, 0x6d, 0x00, 0x13, 0x14, 0x87, 0x41, 0xcf, 0x11, 0xb8, 0x6a, 0xa6, 0xbe, 0x0f,
                0x3c, 0x3a,
            ],
        ),
        // src/runtime/task/join.rs, 1.50.0 through 1.52.4
        (
            "src/runtime/task/join.rs",
            [
                0x3a, 0x69, 0x54, 0x68, 0x60, 0x38, 0x02, 0x5c, 0x03, 0x98, 0x8f, 0x37, 0x18, 0x6a,
                0xbc, 0x64,
            ],
        ),
        // src/runtime/task/join.rs, 1.53.0 and 1.53.1
        (
            "src/runtime/task/join.rs",
            [
                0xcf, 0xf0, 0x25, 0x53, 0x0c, 0xad, 0x34, 0x43, 0xd2, 0x36, 0xed, 0x4a, 0x06, 0x25,
                0x1b, 0x98,
            ],
        ),
        // src/runtime/task/harness.rs, 1.47.0 through 1.53.1
        (
            "src/runtime/task/harness.rs",
            [
                0xc1, 0x61, 0x78, 0x2e, 0xb1, 0xb8, 0x5e, 0x89, 0x3f, 0x54, 0xe2, 0x2a, 0x48, 0x56,
                0xd0, 0xb4,
            ],
        ),
    ],
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
    family: "tokio-sleep-state-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/time/sleep.rs, 1.47.0 through 1.47.5
        (
            "src/time/sleep.rs",
            [
                0x0e, 0x71, 0x9b, 0x8c, 0x3c, 0x75, 0x60, 0x94, 0x01, 0x3d, 0xc3, 0xf4, 0xa6, 0xc8,
                0x73, 0x09,
            ],
        ),
        // src/time/sleep.rs, 1.48.0
        (
            "src/time/sleep.rs",
            [
                0xa5, 0x4e, 0xde, 0x66, 0x30, 0xdc, 0x0b, 0x53, 0xb8, 0x0b, 0x0e, 0x33, 0x12, 0xce,
                0xf6, 0xaf,
            ],
        ),
        // src/time/sleep.rs, 1.49.0 through 1.52.4
        (
            "src/time/sleep.rs",
            [
                0xa9, 0x8f, 0x88, 0xb2, 0x80, 0x9f, 0xab, 0x35, 0x9f, 0xec, 0xba, 0x05, 0xa4, 0xbd,
                0x1b, 0xa6,
            ],
        ),
        // src/time/sleep.rs, 1.53.0 and 1.53.1
        (
            "src/time/sleep.rs",
            [
                0xf1, 0xd4, 0xf1, 0xff, 0xba, 0x94, 0x6c, 0xf9, 0xb5, 0x7d, 0x0a, 0xdf, 0xf5, 0x7d,
                0x04, 0xac,
            ],
        ),
        // src/runtime/time/entry.rs, 1.47.0 through 1.48.0
        (
            "src/runtime/time/entry.rs",
            [
                0x5b, 0xdf, 0xe6, 0xed, 0x44, 0x15, 0x9c, 0x26, 0x15, 0xc4, 0x79, 0xde, 0x00, 0xcf,
                0x09, 0x87,
            ],
        ),
        // src/runtime/time/entry.rs, 1.49.0 through 1.52.4
        (
            "src/runtime/time/entry.rs",
            [
                0x00, 0x55, 0xeb, 0x76, 0x07, 0xcc, 0x11, 0x39, 0x9c, 0x48, 0x58, 0x6b, 0xb3, 0x19,
                0x59, 0x56,
            ],
        ),
        // src/runtime/time/entry.rs, 1.53.0 and 1.53.1
        (
            "src/runtime/time/entry.rs",
            [
                0xe3, 0x82, 0x16, 0x9a, 0xa7, 0x1c, 0x06, 0x35, 0x6a, 0x69, 0xb4, 0xbb, 0x98, 0x57,
                0x77, 0x5b,
            ],
        ),
    ],
};

/// The io operations' protocol, tokio 1.47 through 1.53
/// (`runtime/io/scheduled_io.rs`, `runtime/io/registration.rs`,
/// `runtime/io/driver.rs`, and `io/util/{read,read_exact,read_buf,
/// write,write_all,write_buf,flush,shutdown}.rs`, unchanged across the
/// range but for a list type alias and 1.51.5's driver keeping a
/// registration whose OS deregister failed): the registration's
/// readiness word packs the delivered `Ready` bits in its low sixteen,
/// a tick above
/// them and the shutdown flag at bit 31. Each operation future polls
/// the stream its `&mut` names and nothing else — `poll_read` for the
/// three reads, `poll_write` for the three writes, `poll_flush` and
/// `poll_shutdown` for the other two — and returns `Pending` only when
/// that poll does. A routed stream's poll reaches its socket's (see
/// the stream routes), and a socket's `poll_read`/`poll_write` goes
/// through `Registration::poll_io`, which polls readiness before
/// touching the buffer — so an empty read buffer parks like any other
/// — and `poll_readiness` returns `Pending` only when the direction's
/// mask (readable or read-closed; writable or write-closed) finds no
/// delivered bit and shutdown is clear, having stored the task's waker
/// in that direction's slot under the waiters lock. A socket's flush
/// and shutdown never pend, so a pending flush or shutdown is a write
/// some stream along the route made, parked in the writer slot.
/// `WriteAll` returns before polling when its buffer is exhausted.
/// `Readiness`
/// moves from `Init` to `Done` when its interest is already delivered
/// or the resource is shut down, else pushes its own node at the
/// list's front and enters `Waiting`; in `Waiting` it returns `Ready`
/// once the node's `is_ready` flag is set, which the resource's wake
/// path sets under the lock while taking the waker of every node whose
/// interest the event satisfies. Shutdown wakes every node.
pub const TOKIO_IO_STATE_V1_47: StateProtocol = StateProtocol {
    kind: SemanticRuleKind::TokioIoState,
    family: "tokio-io-state-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/runtime/io/scheduled_io.rs, 1.47.0 through 1.48.0
        (
            "src/runtime/io/scheduled_io.rs",
            [
                0x8e, 0x3f, 0x24, 0xa3, 0x72, 0xd9, 0xfc, 0x89, 0xcf, 0xde, 0x45, 0x7e, 0x62, 0xbc,
                0xdb, 0x40,
            ],
        ),
        // src/runtime/io/scheduled_io.rs, 1.49.0 through 1.52.4
        (
            "src/runtime/io/scheduled_io.rs",
            [
                0x07, 0xd6, 0xf5, 0x10, 0xe9, 0x81, 0x75, 0x4c, 0x75, 0xcc, 0x37, 0xbe, 0x32, 0x9c,
                0x67, 0xb7,
            ],
        ),
        // src/runtime/io/scheduled_io.rs, 1.53.0 and 1.53.1
        (
            "src/runtime/io/scheduled_io.rs",
            [
                0x85, 0x38, 0x6f, 0x7e, 0x13, 0x3b, 0x7d, 0xa3, 0x03, 0xe6, 0x3f, 0xb8, 0x9d, 0xa3,
                0x00, 0x47,
            ],
        ),
        // src/runtime/io/registration.rs, 1.47.0 through 1.50.0
        (
            "src/runtime/io/registration.rs",
            [
                0x97, 0x2b, 0x7b, 0xb8, 0xa6, 0x39, 0xda, 0x73, 0x6c, 0xea, 0x81, 0x71, 0xa2, 0x4b,
                0xbd, 0x17,
            ],
        ),
        // src/runtime/io/registration.rs, 1.51.0 through 1.52.4
        (
            "src/runtime/io/registration.rs",
            [
                0xc3, 0x7a, 0x68, 0xd3, 0x55, 0xf7, 0xbf, 0x3f, 0x88, 0x3d, 0x8b, 0xe0, 0xfb, 0x50,
                0xdd, 0xdd,
            ],
        ),
        // src/runtime/io/registration.rs, 1.53.0 and 1.53.1
        (
            "src/runtime/io/registration.rs",
            [
                0xf6, 0x54, 0x2b, 0x83, 0xf4, 0xf4, 0xcc, 0x36, 0xc9, 0x93, 0xa1, 0xe3, 0x8f, 0x39,
                0x3e, 0x92,
            ],
        ),
        // src/runtime/io/driver.rs, 1.47.0 through 1.47.5
        (
            "src/runtime/io/driver.rs",
            [
                0x99, 0xe9, 0x27, 0x79, 0xa1, 0x77, 0x25, 0x6c, 0x23, 0x54, 0x4f, 0x9c, 0xeb, 0xf8,
                0xcf, 0x59,
            ],
        ),
        // src/runtime/io/driver.rs, 1.48.0 and 1.49.0
        (
            "src/runtime/io/driver.rs",
            [
                0xd0, 0x9c, 0xfa, 0x8a, 0x26, 0x2c, 0x1c, 0x49, 0x0d, 0xb1, 0x0e, 0x3c, 0x35, 0xd5,
                0x76, 0x14,
            ],
        ),
        // src/runtime/io/driver.rs, 1.50.0 through 1.51.4, 1.52.0 through 1.52.4
        (
            "src/runtime/io/driver.rs",
            [
                0x84, 0xc8, 0x25, 0x0e, 0x92, 0x93, 0x1e, 0xe1, 0x4d, 0xc3, 0x83, 0xbc, 0x40, 0x9e,
                0x92, 0x78,
            ],
        ),
        // src/runtime/io/driver.rs, 1.51.5
        (
            "src/runtime/io/driver.rs",
            [
                0xf8, 0xc0, 0xf6, 0x59, 0x3f, 0x21, 0xc1, 0x20, 0x96, 0xb1, 0xb2, 0x03, 0xc2, 0x70,
                0xd5, 0x17,
            ],
        ),
        // src/runtime/io/driver.rs, 1.53.0 and 1.53.1
        (
            "src/runtime/io/driver.rs",
            [
                0x2f, 0x8e, 0xd0, 0x80, 0xe2, 0x6b, 0x82, 0x2f, 0xb6, 0xec, 0x6f, 0xb1, 0x6c, 0x0d,
                0xee, 0xfc,
            ],
        ),
        // src/io/util/read.rs, 1.47.0 through 1.53.1
        (
            "src/io/util/read.rs",
            [
                0x66, 0x1e, 0x10, 0x4b, 0x7c, 0x02, 0x4f, 0x1d, 0xdf, 0x2b, 0xa8, 0xe0, 0xff, 0xba,
                0xa9, 0xd2,
            ],
        ),
        // src/io/util/read_exact.rs, 1.47.0 through 1.53.1
        (
            "src/io/util/read_exact.rs",
            [
                0x34, 0x70, 0x30, 0x5e, 0x5a, 0x97, 0x5b, 0x9a, 0xaa, 0xe5, 0x0f, 0x80, 0x39, 0xe9,
                0x71, 0x07,
            ],
        ),
        // src/io/util/read_buf.rs, 1.47.0 through 1.53.1
        (
            "src/io/util/read_buf.rs",
            [
                0xb5, 0xfb, 0xcf, 0xe6, 0x08, 0x62, 0x49, 0xdd, 0x82, 0x7a, 0xc9, 0x91, 0xe0, 0x5d,
                0x29, 0x00,
            ],
        ),
        // src/io/util/write.rs, 1.47.0 through 1.53.1
        (
            "src/io/util/write.rs",
            [
                0x99, 0xbf, 0xb4, 0x55, 0x4b, 0x2c, 0xd5, 0x41, 0x49, 0xdf, 0x86, 0xfb, 0x6b, 0xee,
                0x0e, 0x62,
            ],
        ),
        // src/io/util/write_all.rs, 1.47.0 through 1.53.1
        (
            "src/io/util/write_all.rs",
            [
                0x17, 0xad, 0x81, 0x4a, 0x2c, 0xe0, 0x50, 0x01, 0xeb, 0xdb, 0xd1, 0x29, 0xfa, 0xf9,
                0xfd, 0x90,
            ],
        ),
        // src/io/util/write_buf.rs, 1.47.0 through 1.49.0
        (
            "src/io/util/write_buf.rs",
            [
                0x64, 0x20, 0xba, 0x1d, 0x0b, 0x88, 0x30, 0xa2, 0x63, 0x1c, 0x0a, 0xff, 0x3b, 0x22,
                0xc0, 0x88,
            ],
        ),
        // src/io/util/write_buf.rs, 1.50.0 through 1.53.1
        (
            "src/io/util/write_buf.rs",
            [
                0xd7, 0x03, 0x5e, 0xb6, 0xc9, 0x86, 0x9a, 0xbc, 0x07, 0x75, 0xc2, 0x95, 0x0c, 0xd1,
                0xbd, 0x87,
            ],
        ),
        // src/io/util/flush.rs, 1.47.0 through 1.53.1
        (
            "src/io/util/flush.rs",
            [
                0x92, 0xaf, 0xf4, 0x0b, 0x85, 0x4d, 0xcd, 0x67, 0xe3, 0x4e, 0x79, 0x88, 0x9a, 0x1f,
                0x09, 0x5f,
            ],
        ),
        // src/io/util/shutdown.rs, 1.47.0 through 1.53.1
        (
            "src/io/util/shutdown.rs",
            [
                0x19, 0xc4, 0xfc, 0x4f, 0x6e, 0xe8, 0xe0, 0x29, 0x3b, 0x96, 0xcf, 0xb9, 0xab, 0x33,
                0xd6, 0x74,
            ],
        ),
    ],
};

/// The bounded mpsc receiver's `recv` protocol, tokio 1.47 through 1.53
/// (`sync/mpsc/chan.rs`, `sync/mpsc/list.rs`, `sync/mpsc/block.rs` and
/// `sync/task/atomic_waker.rs`; across the range `chan.rs` differs only
/// in the trace hook's signature, a `take_waker` on the receiver's
/// drop and a test-only constructor, `list.rs` and `block.rs` only in
/// `len`'s closed-marker accounting, `unsafe` block reflows and
/// 1.51.5's wrapping block indices in `grow`, `has_value` and
/// `reclaim_blocks` — `pop`, `try_advancing_head` and `Block::read` are
/// byte-identical — and `atomic_waker.rs` not at all): `Receiver::recv`
/// awaits `poll_fn(|cx| self.chan.recv(cx))`, and `Rx::recv` checks the
/// cooperative budget, then pops: the head
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
    family: "tokio-mpsc-recv-state-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/sync/mpsc/chan.rs, 1.47.0 through 1.47.2, 1.48.0
        (
            "src/sync/mpsc/chan.rs",
            [
                0x5a, 0x99, 0xc6, 0xbf, 0xce, 0x6d, 0xb8, 0x0a, 0x5d, 0x2e, 0x6e, 0x71, 0xaf, 0x20,
                0x12, 0x27,
            ],
        ),
        // src/sync/mpsc/chan.rs, 1.47.3, 1.49.0 and 1.50.0
        (
            "src/sync/mpsc/chan.rs",
            [
                0xc6, 0x12, 0x40, 0x82, 0x47, 0xb1, 0xae, 0x12, 0x2c, 0x93, 0x8f, 0xb6, 0xc9, 0xeb,
                0x66, 0x64,
            ],
        ),
        // src/sync/mpsc/chan.rs, 1.47.4, 1.51.0 through 1.51.2, 1.52.0 through 1.52.2
        (
            "src/sync/mpsc/chan.rs",
            [
                0xaf, 0x93, 0x46, 0xd5, 0x2a, 0x3d, 0xe4, 0x7c, 0x77, 0x6e, 0x96, 0x7f, 0xfe, 0x6e,
                0x72, 0x40,
            ],
        ),
        // src/sync/mpsc/chan.rs, 1.47.5, 1.51.3 and 1.51.4, 1.52.3 and 1.52.4
        (
            "src/sync/mpsc/chan.rs",
            [
                0x71, 0x3a, 0xce, 0xaf, 0xe4, 0x54, 0x7f, 0x82, 0xd0, 0x31, 0x22, 0x82, 0xb1, 0xe3,
                0x2f, 0x09,
            ],
        ),
        // src/sync/mpsc/chan.rs, 1.51.5
        (
            "src/sync/mpsc/chan.rs",
            [
                0x1b, 0x3b, 0x6a, 0x24, 0x2c, 0x2b, 0xd1, 0x3f, 0xd0, 0x39, 0xe5, 0x93, 0xfa, 0xfb,
                0x12, 0x25,
            ],
        ),
        // src/sync/mpsc/chan.rs, 1.53.0 and 1.53.1
        (
            "src/sync/mpsc/chan.rs",
            [
                0xe5, 0xb1, 0xfe, 0xb2, 0xa3, 0x49, 0x71, 0x84, 0x5c, 0x08, 0x7c, 0x21, 0xa3, 0x4e,
                0x2f, 0x5f,
            ],
        ),
        // src/sync/mpsc/list.rs, 1.47.0 through 1.47.2, 1.48.0
        (
            "src/sync/mpsc/list.rs",
            [
                0x8f, 0x06, 0xc5, 0x57, 0x14, 0xa3, 0xa3, 0x72, 0x7c, 0x27, 0xce, 0x9b, 0x9d, 0x60,
                0x45, 0x64,
            ],
        ),
        // src/sync/mpsc/list.rs, 1.47.3 and 1.47.4
        (
            "src/sync/mpsc/list.rs",
            [
                0xa1, 0x51, 0xdd, 0x61, 0x31, 0x21, 0x85, 0x0f, 0x1e, 0x65, 0xad, 0x41, 0xc0, 0x47,
                0xee, 0x8a,
            ],
        ),
        // src/sync/mpsc/list.rs, 1.47.5
        (
            "src/sync/mpsc/list.rs",
            [
                0x78, 0x0e, 0x9c, 0x9a, 0x6c, 0xfe, 0x41, 0x7f, 0xf2, 0x70, 0xca, 0x1a, 0x08, 0xaf,
                0x68, 0x80,
            ],
        ),
        // src/sync/mpsc/list.rs, 1.49.0 through 1.51.2, 1.52.0 through 1.52.2
        (
            "src/sync/mpsc/list.rs",
            [
                0xea, 0xa2, 0xe2, 0x1a, 0x49, 0x69, 0xf7, 0xb4, 0x1b, 0xa2, 0x3a, 0x50, 0xe4, 0x36,
                0x42, 0x32,
            ],
        ),
        // src/sync/mpsc/list.rs, 1.51.3 and 1.51.4, 1.52.3 through 1.53.1
        (
            "src/sync/mpsc/list.rs",
            [
                0xeb, 0x14, 0xd3, 0xe7, 0x82, 0x6e, 0xd2, 0x67, 0x5c, 0x3b, 0xe0, 0x8f, 0xe4, 0x59,
                0x53, 0xba,
            ],
        ),
        // src/sync/mpsc/list.rs, 1.51.5
        (
            "src/sync/mpsc/list.rs",
            [
                0x03, 0x6f, 0x12, 0x2b, 0xbb, 0xe3, 0x26, 0xc3, 0xac, 0x23, 0x83, 0xd5, 0xfd, 0xac,
                0xbf, 0xd4,
            ],
        ),
        // src/sync/mpsc/block.rs, 1.47.0 through 1.47.4, 1.48.0
        (
            "src/sync/mpsc/block.rs",
            [
                0xfb, 0xf0, 0xa8, 0x5f, 0xe2, 0xd1, 0xf6, 0xa3, 0xf1, 0x50, 0x0a, 0xc7, 0x13, 0x02,
                0x76, 0xdf,
            ],
        ),
        // src/sync/mpsc/block.rs, 1.47.5
        (
            "src/sync/mpsc/block.rs",
            [
                0xb4, 0x0b, 0xd1, 0x5b, 0xcb, 0x81, 0x8d, 0xf1, 0x6a, 0xcd, 0x87, 0x35, 0x23, 0xd9,
                0x25, 0x8f,
            ],
        ),
        // src/sync/mpsc/block.rs, 1.49.0 through 1.51.2, 1.52.0 through 1.52.2
        (
            "src/sync/mpsc/block.rs",
            [
                0xe6, 0x29, 0x91, 0x81, 0x15, 0x30, 0x38, 0x0d, 0xaa, 0xb5, 0xbc, 0xe7, 0xb1, 0x3c,
                0x9c, 0x5a,
            ],
        ),
        // src/sync/mpsc/block.rs, 1.51.3 and 1.51.4, 1.52.3 through 1.53.1
        (
            "src/sync/mpsc/block.rs",
            [
                0xf8, 0xce, 0x09, 0x77, 0xed, 0xa7, 0x41, 0x5d, 0x8f, 0x13, 0xb4, 0x4e, 0x73, 0x61,
                0x49, 0xc6,
            ],
        ),
        // src/sync/mpsc/block.rs, 1.51.5
        (
            "src/sync/mpsc/block.rs",
            [
                0x4d, 0x3c, 0xb0, 0x08, 0x8c, 0xc7, 0x50, 0x01, 0x52, 0x91, 0xdc, 0xea, 0x6a, 0x79,
                0x8a, 0x0b,
            ],
        ),
        // src/sync/task/atomic_waker.rs, 1.47.0 through 1.53.1
        (
            "src/sync/task/atomic_waker.rs",
            [
                0x6c, 0x0e, 0xb2, 0xdd, 0x6b, 0x8e, 0x9d, 0xfd, 0xdb, 0x09, 0x69, 0x81, 0x3b, 0xdd,
                0xc6, 0xd1,
            ],
        ),
    ],
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
    family: "tokio-notified-state-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/sync/notify.rs, 1.47.0 through 1.47.5
        (
            "src/sync/notify.rs",
            [
                0x51, 0x27, 0x05, 0xa0, 0x58, 0xfe, 0x9a, 0x1a, 0xf6, 0x4f, 0x42, 0xba, 0xb4, 0x23,
                0x18, 0x88,
            ],
        ),
        // src/sync/notify.rs, 1.48.0
        (
            "src/sync/notify.rs",
            [
                0x0a, 0x9c, 0x7e, 0xc1, 0x97, 0x2b, 0x3c, 0xfa, 0x93, 0xfa, 0x69, 0x0e, 0xec, 0x17,
                0x6b, 0x41,
            ],
        ),
        // src/sync/notify.rs, 1.49.0 and 1.50.0
        (
            "src/sync/notify.rs",
            [
                0xed, 0xbe, 0xcb, 0xd7, 0xfe, 0x6c, 0x5f, 0xd2, 0x5a, 0x0e, 0xcd, 0x06, 0xb9, 0xec,
                0x54, 0xca,
            ],
        ),
        // src/sync/notify.rs, 1.51.0 through 1.52.4
        (
            "src/sync/notify.rs",
            [
                0x82, 0x8b, 0xaf, 0x96, 0x71, 0x71, 0x37, 0x83, 0x03, 0xb2, 0xcd, 0x2c, 0x7a, 0xf1,
                0x46, 0xae,
            ],
        ),
        // src/sync/notify.rs, 1.53.0 and 1.53.1
        (
            "src/sync/notify.rs",
            [
                0x77, 0xf3, 0x63, 0xb8, 0xd4, 0x2e, 0x62, 0x7b, 0x22, 0x7c, 0x60, 0xdf, 0x1e, 0xa2,
                0xf7, 0xe0,
            ],
        ),
    ],
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
    family: "tokio-oneshot-recv-state-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/sync/oneshot.rs, 1.47.0 through 1.47.5
        (
            "src/sync/oneshot.rs",
            [
                0x6b, 0xa8, 0xe8, 0x59, 0x79, 0x42, 0xa6, 0x8f, 0x68, 0x6e, 0xb9, 0x76, 0x66, 0x77,
                0xd4, 0xfd,
            ],
        ),
        // src/sync/oneshot.rs, 1.48.0
        (
            "src/sync/oneshot.rs",
            [
                0xe2, 0x7b, 0x99, 0x43, 0x5f, 0xee, 0x9b, 0x4d, 0x8e, 0xaf, 0xe7, 0xd7, 0x4d, 0x96,
                0xbf, 0x97,
            ],
        ),
        // src/sync/oneshot.rs, 1.49.0
        (
            "src/sync/oneshot.rs",
            [
                0x72, 0xa7, 0x25, 0x68, 0x4a, 0x5d, 0x1c, 0x41, 0x9b, 0x45, 0x11, 0xd6, 0x1f, 0xe3,
                0x56, 0x7e,
            ],
        ),
        // src/sync/oneshot.rs, 1.50.0 through 1.51.5
        (
            "src/sync/oneshot.rs",
            [
                0xfa, 0x44, 0xb4, 0x9b, 0xfd, 0xed, 0xa9, 0xa3, 0xb6, 0x4c, 0x21, 0x9a, 0x9d, 0x02,
                0x0d, 0x4b,
            ],
        ),
        // src/sync/oneshot.rs, 1.52.0 through 1.52.4
        (
            "src/sync/oneshot.rs",
            [
                0xcf, 0x62, 0x7c, 0xa4, 0xb0, 0xf9, 0x47, 0xfc, 0x35, 0x27, 0x52, 0x7c, 0x9a, 0x61,
                0x9a, 0xb3,
            ],
        ),
        // src/sync/oneshot.rs, 1.53.0 and 1.53.1
        (
            "src/sync/oneshot.rs",
            [
                0xbc, 0x33, 0x05, 0xef, 0x1f, 0x48, 0x03, 0x5a, 0xae, 0x08, 0x93, 0xc6, 0x97, 0x95,
                0xb5, 0xee,
            ],
        ),
    ],
};

/// The tokio futures that acquire a batch semaphore on behalf of a
/// primitive of their own module, tokio 1.47 through 1.53
/// (`sync/mutex.rs`, `sync/rwlock.rs`, `sync/semaphore.rs` and
/// `sync/mpsc/bounded.rs`, each primitive's acquire unchanged across
/// the range): `Mutex::lock` and its owned forms await the mutex's
/// `acquire`, `RwLock`'s read and write forms their `s.acquire(n)`,
/// `Semaphore::acquire` and its many and owned forms `ll_sem.acquire`,
/// and a bounded sender's `send` awaits `reserve`, which awaits
/// `reserve_inner`'s acquire of one slot of the channel's capacity.
/// Every such async fn lies in its primitive's module, so the module's
/// path is the key; the primitive is named as a listing names it.
pub const TOKIO_ACQUIRE_OWNERS_V1_47: AcquireOwners = AcquireOwners {
    family: "tokio-acquire-owners-1.47",
    releases: TOKIO_RELEASES,
    checksums: &[
        // src/sync/mutex.rs, 1.47.0 through 1.47.5
        (
            "src/sync/mutex.rs",
            [
                0x0d, 0x34, 0x22, 0x3d, 0x92, 0xb9, 0xe0, 0xf0, 0xd5, 0xae, 0xac, 0x1a, 0xd5, 0xb3,
                0xdb, 0xd1,
            ],
        ),
        // src/sync/mutex.rs, 1.48.0 through 1.53.1
        (
            "src/sync/mutex.rs",
            [
                0x5a, 0x1f, 0x44, 0x94, 0x02, 0x04, 0xa7, 0xb3, 0x86, 0x47, 0x80, 0x3c, 0x9d, 0x9c,
                0xa2, 0x9f,
            ],
        ),
        // src/sync/rwlock.rs, 1.47.0 through 1.47.4
        (
            "src/sync/rwlock.rs",
            [
                0x1d, 0xfe, 0xee, 0x5d, 0x9b, 0x63, 0x24, 0xe0, 0xb6, 0x8d, 0xa3, 0x0e, 0x32, 0xf2,
                0x81, 0x3e,
            ],
        ),
        // src/sync/rwlock.rs, 1.47.5
        (
            "src/sync/rwlock.rs",
            [
                0x30, 0x40, 0xa8, 0x6b, 0x6f, 0x7d, 0x56, 0x50, 0x7c, 0xc4, 0xc6, 0x51, 0xde, 0xf2,
                0xd6, 0xaa,
            ],
        ),
        // src/sync/rwlock.rs, 1.48.0 and 1.49.0
        (
            "src/sync/rwlock.rs",
            [
                0xc2, 0x07, 0x1f, 0x9e, 0x62, 0x12, 0x21, 0x9f, 0xe3, 0x2a, 0x79, 0x57, 0x52, 0x8b,
                0xa6, 0x37,
            ],
        ),
        // src/sync/rwlock.rs, 1.50.0 through 1.51.2, 1.52.0 through 1.52.2
        (
            "src/sync/rwlock.rs",
            [
                0x36, 0x18, 0x40, 0x46, 0x79, 0x3a, 0xc8, 0x26, 0x66, 0x26, 0xd2, 0xb6, 0x86, 0xce,
                0x74, 0x42,
            ],
        ),
        // src/sync/rwlock.rs, 1.51.3 through 1.51.5, 1.52.3 through 1.53.1
        (
            "src/sync/rwlock.rs",
            [
                0xec, 0x26, 0xe1, 0x57, 0xae, 0x85, 0xa8, 0x43, 0x69, 0xa3, 0x94, 0x21, 0x49, 0xfe,
                0xd7, 0xad,
            ],
        ),
        // src/sync/semaphore.rs, 1.47.0 through 1.47.5
        (
            "src/sync/semaphore.rs",
            [
                0x8d, 0xf3, 0xe5, 0x5d, 0xb7, 0x91, 0x8c, 0x4b, 0x97, 0xb8, 0x84, 0xb6, 0x85, 0xe6,
                0x0b, 0xfb,
            ],
        ),
        // src/sync/semaphore.rs, 1.48.0 through 1.52.4
        (
            "src/sync/semaphore.rs",
            [
                0xb5, 0xe9, 0x5d, 0xf0, 0x9b, 0xa8, 0xec, 0x01, 0x10, 0x52, 0x30, 0xad, 0x56, 0xed,
                0x37, 0xeb,
            ],
        ),
        // src/sync/semaphore.rs, 1.53.0 and 1.53.1
        (
            "src/sync/semaphore.rs",
            [
                0xf9, 0xb0, 0x48, 0xbe, 0xc2, 0x33, 0x45, 0xf1, 0x1f, 0x7f, 0x94, 0x6b, 0xef, 0x04,
                0xc6, 0x44,
            ],
        ),
        // src/sync/mpsc/bounded.rs, 1.47.0 through 1.47.4
        (
            "src/sync/mpsc/bounded.rs",
            [
                0x6f, 0x81, 0x25, 0xb6, 0xd4, 0x8a, 0x58, 0xfa, 0xea, 0xcf, 0x46, 0x7f, 0x24, 0xc6,
                0xb2, 0xb7,
            ],
        ),
        // src/sync/mpsc/bounded.rs, 1.47.5
        (
            "src/sync/mpsc/bounded.rs",
            [
                0xc7, 0xac, 0x30, 0x59, 0xf8, 0x42, 0x4c, 0x08, 0x8f, 0xde, 0x2e, 0xe6, 0x45, 0x8b,
                0xe9, 0xf7,
            ],
        ),
        // src/sync/mpsc/bounded.rs, 1.48.0
        (
            "src/sync/mpsc/bounded.rs",
            [
                0x98, 0xcf, 0x47, 0x65, 0x76, 0x22, 0x4d, 0xca, 0xaf, 0x2b, 0x94, 0xb6, 0x26, 0x99,
                0xde, 0x32,
            ],
        ),
        // src/sync/mpsc/bounded.rs, 1.49.0 through 1.51.2, 1.52.0 through 1.52.2
        (
            "src/sync/mpsc/bounded.rs",
            [
                0x40, 0xbb, 0x34, 0x0d, 0x5a, 0x8b, 0x8d, 0x2b, 0xe1, 0x8b, 0x32, 0x66, 0x85, 0x77,
                0x22, 0xaa,
            ],
        ),
        // src/sync/mpsc/bounded.rs, 1.51.3 and 1.51.4, 1.52.3 and 1.52.4
        (
            "src/sync/mpsc/bounded.rs",
            [
                0x82, 0x2a, 0x1a, 0x86, 0x1a, 0xb3, 0x64, 0x52, 0x99, 0x2c, 0x52, 0xaa, 0xb4, 0x9b,
                0xc2, 0x0d,
            ],
        ),
        // src/sync/mpsc/bounded.rs, 1.51.5
        (
            "src/sync/mpsc/bounded.rs",
            [
                0x4f, 0x18, 0x59, 0x42, 0x0d, 0x5f, 0x2a, 0x61, 0xd3, 0x80, 0xd2, 0xaa, 0x74, 0xb8,
                0x82, 0x51,
            ],
        ),
        // src/sync/mpsc/bounded.rs, 1.53.0 and 1.53.1
        (
            "src/sync/mpsc/bounded.rs",
            [
                0xcf, 0x02, 0x2c, 0x9f, 0x41, 0xaa, 0x45, 0xb3, 0xd9, 0x20, 0xe3, 0x8c, 0xe2, 0xdb,
                0xbe, 0x68,
            ],
        ),
    ],
    owners: &[
        ("tokio::sync::mutex::", "tokio::sync::Mutex"),
        ("tokio::sync::rwlock::", "tokio::sync::RwLock"),
        ("tokio::sync::semaphore::", "tokio::sync::Semaphore"),
        (
            "tokio::sync::mpsc::bounded::",
            "tokio::sync::mpsc bounded channel",
        ),
    ],
};

/// A reviewed map from the modules whose futures acquire a batch
/// semaphore to the primitive each acquires for, at the tokio releases
/// it was read at, with the checksums of the files it read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AcquireOwners {
    /// The review's name, as a warning that it declines names it.
    pub family: &'static str,
    pub releases: Releases,
    /// `(file, md5)` for every reviewed revision of each owner's file,
    /// relative to the crate root.
    pub checksums: &'static [(&'static str, [u8; 16])],
    pub owners: &'static [(&'static str, &'static str)],
}

/// The primitive a future named `name` acquires a batch semaphore for,
/// at a recovered tokio version: `None` for a future in no owner's
/// module, and for any at all where no version was recovered or the
/// review did not read it.
pub fn tokio_acquire_owner(name: &str, version: Option<&semver::Version>) -> Option<&'static str> {
    let owners = &TOKIO_ACQUIRE_OWNERS_V1_47;
    if !owners.releases.covers(version?) {
        return None;
    }
    owners
        .owners
        .iter()
        .find(|(module, _)| name.starts_with(module))
        .map(|(_, primitive)| *primitive)
}

/// The reviewed state protocol for a resource kind at a recovered tokio
/// version: `None` when no version was recovered or the protocol's
/// review did not read it. A layout family is selected regardless; a
/// protocol is not.
pub fn tokio_state_protocol(
    kind: ResourceKind,
    version: Option<&semver::Version>,
) -> Option<&'static StateProtocol> {
    let protocol = match kind {
        ResourceKind::Sleep => &TOKIO_SLEEP_STATE_V1_47,
        ResourceKind::JoinHandle => &TOKIO_JOIN_HANDLE_STATE_V1_47,
        ResourceKind::SemaphoreAcquire => &TOKIO_ACQUIRE_STATE_V1_47,
        // Not tokio's either: a handshake's protocol is the
        // tokio-rustls convention its own rule binds under.
        ResourceKind::IoOperation(IoOperationKind::Handshake) => return None,
        ResourceKind::IoOperation(_) => &TOKIO_IO_STATE_V1_47,
        ResourceKind::MpscRecv => &TOKIO_MPSC_RECV_STATE_V1_47,
        ResourceKind::Notified => &TOKIO_NOTIFIED_STATE_V1_47,
        ResourceKind::OneshotRecv => &TOKIO_ONESHOT_RECV_STATE_V1_47,
        // Not tokio's: the connection's protocol is the hyper
        // convention its own rule binds under.
        ResourceKind::HttpConn => return None,
    };
    protocol.releases.covers(version?).then_some(protocol)
}

/// Every reviewed tokio state protocol.
pub const TOKIO_STATE_PROTOCOLS: [&StateProtocol; 7] = [
    &TOKIO_ACQUIRE_STATE_V1_47,
    &TOKIO_JOIN_HANDLE_STATE_V1_47,
    &TOKIO_SLEEP_STATE_V1_47,
    &TOKIO_IO_STATE_V1_47,
    &TOKIO_MPSC_RECV_STATE_V1_47,
    &TOKIO_NOTIFIED_STATE_V1_47,
    &TOKIO_ONESHOT_RECV_STATE_V1_47,
];

/// A tokio protocol review a recovered version falls outside: the
/// review's name, its range as a warning names it, and whether the
/// version is newer than the range rather than older.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProtocolOutside {
    pub family: &'static str,
    pub range: String,
    pub newer: bool,
}

/// The tokio protocol reviews — every state protocol, and the map of
/// which primitive a batch-semaphore acquire is for — that a recovered
/// version falls outside of. Each binds nothing at that version, though
/// a layout family is selected for it all the same, and an extraction
/// says so. `None` for a version a review of every subject covers.
pub fn tokio_protocols_outside(version: &semver::Version) -> Option<Vec<ProtocolOutside>> {
    let owners = &TOKIO_ACQUIRE_OWNERS_V1_47;
    let reviewed: Vec<Review> = TOKIO_STATE_PROTOCOLS
        .iter()
        .map(|p| (p.family, p.releases))
        .chain([(owners.family, owners.releases)])
        .collect();
    let outside = outside(version, &reviewed);
    (!outside.is_empty()).then_some(outside)
}

/// A review as [`outside`] weighs it: its family and releases.
type Review = (&'static str, Releases);

/// The reviews in `reviewed` of every subject no review covers the
/// version of. A subject a later review covers is not outside. A
/// version between two spans is newer than the one below it, and the
/// range it is told it misses is that span.
fn outside(version: &semver::Version, reviewed: &[Review]) -> Vec<ProtocolOutside> {
    reviewed
        .iter()
        .filter(|(family, ..)| {
            !reviewed.iter().any(|(other, releases)| {
                subject(other) == subject(family) && releases.covers(version)
            })
        })
        .map(|&(family, releases)| ProtocolOutside {
            family,
            range: releases.range_for(version),
            newer: releases.select(version) != LayoutSelection::BelowFloor,
        })
        .collect()
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
        ] {
            assert_eq!(
                rustc_coroutine_convention(producer).map(|c| c.family),
                Some("rustc-coroutine-1.97"),
                "{producer}"
            );
        }
        for producer in [
            "rustc version 1.96.0 (aabb 2026-05-01)",
            // A nightly or beta is none of the releases read.
            "rustc version 1.98.0-nightly (eeff 2026-07-01)",
            "rustc version 1.98.1-beta.2 (eeff 2026-08-30)",
            // A patch past its minor's span, and one between two spans.
            "rustc version 1.98.9 (aabb 2026-12-01)",
            "rustc version 1.97.2 (aabb 2026-09-01)",
            "rustc version 2.999.0 (aabb 2026-10-01)",
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
            assert!(
                rustc_core_pending_convention(producer).is_none(),
                "{producer}"
            );
        }
    }

    /// The adapter, ABI and `Pending` conventions are separate reviews
    /// with their own names, covering the same toolchains as the
    /// coroutine one.
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
        assert_eq!(
            rustc_core_pending_convention(producer).map(|c| c.family),
            Some("rustc-core-pending-1.97")
        );
        let producer = "clang LLVM (rustc version 1.97.0 (2d8144b78 2026-07-07))";
        assert!(rustc_std_adapter_convention(producer).is_some());
        assert!(rustc_dyn_future_abi_convention(producer).is_some());
        assert!(rustc_core_pending_convention(producer).is_some());
    }

    /// Only a compiler newer than a convention's review outgrows it —
    /// one older is the floor warning's to name — and the subject a
    /// later review would share is the family name less its version.
    #[test]
    fn test_rustc_conventions_outgrown_by_a_newer_compiler_only() {
        let (version, outgrown) =
            rustc_conventions_outgrown("clang LLVM (rustc version 2.999.0 (aabb 2026-10-01))")
                .expect("2.999 outgrows the reviews");
        assert_eq!(version, semver::Version::new(2, 999, 0));
        assert_eq!(
            outgrown.iter().map(|c| c.family).collect::<Vec<_>>(),
            RUSTC_CONVENTIONS.map(|c| c.family),
            "2.999 is newer than every review"
        );
        // A patch released into a reviewed minor after its review is
        // outgrown like a newer minor, against what was read of it.
        let (version, outgrown) =
            rustc_conventions_outgrown("rustc version 1.97.2 (aabb 2026-09-01)")
                .expect("an unread 1.97 patch outgrows the reviews");
        assert_eq!(outgrown.len(), RUSTC_CONVENTIONS.len());
        assert_eq!(
            RUSTC_COROUTINE_V1_97.releases.range_for(&version),
            "1.97.0-1.97.1"
        );
        // A nightly of a reviewed release is outgrown like an unread
        // patch, placed before its minor's span.
        let (version, _) =
            rustc_conventions_outgrown("rustc version 1.98.0-nightly (eeff 2026-07-01)")
                .expect("a nightly outgrows the reviews");
        assert_eq!(
            RUSTC_COROUTINE_V1_97.releases.range_for(&version),
            "1.98.0-1.98.1"
        );
        assert_eq!(
            RUSTC_COROUTINE_V1_97.releases.select(&version),
            LayoutSelection::BelowFloor
        );
        for producer in [
            "rustc version 1.97.0 (2d8144b78 2026-07-07)",
            "rustc version 1.96.0 (aabb 2026-05-01)",
            "GNU C17 14.2.0 -mtune=generic -g",
            "rustc version 1.98",
        ] {
            assert_eq!(rustc_conventions_outgrown(producer), None, "{producer}");
        }
        assert_eq!(RUSTC_COROUTINE_V1_97.subject(), "rustc-coroutine");
        assert_eq!(
            RUSTC_STD_FUTEX_MUTEX_V1_97.subject(),
            "rustc-std-futex-mutex"
        );
        assert_eq!(RUSTC_COROUTINE_V1_97.range(), "1.97.0-1.98.1");
        assert_eq!(rustc_reviewed_range(), "1.97.0-1.98.1");
    }

    /// A later review of one subject keeps that subject covered, and
    /// only that one: beside a coroutine review reaching 2.999, a 2.999
    /// compiler outgrows the adapter review alone, and a 3.0 compiler
    /// outgrows both coroutine reviews as well.
    #[test]
    fn test_a_later_review_covers_its_own_subject_only() {
        const COROUTINE_V2_999: RustcConvention = RustcConvention {
            family: "rustc-coroutine-2.999",
            releases: Releases(&[((2, 999, 0), (2, 999, 0))]),
            checksums: &[],
        };
        let reviewed = [
            &RUSTC_COROUTINE_V1_97,
            &COROUTINE_V2_999,
            &RUSTC_STD_ADAPTERS_V1_97,
        ];
        let families = |producer: &str| {
            outgrown(producer, &reviewed)
                .map(|(_, outgrown)| outgrown.iter().map(|c| c.family).collect::<Vec<_>>())
        };
        assert_eq!(
            families("rustc version 2.999.0 (aabb 2026-10-01)"),
            Some(vec!["rustc-std-adapters-1.97"])
        );
        assert_eq!(
            families("rustc version 3.0.0 (aabb 2027-01-01)"),
            Some(vec![
                "rustc-coroutine-1.97",
                "rustc-coroutine-2.999",
                "rustc-std-adapters-1.97"
            ])
        );
        assert_eq!(families("rustc version 1.98.0 (aabb 2026-08-18)"), None);
    }

    /// Every tokio protocol review is outside a version past either
    /// edge of its releases, on the side the version falls, and outside
    /// a patch released into a reviewed minor after its review, named
    /// against what was read of that minor; none is at a reviewed
    /// release.
    #[test]
    fn test_tokio_protocols_are_outside_a_version_past_their_range() {
        let v = |s: &str| semver::Version::parse(s).unwrap();
        let every = TOKIO_STATE_PROTOCOLS
            .iter()
            .map(|p| p.family)
            .chain([TOKIO_ACQUIRE_OWNERS_V1_47.family]);
        for (version, range, newer) in [
            ("1.54.0", "1.47.0-1.53.1", true),
            ("1.53.2", "1.53.0-1.53.1", true),
            ("1.51.6", "1.51.0-1.51.5", true),
            // Past the later of a split minor's two spans.
            ("1.52.5", "1.52.1-1.52.4", true),
            ("1.46.3", "1.47.0-1.53.1", false),
        ] {
            assert_eq!(
                tokio_protocols_outside(&v(version)),
                Some(
                    every
                        .clone()
                        .map(|family| ProtocolOutside {
                            family,
                            range: range.to_owned(),
                            newer,
                        })
                        .collect()
                ),
                "{version}"
            );
        }
        for version in [
            "1.47.0", "1.47.5", "1.48.0", "1.51.4", "1.52.0", "1.52.1", "1.53.1",
        ] {
            assert_eq!(tokio_protocols_outside(&v(version)), None, "{version}");
        }
    }

    /// A later review of one tokio protocol keeps that protocol inside
    /// and only that one: beside a sleep review reaching 1.54, a 1.54
    /// version is outside the io review alone.
    #[test]
    fn test_a_later_protocol_review_covers_its_own_subject_only() {
        let through_1_53 = Releases(&[((1, 47, 0), (1, 53, 9))]);
        let reviewed: [Review; 3] = [
            ("tokio-sleep-state-1.47", through_1_53),
            (
                "tokio-sleep-state-1.54",
                Releases(&[((1, 54, 0), (1, 55, 9))]),
            ),
            ("tokio-io-state-1.47", through_1_53),
        ];
        let families = |version: &str| -> Vec<&str> {
            outside(&semver::Version::parse(version).unwrap(), &reviewed)
                .iter()
                .map(|o| o.family)
                .collect()
        };
        assert_eq!(families("1.54.0"), ["tokio-io-state-1.47"]);
        assert_eq!(
            families("1.56.0"),
            [
                "tokio-sleep-state-1.47",
                "tokio-sleep-state-1.54",
                "tokio-io-state-1.47"
            ]
        );
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
                &HYPER_UTIL_AUTO_CONN_V0_1_10,
                ["0.1.10", "0.1.12", "0.1.15", "0.1.20"].as_slice(),
                "0.1.9",
                "0.1.21",
            ),
            (
                &HYPER_UTIL_POOL_V0_1_16,
                ["0.1.16", "0.1.17", "0.1.18", "0.1.19", "0.1.20"].as_slice(),
                "0.1.15",
                "0.1.21",
            ),
            (
                &HYPER_UTIL_RESPONSE_V0_1_10,
                ["0.1.10", "0.1.15", "0.1.20"].as_slice(),
                "0.1.9",
                "0.1.21",
            ),
            (
                &TOWER_RETRY_V0_5_2,
                ["0.5.2", "0.5.3"].as_slice(),
                "0.5.1",
                "0.5.4",
            ),
            (
                &REQWEST_COOKIE_V0_12_24,
                ["0.12.24", "0.12.28", "0.13.0", "0.13.2", "0.13.4"].as_slice(),
                "0.12.23",
                "0.13.5",
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
            (
                &TOKIO_INTERVAL_TICK_V1_47,
                ["1.47.0", "1.47.5", "1.48.0", "1.52.4", "1.53.0", "1.53.1"].as_slice(),
                "1.46.1",
                "1.53.2",
            ),
            (
                &HYPER_H1_CONN_V1_6_0,
                [
                    "1.6.0", "1.7.0", "1.8.0", "1.8.1", "1.9.0", "1.10.0", "1.10.1",
                ]
                .as_slice(),
                "1.5.2",
                "1.11.0",
            ),
            (
                &DROPSHOT_SERVER_V0_17_0,
                ["0.17.0", "0.17.1"].as_slice(),
                "0.16.7",
                "0.17.2",
            ),
            (
                &REQWEST_PENDING_REQUEST_V0_12_0,
                [
                    "0.12.0", "0.12.19", "0.12.20", "0.12.28", "0.13.0", "0.13.2",
                ]
                .as_slice(),
                "0.11.27",
                "0.13.3",
            ),
            (
                &HTTP_REQUEST_V1_0_0,
                ["1.0.0", "1.1.0", "1.2.0", "1.3.1", "1.4.2"].as_slice(),
                "0.2.12",
                "1.5.0",
            ),
            (
                &DROPSHOT_HANDLER_V0_17_0,
                ["0.17.0", "0.17.1"].as_slice(),
                "0.16.7",
                "0.17.2",
            ),
            (
                &TOKIO_RUSTLS_STREAM_V0_26_0,
                ["0.26.0", "0.26.3", "0.26.6"].as_slice(),
                "0.25.0",
                "0.26.7",
            ),
            (
                &HYPER_UTIL_IO_V0_1_10,
                ["0.1.10", "0.1.15", "0.1.20"].as_slice(),
                "0.1.9",
                "0.1.21",
            ),
            (
                &REQWEST_CONN_V0_12_14,
                ["0.12.14", "0.12.28", "0.13.5"].as_slice(),
                "0.12.13",
                "0.13.6",
            ),
            (
                &HYPER_RUSTLS_STREAM_V0_27_0,
                ["0.27.0", "0.27.7", "0.27.10"].as_slice(),
                "0.26.0",
                "0.27.11",
            ),
            (
                &TOKIO_RUSTLS_HANDSHAKE_V0_26_0,
                ["0.26.0", "0.26.3", "0.26.6"].as_slice(),
                "0.25.0",
                "0.26.7",
            ),
            (
                &RUSTLS_SESSION_V0_23_23,
                ["0.23.23", "0.23.41", "0.23.45"].as_slice(),
                "0.23.22",
                "0.23.46",
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
        assert_eq!(TRACING_INSTRUMENTED_V0_1_40.range(), "0.1.40-0.1.44");
        assert_eq!(FUTURES_UTIL_ADAPTERS_V0_3_30.range(), "0.3.30-0.3.34");
        assert_eq!(HYPER_UTIL_TOKIO_SLEEP_V0_1_10.range(), "0.1.10-0.1.20");
        assert_eq!(TOKIO_STREAM_WATCH_V0_1_14.range(), "0.1.14-0.1.19");
        assert_eq!(TOKIO_UTIL_REUSABLE_BOX_V0_7_11.range(), "0.7.11-0.7.19");
        assert_eq!(TOKIO_INTERVAL_TICK_V1_47.range(), "1.47.0-1.53.1");
        // Seven files reviewed at seven releases: every revision of
        // each is listed once.
        assert_eq!(HYPER_H1_CONN_V1_6_0.range(), "1.6.0-1.10.1");
        assert_eq!(HYPER_H1_CONN_V1_6_0.checksums.len(), 29);
        // Six revisions of the auto module and two of the rewind across
        // eleven releases, none shared with the sleep's file.
        assert_eq!(HYPER_UTIL_AUTO_CONN_V0_1_10.range(), "0.1.10-0.1.20");
        assert_eq!(HYPER_UTIL_AUTO_CONN_V0_1_10.checksums.len(), 8);
        assert_eq!(DROPSHOT_SERVER_V0_17_0.range(), "0.17.0-0.17.1");
        assert_eq!(DROPSHOT_SERVER_V0_17_0.checksums.len(), 2);
        assert_eq!(REQWEST_PENDING_REQUEST_V0_12_0.range(), "0.12.0-0.13.2");
        assert_eq!(REQWEST_PENDING_REQUEST_V0_12_0.checksums.len(), 24);
        assert_eq!(HTTP_REQUEST_V1_0_0.range(), "1.0.0-1.4.2");
        assert_eq!(HTTP_REQUEST_V1_0_0.checksums.len(), 27);
        assert_eq!(DROPSHOT_HANDLER_V0_17_0.range(), "0.17.0-0.17.1");
        assert_eq!(DROPSHOT_HANDLER_V0_17_0.checksums.len(), 2);
        for (_, checksum) in HYPER_UTIL_TOKIO_SLEEP_V0_1_10.checksums {
            assert!(!HYPER_UTIL_AUTO_CONN_V0_1_10.reviewed_checksum(checksum));
        }
        // Three revisions of `interval.rs` in the range, none shared
        // with the select's file.
        assert_eq!(TOKIO_INTERVAL_TICK_V1_47.checksums.len(), 3);
        for (_, checksum) in TOKIO_SELECT_V1_47.checksums {
            assert!(!TOKIO_INTERVAL_TICK_V1_47.reviewed_checksum(checksum));
        }
    }

    /// A checkout's abbreviation names the one reviewed revision it
    /// begins: none for an unreviewed revision, and none where it is
    /// too short to tell two reviewed revisions apart.
    #[test]
    fn test_a_git_convention_names_one_reviewed_revision() {
        const TWINS: GitConvention = GitConvention {
            revisions: &[("abc1234000", [0; 16]), ("abc1234fff", [1; 16])],
            ..SPROCKETS_TLS_STREAM_D2B68E4
        };
        assert_eq!(
            TWINS.reviewed_revision("abc1234f").map(|r| r.0),
            Some("abc1234fff")
        );
        assert_eq!(TWINS.reviewed_revision("abc1234"), None);
        assert_eq!(TWINS.reviewed_revision("abc1235"), None);
        let reviewed = &SPROCKETS_TLS_STREAM_D2B68E4;
        assert_eq!(
            reviewed.reviewed_revision("a233079").map(|r| r.0),
            Some(reviewed.revisions[2].0)
        );
        assert_eq!(reviewed.reviewed_revision("a233078"), None);
    }

    /// A state protocol binds inside its reviewed tokio range and for
    /// no other version — not below the floor, not above the ceiling,
    /// and never for a target whose version was not recovered, however
    /// its layouts bound.
    #[test]
    fn test_state_protocols_bind_only_inside_the_reviewed_tokio_range() {
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
            for version in ["1.47.0", "1.47.5", "1.49.0", "1.51.0", "1.52.4", "1.53.1"] {
                assert_eq!(
                    tokio_state_protocol(kind, Some(&v(version))).map(|p| p.kind),
                    Some(rule),
                    "{kind:?} at {version}"
                );
            }
            for version in ["1.46.9", "1.51.6", "1.52.5", "1.53.2", "1.54.0", "2.0.0"] {
                assert_eq!(
                    tokio_state_protocol(kind, Some(&v(version))),
                    None,
                    "{kind:?} at {version}"
                );
            }
            assert_eq!(tokio_state_protocol(kind, None), None, "{kind:?}");
        }
        // Neither a connection nor a handshake is tokio's: each is its
        // own crate's rule, at every tokio version.
        for kind in [
            ResourceKind::HttpConn,
            ResourceKind::IoOperation(IoOperationKind::Handshake),
        ] {
            assert_eq!(tokio_state_protocol(kind, Some(&v("1.47.5"))), None);
        }
    }

    /// An acquire's owner is named by its module at the reviewed tokio
    /// releases, floor and ceiling included, and for no version outside
    /// them — an unread patch of a reviewed minor among them — or
    /// unrecovered.
    #[test]
    fn test_acquire_owners_bind_only_inside_the_reviewed_tokio_range() {
        let v = |s: &str| semver::Version::parse(s).unwrap();
        let lock = "tokio::sync::mutex::{impl#3}::lock::{async_fn_env#0}<u32>";
        for version in ["1.47.0", "1.49.0", "1.51.2", "1.53.0", "1.53.1"] {
            assert_eq!(
                tokio_acquire_owner(lock, Some(&v(version))),
                Some("tokio::sync::Mutex"),
                "{version}"
            );
        }
        for version in [
            "1.46.9", "1.51.6", "1.52.5", "1.53.2", "1.54.0", "0.47.0", "2.47.0",
        ] {
            assert_eq!(
                tokio_acquire_owner(lock, Some(&v(version))),
                None,
                "{version}"
            );
        }
        assert_eq!(tokio_acquire_owner(lock, None), None);
        let send = "tokio::sync::mpsc::bounded::{impl#3}::send::{async_fn_env#0}<u32>";
        assert_eq!(
            tokio_acquire_owner(send, Some(&v("1.52.4"))),
            Some("tokio::sync::mpsc bounded channel")
        );
        let sleep = "tokio::time::sleep::Sleep";
        assert_eq!(tokio_acquire_owner(sleep, Some(&v("1.52.4"))), None);
    }
}

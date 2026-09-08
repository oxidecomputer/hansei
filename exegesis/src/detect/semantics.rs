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

use crate::bundle::LayoutSelection;
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

/// The reviewed `Instrumented` implementation a tracing version selects,
/// or which side of the reviewed range it falls on.
pub fn tracing_instrumented_convention(
    version: &semver::Version,
) -> Result<&'static LibraryConvention, LayoutSelection> {
    let convention = &TRACING_INSTRUMENTED_V0_1_40;
    match convention.select(version) {
        LayoutSelection::ReviewedRange => Ok(convention),
        outside => Err(outside),
    }
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

    /// The tracing family binds at both edges of its range inclusive and
    /// names the side a version outside falls on; a checksum is reviewed
    /// only if it is one of the listed revisions.
    #[test]
    fn test_tracing_family_selects_by_exact_version_and_checksum() {
        let v = |s: &str| semver::Version::parse(s).unwrap();
        for version in ["0.1.40", "0.1.41", "0.1.42", "0.1.43", "0.1.44"] {
            assert_eq!(
                tracing_instrumented_convention(&v(version)).map(|c| c.family),
                Ok("tracing-instrumented-0.1.40"),
                "{version}"
            );
        }
        assert_eq!(
            tracing_instrumented_convention(&v("0.1.39")),
            Err(LayoutSelection::BelowFloor)
        );
        assert_eq!(
            tracing_instrumented_convention(&v("0.1.45")),
            Err(LayoutSelection::AboveReviewedRange)
        );
        assert_eq!(
            tracing_instrumented_convention(&v("0.2.0")),
            Err(LayoutSelection::AboveReviewedRange)
        );
        assert_eq!(
            tracing_instrumented_convention(&v("1.0.0-alpha")),
            Err(LayoutSelection::AboveReviewedRange)
        );
        let family = &TRACING_INSTRUMENTED_V0_1_40;
        assert_eq!(family.range(), "0.1.40–0.1.44");
        assert!(family.reviewed_checksum(&family.checksums[0].1));
        assert!(family.reviewed_checksum(&family.checksums[1].1));
        assert!(!family.reviewed_checksum(&[0; 16]));
    }
}

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

/// The coroutine convention a producer string is covered by, if any:
/// rustc's own producer grammar, a parseable version, inside one
/// reviewed range. Any other producer — another compiler, a version
/// outside every range, an unparseable token — has none.
pub fn rustc_coroutine_convention(producer: &str) -> Option<&'static RustcConvention> {
    let version = rustc_version(producer)?;
    let version = (version.major, version.minor);
    [&RUSTC_COROUTINE_V1_97]
        .into_iter()
        .find(|c| version >= c.floor && version <= c.ceiling)
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
        }
    }
}

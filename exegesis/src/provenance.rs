// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Type-local compiler evidence for extraction-time semantic binding.
//! This module selects no production convention: a reviewed rule supplies its
//! own selector, independently of display formatter version fallbacks.

use crate::TypeId;
use crate::reader::{DwReader, OriginId, UnitOrigin};

use semver::Version;

/// Why a type cannot use one convention shared by all its definitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginDecline {
    MissingDefinitions,
    MissingUnit(TypeId),
    MissingProducer(OriginId),
    Unsupported(OriginId),
    Conflict { first: OriginId, other: OriginId },
}

/// Parse the version token in rustc's producer grammar, never arbitrary digits
/// in another compiler's identification. rustc's LLVM backend writes
/// `clang LLVM (rustc version X (hash date))`; the bare `rustc version X …`
/// form is accepted too. Both are anchored at the front, so a producer that
/// merely mentions rustc somewhere is not one. Build/vendor suffixes remain
/// in the original interned producer; semver prerelease/build qualifiers
/// remain here. Parsing identifies a compiler version, not a supported
/// semantic convention.
pub fn rustc_version(producer: &str) -> Option<Version> {
    let rest = producer
        .strip_prefix("clang LLVM (rustc version ")
        .or_else(|| producer.strip_prefix("rustc version "))?;
    let token = rest.split_whitespace().next()?;
    let token = token.strip_suffix(')').unwrap_or(token);
    Version::parse(token).ok()
}

impl DwReader<'_> {
    /// Select one convention only if every defining CU independently supports
    /// it. Unrelated units and declaration CUs are never consulted. The rule's
    /// selector must enforce its reviewed inclusive version bounds and source
    /// requirements; shape, a successful version parse, and newest-family
    /// display fallback cannot authorize polling or initialized-storage access.
    ///
    /// Callers can retain sparse candidate evidence using `type_definitions`
    /// and `die_origin`; the reader does not allocate semantic records for all
    /// types. A decline leaves identity evidence available to other bindings.
    pub fn type_convention<K: Eq>(
        &self,
        ty: TypeId,
        mut select: impl FnMut(OriginId, &UnitOrigin) -> Option<K>,
    ) -> Result<K, OriginDecline> {
        let mut agreed = None;
        for die in self.type_definitions(ty) {
            let (id, origin) = self
                .die_origin(die.0)
                .ok_or(OriginDecline::MissingUnit(die))?;
            if origin.producer.is_none() {
                return Err(OriginDecline::MissingProducer(id));
            }
            let convention = select(id, origin).ok_or(OriginDecline::Unsupported(id))?;
            match &agreed {
                Some((first, previous)) if previous != &convention => {
                    return Err(OriginDecline::Conflict {
                        first: *first,
                        other: id,
                    });
                }
                None => agreed = Some((id, convention)),
                _ => {}
            }
        }
        agreed
            .map(|(_, convention)| convention)
            .ok_or(OriginDecline::MissingDefinitions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rustc_version_requires_the_compiler_prefix_and_whole_token() {
        for (producer, expected) in [
            (
                "clang LLVM (rustc version 1.98.0 (88d9e12ae 2026-08-18))",
                "1.98.0",
            ),
            ("clang LLVM (rustc version 1.97.0)", "1.97.0"),
            ("rustc version 1.97.0 (aabb 2026-07-01)", "1.97.0"),
            (
                "rustc version 1.97.1 (ccdd 2026-07-08) vendor release",
                "1.97.1",
            ),
            (
                "rustc version 1.98.0-vendor.2+patched (eeff 2026-08-18)",
                "1.98.0-vendor.2+patched",
            ),
        ] {
            assert_eq!(
                rustc_version(producer),
                Some(Version::parse(expected).unwrap())
            );
        }
        for producer in [
            "GNU C17 14.2.0",
            "GNU C17 1.98.0 rustc version 1.98.0",
            "clang LLVM (rustc version )",
            "clang LLVM (vendor rustc version 1.98.0)",
            "clang version 19.1.0 (rustc version 1.98.0)",
            "clang version 1.98.0",
            "vendor rustc version 1.98.0",
            "rustc version ",
            "rustc version v1.98.0",
            "rustc version 1.98",
            "rustc version 1.98.0garbage",
            "rustc version 01.98.0",
        ] {
            assert_eq!(rustc_version(producer), None, "{producer}");
        }
    }
}

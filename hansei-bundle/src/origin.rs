// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The cargo registry path convention a third-party delegation rule reads
//! its origin from.
//!
//! A crate cargo fetched from a registry is unpacked under
//! `<CARGO_HOME>/registry/src/<index>/<crate>-<version>/`, and every
//! declaration file rustc records for it keeps that path. The crate name
//! and version in the directory are the evidence a reviewed third-party
//! rule selects its family by: which review applies. They are not source
//! authentication — a patched crate at an unchanged registry version is
//! indistinguishable from the reviewed one, a limit accepted and named
//! where the rules are declared. A path outside that convention — a
//! `vendor/` tree, a git checkout, a path dependency — carries no version
//! a review can be matched to and declines.

use semver::Version;

/// The registry segment every accepted path is anchored at.
pub const REGISTRY_SEGMENT: &str = "registry/src/";

/// What a registry path says about the crate a file belongs to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistryOrigin<'a> {
    /// The registry index directory (`index.crates.io-<hash>`).
    pub index: &'a str,
    /// The crate name, exactly as the directory spells it.
    pub package: &'a str,
    /// The crate version the directory spells.
    pub version: Version,
    /// The path from its `registry/src/` segment on — the host-independent
    /// tail a bundle records, so a reader can re-parse it with this same
    /// function.
    pub path: &'a str,
}

/// Parse a declaration file's path under the registry convention, or
/// `None` for any path that does not follow it exactly. The path may be
/// absolute (as a line table records it) or already cut to its
/// `registry/src/` tail (as a bundle records it). The crate directory
/// must be `<crate>-<semver>` with a nonempty crate name and a version
/// `semver` accepts whole; a `vendor/`, `git/checkouts/` or workspace path
/// has no such segment and is not an origin.
pub fn registry_origin(path: &str) -> Option<RegistryOrigin<'_>> {
    let tail = match path.strip_prefix(REGISTRY_SEGMENT) {
        Some(tail) => tail,
        None => {
            let (_, tail) = path.split_once(&format!("/{REGISTRY_SEGMENT}"))?;
            tail
        }
    };
    let anchored = &path[path.len() - tail.len() - REGISTRY_SEGMENT.len()..];
    let (index, rest) = tail.split_once('/')?;
    let (dir, file) = rest.split_once('/')?;
    if index.is_empty() || file.is_empty() {
        return None;
    }
    // A crate name may itself contain `-`, and a prerelease version may
    // too: the split is at the first `-` whose right side is a whole
    // version, which a crate name's segments (no digits-and-dots tokens
    // semver accepts) never are.
    for (at, _) in dir.match_indices('-') {
        let (package, version) = (&dir[..at], &dir[at + 1..]);
        if package.is_empty() {
            continue;
        }
        if let Ok(version) = Version::parse(version) {
            return Some(RegistryOrigin {
                index,
                package,
                version,
                path: anchored,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_origin_parses_crate_and_version_from_the_anchored_path() {
        let absolute = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tracing-0.1.40/src/instrument.rs";
        let origin = registry_origin(absolute).unwrap();
        assert_eq!(origin.index, "index.crates.io-1949cf8c6b5b557f");
        assert_eq!(origin.package, "tracing");
        assert_eq!(origin.version, Version::new(0, 1, 40));
        assert_eq!(
            origin.path,
            "registry/src/index.crates.io-1949cf8c6b5b557f/tracing-0.1.40/src/instrument.rs"
        );
        // The recorded tail re-parses to the same origin.
        assert_eq!(registry_origin(origin.path).unwrap(), origin);
        // Hyphenated crate names and prerelease versions split at the
        // first `-` whose right side is a whole version.
        let origin =
            registry_origin("registry/src/idx/tracing-core-0.1.33-beta.1/src/lib.rs").unwrap();
        assert_eq!(origin.package, "tracing-core");
        assert_eq!(origin.version, Version::parse("0.1.33-beta.1").unwrap());
    }

    #[test]
    fn test_registry_origin_declines_every_other_layout() {
        for path in [
            // Vendored, git and path dependencies: no registry segment.
            "/build/vendor/tracing-0.1.40/src/instrument.rs",
            "/home/u/.cargo/git/checkouts/tracing-1a2b3c4d5e6f7a8b/0123abc/tracing/src/instrument.rs",
            "/home/u/tracing/src/instrument.rs",
            "src/instrument.rs",
            // A registry segment with a malformed crate directory.
            "registry/src/idx/tracing-0.1/src/instrument.rs",
            "registry/src/idx/tracing/src/instrument.rs",
            "registry/src/idx/-0.1.40/src/instrument.rs",
            "registry/src/idx/tracing-0.1.40",
            "registry/src/idx/tracing-0.1.40/",
            "registry/src//tracing-0.1.40/src/instrument.rs",
            // The segment has to be a whole path component.
            "/home/u/myregistry/src/idx/tracing-0.1.40/src/instrument.rs",
            "",
        ] {
            assert!(registry_origin(path).is_none(), "{path}");
        }
    }
}

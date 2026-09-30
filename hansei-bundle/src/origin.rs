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
//! `vendor/` tree, a path dependency — carries no version a review can be
//! matched to and declines.
//!
//! A crate cargo fetched from git has no release to name; it is checked
//! out under `<CARGO_HOME>/git/checkouts/<repository>-<hash>/<revision>/`,
//! and the repository and the revision are what a review of it names
//! ([`git_origin`]). Every revision is a review of its own.

use semver::Version;

/// The git checkout segment every accepted git path is anchored at.
pub const GIT_SEGMENT: &str = "git/checkouts/";

/// What a git checkout path says about the source a file belongs to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GitOrigin<'a> {
    /// The repository's name, as cargo names its checkout directory:
    /// the last component of its URL.
    pub repository: &'a str,
    /// The checked-out revision, as cargo abbreviates it.
    pub revision: &'a str,
    /// The file's path inside the repository.
    pub file: &'a str,
    /// The path from its `git/checkouts/` segment on — the
    /// host-independent tail a bundle records.
    pub path: &'a str,
}

/// Parse a declaration file's path under cargo's git checkout
/// convention, or `None` for any path that does not follow it exactly:
/// `git/checkouts/<repository>-<16 hex digits>/<revision>/<file>`, the
/// revision at least seven hex digits, the file nonempty. Like
/// [`registry_origin`], the path may be absolute or already cut to its
/// anchored tail.
pub fn git_origin(path: &str) -> Option<GitOrigin<'_>> {
    let tail = match path.strip_prefix(GIT_SEGMENT) {
        Some(tail) => tail,
        None => {
            let (_, tail) = path.split_once(&format!("/{GIT_SEGMENT}"))?;
            tail
        }
    };
    let anchored = &path[path.len() - tail.len() - GIT_SEGMENT.len()..];
    let (checkout, rest) = tail.split_once('/')?;
    let (revision, file) = rest.split_once('/')?;
    let (repository, hash) = checkout.rsplit_once('-')?;
    let hex = |s: &str| s.bytes().all(|b| b.is_ascii_hexdigit());
    if repository.is_empty()
        || hash.len() != 16
        || !hex(hash)
        || revision.len() < 7
        || !hex(revision)
        || file.is_empty()
    {
        return None;
    }
    Some(GitOrigin {
        repository,
        revision,
        file,
        path: anchored,
    })
}

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
    /// The file's path inside the crate.
    pub file: &'a str,
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
                file,
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
        assert_eq!(origin.file, "src/instrument.rs");
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

    #[test]
    fn test_git_origin_parses_repository_and_revision_from_the_anchored_path() {
        let absolute =
            "/home/u/.cargo/git/checkouts/sprockets-882d17aeeb0cb343/a233079/tls/src/lib.rs";
        let origin = git_origin(absolute).unwrap();
        assert_eq!(origin.repository, "sprockets");
        assert_eq!(origin.revision, "a233079");
        assert_eq!(origin.file, "tls/src/lib.rs");
        assert_eq!(
            origin.path,
            "git/checkouts/sprockets-882d17aeeb0cb343/a233079/tls/src/lib.rs"
        );
        assert_eq!(git_origin(origin.path).unwrap(), origin);
        // A hyphenated repository keeps every hyphen but the hash's.
        let origin =
            git_origin("git/checkouts/dice-util-fe337d7974b37b1f/4a39ef0/dice-mfg-msgs/src/lib.rs")
                .unwrap();
        assert_eq!(origin.repository, "dice-util");
        assert_eq!(origin.revision, "4a39ef0");
    }

    #[test]
    fn test_git_origin_declines_every_other_layout() {
        for path in [
            // Registry, vendored and path dependencies.
            "/home/u/.cargo/registry/src/idx/tracing-0.1.40/src/instrument.rs",
            "/build/vendor/sprockets/tls/src/lib.rs",
            "src/lib.rs",
            // A checkout directory without its hash, or with a short one.
            "git/checkouts/sprockets/a233079/tls/src/lib.rs",
            "git/checkouts/sprockets-882d17aeeb0cb34/a233079/tls/src/lib.rs",
            "git/checkouts/-882d17aeeb0cb343/a233079/tls/src/lib.rs",
            // A revision too short, or not hex; no file under it.
            "git/checkouts/sprockets-882d17aeeb0cb343/a23307/tls/src/lib.rs",
            "git/checkouts/sprockets-882d17aeeb0cb343/main/tls/src/lib.rs",
            "git/checkouts/sprockets-882d17aeeb0cb343/a233079/",
            "git/checkouts/sprockets-882d17aeeb0cb343/a233079",
            // The segment has to be a whole path component.
            "/home/u/.cargo/mygit/checkouts/sprockets-882d17aeeb0cb343/a233079/tls/src/lib.rs",
        ] {
            assert!(git_origin(path).is_none(), "{path}");
        }
    }
}

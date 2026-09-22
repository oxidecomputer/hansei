// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Source-location plumbing: owned copies of DWARF locations, the display
//! path a reader sees (crate-cache and toolchain prefixes stripped), and
//! the versions recovered from producer strings and registry paths.

use super::RUSTC_FLOOR;
use crate::bundle::{SourceLoc, StringInterner, strip_build_prefix};
use crate::view::SourceLocView;

/// `Some(version)` when the producer string names a rustc older than
/// [`RUSTC_FLOOR`]. A producer that carries no parseable version (a
/// non-rustc binary, say) is not "below" anything — no warning.
pub(super) fn rustc_below_floor(rustc_version: &str) -> Option<String> {
    let floor = semver::Version::parse(RUSTC_FLOOR).expect("RUSTC_FLOOR parses");
    let ver = semver::Version::parse(rustc_version.split_whitespace().next()?).ok()?;
    (ver < floor).then(|| ver.to_string())
}

/// An owned copy of a source location.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct OwnedLoc {
    pub(super) file: Option<String>,
    pub(super) dir: Option<String>,
    pub(super) comp_dir: Option<String>,
    pub(super) line: Option<u64>,
}

pub(super) fn owned_loc(l: &SourceLocView<'_>) -> OwnedLoc {
    OwnedLoc {
        file: l.file().map(str::to_owned),
        dir: l.dir().map(str::to_owned),
        comp_dir: l.comp_dir().map(str::to_owned),
        line: l.line().map(|n| n.get()),
    }
}

impl OwnedLoc {
    /// The location as the bundle records it: the file cut to its
    /// display path and interned, the line as `u32`. `None` without
    /// both a file and a line — a site with only a file is dropped,
    /// never half-recorded.
    pub(super) fn bundle_loc(&self, strings: &mut StringInterner) -> Option<SourceLoc> {
        let (file, line) = self.site()?;
        Some(SourceLoc {
            file: strings.intern(&file),
            line: line as u32,
        })
    }

    /// The location's display path and line — its identity to the
    /// bundle — or `None` without both a file and a line.
    fn site(&self) -> Option<(String, u64)> {
        let (Some(file), Some(line)) = (self.file.as_deref(), self.line) else {
            return None;
        };
        Some((
            display_path(self.comp_dir.as_deref(), self.dir.as_deref(), file),
            line,
        ))
    }
}

/// What several declarations of one thing agree on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Agreement<'a> {
    /// Every placed declaration names this site.
    Site(&'a OwnedLoc),
    /// No declaration carries both a file and a line.
    Unplaced,
    /// Two placed declarations name different sites: a wrong line is
    /// worse than none, so nothing is recorded.
    Disagreed,
}

/// The site several declarations of one thing agree on — a generic
/// `poll` instantiated in several units, a local the compiler
/// duplicated — compared by display path and line rather than by the
/// raw file, directory and compilation directory: the same registry
/// file is spelled relative under the crate's own compilation
/// directory in that crate's unit and in full from a unit that
/// monomorphized it, and under the display path both spellings are
/// one file. Declarations with no file or no line are skipped, not
/// disagreed with.
pub(super) fn agreed_site<'a>(sites: impl IntoIterator<Item = &'a OwnedLoc>) -> Agreement<'a> {
    let mut placed = sites
        .into_iter()
        .filter_map(|s| s.site().map(|site| (s, site)));
    let Some((first, site)) = placed.next() else {
        return Agreement::Unplaced;
    };
    match placed.all(|(_, other)| other == site) {
        true => Agreement::Site(first),
        false => Agreement::Disagreed,
    }
}

/// Extract `1.97.0 (2d8144b78 2026-07-07)` from a producer string like
/// `clang LLVM (rustc version 1.97.0 (2d8144b78 2026-07-07))`.
pub(super) fn rustc_version_of(producer: &str) -> String {
    match producer.split_once("rustc version ") {
        Some((_, rest)) => rest.strip_suffix(')').unwrap_or(rest).to_owned(),
        None => producer.to_owned(),
    }
}

/// The crate and version a registry source path names, from its
/// `<crate>-<semver>` directory: `("tokio", 1.52.3)` for
/// `…/tokio-1.52.3/src/runtime/task/raw.rs`, whether the path is
/// absolute (as the line table records it) or already cut to the tail
/// a reader sees. The first path segment that splits at a `-` into a
/// nonempty name and a whole version is the crate directory — a name
/// may carry `-`s of its own (`tokio-util-0.7.12`), but none of its
/// segments is a version. A path with no such segment (a workspace
/// crate, a toolchain source) names no crate.
pub(super) fn crate_version_of(path: &str) -> Option<(&str, semver::Version)> {
    path.split('/').find_map(|segment| {
        segment.match_indices('-').find_map(|(at, _)| {
            let (package, version) = (&segment[..at], &segment[at + 1..]);
            if package.is_empty() {
                return None;
            }
            semver::Version::parse(version)
                .ok()
                .map(|version| (package, version))
        })
    })
}

/// Recover the tokio version from a registry source path such as
/// `…/tokio-1.52.3/src/runtime/task/raw.rs`.
pub(super) fn tokio_version_of(loc: &OwnedLoc) -> Option<semver::Version> {
    [loc.dir.as_deref(), loc.file.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(crate_version_of)
        .find_map(|(package, version)| (package == "tokio").then_some(version))
}

/// The display path for a source location: the file joined onto its
/// line-table directory, cut down by [`strip_build_prefix`] to the tail a
/// reader can use.
///
/// A relative directory is relative to the unit's `DW_AT_comp_dir`, and
/// rustc gives each crate its own: the crate root for a dependency, the
/// workspace root for a member. Taking the directory alone therefore drops
/// the crate a dependency's file belongs to — `src/resolvers/dns.rs` for a
/// type emitted in qorb's own unit, where the same file reached from a
/// crate that monomorphized it is named in full. So the path is rooted at
/// `comp_dir` and offered to [`strip_build_prefix`], and the result is
/// taken only if it recognized the root: a workspace root is nobody's
/// crate cache, and `/data/omicron/nexus/src/app/…` is worse than the
/// `nexus/src/app/…` the directory already gave.
pub(super) fn display_path(comp_dir: Option<&str>, dir: Option<&str>, file: &str) -> String {
    let joined = match dir {
        Some(dir) if !dir.is_empty() && !file.starts_with('/') => format!("{dir}/{file}"),
        _ => file.to_owned(),
    };
    if joined.starts_with('/') {
        return strip_build_prefix(&joined).into_owned();
    }
    let Some(comp_dir) = comp_dir.filter(|d| d.starts_with('/')) else {
        return joined;
    };
    let rooted = format!("{comp_dir}/{joined}");
    let cut = strip_build_prefix(&rooted);
    // Every root it knows takes something off, so an unchanged length is
    // how "not recognized" comes back.
    match cut.len() < rooted.len() {
        true => cut.into_owned(),
        false => joined,
    }
}

#[cfg(test)]
mod tests {
    use super::{Agreement, OwnedLoc, agreed_site, display_path};
    use crate::bundle::StringInterner;

    #[test]
    fn test_rustc_floor_warning() {
        use super::rustc_below_floor;
        // The version as `rustc_version_of` records it: number first,
        // hash and date trailing.
        assert_eq!(
            rustc_below_floor("1.96.0 (0000aaaa 2026-01-01)"),
            Some("1.96.0".to_owned())
        );
        assert_eq!(rustc_below_floor("1.97.0 (2d8144b78 2026-07-07)"), None);
        assert_eq!(rustc_below_floor("1.97.1 (8bab26f4f 2026-07-14)"), None);
        assert_eq!(rustc_below_floor("1.98.0"), None);
        // A producer that names no rustc version is unknown, not old.
        assert_eq!(rustc_below_floor("GNU C 12.2.0"), None);
        assert_eq!(rustc_below_floor(""), None);
    }

    #[test]
    fn test_display_path_plain() {
        // No dir, an empty dir, or an absolute file passes through.
        assert_eq!(display_path(None, None, "lib.rs"), "lib.rs");
        assert_eq!(display_path(None, Some(""), "lib.rs"), "lib.rs");
        assert_eq!(
            display_path(None, Some("ignored"), "/abs/path/lib.rs"),
            "/abs/path/lib.rs"
        );
    }

    #[test]
    fn test_display_path_relative_dir() {
        assert_eq!(
            display_path(None, Some("nexus/reconfigurator/preparation/src"), "lib.rs"),
            "nexus/reconfigurator/preparation/src/lib.rs"
        );
    }

    #[test]
    fn test_display_path_registry() {
        // The file component may itself carry a path.
        assert_eq!(
            display_path(
                None,
                Some("/home/wfc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.50.0"),
                "src/sync/watch.rs"
            ),
            "tokio-1.50.0/src/sync/watch.rs"
        );
        assert_eq!(
            display_path(
                None,
                Some(
                    "/home/wfc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_core-1.0.228/src/de"
                ),
                "mod.rs"
            ),
            "serde_core-1.0.228/src/de/mod.rs"
        );
    }

    #[test]
    fn test_display_path_git_checkout() {
        assert_eq!(
            display_path(
                None,
                Some(
                    "/home/wfc/.cargo/git/checkouts/dendrite-ae9f1715c17fc765/cc0c307/dpd-client/src"
                ),
                "lib.rs"
            ),
            "dendrite/cc0c307/dpd-client/src/lib.rs"
        );
        // A checkout dir that does not end in a cache hash is kept whole.
        assert_eq!(
            display_path(
                None,
                Some("/home/x/.cargo/git/checkouts/odd-layout/src"),
                "lib.rs"
            ),
            "odd-layout/src/lib.rs"
        );
    }

    #[test]
    fn test_display_path_toolchain() {
        assert_eq!(
            display_path(
                None,
                Some("/rustc/ed61e7d7e242494fb7057f2657300d9e77bb4fcb/library/std/src/thread"),
                "mod.rs"
            ),
            "library/std/src/thread/mod.rs"
        );
        assert_eq!(
            display_path(
                None,
                Some(
                    "/Users/wfc/.rustup/toolchains/1.97.0-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/ptr"
                ),
                "non_null.rs"
            ),
            "library/core/src/ptr/non_null.rs"
        );
        assert_eq!(
            display_path(None, Some("/rust/deps/hashbrown-0.15.5/src/raw"), "mod.rs"),
            "hashbrown-0.15.5/src/raw/mod.rs"
        );
    }

    #[test]
    fn test_display_path_unknown_absolute() {
        // Unrecognized absolute dirs join unmodified rather than truncate.
        assert_eq!(
            display_path(None, Some("/opt/vendored/foo/src"), "lib.rs"),
            "/opt/vendored/foo/src/lib.rs"
        );
    }

    /// Both spellings a dependency's file gets, from the two units that
    /// name it in one nexus binary: qorb's own, which writes the directory
    /// relative to its crate root, and the crate that monomorphized a qorb
    /// generic, which has to write it in full. Rooting the first at its
    /// compilation directory is what makes them agree.
    #[test]
    fn test_display_path_comp_dir_names_the_crate() {
        const QORB: &str =
            "/home/wfc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/qorb-0.4.1";
        assert_eq!(
            display_path(Some(QORB), Some("src/resolvers"), "dns.rs"),
            "qorb-0.4.1/src/resolvers/dns.rs"
        );
        assert_eq!(
            display_path(Some("/data/omicron"), Some(QORB), "src/pool.rs"),
            "qorb-0.4.1/src/pool.rs"
        );
    }

    /// A workspace member's compilation directory is the workspace root,
    /// which names no crate cache — rooting there would only prepend the
    /// build machine, so the directory's own answer stands.
    #[test]
    fn test_display_path_comp_dir_declined() {
        assert_eq!(
            display_path(Some("/data/omicron"), Some("nexus/src/app"), "mod.rs"),
            "nexus/src/app/mod.rs"
        );
        // A relative compilation directory cannot root anything.
        assert_eq!(
            display_path(Some("omicron"), Some("nexus/src/app"), "mod.rs"),
            "nexus/src/app/mod.rs"
        );
        // An absolute directory is already whole; comp_dir does not apply.
        assert_eq!(
            display_path(Some("/data/omicron"), Some("/opt/vendored/src"), "lib.rs"),
            "/opt/vendored/src/lib.rs"
        );
    }

    const HYPER: &str =
        "/home/wfc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hyper-1.10.1";

    fn loc(
        comp_dir: Option<&str>,
        dir: Option<&str>,
        file: Option<&str>,
        line: Option<u64>,
    ) -> OwnedLoc {
        OwnedLoc {
            file: file.map(str::to_owned),
            dir: dir.map(str::to_owned),
            comp_dir: comp_dir.map(str::to_owned),
            line,
        }
    }

    fn site(a: &Agreement<'_>) -> Option<(Option<String>, Option<u64>)> {
        match a {
            Agreement::Site(l) => Some((l.file.clone(), l.line)),
            _ => None,
        }
    }

    #[test]
    fn test_agreed_site_one() {
        let one = loc(
            Some(HYPER),
            Some("src/client/conn"),
            Some("http1.rs"),
            Some(40),
        );
        assert_eq!(
            site(&agreed_site([&one])),
            Some((Some("http1.rs".to_owned()), Some(40)))
        );
    }

    #[test]
    fn test_agreed_site_agreeing() {
        let a = loc(
            Some(HYPER),
            Some("src/client/conn"),
            Some("http1.rs"),
            Some(40),
        );
        let b = a.clone();
        assert_eq!(
            site(&agreed_site([&a, &b])),
            Some((Some("http1.rs".to_owned()), Some(40)))
        );
    }

    /// Two lines for one type are two different `poll`s, and nothing
    /// says which the reader wants: neither is recorded.
    #[test]
    fn test_agreed_site_disagreeing() {
        let a = loc(
            Some(HYPER),
            Some("src/client/conn"),
            Some("http1.rs"),
            Some(40),
        );
        let b = loc(
            Some(HYPER),
            Some("src/client/conn"),
            Some("http1.rs"),
            Some(64),
        );
        assert_eq!(agreed_site([&a, &b]), Agreement::Disagreed);
        let c = loc(
            Some(HYPER),
            Some("src/client/conn"),
            Some("http2.rs"),
            Some(40),
        );
        assert_eq!(agreed_site([&a, &c]), Agreement::Disagreed);
    }

    /// A declaration with a file and no line is not a site: it is
    /// skipped, not disagreed with, and alone it places nothing.
    #[test]
    fn test_agreed_site_skips_the_unplaced() {
        let placed = loc(
            Some(HYPER),
            Some("src/client/conn"),
            Some("http1.rs"),
            Some(40),
        );
        let fileless = loc(Some(HYPER), Some("src/client/conn"), None, Some(40));
        let lineless = loc(Some(HYPER), Some("src/client/conn"), Some("http1.rs"), None);
        assert_eq!(
            site(&agreed_site([&fileless, &placed, &lineless])),
            Some((Some("http1.rs".to_owned()), Some(40)))
        );
        assert_eq!(agreed_site([&fileless, &lineless]), Agreement::Unplaced);
        assert_eq!(agreed_site([]), Agreement::Unplaced);
    }

    /// One registry file, spelled relative under the crate's own
    /// compilation directory in its unit and in full from a unit that
    /// monomorphized it: one site under the display path, where the
    /// raw triple would have called it two.
    #[test]
    fn test_agreed_site_registry_spellings() {
        let own_unit = loc(
            Some(HYPER),
            Some("src/client/conn"),
            Some("http1.rs"),
            Some(40),
        );
        let other_unit = loc(
            Some("/data/omicron"),
            None,
            Some(&format!("{HYPER}/src/client/conn/http1.rs")),
            Some(40),
        );
        assert!(matches!(
            agreed_site([&own_unit, &other_unit]),
            Agreement::Site(l) if l.file.as_deref() == Some("http1.rs")
        ));
    }

    #[test]
    fn test_crate_version_of_reads_the_crate_directory() {
        use super::{crate_version_of, tokio_version_of};
        let v = |s: &str| semver::Version::parse(s).unwrap();
        // Absolute as the line table records it, or cut to the tail.
        assert_eq!(
            crate_version_of(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.52.3/src/runtime/task/raw.rs"
            ),
            Some(("tokio", v("1.52.3")))
        );
        assert_eq!(
            crate_version_of("tokio-1.52.3/src/runtime/task/raw.rs"),
            Some(("tokio", v("1.52.3")))
        );
        // A name with `-`s of its own splits where the rest is a whole
        // version; the registry index directory's hash is not one.
        assert_eq!(
            crate_version_of(
                "registry/src/index.crates.io-1949cf8c6b5b557f/hickory-proto-0.25.2/src/xfer/mod.rs"
            ),
            Some(("hickory-proto", v("0.25.2")))
        );
        assert_eq!(
            crate_version_of("tracing-core-0.1.33-beta.1/src/lib.rs"),
            Some(("tracing-core", v("0.1.33-beta.1")))
        );
        // No crate directory: a workspace path, a toolchain source, a
        // bare version, an empty name.
        for path in [
            "nexus/db-queries/src/db/datastore/mod.rs",
            "/rustc/2d8144b78/library/core/src/ptr/mod.rs",
            "/home/u/.rustup/toolchains/1.98.0-aarch64-apple-darwin/lib/rustlib/src/rust/library/alloc/src/vec/mod.rs",
            "-1.2.3/src/lib.rs",
            "",
        ] {
            assert_eq!(crate_version_of(path), None, "{path}");
        }
        // tokio's version is the same read, filtered to tokio: a path
        // through `tokio-util` names no tokio version.
        let loc = |dir: &str| OwnedLoc {
            file: Some("src/lib.rs".to_owned()),
            dir: Some(dir.to_owned()),
            comp_dir: None,
            line: None,
        };
        assert_eq!(
            tokio_version_of(&loc("/home/u/.cargo/registry/src/idx/tokio-1.52.3")),
            Some(v("1.52.3"))
        );
        assert_eq!(
            tokio_version_of(&loc("/home/u/.cargo/registry/src/idx/tokio-util-0.7.12")),
            None
        );
    }

    #[test]
    fn test_bundle_loc_requires_file_and_line() {
        let mut strings = StringInterner::new();
        let placed = loc(
            Some(HYPER),
            Some("src/client/conn"),
            Some("http1.rs"),
            Some(40),
        );
        let recorded = placed.bundle_loc(&mut strings).unwrap();
        assert_eq!(
            strings.get(recorded.file),
            Some("hyper-1.10.1/src/client/conn/http1.rs")
        );
        assert_eq!(recorded.line, 40);
        let lineless = loc(Some(HYPER), Some("src/client/conn"), Some("http1.rs"), None);
        assert!(lineless.bundle_loc(&mut strings).is_none());
    }
}

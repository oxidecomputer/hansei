//! Source-location plumbing: owned copies of DWARF locations, the display
//! path a reader sees (crate-cache and toolchain prefixes stripped), and
//! the versions recovered from producer strings and registry paths.

use super::RUSTC_FLOOR;
use crate::bundle::strip_build_prefix;
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
#[derive(Clone, Debug)]
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

/// Extract `1.97.0 (2d8144b78 2026-07-07)` from a producer string like
/// `clang LLVM (rustc version 1.97.0 (2d8144b78 2026-07-07))`.
pub(super) fn rustc_version_of(producer: &str) -> String {
    match producer.split_once("rustc version ") {
        Some((_, rest)) => rest.strip_suffix(')').unwrap_or(rest).to_owned(),
        None => producer.to_owned(),
    }
}

/// Recover the tokio version from a registry source path such as
/// `…/tokio-1.52.3/src/runtime/task/raw.rs`.
pub(super) fn tokio_version_of(loc: &OwnedLoc) -> Option<semver::Version> {
    for part in [loc.dir.as_deref(), loc.file.as_deref()]
        .into_iter()
        .flatten()
    {
        if let Some(i) = part.find("tokio-") {
            let rest = &part[i + "tokio-".len()..];
            let end = rest
                .find(|c: char| c != '.' && !c.is_ascii_digit())
                .unwrap_or(rest.len());
            if let Ok(v) = semver::Version::parse(&rest[..end]) {
                return Some(v);
            }
        }
    }
    None
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
    use super::display_path;

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
}

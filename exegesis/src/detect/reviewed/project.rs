// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Holding a project to the reviews: each release in its `Cargo.lock`,
//! and the channel its toolchain file names, that falls outside them.
//! Each finding names what was found and every range it falls outside,
//! with the reviews that cover that range, and prints as one line.

use super::{Covers, Placement, Review, Subject};

use std::fmt;

/// One release or revision a project uses that falls outside the
/// reviews of its subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The crate's package name, or `rustc`.
    pub subject: String,
    /// The release as the project names it, a git checkout's revision
    /// after it: `0.1.0 (d2b68e4f4)`.
    pub found: String,
    /// Each range it falls outside of, with the reviews that cover that
    /// range; empty when it names no release any review can place.
    pub outside: Vec<Range>,
}

/// A range a finding falls outside of, and every review covering it:
/// several reviews of one range are named once, as `hyper-util`'s are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// How the finding relates to the range: `below`, `above`, `not one
    /// of`, or `not a git checkout of one of`.
    pub relation: &'static str,
    pub covers: String,
    pub reviews: Vec<&'static str>,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: ", self.subject, self.found)?;
        if self.outside.is_empty() {
            return f.write_str("not a release any review can place");
        }
        for (i, range) in self.outside.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            let reviews = range.reviews.join(", ");
            write!(f, "{} {} ({reviews})", range.relation, range.covers)?;
        }
        Ok(())
    }
}

/// One package a lockfile locks: its name, release, and the revision of
/// a git checkout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locked {
    pub name: String,
    pub version: String,
    pub revision: Option<String>,
}

/// Every package a lockfile locks, in its order.
pub fn locked(text: &str) -> Result<Vec<Locked>, toml::de::Error> {
    let lock: toml::Table = text.parse()?;
    let packages = lock
        .get("package")
        .and_then(|p| p.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    Ok(packages
        .iter()
        .filter_map(|package| {
            let field = |key: &str| package.get(key).and_then(|v| v.as_str());
            let revision = field("source")
                .filter(|s| s.starts_with("git+"))
                .and_then(|s| s.rsplit_once('#'))
                .map(|(_, rev)| rev.to_string());
            Some(Locked {
                name: field("name")?.to_string(),
                version: field("version")?.to_string(),
                revision,
            })
        })
        .collect())
}

/// The channel a toolchain file names: a `rust-toolchain.toml`'s
/// `[toolchain] channel`, or the whole of a legacy `rust-toolchain`.
pub fn toolchain_channel(text: &str) -> String {
    match text.parse::<toml::Table>() {
        Ok(table) => table
            .get("toolchain")
            .and_then(|t| t.get("channel"))
            .and_then(|c| c.as_str())
            .unwrap_or_default()
            .to_string(),
        Err(_) => text.trim().to_string(),
    }
}

/// One review a release or revision falls outside of: how it relates to
/// what the review covers, and the review's name.
struct Outside {
    relation: &'static str,
    covers: String,
    family: &'static str,
}

impl Outside {
    fn new(relation: &'static str, review: &Review) -> Self {
        Outside {
            relation,
            covers: review.covers.to_string(),
            family: review.family,
        }
    }
}

/// Where one release or revision of a subject falls outside its
/// reviews: each range it is outside of, with the reviews that cover
/// it, in the order the reviews first name them.
fn finding(subject: &str, found: &str, outside: &[Outside]) -> Finding {
    let mut ranges: Vec<Range> = Vec::new();
    for o in outside {
        match ranges
            .iter_mut()
            .find(|r| r.relation == o.relation && r.covers == o.covers)
        {
            Some(range) => range.reviews.push(o.family),
            None => ranges.push(Range {
                relation: o.relation,
                covers: o.covers.clone(),
                reviews: vec![o.family],
            }),
        }
    }
    Finding {
        subject: subject.to_string(),
        found: found.to_string(),
        outside: ranges,
    }
}

/// What the reviews say about one release of a subject, by its name:
/// each review of that subject whose range it falls outside of.
fn release_outside(subject: &str, version: &semver::Version, reviews: &[Review]) -> Vec<Outside> {
    reviews
        .iter()
        .filter(|r| r.subject.name() == subject)
        .filter_map(|r| {
            let (placement, range) = r.place(version)?;
            let relation = match placement {
                Placement::Inside => return None,
                Placement::Below => "below",
                Placement::Above => "above",
            };
            Some(Outside {
                relation,
                covers: range,
                family: r.family,
            })
        })
        .collect()
}

/// Every package of a lockfile's that a review covers and that falls
/// outside it; see [`package_findings`].
pub fn lockfile_findings(text: &str, reviews: &[Review]) -> Result<Vec<Finding>, toml::de::Error> {
    Ok(package_findings(&locked(text)?, reviews))
}

/// Every locked package a review covers that falls outside it: a
/// release outside a crate's range, or a revision (or a release where a
/// revision is reviewed) outside a git crate's.
pub fn package_findings(packages: &[Locked], reviews: &[Review]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for package in packages {
        let name = package.name.as_str();
        let revision = package.revision.as_deref();
        let mut outside = Vec::new();
        let crate_reviews = reviews
            .iter()
            .filter(|r| matches!(r.subject, Subject::Crate(package) if package == name));
        for r in crate_reviews {
            match revision.and_then(|rev| r.covers_revision(rev)) {
                Some(true) => {}
                Some(false) => outside.push(Outside::new("not one of", r)),
                None if matches!(r.covers, Covers::Revisions { .. }) => {
                    outside.push(Outside::new("not a git checkout of one of", r))
                }
                None => {}
            }
        }
        if let Ok(release) = semver::Version::parse(&package.version) {
            outside.extend(release_outside(name, &release, reviews));
        }
        if !outside.is_empty() {
            let version = &package.version;
            let found = match revision {
                Some(rev) => format!("{version} ({})", &rev[..rev.len().min(9)]),
                None => version.to_string(),
            };
            findings.push(finding(name, &found, &outside));
        }
    }
    findings
}

/// The toolchain file's channel held to rustc's reviews; see
/// [`channel_findings`].
pub fn toolchain_findings(text: &str, reviews: &[Review]) -> Vec<Finding> {
    channel_findings(&toolchain_channel(text), reviews)
}

/// A toolchain channel held to rustc's reviews. A channel that names no
/// release (`stable`, a nightly, a bare minor such as `1.98`, which
/// rustup resolves to its newest patch) is a finding of its own: no
/// review can place it.
pub fn channel_findings(channel: &str, reviews: &[Review]) -> Vec<Finding> {
    let Ok(release) = semver::Version::parse(channel) else {
        return vec![finding("rustc", channel, &[])];
    };
    let outside = release_outside(Subject::Rustc.name(), &release, reviews);
    if outside.is_empty() {
        Vec::new()
    } else {
        vec![finding("rustc", channel, &outside)]
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Finding, Locked, Range, locked, lockfile_findings, toolchain_channel, toolchain_findings,
    };
    use crate::detect::reviewed::{GIT_CONVENTIONS, Review, reviews};

    use testrun::fixture::test_programs_dir;

    /// The fixtures build only releases the reviews cover: the primary
    /// cell's lockfile, and every other pinned cell's, is inside every
    /// review of each crate it locks. A `cargo update` in test-programs
    /// moves each crate as far as its requirement admits, and that can
    /// be past the newest reviewed release (tokio-util's `0.7.11` admits
    /// every 0.7): fixtures built from it would exercise a release no
    /// detector was checked against, and every suite reading them would
    /// still pass.
    #[test]
    fn test_the_fixture_lockfiles_stay_inside_the_reviews() {
        let dir = test_programs_dir();
        let locks = dir.join("locks");
        let mut lockfiles: Vec<_> = std::fs::read_dir(&locks)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", locks.display()))
            .map(|entry| entry.expect("a directory entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "lock"))
            .collect();
        assert!(!lockfiles.is_empty(), "no lockfiles in {}", locks.display());
        lockfiles.push(dir.join("Cargo.lock"));
        lockfiles.sort();

        let reviews = reviews();
        let mut outside = Vec::new();
        for path in &lockfiles {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            let findings = lockfile_findings(&text, &reviews)
                .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
            let name = path.strip_prefix(&dir).unwrap_or(path).display();
            outside.extend(
                findings
                    .iter()
                    .map(|f| format!("test-programs/{name}: {f}")),
            );
        }
        assert!(
            outside.is_empty(),
            "the fixtures lock releases outside the reviews; review them, or pin \
             the fixtures inside:\n{}",
            outside.join("\n")
        );
    }

    /// A lockfile of the given `(name, version, source)` packages.
    fn lockfile(packages: &[(&str, &str, Option<&str>)]) -> String {
        let mut text = String::from("version = 4\n");
        for (name, version, source) in packages {
            text.push_str(&format!(
                "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n"
            ));
            if let Some(source) = source {
                text.push_str(&format!("source = \"{source}\"\n"));
            }
        }
        text
    }

    const REGISTRY: Option<&str> = Some("registry+https://github.com/rust-lang/crates.io-index");

    /// Findings as the lines they print as.
    fn lines(findings: Vec<Finding>) -> Vec<String> {
        findings.iter().map(ToString::to_string).collect()
    }

    fn lock_findings(packages: &[(&str, &str, Option<&str>)]) -> Vec<String> {
        lines(lockfile_findings(&lockfile(packages), &reviews()).expect("the lockfile parses"))
    }

    /// A lockfile's packages in order, a git checkout's with the
    /// revision its source records; an entry without a name or version
    /// is no package.
    #[test]
    fn test_locked_reads_each_package() {
        let mut text = lockfile(&[
            ("hyper", "1.6.0", REGISTRY),
            (
                "sprockets-tls",
                "0.1.0",
                Some("git+https://github.com/oxidecomputer/sprockets?rev=x#abc123"),
            ),
        ]);
        text.push_str("\n[[package]]\nname = \"half\"\n");
        let package = |name: &str, version: &str, revision: Option<&str>| Locked {
            name: name.to_string(),
            version: version.to_string(),
            revision: revision.map(str::to_string),
        };
        assert_eq!(
            locked(&text).expect("the lockfile parses"),
            vec![
                package("hyper", "1.6.0", None),
                package("sprockets-tls", "0.1.0", Some("abc123")),
            ]
        );
    }

    /// A finding carries what it prints: the subject, what was found,
    /// and each range with every review covering it.
    #[test]
    fn test_a_finding_names_its_ranges() {
        let found = lockfile_findings(&lockfile(&[("hyper-util", "99.0.0", REGISTRY)]), &reviews())
            .expect("the lockfile parses");
        let [finding] = found.as_slice() else {
            panic!("{found:#?}")
        };
        assert_eq!(finding.subject, "hyper-util");
        assert_eq!(finding.found, "99.0.0");
        let ranges: Vec<(&str, &str, usize)> = finding
            .outside
            .iter()
            .map(|r: &Range| (r.relation, r.covers.as_str(), r.reviews.len()))
            .collect();
        assert_eq!(
            ranges,
            [("above", "0.1.10-0.1.20", 5), ("above", "0.1.16-0.1.20", 1)]
        );
    }

    /// The channel is a toolchain file's `[toolchain] channel`, or the
    /// whole of a legacy bare one.
    #[test]
    fn test_toolchain_channel_reads_either_file() {
        assert_eq!(
            toolchain_channel("[toolchain]\nchannel = \"1.99.0\"\n"),
            "1.99.0"
        );
        assert_eq!(toolchain_channel("1.98.1\n"), "1.98.1");
    }

    /// Releases inside every review of their crate, and crates no
    /// review covers, find nothing.
    #[test]
    fn test_a_reviewed_lockfile_finds_nothing() {
        let found = lock_findings(&[
            ("tokio", "1.52.1", REGISTRY),
            ("hyper", "1.6.0", REGISTRY),
            ("parking_lot", "0.12.3", REGISTRY),
            ("serde", "99.0.0", REGISTRY),
            ("my-app", "0.1.0", None),
        ]);
        assert_eq!(found, Vec::<String>::new());
    }

    /// A release outside its crate's reviews is one line naming it and
    /// each side it falls on, the reviews of one range named together.
    #[test]
    fn test_a_release_outside_names_each_range_once() {
        let found = lock_findings(&[
            ("parking_lot", "0.10.2", REGISTRY),
            ("hyper-util", "99.0.0", REGISTRY),
        ]);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(
            found[0].starts_with("parking_lot 0.10.2: below 0.11.0-"),
            "{found:#?}"
        );
        assert!(
            found[1].starts_with("hyper-util 99.0.0: above "),
            "{found:#?}"
        );
        // Five hyper-util reviews share one range and one has its own:
        // two ranges, every review named once.
        assert_eq!(found[1].matches("; ").count(), 1, "{}", found[1]);
        assert!(found[1].contains("hyper-util-auto-conn-"), "{}", found[1]);
        assert!(found[1].contains("hyper-util-pool-"), "{}", found[1]);
    }

    /// Each locked release of a crate is held to the reviews on its own:
    /// a lockfile holding two finds only the one outside.
    #[test]
    fn test_each_locked_release_is_held_separately() {
        let found = lock_findings(&[
            ("reqwest", "0.12.28", REGISTRY),
            ("reqwest", "0.11.27", REGISTRY),
        ]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].starts_with("reqwest 0.11.27: below "),
            "{found:#?}"
        );
    }

    /// A git crate is held to its reviewed revisions: a reviewed one,
    /// by any prefix the source records, finds nothing; another
    /// revision, or the crate from a registry, is outside.
    #[test]
    fn test_a_git_crate_is_held_to_its_revisions() {
        let reviewed = GIT_CONVENTIONS[0].revisions[0].0;
        let git = |rev: &str| format!("git+https://github.com/oxidecomputer/sprockets?rev=x#{rev}");
        let at_reviewed = git(reviewed);
        assert_eq!(
            lock_findings(&[("sprockets-tls", "0.1.0", Some(at_reviewed.as_str()))]),
            Vec::<String>::new()
        );

        let elsewhere = git("0123456789abcdef");
        let found = lock_findings(&[("sprockets-tls", "0.1.0", Some(elsewhere.as_str()))]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].starts_with("sprockets-tls 0.1.0 (012345678): not one of "),
            "{found:#?}"
        );
        assert_eq!(found[0].matches("; ").count(), 0, "{}", found[0]);

        let found = lock_findings(&[("sprockets-tls", "0.1.0", REGISTRY)]);
        assert!(
            found[0].starts_with("sprockets-tls 0.1.0: not a git checkout of one of "),
            "{found:#?}"
        );
    }

    /// The channel is held to rustc's reviews release by release; one
    /// that names no release — a bare minor, which rustup resolves to
    /// whatever patch is newest, as much as `stable` — is its own
    /// finding; the bare legacy file reads the same.
    #[test]
    fn test_a_toolchain_is_held_to_rustcs_reviews() {
        let toml = |channel: &str| format!("[toolchain]\nchannel = \"{channel}\"\n");
        let reviews = reviews();
        // The findings as the lines they print as.
        let toolchain_findings =
            |text: &str, reviews: &[Review]| lines(toolchain_findings(text, reviews));
        for channel in ["1.98.0", "1.98.1", "1.99.0"] {
            assert_eq!(
                toolchain_findings(&toml(channel), &reviews),
                Vec::<String>::new(),
                "{channel}"
            );
        }
        assert_eq!(
            toolchain_findings(&toml("1.98"), &reviews),
            vec!["rustc 1.98: not a release any review can place".to_string()]
        );

        let found = toolchain_findings(&toml("1.999.0"), &reviews);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].starts_with("rustc 1.999.0: above 1.97.0-1.99.0 ("),
            "{found:#?}"
        );
        // A patch released into a reviewed minor after its review is
        // above what was read of that minor.
        let found = toolchain_findings(&toml("1.97.2"), &reviews);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].starts_with("rustc 1.97.2: above 1.97.0-1.97.1 ("),
            "{found:#?}"
        );
        assert_eq!(found[0].matches("; ").count(), 0, "{}", found[0]);

        assert_eq!(
            toolchain_findings(&toml("stable"), &reviews),
            vec!["rustc stable: not a release any review can place".to_string()]
        );
        let found = toolchain_findings("1.96.0\n", &reviews);
        assert!(found[0].starts_with("rustc 1.96.0: below "), "{found:#?}");
    }
}

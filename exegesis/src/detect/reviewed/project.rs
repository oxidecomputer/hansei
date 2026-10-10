// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Holding a project to the reviews: each release in its `Cargo.lock`,
//! and the channel its toolchain file names, that falls outside them.
//! Each finding is one line, naming what was found and every range it
//! falls outside, with the reviews that cover that range.

use super::{Covers, Placement, Review, Subject};

/// One review a release or revision falls outside of: how it relates to
/// what the review covers, and the review's name.
struct Outside<'r> {
    relation: &'static str,
    covers: String,
    family: &'r str,
}

impl<'r> Outside<'r> {
    fn new(relation: &'static str, review: &'r Review) -> Self {
        Outside {
            relation,
            covers: review.covers.to_string(),
            family: review.family,
        }
    }
}

/// Where one release or revision of a subject falls outside its
/// reviews, as the line that names it: the subject and what was found,
/// then each range it is outside of with the reviews that cover it —
/// several reviews of one range named once, as `hyper-util`'s are.
fn finding_line(subject: &str, found: &str, outside: &[Outside<'_>]) -> String {
    let mut ranges: Vec<(&str, &str, Vec<&str>)> = Vec::new();
    for o in outside {
        match ranges
            .iter_mut()
            .find(|(relation, covers, _)| *relation == o.relation && *covers == o.covers)
        {
            Some((_, _, families)) => families.push(o.family),
            None => ranges.push((o.relation, &o.covers, vec![o.family])),
        }
    }
    let ranges: Vec<String> = ranges
        .iter()
        .map(|(relation, covers, families)| {
            format!("{relation} {covers} ({})", families.join(", "))
        })
        .collect();
    format!("{subject} {found}: {}", ranges.join("; "))
}

/// What the reviews say about one release of a subject, by its name:
/// each review of that subject whose range it falls outside of.
fn release_outside<'r>(
    subject: &str,
    version: &semver::Version,
    reviews: &'r [Review],
) -> Vec<Outside<'r>> {
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

/// Every locked package a review covers that falls outside it: a
/// release outside a crate's range, or a revision (or a release where a
/// revision is reviewed) outside a git crate's.
pub fn lockfile_findings(text: &str, reviews: &[Review]) -> Result<Vec<String>, toml::de::Error> {
    let lock: toml::Table = text.parse()?;
    let packages = lock
        .get("package")
        .and_then(|p| p.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut findings = Vec::new();
    for package in packages {
        let field = |key: &str| package.get(key).and_then(|v| v.as_str());
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            continue;
        };
        let revision = field("source")
            .filter(|s| s.starts_with("git+"))
            .and_then(|s| s.rsplit_once('#'))
            .map(|(_, rev)| rev);
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
        if let Ok(release) = semver::Version::parse(version) {
            outside.extend(release_outside(name, &release, reviews));
        }
        if !outside.is_empty() {
            let found = match revision {
                Some(rev) => format!("{version} ({})", &rev[..rev.len().min(9)]),
                None => version.to_string(),
            };
            findings.push(finding_line(name, &found, &outside));
        }
    }
    Ok(findings)
}

/// The toolchain file's channel held to rustc's reviews. A channel that
/// names no release (`stable`, a nightly, a bare minor such as `1.98`,
/// which rustup resolves to its newest patch) is a finding of its own:
/// no review can place it.
pub fn toolchain_findings(text: &str, reviews: &[Review]) -> Vec<String> {
    let channel = match text.parse::<toml::Table>() {
        Ok(table) => table
            .get("toolchain")
            .and_then(|t| t.get("channel"))
            .and_then(|c| c.as_str())
            .unwrap_or_default()
            .to_string(),
        // The legacy `rust-toolchain` file is the bare channel.
        Err(_) => text.trim().to_string(),
    };
    let Ok(release) = semver::Version::parse(&channel) else {
        return vec![format!(
            "rustc {channel}: not a release any review can place"
        )];
    };
    let outside = release_outside(Subject::Rustc.name(), &release, reviews);
    if outside.is_empty() {
        Vec::new()
    } else {
        vec![finding_line("rustc", &channel, &outside)]
    }
}

#[cfg(test)]
mod tests {
    use super::{lockfile_findings, toolchain_findings};
    use crate::detect::reviewed::{GIT_CONVENTIONS, reviews};

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

    fn lock_findings(packages: &[(&str, &str, Option<&str>)]) -> Vec<String> {
        lockfile_findings(&lockfile(packages), &reviews()).expect("the lockfile parses")
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Where a project has moved past hansei: past its reviews, past the
//! toolchains and primary pins of test-programs' matrix, or past the
//! releases test-programs locks.

use exegesis::detect::reviewed::project::{self, Locked, channel_findings, package_findings};
use exegesis::detect::reviewed::{Review, Subject};
use semver::Version;
use serde::Serialize;
use testrun::fixture::Matrix;

use std::collections::BTreeSet;
use std::fmt;

/// What a project is held against.
pub struct Inputs<'a> {
    /// The packages the project's `Cargo.lock` locks.
    pub project: &'a [Locked],
    /// The channel its toolchain file names.
    pub channel: &'a str,
    /// The packages test-programs' primary `Cargo.lock` locks.
    pub fixtures: &'a [Locked],
    pub matrix: &'a Matrix,
    pub reviews: &'a [Review],
}

/// One way a project has moved past hansei.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Finding {
    /// A release or revision outside a review: extraction binds none of
    /// what the review covers, and refuses the binary unless allowed.
    /// `summary` is the line `hansei tokio-info reviewed` prints for it.
    Unreviewed {
        subject: String,
        found: String,
        outside: Vec<Outside>,
        summary: String,
    },
    /// A toolchain channel test-programs' matrix does not build, so no
    /// golden has seen what it emits.
    Unmatrixed {
        subject: &'static str,
        found: String,
        matrix: Vec<String>,
    },
    /// A tokio or rustc minor newer than the matrix's primary pin, which
    /// the fresh-core suites and the extraction goldens run, and which
    /// advances by hand.
    Primary {
        subject: &'static str,
        found: String,
        minor: String,
        pin: String,
    },
    /// A reviewed crate the project locks at a newer release than
    /// test-programs does: the fixtures do not exercise what the project
    /// runs. tokio is held to the primary pin instead.
    Fixture {
        subject: String,
        found: String,
        fixture: String,
    },
}

/// A range an unreviewed release falls outside of, and every review
/// covering it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Outside {
    pub relation: &'static str,
    pub covers: String,
    pub reviews: Vec<&'static str>,
}

impl From<project::Finding> for Finding {
    fn from(f: project::Finding) -> Self {
        Finding::Unreviewed {
            summary: f.to_string(),
            outside: f
                .outside
                .into_iter()
                .map(|r| Outside {
                    relation: r.relation,
                    covers: r.covers,
                    reviews: r.reviews,
                })
                .collect(),
            subject: f.subject,
            found: f.found,
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::Unreviewed { summary, .. } => f.write_str(summary),
            Finding::Unmatrixed {
                subject,
                found,
                matrix,
            } => write!(
                f,
                "{subject} {found}: not a toolchain test-programs/matrix.toml builds ({})",
                matrix.join(", ")
            ),
            Finding::Primary {
                subject,
                found,
                minor,
                pin,
            } => write!(
                f,
                "{subject} {found}: {minor} is newer than the matrix's primary pin, {pin}"
            ),
            Finding::Fixture {
                subject,
                found,
                fixture,
            } => write!(f, "{subject} {found}: newer than test-programs' {fixture}"),
        }
    }
}

/// Every finding, by kind in the order [`Finding`] lists them:
/// unreviewed releases in the lockfile's order and then the toolchain,
/// primary pins tokio then rustc, fixture lags by crate name.
pub fn findings(inputs: &Inputs<'_>) -> Vec<Finding> {
    let Inputs {
        project,
        channel,
        fixtures,
        matrix,
        reviews,
    } = *inputs;
    let mut findings: Vec<Finding> = package_findings(project, reviews)
        .into_iter()
        .chain(channel_findings(channel, reviews))
        .map(Finding::from)
        .collect();

    if !matrix.toolchain.versions.iter().any(|v| v == channel) {
        findings.push(Finding::Unmatrixed {
            subject: "rustc",
            found: channel.to_string(),
            matrix: matrix.toolchain.versions.clone(),
        });
    }

    let tokio = newest(project, "tokio");
    let rustc = Version::parse(channel).ok();
    for (subject, theirs, pin) in [
        ("tokio", tokio, &matrix.primary.tokio),
        ("rustc", rustc, &matrix.primary.toolchain),
    ] {
        let (Some(theirs), Ok(ours)) = (theirs, Version::parse(pin)) else {
            continue;
        };
        if (theirs.major, theirs.minor) > (ours.major, ours.minor) {
            findings.push(Finding::Primary {
                subject,
                minor: format!("{}.{}", theirs.major, theirs.minor),
                found: theirs.to_string(),
                pin: pin.clone(),
            });
        }
    }

    let crates: BTreeSet<&str> = reviews
        .iter()
        .filter_map(|r| match r.subject {
            Subject::Crate(name) if name != "tokio" => Some(name),
            _ => None,
        })
        .collect();
    for name in crates {
        let (Some(theirs), Some(ours)) = (newest(project, name), newest(fixtures, name)) else {
            continue;
        };
        if theirs > ours {
            findings.push(Finding::Fixture {
                subject: name.to_string(),
                found: theirs.to_string(),
                fixture: ours.to_string(),
            });
        }
    }
    findings
}

/// The newest release of a package a lockfile locks, if it locks one.
fn newest(packages: &[Locked], name: &str) -> Option<Version> {
    packages
        .iter()
        .filter(|p| p.name == name)
        .filter_map(|p| Version::parse(&p.version).ok())
        .max()
}

#[cfg(test)]
mod tests {
    use super::{Finding, Inputs, findings};

    use exegesis::detect::reviewed::project::{Locked, locked};
    use exegesis::detect::reviewed::reviews;
    use testrun::fixture::{Axis, Cells, Matrix, Primary, test_programs_dir};

    /// A matrix pinning tokio 1.52.1 and rustc 1.99.0 as primary, and
    /// building three toolchains.
    fn matrix() -> Matrix {
        let strings = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        Matrix {
            primary: Primary {
                tokio: "1.52.1".to_string(),
                toolchain: "1.99.0".to_string(),
            },
            tokio: Axis {
                floor: "1.47.5".to_string(),
                versions: strings(&["1.47.5", "1.52.1"]),
            },
            toolchain: Axis {
                floor: "1.97.1".to_string(),
                versions: strings(&["1.97.1", "1.98.1", "1.99.0"]),
            },
            cells: Cells {
                no_unstable_tokio: Vec::new(),
                secondary_toolchain_tokio: Vec::new(),
                ct_only_tokio: Vec::new(),
            },
        }
    }

    /// Registry packages of the given `(name, version)`s.
    fn lock(packages: &[(&str, &str)]) -> Vec<Locked> {
        packages
            .iter()
            .map(|(name, version)| Locked {
                name: name.to_string(),
                version: version.to_string(),
                revision: None,
            })
            .collect()
    }

    /// What the fixtures lock in these tests: every crate inside its
    /// reviews, and tokio at the primary pin.
    const FIXTURES: &[(&str, &str)] = &[
        ("tokio", "1.52.1"),
        ("reqwest", "0.13.2"),
        ("hashbrown", "0.16.0"),
        ("tokio-util", "0.7.19"),
        ("serde", "1.0.200"),
    ];

    fn drift(project: &[(&str, &str)], channel: &str) -> Vec<Finding> {
        findings(&Inputs {
            project: &lock(project),
            channel,
            fixtures: &lock(FIXTURES),
            matrix: &matrix(),
            reviews: &reviews(),
        })
    }

    fn kinds(findings: &[Finding]) -> Vec<String> {
        findings
            .iter()
            .map(|f| {
                let value = serde_json::to_value(f).expect("a finding serializes");
                format!("{} {}", value["kind"], value["subject"])
            })
            .collect()
    }

    /// A project locking what the fixtures lock, on the primary
    /// toolchain, has drifted nowhere.
    #[test]
    fn test_a_project_matching_the_fixtures_finds_nothing() {
        assert_eq!(drift(FIXTURES, "1.99.0"), Vec::new());
    }

    /// A reviewed crate the project locks newer than the fixtures do is
    /// fixture drift, named by the newest release of each side; one at
    /// the same release or older is not, nor is a crate no review
    /// covers, one the fixtures do not lock, or tokio, which the primary
    /// pin holds instead.
    #[test]
    fn test_a_newer_reviewed_crate_is_fixture_drift() {
        let found = drift(
            &[
                ("tokio", "1.52.4"),
                ("reqwest", "0.13.5"),
                ("hashbrown", "0.15.5"),
                ("hashbrown", "0.16.1"),
                ("tokio-util", "0.7.18"),
                ("serde", "1.0.228"),
                ("dropshot", "0.17.1"),
            ],
            "1.99.0",
        );
        assert_eq!(
            found,
            vec![
                Finding::Fixture {
                    subject: "hashbrown".to_string(),
                    found: "0.16.1".to_string(),
                    fixture: "0.16.0".to_string(),
                },
                Finding::Fixture {
                    subject: "reqwest".to_string(),
                    found: "0.13.5".to_string(),
                    fixture: "0.13.2".to_string(),
                },
            ]
        );
        assert_eq!(
            found[1].to_string(),
            "reqwest 0.13.5: newer than test-programs' 0.13.2"
        );
    }

    /// A tokio or rustc minor past the primary pin is primary drift,
    /// named by the minor; a newer patch of the pin's own minor is not.
    /// A toolchain past the matrix is also one it does not build, and
    /// one past rustc's reviews unreviewed.
    #[test]
    fn test_a_newer_minor_than_the_primary_is_primary_drift() {
        assert_eq!(drift(&[("tokio", "1.52.4")], "1.99.0"), Vec::new());

        let found = drift(&[("tokio", "1.53.0"), ("tokio", "1.51.5")], "1.100.0");
        assert_eq!(
            kinds(&found),
            [
                "\"unreviewed\" \"rustc\"",
                "\"unmatrixed\" \"rustc\"",
                "\"primary\" \"tokio\"",
                "\"primary\" \"rustc\"",
            ]
        );
        assert_eq!(
            found[2],
            Finding::Primary {
                subject: "tokio",
                found: "1.53.0".to_string(),
                minor: "1.53".to_string(),
                pin: "1.52.1".to_string(),
            }
        );
        assert_eq!(
            found[1].to_string(),
            "rustc 1.100.0: not a toolchain test-programs/matrix.toml builds \
             (1.97.1, 1.98.1, 1.99.0)"
        );
        assert_eq!(
            found[3].to_string(),
            "rustc 1.100.0: 1.100 is newer than the matrix's primary pin, 1.99.0"
        );
    }

    /// A channel naming no release is unreviewed and unbuilt, and lags
    /// no pin: there is no minor to compare.
    #[test]
    fn test_a_channel_naming_no_release_lags_nothing() {
        let found = drift(FIXTURES, "stable");
        assert_eq!(
            kinds(&found),
            ["\"unreviewed\" \"rustc\"", "\"unmatrixed\" \"rustc\""]
        );
        assert_eq!(
            found[0].to_string(),
            "rustc stable: not a release any review can place"
        );
    }

    /// An unreviewed finding carries its structure beside the line
    /// `hansei tokio-info reviewed` prints for it, which issue titles
    /// and bodies are made from.
    #[test]
    fn test_an_unreviewed_release_serializes_whole() {
        let found = drift(&[("hyper", "1.11.0")], "1.99.0");
        let value = serde_json::to_value(&found).expect("findings serialize");
        assert_eq!(
            value,
            serde_json::json!([{
                "kind": "unreviewed",
                "subject": "hyper",
                "found": "1.11.0",
                "outside": [{
                    "relation": "above",
                    "covers": "1.6.0-1.10.1",
                    "reviews": ["hyper-h1-conn-1.6.0"],
                }],
                "summary": "hyper 1.11.0: above 1.6.0-1.10.1 (hyper-h1-conn-1.6.0)",
            }])
        );
        assert_eq!(found[0].to_string(), value[0]["summary"]);
    }

    /// The fixtures, held to themselves on the primary toolchain, have
    /// drifted nowhere: they lock only reviewed releases, their tokio is
    /// the primary pin, and the matrix builds the primary toolchain.
    #[test]
    fn test_the_fixtures_have_not_drifted_from_themselves() {
        let dir = test_programs_dir();
        let text = std::fs::read_to_string(dir.join("Cargo.lock")).expect("the fixture lockfile");
        let fixtures = locked(&text).expect("the fixture lockfile parses");
        let matrix = Matrix::read(&dir);
        let found = findings(&Inputs {
            project: &fixtures,
            channel: &matrix.primary.toolchain,
            fixtures: &fixtures,
            matrix: &matrix,
            reviews: &reviews(),
        });
        assert_eq!(found, Vec::new());
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Every review in one list: the rustc versions, crate releases and git
//! revisions whose layouts and conventions a detector or rule was
//! checked against, and outside which it binds nothing.
//!
//! The reviews themselves live beside the code each one gates, mostly
//! in [`super::semantics`], and their gates read them there. This list
//! is for the questions asked of all of them at once — what does this
//! hansei cover, and does a project's lockfile stay inside it — and a
//! test holds it to every review the source declares, so a new one
//! cannot be left out of it.

use super::semantics::{
    AcquireOwners, DROPSHOT_HANDLER_V0_17_0, DROPSHOT_SERVER_V0_17_0,
    FUTURES_UTIL_ADAPTERS_V0_3_30, GitConvention, HASHBROWN_TABLE_V0_12_3, HTTP_REQUEST_V1_0_0,
    HYPER_H1_CONN_V1_6_0, HYPER_RUSTLS_STREAM_V0_27_0, HYPER_UTIL_AUTO_CONN_V0_1_10,
    HYPER_UTIL_CONNECTED_V0_1_10, HYPER_UTIL_IO_V0_1_10, HYPER_UTIL_POOL_V0_1_16,
    HYPER_UTIL_RESPONSE_V0_1_10, HYPER_UTIL_TOKIO_SLEEP_V0_1_10, LibraryConvention,
    PARKING_LOT_RAW_MUTEX_V0_11_0, REQWEST_CONN_V0_12_14, REQWEST_COOKIE_V0_12_24,
    REQWEST_PENDING_REQUEST_V0_12_0, RUSTC_CONVENTIONS, RUSTLS_SESSION_V0_23_23, Releases,
    SPROCKETS_TLS_CLIENT_D2B68E4, SPROCKETS_TLS_SERVER_D2B68E4, SPROCKETS_TLS_STREAM_D2B68E4,
    StateProtocol, TOKIO_ACQUIRE_OWNERS_V1_47, TOKIO_INTERVAL_TICK_V1_47, TOKIO_RELEASES,
    TOKIO_RUSTLS_HANDSHAKE_V0_26_0, TOKIO_RUSTLS_STREAM_V0_26_0, TOKIO_SELECT_V1_47,
    TOKIO_STATE_PROTOCOLS, TOKIO_STREAM_MAP_V0_1_14, TOKIO_STREAM_WATCH_V0_1_14,
    TOKIO_UTIL_REUSABLE_BOX_V0_7_11, TOWER_RETRY_V0_5_2, TRACING_INSTRUMENTED_V0_1_40,
};
use crate::bundle::LayoutSelection;

use std::fmt;

/// Every reviewed crate release range.
pub const LIBRARY_CONVENTIONS: [&LibraryConvention; 27] = [
    &TRACING_INSTRUMENTED_V0_1_40,
    &PARKING_LOT_RAW_MUTEX_V0_11_0,
    &FUTURES_UTIL_ADAPTERS_V0_3_30,
    &HYPER_UTIL_AUTO_CONN_V0_1_10,
    &HYPER_UTIL_IO_V0_1_10,
    &HYPER_UTIL_TOKIO_SLEEP_V0_1_10,
    &HYPER_UTIL_POOL_V0_1_16,
    &HYPER_UTIL_CONNECTED_V0_1_10,
    &HYPER_UTIL_RESPONSE_V0_1_10,
    &TOWER_RETRY_V0_5_2,
    &REQWEST_COOKIE_V0_12_24,
    &DROPSHOT_SERVER_V0_17_0,
    &REQWEST_PENDING_REQUEST_V0_12_0,
    &HTTP_REQUEST_V1_0_0,
    &DROPSHOT_HANDLER_V0_17_0,
    &HYPER_H1_CONN_V1_6_0,
    &TOKIO_SELECT_V1_47,
    &TOKIO_INTERVAL_TICK_V1_47,
    &TOKIO_STREAM_WATCH_V0_1_14,
    &TOKIO_UTIL_REUSABLE_BOX_V0_7_11,
    &TOKIO_STREAM_MAP_V0_1_14,
    &TOKIO_RUSTLS_STREAM_V0_26_0,
    &RUSTLS_SESSION_V0_23_23,
    &REQWEST_CONN_V0_12_14,
    &HYPER_RUSTLS_STREAM_V0_27_0,
    &TOKIO_RUSTLS_HANDSHAKE_V0_26_0,
    &HASHBROWN_TABLE_V0_12_3,
];

/// Every reviewed set of git revisions.
pub const GIT_CONVENTIONS: [&GitConvention; 3] = [
    &SPROCKETS_TLS_STREAM_D2B68E4,
    &SPROCKETS_TLS_CLIENT_D2B68E4,
    &SPROCKETS_TLS_SERVER_D2B68E4,
];

/// The family name the tokio layout families' reviewed range goes by.
pub const TOKIO_LAYOUT_FAMILIES: &str = "tokio-layout-families";

/// What a review covers: the compiler, or a crate by its package name
/// as a lockfile records it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Subject {
    Rustc,
    Crate(&'static str),
}

impl Subject {
    pub fn name(self) -> &'static str {
        match self {
            Subject::Rustc => "rustc",
            Subject::Crate(package) => package,
        }
    }
}

/// What a review covers of its subject.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Covers {
    /// The releases in each of these spans.
    Releases(Releases),
    /// These git revisions, by full hash, of the named repository.
    Revisions {
        repository: &'static str,
        revisions: Vec<&'static str>,
    },
}

impl fmt::Display for Covers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Covers::Releases(releases) => write!(f, "{releases}"),
            Covers::Revisions { revisions, .. } => {
                let short: Vec<&str> = revisions.iter().map(|r| &r[..r.len().min(9)]).collect();
                write!(f, "{}", short.join(","))
            }
        }
    }
}

/// Where a release falls against a range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Placement {
    Below,
    Inside,
    Above,
}

/// One review: its subject, the name it goes by in warnings and in the
/// bundle (its family), and what of the subject it covers.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Review {
    pub subject: Subject,
    pub family: &'static str,
    pub covers: Covers,
}

impl Review {
    /// Where `version` falls against the reviewed releases — above for
    /// a patch between two spans, which the review did not read — and
    /// the range a finding names for it; `None` for a review of
    /// revisions, which no release number places.
    pub fn place(&self, version: &semver::Version) -> Option<(Placement, String)> {
        let Covers::Releases(releases) = &self.covers else {
            return None;
        };
        let placement = match releases.select(version) {
            LayoutSelection::BelowFloor => Placement::Below,
            LayoutSelection::AboveReviewedRange => Placement::Above,
            _ => Placement::Inside,
        };
        Some((placement, releases.range_for(version)))
    }

    /// Whether the review covers this git revision: a reviewed full
    /// hash it is a prefix of, as a lockfile's `#rev` or a checkout's
    /// abbreviation names one. `None` for a review of releases.
    pub fn covers_revision(&self, revision: &str) -> Option<bool> {
        let Covers::Revisions { revisions, .. } = &self.covers else {
            return None;
        };
        Some(!revision.is_empty() && revisions.iter().any(|r| r.starts_with(revision)))
    }
}

fn library(c: &LibraryConvention) -> Review {
    Review {
        subject: Subject::Crate(c.package),
        family: c.family,
        covers: Covers::Releases(c.releases),
    }
}

fn git(c: &GitConvention) -> Review {
    Review {
        subject: Subject::Crate(c.package),
        family: c.family,
        covers: Covers::Revisions {
            repository: c.repository,
            revisions: c.revisions.iter().map(|&(rev, _)| rev).collect(),
        },
    }
}

fn tokio(family: &'static str, releases: Releases) -> Review {
    Review {
        subject: Subject::Crate("tokio"),
        family,
        covers: Covers::Releases(releases),
    }
}

fn state(p: &StateProtocol) -> Review {
    tokio(p.family, p.releases)
}

fn owners(o: &AcquireOwners) -> Review {
    tokio(o.family, o.releases)
}

/// What a review records of the sources it read, for the matrix suite
/// to hold against the sources each cell builds: its subject, name and
/// releases, and the md5 of every reviewed revision of each file it
/// read — relative to the crate root, or for rustc to the root of the
/// toolchain's `rust-src`.
#[derive(Clone, Copy, Debug)]
pub struct Sources {
    pub subject: Subject,
    pub family: &'static str,
    pub releases: Releases,
    pub checksums: &'static [(&'static str, [u8; 16])],
}

/// Every review that records the sources it read: each rustc
/// convention, crate release review, tokio state protocol and the
/// acquire owners. A git review is held to its revisions instead, and
/// the layout families read no one file.
pub fn sources() -> Vec<Sources> {
    let rustc = RUSTC_CONVENTIONS.iter().map(|c| Sources {
        subject: Subject::Rustc,
        family: c.family,
        releases: c.releases,
        checksums: c.checksums,
    });
    let library = LIBRARY_CONVENTIONS.iter().map(|c| Sources {
        subject: Subject::Crate(c.package),
        family: c.family,
        releases: c.releases,
        checksums: c.checksums,
    });
    let protocols = TOKIO_STATE_PROTOCOLS.iter().map(|p| Sources {
        subject: Subject::Crate("tokio"),
        family: p.family,
        releases: p.releases,
        checksums: p.checksums,
    });
    let owners = &TOKIO_ACQUIRE_OWNERS_V1_47;
    rustc
        .chain(library)
        .chain(protocols)
        .chain([Sources {
            subject: Subject::Crate("tokio"),
            family: owners.family,
            releases: owners.releases,
            checksums: owners.checksums,
        }])
        .collect()
}

/// Every review this hansei carries: rustc's conventions, the crate
/// releases and git revisions, tokio's state protocols, and the tokio
/// layout families' reviewed releases.
pub fn reviews() -> Vec<Review> {
    let rustc = RUSTC_CONVENTIONS.iter().map(|c| Review {
        subject: Subject::Rustc,
        family: c.family,
        covers: Covers::Releases(c.releases),
    });
    let families = tokio(TOKIO_LAYOUT_FAMILIES, TOKIO_RELEASES);
    rustc
        .chain(LIBRARY_CONVENTIONS.iter().map(|c| library(c)))
        .chain(GIT_CONVENTIONS.iter().map(|c| git(c)))
        .chain(TOKIO_STATE_PROTOCOLS.iter().map(|p| state(p)))
        .chain([owners(&TOKIO_ACQUIRE_OWNERS_V1_47), families])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    /// The reviews the source declares, by kind, as `pub const NAME:
    /// Kind = …` lines. Counting declarations rather than naming them
    /// is enough with family names unique: a declaration left out of
    /// the list leaves its kind's count short.
    fn declared(kind: &str) -> usize {
        let source = include_str!("semantics.rs");
        let needle = format!(": {kind} = ");
        source
            .lines()
            .filter(|l| l.starts_with("pub const ") && l.contains(&needle))
            .count()
    }

    /// Every review the source declares is in the list, once.
    #[test]
    fn test_every_declared_review_is_listed() {
        assert_eq!(LIBRARY_CONVENTIONS.len(), declared("LibraryConvention"));
        assert_eq!(GIT_CONVENTIONS.len(), declared("GitConvention"));
        assert_eq!(RUSTC_CONVENTIONS.len(), declared("RustcConvention"));
        assert_eq!(TOKIO_STATE_PROTOCOLS.len(), declared("StateProtocol"));
        assert_eq!(1, declared("AcquireOwners"));

        let all = reviews();
        let families: BTreeSet<&str> = all.iter().map(|r| r.family).collect();
        assert_eq!(families.len(), all.len(), "a family is listed twice");
        assert_eq!(
            all.len(),
            LIBRARY_CONVENTIONS.len()
                + GIT_CONVENTIONS.len()
                + RUSTC_CONVENTIONS.len()
                + TOKIO_STATE_PROTOCOLS.len()
                + 2
        );
        // Every review but the git ones and the layout families is in
        // the list the matrix suite holds to the sources it builds.
        assert_eq!(sources().len(), all.len() - GIT_CONVENTIONS.len() - 1);
    }

    /// Every review's spans run forward and in order: a floor above its
    /// ceiling would place every release outside, and an overlap would
    /// mean two spans claim one minor.
    #[test]
    fn test_every_range_runs_forward() {
        for review in reviews() {
            if let Covers::Releases(releases) = &review.covers {
                assert!(!releases.0.is_empty(), "{}", review.family);
                for &(floor, ceiling) in releases.0 {
                    assert!(
                        floor <= ceiling,
                        "{}: {floor:?} > {ceiling:?}",
                        review.family
                    );
                }
                for pair in releases.0.windows(2) {
                    assert!(pair[0].1 < pair[1].0, "{}: {pair:?}", review.family);
                }
            }
        }
    }

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    /// A span is exact at both ends, and a patch between two spans is
    /// above the review, named against the span below it.
    #[test]
    fn test_releases_place_at_patch_granularity() {
        let place = |r: &Review, s: &str| r.place(&v(s)).map(|(p, _)| p);
        let one = library(&HYPER_H1_CONN_V1_6_0);
        assert_eq!(place(&one, "1.5.9"), Some(Placement::Below));
        assert_eq!(place(&one, "1.6.0"), Some(Placement::Inside));
        assert_eq!(place(&one, "1.10.1"), Some(Placement::Inside));
        assert_eq!(place(&one, "1.10.2"), Some(Placement::Above));

        let spans = tokio(
            "t",
            Releases(&[((1, 47, 0), (1, 47, 5)), ((1, 48, 0), (1, 48, 2))]),
        );
        assert_eq!(place(&spans, "1.46.9"), Some(Placement::Below));
        assert_eq!(place(&spans, "1.47.0"), Some(Placement::Inside));
        assert_eq!(place(&spans, "1.47.5"), Some(Placement::Inside));
        assert_eq!(
            spans.place(&v("1.47.6")),
            Some((Placement::Above, "1.47.0-1.47.5".to_string()))
        );
        assert_eq!(place(&spans, "1.48.2"), Some(Placement::Inside));
        assert_eq!(
            spans.place(&v("1.49.0")),
            Some((Placement::Above, "1.47.0-1.48.2".to_string()))
        );
        assert_eq!(spans.covers.to_string(), "1.47.0-1.47.5,1.48.0-1.48.2");
        assert_eq!(spans.covers_revision("abc"), None);
    }

    /// A revision review covers a reviewed hash by any prefix of it,
    /// and nothing else; a release number places nothing there.
    #[test]
    fn test_revisions_are_covered_by_prefix() {
        let review = git(&SPROCKETS_TLS_STREAM_D2B68E4);
        let Covers::Revisions { revisions, .. } = &review.covers else {
            unreachable!()
        };
        let full = revisions[0];
        assert_eq!(review.covers_revision(full), Some(true));
        assert_eq!(review.covers_revision(&full[..7]), Some(true));
        assert_eq!(review.covers_revision("0000000"), Some(false));
        assert_eq!(review.covers_revision(""), Some(false));
        assert_eq!(review.place(&v("0.1.0")), None);
    }
}

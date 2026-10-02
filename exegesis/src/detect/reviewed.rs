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

use super::Family;
use super::semantics::{
    AcquireOwners, DROPSHOT_HANDLER_V0_17_0, DROPSHOT_SERVER_V0_17_0,
    FUTURES_UTIL_ADAPTERS_V0_3_30, GitConvention, HASHBROWN_TABLE_V0_12_3, HTTP_REQUEST_V1_0_0,
    HYPER_H1_CONN_V1_6_0, HYPER_RUSTLS_STREAM_V0_27_0, HYPER_UTIL_AUTO_CONN_V0_1_10,
    HYPER_UTIL_CONNECTED_V0_1_10, HYPER_UTIL_IO_V0_1_10, HYPER_UTIL_POOL_V0_1_16,
    HYPER_UTIL_RESPONSE_V0_1_10, HYPER_UTIL_TOKIO_SLEEP_V0_1_10, LibraryConvention,
    PARKING_LOT_RAW_MUTEX_V0_12_1, REQWEST_CONN_V0_12_14, REQWEST_COOKIE_V0_12_24,
    REQWEST_PENDING_REQUEST_V0_12_0, RUSTC_CONVENTIONS, RUSTLS_SESSION_V0_23_23,
    SPROCKETS_TLS_CLIENT_D2B68E4, SPROCKETS_TLS_SERVER_D2B68E4, SPROCKETS_TLS_STREAM_D2B68E4,
    StateProtocol, TOKIO_ACQUIRE_OWNERS_V1_47, TOKIO_INTERVAL_TICK_V1_47,
    TOKIO_RUSTLS_HANDSHAKE_V0_26_0, TOKIO_RUSTLS_STREAM_V0_26_0, TOKIO_SELECT_V1_47,
    TOKIO_STATE_PROTOCOLS, TOKIO_STREAM_MAP_V0_1_14, TOKIO_STREAM_WATCH_V0_1_14,
    TOKIO_UTIL_REUSABLE_BOX_V0_7_11, TOWER_RETRY_V0_5_2, TRACING_INSTRUMENTED_V0_1_40,
};

use std::cmp::Ordering;
use std::fmt;

/// Every reviewed crate release range.
pub const LIBRARY_CONVENTIONS: [&LibraryConvention; 27] = [
    &TRACING_INSTRUMENTED_V0_1_40,
    &PARKING_LOT_RAW_MUTEX_V0_12_1,
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

/// One end of a reviewed range. A bound with no patch is a minor
/// release's every patch: as a floor it starts at `.0`, as a ceiling it
/// takes in every patch of that minor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bound {
    pub major: u64,
    pub minor: u64,
    pub patch: Option<u64>,
}

impl Bound {
    const fn minor(major: u64, minor: u64) -> Self {
        Bound {
            major,
            minor,
            patch: None,
        }
    }

    const fn patch((major, minor, patch): (u64, u64, u64)) -> Self {
        Bound {
            major,
            minor,
            patch: Some(patch),
        }
    }

    /// How a version compares with this bound, a patchless bound
    /// equal to every patch of its minor.
    fn cmp_version(&self, version: &semver::Version) -> Ordering {
        let minor = (version.major, version.minor).cmp(&(self.major, self.minor));
        match self.patch {
            Some(patch) => minor.then(version.patch.cmp(&patch)),
            None => minor,
        }
    }
}

impl fmt::Display for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.patch {
            Some(patch) => write!(f, "{}.{}.{patch}", self.major, self.minor),
            None => write!(f, "{}.{}", self.major, self.minor),
        }
    }
}

/// What a review covers of its subject.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Covers {
    /// Every release from `floor` to `ceiling`, both inclusive.
    Releases { floor: Bound, ceiling: Bound },
    /// These git revisions, by full hash, of the named repository.
    Revisions {
        repository: &'static str,
        revisions: Vec<&'static str>,
    },
}

impl fmt::Display for Covers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Covers::Releases { floor, ceiling } => write!(f, "{floor}-{ceiling}"),
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
    /// Where `version` falls against the reviewed releases; `None` for a
    /// review of revisions, which no release number places.
    pub fn place(&self, version: &semver::Version) -> Option<Placement> {
        let Covers::Releases { floor, ceiling } = &self.covers else {
            return None;
        };
        Some(if floor.cmp_version(version) == Ordering::Less {
            Placement::Below
        } else if ceiling.cmp_version(version) == Ordering::Greater {
            Placement::Above
        } else {
            Placement::Inside
        })
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
        covers: Covers::Releases {
            floor: Bound::patch(c.floor),
            ceiling: Bound::patch(c.ceiling),
        },
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

fn tokio_minor(family: &'static str, floor: (u64, u64), ceiling: (u64, u64)) -> Review {
    Review {
        subject: Subject::Crate("tokio"),
        family,
        covers: Covers::Releases {
            floor: Bound::minor(floor.0, floor.1),
            ceiling: Bound::minor(ceiling.0, ceiling.1),
        },
    }
}

fn state(p: &StateProtocol) -> Review {
    tokio_minor(p.family, p.floor, p.ceiling)
}

fn owners(o: &AcquireOwners) -> Review {
    tokio_minor(o.family, o.floor, o.ceiling)
}

/// Every review this hansei carries: rustc's conventions, the crate
/// releases and git revisions, tokio's state protocols, and the tokio
/// layout families' reviewed range.
pub fn reviews() -> Vec<Review> {
    let rustc = RUSTC_CONVENTIONS.iter().map(|c| Review {
        subject: Subject::Rustc,
        family: c.family,
        covers: Covers::Releases {
            floor: Bound::minor(c.floor.0, c.floor.1),
            ceiling: Bound::minor(c.ceiling.0, c.ceiling.1),
        },
    });
    let families = {
        let floor = Family::ALL[0].floor();
        tokio_minor(TOKIO_LAYOUT_FAMILIES, floor, Family::REVIEWED_CEILING)
    };
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
    }

    /// Every range runs forward: a floor above its ceiling would place
    /// every release outside.
    #[test]
    fn test_every_range_runs_forward() {
        for review in reviews() {
            if let Covers::Releases { floor, ceiling } = &review.covers {
                let floor = (floor.major, floor.minor, floor.patch.unwrap_or(0));
                let ceiling = (
                    ceiling.major,
                    ceiling.minor,
                    ceiling.patch.unwrap_or(u64::MAX),
                );
                assert!(
                    floor <= ceiling,
                    "{}: {floor:?} > {ceiling:?}",
                    review.family
                );
            }
        }
    }

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    /// A patch bound is exact at both ends; a patchless one takes in
    /// every patch of its minor.
    #[test]
    fn test_releases_place_at_the_bounds_granularity() {
        let patch = library(&HYPER_H1_CONN_V1_6_0);
        assert_eq!(patch.place(&v("1.5.9")), Some(Placement::Below));
        assert_eq!(patch.place(&v("1.6.0")), Some(Placement::Inside));
        let Covers::Releases { ceiling, .. } = patch.covers else {
            unreachable!()
        };
        assert_eq!(
            patch.place(&v(&ceiling.to_string())),
            Some(Placement::Inside)
        );
        let past = semver::Version::new(ceiling.major, ceiling.minor, ceiling.patch.unwrap() + 1);
        assert_eq!(patch.place(&past), Some(Placement::Above));

        let minor = tokio_minor("t", (1, 47), (1, 53));
        assert_eq!(minor.place(&v("1.46.9")), Some(Placement::Below));
        assert_eq!(minor.place(&v("1.47.0")), Some(Placement::Inside));
        assert_eq!(minor.place(&v("1.53.99")), Some(Placement::Inside));
        assert_eq!(minor.place(&v("1.54.0")), Some(Placement::Above));
        assert_eq!(minor.covers_revision("abc"), None);
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

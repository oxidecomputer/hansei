// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The crate release each emitted type's own declarations name — the
//! type table's `crate_labels`.
//!
//! A type DIE carries a name and a namespace and no version. A target
//! that links one crate at two releases has two types under one name
//! wherever the releases disagree on the layout, and the only version
//! evidence the DWARF holds is in the files its functions are declared
//! in: a cargo registry path spells `<crate>-<version>`. So a type's
//! release is read from the functions whose `self` is that type — its
//! methods, its `poll`, a coroutine's resume function — and from the
//! type's own declaration file where rustc recorded one, keeping only
//! the files inside the type's own crate. A downstream crate's `impl`
//! of a foreign trait for the type, and every generic the type is
//! passed to, are declared under other crates' paths and say nothing
//! about the type's release; a unit's compilation directory names the
//! crate that instantiated a generic, not the crate that defined it.
//! Where nothing inside the type's crate declares anything on it, the
//! type gets no label rather than a guess.

use super::Emitter;
use super::sweep::source_of;
use crate::bundle::BundleTypeId;
use crate::bundle::origin::registry_origin;
use crate::raw_types::{RawType, SourceLoc};
use crate::{DwReader, StrId, TypeId};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// What the declarations of the emitted types say about their releases.
#[derive(Default)]
pub(super) struct Labels {
    /// Per emitted type, the package its declarations are written under
    /// and every release of it they name, ascending.
    pub(super) labels: BTreeMap<BundleTypeId, (String, Vec<semver::Version>)>,
    /// Types whose declarations named two different packages that both
    /// spell the type's crate root, so neither is the label.
    pub(super) declined: usize,
}

impl Labels {
    /// How many labeled types name more than one release: two releases
    /// whose layouts of the type agree are one type that both declare.
    pub(super) fn several_releases(&self) -> usize {
        self.labels
            .values()
            .filter(|(_, versions)| versions.len() > 1)
            .count()
    }
}

/// A recorded location's identity, as its interned parts: every
/// function declared in one file of one unit shares these, so the path
/// is joined and parsed once per distinct triple rather than once per
/// function.
type LocKey = (Option<StrId>, Option<StrId>, Option<StrId>);

fn loc_key(loc: &SourceLoc<StrId>) -> LocKey {
    (loc.file, loc.dir, loc.comp_dir)
}

/// Read every emitted type's release from the declarations inside its
/// own crate.
pub(super) fn crate_labels(reader: &DwReader<'_>, em: &Emitter<'_>) -> Labels {
    let emitted: HashMap<TypeId, BundleTypeId> = em.emitted_ids().collect();

    // Every (emitted type, declaring location) pair the function table
    // offers: a function whose `self` is an emitted type is a
    // declaration on it. The table is large (millions of functions on
    // a real target) and the classification is read-only, so it is
    // fanned out; the pairs are few (one per method file) and are
    // resolved serially below.
    let mut pairs: HashSet<(BundleTypeId, LocKey)> = reader
        .functions
        .par_iter()
        .fold(HashSet::new, |mut acc, (_, func)| {
            if let Some(loc) = func.source_loc.as_deref()
                && let Some(first) = func.formal_parameters.first().and_then(|p| p.type_id)
                && let Some(target) = self_target(reader, first)
                && let Some(&bid) = emitted.get(&target)
            {
                acc.insert((bid, loc_key(loc)));
            }
            acc
        })
        .reduce(HashSet::new, |mut a, b| {
            a.extend(b);
            a
        });

    // The type's own declaration file, where rustc recorded one.
    for (&tid, &bid) in &emitted {
        if let Some(RawType::Struct(st)) = reader.canonical_type(tid)
            && let Some(loc) = st.source_loc.as_deref()
        {
            pairs.insert((bid, loc_key(loc)));
        }
    }

    // Each distinct location parsed once; each type's crate root once.
    let mut origins: HashMap<LocKey, Option<(String, semver::Version)>> = HashMap::new();
    let mut roots: HashMap<BundleTypeId, Option<&str>> = HashMap::new();
    let by_bid: HashMap<BundleTypeId, TypeId> = emitted.iter().map(|(&t, &b)| (b, t)).collect();
    let mut found: BTreeMap<BundleTypeId, BTreeMap<String, BTreeSet<semver::Version>>> =
        BTreeMap::new();
    for (bid, key) in pairs {
        let root = *roots
            .entry(bid)
            .or_insert_with(|| crate_root(reader, by_bid[&bid]));
        let Some(root) = root else {
            continue;
        };
        let origin = origins.entry(key).or_insert_with(|| {
            let loc = SourceLoc {
                file_id: None,
                file: key.0,
                dir: key.1,
                comp_dir: key.2,
                line: None,
                column: None,
            };
            source_of(reader, &loc).and_then(|source| {
                registry_origin(&source.path)
                    .map(|origin| (origin.package.to_owned(), origin.version))
            })
        });
        let Some((package, version)) = origin else {
            continue;
        };
        if !package_names_crate(package, root) {
            continue;
        }
        found
            .entry(bid)
            .or_default()
            .entry(package.clone())
            .or_default()
            .insert(version.clone());
    }

    let mut out = Labels::default();
    for (bid, packages) in found {
        let mut packages = packages.into_iter();
        let (package, versions) = packages.next().expect("a noted type names a package");
        if packages.next().is_some() {
            out.declined += 1;
            continue;
        }
        out.labels
            .insert(bid, (package, versions.into_iter().collect()));
    }
    out
}

/// The type a method's `self` parameter is on: `T` for `T`, `&T`,
/// `&mut T`, `*const T` and `Pin<&mut T>`, canonicalized. `None` for a
/// parameter whose type the reader cannot follow.
fn self_target(reader: &DwReader<'_>, mut id: TypeId) -> Option<TypeId> {
    // A `Pin<&mut T>` is two levels; anything deeper is not a self.
    for _ in 0..4 {
        match reader.canonical_type(id)? {
            RawType::Pointer(p) => id = p.target_type_id,
            RawType::Struct(st)
                if st
                    .name
                    .is_some_and(|n| reader.strings.get(n).starts_with("Pin<")) =>
            {
                id = st.members.first()?.type_id;
            }
            _ => return Some(reader.canonicalize(id)),
        }
    }
    None
}

/// The crate a type belongs to: the outermost namespace of its path.
/// `None` for a type outside every namespace (a primitive, an
/// anonymous pointer).
fn crate_root<'r>(reader: &'r DwReader<'_>, id: TypeId) -> Option<&'r str> {
    let mut ns = reader.canonical_type(id)?.namespace()?;
    loop {
        let entry = reader.namespaces.get(ns);
        match entry.parent {
            Some(parent) => ns = parent,
            None => return Some(reader.strings.get(entry.name)),
        }
    }
}

/// Whether a registry package directory names the crate `root` is the
/// path of: cargo spells `hickory-proto` where rustc spells
/// `hickory_proto`.
fn package_names_crate(package: &str, root: &str) -> bool {
    package.len() == root.len()
        && package
            .bytes()
            .zip(root.bytes())
            .all(|(p, r)| p == r || (p == b'-' && r == b'_'))
}

#[cfg(test)]
mod tests {
    use super::{Labels, package_names_crate};
    use crate::bundle::BundleTypeId;

    use semver::Version;

    #[test]
    fn test_several_releases_counts_labels_naming_more_than_one() {
        let mut labels = Labels::default();
        let label = |versions: &[Version]| ("a".to_owned(), versions.to_vec());
        labels
            .labels
            .insert(BundleTypeId(1), label(&[Version::new(1, 0, 0)]));
        labels.labels.insert(
            BundleTypeId(2),
            label(&[Version::new(1, 0, 0), Version::new(2, 0, 0)]),
        );
        labels
            .labels
            .insert(BundleTypeId(3), label(&[Version::new(3, 1, 4)]));
        assert_eq!(labels.several_releases(), 1);
    }

    #[test]
    fn test_a_package_names_its_crate_across_the_dash() {
        assert!(package_names_crate("reqwest", "reqwest"));
        assert!(package_names_crate("hickory-proto", "hickory_proto"));
        assert!(package_names_crate("hickory_proto", "hickory_proto"));
        // The dash is cargo's spelling, never rustc's.
        assert!(!package_names_crate("hickory_proto", "hickory-proto"));
        // The dash stands in for an underscore, never for anything else,
        // and nothing stands in for the dash.
        assert!(!package_names_crate("hickory-proto", "hickoryxproto"));
        assert!(!package_names_crate("hickoryxproto", "hickory_proto"));
        assert!(!package_names_crate("tough", "reqwest"));
        assert!(!package_names_crate("reqwest", "reqwest_middleware"));
        assert!(!package_names_crate("", "reqwest"));
    }
}

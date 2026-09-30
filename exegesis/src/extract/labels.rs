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
//! type takes its crate's release only when the binary's functions name
//! exactly one release of that crate's package, and otherwise gets no
//! label rather than a guess: which of a generic's methods keep a
//! declaration is the optimizer's call, so without the fallback one
//! type's label would come and go with unrelated source edits.

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

/// Every emitted type's release, read off what [`declared_releases`]
/// gathered for it.
pub(super) fn crate_labels(em: &Emitter<'_>, declared: &Declared) -> Labels {
    let mut labels = BTreeMap::new();
    let mut declined = 0;
    for (tid, bid) in em.emitted_ids() {
        if let Some(label) = declared.labels.get(&tid) {
            labels.insert(bid, label.clone());
        } else if declared.declined.contains(&tid) {
            declined += 1;
        }
    }
    Labels { labels, declined }
}

/// What the declarations inside each of a set of types' own crates say
/// about its release.
pub(super) struct Declared {
    /// Per type, the package its declarations are written under and
    /// every release of it they name, ascending.
    pub(super) labels: BTreeMap<TypeId, (String, Vec<semver::Version>)>,
    /// Types whose declarations named two different packages that both
    /// name the type's crate root, so neither is the label.
    pub(super) declined: HashSet<TypeId>,
}

/// The package and releases the declarations of each of `targets` name
/// inside its own crate. The crate labels and the release sizes both
/// read it, over the emitted types and every plain type respectively;
/// it is gathered once for the two, since each gathering is a pass
/// over the whole function table.
pub(super) fn declared_releases(reader: &DwReader<'_>, targets: &HashSet<TypeId>) -> Declared {
    // Every (target, declaring location) pair the function table
    // offers: a function whose `self` is a target is a declaration on
    // it. The table is large (millions of functions on a real target)
    // and the classification is read-only, so it is fanned out; the
    // pairs are few (one per method file) and are resolved serially
    // below.
    let mut pairs: HashSet<(TypeId, LocKey)> = reader
        .functions
        .par_iter()
        .fold(HashSet::new, |mut acc, (_, func)| {
            if let Some(loc) = func.source_loc.as_deref()
                && let Some(first) = func.formal_parameters.first().and_then(|p| p.type_id)
                && let Some(target) = self_target(reader, first)
                && targets.contains(&target)
            {
                acc.insert((target, loc_key(loc)));
            }
            acc
        })
        .reduce(HashSet::new, |mut a, b| {
            a.extend(b);
            a
        });

    // The type's own declaration file, where rustc recorded one.
    for &tid in targets {
        if let Some(RawType::Struct(st)) = reader.canonical_type(tid)
            && let Some(loc) = st.source_loc.as_deref()
        {
            pairs.insert((tid, loc_key(loc)));
        }
    }

    let origin_of = |key: LocKey| {
        let loc = SourceLoc {
            file_id: None,
            file: key.0,
            dir: key.1,
            comp_dir: key.2,
            line: None,
            column: None,
        };
        source_of(reader, &loc).and_then(|source| {
            registry_origin(&source.path).map(|origin| (origin.package.to_owned(), origin.version))
        })
    };
    // Every release of every registry package the binary links, and
    // every crate the standard library vendors: the files each unit's
    // line program lists, which name every crate whose code the unit
    // compiled — a generic's included, wherever it was instantiated.
    let listed: HashSet<LocKey> = reader
        .origins
        .values()
        .flat_map(|origin| {
            origin
                .source_files
                .iter()
                .map(|file| loc_key(&file.location))
        })
        .collect();
    let linked: Linked = listed
        .par_iter()
        .fold(Linked::default, |mut acc, &key| {
            let loc = SourceLoc {
                file_id: None,
                file: key.0,
                dir: key.1,
                comp_dir: key.2,
                line: None,
                column: None,
            };
            if let Some(source) = source_of(reader, &loc) {
                if let Some(origin) = registry_origin(&source.path) {
                    acc.registry
                        .entry(origin.package.to_owned())
                        .or_default()
                        .insert(origin.version);
                } else if let Some(package) = vendored_package(&source.path) {
                    acc.vendored.insert(package.to_owned());
                }
            }
            acc
        })
        .reduce(Linked::default, |mut a, b| {
            for (package, versions) in b.registry {
                a.registry.entry(package).or_default().extend(versions);
            }
            a.vendored.extend(b.vendored);
            a
        });

    // Each distinct location parsed once.
    let mut origins: HashMap<LocKey, Option<(String, semver::Version)>> = HashMap::new();
    // Each type's crate root once.
    let mut roots: HashMap<TypeId, Option<&str>> = HashMap::new();
    let mut found: BTreeMap<TypeId, BTreeMap<String, BTreeSet<semver::Version>>> = BTreeMap::new();
    for (tid, key) in pairs {
        let root = *roots.entry(tid).or_insert_with(|| crate_root(reader, tid));
        let Some(root) = root else {
            continue;
        };
        let Some((package, version)) = origins.entry(key).or_insert_with(|| origin_of(key)) else {
            continue;
        };
        if !package_names_crate(package, root) {
            continue;
        }
        found
            .entry(tid)
            .or_default()
            .entry(package.clone())
            .or_default()
            .insert(version.clone());
    }

    let mut labels = BTreeMap::new();
    let mut declined = HashSet::new();
    for (tid, packages) in found {
        let mut packages = packages.into_iter();
        let (package, versions) = packages.next().expect("a noted type names a package");
        if packages.next().is_some() {
            declined.insert(tid);
            continue;
        }
        labels.insert(tid, (package, versions.into_iter().collect()));
    }
    // A type nothing inside its crate declares anything on — whether a
    // method's declaration survives is the optimizer's call, made anew
    // per build — still has one release to be of where the binary links
    // its crate at exactly one. Every plain type is a target, so the
    // roots are read fanned out.
    let sole = sole_releases(&linked);
    let lent: Vec<(TypeId, (String, Vec<semver::Version>))> = targets
        .par_iter()
        .filter(|tid| !labels.contains_key(tid) && !declined.contains(tid))
        .filter_map(|&tid| {
            let (package, version) = sole.get(crate_root(reader, tid)?)?;
            Some((tid, (package.clone(), vec![version.clone()])))
        })
        .collect();
    labels.extend(lent);
    Declared { labels, declined }
}

/// The crates a binary's line tables name: each registry package with
/// every release of it, and the crates the standard library vendors.
#[derive(Default)]
struct Linked {
    registry: BTreeMap<String, BTreeSet<semver::Version>>,
    /// Packages under rustc's remapped `/rust/deps/<crate>-<version>/`:
    /// std's own copy of a crate (hashbrown, …), a compilation apart
    /// from any registry copy of the same crate, whose types carry the
    /// same names.
    vendored: BTreeSet<String>,
}

/// Per crate root, the one release of the one registry package naming
/// it that the binary links, where that is every copy of the crate it
/// links: two packages naming one root, one package at two releases, or
/// a copy std vendors beside the registry's leave the root out.
fn sole_releases(linked: &Linked) -> HashMap<String, (String, semver::Version)> {
    let root_of = |package: &str| package.replace('-', "_");
    let vendored: HashSet<String> = linked.vendored.iter().map(|p| root_of(p)).collect();
    let mut by_root: HashMap<String, Vec<(&String, &BTreeSet<semver::Version>)>> = HashMap::new();
    for (package, versions) in &linked.registry {
        by_root
            .entry(root_of(package))
            .or_default()
            .push((package, versions));
    }
    by_root
        .into_iter()
        .filter(|(root, _)| !vendored.contains(root))
        .filter_map(|(root, packages)| match packages[..] {
            [(package, versions)] if versions.len() == 1 => {
                let version = versions.first().expect("one release").clone();
                Some((root, (package.clone(), version)))
            }
            _ => None,
        })
        .collect()
}

/// The crate a path under rustc's remapped `/rust/deps/` names: the
/// directory after it, `<crate>-<version>`, split at the first `-` whose
/// right side is a whole version, as a registry directory is.
fn vendored_package(path: &str) -> Option<&str> {
    let (_, rest) = path.split_once("/rust/deps/")?;
    let (dir, _) = rest.split_once('/')?;
    dir.match_indices('-')
        .map(|(at, _)| (&dir[..at], &dir[at + 1..]))
        .find(|(package, version)| !package.is_empty() && semver::Version::parse(version).is_ok())
        .map(|(package, _)| package)
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
pub(super) fn crate_root<'r>(reader: &'r DwReader<'_>, id: TypeId) -> Option<&'r str> {
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
pub(super) fn package_names_crate(package: &str, root: &str) -> bool {
    package.len() == root.len()
        && package
            .bytes()
            .zip(root.bytes())
            .all(|(p, r)| p == r || (p == b'-' && r == b'_'))
}

#[cfg(test)]
mod tests {
    use super::{Labels, Linked, package_names_crate, sole_releases, vendored_package};
    use crate::bundle::BundleTypeId;

    use semver::Version;

    /// A crate the binary links at one release lends it to a type
    /// nothing declares on; a second release, a second package naming
    /// the same crate, or std's own copy of it leaves the type
    /// unlabeled.
    #[test]
    fn test_a_sole_release_labels_the_crates_types() {
        let linked = |entries: &[(&str, &[Version])]| Linked {
            registry: entries
                .iter()
                .map(|(package, versions)| {
                    (package.to_string(), versions.iter().cloned().collect())
                })
                .collect(),
            vendored: Default::default(),
        };
        let one = linked(&[
            ("tokio", &[Version::new(1, 48, 0)]),
            ("hickory-proto", &[Version::new(0, 24, 1)]),
        ]);
        assert_eq!(
            sole_releases(&one).get("tokio"),
            Some(&("tokio".to_owned(), Version::new(1, 48, 0)))
        );
        assert_eq!(
            sole_releases(&one).get("hickory_proto"),
            Some(&("hickory-proto".to_owned(), Version::new(0, 24, 1)))
        );
        // Not a registry crate the binary links: the fixture's own, or
        // core.
        assert_eq!(sole_releases(&one).get("core"), None);
        let two = linked(&[("tokio", &[Version::new(1, 47, 5), Version::new(1, 48, 0)])]);
        assert_eq!(sole_releases(&two).get("tokio"), None);
        let two_names = linked(&[
            ("hickory-proto", &[Version::new(0, 24, 1)]),
            ("hickory_proto", &[Version::new(0, 24, 1)]),
        ]);
        assert_eq!(sole_releases(&two_names).get("hickory_proto"), None);
        let mut beside_std = linked(&[
            ("hashbrown", &[Version::new(0, 17, 1)]),
            ("tokio", &[Version::new(1, 48, 0)]),
        ]);
        beside_std.vendored.insert("hashbrown".to_owned());
        assert_eq!(sole_releases(&beside_std).get("hashbrown"), None);
        assert!(sole_releases(&beside_std).contains_key("tokio"));
    }

    /// std's vendored crates sit under rustc's remapped `/rust/deps/`,
    /// named the way a registry directory is.
    #[test]
    fn test_a_vendored_path_names_its_crate() {
        assert_eq!(
            vendored_package("/rust/deps/hashbrown-0.17.1/src/map.rs"),
            Some("hashbrown")
        );
        assert_eq!(
            vendored_package("/rust/deps/rustc-demangle-0.1.26/src/lib.rs"),
            Some("rustc-demangle")
        );
        assert_eq!(vendored_package("/rust/deps/hashbrown/src/map.rs"), None);
        assert_eq!(
            vendored_package("/rustc/88d9e12ae/library/std/src/lib.rs"),
            None
        );
    }

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

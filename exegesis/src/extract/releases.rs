// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The sizes a crate's releases give the types they declare — the type
//! table's `release_sizes`.
//!
//! A binary that links one crate at two releases instantiates a generic
//! over that crate's types once per release, and a target built apart
//! from this binary names both instantiations with one hash-free
//! symbol. What tells the target's crate hashes apart is a layout the
//! releases disagree on: a vtable in the target records its concrete
//! type's size beside the drop glue whose symbol names the type under
//! the target's hash. This pass finds every such disagreement the
//! DWARF holds: each struct, enum and union whose declarations name
//! one release of its own crate (read as the crate labels are read),
//! grouped by crate and name, kept where the crate has two releases or
//! more and each release gives the type one size no other release
//! gives it.
//!
//! Only plain types count. A closure or coroutine environment is laid
//! out after the compiler's optimizations, and a debug build and a
//! production build of the same source can give it two sizes; a type
//! holding one by value, at any depth, inherits the doubt. Everything
//! else is laid out from its fields alone.

use super::fq_name;
use super::labels::Declared;
use crate::raw_types::{RawType, VariantShape};
use crate::{DwReader, StrId, TypeId};

use rayon::iter::ParallelIterator;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// One type the releases of its crate lay out at different sizes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ReleaseSize {
    pub(super) package: String,
    /// Normalized the way a drop glue symbol's type is matched.
    pub(super) name: String,
    /// Ascending by release; no two sizes equal.
    pub(super) sizes: Vec<(semver::Version, u64)>,
}

/// One type name's declarations, per release: the sizes they give it
/// and the types that declare it.
type ByRelease<'v> = BTreeMap<&'v semver::Version, (BTreeSet<u64>, Vec<TypeId>)>;

/// The types whose releases this pass compares: every named struct,
/// enum and union that is not itself an environment. Their
/// declarations are gathered beside the emitted types' for the crate
/// labels, and [`release_sizes`] reads its candidates' back.
pub(super) fn candidates(reader: &DwReader<'_>) -> HashSet<TypeId> {
    reader
        .par_canonical_types()
        .filter(|&(_, raw)| is_candidate(reader, raw))
        .map(|(id, _)| id)
        .collect()
}

fn is_candidate(reader: &DwReader<'_>, raw: &RawType<StrId>) -> bool {
    matches!(
        raw,
        RawType::Struct(_) | RawType::Enum(_) | RawType::Union(_)
    ) && raw
        .name()
        .is_some_and(|n| !is_environment(reader.strings.get(n)))
}

/// Every plain type of a multi-release crate whose releases disagree on
/// its size, sorted by package and name, read off the declarations
/// gathered for the [`candidates`].
pub(super) fn release_sizes(reader: &DwReader<'_>, declared: &Declared) -> Vec<ReleaseSize> {
    let labels: BTreeMap<TypeId, &(String, Vec<semver::Version>)> = declared
        .labels
        .iter()
        .filter(|&(&id, _)| {
            reader
                .canonical_type(id)
                .is_some_and(|raw| is_candidate(reader, raw))
        })
        .map(|(&id, label)| (id, label))
        .collect();

    let mut releases: HashMap<&str, BTreeSet<&semver::Version>> = HashMap::new();
    for (package, versions) in labels.values() {
        releases.entry(package).or_default().extend(versions);
    }
    let mut grouped: BTreeMap<(&str, String), ByRelease<'_>> = BTreeMap::new();
    for (&id, (package, versions)) in &labels {
        // A type two releases declare alike tells neither apart.
        let [version] = versions.as_slice() else {
            continue;
        };
        if releases[package.as_str()].len() < 2 {
            continue;
        }
        let Some(size) = size_of(reader, id) else {
            continue;
        };
        let Some(name) = fq_name(reader, id) else {
            continue;
        };
        let name = crate::symbols::normalized_rust_type_name(&name).into_owned();
        let entry = grouped
            .entry((package, name))
            .or_default()
            .entry(version)
            .or_default();
        entry.0.insert(size);
        entry.1.push(id);
    }

    let mut plain = Plainness::default();
    let mut out = Vec::new();
    for ((package, name), by_release) in grouped {
        if by_release.len() < 2 || by_release.values().any(|(sizes, _)| sizes.len() != 1) {
            continue;
        }
        let sizes: Vec<(semver::Version, u64)> = by_release
            .iter()
            .map(|(version, (sizes, _))| ((*version).clone(), *sizes.first().unwrap()))
            .collect();
        let distinct: BTreeSet<u64> = sizes.iter().map(|&(_, size)| size).collect();
        if distinct.len() != sizes.len() {
            continue;
        }
        if !by_release
            .values()
            .flat_map(|(_, ids)| ids)
            .all(|&id| plain.is_plain(reader, id))
        {
            continue;
        }
        out.push(ReleaseSize {
            package: package.to_owned(),
            name,
            sizes,
        });
    }
    out
}

fn size_of(reader: &DwReader<'_>, id: TypeId) -> Option<u64> {
    match reader.canonical_type(id)? {
        RawType::Struct(st) => Some(st.size),
        RawType::Enum(en) => Some(en.size),
        RawType::Union(un) => Some(un.size),
        _ => None,
    }
}

/// Whether a type holds no closure or coroutine environment by value.
#[derive(Default)]
struct Plainness {
    memo: HashMap<TypeId, bool>,
}

impl Plainness {
    fn is_plain(&mut self, reader: &DwReader<'_>, id: TypeId) -> bool {
        let id = reader.canonicalize(id);
        if let Some(&known) = self.memo.get(&id) {
            return known;
        }
        // A type met again while its own check is under way holds
        // itself only through a pointer, which is plain; the check in
        // progress decides it.
        self.memo.insert(id, true);
        let verdict = self.decide(reader, id);
        self.memo.insert(id, verdict);
        verdict
    }

    fn decide(&mut self, reader: &DwReader<'_>, id: TypeId) -> bool {
        let Some(raw) = reader.canonical_type(id) else {
            // Nothing to say it is plain.
            return false;
        };
        if raw
            .name()
            .is_some_and(|n| is_environment(reader.strings.get(n)))
        {
            return false;
        }
        let inner: Vec<TypeId> = match raw {
            RawType::Base(_) | RawType::Pointer(_) => return true,
            RawType::Array(a) => vec![a.elem_type_id],
            RawType::Struct(st) => st.members.iter().map(|m| m.type_id).collect(),
            RawType::Union(un) => un.members.iter().map(|m| m.type_id).collect(),
            RawType::Enum(en) => match &en.shape {
                VariantShape::Zero | VariantShape::CStyle { .. } => return true,
                VariantShape::One(v) => vec![v.member.type_id],
                VariantShape::Many { variants, .. } => {
                    variants.iter().map(|(_, v)| v.member.type_id).collect()
                }
            },
        };
        inner.into_iter().all(|t| self.is_plain(reader, t))
    }
}

/// Whether a type name is a closure or coroutine environment's:
/// `{closure_env#0}`, `{async_fn_env#0}`, `{async_block_env#0}` and the
/// like.
fn is_environment(name: &str) -> bool {
    name.contains("_env#")
}

#[cfg(test)]
mod tests {
    use super::{Plainness, is_environment};
    use crate::raw_types::{
        RawArray, RawBase, RawEnum, RawMember, RawPointer, RawStruct, RawType, RawUnion,
        RawVariant, VariantShape,
    };
    use crate::{DwReader, Encoding, TypeId};

    use gimli::UnitSectionOffset;

    fn id(n: usize) -> TypeId {
        TypeId(UnitSectionOffset(n))
    }

    /// A reader holding the types `plain` is asked about: a word, an
    /// environment, and one type per edge the check follows — a struct
    /// member, a union member, an enum payload, an array element — each
    /// holding the environment by value, beside a struct that holds it
    /// only through a pointer and one that reaches itself that way.
    fn reader() -> DwReader<'static> {
        let mut r = DwReader::default();
        let name = |r: &mut DwReader<'static>, s: &'static str| Some(r.strings.intern(s));
        let member = |t: TypeId| RawMember {
            name: None,
            offset: 0,
            type_id: t,
            source_loc: None,
        };
        let strukt = |r: &mut DwReader<'static>, n: &'static str, members: Vec<TypeId>| {
            RawType::Struct(RawStruct {
                name: name(r, n),
                namespace: None,
                size: 8,
                members: members.into_iter().map(member).collect(),
                template_params: Box::new([]),
                source_loc: None,
            })
        };
        let word = RawType::Base(RawBase {
            name: name(&mut r, "u64"),
            namespace: None,
            encoding: Encoding::Unsigned,
            size: 8,
            alignment: None,
        });
        r.types.insert(id(1), word);
        let env = strukt(&mut r, "{closure_env#0}", vec![id(1)]);
        r.types.insert(id(2), env);
        let plain = strukt(&mut r, "Plain", vec![id(1)]);
        r.types.insert(id(3), plain);
        let holder = strukt(&mut r, "Holder", vec![id(1), id(2)]);
        r.types.insert(id(4), holder);
        let union = RawType::Union(RawUnion {
            name: name(&mut r, "Either"),
            namespace: None,
            size: 8,
            members: vec![member(id(1)), member(id(2))].into_boxed_slice(),
            template_params: Box::new([]),
            source_loc: None,
        });
        r.types.insert(id(5), union);
        let enumeration = RawType::Enum(RawEnum {
            name: name(&mut r, "Choice"),
            namespace: None,
            size: 8,
            alignment: None,
            shape: VariantShape::One(RawVariant {
                member: member(id(2)),
            }),
            template_params: Box::new([]),
            source_loc: None,
        });
        r.types.insert(id(6), enumeration);
        r.types.insert(
            id(7),
            RawType::Array(RawArray {
                elem_type_id: id(2),
                count: 2,
            }),
        );
        let to_env = RawType::Pointer(RawPointer {
            name: None,
            target_type_id: id(2),
        });
        r.types.insert(id(8), to_env);
        let by_pointer = strukt(&mut r, "ByPointer", vec![id(8)]);
        r.types.insert(id(9), by_pointer);
        let to_self = RawType::Pointer(RawPointer {
            name: None,
            target_type_id: id(10),
        });
        r.types.insert(id(11), to_self);
        let node = strukt(&mut r, "Node", vec![id(1), id(11)]);
        r.types.insert(id(10), node);
        r
    }

    #[test]
    fn test_a_type_is_plain_unless_it_holds_an_environment_by_value() {
        let r = reader();
        let mut plain = Plainness::default();
        for (n, expected, what) in [
            (1, true, "a word"),
            (3, true, "a struct of words"),
            (9, true, "an environment behind a pointer"),
            (10, true, "a struct reaching itself through a pointer"),
            (2, false, "the environment itself"),
            (4, false, "a struct member"),
            (5, false, "a union member"),
            (6, false, "an enum payload"),
            (7, false, "an array element"),
            (99, false, "a type the reader lacks"),
        ] {
            assert_eq!(plain.is_plain(&r, id(n)), expected, "{what}");
        }
    }

    /// The candidates are the named structs, unions and enums that are
    /// no environment: not a base type, an environment, a pointer or an
    /// array.
    #[test]
    fn test_the_candidates_are_named_aggregates_other_than_environments() {
        let r = reader();
        let mut found: Vec<TypeId> = super::candidates(&r).into_iter().collect();
        found.sort();
        let mut expected = vec![id(3), id(4), id(5), id(6), id(9), id(10)];
        expected.sort();
        assert_eq!(found, expected);
    }

    /// Each crate at two releases or more gives an entry for every plain
    /// type its releases size differently — a struct, an enum, a union,
    /// and across three releases as across two — and nothing for a type
    /// sized alike, a type both releases declare as one, a type holding
    /// an environment, or a crate at one release.
    #[test]
    fn test_release_sizes_are_the_plain_types_the_releases_size_apart() {
        use super::super::labels::Declared;
        use super::release_sizes;
        use std::collections::{BTreeMap, HashSet};

        let mut r = reader();
        let demo = r.strings.intern("demo");
        let tri = r.strings.intern("tri");
        let one = r.strings.intern("one");
        let (demo, tri, one) = (
            r.namespaces.insert(None, demo),
            r.namespaces.insert(None, tri),
            r.namespaces.insert(None, one),
        );
        let mut next = 100;
        let mut labels: BTreeMap<TypeId, (String, Vec<semver::Version>)> = BTreeMap::new();
        let mut declare =
            |r: &mut DwReader<'static>,
             ns,
             package: &str,
             name: &'static str,
             raw: fn(Option<crate::StrId>, crate::NsId, u64, TypeId) -> RawType<crate::StrId>,
             size: u64,
             members: TypeId,
             versions: &[&str]| {
                next += 1;
                let name = Some(r.strings.intern(name));
                r.types.insert(id(next), raw(name, ns, size, members));
                labels.insert(
                    id(next),
                    (
                        package.to_owned(),
                        versions
                            .iter()
                            .map(|v| semver::Version::parse(v).unwrap())
                            .collect(),
                    ),
                );
            };
        fn strukt(
            name: Option<crate::StrId>,
            ns: crate::NsId,
            size: u64,
            m: TypeId,
        ) -> RawType<crate::StrId> {
            RawType::Struct(RawStruct {
                name,
                namespace: Some(ns),
                size,
                members: Box::new([RawMember {
                    name: None,
                    offset: 0,
                    type_id: m,
                    source_loc: None,
                }]),
                template_params: Box::new([]),
                source_loc: None,
            })
        }
        fn union(
            name: Option<crate::StrId>,
            ns: crate::NsId,
            size: u64,
            m: TypeId,
        ) -> RawType<crate::StrId> {
            RawType::Union(RawUnion {
                name,
                namespace: Some(ns),
                size,
                members: Box::new([RawMember {
                    name: None,
                    offset: 0,
                    type_id: m,
                    source_loc: None,
                }]),
                template_params: Box::new([]),
                source_loc: None,
            })
        }
        fn enumeration(
            name: Option<crate::StrId>,
            ns: crate::NsId,
            size: u64,
            m: TypeId,
        ) -> RawType<crate::StrId> {
            RawType::Enum(RawEnum {
                name,
                namespace: Some(ns),
                size,
                alignment: None,
                shape: VariantShape::One(RawVariant {
                    member: RawMember {
                        name: None,
                        offset: 0,
                        type_id: m,
                        source_loc: None,
                    },
                }),
                template_params: Box::new([]),
                source_loc: None,
            })
        }
        let (word, env) = (id(1), id(2));
        for (v, s) in [("1.0.0", 8), ("2.0.0", 16)] {
            declare(&mut r, demo, "demo", "S", strukt, s, word, &[v]);
        }
        for (v, s) in [("1.0.0", 4), ("2.0.0", 8)] {
            declare(&mut r, demo, "demo", "E", enumeration, s, word, &[v]);
        }
        for (v, s) in [("1.0.0", 1), ("2.0.0", 2)] {
            declare(&mut r, demo, "demo", "U", union, s, word, &[v]);
        }
        for v in ["1.0.0", "2.0.0"] {
            declare(&mut r, demo, "demo", "Alike", strukt, 8, word, &[v]);
        }
        declare(
            &mut r,
            demo,
            "demo",
            "Both",
            strukt,
            8,
            word,
            &["1.0.0", "2.0.0"],
        );
        for (v, s) in [("1.0.0", 8), ("2.0.0", 16)] {
            declare(&mut r, demo, "demo", "Held", strukt, s, env, &[v]);
        }
        for (v, s) in [("1.0.0", 1), ("2.0.0", 2), ("3.0.0", 3)] {
            declare(&mut r, tri, "tri", "T", strukt, s, word, &[v]);
        }
        declare(&mut r, one, "one", "O", strukt, 8, word, &["1.0.0"]);

        let declared = Declared {
            labels,
            declined: HashSet::new(),
        };
        // Package, type name, and each release with its size.
        type Entry = (String, String, Vec<(String, u64)>);
        let found: Vec<Entry> = release_sizes(&r, &declared)
            .into_iter()
            .map(|e| {
                (
                    e.package,
                    e.name,
                    e.sizes
                        .into_iter()
                        .map(|(v, s)| (v.to_string(), s))
                        .collect(),
                )
            })
            .collect();
        let entry = |p: &str, n: &str, sizes: &[(&str, u64)]| {
            (
                p.to_owned(),
                n.to_owned(),
                sizes.iter().map(|&(v, s)| (v.to_owned(), s)).collect(),
            )
        };
        assert_eq!(
            found,
            vec![
                entry("demo", "demo::E", &[("1.0.0", 4), ("2.0.0", 8)]),
                entry("demo", "demo::S", &[("1.0.0", 8), ("2.0.0", 16)]),
                entry("demo", "demo::U", &[("1.0.0", 1), ("2.0.0", 2)]),
                entry("tri", "tri::T", &[("1.0.0", 1), ("2.0.0", 2), ("3.0.0", 3)]),
            ]
        );
    }

    #[test]
    fn test_environments_are_named_by_their_env_segment() {
        assert!(is_environment("{closure_env#0}<u8>"));
        assert!(is_environment("{async_fn_env#0}"));
        assert!(is_environment("{async_block_env#3}"));
        assert!(is_environment("{coroutine_env#1}"));
        assert!(!is_environment("TlsBackend"));
        assert!(!is_environment("Option<envy::Config>"));
    }
}

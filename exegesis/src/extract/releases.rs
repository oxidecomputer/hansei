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
    use super::is_environment;

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

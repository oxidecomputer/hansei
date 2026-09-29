// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Which release of a crate each of a target's crate hashes is.
//!
//! A target that links a crate at two releases, read with a bundle from
//! another build, carries crate hashes the bundle's symbols do not: a
//! symbol naming a type of that crate misses the exact table, and the
//! hash-free key answers with every release's type. The bundle's
//! `release_sizes` list the types those releases lay out at different
//! sizes. A vtable in the target records its concrete type's size
//! beside the drop glue whose symbol names the type under the target's
//! own hash, so a vtable of one of those types says which release that
//! hash is: the one release that gives the type that size.
//!
//! Evidence is taken, never weighed. A hash is paired when everything
//! the vtables say of it names one release, and not at all when any of
//! it contradicts the rest or names none. Two hashes claiming one
//! release pair neither. Where a crate's every hash but one is paired
//! and the target and the bundle know as many releases as it has
//! hashes, the last pairs with the last release.

use hansei_bundle::{Bundle, BundleTypeId, ReleaseSize, StrRef, StringTable, TypeDef};
use proc::{Mappings, Target};

use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The target's crate hashes paired with the bundle's releases.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pairing {
    /// `(crate, hash)` → release, the crate as symbols write it
    /// (`hickory_proto`), the hash as the demangler prints it.
    releases: BTreeMap<(String, String), String>,
}

impl Pairing {
    /// The release a crate hash was paired with.
    pub fn release(&self, krate: &str, hash: &str) -> Option<&str> {
        self.releases
            .get(&(krate.to_owned(), hash.to_owned()))
            .map(String::as_str)
    }

    /// A pairing from known `(crate, hash, release)` triples, for tests.
    #[cfg(test)]
    pub(crate) fn from_triples(triples: &[(&str, &str, &str)]) -> Self {
        Pairing {
            releases: triples
                .iter()
                .map(|&(k, h, r)| ((k.to_owned(), h.to_owned()), r.to_owned()))
                .collect(),
        }
    }
}

/// What one vtable said: the hash its drop glue named the type under,
/// the type's evidence entry, and the size the vtable records.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation<'a> {
    krate: String,
    hash: String,
    entry: &'a ReleaseSize,
    size: u64,
}

/// Pair the target's crate hashes, reading its symbols and its
/// file-backed data for vtables of the bundle's `release_sizes`.
pub fn pair<T: Target>(bundle: &Bundle, proc: &T, mappings: &Mappings) -> Pairing {
    let evidence = Evidence::new(&bundle.strings, &bundle.types.release_sizes);
    if evidence.by_name.is_empty() {
        return Pairing::default();
    }
    let Ok(symbols) = proc.symbols() else {
        return Pairing::default();
    };
    let (glue, hashes) = evidence.glue(symbols.iter().map(|s| (s.st_value, s.name.as_str())));
    let mut observations = Vec::new();
    if !glue.is_empty() {
        for region in mappings.as_slice() {
            if region.flags.is_exec() || region.path.is_none() {
                continue;
            }
            let Ok(bytes) = proc.read_bytes(region.vaddr, region.size) else {
                continue;
            };
            observations.extend(vtables(bytes, &glue));
        }
    }
    decide(&evidence, &observations, &hashes)
}

/// The bundle's release sizes, by the name a drop glue symbol's type is
/// matched on, and every release each crate is known at.
struct Evidence<'a> {
    strings: &'a StringTable,
    by_name: HashMap<&'a str, &'a ReleaseSize>,
    /// Crate as symbols write it → its releases.
    releases: BTreeMap<String, BTreeSet<&'a str>>,
}

impl<'a> Evidence<'a> {
    fn new(strings: &'a StringTable, entries: &'a [ReleaseSize]) -> Self {
        let text = |r: StrRef| strings.get(r).unwrap_or("");
        let mut by_name = HashMap::new();
        let mut releases: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for entry in entries {
            by_name.insert(text(entry.name), entry);
            releases
                .entry(crate_of(text(entry.package)))
                .or_default()
                .extend(entry.sizes.iter().map(|&(release, _)| text(release)));
        }
        Evidence {
            strings,
            by_name,
            releases,
        }
    }

    fn text(&self, r: StrRef) -> &'a str {
        self.strings.get(r).unwrap_or("")
    }

    /// From the target's symbols: each drop glue of an evidence type,
    /// by address, with the one hash its crate carries there; and every
    /// hash each evidence crate carries anywhere in the symbols.
    #[allow(clippy::type_complexity)]
    fn glue<'s>(
        &self,
        symbols: impl Iterator<Item = (u64, &'s str)>,
    ) -> (
        HashMap<u64, (String, String, &'a ReleaseSize)>,
        BTreeMap<String, BTreeSet<String>>,
    ) {
        // A v0 symbol writes a crate as `<len><name>` after its hash; a
        // symbol without that for any evidence crate is skipped before
        // it is demangled.
        let needles: Vec<(String, String)> = self
            .releases
            .keys()
            .map(|k| (k.clone(), format!("{}{k}", k.len())))
            .collect();
        let mut glue = HashMap::new();
        let mut hashes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (addr, mangled) in symbols {
            let mangled = hansei_bundle::strip_llvm_suffix(mangled);
            if !mangled.starts_with("_R") || !needles.iter().any(|(_, n)| mangled.contains(n)) {
                continue;
            }
            let Ok(demangled) = rustc_demangle::try_demangle(mangled) else {
                continue;
            };
            let full = format!("{demangled}");
            let tokens = crate_hashes(&full);
            for &(krate, hash) in &tokens {
                if self.releases.contains_key(krate) {
                    hashes
                        .entry(krate.to_owned())
                        .or_default()
                        .insert(hash.to_owned());
                }
            }
            let plain = format!("{demangled:#}");
            let Some(inner) = plain
                .strip_prefix("core::ptr::drop_glue::<")
                .and_then(|rest| rest.strip_suffix('>'))
            else {
                continue;
            };
            let name = hansei_bundle::symbols::normalized_rust_type_name(inner);
            let Some(&entry) = self.by_name.get(name.as_ref()) else {
                continue;
            };
            let krate = crate_of(self.text(entry.package));
            let own: BTreeSet<&str> = tokens
                .iter()
                .filter(|&&(k, _)| k == krate)
                .map(|&(_, h)| h)
                .collect();
            // Glue naming the crate under two hashes says nothing about
            // either.
            if let [hash] = own.into_iter().collect::<Vec<_>>().as_slice() {
                glue.insert(addr, (krate, (*hash).to_owned(), entry));
            }
        }
        (glue, hashes)
    }
}

/// Every vtable in `bytes` whose drop slot is one of `glue`'s: its
/// next two words are the size and the alignment, and an alignment that
/// is no power of two is no vtable.
fn vtables<'a>(
    bytes: &[u8],
    glue: &HashMap<u64, (String, String, &'a ReleaseSize)>,
) -> Vec<Observation<'a>> {
    let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let mut out = Vec::new();
    let mut at = 0;
    while at + 24 <= bytes.len() {
        if let Some((krate, hash, entry)) = glue.get(&word(at)) {
            let (size, align) = (word(at + 8), word(at + 16));
            if align.is_power_of_two() && align <= 4096 {
                out.push(Observation {
                    krate: krate.clone(),
                    hash: hash.clone(),
                    entry,
                    size,
                });
            }
        }
        at += 8;
    }
    out
}

/// Pair each hash the observations agree on, then the last of a crate
/// by elimination.
fn decide(
    evidence: &Evidence<'_>,
    observations: &[Observation<'_>],
    hashes: &BTreeMap<String, BTreeSet<String>>,
) -> Pairing {
    // Per (crate, hash): the releases named, and whether any vtable
    // named none.
    let mut said: BTreeMap<(String, String), (BTreeSet<&str>, bool)> = BTreeMap::new();
    for obs in observations {
        let named: Vec<&str> = obs
            .entry
            .sizes
            .iter()
            .filter(|&&(_, size)| size == obs.size)
            .map(|&(release, _)| evidence.text(release))
            .collect();
        let slot = said
            .entry((obs.krate.clone(), obs.hash.clone()))
            .or_default();
        match named.as_slice() {
            [release] => {
                slot.0.insert(release);
            }
            _ => slot.1 = true,
        }
    }

    let mut contradicted: BTreeSet<String> = BTreeSet::new();
    let mut paired: BTreeMap<(String, String), String> = BTreeMap::new();
    for ((krate, hash), (named, stray)) in said {
        if stray || named.len() != 1 {
            contradicted.insert(krate);
            continue;
        }
        paired.insert((krate, hash), named.into_iter().next().unwrap().to_owned());
    }

    // Two hashes claiming one release pair neither.
    let mut claims: BTreeMap<(String, String), usize> = BTreeMap::new();
    for ((krate, _), release) in &paired {
        *claims.entry((krate.clone(), release.clone())).or_default() += 1;
    }
    paired.retain(|(krate, _), release| {
        let doubled = claims[&(krate.clone(), release.clone())] > 1;
        if doubled {
            contradicted.insert(krate.clone());
        }
        !doubled
    });

    // The last hash of a crate, where nothing about the crate was
    // contradicted and the target has exactly as many hashes as the
    // bundle knows releases.
    for (krate, releases) in &evidence.releases {
        if contradicted.contains(krate) {
            continue;
        }
        let Some(target) = hashes.get(krate) else {
            continue;
        };
        if target.len() != releases.len() {
            continue;
        }
        let open: Vec<&String> = target
            .iter()
            .filter(|h| !paired.contains_key(&(krate.clone(), (*h).clone())))
            .collect();
        let claimed: BTreeSet<&str> = paired
            .iter()
            .filter(|((k, _), _)| k == krate)
            .map(|(_, r)| r.as_str())
            .collect();
        let unclaimed: Vec<&&str> = releases.iter().filter(|r| !claimed.contains(**r)).collect();
        if let ([hash], [release]) = (open.as_slice(), unclaimed.as_slice()) {
            paired.insert((krate.clone(), (*hash).clone()), (**release).to_owned());
        }
    }
    Pairing { releases: paired }
}

/// The crate a registry package is, as symbols write it.
fn crate_of(package: &str) -> String {
    package.replace('-', "_")
}

/// Every `crate[hash]` a demangled v0 symbol writes, in order, each
/// once.
pub(crate) fn crate_hashes(demangled: &str) -> Vec<(&str, &str)> {
    let bytes = demangled.as_bytes();
    let mut out: Vec<(&str, &str)> = Vec::new();
    let mut at = 0;
    while let Some(open) = demangled[at..].find('[').map(|i| at + i) {
        let Some(close) = demangled[open..].find(']').map(|i| open + i) else {
            break;
        };
        let hash = &demangled[open + 1..close];
        let start = demangled[..open]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        let krate = &demangled[start..open];
        if !krate.is_empty()
            && !hash.is_empty()
            && hash.bytes().all(|b| b.is_ascii_hexdigit())
            && !bytes[start].is_ascii_digit()
            && !out.contains(&(krate, hash))
        {
            out.push((krate, hash));
        }
        at = open + 1;
    }
    out
}

/// The most types [`releases_of`] visits before it calls a type tied
/// to nothing.
const MAX_TIE_WALK: usize = 20_000;

/// The releases of `package` a type is tied to: every release a label
/// of `package`'s names among the types it is built from — itself, its
/// members, its variants' payloads, its pointers' targets and its
/// generic arguments, not looking past a labeled type. A generic of
/// another crate instantiated over one release's types reaches that
/// release's alone; a type reaching two is tied to neither. Empty when
/// nothing ties it to any, or when the walk runs past its bound.
pub(crate) fn releases_of(bundle: &Bundle, ty: BundleTypeId, package: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![ty];
    while let Some(ty) = stack.pop() {
        if !seen.insert(ty) {
            continue;
        }
        if seen.len() > MAX_TIE_WALK {
            return BTreeSet::new();
        }
        if let Some(label) = bundle.types.crate_labels.get(&ty)
            && bundle.strings.get(label.package) == Some(package)
        {
            // A type every release declares alike ties to none of
            // them, and neither does what it is built from.
            if let [v] = label.versions.as_slice() {
                out.insert(bundle.strings.get(*v).unwrap_or("").to_owned());
            }
            continue;
        }
        if let Some(args) = bundle.types.generic_args.get(&ty) {
            stack.extend(args.iter().copied());
        }
        match bundle.types.types.get(ty.0 as usize) {
            Some(TypeDef::Struct { members, .. } | TypeDef::Union { members, .. }) => {
                stack.extend(members.iter().map(|m| m.ty));
            }
            Some(TypeDef::Enum { shape, .. }) => {
                stack.extend(shape.variants.iter().map(|v| v.payload.ty));
            }
            Some(TypeDef::Pointer { target, .. }) => stack.push(*target),
            Some(TypeDef::Array { elem, .. }) => stack.push(*elem),
            _ => {}
        }
    }
    out
}

/// Of `candidates`, the one whose releases match what the pairing says
/// of every evidence crate `symbol` names; `None` when the symbol names
/// no paired crate, a crate under a hash the pairing does not know, or
/// when not exactly one candidate matches. A candidate tied to no
/// release of a crate the symbol names cannot be told apart by it, so
/// it matches nothing.
pub(crate) fn select(
    bundle: &Bundle,
    pairing: &Pairing,
    symbol: &str,
    candidates: &[BundleTypeId],
) -> Option<BundleTypeId> {
    let mangled = hansei_bundle::strip_llvm_suffix(symbol);
    let demangled = format!("{}", rustc_demangle::try_demangle(mangled).ok()?);
    let known: BTreeMap<String, String> = bundle
        .types
        .release_sizes
        .iter()
        .filter_map(|e| bundle.strings.get(e.package))
        .map(|p| (crate_of(p), p.to_owned()))
        .collect();
    let mut wanted: Vec<(&str, &str)> = Vec::new();
    for (krate, hash) in crate_hashes(&demangled) {
        let Some(package) = known.get(krate) else {
            continue;
        };
        wanted.push((package, pairing.release(krate, hash)?));
    }
    if wanted.is_empty() {
        return None;
    }
    let matching: Vec<BundleTypeId> = candidates
        .iter()
        .copied()
        .filter(|&c| {
            wanted.iter().all(|&(package, release)| {
                let releases = releases_of(bundle, c, package);
                releases.len() == 1 && releases.contains(release)
            })
        })
        .collect();
    match matching.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Evidence, Observation, crate_hashes, decide, vtables};

    use hansei_bundle::{ReleaseSize, StringInterner, StringTable};

    use std::collections::{BTreeMap, BTreeSet, HashMap};

    #[test]
    fn test_crate_hashes_are_the_bracketed_roots() {
        let s = "<reqwest[1507216f5062e83]::connect::Connector as tower_service[9a]::Service<http[ff]::uri::Uri>>::call";
        assert_eq!(
            crate_hashes(s),
            vec![
                ("reqwest", "1507216f5062e83"),
                ("tower_service", "9a"),
                ("http", "ff"),
            ]
        );
        // An array type's length is no crate.
        assert_eq!(crate_hashes("[u8; 4]"), vec![]);
        assert_eq!(crate_hashes("x[12]"), vec![("x", "12")]);
    }

    /// Two reqwest types the releases size differently.
    fn table() -> (StringTable, Vec<ReleaseSize>) {
        let mut strings = StringInterner::new();
        let reqwest = strings.intern("reqwest");
        let backend = strings.intern("reqwest::tls::TlsBackend");
        let builder = strings.intern("reqwest::async_impl::client::ClientBuilder");
        let old = strings.intern("0.12.28");
        let new = strings.intern("0.13.2");
        let entries = vec![
            ReleaseSize {
                package: reqwest,
                name: builder,
                sizes: vec![(old, 576), (new, 1016)],
            },
            ReleaseSize {
                package: reqwest,
                name: backend,
                sizes: vec![(old, 0), (new, 344)],
            },
        ];
        (strings.finish(), entries)
    }

    fn obs<'a>(e: &'a Evidence<'_>, name: &str, hash: &str, size: u64) -> Observation<'a> {
        Observation {
            krate: "reqwest".to_owned(),
            hash: hash.to_owned(),
            entry: e.by_name[name],
            size,
        }
    }

    fn hashes(list: &[&str]) -> BTreeMap<String, BTreeSet<String>> {
        BTreeMap::from([(
            "reqwest".to_owned(),
            list.iter().map(|h| h.to_string()).collect(),
        )])
    }

    const BACKEND: &str = "reqwest::tls::TlsBackend";
    const BUILDER: &str = "reqwest::async_impl::client::ClientBuilder";

    /// One vtable pairs its hash; the other hash of the crate pairs by
    /// elimination.
    #[test]
    fn test_one_vtable_pairs_its_hash_and_the_last_by_elimination() {
        let (strings, entries) = table();
        let e = Evidence::new(&strings, &entries);
        let p = decide(&e, &[obs(&e, BACKEND, "aa", 344)], &hashes(&["aa", "bb"]));
        assert_eq!(p.release("reqwest", "aa"), Some("0.13.2"));
        assert_eq!(p.release("reqwest", "bb"), Some("0.12.28"));
    }

    /// No elimination where the target carries more hashes than the
    /// bundle knows releases.
    #[test]
    fn test_elimination_needs_as_many_hashes_as_releases() {
        let (strings, entries) = table();
        let e = Evidence::new(&strings, &entries);
        let p = decide(
            &e,
            &[obs(&e, BACKEND, "aa", 344)],
            &hashes(&["aa", "bb", "cc"]),
        );
        assert_eq!(p.release("reqwest", "aa"), Some("0.13.2"));
        assert_eq!(p.release("reqwest", "bb"), None);
    }

    /// A vtable whose size no release gives the type, or two vtables of
    /// one hash naming two releases, pair nothing of the crate.
    #[test]
    fn test_evidence_is_taken_never_weighed() {
        let (strings, entries) = table();
        let e = Evidence::new(&strings, &entries);
        let stray = decide(
            &e,
            &[obs(&e, BACKEND, "aa", 344), obs(&e, BUILDER, "aa", 7)],
            &hashes(&["aa", "bb"]),
        );
        assert_eq!(stray, Default::default());
        let split = decide(
            &e,
            &[obs(&e, BACKEND, "aa", 344), obs(&e, BUILDER, "aa", 576)],
            &hashes(&["aa", "bb"]),
        );
        assert_eq!(split, Default::default());
    }

    /// Drop glue of an evidence type names its hash; the vtable after
    /// it records the size; a word that only looks like the glue, with
    /// an alignment no power of two after it, is no vtable. Every hash
    /// a crate carries is counted, glue or not.
    #[test]
    fn test_the_scan_reads_glue_and_the_vtable_after_it() {
        let (strings, entries) = table();
        let e = Evidence::new(&strings, &entries);
        let glue_sym = mangle_glue("reqwest", "1a", "tls", "TlsBackend");
        let other_sym = mangle_glue("reqwest", "2b", "tls", "Other");
        let (glue, hashes) =
            e.glue([(0x1000, glue_sym.as_str()), (0x2000, other_sym.as_str())].into_iter());
        assert_eq!(glue.len(), 1, "only the evidence type's glue: {glue:?}");
        let (krate, hash, entry) = &glue[&0x1000];
        assert_eq!((krate.as_str(), hash.as_str()), ("reqwest", "1a"));
        assert_eq!(strings.get(entry.name), Some("reqwest::tls::TlsBackend"));
        assert_eq!(
            hashes["reqwest"],
            BTreeSet::from(["1a".to_owned(), "2b".to_owned()])
        );

        let words = |w: &[u64]| w.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
        let glue: HashMap<_, _> = glue.into_iter().collect();
        let found = vtables(&words(&[7, 0x1000, 344, 8, 0x1000, 344, 3]), &glue);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].hash.as_str(), found[0].size), ("1a", 344));
    }

    /// A v0 symbol for `core::ptr::drop_glue::<krate::module::Name>`
    /// with `krate` under disambiguator `hash` (hex).
    fn mangle_glue(krate: &str, hash: &str, module: &str, name: &str) -> String {
        let disambiguator = u64::from_str_radix(hash, 16).unwrap();
        // v0 writes a disambiguator `d` as `s_` for 1 and `s<n>_` for
        // `n + 2`, `n` in base 62: `base62(d - 1)` below writes `d - 2`.
        let base62 = |mut n: u64| {
            const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            if n == 0 {
                return String::new();
            }
            n -= 1;
            let mut out = Vec::new();
            loop {
                out.push(DIGITS[(n % 62) as usize]);
                n /= 62;
                if n == 0 {
                    break;
                }
            }
            out.reverse();
            String::from_utf8(out).unwrap()
        };
        let path = format!(
            "NtNtCs{}_{}{krate}{}{module}{}{name}",
            base62(disambiguator - 1),
            krate.len(),
            module.len(),
            name.len()
        );
        format!("_RINvNtCs1_4core3ptr9drop_glue{path}E")
    }

    /// Two hashes claiming one release pair neither.
    #[test]
    fn test_two_hashes_claiming_one_release_pair_neither() {
        let (strings, entries) = table();
        let e = Evidence::new(&strings, &entries);
        let p = decide(
            &e,
            &[obs(&e, BACKEND, "aa", 344), obs(&e, BUILDER, "bb", 1016)],
            &hashes(&["aa", "bb"]),
        );
        assert_eq!(p, Default::default());
    }
}

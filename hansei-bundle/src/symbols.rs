//! Symbol-name normalization experiments and diagnostics.
//!
//! This module deliberately keeps normalization separate from the bundle
//! join tables.  The first implementation uses `rustc-demangle`'s v0 parser
//! as a conservative prototype: alternate display omits crate-root
//! disambiguators while preserving the rest of the demangled structure.

use crate::strip_llvm_suffix;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::BuildHasher;

/// Raw v0 symbols grouped by a build-independent prototype key.
pub type NormalizedSymbols = BTreeMap<String, Vec<String>>;

/// Build a normalized multimap and collapse raw aliases that resolve to the
/// same semantic value.
pub fn normalized_value_index<V: Copy + Ord>(
    symbols: &BTreeMap<String, V>,
) -> BTreeMap<String, Vec<V>> {
    let mut index: BTreeMap<String, BTreeSet<V>> = BTreeMap::new();
    for (symbol, value) in symbols {
        if let Some(key) = normalized_v0_key(symbol) {
            index.entry(key).or_default().insert(*value);
        }
    }
    index
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect()
}

/// Produce a prototype normalized key for a v0-mangled Rust symbol.
///
/// LLVM's internalization suffix is excluded independently.  Non-v0 and
/// malformed names return `None` rather than silently becoming exact keys.
pub fn normalized_v0_key(symbol: &str) -> Option<String> {
    let symbol = strip_llvm_suffix(symbol);
    if !(symbol.starts_with("_R") || symbol.starts_with("__R") || symbol.starts_with('R')) {
        return None;
    }
    let demangled = rustc_demangle::try_demangle(symbol).ok()?;
    Some(format!("{demangled:#}"))
}

/// Build a deterministic multimap without duplicating aliases repeated in
/// `.symtab` and `.dynsym`.
pub fn normalized_symbol_index<'a>(
    symbols: impl IntoIterator<Item = &'a str>,
) -> NormalizedSymbols {
    let mut unique = BTreeSet::new();
    for symbol in symbols {
        unique.insert(strip_llvm_suffix(symbol));
    }

    let mut index = NormalizedSymbols::new();
    for symbol in unique {
        if let Some(key) = normalized_v0_key(symbol) {
            index.entry(key).or_default().push(symbol.to_owned());
        }
    }
    index
}

/// Recover the concrete `T` named by a demangled vtable function symbol.
///
/// Rust trait-object vtables identify their concrete type through either
/// `drop_glue::<T>`/`drop_in_place::<T>` or a method named
/// `<T as Trait>::method`. The returned slice borrows the demangled symbol.
pub fn concrete_type_from_vtable_symbol(symbol: &str) -> Option<&str> {
    for marker in ["core::ptr::drop_glue::<", "core::ptr::drop_in_place::<"] {
        if let Some(rest) = symbol
            .strip_prefix(marker)
            .and_then(|rest| rest.strip_suffix('>'))
        {
            return Some(rest);
        }
    }

    let rest = symbol.strip_prefix('<')?;
    let mut depth = 1usize;
    for (index, ch) in rest.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 1 && rest[index..].starts_with(" as ") {
            return Some(&rest[..index]);
        }
        if depth == 0 {
            break;
        }
    }
    None
}

/// The allocator argument one formatting path spells out and the other
/// elides, in its whitespace-free form.
const GLOBAL_ELISION: &str = ",alloc::alloc::Global>";

/// Compare Rust type spellings while ignoring formatting whitespace added
/// by different debug-info and demangling paths.
///
/// Compares the normalized forms without building them: two streams walked
/// in step stop at the first character that differs, which for two unrelated
/// names is the first or second one. Building the keys instead costs two
/// allocations and a full pass over both names however early they diverge,
/// and this is called once per candidate in a name lookup — for a bundle
/// with a hundred thousand types, once per candidate per lookup.
pub fn rust_type_names_equal(left: &str, right: &str) -> bool {
    normalized_chars(left).eq(normalized_chars(right))
}

/// Produce the comparison key used for Rust type names recovered through
/// different formatting paths.
///
/// Borrows when the name is already in normal form, which nearly every name
/// is; only one carrying whitespace or a spelled-out `Global` is rebuilt.
pub fn normalized_rust_type_name(name: &str) -> Cow<'_, str> {
    if name.chars().any(char::is_whitespace) || name.contains(GLOBAL_ELISION) {
        Cow::Owned(normalized_chars(name).collect())
    } else {
        Cow::Borrowed(name)
    }
}

/// A hash of `name`'s normalized form, equal for any two names
/// [`rust_type_names_equal`] accepts.
///
/// Lets a name lookup be a hash lookup: the index groups candidates by this,
/// and the comparison above still decides each one, so a collision costs a
/// comparison rather than a wrong answer.
pub fn rust_type_name_hash(name: &str) -> u64 {
    foldhash::fast::FixedState::default().hash_one(normalized_rust_type_name(name))
}

/// The characters of `name`'s normalized form: whitespace dropped, and each
/// `,alloc::alloc::Global>` closing a generic argument list collapsed to the
/// `>` alone.
fn normalized_chars(name: &str) -> Normalized<'_> {
    Normalized { name, pos: 0 }
}

struct Normalized<'a> {
    name: &'a str,
    /// Byte index of the next character to consider.
    pos: usize,
}

impl Iterator for Normalized<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        loop {
            let ch = self.name[self.pos..].chars().next()?;
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
                continue;
            }
            // Only an elision can start here, so the leading comma decides it
            // for every other character in one comparison.
            if ch == ','
                && let Some(end) = self.elision_end()
            {
                self.pos = end;
                return Some('>');
            }
            self.pos += ch.len_utf8();
            return Some(ch);
        }
    }
}

impl Normalized<'_> {
    /// The byte index just past a [`GLOBAL_ELISION`] written at `pos`, whose
    /// characters may be separated by whitespace like any others.
    fn elision_end(&self) -> Option<usize> {
        let mut rest = self.name[self.pos..].char_indices();
        let mut end = 0;
        for want in GLOBAL_ELISION.chars() {
            loop {
                let (offset, ch) = rest.next()?;
                if ch.is_whitespace() {
                    continue;
                }
                if ch != want {
                    return None;
                }
                end = offset + ch.len_utf8();
                break;
            }
        }
        Some(self.pos + end)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GLOBAL_ELISION, concrete_type_from_vtable_symbol, normalized_rust_type_name,
        normalized_symbol_index, normalized_v0_key, normalized_value_index, rust_type_names_equal,
    };
    use std::borrow::Cow;
    use std::collections::BTreeMap;

    const DEBUG: &str =
        "_RNvNCNvNtNtCs4y941wpZLOZ_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";
    const NODEBUG: &str =
        "_RNvNCNvNtNtCsbdypcaruIt3_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";

    #[test]
    fn crate_disambiguators_normalize_to_the_same_key() {
        assert_eq!(normalized_v0_key(DEBUG), normalized_v0_key(NODEBUG));
    }

    #[test]
    fn llvm_suffix_does_not_change_the_key() {
        assert_eq!(
            normalized_v0_key(DEBUG),
            normalized_v0_key(&format!("{DEBUG}.llvm.12345"))
        );
    }

    #[test]
    fn index_preserves_colliding_raw_names() {
        let index = normalized_symbol_index([DEBUG, NODEBUG, DEBUG]);
        let values = index.values().next().expect("missing normalized key");
        assert_eq!(values, &[DEBUG.to_owned(), NODEBUG.to_owned()]);
    }

    #[test]
    fn non_v0_symbols_are_rejected() {
        assert_eq!(normalized_v0_key("malloc"), None);
        assert_eq!(normalized_v0_key("_ZN3fooE"), None);
    }

    #[test]
    fn value_index_collapses_codegen_aliases() {
        let symbols = BTreeMap::from([(DEBUG.to_owned(), 7), (NODEBUG.to_owned(), 7)]);
        assert_eq!(
            normalized_value_index(&symbols).values().next(),
            Some(&vec![7])
        );
    }

    #[test]
    fn value_index_preserves_semantic_ambiguity() {
        let symbols = BTreeMap::from([(DEBUG.to_owned(), 7), (NODEBUG.to_owned(), 9)]);
        assert_eq!(
            normalized_value_index(&symbols).values().next(),
            Some(&vec![7, 9])
        );
    }

    #[test]
    fn vtable_symbols_recover_concrete_types() {
        assert_eq!(
            concrete_type_from_vtable_symbol("core::ptr::drop_glue::<app::Thing<u64>>"),
            Some("app::Thing<u64>")
        );
        assert_eq!(
            concrete_type_from_vtable_symbol(
                "<app::Thing<alloc::vec::Vec<u8>> as app::Trait>::method"
            ),
            Some("app::Thing<alloc::vec::Vec<u8>>")
        );
    }

    #[test]
    fn rust_type_name_comparison_ignores_demangler_spacing() {
        assert!(rust_type_names_equal(
            "slog::Drain<Ok=(), Err=core::convert::Infallible>",
            "slog::Drain<Ok = (), Err = core::convert::Infallible>"
        ));
        assert!(!rust_type_names_equal("app::Thing<u32>", "app::Thing<u64>"));
    }

    #[test]
    fn rust_type_name_comparison_ignores_default_global_allocators() {
        assert!(rust_type_names_equal(
            "alloc::sync::Arc<dyn app::Trait, alloc::alloc::Global>",
            "alloc::sync::Arc<dyn app::Trait>"
        ));
    }

    /// The normalized form these names once had, spelled the obvious way:
    /// compact the whole string, then rewrite it. The streaming form must
    /// agree with it character for character, including where the rewrite
    /// does *not* apply — `str::replace` scans once and never reconsiders
    /// what it has emitted, so a `>` it writes cannot close a match with the
    /// text before it.
    fn built_key(name: &str) -> String {
        let compact: String = name.chars().filter(|ch| !ch.is_whitespace()).collect();
        compact.replace(GLOBAL_ELISION, ">")
    }

    #[test]
    fn streamed_key_matches_the_built_one() {
        const NAMES: &[&str] = &[
            "",
            ",",
            ">",
            "u32",
            "app::Thing<u32>",
            "slog::Drain<Ok = (), Err = core::convert::Infallible>",
            "alloc::vec::Vec<u8, alloc::alloc::Global>",
            // The elision spelled with the spacing a demangler adds.
            "alloc::vec::Vec<u8 , alloc::alloc::Global >",
            // Two of them, one nested inside the other.
            "a::B<alloc::vec::Vec<u8, alloc::alloc::Global>, alloc::alloc::Global>",
            // A near miss: the allocator is an argument, but not the last.
            "a::B<u8, alloc::alloc::Global, u16>",
            // The one that separates a single pass from a repeated one: the
            // first candidate fails on the character after the allocator, and
            // the `>` written for the second must not then close the first.
            "a::B<u8,alloc::alloc::Global,alloc::alloc::Global>",
            // A prefix of the pattern, ending the string mid-match.
            "a::B<u8, alloc::alloc::Glob",
            ",alloc::alloc::Global>",
            // Whitespace that is not a space, and a multi-byte character
            // either side of a comma.
            "a::B<u8,\talloc::alloc::Global>",
            "a::B<\u{a0}u8, alloc::alloc::Global>",
            "a::Ünïcode<u8, alloc::alloc::Global>",
        ];
        for name in NAMES {
            assert_eq!(
                normalized_rust_type_name(name),
                built_key(name),
                "normalizing {name:?}"
            );
        }
    }

    #[test]
    fn names_already_in_normal_form_are_not_rebuilt() {
        assert!(matches!(
            normalized_rust_type_name("app::Thing<u32>"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            normalized_rust_type_name("app::Thing<u32, alloc::alloc::Global>"),
            Cow::Owned(_)
        ));
    }
}

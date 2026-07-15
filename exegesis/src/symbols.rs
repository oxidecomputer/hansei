//! Symbol-name normalization experiments and diagnostics.
//!
//! This module deliberately keeps normalization separate from the bundle
//! join tables.  The first implementation uses `rustc-demangle`'s v0 parser
//! as a conservative prototype: alternate display omits crate-root
//! disambiguators while preserving the rest of the demangled structure.

use crate::bundle::strip_llvm_suffix;

use std::collections::{BTreeMap, BTreeSet};

/// Raw v0 symbols grouped by a build-independent prototype key.
pub type NormalizedSymbols = BTreeMap<String, Vec<String>>;

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

#[cfg(test)]
mod tests {
    use super::{normalized_symbol_index, normalized_v0_key};

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
}

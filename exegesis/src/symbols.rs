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
        if let Some(rest) = symbol.strip_prefix(marker).and_then(|rest| rest.strip_suffix('>')) {
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

/// Compare Rust type spellings while ignoring formatting whitespace added
/// by different debug-info and demangling paths.
pub fn rust_type_names_equal(left: &str, right: &str) -> bool {
    left.chars()
        .filter(|ch| !ch.is_whitespace())
        .eq(right.chars().filter(|ch| !ch.is_whitespace()))
}

/// Produce the comparison key used for Rust type names recovered through
/// different formatting paths.
pub fn normalized_rust_type_name(name: &str) -> String {
    name.chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        concrete_type_from_vtable_symbol, normalized_symbol_index, normalized_v0_key,
        normalized_value_index, rust_type_names_equal,
    };
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
        let symbols = BTreeMap::from([
            (DEBUG.to_owned(), 7),
            (NODEBUG.to_owned(), 7),
        ]);
        assert_eq!(normalized_value_index(&symbols).values().next(), Some(&vec![7]));
    }

    #[test]
    fn value_index_preserves_semantic_ambiguity() {
        let symbols = BTreeMap::from([
            (DEBUG.to_owned(), 7),
            (NODEBUG.to_owned(), 9),
        ]);
        assert_eq!(normalized_value_index(&symbols).values().next(), Some(&vec![7, 9]));
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
}

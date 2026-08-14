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
        normalized_v0_key, normalized_value_index, rust_type_name_hash, rust_type_names_equal,
    };

    use proptest::prelude::*;

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

    /// The pieces a generated name is assembled from. Enough punctuation to
    /// build plausible generic spellings, the whitespace a demangler adds,
    /// a multi-byte character to keep the byte arithmetic honest, and both
    /// halves of the allocator elision separately — so that the near misses
    /// (an allocator argument that is not the last, a pattern cut short by
    /// the end of the name, two of them in a row) turn up as often as whole
    /// matches do.
    const PIECES: &[&str] = &[
        "a",
        "b",
        "::",
        "<",
        ">",
        ",",
        " ",
        "\t",
        "\u{a0}",
        "Ü",
        "alloc::alloc::Global",
        "alloc::alloc::Glob",
        GLOBAL_ELISION,
        // The elision with the spacing a demangler puts *inside* it, which
        // an assembly out of the pieces above would reach far too rarely to
        // cover the matcher's tolerance of it.
        ", alloc::alloc::Global >",
    ];

    /// A name built from [`PIECES`].
    fn name() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(PIECES), 0..14)
            .prop_map(|pieces| pieces.concat())
    }

    /// One token of a name that is to be spelled two ways.
    #[derive(Clone, Debug)]
    enum Token {
        Piece(&'static str),
        /// A generic argument list closed with the default allocator, which
        /// one demangling path spells out and the other elides.
        CloseAlloc,
    }

    /// The pieces a two-way spelling is built from: punctuation only, with
    /// the whitespace coming from [`GAPS`] and the allocator from a
    /// [`Token::CloseAlloc`]. Nothing else may spell the allocator out — a
    /// name that writes `,alloc::alloc::Global` on its own account would let
    /// the elision beside it bind to the wrong comma, and the two spellings
    /// would then be different names for good reason.
    const PLAIN_PIECES: &[&str] = &["a", "b", "::", "<", ">", ",", "Ü"];

    /// The whitespace runs woven between tokens; two demanglers differ in
    /// exactly this, and it is never to mean anything.
    const GAPS: &[&str] = &["", " ", "  ", "\t", "\u{a0}"];

    /// Write `tokens` out, taking each whitespace run from `gaps` and each
    /// allocator's spelling from `spelled`, both cycled so a generated choice
    /// list need not match the token count.
    fn spell(tokens: &[Token], gaps: &[&str], spelled: &[bool]) -> String {
        // The allocator argument alone, so the comma that introduces it and
        // the bracket that closes it can be written with a gap either side.
        let allocator = &GLOBAL_ELISION[1..GLOBAL_ELISION.len() - 1];
        let mut cycle = gaps.iter().cycle();
        let mut gap = move || {
            *cycle
                .next()
                .expect("a cycle over a non-empty list never ends")
        };
        let mut out = String::new();
        for (i, token) in tokens.iter().enumerate() {
            out.push_str(gap());
            match token {
                Token::Piece(piece) => out.push_str(piece),
                // Spelled out the way a demangler writes it, whitespace
                // included — which puts the whitespace *inside* the pattern,
                // where it has to be tolerated rather than merely skipped
                // before and after.
                Token::CloseAlloc if spelled[i % spelled.len()] => {
                    out.push(',');
                    out.push_str(gap());
                    out.push_str(allocator);
                    out.push_str(gap());
                    out.push('>');
                }
                Token::CloseAlloc => out.push('>'),
            }
        }
        out
    }

    /// One name spelled two ways: same tokens, but every whitespace run and
    /// every default allocator written the way either demangling path might
    /// write it. Whatever they look like, they are one name.
    fn respelled_pair() -> impl Strategy<Value = (String, String)> {
        let tokens = prop::collection::vec(
            prop_oneof![
                4 => prop::sample::select(PLAIN_PIECES).prop_map(Token::Piece),
                1 => Just(Token::CloseAlloc),
            ],
            0..14,
        );
        let gaps = || prop::collection::vec(prop::sample::select(GAPS), 1..6);
        let spelled = || prop::collection::vec(any::<bool>(), 1..6);
        (tokens, gaps(), spelled(), gaps(), spelled()).prop_map(
            |(tokens, left_gaps, left_spelled, right_gaps, right_spelled)| {
                (
                    spell(&tokens, &left_gaps, &left_spelled),
                    spell(&tokens, &right_gaps, &right_spelled),
                )
            },
        )
    }

    /// Two names to compare: usually unrelated ones, which part company at
    /// their first character, and sometimes one name spelled twice, which is
    /// what walks a comparison to the end.
    fn name_pair() -> impl Strategy<Value = (String, String)> {
        prop_oneof![(name(), name()), respelled_pair()]
    }

    proptest! {
        /// The streaming normalizer against the obvious one, over generated
        /// names rather than the chosen few above.
        #[test]
        fn test_any_name_normalizes_to_its_built_key(name in name()) {
            prop_assert_eq!(normalized_rust_type_name(&name), built_key(&name));
        }

        /// The pairwise comparator walks two normalizations in step and stops
        /// at the first difference, so it is a second implementation of the
        /// rule above and answers to the same oracle.
        #[test]
        fn test_name_comparison_agrees_with_the_built_keys((left, right) in name_pair()) {
            prop_assert_eq!(
                rust_type_names_equal(&left, &right),
                built_key(&left) == built_key(&right)
            );
        }

        /// The property the whole module exists for: a type named by two
        /// paths that disagree about spacing and about whether the default
        /// allocator is written down is *one* type to every caller — the
        /// comparison, the key, and the hash a name lookup indexes by.
        #[test]
        fn test_a_respelled_name_is_the_same_name((left, right) in respelled_pair()) {
            prop_assert!(
                rust_type_names_equal(&left, &right),
                "{left:?} and {right:?} compare unequal"
            );
            prop_assert_eq!(
                normalized_rust_type_name(&left),
                normalized_rust_type_name(&right)
            );
            prop_assert_eq!(rust_type_name_hash(&left), rust_type_name_hash(&right));
        }
    }
}

//! The one compiled form behind every string *search* the session
//! offers: a case-insensitive regex. A plain substring types as
//! itself; anything more is the `regex` crate's grammar, and
//! metacharacters in a type name are the caller's to escape.
//! Arguments that *name* one definition — the type given to `print`
//! or `type`, a type id, an lwp — stay exact and never come here.

use anyhow::{Context as _, Result};
use regex::Regex;

/// A compiled search pattern. `(?i)` is prepended, so matching is
/// case-insensitive everywhere a search is; a pattern that must
/// distinguish case can turn it back off with `(?-i)`.
#[derive(Debug)]
pub struct Pattern(Regex);

impl Pattern {
    /// Compile `pattern`. The error names the pattern and carries the
    /// regex crate's own complaint; the caller adds which flag or
    /// field the pattern came from.
    pub fn new(pattern: &str) -> Result<Self> {
        Regex::new(&format!("(?i){pattern}"))
            .map(Pattern)
            .with_context(|| format!("invalid pattern {pattern:?}"))
    }

    /// Whether the pattern matches anywhere in `text` — a search, not
    /// an anchored comparison; `^`/`$` anchor where one is wanted.
    pub fn is_match(&self, text: &str) -> bool {
        self.0.is_match(text)
    }
}

#[cfg(test)]
mod tests {
    use super::Pattern;

    /// A substring types as itself, whatever its case: the point of
    /// the shared helper is that every search matches the same way.
    #[test]
    fn test_a_substring_matches_case_insensitively() {
        let p = Pattern::new("vec<u8").expect("a plain substring compiles");
        assert!(p.is_match("alloc::vec::Vec<u8>"));
        assert!(p.is_match("ALLOC::VEC::VEC<U8>"));
        assert!(!p.is_match("alloc::vec::Vec<u16>"));
    }

    /// The full grammar is there for the asking: anchors narrow a
    /// search, and `(?-i)` turns the default sensitivity back off.
    #[test]
    fn test_the_regex_grammar_is_available() {
        let p = Pattern::new("^idle").expect("an anchor compiles");
        assert!(p.is_match("Idle (cancelled)"));
        assert!(!p.is_match("was idle"));
        let p = Pattern::new("(?-i)Idle").expect("an override compiles");
        assert!(!p.is_match("idle"));
    }

    /// Metacharacters in a type name are the user's to escape: the
    /// escaped spelling matches the literal text, and a broken pattern
    /// is a loud error naming itself rather than a silent non-match.
    #[test]
    fn test_metacharacters_are_the_users_to_escape() {
        let name = "a::B<(u8, u16)>";
        let p = Pattern::new(&regex::escape(name)).expect("the escaped spelling compiles");
        assert!(p.is_match("outer a::B<(u8, u16)> inner"));
        let err = Pattern::new("(unclosed").expect_err("an unclosed group is refused");
        assert!(err.to_string().contains("invalid pattern"), "{err:#}");
    }
}

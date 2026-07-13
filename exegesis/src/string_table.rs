use foldhash::HashMap;

use std::num::NonZero;

/// An index into a string table.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StrId(NonZero<u32>);

impl StrId {
    /// Create a new `StrId` from a `NonZero<u32>`.
    pub(crate) fn new(id: NonZero<u32>) -> Self {
        Self(id)
    }

    /// Returns the inner `NonZero<u32>` value.
    pub fn get(self) -> NonZero<u32> {
        self.0
    }

    /// Returns the zero-based index into the string table's backing vec.
    pub(crate) fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

/// A deduplicating string table that maps `&'dw str` to [`StrId`].
///
/// Strings are stored in insertion order and deduplicated via a hash map.
/// Panics if more than `u32::MAX` unique strings are interned.
#[derive(Debug, Default)]
pub struct StringTable<'dw> {
    entries: Vec<&'dw str>,
    index: HashMap<&'dw str, StrId>,
    dups: usize,
}

impl<'dw> StringTable<'dw> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a string, returning its [`StrId`]. If the string has already
    /// been interned, the existing id is returned.
    pub fn intern(&mut self, s: &'dw str) -> StrId {
        if self.index.contains_key(s) {
            self.dups += 1;
        }
        *self.index.entry(s).or_insert_with(|| {
            let idx = u32::try_from(self.entries.len() + 1)
                .expect("StringTable overflow: more than u32::MAX strings");
            let id = StrId::new(NonZero::new(idx).unwrap());
            self.entries.push(s);
            id
        })
    }

    /// Retrieve the string for a given [`StrId`].
    pub fn get(&self, id: StrId) -> &'dw str {
        self.entries[id.index()]
    }

    /// Look up a string without interning it. Returns `None` if the string
    /// has never been interned.
    pub fn find(&self, s: &str) -> Option<StrId> {
        self.index.get(s).copied()
    }

    /// The number of unique strings in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the table contains no strings.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dups_found(&self) -> usize {
        self.dups
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intern_and_retrieve() {
        let mut t = StringTable::new();
        let id = t.intern("hello");
        assert_eq!(t.get(id), "hello");
    }

    #[test]
    fn test_intern_multiple() {
        let mut t = StringTable::new();
        let a = t.intern("alpha");
        let b = t.intern("beta");
        let c = t.intern("gamma");

        assert_eq!(t.get(a), "alpha");
        assert_eq!(t.get(b), "beta");
        assert_eq!(t.get(c), "gamma");
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn test_deduplicates() {
        let mut t = StringTable::new();
        let id1 = t.intern("dup");
        let id2 = t.intern("dup");

        assert_eq!(id1, id2);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_distinct_strings_get_distinct_ids() {
        let mut t = StringTable::new();
        let a = t.intern("one");
        let b = t.intern("two");

        assert_ne!(a, b);
    }

    #[test]
    fn test_empty_string() {
        let mut t = StringTable::new();
        let id = t.intern("");
        assert_eq!(t.get(id), "");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_is_empty() {
        let mut t = StringTable::new();
        assert!(t.is_empty());
        t.intern("x");
        assert!(!t.is_empty());
    }
}

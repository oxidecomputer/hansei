use foldhash::HashMap;

use serde::{Deserialize, Serialize};

/// An index into a bundle's [`StringTable`].
///
/// Unlike [`crate::string_table::StrId`], which borrows from mapped DWARF
/// sections, this refers into the owned, serialized table inside a bundle.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct StrRef(pub u32);

impl StrRef {
    fn index(self) -> usize {
        self.0 as usize
    }
}

/// The owned, deduplicated string table serialized into a bundle.
///
/// All strings are concatenated into a single buffer; entry `i` ends at byte
/// offset `ends[i]` and starts where entry `i - 1` ended. This keeps the
/// serialized form (and the deserialized heap footprint) to two allocations
/// no matter how many strings a large binary's bundle contains.
///
/// The table is read-only; strings are added through [`StringInterner`].
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct StringTable {
    data: String,
    ends: Vec<u32>,
}

impl StringTable {
    /// Retrieve the string for `r`, or `None` if `r` is out of range or the
    /// table data is corrupt (offsets not on UTF-8 boundaries).
    pub fn get(&self, r: StrRef) -> Option<&str> {
        let end = *self.ends.get(r.index())? as usize;
        let start = match r.index() {
            0 => 0,
            i => self.ends[i - 1] as usize,
        };
        self.data.get(start..end)
    }

    /// The number of strings in the table.
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    /// Returns `true` if the table contains no strings.
    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    /// Iterate over all strings in interning order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        (0..self.ends.len()).map(|i| self.get(StrRef(i as u32)).unwrap())
    }

    /// Check structural invariants: offsets monotonically non-decreasing,
    /// in-bounds, and on UTF-8 boundaries.
    pub(crate) fn is_well_formed(&self) -> bool {
        let mut prev = 0u32;
        for &end in &self.ends {
            if end < prev || end as usize > self.data.len() {
                return false;
            }
            prev = end;
        }
        (0..self.ends.len()).all(|i| self.get(StrRef(i as u32)).is_some())
    }
}

/// Builds a [`StringTable`], deduplicating as strings are interned.
///
/// The dedup index is only needed while producing a bundle, so it lives here
/// rather than in the serialized table.
#[derive(Debug, Default)]
pub struct StringInterner {
    table: StringTable,
    index: HashMap<String, StrRef>,
}

impl StringInterner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a string, returning its [`StrRef`]. If the string has already
    /// been interned, the existing ref is returned.
    pub fn intern(&mut self, s: &str) -> StrRef {
        if let Some(&r) = self.index.get(s) {
            return r;
        }
        self.table.data.push_str(s);
        let r = StrRef(u32::try_from(self.table.ends.len()).expect("string table overflow"));
        let end = u32::try_from(self.table.data.len()).expect("string table data overflow");
        self.table.ends.push(end);
        self.index.insert(s.to_owned(), r);
        r
    }

    /// The string a [`StrRef`] this interner produced stands for. Needed to
    /// read a name back out of a display program while it is still being
    /// built — a member addressed by name is a `StrRef`, and matching it
    /// against DWARF means resolving it first.
    pub fn get(&self, r: StrRef) -> Option<&str> {
        self.table.get(r)
    }

    /// Consume the interner, returning the finished table.
    pub fn finish(self) -> StringTable {
        self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intern_and_get() {
        let mut i = StringInterner::new();
        let a = i.intern("hello");
        let t = i.finish();
        assert_eq!(t.get(a), Some("hello"));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_deduplicates() {
        let mut i = StringInterner::new();
        let a = i.intern("dup");
        let b = i.intern("dup");
        assert_eq!(a, b);
        assert_eq!(i.finish().len(), 1);
    }

    #[test]
    fn test_distinct_strings_distinct_refs() {
        let mut i = StringInterner::new();
        let a = i.intern("one");
        let b = i.intern("two");
        assert_ne!(a, b);
        let t = i.finish();
        assert_eq!(t.get(a), Some("one"));
        assert_eq!(t.get(b), Some("two"));
    }

    #[test]
    fn test_empty_string() {
        let mut i = StringInterner::new();
        let e = i.intern("");
        let a = i.intern("after");
        let t = i.finish();
        assert_eq!(t.get(e), Some(""));
        assert_eq!(t.get(a), Some("after"));
    }

    #[test]
    fn test_unicode() {
        let mut i = StringInterner::new();
        let a = i.intern("łódź::Δ<T>");
        let b = i.intern("plain");
        let t = i.finish();
        assert_eq!(t.get(a), Some("łódź::Δ<T>"));
        assert_eq!(t.get(b), Some("plain"));
        assert!(t.is_well_formed());
    }

    #[test]
    fn test_out_of_range_ref() {
        let t = StringInterner::new().finish();
        assert_eq!(t.get(StrRef(0)), None);
        assert!(t.is_empty());
    }

    #[test]
    fn test_iter_order() {
        let mut i = StringInterner::new();
        i.intern("a");
        i.intern("b");
        i.intern("a");
        i.intern("c");
        let t = i.finish();
        let all: Vec<_> = t.iter().collect();
        assert_eq!(all, ["a", "b", "c"]);
    }

    #[test]
    fn test_corrupt_table_rejected() {
        // Offsets that are out of bounds, decreasing, or off UTF-8
        // boundaries must be caught by is_well_formed, not panic.
        let t = StringTable {
            data: "abc".into(),
            ends: vec![5],
        };
        assert_eq!(t.get(StrRef(0)), None);
        assert!(!t.is_well_formed());

        let t = StringTable {
            data: "abc".into(),
            ends: vec![2, 1],
        };
        assert!(!t.is_well_formed());

        let t = StringTable {
            data: "λ".into(),
            ends: vec![1, 2],
        };
        assert_eq!(t.get(StrRef(0)), None);
        assert!(!t.is_well_formed());
    }
}

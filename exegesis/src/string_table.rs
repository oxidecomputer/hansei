// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use foldhash::HashMap;
use foldhash::fast::FixedState;

use std::collections::hash_map::Entry;
use std::hash::BuildHasher;
use std::num::NonZero;
use std::sync::Mutex;

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
}

/// Number of shards. Interning contends only when two threads hit the same
/// shard with a new string at the same time, so more shards means less
/// contention; the cost is one `Mutex` + `HashMap` header each.
const SHARD_BITS: u32 = 8;
const SHARDS: usize = 1 << SHARD_BITS;

/// Striped id encoding: the low [`SHARD_BITS`] bits name the shard, the rest
/// index that shard's `entries` vec. `+1` keeps the id non-zero. Because each
/// shard indexes its own vec, no global id space has to be pre-partitioned —
/// every shard's vec grows independently on demand.
#[inline]
fn encode(shard: usize, local: u32) -> StrId {
    let raw = (local << SHARD_BITS) | shard as u32;
    StrId::new(NonZero::new(raw + 1).expect("raw + 1 is never zero"))
}

#[inline]
fn decode(id: StrId) -> (usize, usize) {
    let raw = id.0.get() - 1;
    (
        (raw & (SHARDS as u32 - 1)) as usize,
        (raw >> SHARD_BITS) as usize,
    )
}

/// Which shard a string lives in. A fixed seed makes this the same mapping on
/// every thread and every run, so equal strings always target one shard.
#[inline]
fn shard_of(s: &str) -> usize {
    (FixedState::default().hash_one(s) as usize) & (SHARDS - 1)
}

#[derive(Debug, Default)]
struct Shard<'dw> {
    index: HashMap<&'dw str, StrId>,
    entries: Vec<&'dw str>,
    dups: usize,
}

/// Intern `s` (known to belong to shard `k`) into an exclusively-held shard.
#[inline]
fn shard_intern<'dw>(shard: &mut Shard<'dw>, k: usize, s: &'dw str) -> StrId {
    let Shard {
        index,
        entries,
        dups,
    } = shard;
    match index.entry(s) {
        Entry::Occupied(e) => {
            *dups += 1;
            *e.get()
        }
        Entry::Vacant(e) => {
            let id = encode(k, entries.len() as u32);
            entries.push(s);
            e.insert(id);
            id
        }
    }
}

/// A deduplicating string interner that maps `&'dw str` to [`StrId`], sharded
/// so that many threads can intern concurrently.
///
/// [`intern`](Self::intern) takes `&self` — each shard is behind its own lock
/// — so the CGU-parsing workers in [`crate::reader::DwReader::read_types`] can
/// intern in parallel instead of funnelling every string through the serial
/// collector. Shard selection is by content hash, so equal strings dedup to a
/// single id no matter which thread interns first.
///
/// Interning is write-only; once every CGU is parsed, [`freeze`](Self::freeze)
/// drops the locks and yields a [`FrozenStrings`] for the single-threaded read
/// phase. The interner is invariant over `'dw` (the `Mutex` hands out `&mut`),
/// so it is kept local to `read_types`; the reader stores the covariant frozen
/// form instead.
///
/// Id *values* depend on inter-thread insertion order and are therefore not
/// stable across runs. Nothing downstream relies on them: the bundle re-interns
/// display strings through its own [`crate::bundle::StringInterner`], and
/// finalization groups types by id *equality*, not order.
#[derive(Debug)]
pub struct ShardedInterner<'dw> {
    shards: Box<[Mutex<Shard<'dw>>]>,
}

impl<'dw> ShardedInterner<'dw> {
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::default())).collect(),
        }
    }

    /// Intern a string, returning its [`StrId`]. If the string has already
    /// been interned (in any thread), the existing id is returned.
    pub fn intern(&self, s: &'dw str) -> StrId {
        let k = shard_of(s);
        shard_intern(&mut self.shards[k].lock().unwrap(), k, s)
    }

    /// Consume the interner, dropping the per-shard locks to produce the
    /// read-optimized [`FrozenStrings`]. Call once, after all interning is
    /// done.
    pub fn freeze(self) -> FrozenStrings<'dw> {
        FrozenStrings {
            shards: self
                .shards
                .into_vec()
                .into_iter()
                .map(|m| m.into_inner().unwrap())
                .collect(),
        }
    }
}

impl Default for ShardedInterner<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of interning: the same striped shards as [`ShardedInterner`]
/// but without the locks, so it is covariant over `'dw` and cheap to read.
/// This is what a [`crate::reader::DwReader`] holds.
///
/// It still supports [`intern`](Self::intern) via `&mut self` (no locking, one
/// owner) so a reader can be built up directly — the parallel path freezes a
/// [`ShardedInterner`] into this, while tests construct one and intern into it.
#[derive(Debug)]
pub struct FrozenStrings<'dw> {
    shards: Box<[Shard<'dw>]>,
}

impl Default for FrozenStrings<'_> {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Shard::default()).collect(),
        }
    }
}

impl<'dw> FrozenStrings<'dw> {
    /// Intern a string into an exclusively-owned table. Ids match those the
    /// concurrent [`ShardedInterner`] would assign for the same shard layout.
    pub fn intern(&mut self, s: &'dw str) -> StrId {
        let k = shard_of(s);
        shard_intern(&mut self.shards[k], k, s)
    }

    /// Retrieve the string for a given [`StrId`].
    pub fn get(&self, id: StrId) -> &'dw str {
        let (k, j) = decode(id);
        self.shards[k].entries[j]
    }

    /// Look up a string without interning it. Returns `None` if the string
    /// has never been interned.
    pub fn find(&self, s: &str) -> Option<StrId> {
        self.shards[shard_of(s)].index.get(s).copied()
    }

    /// The number of unique strings in the table.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.entries.len()).sum()
    }

    /// Returns `true` if the table contains no strings.
    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.entries.is_empty())
    }

    pub fn dups_found(&self) -> usize {
        self.shards.iter().map(|s| s.dups).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ids_are_distinct_and_duplicates_are_counted() {
        let mut strings = FrozenStrings::default();
        let a = strings.intern("a");
        let again = strings.intern("a");
        let b = strings.intern("b");
        assert_eq!(a, again);
        assert_ne!(a.get(), b.get());
        strings.intern("a");
        assert_eq!(strings.dups_found(), 2);
    }

    #[test]
    fn test_intern_and_retrieve() {
        let t = ShardedInterner::new();
        let id = t.intern("hello");
        assert_eq!(t.freeze().get(id), "hello");
    }

    #[test]
    fn test_intern_multiple() {
        let t = ShardedInterner::new();
        let a = t.intern("alpha");
        let b = t.intern("beta");
        let c = t.intern("gamma");

        let t = t.freeze();
        assert_eq!(t.get(a), "alpha");
        assert_eq!(t.get(b), "beta");
        assert_eq!(t.get(c), "gamma");
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn test_deduplicates() {
        let t = ShardedInterner::new();
        let id1 = t.intern("dup");
        let id2 = t.intern("dup");

        assert_eq!(id1, id2);
        let t = t.freeze();
        assert_eq!(t.len(), 1);
        assert_eq!(t.dups_found(), 1);
    }

    #[test]
    fn test_distinct_strings_get_distinct_ids() {
        let t = ShardedInterner::new();
        let a = t.intern("one");
        let b = t.intern("two");

        assert_ne!(a, b);
    }

    #[test]
    fn test_empty_string() {
        let t = ShardedInterner::new();
        let id = t.intern("");
        let t = t.freeze();
        assert_eq!(t.get(id), "");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_is_empty() {
        assert!(ShardedInterner::new().freeze().is_empty());
        let t = ShardedInterner::new();
        t.intern("x");
        assert!(!t.freeze().is_empty());
    }

    #[test]
    fn test_find() {
        let t = ShardedInterner::new();
        let id = t.intern("needle");
        t.intern("haystack");
        let t = t.freeze();
        assert_eq!(t.find("needle"), Some(id));
        assert_eq!(t.find("missing"), None);
    }

    /// Every distinct string round-trips through its striped id, and repeats
    /// collapse to the same id — the property finalization relies on.
    #[test]
    fn test_many_strings_roundtrip_and_dedup() {
        let owned: Vec<String> = (0..10_000).map(|i| format!("sym::item#{i}")).collect();
        let t = ShardedInterner::new();
        let ids: Vec<StrId> = owned.iter().map(|s| t.intern(s.as_str())).collect();
        // Repeats collapse to the same id even before freezing.
        for (s, &id) in owned.iter().zip(&ids) {
            assert_eq!(t.intern(s.as_str()), id);
        }
        let t = t.freeze();
        for (s, &id) in owned.iter().zip(&ids) {
            assert_eq!(t.get(id), s.as_str());
        }
        assert_eq!(t.len(), owned.len());
    }

    /// Interning the same strings concurrently yields one id per string.
    #[test]
    fn test_concurrent_interning_dedups() {
        let owned: Vec<String> = (0..2_000)
            .map(|i| format!("core::ty<{}>", i % 500))
            .collect();
        let t = ShardedInterner::new();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for s in &owned {
                        t.intern(s.as_str());
                    }
                });
            }
        });
        // 500 distinct strings regardless of the 8-way race.
        let t = t.freeze();
        assert_eq!(t.len(), 500);
        // And each still resolves to itself.
        for s in owned.iter().take(500) {
            let id = t.find(s.as_str()).expect("interned");
            assert_eq!(t.get(id), s.as_str());
        }
    }
}

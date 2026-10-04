// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A captured target with faults baked into memory of its own.
//!
//! A denied range is cut out of the segments, so every read touching
//! it fails, a blanked range is kept and zeroed, and a patched word is
//! written over, so every read of it sees the lie. The faults live in
//! the bytes rather than in a `read_bytes` that doctors what it
//! serves, because the renderer reads by borrowing: a lent slice
//! carries a corruption only if the storage behind it does.

use proc::{LwpInfo, Mappings, Regs, SymbolBuf, Target};

use std::ops::Range;

/// A target whose memory has been damaged on purpose. Everything but
/// the bytes — symbols, mappings, LWPs — is the healthy capture's.
pub struct Corrupt<'a, T> {
    inner: &'a T,
    /// The target's readable runs, copied so they can be damaged, each
    /// as `(address, bytes)` and in ascending address order.
    memory: Vec<(u64, Vec<u8>)>,
}

/// The granule a target's readability is probed in where it has no
/// captured runs to list.
const PAGE: u64 = 0x1000;

impl<'a, T: Target> Corrupt<'a, T> {
    /// Copy every byte `inner` can read: a snapshot's captured runs,
    /// or, for a core, every readable stretch of every mapping.
    pub fn new(inner: &'a T) -> Self {
        let memory = runs(inner)
            .into_iter()
            .flat_map(|run| copy_run(inner, run))
            .collect();
        Corrupt { inner, memory }
    }

    /// Reads overlapping `range` fail, as if the pages were not dumped.
    pub fn deny(self, range: Range<u64>) -> Self {
        let memory = self
            .memory
            .into_iter()
            .flat_map(|(addr, bytes)| {
                let len = bytes.len() as u64;
                // What the hole leaves of this run: the part before it
                // and the part after it, either of which may be empty.
                let head = range.start.saturating_sub(addr).min(len) as usize;
                let tail = range.end.saturating_sub(addr).min(len) as usize;
                [
                    (addr, bytes[..head].to_vec()),
                    (addr + tail as u64, bytes[tail..].to_vec()),
                ]
            })
            // A hole at a run's edge leaves an empty piece there,
            // which no read could land in; keep only the bytes.
            .filter(|(_, bytes)| !bytes.is_empty())
            .collect();
        Corrupt { memory, ..self }
    }

    /// The target range will be zeroed, as if the dump had recorded the
    /// mapping at full length and written nothing into it, mimicking a
    /// truncated core.
    pub fn blank(mut self, range: Range<u64>) -> Self {
        let mut blanked = 0;
        for (base, bytes) in &mut self.memory {
            let len = bytes.len() as u64;
            let from = range.start.saturating_sub(*base).min(len) as usize;
            let to = range.end.saturating_sub(*base).min(len) as usize;
            if let Some(slot) = bytes.get_mut(from..to) {
                slot.fill(0);
                blanked += slot.len();
            }
        }
        assert!(blanked > 0, "no recorded segment holds {range:#x?}");
        self
    }

    /// The word at `addr` reads back as `value`.
    pub fn patch(mut self, addr: u64, value: u64) -> Self {
        let patched = self.try_patch(addr, value);
        assert!(patched, "no recorded segment holds {addr:#x}");
        self
    }

    /// [`patch`](Self::patch) for a fault campaign that aims blindly:
    /// whether any captured run held the word, rather than a panic
    /// when none did.
    pub fn try_patch(&mut self, addr: u64, value: u64) -> bool {
        self.write(addr, &value.to_le_bytes())
    }

    /// The byte at `addr` reads back as `value`.
    pub fn patch_byte(mut self, addr: u64, value: u8) -> Self {
        let patched = self.write(addr, &[value]);
        assert!(patched, "no recorded segment holds {addr:#x}");
        self
    }

    /// Every recorded aligned word equal to `value` reads back as
    /// `lie` — how a pointer *to* a structure is corrupted when only
    /// the target's own memory says where that pointer lives (a shard
    /// head, an intrusive link).
    pub fn patch_words_equal(mut self, value: u64, lie: u64) -> Self {
        let mut patched = 0;
        for (addr, bytes) in &mut self.memory {
            let skew = (addr.next_multiple_of(8) - *addr) as usize;
            let Some(aligned) = bytes.get_mut(skew..) else {
                continue;
            };
            for word in aligned.as_chunks_mut::<8>().0 {
                if u64::from_le_bytes(*word) == value {
                    *word = lie.to_le_bytes();
                    patched += 1;
                }
            }
        }
        assert!(patched > 0, "no recorded word holds {value:#x}");
        self
    }

    /// Write `value` over the bytes at `addr`, reporting whether any
    /// captured run holds all of them.
    fn write(&mut self, addr: u64, value: &[u8]) -> bool {
        for (base, bytes) in &mut self.memory {
            let Some(start) = addr.checked_sub(*base).map(|o| o as usize) else {
                continue;
            };
            if let Some(slot) = bytes
                .get_mut(start..)
                .and_then(|b| b.get_mut(..value.len()))
            {
                slot.copy_from_slice(value);
                return true;
            }
        }
        false
    }

    /// The captured run holding `addr`, if the faults left one.
    fn segment(&self, addr: u64) -> Option<(u64, &[u8])> {
        self.memory
            .iter()
            .map(|(base, bytes)| (*base, &bytes[..]))
            .find(|(base, bytes)| addr >= *base && addr - base < bytes.len() as u64)
    }
}

/// The memory `target` can serve, in address order: a snapshot's
/// captured runs, or, for a core, every readable stretch of every
/// mapping.
pub fn runs<T: Target>(target: &T) -> Vec<Range<u64>> {
    target
        .captured_runs()
        .unwrap_or_else(|| readable_runs(target))
}

/// Every stretch of `target`'s mappings it says it can read, probed a
/// page at a time across what it cannot.
fn readable_runs<T: Target>(target: &T) -> Vec<Range<u64>> {
    let mappings = target.mappings().expect("the target lists its mappings");
    let mut runs: Vec<Range<u64>> = Vec::new();
    for mapping in mappings.iter() {
        let range = mapping.range();
        let mut at = range.start;
        while at < range.end {
            match target.readable_len(at, range.end - at) {
                0 => at = (at + PAGE) & !(PAGE - 1),
                len => {
                    match runs.last_mut() {
                        Some(last) if last.end == at => last.end = at + len,
                        _ => runs.push(at..at + len),
                    }
                    at += len;
                }
            }
        }
    }
    runs
}

/// The bytes of `run`, as one piece where the target lends it whole,
/// and otherwise a page at a time, each page it cannot read left out.
fn copy_run<T: Target>(target: &T, run: Range<u64>) -> Vec<(u64, Vec<u8>)> {
    if let Ok(bytes) = target.read_bytes(run.start, run.end - run.start) {
        return vec![(run.start, bytes.to_vec())];
    }
    let mut pieces: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut at = run.start;
    while at < run.end {
        let end = ((at + PAGE) & !(PAGE - 1)).min(run.end);
        if let Ok(bytes) = target.read_bytes(at, end - at) {
            match pieces.last_mut() {
                Some((base, held)) if *base + held.len() as u64 == at => {
                    held.extend_from_slice(bytes)
                }
                _ => pieces.push((at, bytes.to_vec())),
            }
        }
        at = end;
    }
    pieces
}

impl<T: Target> Target for Corrupt<'_, T> {
    fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
        let lent = || {
            let end = addr.checked_add(len)?;
            let (base, bytes) = self.segment(addr)?;
            (end - base <= bytes.len() as u64)
                .then(|| &bytes[(addr - base) as usize..(end - base) as usize])
        };
        lent().ok_or_else(|| proc::Error::unmapped(addr, len))
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        match self.segment(addr) {
            Some((base, bytes)) => (base + bytes.len() as u64 - addr).min(max),
            None => 0,
        }
    }

    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        self.inner.lookup_symbol_by_addr(addr)
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        self.inner.lookup_symbol_by_name(name)
    }

    fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
        self.inner.symbols()
    }

    fn object_symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
        self.inner.object_symbols()
    }

    fn mappings(&self) -> proc::Result<Mappings> {
        self.inner.mappings()
    }

    fn lwps(&self) -> proc::Result<Vec<LwpInfo>> {
        self.inner.lwps()
    }

    fn agent_lwp(&self) -> Option<u32> {
        self.inner.agent_lwp()
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> proc::Result<Option<u64>> {
        self.inner.tls_var_addr(regs, sym)
    }

    fn fatal_signal(&self) -> Option<proc::FatalSignal> {
        self.inner.fatal_signal()
    }

    fn lwp_name(&self, tid: u32) -> Option<String> {
        self.inner.lwp_name(tid)
    }

    fn process_facts(&self) -> Option<proc::ProcessFacts> {
        self.inner.process_facts()
    }

    fn exec_path(&self) -> Option<std::path::PathBuf> {
        self.inner.exec_path()
    }

    fn build_ids(&self) -> Option<proc::BuildIds> {
        self.inner.build_ids()
    }

    fn backing_file_problem(&self, path: &str) -> Option<String> {
        self.inner.backing_file_problem(path)
    }

    fn exec_bias(&self) -> Option<u64> {
        self.inner.exec_bias()
    }

    fn recorded_heap_evidence(&self) -> Option<proc::snapshot::RecordedHeapEvidence> {
        // The policy is the capture's, not the damage's: a snapshot
        // whose allocator metadata this double denies still claims the
        // index, which is exactly the mismatch a replay has to refuse.
        self.inner.recorded_heap_evidence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;

    /// A readable run of at least 64 bytes, as `(base, length)`.
    fn a_run(target: &impl Target) -> (u64, u64) {
        Corrupt::new(target)
            .memory
            .iter()
            .map(|(base, bytes)| (*base, bytes.len() as u64))
            .find(|&(_, len)| len >= 64)
            .expect("a run of some size")
    }

    /// A denied range is a hole with exact edges: the byte before it
    /// and the byte at its end still read, every byte inside it and
    /// every read straddling it fails, and the readable length ahead
    /// of an address is cut at the hole and at the run's end.
    #[test]
    fn test_a_denied_range_has_exact_edges() {
        let (_, core) = testkit::load_any("sleep-join");
        let (base, len) = a_run(&core);
        let hole = base + 16..base + 32;
        let corrupt = Corrupt::new(&core).deny(hole.clone());

        assert!(corrupt.read_bytes(base, 16).is_ok());
        assert!(corrupt.read_bytes(base + 15, 1).is_ok());
        assert!(corrupt.read_bytes(base + 15, 2).is_err());
        assert!(corrupt.read_bytes(base + 16, 1).is_err());
        assert!(corrupt.read_bytes(base + 31, 1).is_err());
        assert!(corrupt.read_bytes(base + 31, 2).is_err());
        assert!(corrupt.read_bytes(base + 32, 1).is_ok());
        assert!(corrupt.read_bytes(base + 32, len - 32).is_ok());
        assert!(corrupt.read_bytes(base + 32, len - 31).is_err());
        assert_eq!(
            corrupt.read_bytes(base + 32, 8).unwrap(),
            core.read_bytes(base + 32, 8).unwrap()
        );

        assert_eq!(corrupt.readable_len(base, 100), 16);
        assert_eq!(corrupt.readable_len(base + 8, 4), 4);
        assert_eq!(corrupt.readable_len(base + 16, 4), 0);
        assert_eq!(corrupt.readable_len(base + 32, 1 << 40), len - 32);
        assert_eq!(corrupt.readable_len(base + len - 4, 100), 4);
        assert_eq!(corrupt.readable_len(base + len, 100), 0);
    }

    /// A patch changes exactly the word or byte it names, and the rest
    /// of the run reads as captured.
    #[test]
    fn test_a_patch_changes_only_its_bytes() {
        let (_, core) = testkit::load_any("sleep-join");
        let (base, _) = a_run(&core);
        let corrupt = Corrupt::new(&core)
            .patch(base + 8, 0x1122_3344_5566_7788)
            .patch_byte(base + 20, 0xab);
        let before = core.read_bytes(base, 32).unwrap();
        let after = corrupt.read_bytes(base, 32).unwrap();
        assert_eq!(&after[..8], &before[..8]);
        assert_eq!(&after[8..16], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&after[16..20], &before[16..20]);
        assert_eq!(after[20], 0xab);
        assert_eq!(&after[21..], &before[21..]);
        let mut blind = Corrupt::new(&core);
        assert!(!blind.try_patch(0xdead_beef_0000, 1));
        assert!(blind.try_patch(base, 1));
    }

    /// Everything that is not memory is the healthy capture's.
    #[test]
    fn test_symbols_and_mappings_are_the_captures() {
        let (_, core) = testkit::load_any("sleep-join");
        let corrupt = Corrupt::new(&core).deny(0..0x1000);
        let name = testkit::expect::SYMBOL;
        let inner = core
            .lookup_symbol_by_name(name)
            .expect("the fixture exports it");
        let ours = corrupt.lookup_symbol_by_name(name).expect("delegated");
        assert_eq!(ours.st_value, inner.st_value);
        assert_eq!(
            corrupt
                .lookup_symbol_by_addr(inner.st_value)
                .map(|s| s.st_value),
            core.lookup_symbol_by_addr(inner.st_value)
                .map(|s| s.st_value)
        );
        assert!(!corrupt.symbols().unwrap().is_empty());
        assert_eq!(
            corrupt.symbols().unwrap().len(),
            core.symbols().unwrap().len()
        );
        assert_eq!(
            corrupt.object_symbols().unwrap().len(),
            core.object_symbols().unwrap().len()
        );
        assert_eq!(corrupt.lwps().unwrap().len(), core.lwps().unwrap().len());
        assert_eq!(
            corrupt.mappings().unwrap().contains_addr(inner.st_value),
            core.mappings().unwrap().contains_addr(inner.st_value)
        );
    }
}

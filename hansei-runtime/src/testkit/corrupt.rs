// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A captured snapshot with faults baked into memory of its own.
//!
//! A denied range is cut out of the segments, so every read touching
//! it fails, a blanked range is kept and zeroed, and a patched word is
//! written over, so every read of it sees the lie. The faults live in
//! the bytes rather than in a `read_bytes` that doctors what it
//! serves, because the renderer reads by borrowing: a lent slice
//! carries a corruption only if the storage behind it does.

use proc::snapshot::Snapshot;
use proc::{LwpInfo, Mappings, Regs, SymbolBuf, Target};

use std::ops::Range;

/// A snapshot whose memory has been damaged on purpose. Everything
/// but the bytes — symbols, mappings, LWPs — is the healthy capture's.
pub struct Corrupt<'a> {
    inner: &'a Snapshot,
    /// The snapshot's captured runs, copied so they can be damaged, each
    /// as `(address, bytes)` and in ascending address order.
    memory: Vec<(u64, Vec<u8>)>,
}

impl<'a> Corrupt<'a> {
    pub fn new(inner: &'a Snapshot) -> Self {
        let memory = inner
            .segments()
            .map(|seg| {
                let bytes = inner
                    .read_bytes(seg.start, seg.end - seg.start)
                    .expect("a recorded segment")
                    .to_vec();
                (seg.start, bytes)
            })
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
                    (head > 0).then(|| (addr, bytes[..head].to_vec())),
                    (tail < bytes.len()).then(|| (addr + tail as u64, bytes[tail..].to_vec())),
                ]
            })
            .flatten()
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

impl Target for Corrupt<'_> {
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

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> proc::Result<Option<u64>> {
        self.inner.tls_var_addr(regs, sym)
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A target built by hand for the unwinder's unit tests: memory
//! regions, a mapping table and a sized symbol table, and nothing else.

use proc::{LoadedObjectWithPath, MapFlags, Mappings, Regs, SymbolBuf, Target};

pub(crate) const TEXT: u64 = 0x40_0000;
pub(crate) const HEAP: u64 = 0x60_0000;
pub(crate) const STACK: u64 = 0x7000_0000;

pub(crate) struct FakeTarget {
    pub(crate) mem: Vec<(u64, Vec<u8>)>,
    pub(crate) mappings: Mappings,
    pub(crate) symbols: Vec<SymbolBuf>,
}

impl Target for FakeTarget {
    fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
        for (base, bytes) in &self.mem {
            if addr >= *base && addr + len <= base + bytes.len() as u64 {
                let at = (addr - base) as usize;
                return Ok(&bytes[at..at + len as usize]);
            }
        }
        Err(proc::Error::unmapped(addr, len))
    }
    /// The sized lookup both core readers do: the symbol whose range
    /// holds the address, and nothing for an address past every
    /// symbol's end.
    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        self.symbols
            .iter()
            .find(|s| (s.st_value..s.st_value + s.st_size).contains(&addr))
            .cloned()
    }
    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        self.symbols.iter().find(|s| s.name == name).cloned()
    }
    fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
        Ok(self.symbols.clone())
    }
    fn mappings(&self) -> proc::Result<Mappings> {
        unreachable!("the tests hand the unwinder its mappings")
    }
    fn lwps(&self) -> proc::Result<Vec<proc::LwpInfo>> {
        Ok(Vec::new())
    }
    fn tls_var_addr(&self, _: &Regs, _: &SymbolBuf) -> proc::Result<Option<u64>> {
        Ok(None)
    }
}

fn mapping(vaddr: u64, size: u64, flags: u32) -> LoadedObjectWithPath {
    LoadedObjectWithPath {
        path: None,
        vaddr,
        size,
        flags: MapFlags(flags),
    }
}

/// A target whose stack memory holds the given words, with a text,
/// a heap and a stack mapping. No symbols, no CFI.
pub(crate) fn target(stack_words: &[(u64, u64)]) -> FakeTarget {
    const READ: u32 = 0x04;
    const WRITE: u32 = 0x02;
    const EXEC: u32 = 0x01;
    let mem = stack_words
        .iter()
        .map(|&(addr, word)| (addr, word.to_le_bytes().to_vec()))
        .collect();
    let mappings = [
        mapping(TEXT, 0x1000, READ | EXEC),
        mapping(HEAP, 0x1000, READ | WRITE),
        mapping(STACK, 0x1_0000, READ | WRITE),
    ]
    .into_iter()
    .collect();
    FakeTarget {
        mem,
        mappings,
        symbols: Vec::new(),
    }
}

/// A function symbol covering `[start, start + size)`.
pub(crate) fn symbol(name: &str, start: u64, size: u64) -> SymbolBuf {
    SymbolBuf {
        name: name.to_string(),
        st_name: 0,
        st_info: 0,
        st_other: 0,
        st_shndx: 0,
        st_value: start,
        st_size: size,
    }
}

/// The names a walk's frames resolved to, `-` for a frame without one.
pub(crate) fn names(bt: &crate::Backtrace) -> Vec<String> {
    bt.frames
        .iter()
        .map(|f| match &f.symbol {
            Some(s) => s.name.clone(),
            None => "-".to_string(),
        })
        .collect()
}

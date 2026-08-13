//! What both core readers mean the same way, spelled once: the parsed
//! `PT_LOAD` record with its dumped-versus-mapped split, the per-object
//! symbol store with its by-name lookup contract, and the decoding
//! context for the ELF structures a core carries. The readers differ in
//! how they *find* these things — that stays in each of them — but not
//! in what the things are.

use crate::SymbolBuf;

use goblin::container::{Container, Ctx};

use std::ops::Range;
use std::sync::OnceLock;

/// One `PT_LOAD` of the core.
#[derive(Clone, Debug)]
pub(crate) struct Segment {
    pub(crate) vaddr: u64,
    pub(crate) memsz: u64,
    pub(crate) filesz: u64,
    pub(crate) offset: u64,
    pub(crate) flags: u32,
}

impl Segment {
    /// The part of this region whose bytes are in the core file.
    pub(crate) fn dumped(&self) -> Range<u64> {
        self.vaddr..self.vaddr + self.filesz
    }

    pub(crate) fn range(&self) -> Range<u64> {
        self.vaddr..self.vaddr + self.memsz
    }
}

/// A core is ELF64 and little-endian, which is what the ELF structures
/// read out of it — or written into a synthetic one — are decoded as.
pub(crate) fn elf_ctx() -> Ctx {
    Ctx::new(Container::Big, scroll::Endian::Little)
}

/// The symbols of one object, at their runtime addresses.
#[derive(Default)]
pub(crate) struct Symbols {
    /// Function symbols, sorted by address, for containment lookup.
    pub(crate) functions: Vec<SymbolBuf>,
    /// Data symbols, including the `STT_TLS` ones, whose `st_value` is
    /// an offset into a TLS block rather than an address.
    pub(crate) objects: Vec<SymbolBuf>,
    /// Positions into functions-then-objects, sorted by name, built on
    /// the first by-name lookup. Attach-time fingerprint validation asks
    /// for thousands of names, and a linear scan per name over a
    /// debug-build symtab was a quarter of the time to the first prompt.
    by_name: OnceLock<Vec<u32>>,
}

impl Symbols {
    /// The symbol at a position in the functions-then-objects chain.
    fn at(&self, position: u32) -> &SymbolBuf {
        let position = position as usize;
        self.functions
            .get(position)
            .unwrap_or_else(|| &self.objects[position - self.functions.len()])
    }

    /// The first symbol of this name in chain order — the one a linear
    /// scan found, by binary search. The sort is stable, so symbols
    /// sharing a name keep their chain order.
    pub(crate) fn find_by_name(&self, name: &str) -> Option<&SymbolBuf> {
        let index = self.by_name.get_or_init(|| {
            let mut index: Vec<u32> =
                (0..(self.functions.len() + self.objects.len()) as u32).collect();
            index.sort_by_key(|&p| self.at(p).name.as_str());
            index
        });
        let lo = index.partition_point(|&p| self.at(p).name.as_str() < name);
        index
            .get(lo)
            .map(|&p| self.at(p))
            .filter(|sym| sym.name == name)
    }
}

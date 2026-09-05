// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What both core readers mean the same way, spelled once: the parsed
//! `PT_LOAD` record with its dumped-versus-mapped split, the per-object
//! symbol store with its by-name lookup contract, and the decoding
//! context for the ELF structures a core carries. The readers differ in
//! how they *find* these things — that stays in each of them — but not
//! in what the things are.

use crate::SymbolBuf;

use goblin::container::{Container, Ctx};
use goblin::elf::sym::{STB_WEAK, STT_TLS, Sym};

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

/// Whether a symtab entry names something in its object: the line
/// both readers draw before an entry goes into a [`Symbols`] table, so
/// that one program's symbols read the same from either kind of core.
///
/// The line is where libproc's symbol iterator draws it, since that is
/// what the rest of this workspace joins on and what the illumos reader
/// is held to. Asked for `BIND_GLOBAL | BIND_LOCAL`, the iterator
/// reports no weak entry — an alias such as `_mcount`, or an undefined
/// reference — and it never reports a nameless one. It does report an
/// import the executable has a PLT entry for, at that entry's address:
/// the one address this object has for the name, and the reason the
/// test is on the value rather than on `SHN_UNDEF`. What it has no
/// address for is an import at value 0, which is every import of a
/// PIE: biased, each would become a function of size 0 at the load
/// base, and the executable would claim to define `memcpy`.
///
/// The one valueless entry that names something is a thread-local at
/// offset 0: its value is an offset into the TLS block, and the first
/// variable in the block sits at the start of it.
pub(crate) fn names_something(name: &str, sym: &Sym) -> bool {
    !name.is_empty() && sym.st_bind() != STB_WEAK && (sym.st_value != 0 || sym.st_type() == STT_TLS)
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

#[cfg(test)]
mod tests {
    use super::*;

    use goblin::elf::section_header::SHN_UNDEF;
    use goblin::elf::sym::{STB_GLOBAL, STB_LOCAL, STT_FUNC, STT_OBJECT};

    /// A defined entry lives in some real section; 14 is as good as any.
    const TEXT: usize = 14;
    const UNDEF: usize = SHN_UNDEF as usize;

    fn sym(bind: u8, ty: u8, shndx: usize, value: u64) -> Sym {
        Sym {
            st_name: 1,
            st_info: (bind << 4) | ty,
            st_other: 0,
            st_shndx: shndx,
            st_value: value,
            st_size: 8,
        }
    }

    /// One row per way an entry can fail to name anything, and the
    /// shapes that must survive them: the thread-local at offset 0,
    /// which the zero-value rule must not eat, and the import at a PLT
    /// address, which libproc reports.
    #[test]
    fn test_names_something_draws_libprocs_line() {
        let admitted = |name, bind, ty, shndx, value| {
            assert!(
                names_something(name, &sym(bind, ty, shndx, value)),
                "{name} dropped"
            );
        };
        let dropped = |name, bind, ty, shndx, value| {
            assert!(
                !names_something(name, &sym(bind, ty, shndx, value)),
                "{name} admitted"
            );
        };

        admitted("f", STB_GLOBAL, STT_FUNC, TEXT, 0x1000);
        admitted("f", STB_LOCAL, STT_FUNC, TEXT, 0x1000);
        admitted("v", STB_GLOBAL, STT_OBJECT, TEXT, 0x2000);
        // The first thread-local in a block is at offset 0.
        admitted("t", STB_GLOBAL, STT_TLS, TEXT, 0);
        // An import with a PLT entry has an address in this object.
        admitted("puts", STB_GLOBAL, STT_FUNC, UNDEF, 0x1020);

        dropped("", STB_GLOBAL, STT_FUNC, TEXT, 0x1000);
        dropped("_mcount", STB_WEAK, STT_FUNC, TEXT, 0x1000);
        dropped("__cxa_finalize", STB_WEAK, STT_FUNC, UNDEF, 0);
        dropped("memcpy", STB_GLOBAL, STT_FUNC, UNDEF, 0);
        dropped("nowhere", STB_GLOBAL, STT_FUNC, TEXT, 0);
        dropped("nowhere", STB_GLOBAL, STT_OBJECT, TEXT, 0);
    }
}

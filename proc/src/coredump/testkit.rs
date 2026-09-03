// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shared scaffolding for the two synthetic-core builders: the leaf
//! serializers and layout facts both test modules spell the same way.
//! Each reader keeps its own `CoreBuilder` — what an illumos core
//! carries (per-object symtabs, a link map, section headers) and what a
//! Linux one does (`NT_FILE`, backing files) differ by design — but a
//! program header, a note record, and a register block do not.

use super::common::elf_ctx;
use crate::Regs;

use goblin::elf::program_header::ProgramHeader;
use goblin::elf::program_header::program_header64::SIZEOF_PHDR;
use scroll::Pwrite;

pub(crate) const PAGE: u64 = 0x1000;

/// The builders pad their notes to four bytes, which is what a core
/// actually uses whatever its `PT_NOTE` alignment claims.
pub(crate) const NOTE_ALIGN: usize = 4;

/// One `PT_LOAD` a builder will emit.
pub(crate) struct Load {
    pub(crate) vaddr: u64,
    pub(crate) memsz: u64,
    pub(crate) flags: u32,
    /// The bytes actually written to the core; shorter than `memsz`
    /// when the dump left part of the region out.
    pub(crate) bytes: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn phdr(
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
) -> Vec<u8> {
    let header = ProgramHeader {
        p_type,
        p_flags,
        p_offset,
        p_vaddr,
        p_paddr: p_vaddr,
        p_filesz,
        p_memsz,
        p_align,
    };
    let mut out = vec![0u8; SIZEOF_PHDR];
    out.pwrite_with(header, 0, elf_ctx())
        .expect("failed to write a program header");
    out
}

pub(crate) fn note(ntype: u32, name: &str, desc: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let namesz = name.len() + 1;
    out.extend((namesz as u32).to_le_bytes());
    out.extend((desc.len() as u32).to_le_bytes());
    out.extend(ntype.to_le_bytes());
    out.extend(name.as_bytes());
    out.push(0);
    while out.len() % NOTE_ALIGN != 0 {
        out.push(0);
    }
    out.extend(desc);
    while out.len() % NOTE_ALIGN != 0 {
        out.push(0);
    }
    out
}

pub(crate) fn regs_at(rip: u64, rsp: u64) -> Regs {
    Regs {
        rip,
        rsp,
        ..Regs::default()
    }
}

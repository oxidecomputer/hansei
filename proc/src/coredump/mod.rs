//! Core-dump readers, one per format.
//!
//! These parse a file and nothing else — no libproc, no procfs, no
//! ptrace — so which reader is wanted follows from the core, not from
//! the host looking at it. A Linux core read on illumos and an illumos
//! core read on Linux are the same operation as reading either at home.
//!
//! What is *not* here is live processes: attaching to one is the
//! operating system's business, and each has its own way (libproc on
//! illumos, procfs and ptrace on Linux). Those backends stay beside
//! this module and stay gated to the host that has them.

pub mod linux;

use crate::{Error, Result};

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Which system's core this is.
///
/// Both are `ET_CORE` ELF files and neither says so in its header —
/// `EI_OSABI` is `SYSV` in both — so the answer comes from the notes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Flavour {
    Linux,
    Illumos,
}

/// Notes only one of the two systems writes.
///
/// The shared SVR4 heritage is no help — both write `NT_PRSTATUS` (1),
/// `NT_PRPSINFO` (3) and `NT_AUXV` (6), and both leave `EI_OSABI` at
/// `SYSV` — so identification rests on the notes each system added for
/// itself. Note *types* are the right thing to key on: unlike the size
/// of a register set, they do not change from one architecture to the
/// next.
///
/// Section headers are the obvious alternative and a worse one, for
/// three reasons that have nothing to do with what they cost to read.
/// Their presence is not even consistent within one system: a
/// kernel-written Linux core has no section headers at all, while a
/// `gcore` one from gdb has a table of `note0`/`load` entries mirroring
/// its program headers. What makes an illumos core's sections
/// interesting — the per-object `.symtab` and `.SUNW_ctf` — is there
/// only because `coreadm` content included `symtab` and `ctf`, and that
/// is configurable. And sections sit at the end of the file where a
/// core truncated by a size limit loses them first, while the notes are
/// written near the front and describe the process whatever else was
/// left out.
mod note {
    /// illumos, from `<sys/procfs.h>`: the modern process and per-LWP
    /// status notes, which every illumos core carries. Linux assigns no
    /// meaning to these numbers.
    pub const PSTATUS: u32 = 10;
    pub const PSINFO: u32 = 13;
    pub const LWPSTATUS: u32 = 16;
    pub const LWPSINFO: u32 = 17;

    /// Linux, from `<elf.h>`: the mapped-file table, spelled "FILE" in
    /// ASCII. illumos has no equivalent and no note of this number.
    pub const FILE: u32 = 0x4649_4c45;

    /// Linux puts its architecture notes under this owner rather than
    /// `CORE`; illumos writes only `CORE`.
    pub const LINUX_OWNER: &[u8] = b"LINUX\0";
}

/// `struct elf_prstatus` as Linux writes it for x86-64, and `prstatus_t`
/// as illumos does. Only a fallback — see [`flavour_from_notes`].
const NT_PRSTATUS: u32 = 1;
const LINUX_PRSTATUS_LEN: usize = 336;
const ILLUMOS_PRSTATUS_LEN: usize = 824;

/// Identify a core without committing to reading it.
///
/// Reads only the ELF and note headers, so it costs a few pages however
/// large the core is.
pub fn flavour(path: &Path) -> Result<Flavour> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(Error::read)?
        .read_to_end(&mut bytes)
        .map_err(Error::read)?;
    flavour_of(&bytes)
}

pub(crate) fn flavour_of(bytes: &[u8]) -> Result<Flavour> {
    use goblin::elf::Elf;
    use goblin::elf::program_header::PT_NOTE;

    let elf = Elf::parse(bytes).map_err(|_| Error::bad_core("not an ELF file"))?;
    if elf.header.e_type != goblin::elf::header::ET_CORE {
        return Err(Error::bad_core("not a core file"));
    }

    for ph in elf.program_headers.iter().filter(|ph| ph.p_type == PT_NOTE) {
        let start = ph.p_offset as usize;
        let end = start
            .checked_add(ph.p_filesz as usize)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| Error::bad_core("PT_NOTE runs past the end of the file"))?;
        if let Some(f) = flavour_from_notes(&bytes[start..end]) {
            return Ok(f);
        }
    }
    Err(Error::bad_core(
        "no NT_PRSTATUS note, so the core names no threads and no system",
    ))
}

/// Walk one `PT_NOTE`, looking for a note only one system writes.
///
/// Deliberately its own small walk rather than a reader's: the readers
/// disagree about how to read a note's body, which is the thing being
/// decided here, so this reads only the headers every ELF note shares.
///
/// The size of `NT_PRSTATUS` is a last resort, for a core carrying none
/// of the distinctive notes — a Linux core of a process with no file
/// mappings has no `NT_FILE`, which is hard to arrange but easy to
/// synthesise. It is checked last because it is the one signal here
/// that would have to be revisited on another architecture.
fn flavour_from_notes(bytes: &[u8]) -> Option<Flavour> {
    let mut fallback = None;
    let mut pos = 0usize;

    while pos + 12 <= bytes.len() {
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let namesz = word(pos) as usize;
        let descsz = word(pos + 4) as usize;
        let ntype = word(pos + 8);

        let name_start = pos + 12;
        let name_end = name_start.checked_add(namesz)?;
        let desc_start = name_end.next_multiple_of(4);
        let desc_end = desc_start.checked_add(descsz)?;
        if desc_end > bytes.len() {
            return fallback;
        }
        let name = &bytes[name_start..name_end];

        match ntype {
            note::PSTATUS | note::PSINFO | note::LWPSTATUS | note::LWPSINFO => {
                return Some(Flavour::Illumos);
            }
            note::FILE => return Some(Flavour::Linux),
            NT_PRSTATUS if fallback.is_none() => {
                fallback = match descsz {
                    LINUX_PRSTATUS_LEN => Some(Flavour::Linux),
                    ILLUMOS_PRSTATUS_LEN => Some(Flavour::Illumos),
                    _ => None,
                };
            }
            _ => {}
        }
        if name == note::LINUX_OWNER {
            return Some(Flavour::Linux);
        }

        pos = desc_end.next_multiple_of(4);
    }
    fallback
}

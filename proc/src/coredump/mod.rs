//! Core-dump readers, one per format.
//!
//! These parse a file and nothing else — no libproc, no procfs, no
//! ptrace — so which reader is wanted follows from the core, not from
//! the host looking at it. A Linux core read on illumos and an illumos
//! core read on Linux are the same operation as reading either at home.
//!
//! The one other reader in the crate — the feature-gated libproc
//! reference the illumos reader here is compared against in tests —
//! stays beside this module, gated to the host that has libproc.

pub mod illumos;
pub mod linux;

use crate::{Error, Result};

use goblin::elf::note::{NT_FILE, NT_PRSTATUS};

use memmap2::Mmap;

use std::fs::File;
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

/// The notes only illumos writes. Linux's side of the question is
/// `NT_FILE`, its mapped-file table, which goblin names for us.
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

    /// Linux puts its architecture notes under this owner rather than
    /// `CORE`; illumos writes only `CORE`.
    pub const LINUX_OWNER: &str = "LINUX";
}

/// `struct elf_prstatus` as Linux writes it for x86-64, and `prstatus_t`
/// as illumos does. Only a fallback — see [`flavour_of`].
const LINUX_PRSTATUS_LEN: usize = 336;
const ILLUMOS_PRSTATUS_LEN: usize = 824;

/// Identify a core without committing to reading it.
///
/// Reads only the ELF and note headers, so it costs a few pages however
/// large the core is.
pub fn flavour(path: &Path) -> Result<Flavour> {
    let file = File::open(path).map_err(Error::read)?;
    // SAFETY: as everywhere else in this workspace, we assume the file is
    // not modified while mapped.
    let core = unsafe { Mmap::map(&file) }.map_err(Error::read)?;
    flavour_of(&core)
}

/// The size of `NT_PRSTATUS` is a last resort, for a core carrying none
/// of the distinctive notes — a Linux core of a process with no file
/// mappings has no `NT_FILE`, which is hard to arrange but easy to
/// synthesise. It is checked last because it is the one signal here
/// that would have to be revisited on another architecture.
pub(crate) fn flavour_of(bytes: &[u8]) -> Result<Flavour> {
    use goblin::elf::Elf;

    let elf = Elf::parse(bytes).map_err(|_| Error::bad_core("not an ELF file"))?;
    if elf.header.e_type != goblin::elf::header::ET_CORE {
        return Err(Error::bad_core("not a core file"));
    }

    let mut fallback = None;
    for note in elf.iter_note_headers(bytes).into_iter().flatten() {
        let Ok(note) = note else {
            break;
        };
        match note.n_type {
            note::PSTATUS | note::PSINFO | note::LWPSTATUS | note::LWPSINFO => {
                return Ok(Flavour::Illumos);
            }
            NT_FILE => return Ok(Flavour::Linux),
            NT_PRSTATUS if fallback.is_none() => {
                fallback = match note.desc.len() {
                    LINUX_PRSTATUS_LEN => Some(Flavour::Linux),
                    ILLUMOS_PRSTATUS_LEN => Some(Flavour::Illumos),
                    _ => None,
                };
            }
            _ => {}
        }
        if note.name == note::LINUX_OWNER {
            return Ok(Flavour::Linux);
        }
    }
    fallback.ok_or_else(|| {
        Error::bad_core("no NT_PRSTATUS note, so the core names no threads and no system")
    })
}

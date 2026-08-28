//! [`Proc`]: whichever backend can read the core in hand.
//!
//! A core is identified by what wrote it, not by what is reading it, so
//! [`Proc::open_core`] looks at the file and picks. Either system's core
//! reads from the file, anywhere: the portable readers parse the notes
//! and symbol tables themselves, and every read is lent straight out of
//! the mapped file ([`Target::read_bytes`]) rather than copied through
//! libproc's `pread` — which a render pass issuing one read per string
//! can feel. On illumos libproc remains the reference reader, held
//! against the portable one in tests via the test-only `libproc::Core`
//! — never through this facade, which holds only readers that lend.

use crate::coredump::{self, Flavour};
use crate::{BuildIds, LwpInfo, Mappings, Regs, Result, SymbolBuf, Target};

use std::path::{Path, PathBuf};

/// A target: a core dump of either system.
pub enum Proc {
    /// A Linux core, read from the file.
    LinuxCore(coredump::linux::Core),
    /// An illumos core, read from the file.
    IllumosCore(coredump::illumos::Core),
}

impl Proc {
    /// Open a core dump, whichever system wrote it.
    pub fn open_core(path: &Path) -> Result<Self> {
        Self::open_core_with_binary(path, None)
    }

    /// Open a core dump, reading the executable from `binary` rather
    /// than from the path the core recorded for it.
    ///
    /// Only a Linux core has anything to substitute. An illumos core
    /// carries each mapped object's symbol table in its own section
    /// headers, so it needs no companion binary and ignores one.
    pub fn open_core_with_binary(path: &Path, binary: Option<&Path>) -> Result<Self> {
        match coredump::flavour(path)? {
            Flavour::Linux => Ok(Proc::LinuxCore(coredump::linux::Core::open_with_binary(
                path, binary,
            )?)),
            Flavour::Illumos => Ok(Proc::IllumosCore(coredump::illumos::Core::open(path)?)),
        }
    }

    /// Whether this core needs a companion executable to resolve any
    /// symbol at all.
    pub fn needs_binary(&self) -> bool {
        matches!(self, Proc::LinuxCore(_))
    }

    /// The executable's build id as the core and the file backing it
    /// each spell it, for the cores where the question arises.
    pub fn build_ids(&self) -> Option<BuildIds> {
        match self {
            Proc::LinuxCore(c) => Some(c.build_ids()),
            Proc::IllumosCore(_) => None,
        }
    }
}

/// Forward an inherent method to whichever backend is in hand.
macro_rules! dispatch {
    ($self:ident, $method:ident($($arg:expr),*)) => {
        match $self {
            Proc::LinuxCore(c) => c.$method($($arg),*),
            Proc::IllumosCore(c) => c.$method($($arg),*),
        }
    };
}

impl Proc {
    /// The path the core records for the target's executable.
    pub fn exec_name(&self) -> Result<PathBuf> {
        dispatch!(self, exec_name())
    }
}

impl std::fmt::Debug for Proc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        dispatch!(self, fmt(f))
    }
}

// The whole facade crosses threads during parallel rendering.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<Proc>();
};

impl Target for Proc {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<&[u8]> {
        match self {
            Proc::LinuxCore(c) => Target::read_bytes(c, addr, len),
            Proc::IllumosCore(c) => Target::read_bytes(c, addr, len),
        }
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        dispatch!(self, readable_len(addr, max))
    }

    fn fatal_signal(&self) -> Option<crate::FatalSignal> {
        match self {
            Proc::LinuxCore(c) => Target::fatal_signal(c),
            Proc::IllumosCore(c) => Target::fatal_signal(c),
        }
    }

    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        dispatch!(self, lookup_symbol_by_addr(addr))
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        dispatch!(self, lookup_symbol_by_name(name))
    }

    fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        dispatch!(self, symbols())
    }

    fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        dispatch!(self, object_symbols())
    }

    fn mappings(&self) -> Result<Mappings> {
        dispatch!(self, mappings())
    }

    fn lwps(&self) -> Result<Vec<LwpInfo>> {
        dispatch!(self, lwps())
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        dispatch!(self, tls_var_addr(regs, sym))
    }

    fn exec_bias(&self) -> Option<u64> {
        dispatch!(self, exec_bias())
    }
}

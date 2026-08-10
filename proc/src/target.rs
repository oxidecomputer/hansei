//! [`Proc`]: whichever backend can read the target in hand.
//!
//! A core is identified by what wrote it, not by what is reading it, so
//! [`Proc::open_core`] looks at the file and picks. Either system's core
//! reads from the file, anywhere: the portable readers parse the notes
//! and symbol tables themselves, and every read is lent straight out of
//! the mapped file ([`Target::pslice`]) rather than copied through
//! libproc's `pread` — which a render pass issuing one read per string
//! can feel. On illumos libproc remains
//! the reference reader, held against the portable one in tests via
//! [`Proc::open_core_libproc`].
//!
//! Live processes are the operating system's business and stay with it:
//! [`Proc::grab_pid`] exists only on illumos, where libproc provides it.

use crate::coredump::{self, Flavour};
use crate::{LoadedObject, LwpInfo, Mappings, Regs, Result, Status, SymbolBuf, Target};

use std::path::{Path, PathBuf};

/// A target: a core dump of either system, or a live process.
pub enum Proc {
    /// A live process, through libproc.
    #[cfg(target_os = "illumos")]
    Libproc(crate::illumos::Proc),
    /// A Linux core, read from the file.
    LinuxCore(coredump::linux::Core),
    /// An illumos core, read from the file.
    IllumosCore(coredump::illumos::Core),
}

impl Proc {
    /// Open a core dump, whichever system wrote it.
    pub fn open_core(path: &Path) -> Result<Self> {
        match coredump::flavour(path)? {
            Flavour::Linux => Ok(Proc::LinuxCore(coredump::linux::Core::open(path)?)),
            Flavour::Illumos => Ok(Proc::IllumosCore(coredump::illumos::Core::open(path)?)),
        }
    }

    /// The core's format, for a caller that wants to say so.
    pub fn flavour(&self) -> Flavour {
        match self {
            #[cfg(target_os = "illumos")]
            Proc::Libproc(_) => Flavour::Illumos,
            Proc::LinuxCore(_) => Flavour::Linux,
            Proc::IllumosCore(_) => Flavour::Illumos,
        }
    }
}

/// Forward an inherent method to whichever backend is in hand.
macro_rules! dispatch {
    ($self:ident, $method:ident($($arg:expr),*)) => {
        match $self {
            #[cfg(target_os = "illumos")]
            Proc::Libproc(p) => p.$method($($arg),*),
            Proc::LinuxCore(c) => c.$method($($arg),*),
            Proc::IllumosCore(c) => c.$method($($arg),*),
        }
    };
}

impl Proc {
    pub fn status(&self) -> Status {
        dispatch!(self, status())
    }

    pub fn exec_name(&self) -> Result<PathBuf> {
        dispatch!(self, exec_name())
    }

    pub fn lwps(&self) -> Result<Vec<LwpInfo>> {
        dispatch!(self, lwps())
    }

    pub fn regs(&self, lwp: u32) -> Result<Regs> {
        dispatch!(self, regs(lwp))
    }

    pub fn read_u64(&self, address: u64) -> Result<u64> {
        dispatch!(self, read_u64(address))
    }

    pub fn read_u32(&self, address: u64) -> Result<u32> {
        dispatch!(self, read_u32(address))
    }

    pub fn read_u16(&self, address: u64) -> Result<u16> {
        dispatch!(self, read_u16(address))
    }

    pub fn read_u8(&self, address: u64) -> Result<u8> {
        dispatch!(self, read_u8(address))
    }

    pub fn mappings(&self) -> Result<Mappings> {
        dispatch!(self, mappings())
    }

    pub fn addr_to_map(&self, address: u64) -> Option<LoadedObject> {
        dispatch!(self, addr_to_map(address))
    }

    pub fn addr_is_mapped(&self, address: u64) -> bool {
        dispatch!(self, addr_is_mapped(address))
    }

    pub fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        dispatch!(self, symbols())
    }

    pub fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        dispatch!(self, object_symbols())
    }

    pub fn lookup_symbol_by_addr(&self, address: u64) -> Option<SymbolBuf> {
        dispatch!(self, lookup_symbol_by_addr(address))
    }

    pub fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        dispatch!(self, lookup_symbol_by_name(name))
    }

    pub fn lookup_symbol_name_by_addr(&self, address: u64) -> Option<String> {
        dispatch!(self, lookup_symbol_name_by_addr(address))
    }
}

// ---------------------------------------------------------------------------
// illumos-only
// ---------------------------------------------------------------------------

#[cfg(target_os = "illumos")]
impl Proc {
    pub fn grab_pid(pid: u32) -> Result<Self> {
        Ok(Proc::Libproc(crate::illumos::Proc::grab_pid(pid)?))
    }

    /// Open an illumos core through libproc rather than the portable
    /// reader. libproc is the reference the portable reader is held to,
    /// so this is for the tests that compare the two on one core.
    pub fn open_core_libproc(path: &Path) -> Result<Self> {
        Ok(Proc::Libproc(crate::illumos::Proc::open_core(path)?))
    }

    pub fn grab_pid_no_stop(pid: u32) -> Result<Self> {
        Ok(Proc::Libproc(crate::illumos::Proc::grab_pid_no_stop(pid)?))
    }

    /// Read through libproc's `Pread`, which serves live grabs and
    /// libproc-opened cores alike. This is the libproc-compat surface
    /// only: the portable core readers lend borrows via
    /// [`Target::pslice`] instead and refuse it.
    pub fn pread(&self, buf: &mut [u8], address: u64) -> Result<u64> {
        match self {
            Proc::Libproc(p) => p.pread(buf, address),
            _ => Err(crate::Error::not_a_live_process()),
        }
    }

    pub fn pread_exact(&self, buf: &mut [u8], address: u64) -> Result<()> {
        match self {
            Proc::Libproc(p) => p.pread_exact(buf, address),
            _ => Err(crate::Error::not_a_live_process()),
        }
    }

    pub fn run(&self) -> Result<()> {
        match self {
            Proc::Libproc(p) => p.run(),
            _ => Err(crate::Error::not_a_live_process()),
        }
    }

    pub fn stop(&self, wait_ms: u32) -> Result<()> {
        match self {
            Proc::Libproc(p) => p.stop(wait_ms),
            _ => Err(crate::Error::not_a_live_process()),
        }
    }

    pub fn lwp_handle(&self, lwpid: u32) -> Result<crate::illumos::Lwp> {
        match self {
            Proc::Libproc(p) => p.lwp_handle(lwpid),
            _ => Err(crate::Error::not_a_live_process()),
        }
    }

    pub fn lwp_name(&self, lwpid: u32) -> Result<String> {
        match self {
            Proc::Libproc(p) => p.lwp_name(lwpid),
            Proc::IllumosCore(c) => c.lwp_name(lwpid),
            _ => Err(crate::Error::no_lwp_name()),
        }
    }

    /// The LWP's fast-TSD slots. illumos stores a thread-local there, so
    /// this asks for something a Linux core does not have; prefer
    /// [`Target::tls_var_addr`], which both systems can answer.
    pub fn lwp_tsd(&self, lwp: u32) -> Result<[u64; 9]> {
        let regs = self.regs(lwp)?;
        self.tsd_from_regs(&regs)
    }

    pub fn tsd_from_regs(&self, regs: &Regs) -> Result<[u64; 9]> {
        crate::tsd_from_fsbase(self, regs)
    }
}

impl std::fmt::Debug for Proc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(target_os = "illumos")]
            Proc::Libproc(p) => p.fmt(f),
            Proc::LinuxCore(c) => c.fmt(f),
            Proc::IllumosCore(c) => c.fmt(f),
        }
    }
}

// The whole facade crosses threads during parallel rendering, live
// variant included — libproc calls serialize behind that variant's
// own mutex.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<Proc>();
};

impl Target for Proc {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        dispatch!(self, read_bytes(addr, len))
    }

    fn pslice(&self, addr: u64, len: u64) -> Option<&[u8]> {
        match self {
            // libproc reads through a handle; there is nothing to borrow.
            #[cfg(target_os = "illumos")]
            Proc::Libproc(_) => None,
            Proc::LinuxCore(c) => c.pslice(addr, len),
            Proc::IllumosCore(c) => c.pslice(addr, len),
        }
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        match self {
            // Bounding a live process would mean probing its mappings on
            // every read; it claims no bound and the ceiling covers it.
            #[cfg(target_os = "illumos")]
            Proc::Libproc(_) => max,
            Proc::LinuxCore(c) => c.readable_len(addr, max),
            Proc::IllumosCore(c) => c.readable_len(addr, max),
        }
    }

    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        Proc::lookup_symbol_by_addr(self, addr)
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        Proc::lookup_symbol_by_name(self, name)
    }

    fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        Proc::symbols(self)
    }

    fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        Proc::object_symbols(self)
    }

    fn mappings(&self) -> Result<Mappings> {
        Proc::mappings(self)
    }

    fn lwps(&self) -> Result<Vec<LwpInfo>> {
        Proc::lwps(self)
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        dispatch!(self, tls_var_addr(regs, sym))
    }
}

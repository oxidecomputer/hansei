//! Reading bytes from a live process, core file, or snapshot.

use crate::{Error, Result};

use std::borrow::Cow;

pub trait ReadFromProc {
    /// Read `len` bytes at address, returning an error if the address is
    /// unmapped. Borrowed straight from the target's own storage when it
    /// serves the range in one piece (a mapped core segment); owned when
    /// the read had to be assembled. The renderer holds these across its
    /// recursion, so what a mapping can lend costs no allocation at all.
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Cow<'_, [u8]>>;

    /// How many of the `max` bytes at `addr` the target can serve, without
    /// reading any of them.
    ///
    /// A reader that cannot answer cheaply claims no bound and returns
    /// `max`. See [`proc::Target::readable_len`]: this is what keeps a
    /// length word read out of corrupt target memory from being believed
    /// far enough to allocate for it.
    fn readable_len(&self, _addr: u64, max: u64) -> u64 {
        max
    }

    /// The mangled function symbol beginning exactly at `addr`, if one is
    /// available from the target. Display-only readers can leave this
    /// unresolved; vtable formatting then preserves the raw entry.
    fn function_symbol(&self, _addr: u64) -> Option<String> {
        None
    }
}

impl<T: proc::Target> ReadFromProc for T {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Cow<'_, [u8]>> {
        if let Some(bytes) = self.pslice(addr, len) {
            return Ok(Cow::Borrowed(bytes));
        }
        proc::Target::read_bytes(self, addr, len)
            .map(Cow::Owned)
            .map_err(|e| Error::invalid_addr(addr).with_source(e))
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        proc::Target::readable_len(self, addr, max)
    }

    fn function_symbol(&self, addr: u64) -> Option<String> {
        let symbol = proc::Target::lookup_symbol_by_addr(self, addr)?;
        (symbol.st_value == addr && symbol.st_info & 0x0f == 2).then_some(symbol.name)
    }
}

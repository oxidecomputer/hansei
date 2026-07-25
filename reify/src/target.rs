//! Reading bytes from a live process, core file, or snapshot.

use crate::{Error, Result};

pub trait ReadFromProc {
    /// Read `len` bytes at address, returning an error if the address is
    /// unmapped.
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>>;

    /// The mangled function symbol beginning exactly at `addr`, if one is
    /// available from the target. Display-only readers can leave this
    /// unresolved; vtable formatting then preserves the raw entry.
    fn function_symbol(&self, _addr: u64) -> Option<String> {
        None
    }
}

impl<T: proc::Target> ReadFromProc for T {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        proc::Target::read_bytes(self, addr, len)
            .map_err(|e| Error::invalid_addr(addr).with_source(e))
    }

    fn function_symbol(&self, addr: u64) -> Option<String> {
        let symbol = proc::Target::lookup_symbol_by_addr(self, addr)?;
        (symbol.st_value == addr && symbol.st_info & 0x0f == 2).then_some(symbol.name)
    }
}

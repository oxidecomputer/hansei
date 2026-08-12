//! reify's contract over a [`proc::Target`]: every read is lent
//! straight from the target's own storage ([`proc::Target::read_bytes`]),
//! which the renderer holds across its recursion, so a read costs no
//! allocation at all. This module holds the two things reify layers on
//! top — its error vocabulary, and the one policy decision of which
//! symtab answers count as a code symbol.

use crate::{Error, Result};

use proc::Target;

/// Read `len` bytes at `addr`, restating a target's refusal in reify's
/// error vocabulary. The render paths call the target directly and
/// degrade to a marker instead; this is for the navigation and parse
/// entry points, whose failures are [`Error`]s.
pub(crate) fn read_bytes(proc: &dyn Target, addr: u64, len: u64) -> Result<&[u8]> {
    proc.read_bytes(addr, len)
        .map_err(|e| Error::invalid_addr(addr).with_source(e))
}

/// The mangled function symbol beginning exactly at `addr`, if any.
/// Vtable rendering resolves code pointers without ever following one
/// as data, so only a symbol that starts at the address and is a
/// function (`STT_FUNC`) counts; anything else preserves the raw entry.
pub(crate) fn function_symbol(proc: &dyn Target, addr: u64) -> Option<String> {
    let symbol = proc.lookup_symbol_by_addr(addr)?;
    (symbol.st_value == addr && symbol.st_info & 0x0f == 2).then_some(symbol.name)
}

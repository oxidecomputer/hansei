// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The target a fixture-reading test reads: a fresh core of the
//! program ([`super::cores`]).

use proc::snapshot::RecordedHeapEvidence;
use proc::{
    BuildIds, FatalSignal, LwpInfo, Mappings, Proc, ProcessFacts, Regs, Result, SymbolBuf, Target,
};

use super::canonical::Canonical;

use std::ops::Range;
use std::path::PathBuf;

/// One fixture program's target: a fresh core, through the production
/// reader, renamed canonically. Tests name this rather than the types
/// behind it.
#[derive(Debug)]
pub struct Fixture(pub Box<Canonical<Proc>>);

/// Forward a `Target` method to the core.
macro_rules! dispatch {
    ($self:ident, $method:ident($($arg:expr),*)) => {
        Target::$method(&*$self.0, $($arg),*)
    };
}

impl Target for Fixture {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<&[u8]> {
        dispatch!(self, read_bytes(addr, len))
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        dispatch!(self, readable_len(addr, max))
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

    fn fatal_signal(&self) -> Option<FatalSignal> {
        dispatch!(self, fatal_signal())
    }

    fn lwp_name(&self, tid: u32) -> Option<String> {
        dispatch!(self, lwp_name(tid))
    }

    fn agent_lwp(&self) -> Option<u32> {
        dispatch!(self, agent_lwp())
    }

    fn process_facts(&self) -> Option<ProcessFacts> {
        dispatch!(self, process_facts())
    }

    fn exec_path(&self) -> Option<PathBuf> {
        dispatch!(self, exec_path())
    }

    fn build_ids(&self) -> Option<BuildIds> {
        dispatch!(self, build_ids())
    }

    fn backing_file_problem(&self, path: &str) -> Option<String> {
        dispatch!(self, backing_file_problem(path))
    }

    fn recorded_heap_evidence(&self) -> Option<RecordedHeapEvidence> {
        dispatch!(self, recorded_heap_evidence())
    }

    fn mappings(&self) -> Result<Mappings> {
        dispatch!(self, mappings())
    }

    fn captured_runs(&self) -> Option<Vec<Range<u64>>> {
        dispatch!(self, captured_runs())
    }

    fn lwps(&self) -> Result<Vec<LwpInfo>> {
        dispatch!(self, lwps())
    }

    fn read_u64(&self, addr: u64) -> Result<u64> {
        dispatch!(self, read_u64(addr))
    }

    fn read_u32(&self, addr: u64) -> Result<u32> {
        dispatch!(self, read_u32(addr))
    }

    fn read_u16(&self, addr: u64) -> Result<u16> {
        dispatch!(self, read_u16(addr))
    }

    fn read_u8(&self, addr: u64) -> Result<u8> {
        dispatch!(self, read_u8(addr))
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        dispatch!(self, tls_var_addr(regs, sym))
    }

    fn tls_word(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        dispatch!(self, tls_word(regs, sym))
    }

    fn exec_bias(&self) -> Option<u64> {
        dispatch!(self, exec_bias())
    }
}

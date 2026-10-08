// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Off illumos, this module only ever runs inside `mdbmock`, the test
//! host that stands in for mdb over a Linux core. Everything it needs
//! comes through the same mdb and libproc calls as on illumos except
//! one: a Linux thread-local is native ELF TLS, not illumos's pthread
//! key, and resolving one takes the thread's TLS layout, which only the
//! host has. The host exports that as one extra symbol.

use proc::{Regs, SymbolBuf};

use std::ffi::{CString, c_char, c_int, c_void};

type TlsFn = unsafe extern "C" fn(fsbase: u64, name: *const c_char, out: *mut u64) -> c_int;

unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

pub fn tls_var_addr(regs: &Regs, sym: &SymbolBuf) -> proc::Result<Option<u64>> {
    // RTLD_DEFAULT is the null handle on Linux.
    let f = unsafe { dlsym(std::ptr::null_mut(), c"mdbmock_tls_var_addr".as_ptr()) };
    if f.is_null() {
        return Err(proc::Error::not_thread_local(&sym.name, 6));
    }
    let f: TlsFn = unsafe { std::mem::transmute(f) };
    let name = CString::new(sym.name.as_str()).map_err(proc::Error::bad_path)?;
    let mut out = 0u64;
    match unsafe { f(regs.fsbase, name.as_ptr(), &mut out) } {
        0 => Ok(Some(out)),
        1 => Ok(None),
        _ => Err(proc::Error::tls_not_recorded(&sym.name, regs.fsbase)),
    }
}

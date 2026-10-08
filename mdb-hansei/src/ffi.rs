// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The slice of mdb's module API (`<sys/mdb_modapi.h>`, API version 5)
//! and of libproc (`<libproc.h>`) this module calls.
//!
//! Everything here is resolved against the mdb process when it
//! `dlopen()`s the module: mdb itself exports the `mdb_*` functions, and
//! libproc is one of its own dependencies, so the handle mdb exports as
//! `pshandle` target data is a handle into that same library.

#![allow(non_camel_case_types, dead_code)]

use std::ffi::{c_char, c_int, c_uint, c_void};

pub const MDB_API_VERSION: u16 = 5;

pub const DCMD_OK: c_int = 0;
pub const DCMD_ERR: c_int = 1;
pub const DCMD_USAGE: c_int = 2;

pub const DCMD_ADDRSPEC: c_uint = 0x01;
pub const DCMD_LOOP: c_uint = 0x02;
pub const DCMD_LOOPFIRST: c_uint = 0x04;
pub const DCMD_PIPE: c_uint = 0x08;
pub const DCMD_PIPE_OUT: c_uint = 0x10;

pub const WALK_ERR: c_int = -1;
pub const WALK_NEXT: c_int = 0;
pub const WALK_DONE: c_int = 1;

pub const MDB_TYPE_STRING: c_uint = 0;
pub const MDB_TYPE_IMMEDIATE: c_uint = 1;
pub const MDB_TYPE_CHAR: c_uint = 2;

pub const MDB_SYM_FUZZY: c_uint = 0;

/// `MDB_OBJ_EXEC`: the primary executable, as an object name.
pub const MDB_OBJ_EXEC: *const c_char = std::ptr::null();

pub const MDB_SYMTAB: c_uint = 1;
pub const MDB_BIND_ANY: c_uint = 0x0007;
pub const MDB_TYPE_OBJECT: c_uint = 0x0200;
pub const MDB_TYPE_FUNC: c_uint = 0x0400;
pub const MDB_TYPE_TLS: c_uint = 0x4000;

#[repr(C)]
pub union mdb_arg_un {
    pub a_str: *const c_char,
    pub a_val: u64,
    pub a_char: c_char,
}

#[repr(C)]
pub struct mdb_arg_t {
    pub a_type: c_uint,
    pub a_un: mdb_arg_un,
}

pub type mdb_dcmd_f =
    unsafe extern "C" fn(addr: usize, flags: c_uint, argc: c_int, argv: *const mdb_arg_t) -> c_int;

#[repr(C)]
pub struct mdb_dcmd_t {
    pub dc_name: *const c_char,
    pub dc_usage: *const c_char,
    pub dc_descr: *const c_char,
    pub dc_funcp: Option<mdb_dcmd_f>,
    pub dc_help: Option<unsafe extern "C" fn()>,
    pub dc_tabp: *const c_void,
}

pub type mdb_walk_cb_t =
    unsafe extern "C" fn(addr: usize, data: *const c_void, cbdata: *mut c_void) -> c_int;

#[repr(C)]
pub struct mdb_walk_state_t {
    pub walk_callback: Option<mdb_walk_cb_t>,
    pub walk_cbdata: *mut c_void,
    pub walk_addr: usize,
    pub walk_data: *mut c_void,
    pub walk_arg: *mut c_void,
    pub walk_layer: *const c_void,
}

#[repr(C)]
pub struct mdb_walker_t {
    pub walk_name: *const c_char,
    pub walk_descr: *const c_char,
    pub walk_init: Option<unsafe extern "C" fn(*mut mdb_walk_state_t) -> c_int>,
    pub walk_step: Option<unsafe extern "C" fn(*mut mdb_walk_state_t) -> c_int>,
    pub walk_fini: Option<unsafe extern "C" fn(*mut mdb_walk_state_t)>,
    pub walk_init_arg: *mut c_void,
}

#[repr(C)]
pub struct mdb_modinfo_t {
    pub mi_dvers: u16,
    pub mi_dcmds: *const mdb_dcmd_t,
    pub mi_walkers: *const mdb_walker_t,
}

#[repr(C)]
pub struct mdb_object_t {
    pub obj_name: *const c_char,
    pub obj_fullname: *const c_char,
    pub obj_base: usize,
    pub obj_size: usize,
}

/// `GElf_Sym`, which is `Elf64_Sym`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GElf_Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

#[repr(C)]
pub struct mdb_symbol_t {
    pub sym_name: *const c_char,
    pub sym_object: *const c_char,
    pub sym_sym: *const GElf_Sym,
    pub sym_table: c_uint,
    pub sym_id: c_uint,
}

pub type mdb_object_cb_t = unsafe extern "C" fn(*mut mdb_object_t, *mut c_void) -> c_int;
pub type mdb_symbol_cb_t = unsafe extern "C" fn(*mut mdb_symbol_t, *mut c_void) -> c_int;

/// libproc's `prmap_t` (`<sys/procfs.h>`), 64-bit.
#[repr(C)]
pub struct prmap_t {
    pub pr_vaddr: usize,
    pub pr_size: usize,
    pub pr_mapname: [c_char; 64],
    pub pr_offset: i64,
    pub pr_mflags: c_int,
    pub pr_pagesize: c_int,
    pub pr_shmid: c_int,
    pub pr_filler: [c_int; 1],
}

pub type proc_map_f = unsafe extern "C" fn(*mut c_void, *const prmap_t, *const c_char) -> c_int;

unsafe extern "C" {
    pub fn mdb_printf(fmt: *const c_char, ...);
    pub fn mdb_warn(fmt: *const c_char, ...);
    pub fn mdb_vread(buf: *mut c_void, nbytes: usize, addr: usize) -> isize;
    pub fn mdb_lookup_by_obj(obj: *const c_char, name: *const c_char, sym: *mut GElf_Sym) -> c_int;
    pub fn mdb_lookup_by_addr(
        addr: usize,
        flags: c_uint,
        buf: *mut c_char,
        nbytes: usize,
        sym: *mut GElf_Sym,
    ) -> c_int;
    pub fn mdb_symbol_iter(
        obj: *const c_char,
        which: c_uint,
        ty: c_uint,
        cb: mdb_symbol_cb_t,
        data: *mut c_void,
    ) -> c_int;
    pub fn mdb_object_iter(cb: mdb_object_cb_t, data: *mut c_void) -> c_int;
    pub fn mdb_get_xdata(name: *const c_char, buf: *mut c_void, nbytes: usize) -> isize;
    pub fn mdb_thread_name(tid: usize, buf: *mut c_char, bufsize: usize) -> c_int;

    pub fn Pmapping_iter(p: *mut c_void, func: proc_map_f, cd: *mut c_void) -> c_int;
}

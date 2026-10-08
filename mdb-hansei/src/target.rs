// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! [`MdbTarget`]: a [`proc::Target`] that reads whatever mdb has open —
//! a core file or a live process — through mdb itself.
//!
//! Memory and symbols come through the module API. The rest of what a
//! core reader finds in a core's notes — every lwp's `lwpstatus_t`, the
//! `pstatus_t`, the `psinfo_t` — mdb exports as target data, and it is
//! decoded by the very code that decodes the notes
//! ([`proc::coredump::illumos::procfs`]). The one thing the module API
//! has no call for is the full mapping table, which comes from libproc
//! through the process handle mdb exports beside them.
//!
//! The target is a snapshot of everything but memory, taken when it is
//! built. A live process that runs again is a different target: the
//! module rebuilds this one (`::tokio_attach`) rather than trust it.
//!
//! mdb is single-threaded and hansei is not: a session reads the target
//! from worker threads while the dcmd that asked waits for them. So
//! every call into mdb or libproc is made under one lock, and memory is
//! read in chunks and kept, which serves hansei's many small reads from
//! the chunk cache rather than from mdb, and lets `read_bytes` lend out
//! slices that live as long as the target, which the trait requires.

use crate::ffi::*;

use proc::coredump::illumos::procfs;
use proc::{
    FatalSignal, LoadedObjectWithPath, LwpInfo, MapFlags, Mappings, Regs, SymbolBuf, Target,
};

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ops::Range;
use std::sync::{Mutex, MutexGuard};

/// Serializes every call into mdb and libproc.
static MDB: Mutex<()> = Mutex::new(());

pub(crate) fn mdb_lock() -> MutexGuard<'static, ()> {
    MDB.lock().unwrap_or_else(|p| p.into_inner())
}

const PAGE: u64 = 0x1000;
/// The unit memory is read and kept in.
const CHUNK: u64 = 0x10000;

const STT_FUNC: u8 = 2;
const STT_TLS: u8 = 6;

/// A loaded object as mdb names it.
#[derive(Clone, Debug)]
pub struct Object {
    pub path: String,
    pub base: u64,
}

pub struct MdbTarget {
    memory: Memory,
    objects: Vec<Object>,
    mappings: Mappings,
    /// The mapping table as ranges, sorted, for `readable_len`.
    extents: Vec<Range<u64>>,
    lwps: Vec<LwpInfo>,
    lwp_names: HashMap<u32, String>,
    fatal: Option<FatalSignal>,
    agent: Option<u32>,
    exec_path: Option<String>,
    exec_bias: Option<u64>,
    functions: Vec<SymbolBuf>,
    data: Vec<SymbolBuf>,
}

impl MdbTarget {
    /// Snapshot what mdb has open. Called on mdb's own thread.
    pub fn new() -> anyhow::Result<Self> {
        let objects = loaded_objects();
        let mappings_raw = mappings(&objects)?;
        let mut extents: Vec<Range<u64>> = mappings_raw
            .iter()
            .map(|m| m.vaddr..m.vaddr.saturating_add(m.size))
            .collect();
        extents.sort_by_key(|r| r.start);
        let mut target = MdbTarget {
            memory: Memory::default(),
            exec_path: xdata("psinfo").and_then(|p| procfs::exec_path(&p)),
            mappings: mappings_raw.into_iter().collect(),
            extents,
            lwps: Vec::new(),
            lwp_names: HashMap::new(),
            fatal: None,
            agent: None,
            exec_bias: None,
            functions: exec_symbols(MDB_TYPE_FUNC),
            data: exec_symbols(MDB_TYPE_OBJECT | MDB_TYPE_TLS),
            objects,
        };
        if let Some(pstatus) = xdata("pstatus") {
            target.fatal = procfs::fatal_signal(&pstatus);
            target.agent = procfs::agent_lwp(&pstatus);
        }
        target.lwps = target.read_lwps()?;
        target.lwp_names = target
            .lwps
            .iter()
            .filter_map(|l| thread_name(l.tid).map(|n| (l.tid, n)))
            .collect();
        target.exec_bias = target.compute_exec_bias();
        Ok(target)
    }

    /// The executable mdb is looking at, with where it was loaded: the
    /// object the command line names, or failing that the lowest-loaded
    /// one, which on illumos is always the executable.
    pub fn exec(&self) -> Option<&Object> {
        let named = self.exec_path.as_deref().and_then(|exec| {
            let file = exec.rsplit('/').next().unwrap_or(exec);
            self.objects
                .iter()
                .find(|o| o.path == exec || o.path.rsplit('/').next() == Some(file))
        });
        named.or_else(|| self.objects.iter().min_by_key(|o| o.base))
    }

    fn read_lwps(&self) -> anyhow::Result<Vec<LwpInfo>> {
        let raw = xdata("lwpstatus").ok_or_else(|| {
            anyhow::anyhow!("mdb has no lwp state for this target (is it a process or a core?)")
        })?;
        if raw.len() % procfs::LWPSTATUS_LEN != 0 {
            anyhow::bail!(
                "mdb's lwpstatus data is {} bytes, not a whole number of {}-byte lwpstatus_t",
                raw.len(),
                procfs::LWPSTATUS_LEN
            );
        }
        let mut lwps = Vec::new();
        for desc in raw.chunks_exact(procfs::LWPSTATUS_LEN) {
            let Some((mut lwp, ustack)) = procfs::lwp(desc) else {
                continue;
            };
            // The stack the thread was given, as the core reader takes
            // it; failing that, the mapping holding its stack pointer.
            lwp.stack_range = procfs::stack_range(&|a| self.read_u64(a), ustack)
                .or_else(|| self.extent_at(lwp.regs.rsp).cloned())
                .unwrap_or(0..0);
            lwps.push(lwp);
        }
        lwps.sort_by_key(|l| l.tid);
        Ok(lwps)
    }

    /// How far the executable landed from where it was linked: its
    /// load base less its lowest `PT_LOAD`, read from its own ELF
    /// header, which the first mapping holds.
    fn compute_exec_bias(&self) -> Option<u64> {
        let base = self.exec()?.base;
        let phoff = self.read_u64(base + 0x20).ok()?;
        let header = self.read_bytes(base + 0x36, 4).ok()?;
        let phentsize = u64::from(u16::from_le_bytes([header[0], header[1]]));
        let phnum = u64::from(u16::from_le_bytes([header[2], header[3]]));
        let lowest = (0..phnum)
            .filter_map(|i| {
                let at = base + phoff + i * phentsize;
                let p_type = self.read_u32(at).ok()?;
                (p_type == 1)
                    .then(|| self.read_u64(at + 0x10).ok())
                    .flatten()
            })
            .min()?;
        base.checked_sub(lowest & !(PAGE - 1))
    }

    fn extent_at(&self, addr: u64) -> Option<&Range<u64>> {
        let i = self.extents.partition_point(|r| r.start <= addr);
        self.extents
            .get(i.checked_sub(1)?)
            .filter(|r| r.contains(&addr))
    }
}

impl Target for MdbTarget {
    fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
        self.memory.read(addr, len)
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        let Some(extent) = self.extent_at(addr) else {
            return 0;
        };
        let limit = (extent.end - addr).min(max);
        // Within the mapping, as far as the pages can be read: a core
        // may have mapped a region without dumping all of it.
        let mut n = 0;
        while n < limit {
            let at = addr + n;
            let page_end = (at & !(PAGE - 1)) + PAGE;
            if !self.memory.page_readable(at & !(PAGE - 1)) {
                break;
            }
            n += page_end - at;
        }
        n.min(limit)
    }

    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        let mut buf = vec![0 as c_char; 8192];
        let mut sym = GElf_Sym::default();
        let rc = {
            let _g = mdb_lock();
            unsafe {
                mdb_lookup_by_addr(
                    addr as usize,
                    MDB_SYM_FUZZY,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut sym,
                )
            }
        };
        if rc != 0 {
            return None;
        }
        // The core reader answers from function symbols, and only for
        // an address inside one; mdb's fuzzy match is wider than that.
        let size_ok = addr < sym.st_value.saturating_add(sym.st_size)
            || (sym.st_size == 0 && addr == sym.st_value);
        if sym.st_info & 0xf != STT_FUNC || addr < sym.st_value || !size_ok {
            return None;
        }
        let name = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        Some(symbol_buf(name, &sym))
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        let (object, bare) = match name.split_once('`') {
            Some((object, bare)) => (Some(CString::new(object).ok()?), bare),
            None => (None, name),
        };
        let cname = CString::new(bare).ok()?;
        let mut sym = GElf_Sym::default();
        let rc = {
            let _g = mdb_lock();
            let obj = object.as_ref().map_or(MDB_OBJ_EXEC, |o| o.as_ptr());
            unsafe { mdb_lookup_by_obj(obj, cname.as_ptr(), &mut sym) }
        };
        (rc == 0).then(|| symbol_buf(bare.to_string(), &sym))
    }

    fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
        Ok(self.functions.clone())
    }

    fn object_symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
        Ok(self.data.clone())
    }

    fn fatal_signal(&self) -> Option<FatalSignal> {
        self.fatal.clone()
    }

    fn lwp_name(&self, tid: u32) -> Option<String> {
        self.lwp_names.get(&tid).cloned()
    }

    fn agent_lwp(&self) -> Option<u32> {
        self.agent
    }

    fn exec_path(&self) -> Option<std::path::PathBuf> {
        self.exec_path
            .as_ref()
            .or_else(|| self.exec().map(|o| &o.path))
            .map(Into::into)
    }

    fn mappings(&self) -> proc::Result<Mappings> {
        Ok(self.mappings.clone())
    }

    fn lwps(&self) -> proc::Result<Vec<LwpInfo>> {
        Ok(self.lwps.clone())
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> proc::Result<Option<u64>> {
        // illumos's `thread_local!` is the pthread-key model: the
        // symbol holds a key, the value sits in the thread's fast TSD.
        // A native-TLS symbol only appears when this module is run off
        // illumos, under the test host, which answers for it.
        #[cfg(not(target_os = "illumos"))]
        if sym.st_info & 0xf == STT_TLS {
            return crate::testhost::tls_var_addr(regs, sym);
        }
        proc::tls_addr_from_pthread_key(&|addr| self.read_u64(addr), regs, sym)
    }

    fn exec_bias(&self) -> Option<u64> {
        self.exec_bias
    }
}

fn symbol_buf(name: String, sym: &GElf_Sym) -> SymbolBuf {
    SymbolBuf {
        name,
        st_name: sym.st_name as usize,
        st_info: sym.st_info,
        st_other: sym.st_other,
        st_shndx: sym.st_shndx as usize,
        st_value: sym.st_value,
        st_size: sym.st_size,
    }
}

/// Target data mdb exports by name (`::xdata` lists it).
fn xdata(name: &str) -> Option<Vec<u8>> {
    let cname = CString::new(name).ok()?;
    let _g = mdb_lock();
    let len = unsafe { mdb_get_xdata(cname.as_ptr(), std::ptr::null_mut(), 0) };
    if len <= 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    let got = unsafe { mdb_get_xdata(cname.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if got <= 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(buf)
}

fn thread_name(tid: u32) -> Option<String> {
    let mut buf = [0 as c_char; 64];
    let rc = {
        let _g = mdb_lock();
        unsafe { mdb_thread_name(tid as usize, buf.as_mut_ptr(), buf.len()) }
    };
    if rc != 0 {
        return None;
    }
    let name = unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    (!name.is_empty()).then_some(name)
}

fn loaded_objects() -> Vec<Object> {
    unsafe extern "C" fn cb(obj: *mut mdb_object_t, data: *mut c_void) -> c_int {
        let out = unsafe { &mut *data.cast::<Vec<Object>>() };
        let obj = unsafe { &*obj };
        let path = if obj.obj_fullname.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(obj.obj_fullname) }
                .to_string_lossy()
                .into_owned()
        };
        out.push(Object {
            path,
            base: obj.obj_base as u64,
        });
        0
    }
    let mut out: Vec<Object> = Vec::new();
    let _g = mdb_lock();
    unsafe { mdb_object_iter(cb, (&raw mut out).cast()) };
    out
}

fn exec_symbols(ty: u32) -> Vec<SymbolBuf> {
    unsafe extern "C" fn cb(sym: *mut mdb_symbol_t, data: *mut c_void) -> c_int {
        let out = unsafe { &mut *data.cast::<Vec<SymbolBuf>>() };
        let sym = unsafe { &*sym };
        if sym.sym_name.is_null() || sym.sym_sym.is_null() {
            return 0;
        }
        let name = unsafe { CStr::from_ptr(sym.sym_name) }
            .to_string_lossy()
            .into_owned();
        if !name.is_empty() {
            out.push(symbol_buf(name, unsafe { &*sym.sym_sym }));
        }
        0
    }
    let mut out: Vec<SymbolBuf> = Vec::new();
    {
        let _g = mdb_lock();
        unsafe {
            mdb_symbol_iter(
                MDB_OBJ_EXEC,
                MDB_SYMTAB,
                MDB_BIND_ANY | ty,
                cb,
                (&raw mut out).cast(),
            )
        };
    }
    out.sort_by_key(|s| (s.st_value, s.name.clone()));
    out.dedup_by(|a, b| a.name == b.name && a.st_value == b.st_value);
    out
}

/// Every mapping, from libproc, each named by the object that covers
/// it as the core reader names them: the flags are the kernel's, kept
/// to the ones the core reader records.
fn mappings(objects: &[Object]) -> anyhow::Result<Vec<LoadedObjectWithPath>> {
    unsafe extern "C" fn cb(
        data: *mut c_void,
        map: *const prmap_t,
        object: *const c_char,
    ) -> c_int {
        let out = unsafe { &mut *data.cast::<Vec<(prmap_snapshot, Option<String>)>>() };
        let map = unsafe { &*map };
        let name = (!object.is_null())
            .then(|| {
                unsafe { CStr::from_ptr(object) }
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|n| !n.is_empty());
        out.push((
            prmap_snapshot {
                vaddr: map.pr_vaddr as u64,
                size: map.pr_size as u64,
                mflags: map.pr_mflags as u32,
            },
            name,
        ));
        0
    }

    let handle = xdata("pshandle")
        .ok_or_else(|| anyhow::anyhow!("mdb has no process handle for this target"))?;
    let handle = usize::from_ne_bytes(handle.as_slice().try_into()?) as *mut c_void;
    let mut raw: Vec<(prmap_snapshot, Option<String>)> = Vec::new();
    let rc = {
        let _g = mdb_lock();
        unsafe { Pmapping_iter(handle, cb, (&raw mut raw).cast()) }
    };
    if rc != 0 {
        anyhow::bail!("libproc could not iterate the target's mappings");
    }

    // MA_READ | MA_WRITE | MA_EXEC, MA_BREAK, MA_ANON: what the core
    // reader records.
    const KEPT: u32 = 0x07 | 0x10 | 0x40;
    let resolve = |name: Option<String>| {
        // libproc names an object by the link map's spelling; mdb's
        // object list has the same objects with their full paths.
        let name = name?;
        Some(
            objects
                .iter()
                .find(|o| o.path == name || o.path.rsplit('/').next() == Some(name.as_str()))
                .map_or(name, |o| o.path.clone()),
        )
    };
    Ok(raw
        .into_iter()
        .map(|(m, name)| {
            let path = resolve(name);
            let mut flags = m.mflags & KEPT;
            if path.is_none() {
                flags |= 0x40;
            }
            LoadedObjectWithPath {
                path,
                vaddr: m.vaddr,
                size: m.size,
                flags: MapFlags(flags),
            }
        })
        .collect())
}

#[allow(non_camel_case_types)]
struct prmap_snapshot {
    vaddr: u64,
    size: u64,
    mflags: u32,
}

/// Target memory, read through mdb a chunk at a time and kept.
///
/// Whatever is read once stays, at a fixed address in the heap, until
/// the target is dropped: that is what lets [`Target::read_bytes`] lend
/// a slice for as long as the target lives. A chunk that cannot be read
/// whole (the end of a mapping, an undumped page) falls back to its
/// pages, and a read that straddles a boundary is read on its own.
#[derive(Default)]
struct Memory {
    inner: Mutex<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    /// Chunk base -> its bytes, or `None` when it could not be read whole.
    chunks: HashMap<u64, Option<Box<[u8]>>>,
    /// Page base -> its bytes, or `None` when unreadable.
    pages: HashMap<u64, Option<Box<[u8]>>>,
    /// Reads that fit no single chunk or page.
    spans: Vec<Box<[u8]>>,
}

impl Memory {
    fn read(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
        if len == 0 {
            return Ok(&[]);
        }
        let end = addr
            .checked_add(len)
            .ok_or_else(|| proc::Error::unmapped(addr, len))?;
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());

        let chunk = addr & !(CHUNK - 1);
        if end <= chunk + CHUNK {
            if let Some(bytes) = m.chunk(chunk) {
                let off = (addr - chunk) as usize;
                return Ok(lend(&bytes[off..off + len as usize]));
            }
            let page = addr & !(PAGE - 1);
            if end <= page + PAGE {
                return match m.page(page) {
                    Some(bytes) => {
                        let off = (addr - page) as usize;
                        Ok(lend(&bytes[off..off + len as usize]))
                    }
                    None => Err(proc::Error::unmapped(addr, len)),
                };
            }
        }
        // Too long, or across a boundary: read exactly what was asked.
        let mut buf = vec![0u8; len as usize].into_boxed_slice();
        if !vread(&mut buf, addr) {
            return Err(proc::Error::unmapped(addr, len));
        }
        let out = lend(&buf);
        m.spans.push(buf);
        Ok(out)
    }

    fn page_readable(&self, page: u64) -> bool {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        m.chunk(page & !(CHUNK - 1)).is_some() || m.page(page).is_some()
    }
}

impl MemoryInner {
    fn chunk(&mut self, base: u64) -> Option<&[u8]> {
        self.chunks
            .entry(base)
            .or_insert_with(|| {
                let mut buf = vec![0u8; CHUNK as usize].into_boxed_slice();
                vread(&mut buf, base).then_some(buf)
            })
            .as_deref()
    }

    fn page(&mut self, base: u64) -> Option<&[u8]> {
        self.pages
            .entry(base)
            .or_insert_with(|| {
                let mut buf = vec![0u8; PAGE as usize].into_boxed_slice();
                vread(&mut buf, base).then_some(buf)
            })
            .as_deref()
    }
}

/// Extend a borrow of kept memory to the target's lifetime.
///
/// Sound because nothing is ever removed from [`MemoryInner`] or
/// written again once read: each `Box<[u8]>` keeps its heap address for
/// as long as the `Memory` that owns it, whatever the maps around it do.
fn lend<'a>(bytes: &[u8]) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(bytes.as_ptr(), bytes.len()) }
}

fn vread(buf: &mut [u8], addr: u64) -> bool {
    let _g = mdb_lock();
    let n = unsafe { mdb_vread(buf.as_mut_ptr().cast(), buf.len(), addr as usize) };
    n == buf.len() as isize
}

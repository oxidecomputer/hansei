//! The libproc-backed [`Proc`] target: a live process or core dump,
//! read through `Pgrab`/`Pgrab_core`. illumos-only; everything else in
//! this crate is platform-independent.

use crate::{
    Error, LoadedObject, LoadedObjectWithPath, LwpInfo, MapFlags, Mappings, Regs, Result, Status,
    SymbolBuf, Target, Timespec,
};

use libproc_sys::{
    BIND_GLOBAL, BIND_LOCAL, GElf_Sym, Lfree, Lgrab, Lgrab_error, Lstatus, MAXPATHLEN,
    PGRAB_NOSTOP, PGRAB_RDONLY, PGRAB_RETAIN, PR_SYMTAB, PRELEASE_CLEAR, Paddr_to_map, Pexecname,
    Pgrab, Pgrab_core, Pgrab_error, Plookup_by_addr, Plookup_by_name, Plwp_getname, Plwp_getregs,
    Plwp_iter, Plwp_main_stack, Pmapping_iter_resolved, Pread, Prelease, Psetrun, Pstatus, Pstop,
    Psymbol_iter, REG_CS, REG_DS, REG_ERR, REG_ES, REG_FS, REG_FSBASE, REG_GS, REG_GSBASE, REG_R8,
    REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_RAX, REG_RBP, REG_RBX,
    REG_RCX, REG_RDI, REG_RDX, REG_RFL, REG_RIP, REG_RSI, REG_RSP, REG_SS, REG_TRAPNO, TYPE_FUNC,
    TYPE_OBJECT, gregset_t, lwpstatus_t, pid_t, prmap_t, ps_lwphandle, ps_prochandle, stack_t,
};

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_void};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::sync::Mutex;

#[derive(Debug)]
pub struct Proc {
    handle: NonNull<ps_prochandle>,
    /// Serializes every libproc call. A `ps_prochandle` caches state
    /// across calls and is not thread-safe, but it has no thread
    /// affinity, so exclusive access is all its safety needs.
    libproc: Mutex<()>,
}

// SAFETY: the raw handle is only ever dereferenced by libproc, and
// every libproc call runs under the `libproc` mutex; between calls the
// handle is just an address.
unsafe impl Send for Proc {}
unsafe impl Sync for Proc {}

impl From<gregset_t> for Regs {
    fn from(regs: gregset_t) -> Self {
        Regs {
            r15: regs[REG_R15 as usize] as u64,
            r14: regs[REG_R14 as usize] as u64,
            r13: regs[REG_R13 as usize] as u64,
            r12: regs[REG_R12 as usize] as u64,
            r11: regs[REG_R11 as usize] as u64,
            r10: regs[REG_R10 as usize] as u64,
            r9: regs[REG_R9 as usize] as u64,
            r8: regs[REG_R8 as usize] as u64,
            rdi: regs[REG_RDI as usize] as u64,
            rsi: regs[REG_RSI as usize] as u64,
            rbp: regs[REG_RBP as usize] as u64,
            rbx: regs[REG_RBX as usize] as u64,
            rdx: regs[REG_RDX as usize] as u64,
            rcx: regs[REG_RCX as usize] as u64,
            rax: regs[REG_RAX as usize] as u64,
            trapno: regs[REG_TRAPNO as usize] as u64,
            err: regs[REG_ERR as usize] as u64,
            rip: regs[REG_RIP as usize] as u64,
            cs: regs[REG_CS as usize] as u64,
            rfl: regs[REG_RFL as usize] as u64,
            rsp: regs[REG_RSP as usize] as u64,
            ss: regs[REG_SS as usize] as u64,
            fs: regs[REG_FS as usize] as u64,
            gs: regs[REG_GS as usize] as u64,
            es: regs[REG_ES as usize] as u64,
            ds: regs[REG_DS as usize] as u64,
            fsbase: regs[REG_FSBASE as usize] as u64,
            gsbase: regs[REG_GSBASE as usize] as u64,
        }
    }
}

impl Proc {
    pub fn grab_pid(pid: u32) -> Result<Self> {
        // Pass empty flags so the process is stopped and any existing flags are
        // cleared.
        let flags = 0;
        Self::open_proc(pid, flags)
    }

    pub fn grab_pid_no_stop(pid: u32) -> Result<Self> {
        // Don't stop the process and retain existing flags to avoid setting
        // PR_KLC, so the process resumes execution even if we die.
        let flags = (PGRAB_NOSTOP | PGRAB_RETAIN) as i32;
        Self::open_proc(pid, flags)
    }

    fn open_proc(pid: u32, flags: i32) -> Result<Self> {
        let mut perr: c_int = 0;

        let handle = unsafe { Pgrab(pid as pid_t, flags, &mut perr) };
        let Some(handle) = NonNull::new(handle) else {
            let err_msg = unsafe { Pgrab_error(perr) };

            // SAFETY: The implementation of Pgrab_error returns a static string.
            let c_msg = unsafe { CStr::from_ptr(err_msg) };

            // UNWRAP: We know all possible values returned by Pgrab_error are valid UTF-8.
            let msg = c_msg.to_str().unwrap();

            return Err(Error::grab_failed(msg));
        };
        Ok(Proc {
            handle,
            libproc: Mutex::new(()),
        })
    }

    pub fn open_core(core_path: &Path) -> Result<Self> {
        let c_core_path =
            CString::new(core_path.as_os_str().as_bytes()).map_err(Error::bad_path)?;
        let mut perr: c_int = 0;
        let flags = PGRAB_RDONLY as c_int;

        let handle = unsafe { Pgrab_core(c_core_path.as_ptr(), ptr::null(), flags, &mut perr) };
        let Some(handle) = NonNull::new(handle) else {
            let err_msg = unsafe { Pgrab_error(perr) };

            // SAFETY: The implementation of Pgrab_error returns a static string.
            let c_msg = unsafe { CStr::from_ptr(err_msg) };

            // UNWRAP: We know all possible values returned by Pgrab_error are valid UTF-8.
            let msg = c_msg.to_str().unwrap();

            return Err(Error::grab_failed(msg));
        };
        Ok(Proc {
            handle,
            libproc: Mutex::new(()),
        })
    }

    pub fn status(&self) -> Status {
        let _libproc = self.libproc.lock().unwrap();
        let status = unsafe { Pstatus(self.handle.as_ptr()) };

        let status = match unsafe { status.as_ref() } {
            Some(s) => s,
            None => {
                // Pstatus(3proc) is documented as always returning a valid pointer.
                panic!("Pstatus returned null ptr");
            }
        };
        let brk_start = status.pr_brkbase as u64;
        let brk_end = brk_start + status.pr_brksize as u64;

        let stack_start = status.pr_stkbase as u64;
        let stack_end = stack_start + status.pr_stksize as u64;

        Status {
            active_lwp: status.pr_lwp.pr_lwpid as u32,
            brk_range: brk_start..brk_end,
            stack_range: stack_start..stack_end,
        }
    }

    pub fn run(&self) -> Result<()> {
        let _libproc = self.libproc.lock().unwrap();
        // Don't set any signals or flags.
        let ret = unsafe { Psetrun(self.handle.as_ptr(), 0, 0) };
        if ret != 0 {
            return Err(Error::start(ret));
        }

        Ok(())
    }

    pub fn stop(&self, wait_ms: u32) -> Result<()> {
        let _libproc = self.libproc.lock().unwrap();
        let ret = unsafe { Pstop(self.handle.as_ptr(), wait_ms) };
        if ret != 0 {
            return Err(Error::stop(ret));
        }

        Ok(())
    }

    pub fn exec_name(&self) -> Result<PathBuf> {
        let _libproc = self.libproc.lock().unwrap();
        let mut buf = vec![0u8; MAXPATHLEN as usize];

        let ret = unsafe {
            Pexecname(
                self.handle.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
            )
        };

        if !ret.is_null() {
            let c_path = CStr::from_bytes_until_nul(&buf).map_err(Error::no_nul)?;
            let os_path = OsStr::from_bytes(c_path.to_bytes());
            let path = Path::new(os_path);
            Ok(path.to_owned())
        } else {
            Err(Error::no_exec_name())
        }
    }

    pub fn lwps(&self) -> Result<Vec<LwpInfo>> {
        let _libproc = self.libproc.lock().unwrap();
        mod callback {
            use super::*;

            pub(super) struct LwpCbData {
                pub handle: *mut ps_prochandle,
                pub data: Vec<LwpInfo>,
            }

            pub extern "C" fn lwp_callback(data: *mut c_void, status: *const lwpstatus_t) -> c_int {
                unsafe {
                    let cb_data = &mut *(data as *mut LwpCbData);
                    let Some(status) = status.as_ref() else {
                        return 0;
                    };

                    let mut stack = MaybeUninit::<stack_t>::uninit();
                    let ret =
                        Plwp_main_stack(cb_data.handle, status.pr_lwpid as u32, stack.as_mut_ptr());
                    if ret != 0 {
                        // skip
                        return 0;
                    }

                    let regs = status.pr_reg.into();

                    let stack = stack.assume_init();
                    let stack_start = stack.ss_sp as u64;
                    let stack_end = stack_start + stack.ss_size as u64;

                    let tstamp = Timespec {
                        tv_sec: status.pr_tstamp.tv_sec,
                        tv_nsec: status.pr_tstamp.tv_nsec,
                    };

                    cb_data.data.push(LwpInfo {
                        tid: status.pr_lwpid as u32,
                        regs,
                        stack_range: stack_start..stack_end,
                        tstamp,
                    });
                }

                0 // Continue iteration
            }
        }

        let mut cb_data = callback::LwpCbData {
            handle: self.handle.as_ptr(),
            data: Vec::new(),
        };
        let ret = unsafe {
            Plwp_iter(
                self.handle.as_ptr(),
                Some(callback::lwp_callback),
                &mut cb_data as *mut _ as *mut c_void,
            )
        };
        if ret != 0 {
            return Err(Error::lwp_iter_failed());
        }

        Ok(cb_data.data)
    }

    pub fn lwp_handle(&self, lwpid: u32) -> Result<Lwp> {
        let _libproc = self.libproc.lock().unwrap();
        let mut perr: c_int = 0;

        // SAFETY: Our handle is valid.
        let handle = unsafe { Lgrab(self.handle.as_ptr(), lwpid, &mut perr) };
        let Some(handle) = NonNull::new(handle) else {
            // SAFETY: Can't really mess this one up.
            let err_msg = unsafe { Lgrab_error(perr) };

            // SAFETY: The implementation of Lgrab_error returns a static string.
            let c_msg = unsafe { CStr::from_ptr(err_msg) };

            // UNWRAP: We know all possible values returned by Pgrab_error are valid UTF-8.
            let msg = c_msg.to_str().unwrap();

            return Err(Error::lgrab_failed(msg));
        };
        Ok(Lwp { handle })
    }

    pub fn lwp_name(&self, lwpid: u32) -> Result<String> {
        let _libproc = self.libproc.lock().unwrap();
        // This length includes the trailing NUL.
        const THREAD_NAME_MAX: usize = 32;
        let mut buf = [0; THREAD_NAME_MAX];

        // SAFETY: Our handle and buf ptr are valid.
        let ret = unsafe {
            Plwp_getname(
                self.handle.as_ptr(),
                lwpid,
                buf.as_mut_ptr(),
                THREAD_NAME_MAX,
            )
        };
        if ret != 0 {
            return Err(Error::no_lwp_name());
        }

        // SAFETY: We know buf has a valid address and we have passed the correct
        // buffer length to `Plwp_getname`.
        let c_msg = unsafe { CStr::from_ptr(buf.as_ptr()) };
        let name = c_msg.to_string_lossy().to_string();

        Ok(name)
    }

    pub fn pread(&self, buf: &mut [u8], address: u64) -> Result<u64> {
        let _libproc = self.libproc.lock().unwrap();
        let ct = unsafe {
            Pread(
                self.handle.as_ptr(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                address as usize,
            )
        };
        if ct >= 0 {
            Ok(ct as u64)
        } else {
            Err(Error::read(io::Error::last_os_error()))
        }
    }

    pub fn pread_exact(&self, buf: &mut [u8], address: u64) -> Result<()> {
        if self.pread(buf, address)? != buf.len() as u64 {
            return Err(Error::unexpected_eof());
        }

        Ok(())
    }

    pub fn read_u64(&self, address: u64) -> Result<u64> {
        let mut buf = [0u8; size_of::<u64>()];
        self.pread_exact(&mut buf, address)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn read_u32(&self, address: u64) -> Result<u32> {
        let mut buf = [0u8; size_of::<u32>()];
        self.pread_exact(&mut buf, address)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_u16(&self, address: u64) -> Result<u16> {
        let mut buf = [0u8; size_of::<u16>()];
        self.pread_exact(&mut buf, address)?;
        Ok(u16::from_le_bytes(buf))
    }

    pub fn read_u8(&self, address: u64) -> Result<u8> {
        let mut val = [0u8];
        self.pread_exact(&mut val, address)?;
        Ok(val[0])
    }

    pub fn regs(&self, lwp: u32) -> Result<Regs> {
        let _libproc = self.libproc.lock().unwrap();
        let mut regs: gregset_t = [0; 28];
        let ret = unsafe { Plwp_getregs(self.handle.as_ptr(), lwp, regs.as_mut_ptr()) };
        if ret == 0 {
            Ok(Regs::from(regs))
        } else {
            Err(Error::read(io::Error::from_raw_os_error(ret)))
        }
    }

    /// Get the values of a LWP's `ul_ftsd` field from its `ulwp_t`. This
    /// contains the thread-local storage (TLS) for the LWP, also known as
    /// thread-specific data (TSD).
    pub fn lwp_tsd(&self, lwp: u32) -> Result<[u64; 9]> {
        let regs = self.regs(lwp)?;
        self.tsd_from_regs(&regs)
    }

    /// Use the provided register set to find the values of a LWP's `ul_ftsd`
    /// field from its `ulwp_t`. This contains the thread-local storage (TLS)
    /// for the LWP, also known as thread-specific data (TSD).
    pub fn tsd_from_regs(&self, regs: &Regs) -> Result<[u64; 9]> {
        crate::tsd_from_fsbase(self, regs)
    }

    pub fn mappings(&self) -> Result<Mappings> {
        let _libproc = self.libproc.lock().unwrap();
        mod callback {
            use super::*;
            pub extern "C" fn object_callback(
                data: *mut c_void,
                map: *const prmap_t,
                name: *const c_char,
            ) -> c_int {
                // SAFETY: We've passed in a valid pointer.
                let objs = unsafe { &mut *(data as *mut Vec<_>) };

                // SAFETY: libproc guarantees that this pointer is valid.
                let map_ref = unsafe { &*map };

                let path = if !name.is_null() {
                    // SAFETY: We just verified the pointer is not null.
                    let s = unsafe { CStr::from_ptr(name) };
                    Some(s.to_string_lossy().to_string())
                } else {
                    None
                };

                objs.push(LoadedObjectWithPath {
                    path,
                    vaddr: map_ref.pr_vaddr as u64,
                    size: map_ref.pr_size as u64,
                    flags: MapFlags(map_ref.pr_mflags as u32),
                });

                0 // Continue iteration
            }
        }

        let mut objs = Vec::new();
        let ret = unsafe {
            Pmapping_iter_resolved(
                self.handle.as_ptr(),
                Some(callback::object_callback),
                &mut objs as *mut _ as *mut c_void,
            )
        };
        objs.sort_unstable();
        if ret == 0 {
            Ok(Mappings { inner: objs })
        } else {
            Err(Error::map_iter_failed())
        }
    }

    pub fn addr_to_map(&self, address: u64) -> Option<LoadedObject> {
        let _libproc = self.libproc.lock().unwrap();
        let prmap_ptr = unsafe { Paddr_to_map(self.handle.as_ptr(), address as usize) };

        let prmap = unsafe { prmap_ptr.as_ref() }?;

        Some(LoadedObject {
            vaddr: prmap.pr_vaddr as u64,
            size: prmap.pr_size as u64,
            flags: MapFlags(prmap.pr_mflags as u32),
        })
    }

    pub fn addr_is_mapped(&self, addr: u64) -> bool {
        self.addr_to_map(addr).is_some()
    }

    fn symbols_with_mask(&self, type_mask: u32) -> Result<Vec<SymbolBuf>> {
        let _libproc = self.libproc.lock().unwrap();
        mod callback {
            use super::*;

            pub extern "C" fn symbol_callback(
                data: *mut c_void,
                sym: *const GElf_Sym,
                name: *const c_char,
            ) -> c_int {
                // SAFETY: We've passed in a valid pointer.
                let symbols = unsafe { &mut *(data as *mut Vec<_>) };

                // SAFETY: libproc guarantees this will be a GElf_Sym*.
                let Some(sym) = (unsafe { sym.as_ref() }) else {
                    return 0;
                };

                // Something has gone wrong if this is invalid, but we'll
                // continue iteration in case later symbols work.
                if name.is_null() {
                    return 0;
                }

                // SAFETY: We just confirmed this is non-null.
                let c_str = unsafe { CStr::from_ptr(name) };

                // Just bail out if the name is malformed, again continuing
                // iteration.
                let Ok(name_str) = c_str.to_str() else {
                    return 0;
                };

                // We could pretty safely assume the name pointer would remain
                // valid for the lifetime of the handle with a core dump,
                // but this is not the case with a live process. Copy out
                // the name. If we find that these copies have a measurable
                // impact, we could consider a separate, non-copying variant
                // just for cores.
                let name = name_str.to_string();

                symbols.push(SymbolBuf {
                    name,
                    st_name: sym.st_name as usize,
                    st_info: sym.st_info,
                    st_other: sym.st_other,
                    st_shndx: sym.st_shndx as usize,
                    st_value: sym.st_value,
                    st_size: sym.st_size,
                });

                0 // Continue iteration
            }
        }

        // Search the executable only; callers select functions or objects.
        const PR_OBJ_EXEC: *const c_char = ptr::null();
        let fmask = type_mask | BIND_GLOBAL | BIND_LOCAL;

        let mut symbols = Vec::new();
        let ret = unsafe {
            Psymbol_iter(
                self.handle.as_ptr(),
                PR_OBJ_EXEC,
                PR_SYMTAB as i32,
                fmask as i32,
                Some(callback::symbol_callback),
                &mut symbols as *mut _ as *mut c_void,
            )
        };

        if ret == 0 {
            Ok(symbols)
        } else {
            Err(Error::symbol_iter_failed())
        }
    }

    pub fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        self.symbols_with_mask(TYPE_FUNC)
    }

    pub fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        self.symbols_with_mask(TYPE_OBJECT)
    }

    pub fn lookup_symbol_by_addr(&self, address: u64) -> Option<SymbolBuf> {
        let _libproc = self.libproc.lock().unwrap();
        let mut buf = vec![0u8; 4096];
        let mut sym = MaybeUninit::<GElf_Sym>::uninit();

        let ret = unsafe {
            Plookup_by_addr(
                self.handle.as_ptr(),
                address as usize,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                sym.as_mut_ptr(),
            )
        };
        if ret != 0 {
            return None;
        }

        let sym = unsafe { sym.assume_init() };
        let Ok(c_name) = CStr::from_bytes_until_nul(&buf) else {
            return None;
        };

        let name = c_name.to_string_lossy().to_string();

        Some(SymbolBuf {
            name,
            st_name: sym.st_name as usize,
            st_info: sym.st_info,
            st_other: sym.st_other,
            st_shndx: sym.st_shndx as usize,
            st_value: sym.st_value,
            st_size: sym.st_size,
        })
    }

    pub fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        let _libproc = self.libproc.lock().unwrap();
        const PR_OBJ_EXEC: *const c_char = ptr::null();

        let Ok(c_name) = CString::new(name) else {
            return None;
        };

        let mut sym = MaybeUninit::<GElf_Sym>::uninit();

        let ret = unsafe {
            Plookup_by_name(
                self.handle.as_ptr(),
                PR_OBJ_EXEC,
                c_name.as_ptr(),
                sym.as_mut_ptr(),
            )
        };
        if ret != 0 {
            return None;
        }

        let sym = unsafe { sym.assume_init() };

        Some(SymbolBuf {
            name: name.to_string(),
            st_name: sym.st_name as usize,
            st_info: sym.st_info,
            st_other: sym.st_other,
            st_shndx: sym.st_shndx as usize,
            st_value: sym.st_value,
            st_size: sym.st_size,
        })
    }

    pub fn lookup_symbol_name_by_addr(&self, address: u64) -> Option<String> {
        let sym = self.lookup_symbol_by_addr(address)?;

        Some(sym.name)
    }
}

impl Target for Proc {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        // `len` may itself have been read out of the target, and a live
        // process declines to bound it (see [`Target::readable_len`]) — so
        // allocate as the bytes arrive rather than sizing a buffer by an
        // unverified claim, and a garbage length fails at the first
        // unreadable page instead of allocating what it named.
        const CHUNK: u64 = 4 * 1024 * 1024;
        let mut buf = Vec::new();
        while (buf.len() as u64) < len {
            let step = CHUNK.min(len - buf.len() as u64) as usize;
            let start = buf.len();
            buf.resize(start + step, 0);
            let got = self.pread(&mut buf[start..], addr + start as u64)?;
            if got < step as u64 {
                return Err(Error::unexpected_eof());
            }
        }
        Ok(buf)
    }

    fn lookup_symbol_by_addr(&self, address: u64) -> Option<SymbolBuf> {
        Proc::lookup_symbol_by_addr(self, address)
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
        crate::tls_addr_from_pthread_key(self, regs, sym)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        // Clear any flags, let the process resume execution.
        let flags = PRELEASE_CLEAR as i32;
        unsafe { Prelease(self.handle.as_mut(), flags) };
    }
}

pub struct Lwp {
    handle: NonNull<ps_lwphandle>,
}

impl Lwp {
    pub fn status(&self) -> Timespec {
        // SAFETY: Our lwp handle is valid.
        let ret = unsafe { Lstatus(self.handle.as_ptr()) };

        // SAFETY: libproc guarantees that the pointer returned is valid.
        match unsafe { ret.as_ref() } {
            Some(status) => Timespec {
                tv_sec: status.pr_tstamp.tv_sec,
                tv_nsec: status.pr_tstamp.tv_nsec,
            },
            None => unreachable!("Lstatus returned null"),
        }
    }
}

impl Drop for Lwp {
    fn drop(&mut self) {
        // SAFETY: Our lwp handle is valid.
        unsafe { Lfree(self.handle.as_mut()) };
    }
}

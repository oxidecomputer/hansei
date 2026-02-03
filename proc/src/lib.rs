use libproc_sys::{
    GElf_Sym, MAXPATHLEN, Plookup_by_addr, gregset_t, lwpstatus_t, prmap_t, ps_prochandle, stack_t,
};

use std::ffi::{CStr, CString, FromBytesUntilNulError, NulError, OsStr, c_char, c_int, c_void};
use std::fmt;
use std::io;
use std::mem::{self, MaybeUninit};
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};

type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not convert path to C string")]
    BadPath(#[from] NulError),
    #[error("failed to open core: {0}")]
    GrabFailed(&'static str),
    #[error("failed to iterate over lwps")]
    LwpIterFailed,
    #[error("failed to iterate over mappings")]
    MapIterFailed,
    #[error("failed to get exec name")]
    NoExecName,
    #[error("no nul byte in C string")]
    NoNul(#[from] FromBytesUntilNulError),
    #[error("error: {0}")] // TODO better message
    Read(#[from] io::Error), // TODO fix name
    #[error("failed to iterate over symbols")]
    SymbolIterFailed,
    #[error("failed to fill whole buffer")]
    UnexpectedEof,
}

#[derive(Debug)]
pub struct Core {
    handle: NonNull<ps_prochandle>,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Reg(pub u16);

impl Reg {
    pub fn is_callee_saved(&self) -> bool {
        match self.0 {
            3 => true,       // rbx
            6 => true,       // rbp
            12..=15 => true, // r12, r13, r14, r15
            _ => false,
        }
    }
}
pub mod x86_64 {
    use super::Reg;

    pub const REGS: [Reg; 16] = [
        RAX, RDX, RCX, RBX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15,
    ];

    pub const RAX: Reg = Reg(0);
    pub const RDX: Reg = Reg(1);
    pub const RCX: Reg = Reg(2);
    pub const RBX: Reg = Reg(3);
    pub const RSI: Reg = Reg(4);
    pub const RDI: Reg = Reg(5);
    pub const RBP: Reg = Reg(6);
    pub const RSP: Reg = Reg(7);
    pub const R8: Reg = Reg(8);
    pub const R9: Reg = Reg(9);
    pub const R10: Reg = Reg(10);
    pub const R11: Reg = Reg(11);
    pub const R12: Reg = Reg(12);
    pub const R13: Reg = Reg(13);
    pub const R14: Reg = Reg(14);
    pub const R15: Reg = Reg(15);
    pub const RIP: Reg = Reg(16);
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Reg(0) => "rax",
            Reg(1) => "rdx",
            Reg(2) => "rcx",
            Reg(3) => "rbx",
            Reg(4) => "rsi",
            Reg(5) => "rdi",
            Reg(6) => "rbp",
            Reg(7) => "rsp",
            Reg(8) => "r8",
            Reg(9) => "r9",
            Reg(10) => "r10",
            Reg(11) => "r11",
            Reg(12) => "r12",
            Reg(13) => "r13",
            Reg(14) => "r14",
            Reg(15) => "r15",
            Reg(16) => "rip",
            _ => "<unknown_register>",
        };
        write!(f, "{name}")
    }
}

impl From<gimli::Register> for Reg {
    fn from(reg: gimli::Register) -> Self {
        Reg(reg.0)
    }
}

impl From<Reg> for gimli::Register {
    fn from(reg: Reg) -> Self {
        gimli::Register(reg.0)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Regs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub trapno: u64,
    pub err: u64,
    pub rip: u64,
    pub cs: u64,
    pub rfl: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs: u64,
    pub gs: u64,
    pub es: u64,
    pub ds: u64,
    pub fsbase: u64,
    pub gsbase: u64,
}

impl Regs {
    pub fn is_callee_saved(reg: Reg) -> bool {
        match reg.0 {
            3 => true,       // rbx
            6 => true,       // rbp
            12..=15 => true, // r12, r13, r14, r15
            _ => false,
        }
    }
}

impl fmt::Display for Regs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "%rax = {:#018x}\t%r8  = {:#018x}", self.rax, self.r8)?;
        writeln!(f, "%rbx = {:#018x}\t%r9  = {:#018x}", self.rbx, self.r9)?;
        writeln!(f, "%rcx = {:#018x}\t%r10 = {:#018x}", self.rcx, self.r10)?;
        writeln!(f, "%rdx = {:#018x}\t%r11 = {:#018x}", self.rdx, self.r11)?;
        writeln!(f, "%rsi = {:#018x}\t%r12 = {:#018x}", self.rsi, self.r12)?;
        writeln!(f, "%rdi = {:#018x}\t%r13 = {:#018x}", self.rdi, self.r13)?;
        writeln!(f, "{:<25}\t%r14 = {:#018x}", " ", self.r14)?;
        writeln!(f, "{:<25}\t%r15 = {:#018x}\n", " ", self.r15)?;

        writeln!(f, "%rip = {:#018x}", self.rip)?;
        writeln!(f, "%rbp = {:#018x}", self.rbp)?;
        write!(f, "%rsp = {:#018x}", self.rsp)?;
        Ok(())
    }
}

impl std::ops::Index<Reg> for Regs {
    type Output = u64;

    fn index(&self, index: Reg) -> &Self::Output {
        match index.0 {
            0 => &self.rax,
            1 => &self.rdx,
            2 => &self.rcx,
            3 => &self.rbx,
            4 => &self.rsi,
            5 => &self.rdi,
            6 => &self.rbp,
            7 => &self.rsp,
            8 => &self.r8,
            9 => &self.r9,
            10 => &self.r10,
            11 => &self.r11,
            12 => &self.r12,
            13 => &self.r13,
            14 => &self.r14,
            15 => &self.r15,
            _ => unreachable!(), // TODO
        }
    }
}

impl std::ops::IndexMut<Reg> for Regs {
    fn index_mut(&mut self, reg: Reg) -> &mut Self::Output {
        match reg.0 {
            0 => &mut self.rax,
            1 => &mut self.rdx,
            2 => &mut self.rcx,
            3 => &mut self.rbx,
            4 => &mut self.rsi,
            5 => &mut self.rdi,
            6 => &mut self.rbp,
            7 => &mut self.rsp,
            8 => &mut self.r8,
            9 => &mut self.r9,
            10 => &mut self.r10,
            11 => &mut self.r11,
            12 => &mut self.r12,
            13 => &mut self.r13,
            14 => &mut self.r14,
            15 => &mut self.r15,
            _ => unreachable!(), // TODO
        }
    }
}

impl fmt::Debug for Regs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Regs")
            .field("r15", &format_args!("{:#x}", self.r15))
            .field("r14", &format_args!("{:#x}", self.r14))
            .field("r13", &format_args!("{:#x}", self.r13))
            .field("r12", &format_args!("{:#x}", self.r12))
            .field("r11", &format_args!("{:#x}", self.r11))
            .field("r10", &format_args!("{:#x}", self.r10))
            .field("r9", &format_args!("{:#x}", self.r9))
            .field("r8", &format_args!("{:#x}", self.r8))
            .field("rdi", &format_args!("{:#x}", self.rdi))
            .field("rsi", &format_args!("{:#x}", self.rsi))
            .field("rbp", &format_args!("{:#x}", self.rbp))
            .field("rbx", &format_args!("{:#x}", self.rbx))
            .field("rdx", &format_args!("{:#x}", self.rdx))
            .field("rcx", &format_args!("{:#x}", self.rcx))
            .field("rax", &format_args!("{:#x}", self.rax))
            .field("trapno", &format_args!("{:#x}", self.trapno))
            .field("err", &format_args!("{:#x}", self.err))
            .field("rip", &format_args!("{:#x}", self.rip))
            .field("cs", &format_args!("{:#x}", self.cs))
            .field("rfl", &format_args!("{:#x}", self.rfl))
            .field("rsp", &format_args!("{:#x}", self.rsp))
            .field("ss", &format_args!("{:#x}", self.ss))
            .field("fs", &format_args!("{:#x}", self.fs))
            .field("gs", &format_args!("{:#x}", self.gs))
            .field("es", &format_args!("{:#x}", self.es))
            .field("ds", &format_args!("{:#x}", self.ds))
            .field("fsbase", &format_args!("{:#x}", self.fsbase))
            .field("gsbase", &format_args!("{:#x}", self.gsbase))
            .finish()
    }
}

impl From<gregset_t> for Regs {
    fn from(regs: gregset_t) -> Self {
        Regs {
            r15: regs[libproc_sys::REG_R15 as usize] as u64,
            r14: regs[libproc_sys::REG_R14 as usize] as u64,
            r13: regs[libproc_sys::REG_R13 as usize] as u64,
            r12: regs[libproc_sys::REG_R12 as usize] as u64,
            r11: regs[libproc_sys::REG_R11 as usize] as u64,
            r10: regs[libproc_sys::REG_R10 as usize] as u64,
            r9: regs[libproc_sys::REG_R9 as usize] as u64,
            r8: regs[libproc_sys::REG_R8 as usize] as u64,
            rdi: regs[libproc_sys::REG_RDI as usize] as u64,
            rsi: regs[libproc_sys::REG_RSI as usize] as u64,
            rbp: regs[libproc_sys::REG_RBP as usize] as u64,
            rbx: regs[libproc_sys::REG_RBX as usize] as u64,
            rdx: regs[libproc_sys::REG_RDX as usize] as u64,
            rcx: regs[libproc_sys::REG_RCX as usize] as u64,
            rax: regs[libproc_sys::REG_RAX as usize] as u64,
            trapno: regs[libproc_sys::REG_TRAPNO as usize] as u64,
            err: regs[libproc_sys::REG_ERR as usize] as u64,
            rip: regs[libproc_sys::REG_RIP as usize] as u64,
            cs: regs[libproc_sys::REG_CS as usize] as u64,
            rfl: regs[libproc_sys::REG_RFL as usize] as u64,
            rsp: regs[libproc_sys::REG_RSP as usize] as u64,
            ss: regs[libproc_sys::REG_SS as usize] as u64,
            fs: regs[libproc_sys::REG_FS as usize] as u64,
            gs: regs[libproc_sys::REG_GS as usize] as u64,
            es: regs[libproc_sys::REG_ES as usize] as u64,
            ds: regs[libproc_sys::REG_DS as usize] as u64,
            fsbase: regs[libproc_sys::REG_FSBASE as usize] as u64,
            gsbase: regs[libproc_sys::REG_GSBASE as usize] as u64,
        }
    }
}

impl Core {
    pub fn open(core_path: &Path) -> Result<Self> {
        let c_core_path = CString::new(core_path.as_os_str().as_bytes())?;
        let mut perr: c_int = 0;
        let flags = 0 | libproc_sys::PGRAB_RDONLY as c_int;

        let handle =
            unsafe { libproc_sys::Pgrab_core(c_core_path.as_ptr(), ptr::null(), flags, &mut perr) };
        let Some(handle) = NonNull::new(handle) else {
            let err_msg = unsafe { libproc_sys::Pgrab_error(perr) };

            // SAFETY: The implementation of Pgrab_error returns a static string.
            let c_msg = unsafe { CStr::from_ptr(err_msg) };

            // UNWRAP: We know all possible values returned by Pgrab_error are valid UTF-8.
            let msg = c_msg.to_str().unwrap();

            return Err(Error::GrabFailed(msg));
        };
        Ok(Core { handle })
    }

    pub fn status(&self) -> Status {
        let status = unsafe { libproc_sys::Pstatus(self.handle.as_ptr()) };

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

    pub fn exec_name(&self) -> Result<PathBuf> {
        let mut buf = vec![0u8; MAXPATHLEN as usize];

        let ret = unsafe {
            libproc_sys::Pexecname(
                self.handle.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
            )
        };

        if !ret.is_null() {
            let c_path = CStr::from_bytes_until_nul(&buf)?;
            let os_path = OsStr::from_bytes(c_path.to_bytes());
            let path = Path::new(os_path);
            Ok(path.to_owned())
        } else {
            Err(Error::NoExecName)
        }
    }

    pub fn lwps(&self) -> Result<Vec<Lwp>> {
        mod callback {
            use super::*;

            pub(super) struct LwpCbData {
                pub handle: *mut ps_prochandle,
                pub data: Vec<Lwp>,
            }

            pub extern "C" fn lwp_callback(data: *mut c_void, status: *const lwpstatus_t) -> c_int {
                unsafe {
                    let cb_data = &mut *(data as *mut LwpCbData);
                    let Some(status) = status.as_ref() else {
                        return 0;
                    };

                    let mut stack = MaybeUninit::<stack_t>::uninit();
                    let ret = libproc_sys::Plwp_main_stack(
                        cb_data.handle,
                        status.pr_lwpid as u32,
                        stack.as_mut_ptr(),
                    );
                    if ret != 0 {
                        // skip
                        return 0;
                    }

                    let stack = stack.assume_init();
                    let stack_start = stack.ss_sp as u64;
                    let stack_end = stack_start + stack.ss_size as u64;

                    let tstamp = Timespec {
                        tv_sec: status.pr_tstamp.tv_sec,
                        tv_nsec: status.pr_tstamp.tv_nsec,
                    };

                    cb_data.data.push(Lwp {
                        tid: status.pr_lwpid as u32,
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
            libproc_sys::Plwp_iter(
                self.handle.as_ptr(),
                Some(callback::lwp_callback),
                &mut cb_data as *mut _ as *mut c_void,
            )
        };
        if ret != 0 {
            return Err(Error::LwpIterFailed);
        }

        Ok(cb_data.data)
    }

    pub fn pread(&self, buf: &mut [u8], address: u64) -> Result<u64> {
        let ct = unsafe {
            libproc_sys::Pread(
                self.handle.as_ptr(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                address as usize,
            )
        };
        if ct >= 0 {
            Ok(ct as u64)
        } else {
            Err(io::Error::last_os_error().into())
        }
    }

    pub fn pread_exact(&self, buf: &mut [u8], address: u64) -> Result<()> {
        if !self.pread(buf, address)? == buf.len() as u64 {
            return Err(Error::UnexpectedEof);
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
        let mut regs: gregset_t = [0; 28];
        let ret =
            unsafe { libproc_sys::Plwp_getregs(self.handle.as_ptr(), lwp, regs.as_mut_ptr()) };
        if ret == 0 {
            Ok(Regs::from(regs))
        } else {
            Err(io::Error::from_raw_os_error(ret).into())
        }
    }

    /// Get the values of a LWP's `ul_ftsd` field from its `ulwp_t`.
    /// This contains the thread-local storage (TLS) for the LWP, also known as
    /// thread-specific data (TSD).
    pub fn lwp_tsd(&self, lwp: u32) -> Result<[u64; 9]> {
        // A thread's `ulwp_t` struct from libc is not exposed as part of
        // libproc. We can trivially get its address via `%fsbase`, but
        // generating bindings would then drag in a large part of the OS which
        // is quite a hassle. Instead we calculate its offset, which is
        // obviously not reliable, but it's been ten years since the last
        // time `ulwp_t` changed format, so we can probably get away with this
        // hack for a while.
        const UL_FTSD_OFFSET: u64 = 320;

        // Start with u64 to ensure alignment is correct.
        let tls = [0u64; 9];

        // SAFETY: There are no layout requirements for either [u64; 9] or [u8; 72].
        let mut bytes: [u8; 72] = unsafe { mem::transmute(tls) };

        let regs = self.regs(lwp)?;
        self.pread(&mut bytes, regs.fsbase + UL_FTSD_OFFSET)?;

        // SAFETY: Returning to the original type.
        let tls = unsafe { mem::transmute(bytes) };

        Ok(tls)
    }

    pub fn mappings(&self) -> Result<Mappings> {
        mod callback {
            use super::*;
            pub extern "C" fn object_callback(
                data: *mut c_void,
                map: *const prmap_t,
                name: *const c_char,
            ) -> c_int {
                unsafe {
                    let objs = &mut *(data as *mut Vec<_>);
                    let map_ref = &*map;

                    let path = if !name.is_null() {
                        Some(CStr::from_ptr(name).to_string_lossy().to_string())
                    } else {
                        None
                    };

                    objs.push(LoadedObjectWithPath {
                        path,
                        vaddr: map_ref.pr_vaddr as u64,
                        size: map_ref.pr_size as u64,
                        flags: MapFlags(map_ref.pr_mflags as u32),
                    });
                }

                0 // Continue iteration
            }
        }

        let mut objs = Vec::new();
        let ret = unsafe {
            libproc_sys::Pmapping_iter_resolved(
                self.handle.as_ptr(),
                Some(callback::object_callback),
                &mut objs as *mut _ as *mut c_void,
            )
        };
        objs.sort_unstable();
        if ret == 0 {
            Ok(Mappings { inner: objs })
        } else {
            Err(Error::MapIterFailed)
        }
    }

    pub fn lookup_map(&self, address: u64) -> Option<LoadedObject> {
        let prmap_ptr =
            unsafe { libproc_sys::Paddr_to_map(self.handle.as_ptr(), address as usize) };

        if prmap_ptr.is_null() {
            return None;
        }
        let prmap = unsafe { *prmap_ptr };

        Some(LoadedObject {
            vaddr: prmap.pr_vaddr as u64,
            size: prmap.pr_size as u64,
            flags: prmap.pr_mflags as u32,
        })
    }

    pub fn symbols<'a>(&'a self) -> Result<Vec<Symbol<'a>>> {
        mod callback {
            use super::*;

            pub extern "C" fn symbol_callback(
                data: *mut c_void,
                sym: *const GElf_Sym,
                name: *const c_char,
            ) -> c_int {
                unsafe {
                    let symbols = &mut *(data as *mut Vec<_>);
                    let Some(sym) = sym.as_ref() else {
                        return 0;
                    };

                    if name.is_null() {
                        return 0;
                    }
                    let c_str = CStr::from_ptr(name);
                    let Ok(name) = c_str.to_str() else {
                        return 0;
                    };

                    symbols.push(Symbol {
                        name,
                        st_name: sym.st_name as usize,
                        st_info: sym.st_info,
                        st_other: sym.st_other,
                        st_shndx: sym.st_shndx as usize,
                        st_value: sym.st_value,
                        st_size: sym.st_size,
                    });
                }

                0 // Continue iteration
            }
        }
        // Search for symbols in the executable only.
        const PR_OBJ_EXEC: *const c_char = ptr::null();
        let fmask = libproc_sys::TYPE_FUNC | libproc_sys::BIND_GLOBAL | libproc_sys::BIND_LOCAL;

        let mut symbols = Vec::new();
        let ret = unsafe {
            libproc_sys::Psymbol_iter(
                self.handle.as_ptr(),
                PR_OBJ_EXEC,
                libproc_sys::PR_SYMTAB as i32,
                fmask as i32,
                Some(callback::symbol_callback),
                &mut symbols as *mut _ as *mut c_void,
            )
        };

        if ret == 0 {
            Ok(symbols)
        } else {
            Err(Error::SymbolIterFailed)
        }
    }

    pub fn lookup_symbol(&self, address: u64) -> Option<SymbolBuf> {
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

    pub fn lookup_symbol_name(&self, address: u64) -> Option<String> {
        let sym = self.lookup_symbol(address)?;

        Some(sym.name)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Status {
    pub active_lwp: u32,
    pub brk_range: Range<u64>,
    pub stack_range: Range<u64>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Lwp {
    /// The LWP's thread id.
    pub tid: u32,
    /// The address range of the LWP's stack.
    pub stack_range: Range<u64>,
    /// The timestamp the LWP was stopped.
    pub tstamp: Timespec,
}

impl fmt::Debug for Lwp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lwp")
            .field("tid", &self.tid)
            .field(
                "stack_range",
                &format_args!("{:#x}..{:#x}", self.stack_range.start, self.stack_range.end),
            )
            .field("tstamp", &self.tstamp)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Mappings {
    inner: Vec<LoadedObjectWithPath>,
}

impl Mappings {
    pub fn get(&self, address: u64) -> Option<&LoadedObjectWithPath> {
        self.inner.iter().find(|o| o.range().contains(&address))
    }

    pub fn as_slice(&self) -> &[LoadedObjectWithPath] {
        &self.inner.as_slice()
    }
}

impl std::ops::Deref for Mappings {
    type Target = [LoadedObjectWithPath];

    fn deref(&self) -> &Self::Target {
        self.inner.as_slice()
    }
}

impl std::ops::Index<u64> for Mappings {
    type Output = LoadedObjectWithPath;

    fn index(&self, index: u64) -> &Self::Output {
        self.get(index).expect("no object found for address")
    }
}

impl<'a> IntoIterator for &'a Mappings {
    type Item = &'a LoadedObjectWithPath;
    type IntoIter = std::slice::Iter<'a, LoadedObjectWithPath>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl IntoIterator for Mappings {
    type Item = LoadedObjectWithPath;
    type IntoIter = std::vec::IntoIter<LoadedObjectWithPath>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LoadedObjectWithPath {
    pub path: Option<String>,
    pub vaddr: u64,
    pub size: u64,
    pub flags: MapFlags,
}

impl LoadedObjectWithPath {
    pub fn is_text(&self) -> bool {
        self.flags.is_read() && self.flags.is_exec()
    }

    pub fn is_data(&self) -> bool {
        self.flags.is_read() && self.flags.is_write() && !self.flags.is_anon()
    }

    pub fn is_heap(&self) -> bool {
        self.flags.is_read()
            && self.flags.is_write()
            && self.flags.is_anon()
            && self.flags.is_break()
    }

    pub fn is_guard(&self) -> bool {
        self.flags.0 == 0
    }
}

impl fmt::Debug for LoadedObjectWithPath {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("LoadedObjectWithPath")
            .field("path", &self.path)
            .field("vaddr", &format_args!("{:#016x}", self.vaddr))
            .field("  end", &format_args!("{:#016x}", self.range().end))
            .field(" size", &format_args!("{:#016x}", self.size))
            .field("flags", &self.flags)
            .finish()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct MapFlags(pub u32);

impl MapFlags {
    pub fn is_read(&self) -> bool {
        self.0 & libproc_sys::MA_READ > 0
    }

    pub fn is_write(&self) -> bool {
        self.0 & libproc_sys::MA_WRITE > 0
    }

    pub fn is_exec(&self) -> bool {
        self.0 & libproc_sys::MA_EXEC > 0
    }

    pub fn is_shared(&self) -> bool {
        self.0 & libproc_sys::MA_SHARED > 0
    }

    pub fn is_anon(&self) -> bool {
        self.0 & libproc_sys::MA_ANON > 0
    }

    pub fn is_break(&self) -> bool {
        self.0 & libproc_sys::MA_BREAK > 0
    }
}

impl fmt::Debug for MapFlags {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("MapFlags")
            .field("is_read", &self.is_read())
            .field("is_write", &self.is_write())
            .field("is_exec", &self.is_exec())
            .field("is_shared", &self.is_shared())
            .field("is_anon", &self.is_anon())
            .field("is_break", &self.is_break())
            .field("inner", &format_args!("{:#016b}", self.0))
            .finish()
    }
}

impl LoadedObjectWithPath {
    pub fn file_name(&self) -> Option<&str> {
        self.path
            .as_ref()
            .and_then(|p| p.rsplit_once('/').map(|(_, n)| n))
    }

    pub fn range(&self) -> Range<u64> {
        let end = self.vaddr.saturating_add(self.size);
        self.vaddr..end
    }
}

impl Ord for LoadedObjectWithPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.vaddr.cmp(&other.vaddr)
    }
}

impl PartialOrd for LoadedObjectWithPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(&other))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct LoadedObject {
    pub vaddr: u64,
    pub size: u64,
    pub flags: u32,
}

impl LoadedObject {
    pub fn range(&self) -> Range<u64> {
        let end = self.vaddr.saturating_add(self.size);
        self.vaddr..end
    }
}

impl Ord for LoadedObject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.vaddr.cmp(&other.vaddr)
    }
}

impl PartialOrd for LoadedObject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(&other))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Symbol<'a> {
    pub name: &'a str,
    pub st_name: usize,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: usize,
    pub st_value: u64,
    pub st_size: u64,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SymbolBuf {
    pub name: String,
    pub st_name: usize,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: usize,
    pub st_value: u64,
    pub st_size: u64,
}

impl Drop for Core {
    fn drop(&mut self) {
        // TODO Prelease instead?
        unsafe { libproc_sys::Pfree(self.handle.as_mut()) };
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        todo!()
    }
}

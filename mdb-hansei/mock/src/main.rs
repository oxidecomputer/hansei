// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `mdbmock`: just enough of mdb to run `hansei.so` off illumos.
//!
//! It `dlopen()`s the module as mdb does, answers the module's mdb and
//! libproc calls from a Linux core opened with hansei's own reader, and
//! runs mdb-style pipelines against it:
//!
//! ```text
//! mdbmock --core CORE --binary BIN --dmod hansei.so \
//!     '::walk tokio_task | ::tokio_task -w state idle'
//! ```
//!
//! A stage is `::walk NAME`, `::DCMD args`, or `ADDR::DCMD args`; a
//! stage fed by a pipe runs once per address with mdb's loop and pipe
//! flags, and a stage feeding one runs with `DCMD_PIPE_OUT` and has its
//! output read back as addresses — which is how mdb pipes too.
//!
//! What it answers is what the illumos proc target answers, rebuilt
//! from the core: `lwpstatus`/`pstatus`/`psinfo` target data in
//! illumos's own layouts, the process handle, `Pmapping_iter`. The one
//! thing it adds is `mdbmock_tls_var_addr`, since a Linux thread-local
//! is native TLS, which nothing on illumos needs.

// Every `unsafe extern "C"` export here is an mdb or libproc entry
// point, called by the module under those APIs' own contracts.
#![allow(clippy::missing_safety_doc)]

use anyhow::{Context as _, Result, anyhow, bail};
use proc::coredump::illumos::procfs;
use proc::{CoreFiles, Proc, SymbolBuf, Target};

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::path::PathBuf;
use std::sync::OnceLock;

static CORE: OnceLock<Proc> = OnceLock::new();

fn core() -> &'static Proc {
    CORE.get().expect("core opened before the module is called")
}

// ---------------------------------------------------------------------
// Output: mdb_printf/mdb_warn (printf.c) land here.

thread_local! {
    /// Where mdb_printf goes: stdout, or a capture for a pipe.
    static CAPTURE: RefCell<Option<String>> = const { RefCell::new(None) };
}

unsafe extern "C" {
    fn mdb_printf(fmt: *const c_char, ...);
    fn mdb_warn(fmt: *const c_char, ...);
}

/// The module calls these and nothing in the host does, so without a
/// reference the linker would leave printf.c's object out.
#[used]
static KEEP_PRINTF: [unsafe extern "C" fn(*const c_char, ...); 2] = [mdb_printf, mdb_warn];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdbmock_output(text: *const c_char, is_warning: c_int) {
    let text = unsafe { CStr::from_ptr(text) }.to_string_lossy();
    if is_warning != 0 {
        eprint!("mdb: {text}");
        return;
    }
    let captured = CAPTURE.with(|c| match c.borrow_mut().as_mut() {
        Some(buf) => {
            buf.push_str(&text);
            true
        }
        None => false,
    });
    if !captured {
        print!("{text}");
    }
}

// ---------------------------------------------------------------------
// The module API, over the core.

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GElfSym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

fn gelf(sym: &SymbolBuf) -> GElfSym {
    GElfSym {
        st_name: sym.st_name as u32,
        st_info: sym.st_info,
        st_other: sym.st_other,
        st_shndx: sym.st_shndx as u16,
        st_value: sym.st_value,
        st_size: sym.st_size,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdb_vread(buf: *mut c_void, nbytes: usize, addr: usize) -> isize {
    match core().read_bytes(addr as u64, nbytes as u64) {
        Ok(bytes) => {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast(), nbytes) };
            nbytes as isize
        }
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdb_lookup_by_addr(
    addr: usize,
    _flags: c_uint,
    buf: *mut c_char,
    nbytes: usize,
    sym: *mut GElfSym,
) -> c_int {
    let Some(found) = core().lookup_symbol_by_addr(addr as u64) else {
        return -1;
    };
    let name = found.name.as_bytes();
    let n = name.len().min(nbytes.saturating_sub(1));
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast(), n);
        *buf.add(n) = 0;
        *sym = gelf(&found);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdb_lookup_by_obj(
    obj: *const c_char,
    name: *const c_char,
    sym: *mut GElfSym,
) -> c_int {
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    let full = if obj.is_null() {
        name.into_owned()
    } else {
        format!(
            "{}`{name}",
            unsafe { CStr::from_ptr(obj) }.to_string_lossy()
        )
    };
    match core().lookup_symbol_by_name(&full) {
        Some(found) => {
            unsafe { *sym = gelf(&found) };
            0
        }
        None => -1,
    }
}

#[repr(C)]
pub struct MdbSymbol {
    sym_name: *const c_char,
    sym_object: *const c_char,
    sym_sym: *const GElfSym,
    sym_table: c_uint,
    sym_id: c_uint,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdb_symbol_iter(
    obj: *const c_char,
    _which: c_uint,
    ty: c_uint,
    cb: unsafe extern "C" fn(*mut MdbSymbol, *mut c_void) -> c_int,
    data: *mut c_void,
) -> c_int {
    if !obj.is_null() {
        return -1; // only the executable's table is asked for
    }
    let mut syms = Vec::new();
    if ty & 0x0400 != 0 {
        syms.extend(core().symbols().unwrap_or_default());
    }
    if ty & (0x0200 | 0x4000) != 0 {
        syms.extend(core().object_symbols().unwrap_or_default());
    }
    for (i, s) in syms.iter().enumerate() {
        let name = CString::new(s.name.as_str()).unwrap_or_default();
        let g = gelf(s);
        let mut m = MdbSymbol {
            sym_name: name.as_ptr(),
            sym_object: std::ptr::null(),
            sym_sym: &g,
            sym_table: 1,
            sym_id: i as c_uint,
        };
        if unsafe { cb(&mut m, data) } != 0 {
            break;
        }
    }
    0
}

#[repr(C)]
pub struct MdbObject {
    obj_name: *const c_char,
    obj_fullname: *const c_char,
    obj_base: usize,
    obj_size: usize,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdb_object_iter(
    cb: unsafe extern "C" fn(*mut MdbObject, *mut c_void) -> c_int,
    data: *mut c_void,
) -> c_int {
    // One object per mapped file, at its first mapping, the executable
    // first: what mdb's proc target hands out.
    let maps = core().mappings().unwrap_or_default();
    let exec = core().exec_path().map(|p| p.display().to_string());
    let mut seen: Vec<(String, u64, u64)> = Vec::new();
    for m in maps.as_slice() {
        let Some(path) = &m.path else { continue };
        if !seen.iter().any(|(p, ..)| p == path) {
            seen.push((path.clone(), m.vaddr, m.size));
        }
    }
    seen.sort_by_key(|(p, base, _)| (Some(p) != exec.as_ref(), *base));
    for (path, base, size) in seen {
        let full = CString::new(path.as_str()).unwrap_or_default();
        let short = CString::new(path.rsplit('/').next().unwrap_or(&path)).unwrap_or_default();
        let mut o = MdbObject {
            obj_name: short.as_ptr(),
            obj_fullname: full.as_ptr(),
            obj_base: base as usize,
            obj_size: size as usize,
        };
        if unsafe { cb(&mut o, data) } != 0 {
            break;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdb_thread_name(tid: usize, buf: *mut c_char, size: usize) -> c_int {
    let Some(name) = core().lwp_name(tid as u32) else {
        return -1;
    };
    let n = name.len().min(size.saturating_sub(1));
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast(), n);
        *buf.add(n) = 0;
    }
    0
}

/// illumos's `sizeof (psinfo_t)` and `pr_psargs`, for the one field the
/// module reads.
const PSINFO_LEN: usize = 416;
const PSINFO_PR_PSARGS: usize = 152;
/// illumos's `sizeof (pstatus_t)`; all zero reads as a capture taking
/// no signal, with no agent lwp, which is what a `gcore` is.
const PSTATUS_LEN: usize = 1680;

fn xdata(name: &str) -> Option<Vec<u8>> {
    match name {
        "pshandle" => Some(1usize.to_ne_bytes().to_vec()),
        "lwpstatus" => {
            let mut out = Vec::new();
            for lwp in core().lwps().ok()? {
                // pr_ustack 0: there is no `stack_t` to point at, so the
                // module falls back to the mapping holding %rsp.
                out.extend(procfs::encode_lwpstatus(lwp.tid, &lwp.regs, 0, lwp.tstamp));
            }
            Some(out)
        }
        "pstatus" => Some(vec![0; PSTATUS_LEN]),
        "psinfo" => {
            let mut out = vec![0u8; PSINFO_LEN];
            let exec = core().exec_path()?.display().to_string();
            let n = exec.len().min(79);
            out[PSINFO_PR_PSARGS..PSINFO_PR_PSARGS + n].copy_from_slice(&exec.as_bytes()[..n]);
            Some(out)
        }
        _ => None,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdb_get_xdata(
    name: *const c_char,
    buf: *mut c_void,
    nbytes: usize,
) -> isize {
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    let Some(data) = xdata(&name) else {
        return -1;
    };
    if buf.is_null() && nbytes == 0 {
        return data.len() as isize;
    }
    let n = data.len().min(nbytes);
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf.cast(), n) };
    n as isize
}

#[repr(C)]
pub struct PrMap {
    pr_vaddr: usize,
    pr_size: usize,
    pr_mapname: [c_char; 64],
    pr_offset: i64,
    pr_mflags: c_int,
    pr_pagesize: c_int,
    pr_shmid: c_int,
    pr_filler: [c_int; 1],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Pmapping_iter(
    _p: *mut c_void,
    func: unsafe extern "C" fn(*mut c_void, *const PrMap, *const c_char) -> c_int,
    cd: *mut c_void,
) -> c_int {
    let Ok(maps) = core().mappings() else {
        return -1;
    };
    for m in maps.as_slice() {
        let map = PrMap {
            pr_vaddr: m.vaddr as usize,
            pr_size: m.size as usize,
            pr_mapname: [0; 64],
            pr_offset: 0,
            pr_mflags: m.flags.0 as c_int,
            pr_pagesize: 4096,
            pr_shmid: -1,
            pr_filler: [0],
        };
        let name = m
            .path
            .as_ref()
            .map(|p| CString::new(p.as_str()).unwrap_or_default());
        let rc = unsafe {
            func(
                cd,
                &map,
                name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
            )
        };
        if rc != 0 {
            return rc;
        }
    }
    0
}

/// The one non-mdb export: a Linux thread-local's address in the
/// thread whose thread pointer is `fsbase`. 0 found, 1 none, -1 error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdbmock_tls_var_addr(
    fsbase: u64,
    name: *const c_char,
    out: *mut u64,
) -> c_int {
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    let Some(lwp) = core()
        .lwps()
        .ok()
        .and_then(|l| l.into_iter().find(|l| l.regs.fsbase == fsbase))
    else {
        return -1;
    };
    let Some(sym) = core().lookup_symbol_by_name(&name) else {
        return -1;
    };
    match core().tls_var_addr(&lwp.regs, &sym) {
        Ok(Some(addr)) => {
            unsafe { *out = addr };
            0
        }
        Ok(None) => 1,
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------
// The module, and running pipelines through it.

#[repr(C)]
struct Arg {
    a_type: c_uint,
    a_str: *const c_char,
}

type DcmdFn = unsafe extern "C" fn(usize, c_uint, c_int, *const Arg) -> c_int;

#[repr(C)]
struct Dcmd {
    name: *const c_char,
    usage: *const c_char,
    descr: *const c_char,
    func: Option<DcmdFn>,
    help: *const c_void,
    tab: *const c_void,
}

#[repr(C)]
struct WalkState {
    callback: Option<unsafe extern "C" fn(usize, *const c_void, *mut c_void) -> c_int>,
    cbdata: *mut c_void,
    addr: usize,
    data: *mut c_void,
    arg: *mut c_void,
    layer: *const c_void,
}

#[repr(C)]
struct Walker {
    name: *const c_char,
    descr: *const c_char,
    init: Option<unsafe extern "C" fn(*mut WalkState) -> c_int>,
    step: Option<unsafe extern "C" fn(*mut WalkState) -> c_int>,
    fini: Option<unsafe extern "C" fn(*mut WalkState)>,
    init_arg: *mut c_void,
}

#[repr(C)]
struct ModInfo {
    version: u16,
    dcmds: *const Dcmd,
    walkers: *const Walker,
}

struct Module {
    info: &'static ModInfo,
}

impl Module {
    fn load(path: &str) -> Result<Self> {
        let cpath = CString::new(path)?;
        let handle = unsafe { libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            let err = unsafe { CStr::from_ptr(libc::dlerror()) }.to_string_lossy();
            bail!("dlopen {path}: {err}");
        }
        let init = unsafe { libc::dlsym(handle, c"_mdb_init".as_ptr()) };
        if init.is_null() {
            bail!("{path} has no _mdb_init");
        }
        let init: unsafe extern "C" fn() -> *const ModInfo = unsafe { std::mem::transmute(init) };
        let info = unsafe { &*init() };
        if info.version != 5 {
            bail!("module API version {} (mdb speaks 5)", info.version);
        }
        Ok(Module { info })
    }

    fn dcmd(&self, name: &str) -> Option<&Dcmd> {
        let mut d = self.info.dcmds;
        loop {
            let dc = unsafe { &*d };
            if dc.name.is_null() {
                return None;
            }
            if unsafe { CStr::from_ptr(dc.name) }.to_bytes() == name.as_bytes() {
                return Some(dc);
            }
            d = unsafe { d.add(1) };
        }
    }

    fn walker(&self, name: &str) -> Option<&Walker> {
        let mut w = self.info.walkers;
        loop {
            let wk = unsafe { &*w };
            if wk.name.is_null() {
                return None;
            }
            if unsafe { CStr::from_ptr(wk.name) }.to_bytes() == name.as_bytes() {
                return Some(wk);
            }
            w = unsafe { w.add(1) };
        }
    }

    fn walk(&self, name: &str) -> Result<Vec<u64>> {
        unsafe extern "C" fn collect(addr: usize, _: *const c_void, data: *mut c_void) -> c_int {
            unsafe { (*data.cast::<Vec<u64>>()).push(addr as u64) };
            0
        }
        let w = self
            .walker(name)
            .ok_or_else(|| anyhow!("no walker {name}"))?;
        let mut out: Vec<u64> = Vec::new();
        let mut st = WalkState {
            callback: Some(collect),
            cbdata: (&raw mut out).cast(),
            addr: 0,
            data: std::ptr::null_mut(),
            arg: w.init_arg,
            layer: std::ptr::null(),
        };
        unsafe {
            if (w.init.unwrap())(&mut st) != 0 {
                bail!("walk {name} failed to start");
            }
            while (w.step.unwrap())(&mut st) == 0 {}
            (w.fini.unwrap())(&mut st);
        }
        Ok(out)
    }

    fn call(&self, name: &str, addr: Option<u64>, flags: c_uint, args: &[String]) -> Result<c_int> {
        let d = self.dcmd(name).ok_or_else(|| anyhow!("no dcmd {name}"))?;
        let cargs: Vec<CString> = args
            .iter()
            .map(|a| CString::new(a.as_str()).unwrap())
            .collect();
        let argv: Vec<Arg> = cargs
            .iter()
            .map(|c| Arg {
                a_type: 0,
                a_str: c.as_ptr(),
            })
            .collect();
        let flags = flags | if addr.is_some() { 0x01 } else { 0 };
        let rc = unsafe {
            (d.func.unwrap())(
                addr.unwrap_or(0) as usize,
                flags,
                argv.len() as c_int,
                argv.as_ptr(),
            )
        };
        if rc == 2 {
            let usage = unsafe { CStr::from_ptr(d.usage) }.to_string_lossy();
            eprintln!(
                "mdb: usage: {}::{name} {usage}",
                if addr.is_some() { "addr" } else { "" }
            );
        }
        Ok(rc)
    }
}

/// Split a stage into words, double quotes grouping, as mdb's lexer does.
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

fn run_pipeline(module: &Module, line: &str) -> Result<()> {
    let stages: Vec<&str> = line.split('|').map(str::trim).collect();
    let mut input: Option<Vec<u64>> = None;
    for (i, stage) in stages.iter().enumerate() {
        let last = i + 1 == stages.len();
        let (addr, rest) = stage
            .split_once("::")
            .ok_or_else(|| anyhow!("not a dcmd: {stage}"))?;
        let words = tokens(rest);
        let (name, args) = words.split_first().ok_or_else(|| anyhow!("empty stage"))?;
        let addr = (!addr.trim().is_empty())
            .then(|| u64::from_str_radix(addr.trim().trim_start_matches("0x"), 16))
            .transpose()
            .context("address")?;

        if name == "walk" {
            let walked = module.walk(args.first().ok_or_else(|| anyhow!("walk what?"))?)?;
            if last {
                for a in &walked {
                    println!("{a:x}");
                }
            }
            input = Some(walked);
            continue;
        }

        let pipe_out: c_uint = if last { 0 } else { 0x10 };
        if !last {
            CAPTURE.with(|c| *c.borrow_mut() = Some(String::new()));
        }
        match input.take() {
            Some(addrs) => {
                for (n, a) in addrs.iter().enumerate() {
                    let first = if n == 0 { 0x04 } else { 0 };
                    module.call(name, Some(*a), 0x02 | 0x08 | first | pipe_out, args)?;
                }
            }
            None => {
                module.call(name, addr, pipe_out, args)?;
            }
        }
        if !last {
            let text = CAPTURE.with(|c| c.borrow_mut().take()).unwrap_or_default();
            input = Some(
                text.lines()
                    .filter_map(|l| u64::from_str_radix(l.trim().trim_start_matches("0x"), 16).ok())
                    .collect(),
            );
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let (mut core_path, mut binary, mut dmod) = (None, None, None);
    let mut commands = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--core" => core_path = args.next().map(PathBuf::from),
            "--binary" => binary = args.next().map(PathBuf::from),
            "--dmod" => dmod = args.next(),
            _ => commands.push(a),
        }
    }
    let core_path = core_path.ok_or_else(|| anyhow!("--core CORE"))?;
    let dmod = dmod.ok_or_else(|| anyhow!("--dmod MODULE.so"))?;
    let files = CoreFiles {
        binary: binary.as_deref(),
        sysroot: None,
    };
    let proc = Proc::open_core_with(&core_path, files).context("open core")?;
    let _ = CORE.set(proc);

    let module = Module::load(&dmod)?;
    for line in commands {
        println!("> {line}");
        run_pipeline(&module, &line)?;
    }
    Ok(())
}

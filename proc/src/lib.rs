use std::ffi::{FromBytesUntilNulError, NulError};
use std::fmt;
use std::io;
use std::ops::Range;

pub mod coredump;
#[cfg(target_os = "illumos")]
mod illumos;
pub mod snapshot;
mod target;
#[cfg(test)]
mod tests;
#[cfg(target_os = "illumos")]
pub use illumos::Lwp;
pub use target::Proc;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    backtrace: std::backtrace::Backtrace,
}

#[derive(thiserror::Error, Debug)]
enum ErrorKind {
    #[error("malformed core file: {0}")]
    BadCore(&'static str),
    #[error("could not convert path to C string")]
    BadPath(#[from] NulError),
    #[error("failed to grab process: {0}")]
    GrabFailed(&'static str),
    #[error("failed to grab thread: {0}")]
    LgrabFailed(&'static str),
    #[error("failed to iterate over lwps")]
    LwpIterFailed,
    #[error("failed to iterate over mappings")]
    MapIterFailed,
    #[error("failed to get exec name")]
    NoExecName,
    #[error("failed to get lwp name")]
    NoLwpName,
    #[error("no nul byte in C string")]
    NoNul(#[from] FromBytesUntilNulError),
    #[error("the target is a core dump, not a live process")]
    NotALiveProcess,
    #[error(
        "{name} is not a thread-local symbol (ELF type {ty}), so it names no per-thread storage"
    )]
    NotThreadLocal { name: String, ty: u8 },
    #[error("error: {0}")] // TODO better message
    Read(#[from] io::Error), // TODO fix name
    #[error("failed to start process: {0}")]
    Start(i32), // TODO show name or errno?
    #[error("failed to stop process: {0}")]
    Stop(i32),
    #[error("failed to iterate over symbols")]
    SymbolIterFailed,
    #[error("pthread key {key} is outside the fast-TSD range; slow TSD is unsupported")]
    TlsKeyOutOfRange { key: u64 },
    #[error("the capture recorded no address for thread-local {name} in the thread at {fsbase:#x}")]
    TlsNotRecorded { name: String, fsbase: u64 },
    #[error("failed to fill whole buffer")]
    UnexpectedEof,
    #[error("address range {addr:#x}..+{len:#x} is not mapped in the target")]
    Unmapped { addr: u64, len: u64 },
}

impl Error {
    /// Creates a new error with backtrace capture.
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            backtrace: std::backtrace::Backtrace::capture(),
        }
    }

    /// Returns the backtrace captured when the error was created.
    pub fn backtrace(&self) -> &std::backtrace::Backtrace {
        &self.backtrace
    }

    pub fn bad_core(what: &'static str) -> Self {
        Self::new(ErrorKind::BadCore(what))
    }

    pub fn bad_path(e: NulError) -> Self {
        Self::new(ErrorKind::BadPath(e))
    }

    pub fn grab_failed(s: &'static str) -> Self {
        Self::new(ErrorKind::GrabFailed(s))
    }

    pub fn lgrab_failed(s: &'static str) -> Self {
        Self::new(ErrorKind::LgrabFailed(s))
    }

    pub fn lwp_iter_failed() -> Self {
        Self::new(ErrorKind::LwpIterFailed)
    }

    pub fn map_iter_failed() -> Self {
        Self::new(ErrorKind::MapIterFailed)
    }

    pub fn no_exec_name() -> Self {
        Self::new(ErrorKind::NoExecName)
    }

    pub fn no_lwp_name() -> Self {
        Self::new(ErrorKind::NoLwpName)
    }

    pub fn no_nul(e: FromBytesUntilNulError) -> Self {
        Self::new(ErrorKind::NoNul(e))
    }

    pub fn not_a_live_process() -> Self {
        Self::new(ErrorKind::NotALiveProcess)
    }

    pub fn not_thread_local(name: &str, ty: u8) -> Self {
        Self::new(ErrorKind::NotThreadLocal {
            name: name.to_string(),
            ty,
        })
    }

    pub fn read(e: io::Error) -> Self {
        Self::new(ErrorKind::Read(e))
    }

    pub fn start(errno: i32) -> Self {
        Self::new(ErrorKind::Start(errno))
    }

    pub fn stop(errno: i32) -> Self {
        Self::new(ErrorKind::Stop(errno))
    }

    pub fn symbol_iter_failed() -> Self {
        Self::new(ErrorKind::SymbolIterFailed)
    }

    pub fn tls_key_out_of_range(key: u64) -> Self {
        Self::new(ErrorKind::TlsKeyOutOfRange { key })
    }

    pub fn tls_not_recorded(name: &str, fsbase: u64) -> Self {
        Self::new(ErrorKind::TlsNotRecorded {
            name: name.to_string(),
            fsbase,
        })
    }

    pub fn unexpected_eof() -> Self {
        Self::new(ErrorKind::UnexpectedEof)
    }

    pub fn unmapped(addr: u64, len: u64) -> Self {
        Self::new(ErrorKind::Unmapped { addr, len })
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

/// The narrow reading surface a debugger needs from a target: memory
/// bytes, symbol lookups, mappings, LWP state, and where a thread-local
/// lives in a given thread.
///
/// Implemented by [`Proc`] — a core dump of either system, or a live
/// process through libproc — and by snapshots captured from one, which
/// replay on any platform. The layers interpreting a target run against
/// whichever is to hand.
pub trait Target {
    /// Read exactly `len` bytes at `addr`.
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>>;

    /// The bytes at `addr`, borrowed from the target's own storage when
    /// one piece of it serves the whole read — a mapped core segment or
    /// backing file. `None` means the read needs assembling (or the
    /// backend reads through a handle rather than a mapping); fall back
    /// to [`read_bytes`](Target::read_bytes).
    fn pslice(&self, _addr: u64, _len: u64) -> Option<&[u8]> {
        None
    }

    /// How many of the `max` bytes at `addr` this target can actually
    /// serve, without reading any of them.
    ///
    /// This is what bounds a read whose length came out of the target's
    /// own memory: a length word read from a corrupt `Vec` header claims
    /// whatever its bits say, and believing it means allocating that much
    /// before the read fails. A core knows its segments, so it can answer
    /// exactly; a live process would have to probe, so it declines to
    /// bound and returns `max`. Answering `0` means nothing at `addr` is
    /// readable at all.
    fn readable_len(&self, _addr: u64, max: u64) -> u64 {
        max
    }

    /// The symtab symbol covering `addr`, if any.
    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf>;

    /// The symtab symbol spelled exactly `name`, if any.
    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf>;

    /// Every function symbol in the target executable's symtab.
    fn symbols(&self) -> Result<Vec<SymbolBuf>>;

    /// Every object symbol in the target executable's symtab.
    fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        Ok(Vec::new())
    }

    /// The target's memory mappings.
    fn mappings(&self) -> Result<Mappings>;

    /// The target's LWPs with their register state.
    fn lwps(&self) -> Result<Vec<LwpInfo>>;

    fn read_u64(&self, addr: u64) -> Result<u64> {
        let bytes = self.read_bytes(addr, size_of::<u64>() as u64)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u32(&self, addr: u64) -> Result<u32> {
        let bytes = self.read_bytes(addr, size_of::<u32>() as u64)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u16(&self, addr: u64) -> Result<u16> {
        let bytes = self.read_bytes(addr, size_of::<u16>() as u64)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u8(&self, addr: u64) -> Result<u8> {
        Ok(self.read_bytes(addr, 1)?[0])
    }

    /// The address of the thread-local variable named by `sym` in the
    /// thread whose registers are `regs`, or `None` if that thread holds
    /// no instance of it.
    ///
    /// How a symbol names a thread-local is the platform's business, and
    /// the two disagree completely. On illumos, std's `thread_local!`
    /// compiles to the `os` model: `sym` is an ordinary static holding a
    /// `pthread_key_t`, and the thread's value for that key is a pointer
    /// parked in its fast-TSD slots (see [`tls_addr_from_pthread_key`]).
    /// On Linux it is native ELF TLS: `sym` is an `STT_TLS` symbol whose
    /// `st_value` is an offset into the thread's own TLS block, and the
    /// variable is stored there inline rather than behind a pointer.
    ///
    /// Callers hand over the symbol and take back an address, which is
    /// the only part both models agree on.
    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>>;
}

/// Resolve a thread-local through a pthread key: the illumos model,
/// where `sym` is a static holding a `pthread_key_t` and the thread's
/// value for that key sits in its fast-TSD slots (see
/// [`tsd_from_fsbase`]).
///
/// A zero slot means this thread never set the key, which is ordinary —
/// most LWPs in a tokio process are not runtime workers.
///
/// Both illumos backends use it — libproc's and the core reader's — so
/// it is built everywhere the latter is, which is everywhere.
pub(crate) fn tls_addr_from_pthread_key<T: Target + ?Sized>(
    target: &T,
    regs: &Regs,
    sym: &SymbolBuf,
) -> Result<Option<u64>> {
    let key = target.read_u64(sym.st_value)?;
    let slots = tsd_from_fsbase(target, regs)?;
    // A key past the fast slots would live in the slow TSD array, which
    // no tokio process observed so far uses.
    let addr = *slots
        .get(key as usize)
        .ok_or_else(|| Error::tls_key_out_of_range(key))?;
    Ok((addr != 0).then_some(addr))
}

/// Read a thread's `ulwp_t.ul_ftsd` through any [`Target`]'s memory.
///
/// A thread's `ulwp_t` struct from libc is not exposed as part of
/// libproc. We can trivially get its address via `%fsbase`, but
/// generating bindings would then drag in a large part of the OS which
/// is quite a hassle. Instead we calculate its offset, which is
/// obviously not reliable, but it's been ten years since the last
/// time `ulwp_t` changed format, so we can probably get away with this
/// hack for a while.
pub(crate) fn tsd_from_fsbase<T: Target + ?Sized>(target: &T, regs: &Regs) -> Result<[u64; 9]> {
    const UL_FTSD_OFFSET: u64 = 320;
    const UL_FTSD_LEN: usize = 9;

    let bytes = target.read_bytes(
        regs.fsbase + UL_FTSD_OFFSET,
        (UL_FTSD_LEN * size_of::<u64>()) as u64,
    )?;

    let mut tsd = [0u64; UL_FTSD_LEN];
    for (slot, chunk) in tsd.iter_mut().zip(bytes.chunks_exact(size_of::<u64>())) {
        *slot = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    Ok(tsd)
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
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

impl fmt::Debug for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
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

#[derive(Clone, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Status {
    pub active_lwp: u32,
    pub brk_range: Range<u64>,
    pub stack_range: Range<u64>,
}

#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct LwpInfo {
    /// The LWP's thread id.
    pub tid: u32,
    /// The LWP's register state.
    pub regs: Regs,
    /// The address range of the LWP's stack.
    pub stack_range: Range<u64>,
    /// The timestamp the LWP was stopped.
    pub tstamp: Timespec,
}

impl fmt::Debug for LwpInfo {
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

#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize,
)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize,
)]
pub struct Mappings {
    pub(crate) inner: Vec<LoadedObjectWithPath>,
}

impl Mappings {
    pub fn get(&self, address: u64) -> Option<&LoadedObjectWithPath> {
        self.inner.iter().find(|o| o.range().contains(&address))
    }

    pub fn contains_addr(&self, address: u64) -> bool {
        self.get(address).is_some()
    }

    pub fn as_slice(&self) -> &[LoadedObjectWithPath] {
        self.inner.as_slice()
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

#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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

/// Memory-mapping permission and provenance bits (`prmap_t.pr_mflags`).
///
/// The bit values are fixed by illumos's `<sys/procfs.h>` and are stable
/// ABI, so they are spelled out here rather than taken from libproc-sys;
/// snapshots captured on illumos decode them on any platform.
#[derive(
    Copy, Clone, PartialEq, PartialOrd, Ord, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct MapFlags(pub u32);

impl MapFlags {
    const MA_READ: u32 = 0x04;
    const MA_WRITE: u32 = 0x02;
    const MA_EXEC: u32 = 0x01;
    const MA_SHARED: u32 = 0x08;
    const MA_ANON: u32 = 0x40;
    const MA_BREAK: u32 = 0x10;

    pub fn is_read(&self) -> bool {
        self.0 & Self::MA_READ > 0
    }

    pub fn is_write(&self) -> bool {
        self.0 & Self::MA_WRITE > 0
    }

    pub fn is_exec(&self) -> bool {
        self.0 & Self::MA_EXEC > 0
    }

    pub fn is_shared(&self) -> bool {
        self.0 & Self::MA_SHARED > 0
    }

    pub fn is_anon(&self) -> bool {
        self.0 & Self::MA_ANON > 0
    }

    pub fn is_break(&self) -> bool {
        self.0 & Self::MA_BREAK > 0
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
        Some(self.cmp(other))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct LoadedObject {
    pub vaddr: u64,
    pub size: u64,
    pub flags: MapFlags,
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
        Some(self.cmp(other))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Symbol<'a> {
    pub name: &'a str,
    pub st_name: usize,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: usize,
    pub st_value: u64,
    pub st_size: u64,
}

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize,
)]
pub struct SymbolBuf {
    pub name: String,
    pub st_name: usize,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: usize,
    pub st_value: u64,
    pub st_size: u64,
}

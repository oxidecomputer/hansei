use std::ffi::{FromBytesUntilNulError, NulError};
use std::fmt;
use std::io;
use std::ops::Range;

pub mod coredump;
pub mod snapshot;
mod target;
#[cfg(test)]
mod tests;
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
    #[error(
        "{name} is not a thread-local symbol (ELF type {ty}), so it names no per-thread storage"
    )]
    NotThreadLocal { name: String, ty: u8 },
    #[error("error: {0}")] // TODO better message
    Read(#[from] io::Error), // TODO fix name
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

    pub fn not_thread_local(name: &str, ty: u8) -> Self {
        Self::new(ErrorKind::NotThreadLocal {
            name: name.to_string(),
            ty,
        })
    }

    pub fn read(e: io::Error) -> Self {
        Self::new(ErrorKind::Read(e))
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
/// Implemented by [`Proc`] — a core dump of either system — and by
/// snapshots captured from one, which replay on any platform. The
/// layers interpreting a target run against whichever is to hand.
///
/// `Sync` is part of the contract: a render pass fans a collection's
/// entries out across worker threads that all read through the one
/// target, so a reader that cannot be shared cannot serve a render at
/// all.
pub trait Target: Sync {
    /// Read exactly `len` bytes at `addr`, lent straight from the
    /// target's own storage — a mapped core segment, a snapshot's
    /// captured run. Every target lends: what a backend cannot lend
    /// whole it does not serve at all, which is what lets a render pass
    /// hold millions of borrowed views without copying one of them.
    fn read_bytes(&self, addr: u64, len: u64) -> Result<&[u8]>;

    /// How many of the `max` bytes at `addr` this target can actually
    /// serve, without reading any of them.
    ///
    /// This is what bounds a read whose length came out of the target's
    /// own memory: a length word read from a corrupt `Vec` header claims
    /// whatever its bits say, and believing it means allocating that much
    /// before the read fails. A core knows its segments, so it can answer
    /// exactly. Answering `0` means nothing at `addr` is readable at all.
    fn readable_len(&self, _addr: u64, max: u64) -> u64 {
        max
    }

    /// The symtab symbol covering `addr`, if any.
    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf>;

    /// The symtab symbol spelled exactly `name`, if any.
    ///
    /// A bare name is the executable's own, which is what every join
    /// onto a Rust binary wants. A name qualified with an object, in
    /// mdb's spelling — ``"libumem.so.1`umem_ready"`` — is that
    /// object's instead, and resolves only where the target carries
    /// per-object symbols: an illumos core carries one table per
    /// mapped object, so a library's internals are readable from the
    /// core alone, while a Linux core carries no symbols at all and
    /// only the `--binary` executable's are on hand.
    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf>;

    /// Every function symbol in the target executable's symtab.
    fn symbols(&self) -> Result<Vec<SymbolBuf>>;

    /// Every object symbol in the target executable's symtab.
    fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        Ok(Vec::new())
    }

    /// The signal that terminated the target, where its core records
    /// one. `None` for a target that was not killed by a signal at all:
    /// a live process, a snapshot, or a live capture — `gcore` on
    /// either system stops the process rather than crashing it, and
    /// leaves no fatal signal behind.
    fn fatal_signal(&self) -> Option<FatalSignal> {
        None
    }

    /// The name the target records for this lwp, where its system
    /// records one. An illumos core carries `NT_LWPNAME` notes; a
    /// Linux core records none, and a snapshot does not carry them.
    fn lwp_name(&self, _tid: u32) -> Option<String> {
        None
    }

    /// The process-identity facts the target records — pid, ids, the
    /// command line, and whatever else its system wrote down. `None`
    /// for a target that carries none (a snapshot).
    fn process_facts(&self) -> Option<ProcessFacts> {
        None
    }

    /// The open-fd table the target records, in fd order. `None` for
    /// a target that carries none: a Linux core, a snapshot, or an
    /// illumos core old enough to predate `NT_FDINFO`.
    fn fds(&self) -> Option<&[FdInfo]> {
        None
    }

    /// The path of the target's executable, as the target records it.
    fn exec_path(&self) -> Option<std::path::PathBuf> {
        None
    }

    /// The executable's build id from the two places it is recorded,
    /// for the targets where the question arises — a Linux core
    /// beside the `--binary` standing in for its executable.
    fn build_ids(&self) -> Option<BuildIds> {
        None
    }

    /// The load addresses of the objects whose symbol tables this
    /// target can read — an illumos core carries one per mapped
    /// object, a Linux core only the substituted executable's. Empty
    /// for a target that cannot attribute symbols to objects (a
    /// snapshot records a flat table).
    fn symbol_object_bases(&self) -> Vec<u64> {
        Vec::new()
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

    /// How far the executable landed from where it was linked: what a
    /// static address out of its debug info must be moved by to be read
    /// in this target. Zero for a position-dependent executable, its
    /// load address for a PIE.
    ///
    /// `None` is "this target cannot say", which is a different answer
    /// from zero: a reader that gets it has no runtime address to
    /// offer, and must say so rather than present a link-time address
    /// as though it were one. Every symbol a target resolves is already
    /// biased, so this is only for the addresses that arrive from
    /// elsewhere — the debug info's own.
    fn exec_bias(&self) -> Option<u64> {
        None
    }
}

/// The maximal readable stretches of the `size` bytes at `vaddr`, as
/// `(addr, len)` pairs in address order. `readable` answers how many of
/// at most `max` bytes at an address it can serve — zero inside a hole
/// — and a hole is skipped to the next page boundary, the only place a
/// new readable region can begin: mappings and the dumped extents
/// within them start page-aligned, and only a readable run's *end* (a
/// backing file's last partial page) falls mid-page.
///
/// Anything sweeping a stretch of a target wants this rather than one
/// read of the whole: a core dumps a mapping in whatever pieces its
/// filter kept, and a single read across the first seam fails and takes
/// everything after it with it.
pub fn readable_runs(vaddr: u64, size: u64, readable: impl Fn(u64, u64) -> u64) -> Vec<(u64, u64)> {
    const PAGE: u64 = 4096;
    let mut runs = Vec::new();
    let mut off = 0u64;
    while off < size {
        let addr = vaddr + off;
        let n = readable(addr, size - off);
        if n == 0 {
            off += PAGE - (addr & (PAGE - 1));
            continue;
        }
        runs.push((addr, n));
        off += n;
    }
    runs
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
pub fn tls_addr_from_pthread_key(
    read_u64: &dyn Fn(u64) -> Result<u64>,
    regs: &Regs,
    sym: &SymbolBuf,
) -> Result<Option<u64>> {
    let key = read_u64(sym.st_value)?;
    let slots = tsd_from_fsbase(read_u64, regs)?;
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
pub fn tsd_from_fsbase(read_u64: &dyn Fn(u64) -> Result<u64>, regs: &Regs) -> Result<[u64; 9]> {
    const UL_FTSD_OFFSET: u64 = 320;
    const UL_FTSD_LEN: usize = 9;

    let mut tsd = [0u64; UL_FTSD_LEN];
    for (i, slot) in tsd.iter_mut().enumerate() {
        *slot = read_u64(regs.fsbase + UL_FTSD_OFFSET + (i * size_of::<u64>()) as u64)?;
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

/// The signal that terminated the target, as its core records it.
///
/// Every field is decoded by the backend that read the core, because
/// only it knows which system's numbering the bytes use — `SIGBUS` is
/// 7 on Linux and 10 on illumos, and a display layer mapping numbers
/// itself would be wrong on whichever system it was not written on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FatalSignal {
    /// The signal's name as its own system spells it (`"SIGSEGV"`).
    pub name: &'static str,
    pub signo: i32,
    /// The `siginfo` code refining the signal, and its name where it is
    /// one of the fault codes (`"SEGV_MAPERR"`). User-sent and
    /// kernel-internal codes stay numbers: the union they select in the
    /// `siginfo` carries no address, which is what `fault_addr`'s
    /// absence says.
    pub code: i32,
    pub code_name: Option<&'static str>,
    /// The faulting address, present only when `code` is a fault code —
    /// for any other code the same `siginfo` bytes mean something else
    /// (a sender's pid, a queued value), and reading them as an address
    /// would print confident garbage.
    pub fault_addr: Option<u64>,
    /// The lwp that took the signal, where the core identifies one.
    pub lwp: Option<u32>,
    /// The sending pid, present only for a user-sent signal — a
    /// non-positive `si_code`, whose `siginfo` union leads with
    /// `si_pid` where a fault's holds the address.
    pub sender: Option<i32>,
}

/// The fault codes whose `siginfo` union holds the faulting address.
///
/// The values are shared: Linux took the SVR4 numbering, so
/// `SEGV_MAPERR` is 1 and `BUS_ADRERR` is 2 on both systems, and one
/// table serves either backend. What is *not* shared is the signal
/// numbering that keys it, which is why callers pass the decoded name
/// rather than a number.
pub fn fault_code_name(signal: &str, code: i32) -> Option<&'static str> {
    let names: &[&'static str] = match signal {
        "SIGSEGV" => &["SEGV_MAPERR", "SEGV_ACCERR"],
        "SIGBUS" => &["BUS_ADRALN", "BUS_ADRERR", "BUS_OBJERR"],
        "SIGILL" => &[
            "ILL_ILLOPC",
            "ILL_ILLOPN",
            "ILL_ILLADR",
            "ILL_ILLTRP",
            "ILL_PRVOPC",
            "ILL_PRVREG",
            "ILL_COPROC",
            "ILL_BADSTK",
        ],
        "SIGFPE" => &[
            "FPE_INTDIV",
            "FPE_INTOVF",
            "FPE_FLTDIV",
            "FPE_FLTOVF",
            "FPE_FLTUND",
            "FPE_FLTRES",
            "FPE_FLTINV",
            "FPE_FLTSUB",
        ],
        "SIGTRAP" => &["TRAP_BRKPT", "TRAP_TRACE"],
        _ => &[],
    };
    usize::try_from(code)
        .ok()
        .and_then(|code| code.checked_sub(1))
        .and_then(|index| names.get(index).copied())
}

/// The executable's GNU build id, from the two places it is recorded:
/// the core's own dumped image of it, and the file standing in for it.
///
/// Either side is `None` where there is no id to read — a binary linked
/// without one, or a core that dumped none of the executable's header.
/// Nothing can be concluded from that; only two ids that disagree are
/// evidence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BuildIds {
    pub core: Option<Vec<u8>>,
    pub binary: Option<Vec<u8>>,
}

impl BuildIds {
    /// Whether the two are both present and differ — the one case that
    /// says the file is not the binary the core was taken from.
    pub fn disagree(&self) -> bool {
        matches!((&self.core, &self.binary), (Some(a), Some(b)) if a != b)
    }
}

/// One open file descriptor as an illumos core's `NT_FDINFO` notes
/// record it — the fixed `prfdinfo_core_t`, which unlike the variable
/// `prfdinfo_t` of `/proc/<pid>/fdinfo` carries no `pr_misc` items:
/// a socket has no local or peer name here, only its mode. A Linux
/// core records no fd table at all.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FdInfo {
    pub fd: i32,
    /// `st_mode`: the file type in the `S_IFMT` bits plus permissions.
    pub mode: u32,
    pub ino: u64,
    pub offset: i64,
    pub size: u64,
    /// The `O_*` flags the fd was opened with (`pr_fileflags`).
    pub fileflags: i32,
    /// The path, empty where the kernel recorded none (a socket).
    pub path: String,
}

/// The process-identity facts a core records about its target: who it
/// was, whose child it was, and what it was started as.
///
/// Every field past the ids is `Option` or empty where a core does not
/// record it — the two systems record very different amounts. An
/// illumos core carries the whole `psinfo_t` plus pointers into the
/// dumped stack for argv and the environment; a Linux one carries only
/// the 136-byte `prpsinfo` (ids, `pr_fname`, the 80-byte `pr_psargs`)
/// and `AT_EXECFN` in the auxv. Locating argv on a Linux initial stack
/// would be a heuristic, so it is not attempted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProcessFacts {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    /// Effective ids, where the core distinguishes them (illumos).
    pub euid: Option<u32>,
    pub egid: Option<u32>,
    /// The data model (`"LP64"` / `"ILP32"`), from illumos `pr_dmodel`;
    /// a Linux core does not say.
    pub model: Option<&'static str>,
    /// When the process started, on the realtime clock — illumos
    /// `pr_start`. A Linux core records no start time.
    pub start: Option<Timespec>,
    /// The executable's short name (`pr_fname`).
    pub fname: String,
    /// The command line as the fixed-width `pr_psargs` records it:
    /// whole only when it fit in 80 bytes.
    pub psargs: String,
    /// The full argv, read out of the target's own memory through the
    /// `pr_argv` pointer (illumos). `None` where the core records no
    /// pointer or the array is not in the dump.
    pub argv: Option<Vec<String>>,
    /// The environment, likewise through `pr_envp` (illumos).
    pub env: Option<Vec<String>>,
    /// The path the executable was invoked as, from `AT_EXECFN`
    /// (Linux); illumos has no auxv spelling for it.
    pub execfn: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct LwpInfo {
    /// The LWP's thread id.
    pub tid: u32,
    /// The LWP's register state.
    pub regs: Regs,
    /// The address range of the LWP's stack.
    pub stack_range: Range<u64>,
    /// The alternate signal stack this LWP registered, where it
    /// registered one. Its own mapping, distinct from `stack_range` —
    /// a signal handler running on it is on neither the thread's
    /// stack nor the heap, which is the whole reason to record it.
    /// Empty for an LWP with no alternate stack, and on a target whose
    /// core does not say (a Linux one).
    ///
    /// Adding this to a snapshot is a breaking change and takes a
    /// [`snapshot::FORMAT_VERSION`](crate::snapshot::FORMAT_VERSION)
    /// bump with it: postcard is not self-describing, so a reader
    /// decodes fields by position and a capture written without this
    /// one runs off the end rather than defaulting it. `serde(default)`
    /// buys nothing here.
    pub altstack: Range<u64>,
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
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Mappings {
    pub(crate) inner: Vec<LoadedObjectWithPath>,
}

/// Collect a mapping table, sorted by address the way every reader
/// hands one out — the spelling an external reader (the test suite's
/// libproc reference) builds its table with.
impl FromIterator<LoadedObjectWithPath> for Mappings {
    fn from_iter<I: IntoIterator<Item = LoadedObjectWithPath>>(iter: I) -> Self {
        let mut inner: Vec<_> = iter.into_iter().collect();
        inner.sort_unstable();
        Mappings { inner }
    }
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
    /// Which of an object's regions this is, by what the kernel is
    /// enforcing on it: executable is text, writable is data, and
    /// neither is read-only data.
    ///
    /// These are the region's terms rather than a section's, and the
    /// difference is not pedantry. A link editor puts `.rodata` in the
    /// executable region on most layouts and `.bss` in the writable
    /// one, so `text` here covers both code and the constants beside
    /// it, and `data` covers the zero-filled tail as well as the
    /// initialized front. A finer name would be a guess: a core carries
    /// no section headers for the objects it maps, only the symbol
    /// tables written into it.
    pub fn region(&self) -> &'static str {
        match (self.flags.is_exec(), self.flags.is_write()) {
            (true, _) => "text",
            (false, true) => "data",
            (false, false) => "rodata",
        }
    }

    pub fn is_text(&self) -> bool {
        self.flags.is_read() && self.flags.is_exec()
    }

    pub fn is_data(&self) -> bool {
        self.flags.is_read() && self.flags.is_write() && !self.flags.is_anon()
    }

    /// Whether this is *the* heap — the `brk` region, the one thing
    /// `pmap` labels `[ heap ]`.
    ///
    /// Anonymous is not enough: a process maps hundreds of anonymous
    /// regions (thread stacks, alternate signal stacks, an allocator's
    /// own arenas) and exactly one of them is the break. A reader that
    /// calls them all "heap" is asserting something false about all but
    /// one, so the break flag is required and a target that cannot set
    /// it reports [`is_anon`](MapFlags::is_anon) instead.
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

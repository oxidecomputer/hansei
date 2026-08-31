//! An illumos ELF core dump, read straight out of the file.
//!
//! Like its Linux counterpart this asks the operating system nothing, so
//! it reads an illumos core anywhere. On illumos itself [`crate::Proc`]
//! prefers libproc, which knows more about a core than this does — it
//! walks the link map, so it can name the shared objects a core does not
//! — and this reader is what everywhere else gets.
//!
//! An illumos core carries more than a Linux one. Its notes describe the
//! process twice, once in the SVR4 shapes both systems inherited and
//! again in illumos's own: `NT_LWPSTATUS` per thread rather than a
//! reused `NT_PRSTATUS`, `NT_LWPNAME` for thread names, `NT_PSINFO` for
//! the command line. Better still, `coreadm`'s default content puts each
//! mapped object's symbol table *in the core*, as section headers whose
//! `sh_addr` is where that object was loaded — so symbols come out of the
//! core itself, with no companion binary to find. That is the opposite
//! of Linux, where a core carries no symbols at all and the files it
//! names have to be on the machine reading it.
//!
//! The layouts here are fixed ABI from `<sys/procfs.h>`. Their offsets
//! are the ones `libproc-sys`' generated bindings assert, and the tests
//! hold them to a core illumos actually wrote.

use super::common::{Segment, Symbols, elf_ctx};
use crate::{
    Error, FatalSignal, FdInfo, LoadedObject, LoadedObjectWithPath, LwpInfo, MapFlags, Mappings,
    ProcessFacts, Regs, Result, Status, SymbolBuf, Target, Timespec, fault_code_name,
};

use goblin::elf::Elf;
use goblin::elf::dynamic::dyn64::{Dyn, SIZEOF_DYN};
use goblin::elf::dynamic::{DT_DEBUG, DT_NULL};
use goblin::elf::header::ET_EXEC;
use goblin::elf::header::header64::{Header, SIZEOF_EHDR};
use goblin::elf::program_header::program_header64::SIZEOF_PHDR;
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_DYNAMIC, PT_LOAD, PT_PHDR, ProgramHeader};
use goblin::elf::section_header::SHT_SYMTAB;
use goblin::elf::sym::sym64::SIZEOF_SYM;
use goblin::elf::sym::{STB_LOCAL, STB_WEAK, STT_FUNC, STT_OBJECT, STT_TLS, Sym, st_bind, st_type};
use goblin::strtab::Strtab;
use memmap2::Mmap;
use scroll::Pread;

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// Note types from `<sys/procfs.h>`.
const NT_AUXV: u32 = 6;
/// `pstatus_t`, whose last member is the *representative* lwp's
/// `lwpstatus_t` — for a crash core, the lwp that took the killing
/// signal.
const NT_PSTATUS: u32 = 10;
const NT_PSINFO: u32 = 13;
const NT_LWPSTATUS: u32 = 16;
const NT_LWPNAME: u32 = 25;

/// `lwpstatus_t` for x86-64, whose offsets the `libproc-sys` bindings
/// assert: 1296 bytes, with the thread id first and the register set
/// three-quarters of the way in.
const LWPSTATUS_LEN: usize = 1296;
const LWPSTATUS_PR_LWPID: usize = 4;
/// The signal the lwp was taking when it was dumped. Only the
/// representative lwp embedded in `NT_PSTATUS` answers what killed the
/// process: on a multi-lwp crash the kernel stops the *other* lwps
/// with `SIGKILL`, and their own lwpstatus notes record that — so a
/// per-lwp scan finds a `SIGKILL` on whichever sibling sorts first,
/// not the fault. `gcore` sets it nowhere at all.
const LWPSTATUS_PR_CURSIG: usize = 12;
/// The `siginfo_t` for that signal, embedded in the lwpstatus: three
/// ints in SVR4 order — `si_signo`, `si_code`, `si_errno` — then
/// padding to the 8-aligned union, whose fault variant leads with
/// `si_addr`.
const LWPSTATUS_PR_INFO: usize = 16;
const SI_CODE: usize = 4;
const SI_ADDR: usize = 16;
/// The `stack_t` the thread registered with `sigaltstack`, recorded in
/// the note itself rather than pointed at the way `pr_ustack` is. This
/// is what tells an alternate signal stack from any other anonymous
/// mapping — `pmap` labels those `[ altstack tid=N ]`, and without this
/// they are indistinguishable from the heap.
const LWPSTATUS_PR_ALTSTACK: usize = 336;
const LWPSTATUS_PR_TSTAMP: usize = 464;
/// Points at the `stack_t` in the thread's own memory that describes
/// the stack it was given. Reading it is how the whole stack is found:
/// the program headers show only the pages that were touched, so the
/// main thread's ten-megabyte reservation looks like the few pages it
/// has got round to using.
const LWPSTATUS_PR_USTACK: usize = 528;
const LWPSTATUS_PR_REG: usize = 544;

/// `stack_t`: base, length, flags.
const STACK_SS_SP: u64 = 0;
const STACK_SS_SIZE: u64 = 8;

/// The signal names as illumos numbers them — a different assignment
/// from Linux's past the first six (`SIGBUS` is 10 here and 7 there),
/// which is why each backend owns its table. Real-time signals run
/// from `_SIGRTMIN` (42) to `_SIGRTMAX` (73).
#[rustfmt::skip]
const SIGNAL_NAMES: [&str; 41] = [
    "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT",
    "SIGEMT", "SIGFPE", "SIGKILL", "SIGBUS", "SIGSEGV", "SIGSYS",
    "SIGPIPE", "SIGALRM", "SIGTERM", "SIGUSR1", "SIGUSR2", "SIGCHLD",
    "SIGPWR", "SIGWINCH", "SIGURG", "SIGPOLL", "SIGSTOP", "SIGTSTP",
    "SIGCONT", "SIGTTIN", "SIGTTOU", "SIGVTALRM", "SIGPROF", "SIGXCPU",
    "SIGXFSZ", "SIGWAITING", "SIGLWP", "SIGFREEZE", "SIGTHAW",
    "SIGCANCEL", "SIGLOST", "SIGXRES", "SIGJVM1", "SIGJVM2", "SIGINFO",
];
#[rustfmt::skip]
const RT_SIGNAL_NAMES: [&str; 32] = [
    "SIGRTMIN", "SIGRTMIN+1", "SIGRTMIN+2", "SIGRTMIN+3", "SIGRTMIN+4",
    "SIGRTMIN+5", "SIGRTMIN+6", "SIGRTMIN+7", "SIGRTMIN+8", "SIGRTMIN+9",
    "SIGRTMIN+10", "SIGRTMIN+11", "SIGRTMIN+12", "SIGRTMIN+13",
    "SIGRTMIN+14", "SIGRTMIN+15", "SIGRTMAX-15", "SIGRTMAX-14",
    "SIGRTMAX-13", "SIGRTMAX-12", "SIGRTMAX-11", "SIGRTMAX-10",
    "SIGRTMAX-9", "SIGRTMAX-8", "SIGRTMAX-7", "SIGRTMAX-6", "SIGRTMAX-5",
    "SIGRTMAX-4", "SIGRTMAX-3", "SIGRTMAX-2", "SIGRTMAX-1", "SIGRTMAX",
];

/// The name illumos gives `signo`, or `None` for a number outside the
/// signal range — which no signal-killed core produces, so it is read
/// the way a wrong-sized note is: another system's bytes, not a signal.
fn signal_name(signo: i32) -> Option<&'static str> {
    let index = usize::try_from(signo.checked_sub(1)?).ok()?;
    SIGNAL_NAMES
        .get(index)
        .or_else(|| RT_SIGNAL_NAMES.get(index - SIGNAL_NAMES.len()))
        .copied()
}

/// `pstatus_t`: the process-wide extents its head records. The `brk`
/// region is the one mapping `pmap` calls `[ heap ]`; every other
/// anonymous mapping is something else wearing the same lack of a
/// name, so this is what lets the two be told apart.
const PSTATUS_PR_BRKBASE: usize = 48;
const PSTATUS_PR_BRKSIZE: usize = 56;

/// `psinfo_t`: the command line is what names the executable, since an
/// illumos core has no equivalent of Linux's `NT_FILE` — and the rest
/// of the process identity lives here too. `pr_argv`/`pr_envp` are
/// pointers into the target's own stack, which the dump carries, so
/// the full argv and environment are readable once the segments are.
const PSINFO_LEN: usize = 416;
const PSINFO_PR_PID: usize = 8;
const PSINFO_PR_PPID: usize = 12;
const PSINFO_PR_UID: usize = 24;
const PSINFO_PR_EUID: usize = 28;
const PSINFO_PR_GID: usize = 32;
const PSINFO_PR_EGID: usize = 36;
/// `pr_start`, a `timestruc_t` on the realtime clock.
const PSINFO_PR_START: usize = 88;
const PSINFO_PR_FNAME: usize = 136;
const PSINFO_FNAME_LEN: usize = 16;
const PSINFO_PR_PSARGS: usize = 152;
const PSINFO_PSARGS_LEN: usize = 80;
const PSINFO_PR_ARGC: usize = 236;
const PSINFO_PR_ARGV: usize = 240;
const PSINFO_PR_ENVP: usize = 248;
/// `pr_dmodel`: `PR_MODEL_ILP32` (1) or `PR_MODEL_LP64` (2), from
/// `<sys/procfs_isa.h>`.
const PSINFO_PR_DMODEL: usize = 256;
const PR_MODEL_ILP32: u8 = 1;
const PR_MODEL_LP64: u8 = 2;
/// Where a pointer-array walk gives up: past any real argv or
/// environment, short of chasing a corrupt array across the dump.
const STRING_TABLE_MAX: u64 = 4096;

/// `prfdinfo_core_t`, the fixed form the kernel writes into a core's
/// `NT_FDINFO` notes — one per open fd. Unlike the variable
/// `prfdinfo_t` of `/proc/<pid>/fdinfo` it carries no `pr_misc`
/// items, so a socket has no local or peer name here.
const NT_FDINFO: u32 = 22;
const FDINFO_LEN: usize = 1088;
const FDINFO_PR_MODE: usize = 4;
const FDINFO_PR_INO: usize = 32;
const FDINFO_PR_OFFSET: usize = 40;
const FDINFO_PR_SIZE: usize = 48;
const FDINFO_PR_FILEFLAGS: usize = 56;
const FDINFO_PR_PATH: usize = 64;
const FDINFO_PATH_LEN: usize = 1024;

/// `prlwpname`: a thread id and the name that thread was given.
const LWPNAME_LEN: usize = 40;
const LWPNAME_PR_LWPNAME: usize = 8;
const LWPNAME_MAX: usize = 32;

/// `gregset_t` is 28 `greg_t`, indexed by the `REG_*` constants. The
/// order is illumos's own and shares nothing with Linux's but the
/// register names.
const NGREG: usize = 28;
const REG_R15: usize = 0;
const REG_R14: usize = 1;
const REG_R13: usize = 2;
const REG_R12: usize = 3;
const REG_R11: usize = 4;
const REG_R10: usize = 5;
const REG_R9: usize = 6;
const REG_R8: usize = 7;
const REG_RDI: usize = 8;
const REG_RSI: usize = 9;
const REG_RBP: usize = 10;
const REG_RBX: usize = 11;
const REG_RDX: usize = 12;
const REG_RCX: usize = 13;
const REG_RAX: usize = 14;
const REG_TRAPNO: usize = 15;
const REG_ERR: usize = 16;
const REG_RIP: usize = 17;
const REG_CS: usize = 18;
const REG_RFL: usize = 19;
const REG_RSP: usize = 20;
const REG_SS: usize = 21;
const REG_FS: usize = 22;
const REG_GS: usize = 23;
const REG_ES: usize = 24;
const REG_DS: usize = 25;
const REG_FSBASE: usize = 26;
const REG_GSBASE: usize = 27;

/// Auxiliary-vector tags, from `<sys/auxv.h>`. Together these say where
/// the executable's program headers are, which is the thread to pull on
/// to reach everything else the runtime linker knows.
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;

/// `r_debug` and `Link_map` from `<sys/link.h>`, whose offsets the
/// `libproc-sys` bindings assert.
const R_DEBUG_R_MAP: u64 = 8;
/// The runtime linker keeps itself off the list it publishes, on a
/// second one of its own; without walking that too, `ld.so.1` is the one
/// mapped object left unnamed.
const R_DEBUG_R_LDSOMAP: u64 = 40;
const LINK_MAP_L_ADDR: u64 = 0;
const LINK_MAP_L_NAME: u64 = 8;
const LINK_MAP_L_NEXT: u64 = 24;

/// A mapped object is not going to have more than this many entries in
/// its program header table, nor a process this many objects loaded. A
/// core whose memory says otherwise is corrupt, and walking it forever
/// is not the way to find that out.
const MAX_PHDRS: u64 = 128;
const MAX_OBJECTS: usize = 512;
const MAX_PATH: u64 = 1024;

impl Regs {
    /// Decode a `gregset_t`. Every field of [`Regs`] is one of these —
    /// the struct was modelled on this register set — so unlike the
    /// Linux decode nothing is dropped and nothing is left zero.
    fn from_gregset(r: &[u64; NGREG]) -> Self {
        Regs {
            r15: r[REG_R15],
            r14: r[REG_R14],
            r13: r[REG_R13],
            r12: r[REG_R12],
            r11: r[REG_R11],
            r10: r[REG_R10],
            r9: r[REG_R9],
            r8: r[REG_R8],
            rdi: r[REG_RDI],
            rsi: r[REG_RSI],
            rbp: r[REG_RBP],
            rbx: r[REG_RBX],
            rdx: r[REG_RDX],
            rcx: r[REG_RCX],
            rax: r[REG_RAX],
            trapno: r[REG_TRAPNO],
            err: r[REG_ERR],
            rip: r[REG_RIP],
            cs: r[REG_CS],
            rfl: r[REG_RFL],
            rsp: r[REG_RSP],
            ss: r[REG_SS],
            fs: r[REG_FS],
            gs: r[REG_GS],
            es: r[REG_ES],
            ds: r[REG_DS],
            fsbase: r[REG_FSBASE],
            gsbase: r[REG_GSBASE],
        }
    }
}

/// The path the link map records, resolved where that means anything.
///
/// The runtime linker keeps the path it opened the object by, which on
/// illumos is routinely a symlink — `/lib/64` for `/lib/amd64`.
/// `Pmapping_iter_resolved` earns its name by resolving that against the
/// filesystem, so on illumos this does too and the two agree.
///
/// Anywhere else the filesystem to hand is not the one the core came
/// from, and asking it would at best answer nothing and at worst answer
/// about a different file that happens to share a path. The recorded
/// path is what the core actually says, so elsewhere it stands.
#[cfg(target_os = "illumos")]
fn resolve_path(name: String) -> String {
    std::fs::canonicalize(&name)
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or(name)
}

#[cfg(not(target_os = "illumos"))]
fn resolve_path(name: String) -> String {
    name
}

/// The addresses a set of program headers covers, once biased.
///
/// The arithmetic is checked because the headers came out of a core's
/// memory rather than off disk: a damaged one can hold anything, and an
/// address that wrapped would name a range the object does not occupy
/// and take mappings away from the object that does.
fn span_of(phdrs: &[ProgramHeader], bias: u64) -> Option<Range<u64>> {
    let mut start = u64::MAX;
    let mut end = 0u64;
    for ph in phdrs.iter().filter(|ph| ph.p_type == PT_LOAD) {
        let lo = ph.p_vaddr.checked_add(bias)?;
        let hi = lo.checked_add(ph.p_memsz)?;
        start = start.min(lo);
        end = end.max(hi);
    }
    (start < end).then_some(start..end)
}

/// How far an object landed from where it was linked, from its own
/// program headers: the table describes where it is itself, so comparing
/// that with where it turned out to be — `at_phdr` — gives the bias.
/// Zero for a position-dependent executable, its base for a PIE.
///
/// `None` where the table does not describe itself, which is a table
/// that cannot say rather than one saying zero.
fn phdr_bias(at_phdr: u64, phdrs: &[ProgramHeader]) -> Option<u64> {
    let phdr = phdrs.iter().find(|p| p.p_type == PT_PHDR)?;
    Some(at_phdr.wrapping_sub(phdr.p_vaddr))
}

pub struct Core {
    core: Mmap,
    segments: Vec<Segment>,
    lwps: Vec<LwpInfo>,
    /// Thread names, which a Linux core does not record at all.
    lwp_names: BTreeMap<u32, String>,
    /// Each LWP's `pr_ustack`, in step with `lwps`; resolved into stack
    /// ranges once the segments are readable.
    ustacks: Vec<u64>,
    mappings: Mappings,
    /// The executable's path, from the command line the core recorded.
    exec: Option<String>,
    /// The signal that killed the process, decoded from the faulting
    /// lwp's `pr_cursig` and embedded `pr_info`; `None` for a live
    /// capture, which records no fatal signal.
    fatal: Option<FatalSignal>,
    /// Symbols of every object whose table the core carries, keyed by
    /// the address that object was loaded at.
    symbols: BTreeMap<u64, Symbols>,
    /// The object the executable was loaded at, if its table is here.
    exec_base: Option<u64>,
    /// How far the executable landed from where it was linked, from its
    /// own program headers ([`phdr_bias`]).
    exec_bias: Option<u64>,
    /// The `brk` extent as the core's `pstatus_t` recorded it — the one
    /// region `pmap` calls `[ heap ]`. `None` for a core whose pstatus
    /// is absent or predates the field, which falls back to a guess.
    brk: Option<Range<u64>>,
    /// The process identity out of the `psinfo_t`, argv and environment
    /// included; `None` for a core carrying no psinfo note.
    facts: Option<ProcessFacts>,
    /// The open-fd table out of the `NT_FDINFO` notes, in fd order;
    /// `None` for a core carrying none of them.
    fds: Option<Vec<FdInfo>>,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("exec", &self.exec)
            .field("segments", &self.segments.len())
            .field("lwps", &self.lwps.len())
            .field("objects", &self.symbols.len())
            .finish()
    }
}

impl Core {
    pub fn open(core_path: &Path) -> Result<Self> {
        let file = File::open(core_path).map_err(Error::read)?;
        // SAFETY: as everywhere else in this workspace, we assume the
        // file is not modified while mapped.
        let core = unsafe { Mmap::map(&file) }.map_err(Error::read)?;

        let elf = Elf::parse(&core).map_err(|_| Error::bad_core("not an ELF file"))?;
        if elf.header.e_type != goblin::elf::header::ET_CORE {
            return Err(Error::bad_core("not a core file"));
        }

        let mut segments: Vec<Segment> = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| Segment {
                vaddr: ph.p_vaddr,
                memsz: ph.p_memsz,
                filesz: ph.p_filesz,
                offset: ph.p_offset,
                flags: ph.p_flags,
            })
            .collect();
        segments.sort_by_key(|s| s.vaddr);

        let mut lwps = Vec::new();
        let mut ustacks = Vec::new();
        let mut lwp_names = BTreeMap::new();
        let mut auxv = BTreeMap::new();
        let mut exec = None;
        let mut psinfo: Option<Vec<u8>> = None;
        let mut fds: Option<Vec<FdInfo>> = None;
        let mut fatal = None;
        let mut brk: Option<Range<u64>> = None;
        for note in elf.iter_note_headers(&core).into_iter().flatten() {
            let note = note.map_err(|_| Error::bad_core("malformed note"))?;
            let desc = note.desc;
            match note.n_type {
                NT_LWPSTATUS if desc.len() >= LWPSTATUS_LEN => {
                    lwps.push(parse_lwpstatus(desc));
                    ustacks.push(u64::from_le_bytes(
                        desc[LWPSTATUS_PR_USTACK..LWPSTATUS_PR_USTACK + 8]
                            .try_into()
                            .unwrap(),
                    ));
                }
                // The killing signal is the representative lwp's — the
                // `lwpstatus_t` that ends the pstatus, anchored at the
                // tail so a pstatus header of any vintage reads the
                // same. It is not readable from the per-lwp notes: on a
                // multi-lwp crash the kernel stops the *siblings* with
                // SIGKILL, which their own lwpstatus notes record, so a
                // cursig scan finds a SIGKILL before the fault.
                NT_PSTATUS if desc.len() >= LWPSTATUS_LEN => {
                    if fatal.is_none() {
                        fatal = decode_fatal_signal(&desc[desc.len() - LWPSTATUS_LEN..]);
                    }
                    // The head of the same note, which is where the
                    // process-wide extents live.
                    if desc.len() >= PSTATUS_PR_BRKSIZE + 8 {
                        let at = PSTATUS_PR_BRKBASE;
                        let base = u64::from_le_bytes(desc[at..at + 8].try_into().unwrap());
                        let at = PSTATUS_PR_BRKSIZE;
                        let size = u64::from_le_bytes(desc[at..at + 8].try_into().unwrap());
                        if let Some(end) = base.checked_add(size)
                            && base != 0
                        {
                            brk = Some(base..end);
                        }
                    }
                }
                NT_LWPNAME if desc.len() >= LWPNAME_LEN => {
                    let (tid, name) = parse_lwpname(desc);
                    if !name.is_empty() {
                        lwp_names.insert(tid, name);
                    }
                }
                NT_PSINFO if desc.len() >= PSINFO_LEN && psinfo.is_none() => {
                    exec = parse_psinfo_exec(desc);
                    // Kept whole: the argv/envp pointers it holds can
                    // only be followed once the segments are readable.
                    psinfo = Some(desc.to_vec());
                }
                NT_FDINFO if desc.len() >= FDINFO_LEN => {
                    fds.get_or_insert_with(Vec::new).push(parse_fdinfo(desc));
                }
                NT_AUXV => {
                    for pair in desc.chunks_exact(16) {
                        let tag = u64::from_le_bytes(pair[0..8].try_into().unwrap());
                        let val = u64::from_le_bytes(pair[8..16].try_into().unwrap());
                        if tag == 0 {
                            break;
                        }
                        auxv.insert(tag, val);
                    }
                }
                _ => {}
            }
        }
        if lwps.is_empty() {
            return Err(Error::bad_core("no NT_LWPSTATUS note"));
        }
        // Keep `ustacks` in step with `lwps` through the sort.
        let mut paired: Vec<(LwpInfo, u64)> = lwps.into_iter().zip(ustacks).collect();
        paired.sort_by_key(|(l, _)| l.tid);
        let (lwps, ustacks): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

        let symbols = parse_symbols(&elf, &core);

        let mut core_file = Core {
            core,
            segments,
            lwps,
            lwp_names,
            ustacks,
            mappings: Mappings { inner: Vec::new() },
            exec,
            fatal,
            symbols,
            exec_base: None,
            exec_bias: None,
            brk,
            facts: None,
            fds: fds.map(|mut fds| {
                fds.sort_by_key(|f| f.fd);
                fds
            }),
        };
        core_file.fill_stack_ranges();
        core_file.facts = psinfo
            .as_deref()
            .map(|desc| core_file.process_facts_from(desc));

        // The link map lives in the target's memory, so it can only be
        // walked once the segments are readable. So are the program
        // headers the bias comes from.
        let objects = core_file.link_map_objects(&auxv);
        core_file.mappings = build_mappings(&core_file.segments, &objects, core_file.brk.as_ref());
        core_file.exec_base = core_file.find_exec_base(&objects);
        core_file.exec_bias = core_file
            .exec_phdrs(&auxv)
            .and_then(|(at_phdr, phdrs)| phdr_bias(at_phdr, &phdrs));
        Ok(core_file)
    }

    /// Which of the core's symbol tables is the executable's: the one
    /// whose object the link map names with the path the process was
    /// started from. Failing that — a core with no link map to walk —
    /// the lowest, since illumos maps the executable below every shared
    /// object.
    fn find_exec_base(&self, objects: &[(Range<u64>, String)]) -> Option<u64> {
        let named = self.exec.as_ref().and_then(|exec| {
            let (range, _) = objects.iter().find(|(_, name)| name == exec)?;
            self.symbols
                .keys()
                .find(|base| range.contains(base))
                .copied()
        });
        named.or_else(|| self.symbols.keys().next().copied())
    }

    /// Each thread's stack comes from the `stack_t` it was given, read
    /// out of the core's own memory at `pr_ustack`. That is the stack
    /// the thread has, rather than the part of it the program headers
    /// happen to show, and it is what libproc reports.
    ///
    /// A thread whose `stack_t` cannot be read falls back to the region
    /// holding `%rsp`, which is right for a thread whose stack is one
    /// mapping and short for one whose stack was only partly touched.
    fn fill_stack_ranges(&mut self) {
        let ranges: Vec<Range<u64>> = self
            .lwps
            .iter()
            .zip(&self.ustacks)
            .map(|(lwp, ustack)| {
                self.stack_from_ustack(*ustack).unwrap_or_else(|| {
                    self.segments
                        .iter()
                        .find(|s| s.range().contains(&lwp.regs.rsp))
                        .map(Segment::range)
                        .unwrap_or(0..0)
                })
            })
            .collect();
        for (lwp, range) in self.lwps.iter_mut().zip(ranges) {
            lwp.stack_range = range;
        }
    }

    /// Every object the runtime linker had loaded, and where.
    ///
    /// An illumos core has no equivalent of Linux's `NT_FILE`, so the
    /// names of the mapped objects are not written down anywhere in it.
    /// They are still *in* it, in the target's own memory: the auxiliary
    /// vector says where the executable's program headers are, its
    /// `PT_DYNAMIC` holds a `DT_DEBUG` pointing at the linker's
    /// `r_debug`, and that heads a list of `Link_map` entries naming
    /// every object and the address it was loaded at. This is the walk
    /// libproc does, done here over the core's memory.
    ///
    /// Everything about it is best-effort. A core dumped without text
    /// has no ELF headers to read, and one truncated before the link map
    /// has nothing to walk; either way the objects come back unnamed
    /// rather than wrong.
    fn link_map_objects(&self, auxv: &BTreeMap<u64, u64>) -> Vec<(Range<u64>, String)> {
        let Some(r_debug) = self.r_debug(auxv) else {
            return Vec::new();
        };

        let mut objects = Vec::new();
        for head in [R_DEBUG_R_MAP, R_DEBUG_R_LDSOMAP] {
            let Ok(head) = self.read_u64(r_debug + head) else {
                continue;
            };
            self.walk_link_map(head, &mut objects);
        }
        objects
    }

    fn walk_link_map(&self, head: u64, objects: &mut Vec<(Range<u64>, String)>) {
        let mut entry = head;
        let mut seen = 0;
        while entry != 0 && seen < MAX_OBJECTS {
            seen += 1;
            let (Ok(l_addr), Ok(name_ptr), Ok(next)) = (
                self.read_u64(entry + LINK_MAP_L_ADDR),
                self.read_u64(entry + LINK_MAP_L_NAME),
                self.read_u64(entry + LINK_MAP_L_NEXT),
            ) else {
                return;
            };

            let span = self.object_span(l_addr);
            let name = self
                .read_cstr(name_ptr)
                .filter(|n| !n.is_empty())
                .map(resolve_path);
            if let (Some(span), Some(name)) = (span, name) {
                objects.push((span, name));
            }
            entry = next;
        }
    }

    /// The runtime linker's `r_debug`, reached through the executable's
    /// `PT_DYNAMIC` and the `DT_DEBUG` entry in it. The auxiliary
    /// vector says where the program headers are; they say where the
    /// dynamic section is.
    ///
    /// `None` for a statically linked executable, which has neither a
    /// dynamic section nor a link map.
    fn r_debug(&self, auxv: &BTreeMap<u64, u64>) -> Option<u64> {
        let (at_phdr, phdrs) = self.exec_phdrs(auxv)?;
        let bias = phdr_bias(at_phdr, &phdrs).unwrap_or(0);

        let mut at = phdrs
            .iter()
            .find(|p| p.p_type == PT_DYNAMIC)
            .map(|p| p.p_vaddr.wrapping_add(bias))?;
        // `DT_DEBUG` is where the runtime linker leaves the address of
        // its `r_debug`, which is how a debugger finds what is loaded.
        loop {
            let bytes = self.read_bytes(at, SIZEOF_DYN as u64).ok()?;
            let entry: Dyn = bytes.pread_with(0, scroll::Endian::Little).ok()?;
            match entry.d_tag {
                DT_NULL => return None,
                DT_DEBUG if entry.d_val != 0 => return Some(entry.d_val),
                _ => at = at.checked_add(SIZEOF_DYN as u64)?,
            }
        }
    }

    /// The executable's program headers, and the address the auxiliary
    /// vector says they were loaded at.
    fn exec_phdrs(&self, auxv: &BTreeMap<u64, u64>) -> Option<(u64, Vec<ProgramHeader>)> {
        let at_phdr = *auxv.get(&AT_PHDR)?;
        let phent = *auxv.get(&AT_PHENT)? as u16;
        let phnum = *auxv.get(&AT_PHNUM)? as u16;
        Some((at_phdr, self.read_phdrs(at_phdr, phent, phnum)?))
    }

    /// The addresses one mapped object occupies, from the program
    /// headers of the ELF image at `base`.
    fn object_span(&self, base: u64) -> Option<Range<u64>> {
        let header = self.read_bytes(base, SIZEOF_EHDR as u64).ok()?;
        let header = Header::parse(header).ok()?;

        // An executable's program headers carry absolute addresses, so
        // where it was mapped is not a bias to add to them; a shared
        // object's are offsets from wherever it landed, so it is.
        let bias = match header.e_type {
            ET_EXEC => 0,
            _ => base,
        };

        let at = base.checked_add(header.e_phoff)?;
        let phdrs = self.read_phdrs(at, header.e_phentsize, header.e_phnum)?;
        span_of(&phdrs, bias)
    }

    fn read_phdrs(&self, at: u64, phent: u16, phnum: u16) -> Option<Vec<ProgramHeader>> {
        let phent = u64::from(phent);
        let phnum = u64::from(phnum).min(MAX_PHDRS);
        if phent < SIZEOF_PHDR as u64 || phnum == 0 {
            return None;
        }
        // Read each header where its own table says it is, since
        // `e_phentsize` is free to be larger than the structure.
        let bytes: Vec<u8> = (0..phnum)
            .map(|i| {
                self.read_bytes(at.checked_add(i * phent)?, SIZEOF_PHDR as u64)
                    .ok()
            })
            .collect::<Option<Vec<_>>>()?
            .concat();
        ProgramHeader::parse(&bytes, 0, phnum as usize, elf_ctx()).ok()
    }

    /// Decode the `psinfo_t` into [`ProcessFacts`], following the
    /// `pr_argv`/`pr_envp` pointers into the dumped image for the full
    /// argv and environment. Runs after the segments are readable,
    /// because that is what the pointers aim into.
    fn process_facts_from(&self, desc: &[u8]) -> ProcessFacts {
        let int = |at: usize| i32::from_le_bytes(desc[at..at + 4].try_into().unwrap());
        let uint = |at: usize| u32::from_le_bytes(desc[at..at + 4].try_into().unwrap());
        let long = |at: usize| i64::from_le_bytes(desc[at..at + 8].try_into().unwrap());
        let ptr = |at: usize| u64::from_le_bytes(desc[at..at + 8].try_into().unwrap());
        let start = Timespec {
            tv_sec: long(PSINFO_PR_START),
            tv_nsec: long(PSINFO_PR_START + 8),
        };
        let argc = u64::from(uint(PSINFO_PR_ARGC));
        ProcessFacts {
            pid: int(PSINFO_PR_PID),
            ppid: int(PSINFO_PR_PPID),
            uid: uint(PSINFO_PR_UID),
            gid: uint(PSINFO_PR_GID),
            euid: Some(uint(PSINFO_PR_EUID)),
            egid: Some(uint(PSINFO_PR_EGID)),
            model: match desc[PSINFO_PR_DMODEL] {
                PR_MODEL_ILP32 => Some("ILP32"),
                PR_MODEL_LP64 => Some("LP64"),
                _ => None,
            },
            start: (start.tv_sec != 0).then_some(start),
            fname: super::fixed_str(&desc[PSINFO_PR_FNAME..PSINFO_PR_FNAME + PSINFO_FNAME_LEN]),
            psargs: super::fixed_str(&desc[PSINFO_PR_PSARGS..PSINFO_PR_PSARGS + PSINFO_PSARGS_LEN]),
            argv: self.read_string_table(ptr(PSINFO_PR_ARGV), argc.min(STRING_TABLE_MAX)),
            env: self.read_string_table(ptr(PSINFO_PR_ENVP), STRING_TABLE_MAX),
            execfn: None,
        }
    }

    /// The strings behind an array of pointers in the target: up to
    /// `limit` of them, stopping at a terminating null pointer. `None`
    /// when the array or any string it points at is not in the dump —
    /// a partial answer would read as the whole argv, which is worse
    /// than saying the dump does not carry it.
    fn read_string_table(&self, at: u64, limit: u64) -> Option<Vec<String>> {
        if at == 0 {
            return None;
        }
        let mut out = Vec::new();
        for i in 0..limit {
            let entry = self.read_u64(at + i * 8).ok()?;
            if entry == 0 {
                break;
            }
            out.push(self.read_cstr(entry)?);
        }
        Some(out)
    }

    fn read_cstr(&self, at: u64) -> Option<String> {
        if at == 0 {
            return None;
        }
        let mut out = Vec::new();
        for i in 0..MAX_PATH {
            match self.read_u8(at + i).ok()? {
                0 => return String::from_utf8(out).ok(),
                b => out.push(b),
            }
        }
        None
    }

    fn stack_from_ustack(&self, ustack: u64) -> Option<Range<u64>> {
        if ustack == 0 {
            return None;
        }
        let sp = self.read_u64(ustack + STACK_SS_SP).ok()?;
        let size = self.read_u64(ustack + STACK_SS_SIZE).ok()?;
        (sp != 0 && size != 0).then(|| sp..sp.saturating_add(size))
    }

    fn segment_at(&self, addr: u64) -> Option<&Segment> {
        let idx = self.segments.partition_point(|s| s.vaddr <= addr);
        let seg = &self.segments[idx.checked_sub(1)?];
        (addr < seg.range().end).then_some(seg)
    }

    /// How many of the `max` bytes at `addr` this core can serve: the
    /// dumped remainder of the segment `addr` falls in, which is exactly
    /// the longest slice [`pslice`](Core::pslice) can lend there. An
    /// illumos core carries no backing-file map, so an undumped page
    /// reads as nothing.
    pub fn readable_len(&self, addr: u64, max: u64) -> u64 {
        match self.segment_at(addr).filter(|s| s.dumped().contains(&addr)) {
            Some(seg) => (seg.dumped().end - addr).min(max),
            None => 0,
        }
    }

    /// The object whose symbols cover `addr`: the one loaded at or
    /// below it, nearest.
    fn object_at(&self, addr: u64) -> Option<&Symbols> {
        self.symbols.range(..=addr).next_back().map(|(_, s)| s)
    }

    /// The bytes at `address`, borrowed straight from the mapped core —
    /// for a read one dumped segment serves whole. A read the mapping
    /// cannot serve in one piece (crossing a segment boundary, or
    /// running into an undumped tail) is `None`, and nothing assembles
    /// those: what one segment cannot serve, the core does not serve.
    pub fn pslice(&self, address: u64, len: u64) -> Option<&[u8]> {
        let seg = self
            .segment_at(address)
            .filter(|s| s.dumped().contains(&address))?;
        let skip = address - seg.vaddr;
        if seg.filesz - skip < len {
            return None;
        }
        let at = (seg.offset + skip) as usize;
        self.core.get(at..at + len as usize)
    }

    pub fn exec_name(&self) -> Result<PathBuf> {
        self.exec
            .as_ref()
            .map(PathBuf::from)
            .ok_or_else(Error::no_exec_name)
    }

    pub fn lwps(&self) -> Result<Vec<LwpInfo>> {
        Ok(self.lwps.clone())
    }

    pub fn regs(&self, lwp: u32) -> Result<Regs> {
        self.lwps
            .iter()
            .find(|l| l.tid == lwp)
            .map(|l| l.regs.clone())
            .ok_or_else(|| Error::lgrab_failed("no such lwp in the core"))
    }

    /// The name the thread was given, which illumos records and Linux
    /// does not.
    pub fn lwp_name(&self, lwpid: u32) -> Result<String> {
        self.lwp_names
            .get(&lwpid)
            .cloned()
            .ok_or_else(Error::no_lwp_name)
    }

    pub fn status(&self) -> Status {
        // The lwp to report as current: the one that took the fatal
        // signal, where there is one. The per-lwp notes come in id
        // order — unlike a Linux core, which leads with the dumping
        // thread — so the first lwp is just the lowest id, and on a
        // multi-lwp crash core usually not the one that crashed.
        let active = self
            .fatal
            .as_ref()
            .and_then(|f| f.lwp)
            .and_then(|tid| self.lwps.iter().find(|l| l.tid == tid))
            .or_else(|| self.lwps.first());
        Status {
            active_lwp: active.map(|l| l.tid).unwrap_or(0),
            // What the core recorded, where it recorded it: an illumos
            // `pstatus_t` carries the break outright, which is the one
            // reading that cannot be wrong. The scan below is the
            // fallback for a core whose pstatus is missing or older
            // than the field — the writable anonymous region above the
            // executable, which is where the break usually starts but
            // is a guess, not a record.
            brk_range: self
                .brk
                .clone()
                .or_else(|| {
                    self.segments
                        .iter()
                        .find(|s| {
                            Some(s.vaddr) > self.exec_base
                                && s.flags & PF_W != 0
                                && !self.symbols.contains_key(&s.vaddr)
                        })
                        .map(Segment::range)
                })
                .unwrap_or(0..0),
            stack_range: active.map(|l| l.stack_range.clone()).unwrap_or(0..0),
        }
    }

    pub fn mappings(&self) -> Result<Mappings> {
        Ok(self.mappings.clone())
    }

    pub fn addr_to_map(&self, address: u64) -> Option<LoadedObject> {
        self.mappings.get(address).map(|m| LoadedObject {
            vaddr: m.vaddr,
            size: m.size,
            flags: m.flags,
        })
    }

    pub fn addr_is_mapped(&self, address: u64) -> bool {
        self.addr_to_map(address).is_some()
    }

    pub fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        Ok(self
            .exec_base
            .and_then(|b| self.symbols.get(&b))
            .map(|s| s.functions.clone())
            .unwrap_or_default())
    }

    pub fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        Ok(self
            .exec_base
            .and_then(|b| self.symbols.get(&b))
            .map(|s| s.objects.clone())
            .unwrap_or_default())
    }

    pub fn lookup_symbol_by_addr(&self, address: u64) -> Option<SymbolBuf> {
        let object = self.object_at(address)?;
        let funcs = &object.functions;

        // The nearest address at or below the one asked for, then the
        // first symbol sitting on it: the list is in libproc's order, so
        // the first of a tied run is the one libproc would name.
        let end = funcs.partition_point(|s| s.st_value <= address);
        let value = funcs.get(end.checked_sub(1)?)?.st_value;
        let sym = &funcs[funcs.partition_point(|s| s.st_value < value)];

        (address < sym.st_value + sym.st_size).then(|| sym.clone())
    }

    pub fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        let (base, name) = match name.split_once('`') {
            Some((object, name)) => (self.object_base(object)?, name),
            None => (self.exec_base?, name),
        };
        self.symbols.get(&base)?.find_by_name(name).cloned()
    }

    /// Where the mapped object `object` — named by its path, or just
    /// the file name at the end of it — was loaded, among the objects
    /// whose symbol table this core carries.
    ///
    /// The tables are keyed by load address and the link map named the
    /// mappings, so the join is through whichever mapping starts where
    /// a table claims its object did.
    fn object_base(&self, object: &str) -> Option<u64> {
        self.symbols.keys().copied().find(|&base| {
            self.mappings
                .get(base)
                .is_some_and(|m| m.path.as_deref() == Some(object) || m.file_name() == Some(object))
        })
    }

    pub fn lookup_symbol_name_by_addr(&self, address: u64) -> Option<String> {
        self.lookup_symbol_by_addr(address).map(|s| s.name)
    }

    /// illumos stores a `thread_local!` under a pthread key, so the
    /// symbol holds the key and the value is in the thread's fast-TSD
    /// slots — the same walk libproc's callers do, over this core's
    /// memory instead.
    pub fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        crate::tls_addr_from_pthread_key(&|addr| self.read_u64(addr), regs, sym)
    }

    /// How far the executable landed from where it was linked, read
    /// from its own program headers when the core was opened. `None`
    /// for a core whose auxiliary vector never named them.
    pub fn exec_bias(&self) -> Option<u64> {
        self.exec_bias
    }
}

/// The `PT_LOAD` regions, each named by whichever loaded object covers
/// it. A region no object covers — a stack, the heap, an anonymous
/// mapping — has no name to give, and says so.
///
/// *Covers* is the whole region, not its first byte. An executable's
/// `.bss` ends wherever it ends, while the mapping backing it stops at
/// a page boundary, so the brk heap that starts there begins inside the
/// executable's own extent — and naming a region by its first byte
/// hands the whole heap, gigabytes of it, the executable's name. That
/// is how a pointer into the heap comes to read as one into the binary.
/// The object's extent is rounded to a page before the comparison,
/// because the kernel maps whole pages and every object's last region
/// therefore ends a little past what its program headers claim.
fn build_mappings(
    segments: &[Segment],
    objects: &[(Range<u64>, String)],
    brk: Option<&Range<u64>>,
) -> Mappings {
    // The base page, which is what the tail of a mapping is rounded to
    // whatever page size backs the rest of it.
    const PAGE: u64 = 0x1000;
    let mapped = |end: u64| end.next_multiple_of(PAGE);

    Mappings {
        inner: segments
            .iter()
            .map(|seg| {
                let end = seg.vaddr.saturating_add(seg.memsz);
                let path = objects
                    .iter()
                    .find(|(range, _)| range.contains(&seg.vaddr) && mapped(range.end) >= end)
                    .map(|(_, name)| name.clone());
                let mut flags = seg.flags & (PF_R | PF_W | PF_X);
                if path.is_none() {
                    flags |= 0x40; // MA_ANON
                    // The break, and only the break, is the heap.
                    // Overlap rather than containment is the test: the
                    // brk *pointer* starts partway into the page the
                    // executable's bss ends in, so the mapping backing
                    // the heap begins below `pr_brkbase` — and asking
                    // whether the mapping starts inside the break
                    // misses the one mapping that is the heap. It can
                    // also be split across several segments by which
                    // pages the dump took.
                    if brk.is_some_and(|b| seg.vaddr < b.end && end > b.start) {
                        flags |= 0x10; // MA_BREAK
                    }
                }
                LoadedObjectWithPath {
                    path,
                    vaddr: seg.vaddr,
                    size: seg.memsz,
                    flags: MapFlags(flags),
                }
            })
            .collect(),
    }
}

/// Read every symbol table the core carries.
///
/// `coreadm`'s default content writes one `.symtab`/`.strtab` pair per
/// mapped object, and sets `sh_addr` to where that object was loaded,
/// which is how the tables are told apart. A core dumped without
/// `symtab` content simply has none, and everything but symbol lookup
/// still works.
fn parse_symbols(elf: &Elf<'_>, bytes: &[u8]) -> BTreeMap<u64, Symbols> {
    let mut out: BTreeMap<u64, Symbols> = BTreeMap::new();

    for sh in elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_type == SHT_SYMTAB)
    {
        let Some(strtab) = elf.section_headers.get(sh.sh_link as usize) else {
            continue;
        };
        let (Some(syms), Some(strs)) = (
            bytes.get(sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize),
            bytes.get(strtab.sh_offset as usize..(strtab.sh_offset + strtab.sh_size) as usize),
        ) else {
            continue;
        };

        let count = syms.len() / SIZEOF_SYM;
        let Ok(entries) = Sym::parse(syms, 0, count, elf_ctx()) else {
            continue;
        };
        // `parse`, not `new`: the latter leaves the table unindexed
        // and every lookup in it comes back empty.
        let Ok(strs) = Strtab::parse(strs, 0, strs.len(), 0) else {
            continue;
        };

        // `sh_addr` is where the object was loaded, but whether its
        // symbols already account for that depends on what kind of
        // object it is: an executable's are absolute, a shared object's
        // are offsets from its base. Nothing in the core says which,
        // and the values themselves do — a table whose lowest symbol is
        // below the address the object was loaded at is one of offsets.
        let bias = entries
            .iter()
            .map(|s| s.st_value)
            .filter(|v| *v != 0)
            .min()
            .filter(|lowest| *lowest < sh.sh_addr)
            .map_or(0, |_| sh.sh_addr);

        let object = out.entry(sh.sh_addr).or_default();
        for entry in entries {
            let Sym {
                st_name,
                st_info,
                st_other,
                st_shndx,
                st_value,
                st_size,
            } = entry;

            let Some(name) = strs.get_at(st_name) else {
                continue;
            };
            if name.is_empty() || st_value == 0 {
                continue;
            }
            // libproc asks for `BIND_GLOBAL | BIND_LOCAL` and so never
            // reports a weak symbol; the rest of this workspace joins
            // on what it returns, so a second reader of the same core
            // has to draw the line in the same place. Weak entries here
            // are aliases and undefined references — `_mcount`,
            // `pthread_setname_np` — that name nothing in this object.
            if st_bind(st_info) == STB_WEAK {
                continue;
            }

            let sym = SymbolBuf {
                name: name.to_string(),
                st_name,
                st_info,
                st_other,
                st_shndx,
                // A thread-local's value is an offset into a TLS block
                // whichever kind of object it came from, so the bias
                // must not touch it.
                st_value: if st_type(st_info) == STT_TLS {
                    st_value
                } else {
                    st_value.wrapping_add(bias)
                },
                st_size,
            };
            match st_type(st_info) {
                STT_FUNC => object.functions.push(sym),
                STT_OBJECT | STT_TLS => object.objects.push(sym),
                _ => {}
            }
        }
    }

    for object in out.values_mut() {
        for list in [&mut object.functions, &mut object.objects] {
            list.sort_by(libproc_order);
            list.dedup_by(|a, b| a.name == b.name && a.st_value == b.st_value);
        }
    }
    out
}

/// libproc's own ordering, transcribed from `byaddr_cmp_common` in
/// `usr/src/lib/libproc/common/Psymtab.c`.
///
/// A linker leaves several names on one address whenever it folds
/// identical code. Sorting puts them in order of address and then, for
/// those sharing one, by a chain of preferences: a function over any
/// other kind of symbol, a global or weak binding over a local one, a
/// name that does not start with `$`, a name with fewer leading
/// underscores, the smaller symbol, and finally lexicographic order of
/// what is left of the names after their common underscores. A lookup
/// takes the first of a tied run, which is the one libproc names.
fn libproc_order(a: &SymbolBuf, b: &SymbolBuf) -> Ordering {
    if a.st_value != b.st_value {
        return a.st_value.cmp(&b.st_value);
    }

    // Prefer the function to the non-function.
    let (a_type, b_type) = (st_type(a.st_info), st_type(b.st_info));
    if a_type != b_type {
        if a_type == STT_FUNC {
            return Ordering::Less;
        }
        if b_type == STT_FUNC {
            return Ordering::Greater;
        }
    }

    // Prefer the weak or strong global symbol to the local symbol.
    let (a_bind, b_bind) = (st_bind(a.st_info), st_bind(b.st_info));
    if a_bind != b_bind {
        if b_bind == STB_LOCAL {
            return Ordering::Less;
        }
        if a_bind == STB_LOCAL {
            return Ordering::Greater;
        }
    }

    // Prefer the name that does not begin with '$', which compilers and
    // other symbol generators use as a prefix.
    let (mut a_name, mut b_name) = (a.name.as_bytes(), b.name.as_bytes());
    if b_name.first() == Some(&b'$') {
        return Ordering::Less;
    }
    if a_name.first() == Some(&b'$') {
        return Ordering::Greater;
    }

    // Prefer the name with fewer leading underscores, and compare what
    // is left of the two rather than the whole of either.
    while a_name.first() == Some(&b'_') && b_name.first() == Some(&b'_') {
        a_name = &a_name[1..];
        b_name = &b_name[1..];
    }
    if b_name.first() == Some(&b'_') {
        return Ordering::Less;
    }
    if a_name.first() == Some(&b'_') {
        return Ordering::Greater;
    }

    // Prefer the smaller symbol, then take them in order.
    a.st_size.cmp(&b.st_size).then_with(|| a_name.cmp(b_name))
}

/// The terminating signal, from the representative lwp's `lwpstatus_t`
/// at the tail of the pstatus — `None` when it was taking no signal,
/// which is every capture `gcore` writes. The embedded `pr_info`
/// refines it: the kernel fills the siginfo alongside `pr_cursig`, and
/// its code and address are believed only when it describes the same
/// signal.
fn decode_fatal_signal(desc: &[u8]) -> Option<FatalSignal> {
    let cursig = i16::from_le_bytes(
        desc[LWPSTATUS_PR_CURSIG..LWPSTATUS_PR_CURSIG + 2]
            .try_into()
            .unwrap(),
    );
    if cursig == 0 {
        return None;
    }
    let signo = i32::from(cursig);
    let name = signal_name(signo)?;
    let tid = u32::from_le_bytes(
        desc[LWPSTATUS_PR_LWPID..LWPSTATUS_PR_LWPID + 4]
            .try_into()
            .unwrap(),
    );
    let info = &desc[LWPSTATUS_PR_INFO..];
    let si_signo = i32::from_le_bytes(info[..4].try_into().unwrap());
    let (code, addr) = match si_signo == signo {
        true => (
            i32::from_le_bytes(info[SI_CODE..SI_CODE + 4].try_into().unwrap()),
            u64::from_le_bytes(info[SI_ADDR..SI_ADDR + 8].try_into().unwrap()),
        ),
        false => (0, 0),
    };
    let code_name = fault_code_name(name, code);
    Some(FatalSignal {
        name,
        signo,
        code,
        code_name,
        fault_addr: code_name.is_some().then_some(addr),
        lwp: Some(tid),
    })
}

fn parse_lwpstatus(desc: &[u8]) -> LwpInfo {
    let tid = u32::from_le_bytes(
        desc[LWPSTATUS_PR_LWPID..LWPSTATUS_PR_LWPID + 4]
            .try_into()
            .unwrap(),
    );
    let mut regs = [0u64; NGREG];
    for (slot, chunk) in regs
        .iter_mut()
        .zip(desc[LWPSTATUS_PR_REG..].chunks_exact(8).take(NGREG))
    {
        *slot = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let at = LWPSTATUS_PR_TSTAMP;
    let tstamp = Timespec {
        tv_sec: i64::from_le_bytes(desc[at..at + 8].try_into().unwrap()),
        tv_nsec: i64::from_le_bytes(desc[at + 8..at + 16].try_into().unwrap()),
    };

    // The `stack_t` is present whether or not the thread registered
    // one; an unregistered alternate stack reads as a null base, which
    // is the empty range rather than a mapping at zero.
    let at = LWPSTATUS_PR_ALTSTACK;
    let ss_sp = u64::from_le_bytes(
        desc[at + STACK_SS_SP as usize..at + STACK_SS_SP as usize + 8]
            .try_into()
            .unwrap(),
    );
    let ss_size = u64::from_le_bytes(
        desc[at + STACK_SS_SIZE as usize..at + STACK_SS_SIZE as usize + 8]
            .try_into()
            .unwrap(),
    );
    let altstack = match ss_sp.checked_add(ss_size) {
        Some(end) if ss_sp != 0 && ss_size != 0 => ss_sp..end,
        _ => 0..0,
    };

    LwpInfo {
        tid,
        regs: Regs::from_gregset(&regs),
        // Filled in from the mappings once they are known.
        stack_range: 0..0,
        altstack,
        tstamp,
    }
}

fn parse_lwpname(desc: &[u8]) -> (u32, String) {
    let tid = u32::from_le_bytes(desc[0..4].try_into().unwrap());
    let raw = &desc[LWPNAME_PR_LWPNAME..LWPNAME_PR_LWPNAME + LWPNAME_MAX];
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    (tid, String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// One `prfdinfo_core_t` out of an `NT_FDINFO` note.
fn parse_fdinfo(desc: &[u8]) -> FdInfo {
    let int = |at: usize| i32::from_le_bytes(desc[at..at + 4].try_into().unwrap());
    let word = |at: usize| u64::from_le_bytes(desc[at..at + 8].try_into().unwrap());
    FdInfo {
        fd: int(0),
        mode: u32::from_le_bytes(desc[FDINFO_PR_MODE..FDINFO_PR_MODE + 4].try_into().unwrap()),
        ino: word(FDINFO_PR_INO),
        offset: word(FDINFO_PR_OFFSET) as i64,
        size: word(FDINFO_PR_SIZE),
        fileflags: int(FDINFO_PR_FILEFLAGS),
        path: super::fixed_str(&desc[FDINFO_PR_PATH..FDINFO_PR_PATH + FDINFO_PATH_LEN]),
    }
}

/// The executable's path, from the command line the process was given.
/// `pr_psargs` is the whole line, so the first word is the path — the
/// nearest an illumos core comes to naming its own executable.
fn parse_psinfo_exec(desc: &[u8]) -> Option<String> {
    let raw = &desc[PSINFO_PR_PSARGS..PSINFO_PR_PSARGS + PSINFO_PSARGS_LEN];
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    let args = std::str::from_utf8(&raw[..end]).ok()?;
    let path = args.split_whitespace().next()?;
    (!path.is_empty()).then(|| path.to_string())
}

// Parallel rendering shares one core across worker threads: reads
// borrow from the mapping and the lazy by-name symbol index is a
// OnceLock, so this holds by construction — and must keep holding.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<Core>();
};

impl Target for Core {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<&[u8]> {
        Core::pslice(self, addr, len).ok_or_else(|| Error::unmapped(addr, len))
    }

    fn fatal_signal(&self) -> Option<FatalSignal> {
        self.fatal.clone()
    }

    fn process_facts(&self) -> Option<ProcessFacts> {
        self.facts.clone()
    }

    fn fds(&self) -> Option<&[FdInfo]> {
        self.fds.as_deref()
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        Core::readable_len(self, addr, max)
    }

    fn lookup_symbol_by_addr(&self, address: u64) -> Option<SymbolBuf> {
        Core::lookup_symbol_by_addr(self, address)
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        Core::lookup_symbol_by_name(self, name)
    }

    fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        Core::symbols(self)
    }

    fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        Core::object_symbols(self)
    }

    fn mappings(&self) -> Result<Mappings> {
        Core::mappings(self)
    }

    fn lwps(&self) -> Result<Vec<LwpInfo>> {
        Core::lwps(self)
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        Core::tls_var_addr(self, regs, sym)
    }

    fn exec_bias(&self) -> Option<u64> {
        Core::exec_bias(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::coredump::testkit::{Load, PAGE, note, phdr, regs_at};

    use goblin::elf::header::{EM_X86_64, ET_CORE, ET_DYN, Header as UnifiedHeader};
    use goblin::elf::program_header::PT_NOTE;
    use goblin::elf::section_header::section_header64::SIZEOF_SHDR;
    use goblin::elf::section_header::{SHT_STRTAB, SectionHeader};
    use goblin::elf::sym::STB_GLOBAL;
    use scroll::Pwrite;

    use std::io::Write;

    /// Builds an illumos `ET_CORE` file in memory, so the reader can be
    /// held to cores a real one is awkward to produce: a symbol table
    /// whose object moved, a link map that loops, a `stack_t` that
    /// cannot be read.
    ///
    /// Unlike the Linux builder next door, nothing here reaches for the
    /// test binary: everything an illumos core reader consumes — the
    /// notes, the per-object symbol tables, the link map — is *in* the
    /// core, so the whole suite synthesizes it and runs on any host.
    #[derive(Default)]
    struct CoreBuilder {
        loads: Vec<Load>,
        /// Raw `(n_type, desc)` pairs, emitted in insertion order.
        notes: Vec<(u32, Vec<u8>)>,
        auxv: Vec<(u64, u64)>,
        /// Per-object symbol tables: `(sh_addr, entries)`.
        symtabs: Vec<(u64, Vec<TestSym>)>,
        /// Emitted verbatim in place of the assembled notes, for the
        /// malformed-core tests.
        raw_notes: Option<Vec<u8>>,
    }

    impl CoreBuilder {
        /// A region whose bytes are all in the core.
        fn dumped(self, vaddr: u64, flags: u32, bytes: Vec<u8>) -> Self {
            let memsz = bytes.len() as u64;
            self.partial(vaddr, memsz, flags, bytes)
        }

        /// A region absent from the file: in the address space, with
        /// nothing dumped.
        fn undumped(self, vaddr: u64, memsz: u64, flags: u32) -> Self {
            self.partial(vaddr, memsz, flags, Vec::new())
        }

        /// A region only the front of which was written out.
        fn partial(mut self, vaddr: u64, memsz: u64, flags: u32, bytes: Vec<u8>) -> Self {
            self.loads.push(Load {
                vaddr,
                memsz,
                flags,
                bytes,
            });
            self
        }

        fn thread(self, tid: u32, regs: Regs) -> Self {
            self.thread_with_ustack(tid, regs, 0)
        }

        fn thread_with_ustack(self, tid: u32, regs: Regs, ustack: u64) -> Self {
            let zero = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            self.note(NT_LWPSTATUS, lwpstatus(tid, &regs, ustack, zero))
        }

        /// A crash core's signal record, as the kernel writes it: the
        /// faulting lwp's own note, plus an `NT_PSTATUS` whose
        /// representative lwp — the tail `lwpstatus_t` — is that lwp
        /// taking `cursig`, details in the embedded `pr_info`.
        /// An `NT_PSTATUS` carrying only the break extent — what the
        /// kernel records and `pmap` reads to say `[ heap ]`.
        fn brk(self, base: u64, size: u64) -> Self {
            let mut desc = vec![0u8; PSTATUS_TEST_LEN];
            desc[PSTATUS_PR_BRKBASE..PSTATUS_PR_BRKBASE + 8].copy_from_slice(&base.to_le_bytes());
            desc[PSTATUS_PR_BRKSIZE..PSTATUS_PR_BRKSIZE + 8].copy_from_slice(&size.to_le_bytes());
            self.note(NT_PSTATUS, desc)
        }

        fn crashed(self, tid: u32, regs: Regs, cursig: i16, code: i32, addr: u64) -> Self {
            let lwp = lwpstatus_taking(tid, &regs, cursig, code, addr);
            let mut desc = vec![0u8; PSTATUS_TEST_LEN];
            let at = desc.len() - LWPSTATUS_LEN;
            desc[at..].copy_from_slice(&lwp);
            self.thread(tid, regs).note(NT_PSTATUS, desc)
        }

        /// A sibling lwp the kernel stopped while dumping: its own
        /// note records the `SIGKILL` that stopped it, exactly the
        /// spelling that must never read as what killed the process.
        fn sigkilled_thread(self, tid: u32, regs: Regs) -> Self {
            self.note(NT_LWPSTATUS, lwpstatus_taking(tid, &regs, 9, 0, 0))
        }

        fn lwp_name(self, tid: u32, name: &str) -> Self {
            self.note(NT_LWPNAME, lwpname(tid, name))
        }

        fn psargs(self, args: &str) -> Self {
            self.note(NT_PSINFO, psinfo(args))
        }

        fn auxv(mut self, tag: u64, val: u64) -> Self {
            self.auxv.push((tag, val));
            self
        }

        fn note(mut self, ntype: u32, desc: Vec<u8>) -> Self {
            self.notes.push((ntype, desc));
            self
        }

        fn symtab(mut self, addr: u64, syms: Vec<TestSym>) -> Self {
            self.symtabs.push((addr, syms));
            self
        }

        fn build(&self) -> Vec<u8> {
            let notes = self
                .raw_notes
                .clone()
                .unwrap_or_else(|| self.assemble_notes());

            // Header, then one phdr per note/load segment, the note and
            // load bodies, the section bodies, and the section header
            // table last — where illumos also puts sections, which is
            // why a size-truncated core loses them first.
            let phnum = 1 + self.loads.len();
            let mut offset = (SIZEOF_EHDR + phnum * SIZEOF_PHDR) as u64;
            let note_offset = offset;
            offset += notes.len() as u64;

            let mut phdrs = Vec::new();
            phdrs.extend(phdr(PT_NOTE, 0, note_offset, 0, notes.len() as u64, 0, 4));
            for load in &self.loads {
                phdrs.extend(phdr(
                    PT_LOAD,
                    load.flags,
                    offset,
                    load.vaddr,
                    load.bytes.len() as u64,
                    load.memsz,
                    PAGE,
                ));
                offset += load.bytes.len() as u64;
            }

            // One `.symtab`/`.strtab` pair per object, `sh_addr` naming
            // where the object was loaded — `coreadm`'s default content.
            let mut bodies = Vec::new();
            let mut shdrs = vec![SectionHeader::default()];
            for (addr, syms) in &self.symtabs {
                let (table, strs) = symtab_section(syms);
                shdrs.push(SectionHeader {
                    sh_type: SHT_SYMTAB,
                    sh_addr: *addr,
                    sh_offset: offset + bodies.len() as u64,
                    sh_size: table.len() as u64,
                    sh_link: (shdrs.len() + 1) as u32,
                    sh_entsize: SIZEOF_SYM as u64,
                    ..SectionHeader::default()
                });
                bodies.extend(table);
                shdrs.push(SectionHeader {
                    sh_type: SHT_STRTAB,
                    sh_offset: offset + bodies.len() as u64,
                    sh_size: strs.len() as u64,
                    ..SectionHeader::default()
                });
                bodies.extend(strs);
            }
            let shoff = offset + bodies.len() as u64;

            let mut out = Vec::new();
            let shnum = if self.symtabs.is_empty() {
                0
            } else {
                shdrs.len() as u16
            };
            out.extend(elf_header(ET_CORE, phnum as u16, shnum, shoff));
            out.extend(phdrs);
            out.extend(&notes);
            for load in &self.loads {
                out.extend(&load.bytes);
            }
            out.extend(bodies);
            if shnum > 0 {
                for sh in shdrs {
                    let mut buf = vec![0u8; SIZEOF_SHDR];
                    buf.pwrite_with(sh, 0, elf_ctx())
                        .expect("failed to write a section header");
                    out.extend(buf);
                }
            }
            out
        }

        fn assemble_notes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for (ntype, desc) in &self.notes {
                out.extend(note(*ntype, "CORE", desc));
            }
            if !self.auxv.is_empty() {
                let mut desc = Vec::new();
                for (tag, val) in &self.auxv {
                    desc.extend(tag.to_le_bytes());
                    desc.extend(val.to_le_bytes());
                }
                desc.extend([0u8; 16]);
                out.extend(note(NT_AUXV, "CORE", &desc));
            }
            out
        }

        /// Write the core to a file and open it, the way a caller does.
        fn open(&self) -> (tempfile::TempDir, Result<Core>) {
            let dir = tempfile::tempdir().expect("failed to create a tempdir");
            let path = dir.path().join("core");
            let mut f = File::create(&path).expect("failed to create the core");
            f.write_all(&self.build())
                .expect("failed to write the core");
            drop(f);
            let proc = Core::open(&path);
            (dir, proc)
        }

        fn proc(&self) -> (tempfile::TempDir, Core) {
            let (dir, proc) = self.open();
            (dir, proc.expect("failed to open the core"))
        }
    }

    /// An ELF header, written through goblin rather than by hand: a
    /// builder that lays out its own fields can put one at the wrong
    /// offset and produce a fixture that is merely malformed, which is
    /// a confusing way for a test of a parser to fail.
    fn elf_header(e_type: u16, phnum: u16, shnum: u16, shoff: u64) -> Vec<u8> {
        let mut header = UnifiedHeader::new(elf_ctx());
        header.e_type = e_type;
        header.e_machine = EM_X86_64;
        header.e_phoff = SIZEOF_EHDR as u64;
        header.e_phentsize = SIZEOF_PHDR as u16;
        header.e_phnum = phnum;
        if shnum > 0 {
            header.e_shoff = shoff;
            header.e_shentsize = SIZEOF_SHDR as u16;
            header.e_shnum = shnum;
            header.e_shstrndx = 0;
        }

        let mut out = vec![0u8; SIZEOF_EHDR];
        out.pwrite_with(header, 0, scroll::Endian::Little)
            .expect("failed to write the ELF header");
        out
    }

    /// The inverse of [`Regs::from_gregset`], for building notes. The
    /// slot order itself is pinned by writing raw slots in
    /// [`test_registers_decode_in_illumos_order`], so a mistake shared
    /// with the decoder cannot hide here.
    fn gregset(regs: &Regs) -> [u64; NGREG] {
        let mut r = [0u64; NGREG];
        r[REG_R15] = regs.r15;
        r[REG_R14] = regs.r14;
        r[REG_R13] = regs.r13;
        r[REG_R12] = regs.r12;
        r[REG_R11] = regs.r11;
        r[REG_R10] = regs.r10;
        r[REG_R9] = regs.r9;
        r[REG_R8] = regs.r8;
        r[REG_RDI] = regs.rdi;
        r[REG_RSI] = regs.rsi;
        r[REG_RBP] = regs.rbp;
        r[REG_RBX] = regs.rbx;
        r[REG_RDX] = regs.rdx;
        r[REG_RCX] = regs.rcx;
        r[REG_RAX] = regs.rax;
        r[REG_TRAPNO] = regs.trapno;
        r[REG_ERR] = regs.err;
        r[REG_RIP] = regs.rip;
        r[REG_CS] = regs.cs;
        r[REG_RFL] = regs.rfl;
        r[REG_RSP] = regs.rsp;
        r[REG_SS] = regs.ss;
        r[REG_FS] = regs.fs;
        r[REG_GS] = regs.gs;
        r[REG_ES] = regs.es;
        r[REG_DS] = regs.ds;
        r[REG_FSBASE] = regs.fsbase;
        r[REG_GSBASE] = regs.gsbase;
        r
    }

    fn lwpstatus(tid: u32, regs: &Regs, ustack: u64, tstamp: Timespec) -> Vec<u8> {
        let mut out = vec![0u8; LWPSTATUS_LEN];
        out[LWPSTATUS_PR_LWPID..LWPSTATUS_PR_LWPID + 4].copy_from_slice(&tid.to_le_bytes());
        let at = LWPSTATUS_PR_TSTAMP;
        out[at..at + 8].copy_from_slice(&tstamp.tv_sec.to_le_bytes());
        out[at + 8..at + 16].copy_from_slice(&tstamp.tv_nsec.to_le_bytes());
        let at = LWPSTATUS_PR_USTACK;
        out[at..at + 8].copy_from_slice(&ustack.to_le_bytes());
        for (i, v) in gregset(regs).iter().enumerate() {
            let at = LWPSTATUS_PR_REG + i * 8;
            out[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// The size of the `pstatus_t` an illumos kernel writes today; the
    /// reader tail-anchors the embedded lwpstatus rather than trusting
    /// this, but the fixture matches reality.
    const PSTATUS_TEST_LEN: usize = 1680;

    /// An lwpstatus caught taking `cursig`: `pr_cursig` set and the
    /// embedded `pr_info` filled the way the kernel fills them.
    fn lwpstatus_taking(tid: u32, regs: &Regs, cursig: i16, code: i32, addr: u64) -> Vec<u8> {
        let zero = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut desc = lwpstatus(tid, regs, 0, zero);
        desc[LWPSTATUS_PR_CURSIG..LWPSTATUS_PR_CURSIG + 2].copy_from_slice(&cursig.to_le_bytes());
        let info = LWPSTATUS_PR_INFO;
        desc[info..info + 4].copy_from_slice(&i32::from(cursig).to_le_bytes());
        desc[info + SI_CODE..info + SI_CODE + 4].copy_from_slice(&code.to_le_bytes());
        desc[info + SI_ADDR..info + SI_ADDR + 8].copy_from_slice(&addr.to_le_bytes());
        desc
    }

    fn lwpname(tid: u32, name: &str) -> Vec<u8> {
        let mut out = vec![0u8; LWPNAME_LEN];
        out[0..4].copy_from_slice(&tid.to_le_bytes());
        let bytes = name.as_bytes();
        let len = bytes.len().min(LWPNAME_MAX);
        out[LWPNAME_PR_LWPNAME..LWPNAME_PR_LWPNAME + len].copy_from_slice(&bytes[..len]);
        out
    }

    fn psinfo(psargs: &str) -> Vec<u8> {
        let mut out = vec![0u8; PSINFO_LEN];
        let bytes = psargs.as_bytes();
        let len = bytes.len().min(PSINFO_PSARGS_LEN);
        out[PSINFO_PR_PSARGS..PSINFO_PR_PSARGS + len].copy_from_slice(&bytes[..len]);
        out
    }

    /// A psinfo carrying the whole identity the decoder reads: fixed
    /// ids, an LP64 model, a start time, and the argv/envp pointers a
    /// test lays into a dumped region (zero to record none).
    fn psinfo_ident(psargs: &str, fname: &str, argc: u32, argv: u64, envp: u64) -> Vec<u8> {
        let mut out = psinfo(psargs);
        out[PSINFO_PR_PID..PSINFO_PR_PID + 4].copy_from_slice(&4242i32.to_le_bytes());
        out[PSINFO_PR_PPID..PSINFO_PR_PPID + 4].copy_from_slice(&41i32.to_le_bytes());
        out[PSINFO_PR_UID..PSINFO_PR_UID + 4].copy_from_slice(&100u32.to_le_bytes());
        out[PSINFO_PR_EUID..PSINFO_PR_EUID + 4].copy_from_slice(&0u32.to_le_bytes());
        out[PSINFO_PR_GID..PSINFO_PR_GID + 4].copy_from_slice(&10u32.to_le_bytes());
        out[PSINFO_PR_EGID..PSINFO_PR_EGID + 4].copy_from_slice(&0u32.to_le_bytes());
        out[PSINFO_PR_START..PSINFO_PR_START + 8].copy_from_slice(&1_785_706_353i64.to_le_bytes());
        out[PSINFO_PR_START + 8..PSINFO_PR_START + 16].copy_from_slice(&5i64.to_le_bytes());
        let name = fname.as_bytes();
        out[PSINFO_PR_FNAME..PSINFO_PR_FNAME + name.len()].copy_from_slice(name);
        out[PSINFO_PR_ARGC..PSINFO_PR_ARGC + 4].copy_from_slice(&argc.to_le_bytes());
        out[PSINFO_PR_ARGV..PSINFO_PR_ARGV + 8].copy_from_slice(&argv.to_le_bytes());
        out[PSINFO_PR_ENVP..PSINFO_PR_ENVP + 8].copy_from_slice(&envp.to_le_bytes());
        out[PSINFO_PR_DMODEL] = PR_MODEL_LP64;
        out
    }

    /// One entry for a synthesized `.symtab` section.
    struct TestSym {
        name: &'static str,
        info: u8,
        value: u64,
        size: u64,
    }

    const FUNC: u8 = (STB_GLOBAL << 4) | STT_FUNC;
    const LOCAL_FUNC: u8 = (STB_LOCAL << 4) | STT_FUNC;
    const WEAK_FUNC: u8 = (STB_WEAK << 4) | STT_FUNC;
    const OBJECT: u8 = (STB_GLOBAL << 4) | STT_OBJECT;
    const TLS: u8 = (STB_GLOBAL << 4) | STT_TLS;

    fn sym(name: &'static str, info: u8, value: u64, size: u64) -> TestSym {
        TestSym {
            name,
            info,
            value,
            size,
        }
    }

    fn symtab_section(syms: &[TestSym]) -> (Vec<u8>, Vec<u8>) {
        let mut strtab = vec![0u8];
        let mut table = Vec::new();
        for s in syms {
            let st_name = strtab.len();
            strtab.extend(s.name.as_bytes());
            strtab.push(0);
            let entry = Sym {
                st_name,
                st_info: s.info,
                st_other: 0,
                st_shndx: 1,
                st_value: s.value,
                st_size: s.size,
            };
            let mut buf = vec![0u8; SIZEOF_SYM];
            buf.pwrite_with(entry, 0, elf_ctx())
                .expect("failed to write a symbol");
            table.extend(buf);
        }
        (table, strtab)
    }

    /// Lays structures into one region at chosen offsets — the link-map
    /// structures the walk reads out of the target's memory.
    struct Region {
        base: u64,
        bytes: Vec<u8>,
    }

    impl Region {
        fn new(base: u64, len: usize) -> Self {
            Region {
                base,
                bytes: vec![0; len],
            }
        }

        fn put(&mut self, off: usize, bytes: &[u8]) {
            self.bytes[off..off + bytes.len()].copy_from_slice(bytes);
        }

        fn put_u64(&mut self, off: usize, val: u64) {
            self.put(off, &val.to_le_bytes());
        }

        /// The region is zeroed, so the terminating NUL is already
        /// there.
        fn put_str(&mut self, off: usize, s: &str) {
            self.put(off, s.as_bytes());
        }

        fn addr(&self, off: usize) -> u64 {
            self.base + off as u64
        }
    }

    /// An ELF image as the runtime linker mapped it — header then
    /// program headers, which is all `object_span` and the `r_debug`
    /// walk read of one.
    fn image(base: u64, e_type: u16, phdrs: &[(u32, u64, u64)]) -> Region {
        let mut region = Region::new(base, PAGE as usize);
        region.put(0, &elf_header(e_type, phdrs.len() as u16, 0, 0));
        let mut at = SIZEOF_EHDR;
        for (p_type, vaddr, memsz) in phdrs {
            region.put(at, &phdr(*p_type, PF_R, 0, *vaddr, *memsz, *memsz, PAGE));
            at += SIZEOF_PHDR;
        }
        region
    }

    fn names(syms: Vec<SymbolBuf>) -> Vec<String> {
        syms.into_iter().map(|s| s.name).collect()
    }

    // -----------------------------------------------------------------------
    // Memory
    // -----------------------------------------------------------------------

    #[test]
    fn test_reads_come_from_the_core() {
        let bytes: Vec<u8> = (0..=255).cycle().take(PAGE as usize).collect();
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, bytes.clone())
            .proc();

        assert_eq!(p.read_bytes(0x9000, 16).unwrap(), &bytes[..16]);
        assert_eq!(p.read_bytes(0x9100, 8).unwrap(), &bytes[0x100..0x108]);
        assert_eq!(
            p.read_u64(0x9000).unwrap(),
            u64::from_le_bytes(bytes[..8].try_into().unwrap())
        );
        // The last byte of the region, and one past it.
        assert!(p.read_bytes(0x9000 + PAGE - 1, 1).is_ok());
        assert!(p.read_bytes(0x9000 + PAGE - 1, 2).is_err());
    }

    #[test]
    fn test_unmapped_reads_fail() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0xaa; PAGE as usize])
            .proc();

        assert!(p.read_bytes(0x1000, 8).is_err());
        assert!(p.read_bytes(0x9000 + PAGE, 8).is_err());
        // A read starting inside but running past the end.
        assert!(p.read_bytes(0x9000 + PAGE - 4, 8).is_err());
        assert!(p.read_bytes(u64::MAX - 4, 8).is_err());
    }

    /// An illumos core has no backing-file map to fall back on: an
    /// undumped tail is in the address space, and reads as nothing.
    #[test]
    fn test_the_undumped_tail_reads_as_nothing() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .partial(0x9000, 2 * PAGE, PF_R | PF_W, vec![0x5a; PAGE as usize])
            .undumped(0x20000, PAGE, PF_R | PF_X)
            .proc();

        // The dumped front reads; the tail and the fully undumped
        // region do not, and a read straddling the seam fails whole.
        assert_eq!(p.read_bytes(0x9000, 4).unwrap(), [0x5a; 4]);
        assert!(p.read_bytes(0x9000 + PAGE, 8).is_err());
        assert!(p.read_bytes(0x9000 + PAGE - 4, 8).is_err());
        assert!(p.read_bytes(0x20000, 8).is_err());

        // `readable_len` promises exactly what `pslice` can lend.
        assert_eq!(p.readable_len(0x9000, u64::MAX), PAGE);
        assert_eq!(p.readable_len(0x9000 + PAGE - 4, u64::MAX), 4);
        assert_eq!(p.readable_len(0x9000, 16), 16);
        assert_eq!(p.readable_len(0x9000 + PAGE, 8), 0);
        assert_eq!(p.readable_len(0x20000, 8), 0);
        assert_eq!(p.readable_len(0xdead_0000, 8), 0);
        assert!(p.pslice(0x9000, PAGE).is_some());
        assert!(p.pslice(0x9000 + PAGE - 4, 8).is_none());

        // Undumped is still mapped: the address space is the program
        // headers' business, whatever was written out.
        assert!(p.addr_is_mapped(0x9000 + 2 * PAGE - 1));
        assert!(!p.addr_is_mapped(0x9000 + 2 * PAGE));
        assert!(p.addr_is_mapped(0x20000));
    }

    /// What one segment cannot serve, the core does not serve: a read
    /// crossing two segments fails even where both sides are dumped.
    #[test]
    fn test_reads_do_not_span_segments() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0x11; PAGE as usize])
            .dumped(0xa000, PF_R | PF_W, vec![0x22; PAGE as usize])
            .proc();

        assert_eq!(p.read_bytes(0x9fff, 1).unwrap(), [0x11]);
        assert_eq!(p.read_bytes(0xa000, 1).unwrap(), [0x22]);
        assert!(p.read_bytes(0x9ffc, 8).is_err());
    }

    // -----------------------------------------------------------------------
    // Threads
    // -----------------------------------------------------------------------

    /// The register slots decode at illumos's `REG_*` indices — written
    /// raw here, slot `i` holding `1000 + i`, so this pins the index
    /// table itself rather than round-tripping the builder's inverse.
    #[test]
    fn test_registers_decode_in_illumos_order() {
        let mut desc = lwpstatus(
            7,
            &Regs::default(),
            0,
            Timespec {
                tv_sec: 5,
                tv_nsec: 6,
            },
        );
        for i in 0..NGREG {
            let at = LWPSTATUS_PR_REG + i * 8;
            desc[at..at + 8].copy_from_slice(&(1000 + i as u64).to_le_bytes());
        }
        let (_dir, p) = CoreBuilder::default()
            .note(NT_LWPSTATUS, desc)
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        let lwp = &p.lwps().unwrap()[0];
        assert_eq!(lwp.tid, 7);
        assert_eq!(
            lwp.tstamp,
            Timespec {
                tv_sec: 5,
                tv_nsec: 6
            }
        );
        let want = Regs {
            r15: 1000,
            r14: 1001,
            r13: 1002,
            r12: 1003,
            r11: 1004,
            r10: 1005,
            r9: 1006,
            r8: 1007,
            rdi: 1008,
            rsi: 1009,
            rbp: 1010,
            rbx: 1011,
            rdx: 1012,
            rcx: 1013,
            rax: 1014,
            trapno: 1015,
            err: 1016,
            rip: 1017,
            cs: 1018,
            rfl: 1019,
            rsp: 1020,
            ss: 1021,
            fs: 1022,
            gs: 1023,
            es: 1024,
            ds: 1025,
            fsbase: 1026,
            gsbase: 1027,
        };
        assert_eq!(lwp.regs, want);
    }

    /// Threads sort by id whatever order their notes came in, and each
    /// keeps its own `pr_ustack` through the sort.
    #[test]
    fn test_threads_sort_by_tid() {
        let mut stacks = Region::new(0x8000, PAGE as usize);
        stacks.put_u64(0, 0x10_0000);
        stacks.put_u64(8, 4 * PAGE);
        stacks.put_u64(16, 0x20_0000);
        stacks.put_u64(24, 8 * PAGE);

        let (_dir, p) = CoreBuilder::default()
            .thread_with_ustack(43, regs_at(0, 0x9000), stacks.addr(16))
            .thread_with_ustack(42, regs_at(0, 0x9000), stacks.addr(0))
            .dumped(0x8000, PF_R | PF_W, stacks.bytes)
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        let lwps = p.lwps().unwrap();
        assert_eq!(lwps.len(), 2);
        assert_eq!(lwps[0].tid, 42);
        assert_eq!(lwps[0].stack_range, 0x10_0000..0x10_0000 + 4 * PAGE);
        assert_eq!(lwps[1].tid, 43);
        assert_eq!(lwps[1].stack_range, 0x20_0000..0x20_0000 + 8 * PAGE);
        // Registers are also reachable by thread id.
        assert!(p.regs(43).is_ok());
        assert!(p.regs(99).is_err());
        assert_eq!(p.status().active_lwp, 42);
        assert_eq!(p.status().stack_range, 0x10_0000..0x10_0000 + 4 * PAGE);
    }

    /// A crash core names its faulting lwp through the pstatus's
    /// representative lwp, not by position: the per-lwp notes come in
    /// id order, so the lwp that took the signal is usually not first.
    /// The signal is decoded with illumos's own numbering — 10 is
    /// `SIGBUS` here, `SIGUSR1` on Linux — and the faulting lwp becomes
    /// the current one, stack and all.
    #[test]
    fn test_the_faulting_lwp_carries_the_fatal_signal() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .crashed(2, regs_at(0, 0x18000), 10, 2, 0xdead_b000)
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(0x18000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        assert_eq!(
            p.fatal_signal(),
            Some(FatalSignal {
                name: "SIGBUS",
                signo: 10,
                code: 2,
                code_name: Some("BUS_ADRERR"),
                fault_addr: Some(0xdead_b000),
                lwp: Some(2),
            })
        );
        let status = p.status();
        assert_eq!(status.active_lwp, 2);
        assert_eq!(status.stack_range, p.lwps().unwrap()[1].stack_range);
    }

    /// While dumping, the kernel stops the faulting lwp's siblings
    /// with `SIGKILL`, and each sibling's own lwpstatus records it —
    /// with the lowest id sorting first. What killed the process is
    /// the representative lwp's signal, never a sibling's.
    #[test]
    fn test_stopped_siblings_are_not_the_death() {
        let (_dir, p) = CoreBuilder::default()
            .sigkilled_thread(1, regs_at(0, 0x9000))
            .crashed(2, regs_at(0, 0x18000), 11, 1, 0)
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(0x18000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        let fatal = p.fatal_signal().unwrap();
        assert_eq!((fatal.name, fatal.lwp), ("SIGSEGV", Some(2)));
        assert_eq!(p.status().active_lwp, 2);
    }

    /// A truncated `NT_PSTATUS` holds no representative lwp, and is
    /// skipped rather than sliced past its end.
    #[test]
    fn test_a_short_pstatus_note_is_skipped() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .note(NT_PSTATUS, vec![0u8; 64])
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        assert_eq!(p.fatal_signal(), None);
    }

    /// A sibling's recorded `SIGKILL` with no pstatus signal behind it
    /// is not a death either — nothing is, without the representative
    /// lwp saying so.
    #[test]
    fn test_a_sibling_signal_alone_records_no_death() {
        let (_dir, p) = CoreBuilder::default()
            .sigkilled_thread(1, regs_at(0, 0x9000))
            .thread(2, regs_at(0, 0x18000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        assert_eq!(p.fatal_signal(), None);
    }

    /// A capture taken live — `gcore`, with no lwp taking a signal —
    /// records no death, and the current lwp falls back to the first.
    #[test]
    fn test_a_live_capture_records_no_signal() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .thread(2, regs_at(0, 0x18000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        assert_eq!(p.fatal_signal(), None);
        assert_eq!(p.status().active_lwp, 1);
    }

    /// The name table covers illumos's whole range — the named set,
    /// then the real-time spellings — and refuses numbers beyond it.
    #[test]
    fn test_illumos_signal_names_cover_the_range() {
        assert_eq!(signal_name(10), Some("SIGBUS"));
        assert_eq!(signal_name(41), Some("SIGINFO"));
        assert_eq!(signal_name(42), Some("SIGRTMIN"));
        assert_eq!(signal_name(73), Some("SIGRTMAX"));
        assert_eq!(signal_name(0), None);
        assert_eq!(signal_name(74), None);
    }

    /// The stack comes from the `stack_t` at `pr_ustack`, read out of
    /// the core's own memory: the whole reservation the thread was
    /// given, not the pages the program headers happen to show.
    #[test]
    fn test_the_stack_comes_from_ustack() {
        let mut stack_t = Region::new(0x8000, PAGE as usize);
        stack_t.put_u64(0, 0x7000_0000);
        stack_t.put_u64(8, 0xa0_0000); // ten megabytes, none of it dumped

        let (_dir, p) = CoreBuilder::default()
            .thread_with_ustack(1, regs_at(0, 0x9000), stack_t.addr(0))
            .dumped(0x8000, PF_R | PF_W, stack_t.bytes)
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        assert_eq!(
            p.lwps().unwrap()[0].stack_range,
            0x7000_0000..0x7000_0000 + 0xa0_0000
        );
    }

    /// A thread whose `stack_t` cannot be read — no pointer, an
    /// unmapped one, or a zeroed structure — falls back to the region
    /// holding `%rsp`; a thread whose `%rsp` is nowhere gets nothing.
    #[test]
    fn test_an_unreadable_ustack_falls_back_to_rsp() {
        let (_dir, p) = CoreBuilder::default()
            .thread_with_ustack(1, regs_at(0, 0x9800), 0)
            .thread_with_ustack(2, regs_at(0, 0x9800), 0xdead_0000)
            .thread_with_ustack(3, regs_at(0, 0x9800), 0x8000)
            .thread_with_ustack(4, regs_at(0, 0xffff_0000), 0)
            .dumped(0x8000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        let lwps = p.lwps().unwrap();
        for lwp in &lwps[..3] {
            assert_eq!(lwp.stack_range, 0x9000..0x9000 + PAGE, "lwp {}", lwp.tid);
        }
        assert_eq!(lwps[3].stack_range, 0..0);
    }

    #[test]
    fn test_lwp_names_come_from_their_note() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .thread(2, regs_at(0, 0x9000))
            .lwp_name(1, "tokio-runtime-w")
            .lwp_name(2, "")
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        assert_eq!(p.lwp_name(1).unwrap(), "tokio-runtime-w");
        // An empty name is no name, and an unknown thread has none.
        assert!(p.lwp_name(2).is_err());
        assert!(p.lwp_name(9).is_err());

        // The Target facade answers the same, as an Option: this is
        // the spelling the thread listing reads.
        let target = crate::Proc::IllumosCore(p);
        assert_eq!(
            crate::Target::lwp_name(&target, 1).as_deref(),
            Some("tokio-runtime-w")
        );
        assert_eq!(crate::Target::lwp_name(&target, 2), None);
        assert_eq!(crate::Target::lwp_name(&target, 9), None);
    }

    /// The first word of `pr_psargs` names the executable — the nearest
    /// an illumos core comes to naming its own — and the first
    /// `NT_PSINFO` wins.
    #[test]
    fn test_psinfo_names_the_executable() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .psargs("/opt/oxide/sled-agent run --config /var/x.toml")
            .psargs("/second/prog")
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();
        assert_eq!(
            p.exec_name().unwrap(),
            PathBuf::from("/opt/oxide/sled-agent")
        );

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();
        assert!(p.exec_name().is_err());
    }

    /// The psinfo's identity fields decode whole, and the argv/envp
    /// pointers are followed into the dumped image for the full
    /// command line and environment.
    #[test]
    fn test_psinfo_decodes_the_process_identity() {
        // Pointer arrays and their strings, laid into one dumped page.
        let base = 0x8000u64;
        let mut data = vec![0u8; PAGE as usize];
        let mut put = |at: u64, bytes: &[u8]| {
            let at = (at - base) as usize;
            data[at..at + bytes.len()].copy_from_slice(bytes);
        };
        put(0x8100, b"/opt/prog\0");
        put(0x8110, b"--flag\0");
        put(0x8120, b"HOME=/root\0");
        put(0x8130, b"TZ=UTC\0");
        put(0x8000, &0x8100u64.to_le_bytes());
        put(0x8008, &0x8110u64.to_le_bytes());
        put(0x8040, &0x8120u64.to_le_bytes());
        put(0x8048, &0x8130u64.to_le_bytes());
        // 0x8050 stays zero: the environment's terminating null.

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .note(
                NT_PSINFO,
                psinfo_ident("/opt/prog --flag", "prog", 2, 0x8000, 0x8040),
            )
            .dumped(base, PF_R | PF_W, data)
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        let facts = crate::Target::process_facts(&p).expect("psinfo decodes");
        assert_eq!(facts.pid, 4242);
        assert_eq!(facts.ppid, 41);
        assert_eq!(facts.uid, 100);
        assert_eq!(facts.euid, Some(0));
        assert_eq!(facts.gid, 10);
        assert_eq!(facts.egid, Some(0));
        assert_eq!(facts.model, Some("LP64"));
        let start = facts.start.expect("pr_start is recorded");
        assert_eq!((start.tv_sec, start.tv_nsec), (1_785_706_353, 5));
        assert_eq!(facts.fname, "prog");
        assert_eq!(facts.psargs, "/opt/prog --flag");
        assert_eq!(
            facts.argv.as_deref(),
            Some(&["/opt/prog".to_string(), "--flag".to_string()][..])
        );
        assert_eq!(
            facts.env.as_deref(),
            Some(&["HOME=/root".to_string(), "TZ=UTC".to_string()][..])
        );
        assert_eq!(facts.execfn, None);
    }

    /// One `prfdinfo_core_t` for the test's builder: fd, mode, size,
    /// and a path (empty for the fds the kernel names none for).
    fn fdinfo(fd: i32, mode: u32, size: u64, path: &str) -> Vec<u8> {
        let mut out = vec![0u8; FDINFO_LEN];
        out[0..4].copy_from_slice(&fd.to_le_bytes());
        out[FDINFO_PR_MODE..FDINFO_PR_MODE + 4].copy_from_slice(&mode.to_le_bytes());
        out[FDINFO_PR_INO..FDINFO_PR_INO + 8].copy_from_slice(&77u64.to_le_bytes());
        out[FDINFO_PR_OFFSET..FDINFO_PR_OFFSET + 8].copy_from_slice(&9i64.to_le_bytes());
        out[FDINFO_PR_SIZE..FDINFO_PR_SIZE + 8].copy_from_slice(&size.to_le_bytes());
        out[FDINFO_PR_FILEFLAGS..FDINFO_PR_FILEFLAGS + 4].copy_from_slice(&2i32.to_le_bytes());
        out[FDINFO_PR_PATH..FDINFO_PR_PATH + path.len()].copy_from_slice(path.as_bytes());
        out
    }

    /// Every `NT_FDINFO` note decodes into the fd table, in fd order
    /// whatever order the notes came in; a socket's path is empty, the
    /// way the kernel writes it. A core without the notes has no table
    /// — a different answer from an empty one.
    #[test]
    fn test_fdinfo_notes_decode_into_the_fd_table() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .note(NT_FDINFO, fdinfo(4, 0o140666, 0, ""))
            .note(NT_FDINFO, fdinfo(1, 0o100644, 4096, "/var/log/x.log"))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        let fds = crate::Target::fds(&p).expect("the fd table decodes");
        assert_eq!(fds.len(), 2);
        assert_eq!(fds[0].fd, 1);
        assert_eq!(fds[0].mode, 0o100644);
        assert_eq!(fds[0].ino, 77);
        assert_eq!(fds[0].offset, 9);
        assert_eq!(fds[0].size, 4096);
        assert_eq!(fds[0].fileflags, 2);
        assert_eq!(fds[0].path, "/var/log/x.log");
        assert_eq!(fds[1].fd, 4);
        assert_eq!(fds[1].mode, 0o140666);
        assert_eq!(fds[1].path, "");

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();
        assert_eq!(crate::Target::fds(&p), None);
    }

    /// The ids survive an argv the dump does not carry — the pointers
    /// are followed only as far as the dump allows, and a partial
    /// answer is not invented — and a core with no psinfo at all has
    /// no facts.
    #[test]
    fn test_process_facts_survive_an_unreadable_argv() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .note(
                NT_PSINFO,
                psinfo_ident("/opt/prog", "prog", 1, 0xdead_0000, 0),
            )
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();
        let facts = crate::Target::process_facts(&p).expect("psinfo decodes");
        assert_eq!(facts.pid, 4242);
        assert_eq!(facts.argv, None);
        assert_eq!(facts.env, None);

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();
        assert_eq!(crate::Target::process_facts(&p), None);
    }

    // -----------------------------------------------------------------------
    // Malformed cores
    // -----------------------------------------------------------------------

    /// Notes shorter than the structures they claim are ignored rather
    /// than misread; what remains decides whether the core stands.
    #[test]
    fn test_short_notes_are_ignored() {
        // A core whose only LWPSTATUS is short has no threads at all.
        let (_dir, res) = CoreBuilder::default()
            .note(NT_LWPSTATUS, vec![0; 100])
            .dumped(0x9000, PF_R | PF_W, vec![0; 8])
            .open();
        assert_eq!(
            res.unwrap_err().to_string(),
            "malformed core file: no NT_LWPSTATUS note"
        );

        // Beside a whole thread, short name and psinfo notes just
        // contribute nothing.
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .note(NT_LWPNAME, vec![0; 8])
            .note(NT_PSINFO, vec![0; 50])
            .dumped(0x9000, PF_R | PF_W, vec![0; 8])
            .proc();
        assert!(p.lwp_name(1).is_err());
        assert!(p.exec_name().is_err());
    }

    #[test]
    fn test_open_rejects_what_is_not_a_core() {
        let dir = tempfile::tempdir().unwrap();

        let path = dir.path().join("garbage");
        std::fs::write(&path, b"not an elf file at all").unwrap();
        assert!(Core::open(&path).is_err());

        assert!(Core::open(&dir.path().join("no-such-file")).is_err());

        // A well-formed ELF that is not a core — synthesized, so this
        // holds on any host.
        let path = dir.path().join("exe");
        std::fs::write(&path, image(0, ET_EXEC, &[(PT_LOAD, 0, PAGE)]).bytes).unwrap();
        assert_eq!(
            Core::open(&path).unwrap_err().to_string(),
            "malformed core file: not a core file"
        );
    }

    #[test]
    fn test_open_rejects_a_core_with_no_threads() {
        let (_dir, res) = CoreBuilder::default()
            .dumped(0x9000, PF_R | PF_W, vec![0; 8])
            .open();
        assert_eq!(
            res.unwrap_err().to_string(),
            "malformed core file: no NT_LWPSTATUS note"
        );
    }

    #[test]
    fn test_open_rejects_truncated_notes() {
        // A note header promising a descriptor that is not there.
        let mut builder = CoreBuilder::default().dumped(0x9000, PF_R | PF_W, vec![0; 8]);
        let mut truncated = note(
            NT_LWPSTATUS,
            "CORE",
            &lwpstatus(
                1,
                &regs_at(0, 0x9000),
                0,
                Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            ),
        );
        truncated.truncate(truncated.len() / 2);
        builder.raw_notes = Some(truncated);
        assert!(builder.open().1.is_err());
    }

    // -----------------------------------------------------------------------
    // Symbols
    // -----------------------------------------------------------------------

    /// Symbols come out of the core's own section headers, with no
    /// companion binary to find: the opposite of Linux.
    #[test]
    fn test_symbols_come_from_the_cores_sections() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .symtab(
                0x40_0000,
                vec![
                    sym("alpha", FUNC, 0x40_0100, 0x40),
                    sym("beta", FUNC, 0x40_0200, 0x20),
                    sym("gamma", OBJECT, 0x40_0800, 8),
                ],
            )
            .proc();

        // With no link map to say otherwise, the lowest table is the
        // executable's — illumos maps it below every shared object.
        assert_eq!(names(p.symbols().unwrap()), ["alpha", "beta"]);
        assert_eq!(names(p.object_symbols().unwrap()), ["gamma"]);

        // An executable's values are absolute already: no bias.
        assert_eq!(
            p.lookup_symbol_by_name("alpha").unwrap().st_value,
            0x40_0100
        );
        // By-name lookup crosses from functions into data.
        assert_eq!(
            p.lookup_symbol_by_name("gamma").unwrap().st_value,
            0x40_0800
        );
        assert!(p.lookup_symbol_by_name("delta").is_none());

        // By address: containment against st_size, not nearness.
        assert_eq!(
            p.lookup_symbol_name_by_addr(0x40_0120).as_deref(),
            Some("alpha")
        );
        assert_eq!(
            p.lookup_symbol_name_by_addr(0x40_013f).as_deref(),
            Some("alpha")
        );
        assert!(p.lookup_symbol_by_addr(0x40_0140).is_none());
        assert!(p.lookup_symbol_by_addr(0x40_0500).is_none());
        assert!(p.lookup_symbol_by_addr(0x1000).is_none());
    }

    /// A shared object's table holds link-time offsets; `sh_addr` is
    /// where it landed. Nothing in the core says which kind a table is,
    /// and the values themselves do.
    #[test]
    fn test_shared_object_symbols_are_biased() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .symtab(
                0x5000_0000,
                vec![
                    sym("lib_fn", FUNC, 0x100, 0x10),
                    sym("TLS_SLOT", TLS, 0x10, 8),
                ],
            )
            .proc();

        assert_eq!(
            p.lookup_symbol_by_name("lib_fn").unwrap().st_value,
            0x5000_0100
        );
        // A thread-local's value is an offset into a TLS block; the
        // bias must not touch it.
        assert_eq!(p.lookup_symbol_by_name("TLS_SLOT").unwrap().st_value, 0x10);
    }

    /// What libproc would not report, this reader must not either:
    /// weak symbols, unnamed ones, and undefined references all stay
    /// out, so the two readers of one core agree.
    #[test]
    fn test_weak_and_valueless_symbols_are_dropped() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .symtab(
                0x40_0000,
                vec![
                    sym("real", FUNC, 0x40_0100, 0x10),
                    sym("_mcount", WEAK_FUNC, 0x40_0100, 0x10),
                    sym("", FUNC, 0x40_0200, 0x10),
                    sym("undefined", FUNC, 0, 0),
                    sym("notype", STB_GLOBAL << 4, 0x40_0300, 0x10),
                ],
            )
            .proc();

        assert_eq!(names(p.symbols().unwrap()), ["real"]);
        assert!(p.object_symbols().unwrap().is_empty());
        assert!(p.lookup_symbol_by_name("_mcount").is_none());
        assert!(p.lookup_symbol_by_name("notype").is_none());
    }

    /// Identical-code folding leaves several names on one address; a
    /// lookup takes the one libproc would.
    #[test]
    fn test_tied_addresses_resolve_in_libproc_order() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .symtab(
                0x40_0000,
                vec![
                    sym("_local_alias", LOCAL_FUNC, 0x40_0100, 0x10),
                    sym("public_fn", FUNC, 0x40_0100, 0x10),
                ],
            )
            .proc();

        assert_eq!(
            p.lookup_symbol_name_by_addr(0x40_0105).as_deref(),
            Some("public_fn")
        );
    }

    /// The pairwise preference chain, held to the transcription of
    /// libproc's `byaddr_cmp_common`.
    #[test]
    fn test_libproc_order_prefers_what_libproc_prefers() {
        use Ordering::{Greater, Less};

        fn buf(name: &str, info: u8, value: u64, size: u64) -> SymbolBuf {
            SymbolBuf {
                name: name.to_string(),
                st_name: 0,
                st_info: info,
                st_other: 0,
                st_shndx: 1,
                st_value: value,
                st_size: size,
            }
        }

        // Address order first, whatever else differs.
        assert_eq!(
            libproc_order(&buf("z", OBJECT, 1, 8), &buf("a", FUNC, 2, 8)),
            Less
        );
        // On one address: the function, then the global, then the name
        // without a '$', then fewer leading underscores, then the
        // smaller symbol, then name order.
        assert_eq!(
            libproc_order(&buf("data", OBJECT, 5, 8), &buf("code", FUNC, 5, 8)),
            Greater
        );
        assert_eq!(
            libproc_order(&buf("global", FUNC, 5, 8), &buf("local", LOCAL_FUNC, 5, 8)),
            Less
        );
        assert_eq!(
            libproc_order(&buf("$compiler", FUNC, 5, 8), &buf("named", FUNC, 5, 8)),
            Greater
        );
        assert_eq!(
            libproc_order(&buf("_write", FUNC, 5, 8), &buf("__write", FUNC, 5, 8)),
            Less
        );
        assert_eq!(
            libproc_order(&buf("bigger", FUNC, 5, 16), &buf("smaller", FUNC, 5, 8)),
            Greater
        );
        assert_eq!(
            libproc_order(&buf("abel", FUNC, 5, 8), &buf("baker", FUNC, 5, 8)),
            Less
        );
    }

    /// An address resolves in whichever object covers it, while by-name
    /// lookup searches only the executable — libproc's `PR_OBJ_EXEC`.
    #[test]
    fn test_lookup_lands_in_the_covering_object() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .symtab(0x40_0000, vec![sym("in_exec", FUNC, 0x40_0100, 0x10)])
            .symtab(0x5000_0000, vec![sym("in_lib", FUNC, 0x100, 0x10)])
            .proc();

        assert_eq!(
            p.lookup_symbol_name_by_addr(0x40_0105).as_deref(),
            Some("in_exec")
        );
        assert_eq!(
            p.lookup_symbol_name_by_addr(0x5000_0105).as_deref(),
            Some("in_lib")
        );
        assert!(p.lookup_symbol_by_name("in_lib").is_none());
        assert_eq!(names(p.symbols().unwrap()), ["in_exec"]);
    }

    // -----------------------------------------------------------------------
    // Thread-locals
    // -----------------------------------------------------------------------

    /// illumos stores a `thread_local!` behind a pthread key: the
    /// symbol names a static holding the key, and the thread's value
    /// for it sits in the fast-TSD slots at a fixed offset from
    /// `%fsbase` — all of it plain memory, all of it in the core.
    #[test]
    fn test_tls_var_addr_walks_the_pthread_key() {
        const FSBASE: u64 = 0xa000;

        let mut keys = Region::new(0x8000, PAGE as usize);
        keys.put_u64(0, 3); // a key this thread has set
        keys.put_u64(8, 5); // one it never set
        keys.put_u64(16, 99); // one past the fast slots

        let mut ulwp = Region::new(FSBASE, PAGE as usize);
        ulwp.put_u64(320 + 3 * 8, 0x1234_5678);

        let regs = Regs {
            fsbase: FSBASE,
            ..Regs::default()
        };
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs.clone())
            .dumped(0x8000, PF_R | PF_W, keys.bytes)
            .dumped(FSBASE, PF_R | PF_W, ulwp.bytes)
            .proc();

        let key_sym = |value: u64| SymbolBuf {
            name: "CONTEXT".to_string(),
            st_name: 0,
            st_info: OBJECT,
            st_other: 0,
            st_shndx: 1,
            st_value: value,
            st_size: 8,
        };
        assert_eq!(
            p.tls_var_addr(&regs, &key_sym(0x8000)).unwrap(),
            Some(0x1234_5678)
        );
        // A zero slot means the thread never set the key.
        assert_eq!(p.tls_var_addr(&regs, &key_sym(0x8008)).unwrap(), None);
        // A key past the fast slots is refused, not walked.
        assert!(p.tls_var_addr(&regs, &key_sym(0x8010)).is_err());
        // As is a key whose own static cannot be read.
        assert!(p.tls_var_addr(&regs, &key_sym(0xdead_0000)).is_err());
    }

    // -----------------------------------------------------------------------
    // The link map
    // -----------------------------------------------------------------------

    const LDATA: u64 = 0x6000_0000;

    /// The `r_debug` structures the walk reads: at offset 0, heading a
    /// `Link_map` chain of `(l_addr, name, next)` entries laid down
    /// from offset 64 in 64-byte strides, their names from 512 up.
    fn link_map(entries: &[(u64, &str)], ldso: Option<(u64, &str)>) -> Region {
        let mut r = Region::new(LDATA, PAGE as usize);
        let lay = |r: &mut Region, at: usize, entries: &[(u64, &str)]| {
            for (i, (l_addr, name)) in entries.iter().enumerate() {
                let e = at + i * 64;
                let name_at = 512 + e;
                r.put_u64(e, *l_addr);
                r.put_u64(e + LINK_MAP_L_NAME as usize, r.addr(name_at));
                if i + 1 < entries.len() {
                    let next = r.addr(e + 64);
                    r.put_u64(e + LINK_MAP_L_NEXT as usize, next);
                }
                r.put_str(name_at, name);
            }
        };
        r.put_u64(R_DEBUG_R_MAP as usize, r.addr(64));
        lay(&mut r, 64, entries);
        if let Some((l_addr, name)) = ldso {
            r.put_u64(R_DEBUG_R_LDSOMAP as usize, r.addr(320));
            lay(&mut r, 320, &[(l_addr, name)]);
        }
        r
    }

    /// An executable image whose `PT_DYNAMIC` carries `DT_DEBUG`
    /// pointing at [`LDATA`]. `vbase` is where its program headers
    /// claim to sit: equal to `base` for an `ET_EXEC`, zero for the
    /// link-time addresses of a PIE.
    fn exec_image(base: u64, e_type: u16, vbase: u64) -> Region {
        let mut exec = image(
            base,
            e_type,
            &[
                (PT_PHDR, vbase + SIZEOF_EHDR as u64, 3 * SIZEOF_PHDR as u64),
                (PT_LOAD, vbase, PAGE),
                (PT_DYNAMIC, vbase + 0x200, 2 * SIZEOF_DYN as u64),
            ],
        );
        exec.put_u64(0x200, DT_DEBUG);
        exec.put_u64(0x208, LDATA);
        exec.put_u64(0x210, DT_NULL);
        exec
    }

    /// The full walk an illumos core supports: the auxiliary vector to
    /// the executable's program headers, `PT_DYNAMIC` to `DT_DEBUG` to
    /// `r_debug`, and down both `Link_map` chains — every mapped object
    /// named out of the core's own memory, no filesystem consulted.
    #[test]
    fn test_the_link_map_names_the_mappings() {
        const EXEC_BASE: u64 = 0x40_0000;
        // Below the executable, so only the link map's name — not the
        // lowest-table fallback — can pick the executable's symtab.
        const LIB_BASE: u64 = 0x30_0000;
        const LDSO_BASE: u64 = 0x7000_0000;

        let exec = exec_image(EXEC_BASE, ET_EXEC, EXEC_BASE);
        let lib = image(LIB_BASE, ET_DYN, &[(PT_LOAD, 0, 2 * PAGE)]);
        let ldso = image(LDSO_BASE, ET_DYN, &[(PT_LOAD, 0, PAGE)]);
        // On an illumos host the recorded paths are resolved against
        // the filesystem, so none of these may name a file that is
        // really there — `/lib/64/ld.so.1` would come back as the
        // `/lib/amd64` it links to.
        let ldata = link_map(
            &[(EXEC_BASE, "/opt/prog"), (LIB_BASE, "/lib/64/libdemo.so.1")],
            Some((LDSO_BASE, "/lib/64/ld-demo.so.1")),
        );

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(EXEC_BASE + 0x100, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(LIB_BASE, PF_R | PF_X, lib.bytes)
            .undumped(LIB_BASE + PAGE, PAGE, PF_R | PF_W)
            .dumped(EXEC_BASE, PF_R | PF_X, exec.bytes)
            .dumped(LDATA, PF_R | PF_W, ldata.bytes)
            .dumped(LDSO_BASE, PF_R | PF_X, ldso.bytes)
            .auxv(AT_PHDR, EXEC_BASE + SIZEOF_EHDR as u64)
            .auxv(AT_PHENT, SIZEOF_PHDR as u64)
            .auxv(AT_PHNUM, 3)
            .psargs("/opt/prog --flag")
            .symtab(EXEC_BASE, vec![sym("main", FUNC, EXEC_BASE + 0x100, 0x20)])
            .symtab(LIB_BASE, vec![sym("lib_fn", FUNC, 0x100, 0x10)])
            .proc();

        // Every object's mappings carry its name; the shared object's
        // span comes from its own program headers, so it covers the
        // undumped data page too, and the linker itself — off on the
        // list it keeps for itself — is named all the same.
        let maps = p.mappings().unwrap();
        assert_eq!(
            maps.get(EXEC_BASE).unwrap().path.as_deref(),
            Some("/opt/prog")
        );
        assert_eq!(
            maps.get(LIB_BASE).unwrap().path.as_deref(),
            Some("/lib/64/libdemo.so.1")
        );
        assert_eq!(
            maps.get(LIB_BASE + PAGE).unwrap().path.as_deref(),
            Some("/lib/64/libdemo.so.1")
        );
        assert_eq!(
            maps.get(LDSO_BASE).unwrap().path.as_deref(),
            Some("/lib/64/ld-demo.so.1")
        );
        // What no object covers is anonymous.
        let stack = maps.get(0x9000).unwrap();
        assert_eq!(stack.path, None);
        assert!(stack.flags.is_anon());

        // The executable's symtab is the one the link map names with
        // the path the process was started from — not the lowest.
        assert_eq!(p.exec_name().unwrap(), PathBuf::from("/opt/prog"));
        assert_eq!(names(p.symbols().unwrap()), ["main"]);
        assert!(p.lookup_symbol_by_name("lib_fn").is_none());
        assert_eq!(
            p.lookup_symbol_name_by_addr(LIB_BASE + 0x105).as_deref(),
            Some("lib_fn")
        );

        // A shared object's own table is reachable by naming it, the
        // way mdb spells it — by path or by the file name at the end
        // of one. That is what puts an allocator's internals in reach
        // of a core with no filesystem behind it.
        for object in ["/lib/64/libdemo.so.1", "libdemo.so.1"] {
            let sym = p
                .lookup_symbol_by_name(&format!("{object}`lib_fn"))
                .unwrap_or_else(|| panic!("{object}`lib_fn did not resolve"));
            assert_eq!(sym.st_value, LIB_BASE + 0x100);
        }
        // A qualifier naming no mapped object, and a name that object
        // does not define, are both misses rather than a fall back to
        // the executable's table.
        assert!(p.lookup_symbol_by_name("libnothing.so.1`lib_fn").is_none());
        assert!(p.lookup_symbol_by_name("libdemo.so.1`main").is_none());

        // The break is the writable region above the executable that no
        // object's symbols claim.
        assert_eq!(p.status().brk_range, LDATA..LDATA + PAGE);
    }

    /// The heap begins where the executable's `.bss` ends, which is
    /// inside the executable's own extent rather than after it: the
    /// mapping backing bss stops at a page boundary and the rest of bss
    /// is the first of the brk. So the region that starts there is the
    /// heap, however far into the executable's span it starts, and
    /// naming it after the executable would hand every heap pointer in
    /// the target the binary's name.
    ///
    /// The executable's own regions keep theirs, page rounding and all:
    /// a region ends on a page boundary and an object's span ends
    /// wherever its last byte is, so the two are compared a page apart.
    #[test]
    fn test_the_heap_is_not_named_for_the_bss_it_starts_in() {
        const EXEC_BASE: u64 = 0x40_0000;
        // Program headers claim a page of text and a writable span
        // whose bss runs a little past the second page's end.
        const SPAN: u64 = 2 * PAGE + 0x40;
        const HEAP: u64 = EXEC_BASE + 2 * PAGE;

        let mut exec = image(
            EXEC_BASE,
            ET_EXEC,
            &[
                (
                    PT_PHDR,
                    EXEC_BASE + SIZEOF_EHDR as u64,
                    4 * SIZEOF_PHDR as u64,
                ),
                (PT_LOAD, EXEC_BASE, PAGE),
                (PT_LOAD, EXEC_BASE + PAGE, PAGE + 0x40),
                (PT_DYNAMIC, EXEC_BASE + 0x200, 2 * SIZEOF_DYN as u64),
            ],
        );
        exec.put_u64(0x200, DT_DEBUG);
        exec.put_u64(0x208, LDATA);
        exec.put_u64(0x210, DT_NULL);
        let ldata = link_map(&[(EXEC_BASE, "/opt/prog")], None);

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(EXEC_BASE + 0x100, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(EXEC_BASE, PF_R | PF_X, exec.bytes)
            // The writable mapping, ending on the page boundary the
            // bss spills past.
            .undumped(EXEC_BASE + PAGE, PAGE, PF_R | PF_W)
            // The brk, starting there and running well past the span.
            .undumped(HEAP, 16 * PAGE, PF_R | PF_W)
            .dumped(LDATA, PF_R | PF_W, ldata.bytes)
            .auxv(AT_PHDR, EXEC_BASE + SIZEOF_EHDR as u64)
            .auxv(AT_PHENT, SIZEOF_PHDR as u64)
            .auxv(AT_PHNUM, 4)
            .psargs("/opt/prog")
            .proc();

        let maps = p.mappings().unwrap();
        assert!(
            (EXEC_BASE..EXEC_BASE + SPAN).contains(&HEAP),
            "the heap must start inside the executable's span for this to be a test"
        );
        let heap = maps.get(HEAP).unwrap();
        assert_eq!(heap.path, None, "{heap:?}");
        assert!(heap.flags.is_anon(), "{heap:?}");
        // And nothing the executable does map lost its name to the
        // same comparison.
        for addr in [EXEC_BASE, EXEC_BASE + PAGE] {
            assert_eq!(
                maps.get(addr).unwrap().path.as_deref(),
                Some("/opt/prog"),
                "{:?}",
                maps.get(addr)
            );
        }
        assert_eq!(maps.get(EXEC_BASE).unwrap().region(), "text");
        assert_eq!(maps.get(EXEC_BASE + PAGE).unwrap().region(), "data");
    }

    /// The break is marked as the heap even though its mapping starts
    /// *below* what the kernel calls the break.
    ///
    /// `brk` is a pointer into the page the executable's bss ends in,
    /// so the mapping backing the heap begins at that page's base —
    /// under `pr_brkbase` by however far into the page bss ran. Asking
    /// whether a mapping *starts inside* the break therefore misses the
    /// one mapping that is the heap, which is the whole point of
    /// reading the field. Overlap is the test.
    ///
    /// And it is only the break: the other anonymous mappings a process
    /// has stay anonymous, because calling them heap is the false claim
    /// this replaced.
    #[test]
    fn test_the_break_is_the_heap_though_its_mapping_starts_below_it() {
        const EXEC_BASE: u64 = 0x40_0000;
        // The break begins partway into the page bss ends in, exactly
        // as a real one does.
        const HEAP_MAPPING: u64 = EXEC_BASE + PAGE;
        const BRK_BASE: u64 = HEAP_MAPPING + 0x40;
        const BRK_SIZE: u64 = 16 * PAGE;
        const ELSEWHERE: u64 = 0x9000_0000;

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(EXEC_BASE + 0x100, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .undumped(HEAP_MAPPING, BRK_SIZE, PF_R | PF_W)
            // An anonymous mapping that is not the break.
            .undumped(ELSEWHERE, PAGE, PF_R | PF_W)
            .brk(BRK_BASE, BRK_SIZE)
            .proc();

        // The mapping must start below the break or this tests nothing;
        // checked at compile time, since both are constants.
        const _: () = assert!(HEAP_MAPPING < BRK_BASE);

        let maps = p.mappings().unwrap();
        let heap = maps.get(HEAP_MAPPING).unwrap();
        assert!(heap.is_heap(), "{heap:?}");
        // Deep inside it, too — a heap is many pages and every one of
        // them is the heap.
        assert!(maps.get(BRK_BASE + 8 * PAGE).unwrap().is_heap());

        let other = maps.get(ELSEWHERE).unwrap();
        assert!(other.flags.is_anon(), "{other:?}");
        assert!(!other.is_heap(), "{other:?}");

        // And the recorded break is what `Status` reports, rather than
        // the guess a core without the field falls back to.
        assert_eq!(p.status().brk_range, BRK_BASE..BRK_BASE + BRK_SIZE);
    }

    /// A PIE's program headers hold link-time offsets; the bias worked
    /// out from `PT_PHDR` brings the walk to its dynamic section, and
    /// its `ET_DYN` header tells `object_span` to bias its span.
    #[test]
    fn test_a_pie_exec_walks_through_its_bias() {
        const BASE: u64 = 0x5555_0000;

        let exec = exec_image(BASE, ET_DYN, 0);
        let ldata = link_map(&[(BASE, "/opt/pie")], None);

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(BASE + 0x100, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(BASE, PF_R | PF_X, exec.bytes)
            .dumped(LDATA, PF_R | PF_W, ldata.bytes)
            .auxv(AT_PHDR, BASE + SIZEOF_EHDR as u64)
            .auxv(AT_PHENT, SIZEOF_PHDR as u64)
            .auxv(AT_PHNUM, 3)
            .proc();

        let maps = p.mappings().unwrap();
        assert_eq!(maps.get(BASE).unwrap().path.as_deref(), Some("/opt/pie"));
        assert_eq!(maps.get(0x9000).unwrap().path, None);
    }

    /// The bias a static address out of the debug info must be moved by
    /// to be read here: its base for a PIE, zero for a
    /// position-dependent executable — a claim, not the absence of one
    /// — and nothing at all for a core whose auxiliary vector never
    /// named the program headers to work it out from.
    #[test]
    fn test_the_exec_bias_says_where_the_executable_landed() {
        const BASE: u64 = 0x5555_0000;

        let core = |e_type, vbase, auxv: bool| {
            let exec = exec_image(BASE, e_type, vbase);
            let ldata = link_map(&[(BASE, "/opt/prog")], None);
            let mut b = CoreBuilder::default()
                .thread(1, regs_at(BASE + 0x100, 0x9000))
                .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
                .dumped(BASE, PF_R | PF_X, exec.bytes)
                .dumped(LDATA, PF_R | PF_W, ldata.bytes);
            if auxv {
                b = b
                    .auxv(AT_PHDR, BASE + SIZEOF_EHDR as u64)
                    .auxv(AT_PHENT, SIZEOF_PHDR as u64)
                    .auxv(AT_PHNUM, 3);
            }
            b.proc()
        };

        // Asked through the trait, which is how every reader asks and
        // so the surface that has to answer.
        //
        // A PIE: its headers describe themselves at an offset, and they
        // turned out to be that far above `BASE`.
        let (_dir, p) = core(ET_DYN, 0, true);
        assert_eq!(Target::exec_bias(&p), Some(BASE));

        // Position-dependent: the headers name the address they are at.
        let (_dir, p) = core(ET_EXEC, BASE, true);
        assert_eq!(Target::exec_bias(&p), Some(0));

        // And with nothing saying where the headers are, there is no
        // bias to report rather than a zero to assume.
        let (_dir, p) = core(ET_DYN, 0, false);
        assert_eq!(Target::exec_bias(&p), None);
    }

    /// A link map whose chain loops is walked no further than the
    /// bound: a corrupt core cannot hold the reader forever.
    #[test]
    fn test_a_link_map_cycle_is_bounded() {
        const BASE: u64 = 0x5555_0000;

        let exec = exec_image(BASE, ET_DYN, 0);
        let mut ldata = link_map(&[(BASE, "/opt/pie")], None);
        // The entry's successor is itself.
        let entry = ldata.addr(64);
        ldata.put_u64(64 + LINK_MAP_L_NEXT as usize, entry);

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(BASE + 0x100, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(BASE, PF_R | PF_X, exec.bytes)
            .dumped(LDATA, PF_R | PF_W, ldata.bytes)
            .auxv(AT_PHDR, BASE + SIZEOF_EHDR as u64)
            .auxv(AT_PHENT, SIZEOF_PHDR as u64)
            .auxv(AT_PHNUM, 3)
            .proc();

        assert_eq!(
            p.mappings().unwrap().get(BASE).unwrap().path.as_deref(),
            Some("/opt/pie")
        );
    }

    /// A chain that runs into unmapped memory keeps the objects it
    /// reached: unnamed rather than wrong, and never fatal.
    #[test]
    fn test_a_truncated_link_map_keeps_what_it_reached() {
        const BASE: u64 = 0x5555_0000;
        const LIB_BASE: u64 = 0x7000_0000;

        let exec = exec_image(BASE, ET_DYN, 0);
        let lib = image(LIB_BASE, ET_DYN, &[(PT_LOAD, 0, PAGE)]);
        let mut ldata = link_map(&[(BASE, "/opt/pie")], None);
        // The chain continues into memory the core does not have.
        ldata.put_u64(64 + LINK_MAP_L_NEXT as usize, 0xdead_0000);

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(BASE + 0x100, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(BASE, PF_R | PF_X, exec.bytes)
            .dumped(LDATA, PF_R | PF_W, ldata.bytes)
            .dumped(LIB_BASE, PF_R | PF_X, lib.bytes)
            .auxv(AT_PHDR, BASE + SIZEOF_EHDR as u64)
            .auxv(AT_PHENT, SIZEOF_PHDR as u64)
            .auxv(AT_PHNUM, 3)
            .proc();

        let maps = p.mappings().unwrap();
        assert_eq!(maps.get(BASE).unwrap().path.as_deref(), Some("/opt/pie"));
        // The object past the break in the chain goes unnamed.
        assert_eq!(maps.get(LIB_BASE).unwrap().path, None);
    }

    /// A statically linked executable has no `DT_DEBUG` to follow — a
    /// zero one is the same as none — so nothing is named, and
    /// everything else still works.
    #[test]
    fn test_a_static_exec_has_no_link_map() {
        const BASE: u64 = 0x40_0000;

        let mut exec = image(
            BASE,
            ET_EXEC,
            &[
                (PT_PHDR, BASE + SIZEOF_EHDR as u64, 3 * SIZEOF_PHDR as u64),
                (PT_LOAD, BASE, PAGE),
                (PT_DYNAMIC, BASE + 0x200, 2 * SIZEOF_DYN as u64),
            ],
        );
        exec.put_u64(0x200, DT_DEBUG); // left zero by the linker
        exec.put_u64(0x210, DT_NULL);

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(BASE + 0x100, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(BASE, PF_R | PF_X, exec.bytes)
            .auxv(AT_PHDR, BASE + SIZEOF_EHDR as u64)
            .auxv(AT_PHENT, SIZEOF_PHDR as u64)
            .auxv(AT_PHNUM, 3)
            .symtab(BASE, vec![sym("main", FUNC, BASE + 0x100, 0x20)])
            .proc();

        for m in p.mappings().unwrap().iter() {
            assert_eq!(m.path, None, "{m:?}");
        }
        // Symbols still resolve, through the lowest-table fallback.
        assert_eq!(names(p.symbols().unwrap()), ["main"]);
    }

    /// Program headers out of a core's memory can hold anything; a
    /// span that would wrap the address space is corrupt, and must not
    /// take mappings away from the object that is really there.
    #[test]
    fn test_span_of_rejects_wrapped_addresses() {
        fn ph(p_type: u32, p_vaddr: u64, p_memsz: u64) -> ProgramHeader {
            ProgramHeader {
                p_type,
                p_flags: PF_R,
                p_offset: 0,
                p_vaddr,
                p_paddr: p_vaddr,
                p_filesz: p_memsz,
                p_memsz,
                p_align: PAGE,
            }
        }

        // The ordinary case: the extremes of the loads, biased.
        assert_eq!(
            span_of(
                &[ph(PT_LOAD, 0x1000, 0x1000), ph(PT_LOAD, 0x4000, 0x1000)],
                0x10
            ),
            Some(0x1010..0x5010)
        );
        // Wrapping in either the bias or the extent is corruption.
        assert_eq!(span_of(&[ph(PT_LOAD, u64::MAX - 8, 0x100)], 0), None);
        assert_eq!(span_of(&[ph(PT_LOAD, 0x1000, 0x100)], u64::MAX), None);
        // No loads, or only empty ones, span nothing.
        assert_eq!(span_of(&[ph(PT_NOTE, 0x1000, 0x100)], 0), None);
        assert_eq!(span_of(&[ph(PT_LOAD, 0x1000, 0)], 0), None);
    }
}

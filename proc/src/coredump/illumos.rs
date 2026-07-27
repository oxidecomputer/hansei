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

use crate::{
    Error, LoadedObject, LoadedObjectWithPath, LwpInfo, MapFlags, Mappings, Regs, Result, Status,
    SymbolBuf, Target, Timespec,
};

use goblin::container::{Container, Ctx};
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
const NT_PSINFO: u32 = 13;
const NT_LWPSTATUS: u32 = 16;
const NT_LWPNAME: u32 = 25;

/// `lwpstatus_t` for x86-64, whose offsets the `libproc-sys` bindings
/// assert: 1296 bytes, with the thread id first and the register set
/// three-quarters of the way in.
const LWPSTATUS_LEN: usize = 1296;
const LWPSTATUS_PR_LWPID: usize = 4;
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

/// `psinfo_t`: the command line is what names the executable, since an
/// illumos core has no equivalent of Linux's `NT_FILE`.
const PSINFO_LEN: usize = 416;
const PSINFO_PR_PSARGS: usize = 152;
const PSINFO_PSARGS_LEN: usize = 80;

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

/// One `PT_LOAD` of the core.
#[derive(Clone, Debug)]
struct Segment {
    vaddr: u64,
    memsz: u64,
    filesz: u64,
    offset: u64,
    flags: u32,
}

impl Segment {
    fn dumped(&self) -> Range<u64> {
        self.vaddr..self.vaddr + self.filesz
    }

    fn range(&self) -> Range<u64> {
        self.vaddr..self.vaddr + self.memsz
    }
}

/// An illumos core is ELF64 and little-endian, which is what the ELF
/// structures read out of its memory have to be decoded as.
fn elf_ctx() -> Ctx {
    Ctx::new(Container::Big, scroll::Endian::Little)
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

/// The symbols of one mapped object, taken from the core's own section
/// headers and brought to runtime addresses.
#[derive(Default)]
struct Symbols {
    functions: Vec<SymbolBuf>,
    objects: Vec<SymbolBuf>,
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
    /// Symbols of every object whose table the core carries, keyed by
    /// the address that object was loaded at.
    symbols: BTreeMap<u64, Symbols>,
    /// The object the executable was loaded at, if its table is here.
    exec_base: Option<u64>,
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
                NT_LWPNAME if desc.len() >= LWPNAME_LEN => {
                    let (tid, name) = parse_lwpname(desc);
                    if !name.is_empty() {
                        lwp_names.insert(tid, name);
                    }
                }
                NT_PSINFO if desc.len() >= PSINFO_LEN && exec.is_none() => {
                    exec = parse_psinfo_exec(desc);
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
            symbols,
            exec_base: None,
        };
        core_file.fill_stack_ranges();

        // The link map lives in the target's memory, so it can only be
        // walked once the segments are readable.
        let objects = core_file.link_map_objects(&auxv);
        core_file.mappings = build_mappings(&core_file.segments, &objects);
        core_file.exec_base = core_file.find_exec_base(&objects);
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
        let at_phdr = *auxv.get(&AT_PHDR)?;
        let phent = *auxv.get(&AT_PHENT)? as u16;
        let phnum = *auxv.get(&AT_PHNUM)? as u16;
        let phdrs = self.read_phdrs(at_phdr, phent, phnum)?;

        // The table describes where it is itself, so comparing that to
        // where it turned out to be gives the bias — zero for a
        // position-dependent executable, its base for a PIE.
        let bias = phdrs
            .iter()
            .find(|p| p.p_type == PT_PHDR)
            .map_or(0, |p| at_phdr.wrapping_sub(p.p_vaddr));

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

    /// The addresses one mapped object occupies, from the program
    /// headers of the ELF image at `base`.
    fn object_span(&self, base: u64) -> Option<Range<u64>> {
        let header = self.read_bytes(base, SIZEOF_EHDR as u64).ok()?;
        let header = Header::parse(&header).ok()?;

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

    /// The object whose symbols cover `addr`: the one loaded at or
    /// below it, nearest.
    fn object_at(&self, addr: u64) -> Option<&Symbols> {
        self.symbols.range(..=addr).next_back().map(|(_, s)| s)
    }

    pub fn pread(&self, buf: &mut [u8], address: u64) -> Result<u64> {
        let mut done = 0usize;
        while done < buf.len() {
            let addr = address + done as u64;
            let Some(seg) = self.segment_at(addr).filter(|s| s.dumped().contains(&addr)) else {
                break;
            };
            let skip = addr - seg.vaddr;
            let take = ((seg.filesz - skip) as usize).min(buf.len() - done);
            let at = (seg.offset + skip) as usize;
            let bytes = self
                .core
                .get(at..at + take)
                .ok_or_else(|| Error::bad_core("PT_LOAD runs past the end of the file"))?;
            buf[done..done + take].copy_from_slice(bytes);
            done += take;
        }
        Ok(done as u64)
    }

    pub fn pread_exact(&self, buf: &mut [u8], address: u64) -> Result<()> {
        if self.pread(buf, address)? != buf.len() as u64 {
            return Err(Error::unmapped(address, buf.len() as u64));
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
        Status {
            active_lwp: self.lwps.first().map(|l| l.tid).unwrap_or(0),
            // A core records no break; the heap is the writable
            // anonymous region above the executable.
            brk_range: self
                .segments
                .iter()
                .find(|s| {
                    Some(s.vaddr) > self.exec_base
                        && s.flags & PF_W != 0
                        && !self.symbols.contains_key(&s.vaddr)
                })
                .map(Segment::range)
                .unwrap_or(0..0),
            stack_range: self
                .lwps
                .first()
                .map(|l| l.stack_range.clone())
                .unwrap_or(0..0),
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
        let object = self.symbols.get(&self.exec_base?)?;
        object
            .functions
            .iter()
            .chain(&object.objects)
            .find(|s| s.name == name)
            .cloned()
    }

    pub fn lookup_symbol_name_by_addr(&self, address: u64) -> Option<String> {
        self.lookup_symbol_by_addr(address).map(|s| s.name)
    }

    /// illumos stores a `thread_local!` under a pthread key, so the
    /// symbol holds the key and the value is in the thread's fast-TSD
    /// slots — the same walk libproc's callers do, over this core's
    /// memory instead.
    pub fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        crate::tls_addr_from_pthread_key(self, regs, sym)
    }
}

/// The `PT_LOAD` regions, each named by whichever loaded object covers
/// it. A region no object covers — a stack, the heap, an anonymous
/// mapping — has no name to give, and says so.
fn build_mappings(segments: &[Segment], objects: &[(Range<u64>, String)]) -> Mappings {
    Mappings {
        inner: segments
            .iter()
            .map(|seg| {
                let path = objects
                    .iter()
                    .find(|(range, _)| range.contains(&seg.vaddr))
                    .map(|(_, name)| name.clone());
                let mut flags = seg.flags & (PF_R | PF_W | PF_X);
                if path.is_none() {
                    flags |= 0x40; // MA_ANON
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

    LwpInfo {
        tid,
        regs: Regs::from_gregset(&regs),
        // Filled in from the mappings once they are known.
        stack_range: 0..0,
        tstamp,
    }
}

fn parse_lwpname(desc: &[u8]) -> (u32, String) {
    let tid = u32::from_le_bytes(desc[0..4].try_into().unwrap());
    let raw = &desc[LWPNAME_PR_LWPNAME..LWPNAME_PR_LWPNAME + LWPNAME_MAX];
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    (tid, String::from_utf8_lossy(&raw[..end]).into_owned())
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

impl Target for Core {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        self.pread_exact(&mut buf, addr)?;
        Ok(buf)
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
}

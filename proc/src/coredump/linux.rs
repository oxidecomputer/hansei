//! A Linux ELF core dump, read straight out of the file.
//!
//! Nothing here asks the operating system anything, so it reads a Linux
//! core on any host — which is the point: what a core needs to be
//! interpreted is in the core, not in the machine looking at it. A core
//! is an `ET_CORE` ELF: one `PT_LOAD` per dumped memory region, and a
//! single `PT_NOTE` carrying the register sets (`NT_PRSTATUS`, one per
//! thread), the mapped-file table (`NT_FILE`), and the auxiliary vector
//! (`NT_AUXV`).
//!
//! Two things about a Linux core shape everything here. The default
//! `coredump_filter` (`0x33`) omits private file-backed pages, so the
//! executable's text and rodata are *not* in the file — those segments
//! are present with `p_filesz == 0`, and reads that land in them have to
//! be served from the file on disk that `NT_FILE` names. And symbols
//! come from those same files rather than from the core, so every
//! `st_value` has to be biased by where the object actually landed.
//! Reading a Linux core away from the machine that wrote it therefore
//! wants those files to hand; what was dumped still reads without them.

use crate::{
    Error, LoadedObject, LoadedObjectWithPath, LwpInfo, MapFlags, Mappings, Regs, Result, Status,
    SymbolBuf, Target, Timespec,
};

use goblin::elf::Elf;
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD, PT_NOTE, PT_TLS};
use goblin::elf::sym::{STT_FUNC, STT_OBJECT, STT_TLS};
use memmap2::Mmap;

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// Note types carried by a Linux core, from `<elf.h>`.
const NT_PRSTATUS: u32 = 1;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x4649_4c45;

/// Auxiliary-vector tags, from `<elf.h>`. `AT_PHDR` is the runtime
/// address of the executable's own program headers, which is how the
/// executable is told apart from every other mapped file.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;

/// Field offsets into `struct elf_prstatus` for x86-64, which is fixed
/// ABI: `pr_pid` is the thread id, `pr_reg` a `user_regs_struct`.
const PR_PID: usize = 32;
const PR_REG: usize = 112;
const PR_REG_COUNT: usize = 27;
const PRSTATUS_LEN: usize = PR_REG + PR_REG_COUNT * 8 + 8;

/// ELF notes are a header, a padded name and a padded descriptor. The
/// ELF64 spec says eight-byte padding; Linux writes four and sets the
/// `PT_NOTE` alignment to match, so four is what a core actually uses.
const NOTE_ALIGN: usize = 4;

impl Regs {
    /// Decode a `user_regs_struct` (x86-64), whose field order is fixed
    /// ABI and shares only its contents, not its layout, with the
    /// illumos `gregset_t`.
    ///
    /// `trapno` and `err` stay zero: Linux keeps neither in the thread's
    /// register note. `orig_rax` sits where they would be and means
    /// something else entirely — the syscall number the thread entered
    /// with — so it is dropped rather than misfiled.
    fn from_user_regs(r: &[u64; PR_REG_COUNT]) -> Self {
        Regs {
            r15: r[0],
            r14: r[1],
            r13: r[2],
            r12: r[3],
            rbp: r[4],
            rbx: r[5],
            r11: r[6],
            r10: r[7],
            r9: r[8],
            r8: r[9],
            rax: r[10],
            rcx: r[11],
            rdx: r[12],
            rsi: r[13],
            rdi: r[14],
            rip: r[16],
            cs: r[17],
            rfl: r[18],
            rsp: r[19],
            ss: r[20],
            fsbase: r[21],
            gsbase: r[22],
            ds: r[23],
            es: r[24],
            fs: r[25],
            gs: r[26],
            trapno: 0,
            err: 0,
        }
    }
}

/// A little-endian reader over a note or descriptor body, which is all
/// the decoding a core needs.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| Error::bad_core("note ends mid-field"))?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// Advance to the next `align` boundary; note bodies are padded.
    fn align_to(&mut self, align: usize) {
        self.pos = self.pos.next_multiple_of(align).min(self.bytes.len());
    }

    /// A NUL-terminated string, consuming the terminator.
    fn cstr(&mut self) -> Result<&'a str> {
        let rest = &self.bytes[self.pos..];
        let len = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| Error::bad_core("unterminated string in NT_FILE"))?;
        self.pos += len + 1;
        std::str::from_utf8(&rest[..len]).map_err(|_| Error::bad_core("non-UTF-8 mapping path"))
    }
}

/// One `PT_LOAD` of the core: a region of the target's address space,
/// of which the first `filesz` bytes were actually written out.
#[derive(Clone, Debug)]
struct Segment {
    vaddr: u64,
    memsz: u64,
    filesz: u64,
    offset: u64,
    flags: u32,
}

impl Segment {
    /// The part of this region whose bytes are in the core file.
    fn dumped(&self) -> Range<u64> {
        self.vaddr..self.vaddr + self.filesz
    }

    fn range(&self) -> Range<u64> {
        self.vaddr..self.vaddr + self.memsz
    }
}

/// One `NT_FILE` entry: a range of the address space backed by a file,
/// and where in that file it came from.
#[derive(Clone, Debug)]
struct FileMap {
    range: Range<u64>,
    offset: u64,
    path: String,
}

/// A backing file, mapped once and shared by every region that names it.
struct BackingFile {
    map: Mmap,
    /// The object's symbols, parsed on first use: a big executable's
    /// symtab is not worth reading for a caller that only wants memory.
    symbols: OnceCell<Symbols>,
}

impl BackingFile {
    fn open(path: &str) -> Option<Self> {
        let file = File::open(path).ok()?;
        // SAFETY: as everywhere else in this workspace, we assume the
        // file is not modified while mapped.
        let map = unsafe { Mmap::map(&file) }.ok()?;
        Some(BackingFile {
            map,
            symbols: OnceCell::new(),
        })
    }
}

/// The symbols of one object, at their runtime addresses.
#[derive(Default)]
struct Symbols {
    /// Function symbols, sorted by address, for containment lookup.
    functions: Vec<SymbolBuf>,
    /// Data symbols, including the `STT_TLS` ones, whose `st_value` is
    /// an offset into a TLS block rather than an address.
    objects: Vec<SymbolBuf>,
}

pub struct Core {
    core: Mmap,
    /// The core's `PT_LOAD` regions, sorted by address.
    segments: Vec<Segment>,
    /// The `NT_FILE` table, sorted by address.
    files: Vec<FileMap>,
    /// Backing files, keyed by path, opened lazily: a core routinely
    /// names files that are no longer on this machine, and that is only
    /// fatal for reads that actually land in one.
    backing: BTreeMap<String, Option<BackingFile>>,
    mappings: Mappings,
    lwps: Vec<LwpInfo>,
    /// The executable's path and load bias, found via `AT_PHDR`.
    exec: Option<ExecInfo>,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("exec", &self.exec.as_ref().map(|e| &e.path))
            .field("segments", &self.segments.len())
            .field("files", &self.files.len())
            .field("lwps", &self.lwps.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
struct ExecInfo {
    path: String,
    /// Runtime address minus link-time address for this object.
    bias: u64,
    /// The executable's `PT_TLS` block size, rounded to its alignment:
    /// on x86-64 the static TLS block sits immediately below the thread
    /// pointer, so this is how far below.
    tls_block: u64,
}

impl Core {
    /// Open a core dump. The backing files it names are opened on
    /// demand, so a core whose libraries have moved still yields
    /// everything that was actually dumped.
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
        let mut files = Vec::new();
        let mut auxv = BTreeMap::new();
        for ph in elf.program_headers.iter().filter(|ph| ph.p_type == PT_NOTE) {
            let start = ph.p_offset as usize;
            let end = start
                .checked_add(ph.p_filesz as usize)
                .filter(|end| *end <= core.len())
                .ok_or_else(|| Error::bad_core("PT_NOTE runs past the end of the file"))?;
            parse_notes(&core[start..end], &mut lwps, &mut files, &mut auxv)?;
        }
        if lwps.is_empty() {
            return Err(Error::bad_core("no NT_PRSTATUS note"));
        }
        files.sort_by_key(|f| f.range.start);

        // Map every backing file up front: it is a handful of mmaps,
        // and it lets reads and symbol lookups take &self. Parsing
        // their symtabs stays lazy, which is where the real cost is.
        let backing = files
            .iter()
            .map(|f| (f.path.clone(), BackingFile::open(&f.path)))
            .collect();

        let mut core_file = Core {
            core,
            segments,
            files,
            backing,
            mappings: Mappings { inner: Vec::new() },
            lwps,
            exec: None,
        };
        core_file.mappings = core_file.build_mappings();
        core_file.exec = core_file.find_exec(auxv.get(&AT_PHDR).copied());
        core_file.fill_stack_ranges();
        Ok(core_file)
    }

    /// Join the `PT_LOAD` regions against `NT_FILE` to produce the
    /// mapping table, whose flag bits are spelled the illumos way: the
    /// permission bits already agree (`PF_X`/`PF_W`/`PF_R` are
    /// `MA_EXEC`/`MA_WRITE`/`MA_READ`), and the rest is provenance.
    fn build_mappings(&self) -> Mappings {
        let inner = self
            .segments
            .iter()
            .map(|seg| {
                let backing = self.file_at(seg.vaddr);
                let mut flags = seg.flags & (PF_R | PF_W | PF_X);
                if backing.is_none() {
                    flags |= 0x40; // MA_ANON
                }
                LoadedObjectWithPath {
                    path: backing.map(|f| f.path.clone()),
                    vaddr: seg.vaddr,
                    size: seg.memsz,
                    flags: MapFlags(flags),
                }
            })
            .collect();

        // Not every mapping reaches the program headers. The kernel
        // writes a PT_LOAD for each one, empty where the dump filter
        // dropped it, but gdb's gcore leaves some out of the headers
        // altogether and mentions them only in NT_FILE. Those are
        // readable — the file they name still has them — so they belong
        // in the address space rather than in a hole.
        let mut inner: Vec<LoadedObjectWithPath> = inner;
        for file in &self.files {
            if self
                .segments
                .iter()
                .any(|s| s.vaddr < file.range.end && file.range.start < s.range().end)
            {
                continue;
            }
            inner.push(LoadedObjectWithPath {
                path: Some(file.path.clone()),
                vaddr: file.range.start,
                size: file.range.end - file.range.start,
                // Readable and file-backed is all such an entry says;
                // the permissions it was mapped with went unrecorded.
                flags: MapFlags(PF_R),
            });
        }
        inner.sort_unstable();
        Mappings { inner }
    }

    /// Identify the executable from `AT_PHDR`, whose runtime address
    /// lands in whichever file carries the program headers, and derive
    /// that object's load bias and TLS block size from its own ELF.
    fn find_exec(&self, at_phdr: Option<u64>) -> Option<ExecInfo> {
        let path = self.file_at(at_phdr?)?.path.clone();
        let backing = self.backing(&path)?;
        let elf = Elf::parse(&backing.map).ok()?;
        let bias = self.object_bias(&elf, &path)?;

        // Variant II puts the static TLS block immediately below the
        // thread pointer, so a thread-local's address is the thread
        // pointer less the whole block, plus the symbol's offset in it.
        let tls_block = elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_TLS)
            .map(|ph| ph.p_memsz.next_multiple_of(ph.p_align.max(1)))
            .unwrap_or(0);

        Some(ExecInfo {
            path,
            bias,
            tls_block,
        })
    }

    /// A core carries no per-thread stack bounds, but each thread's
    /// stack is its own mapping, so the region holding `%rsp` is it.
    fn fill_stack_ranges(&mut self) {
        let ranges: Vec<Range<u64>> = self
            .lwps
            .iter()
            .map(|lwp| {
                self.segments
                    .iter()
                    .find(|s| s.range().contains(&lwp.regs.rsp))
                    .map(Segment::range)
                    .unwrap_or(0..0)
            })
            .collect();
        for (lwp, range) in self.lwps.iter_mut().zip(ranges) {
            lwp.stack_range = range;
        }
    }

    fn file_at(&self, addr: u64) -> Option<&FileMap> {
        let idx = self.files.partition_point(|f| f.range.start <= addr);
        let file = &self.files[idx.checked_sub(1)?];
        (addr < file.range.end).then_some(file)
    }

    fn segment_at(&self, addr: u64) -> Option<&Segment> {
        let idx = self.segments.partition_point(|s| s.vaddr <= addr);
        let seg = &self.segments[idx.checked_sub(1)?];
        (addr < seg.range().end).then_some(seg)
    }

    /// The mapped backing file for `path`, if it was there to open. A
    /// core routinely names files that have moved off this machine;
    /// that is only fatal for reads that actually land in one.
    fn backing(&self, path: &str) -> Option<&BackingFile> {
        self.backing.get(path)?.as_ref()
    }

    /// Read as much of `buf` as one source can serve, starting at
    /// `addr`. The core's own bytes win over the file on disk: a
    /// writable page may have been modified since it was mapped.
    fn read_chunk(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        if let Some(seg) = self.segment_at(addr)
            && seg.dumped().contains(&addr)
        {
            let skip = addr - seg.vaddr;
            let avail = (seg.filesz - skip) as usize;
            let take = avail.min(buf.len());
            let start = (seg.offset + skip) as usize;
            let bytes = self
                .core
                .get(start..start + take)
                .ok_or_else(|| Error::bad_core("PT_LOAD runs past the end of the file"))?;
            buf[..take].copy_from_slice(bytes);
            return Ok(take);
        }

        // Not dumped: the pages are unmodified since they were mapped,
        // so the file they came from still has them. This is the normal
        // path for the executable's text under the default
        // coredump_filter.
        let file = self
            .file_at(addr)
            .ok_or_else(|| Error::unmapped(addr, buf.len() as u64))?;
        let skip = addr - file.range.start;
        let avail = (file.range.end - addr) as usize;
        let take = avail.min(buf.len());
        let start = (file.offset + skip) as usize;
        let backing = self
            .backing(&file.path)
            .ok_or_else(|| Error::unmapped(addr, buf.len() as u64))?;
        let bytes = backing
            .map
            .get(start..start + take)
            .ok_or_else(|| Error::unmapped(addr, buf.len() as u64))?;
        buf[..take].copy_from_slice(bytes);
        Ok(take)
    }

    pub fn pread(&self, buf: &mut [u8], address: u64) -> Result<u64> {
        let mut done = 0usize;
        while done < buf.len() {
            let addr = address + done as u64;
            match self.read_chunk(addr, &mut buf[done..]) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(_) if done > 0 => break,
                Err(e) => return Err(e),
            }
        }
        Ok(done as u64)
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

    pub fn exec_name(&self) -> Result<PathBuf> {
        self.exec
            .as_ref()
            .map(|e| PathBuf::from(&e.path))
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

    /// The thread ids and the address ranges the process was using.
    ///
    /// `brk_range` is a reconstruction, not a record: a core carries no
    /// `brk`, so this is the anonymous writable region directly above
    /// the executable's mappings, which is where the break heap sits.
    pub fn status(&self) -> Status {
        let active_lwp = self.lwps.first().map(|l| l.tid).unwrap_or(0);
        let stack_range = self
            .lwps
            .first()
            .map(|l| l.stack_range.clone())
            .unwrap_or(0..0);

        let exec_end = self
            .exec
            .as_ref()
            .and_then(|e| {
                self.files
                    .iter()
                    .filter(|f| f.path == e.path)
                    .map(|f| f.range.end)
                    .max()
            })
            .unwrap_or(0);
        let brk_range = self
            .segments
            .iter()
            .find(|s| s.vaddr >= exec_end && self.file_at(s.vaddr).is_none() && s.flags & PF_W != 0)
            .map(Segment::range)
            .unwrap_or(0..0);

        Status {
            active_lwp,
            brk_range,
            stack_range,
        }
    }

    pub fn addr_to_map(&self, address: u64) -> Option<LoadedObject> {
        self.mappings.get(address).map(|m| LoadedObject {
            vaddr: m.vaddr,
            size: m.size,
            flags: m.flags,
        })
    }

    pub fn addr_is_mapped(&self, addr: u64) -> bool {
        self.addr_to_map(addr).is_some()
    }

    pub fn mappings(&self) -> Result<Mappings> {
        Ok(self.mappings.clone())
    }

    /// The symbols of one object, parsed on first use and biased to
    /// where the object actually landed. `STT_TLS` symbols keep their
    /// raw `st_value`: it is an offset into a TLS block, not an
    /// address, and biasing it would be meaningless.
    fn symbols_of(&self, path: &str) -> Option<&Symbols> {
        let backing = self.backing.get(path)?.as_ref()?;
        let symbols = backing.symbols.get_or_init(|| {
            let Ok(elf) = Elf::parse(&backing.map) else {
                return Symbols::default();
            };
            let bias = match &self.exec {
                Some(e) if e.path == path => e.bias,
                // Only the executable's bias is computed up front;
                // other objects are reached by address, below.
                _ => self.object_bias(&elf, path).unwrap_or(0),
            };

            // .symtab and .dynsym index different string tables, and a
            // stripped library has only the latter. Both are walked so
            // that libc resolves by address even with no symtab.
            let mut out = Symbols::default();
            for (table, strtab) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
                for sym in table.iter() {
                    let Some(name) = strtab.get_at(sym.st_name) else {
                        continue;
                    };
                    if name.is_empty() {
                        continue;
                    }
                    let kind = sym.st_type();
                    let entry = SymbolBuf {
                        name: name.to_string(),
                        st_name: sym.st_name,
                        st_info: sym.st_info,
                        st_other: sym.st_other,
                        st_shndx: sym.st_shndx,
                        // A thread-local's value is an offset into a TLS
                        // block, not an address; biasing it would make
                        // it neither.
                        st_value: if kind == STT_TLS {
                            sym.st_value
                        } else {
                            sym.st_value.wrapping_add(bias)
                        },
                        st_size: sym.st_size,
                    };
                    match kind {
                        STT_FUNC => out.functions.push(entry),
                        STT_OBJECT | STT_TLS => out.objects.push(entry),
                        _ => {}
                    }
                }
            }
            // A symbol in both tables lands here twice.
            for list in [&mut out.functions, &mut out.objects] {
                list.sort_by(|a, b| {
                    a.st_value
                        .cmp(&b.st_value)
                        .then_with(|| a.name.cmp(&b.name))
                });
                list.dedup_by(|a, b| a.name == b.name && a.st_value == b.st_value);
            }
            out
        });
        Some(symbols)
    }

    /// Where an object landed, for the objects that are not the
    /// executable: its lowest mapped range against its lowest `PT_LOAD`.
    fn object_bias(&self, elf: &Elf<'_>, path: &str) -> Option<u64> {
        let first = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .min_by_key(|ph| ph.p_vaddr)?;
        let mapped = self
            .files
            .iter()
            .filter(|f| f.path == path)
            .min_by_key(|f| f.range.start)?;
        Some(mapped.range.start.wrapping_sub(first.p_vaddr))
    }

    /// Every function symbol in the target executable's symtab, matching
    /// libproc's `PR_OBJ_EXEC` search.
    pub fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        let Some(exec) = &self.exec else {
            return Ok(Vec::new());
        };
        Ok(self
            .symbols_of(&exec.path)
            .map(|s| s.functions.clone())
            .unwrap_or_default())
    }

    pub fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        let Some(exec) = &self.exec else {
            return Ok(Vec::new());
        };
        Ok(self
            .symbols_of(&exec.path)
            .map(|s| s.objects.clone())
            .unwrap_or_default())
    }

    /// The symbol covering `address`, searched in whichever object is
    /// mapped there — libproc resolves an address in any object, not
    /// just the executable, and `unwind` relies on that for libc.
    pub fn lookup_symbol_by_addr(&self, address: u64) -> Option<SymbolBuf> {
        let path = self.file_at(address)?.path.clone();
        let symbols = self.symbols_of(&path)?;
        let idx = symbols.functions.partition_point(|s| s.st_value <= address);
        let sym = symbols.functions.get(idx.checked_sub(1)?)?;
        (address < sym.st_value + sym.st_size).then(|| sym.clone())
    }

    pub fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        let exec = self.exec.as_ref()?;
        let symbols = self.symbols_of(&exec.path)?;
        symbols
            .functions
            .iter()
            .chain(&symbols.objects)
            .find(|s| s.name == name)
            .cloned()
    }

    pub fn lookup_symbol_name_by_addr(&self, address: u64) -> Option<String> {
        self.lookup_symbol_by_addr(address).map(|s| s.name)
    }

    /// The address of an ELF thread-local in a given thread.
    ///
    /// x86-64 uses TLS Variant II: the static TLS block sits directly
    /// below the thread pointer (`%fsbase`), the executable's own block
    /// last, so a symbol at offset `st_value` within it is that far up
    /// from the bottom of a block of `tls_block` bytes.
    ///
    /// This covers the local-exec and initial-exec models, which is
    /// where a `thread_local!` in a Rust executable lives — tokio is
    /// linked into the binary, never dlopen'd, so its `CONTEXT` is in
    /// the executable's own `PT_TLS`. A general-dynamic thread-local
    /// from a dlopen'd module would need the DTV walk instead.
    pub fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        let ty = sym.st_info & 0xf;
        if ty != STT_TLS {
            return Err(Error::not_thread_local(&sym.name, ty));
        }
        // A thread with no thread pointer has no TLS to speak of.
        if regs.fsbase == 0 {
            return Ok(None);
        }
        let exec = self
            .exec
            .as_ref()
            .ok_or_else(|| Error::bad_core("no executable in the core's NT_FILE table"))?;
        Ok(Some(
            regs.fsbase
                .wrapping_sub(exec.tls_block)
                .wrapping_add(sym.st_value),
        ))
    }
}

/// Walk one `PT_NOTE`, collecting the notes that describe the process.
///
/// Per-thread notes are grouped, each group opening with `NT_PRSTATUS`,
/// so a new thread record starts on every one of those; the
/// process-wide notes are keyed by type and can appear anywhere.
fn parse_notes(
    bytes: &[u8],
    lwps: &mut Vec<LwpInfo>,
    files: &mut Vec<FileMap>,
    auxv: &mut BTreeMap<u64, u64>,
) -> Result<()> {
    let mut cur = Cursor::new(bytes);
    while cur.remaining() > 12 {
        let namesz = cur.u32()? as usize;
        let descsz = cur.u32()? as usize;
        let ntype = cur.u32()?;
        cur.take(namesz)?;
        cur.align_to(NOTE_ALIGN);
        let desc = cur.take(descsz)?;
        cur.align_to(NOTE_ALIGN);

        match ntype {
            NT_PRSTATUS => lwps.push(parse_prstatus(desc)?),
            NT_FILE => parse_nt_file(desc, files)?,
            NT_AUXV => {
                let mut c = Cursor::new(desc);
                while c.remaining() >= 16 {
                    let tag = c.u64()?;
                    let val = c.u64()?;
                    if tag == AT_NULL {
                        break;
                    }
                    auxv.insert(tag, val);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_prstatus(desc: &[u8]) -> Result<LwpInfo> {
    // Exactly, not merely enough. `struct elf_prstatus` is fixed ABI, so
    // a note of another size is another system's: illumos writes the
    // SVR4 `prstatus_t`, which is 824 bytes and holds its thread id and
    // registers somewhere else entirely. Reading it at these offsets
    // succeeds and yields nonsense, which is worse than refusing it.
    if desc.len() != PRSTATUS_LEN {
        return Err(Error::bad_core(
            "NT_PRSTATUS is not the size Linux writes; \
             this core came from another system",
        ));
    }
    let tid = u32::from_le_bytes(desc[PR_PID..PR_PID + 4].try_into().unwrap());
    let mut regs = [0u64; PR_REG_COUNT];
    for (slot, chunk) in regs
        .iter_mut()
        .zip(desc[PR_REG..].chunks_exact(8).take(PR_REG_COUNT))
    {
        *slot = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    Ok(LwpInfo {
        tid,
        regs: Regs::from_user_regs(&regs),
        // Filled in from the mappings once they are known.
        stack_range: 0..0,
        // A Linux core records no time at which a thread stopped; every
        // thread stopped when the process died.
        tstamp: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    })
}

/// `NT_FILE` is a count and a page size, then that many `(start, end,
/// file offset in pages)` triples, then that many paths in the same
/// order.
fn parse_nt_file(desc: &[u8], files: &mut Vec<FileMap>) -> Result<()> {
    let mut cur = Cursor::new(desc);
    let count = cur.u64()? as usize;
    let page_size = cur.u64()?;

    let mut ranges = Vec::with_capacity(count);
    for _ in 0..count {
        let start = cur.u64()?;
        let end = cur.u64()?;
        let pages = cur.u64()?;
        ranges.push((start, end, pages.wrapping_mul(page_size)));
    }
    for (start, end, offset) in ranges {
        let path = cur.cstr()?.to_string();
        files.push(FileMap {
            range: start..end,
            offset,
            path,
        });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    /// Builds an `ET_CORE` file in memory, so the reader can be held to
    /// cores a real one is awkward to produce: a region dumped and
    /// file-backed at once, a read straddling two sources, a mapping
    /// whose backing file is gone.
    ///
    /// Where a test needs a real ELF object to resolve against, it uses
    /// the test binary itself — a genuine PIE with a symtab, a `PT_TLS`
    /// and program headers, mapped at whatever base the test picks.
    #[derive(Default)]
    struct CoreBuilder {
        loads: Vec<Load>,
        threads: Vec<(u32, Regs)>,
        files: Vec<(Range<u64>, u64, String)>,
        auxv: Vec<(u64, u64)>,
        /// Emitted verbatim in place of the real notes, for the
        /// malformed-core tests.
        raw_notes: Option<Vec<u8>>,
    }

    struct Load {
        vaddr: u64,
        memsz: u64,
        flags: u32,
        /// The bytes actually written to the core; shorter than `memsz`
        /// when the kernel left the region out.
        bytes: Vec<u8>,
    }

    const PAGE: u64 = 0x1000;

    impl CoreBuilder {
        /// A region whose bytes are in the core.
        fn dumped(mut self, vaddr: u64, flags: u32, bytes: Vec<u8>) -> Self {
            self.loads.push(Load {
                vaddr,
                memsz: bytes.len() as u64,
                flags,
                bytes,
            });
            self
        }

        /// A region the dump filter left out: present in the address
        /// space, absent from the file.
        fn undumped(mut self, vaddr: u64, memsz: u64, flags: u32) -> Self {
            self.loads.push(Load {
                vaddr,
                memsz,
                flags,
                bytes: Vec::new(),
            });
            self
        }

        fn thread(mut self, tid: u32, regs: Regs) -> Self {
            self.threads.push((tid, regs));
            self
        }

        fn file(mut self, range: Range<u64>, offset: u64, path: &str) -> Self {
            self.files.push((range, offset, path.to_string()));
            self
        }

        fn auxv(mut self, tag: u64, val: u64) -> Self {
            self.auxv.push((tag, val));
            self
        }

        fn build(&self) -> Vec<u8> {
            let notes = self.raw_notes.clone().unwrap_or_else(|| self.notes());

            // Header, then one phdr per note/load segment, then bodies.
            let phnum = 1 + self.loads.len();
            let mut out = Vec::new();
            out.extend(elf_header(phnum as u16));

            let mut offset = (64 + phnum * 56) as u64;
            let note_offset = offset;
            out.extend(phdr(PT_NOTE, 0, note_offset, 0, notes.len() as u64, 0, 4));
            offset += notes.len() as u64;

            for load in &self.loads {
                out.extend(phdr(
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

            out.extend(&notes);
            for load in &self.loads {
                out.extend(&load.bytes);
            }
            out
        }

        fn notes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for (i, (tid, regs)) in self.threads.iter().enumerate() {
                out.extend(note(NT_PRSTATUS, "CORE", &prstatus(*tid, regs)));
                // The process-wide notes follow the first thread's, the
                // way the kernel writes them.
                if i == 0 {
                    if !self.files.is_empty() {
                        out.extend(note(NT_FILE, "CORE", &nt_file(&self.files)));
                    }
                    if !self.auxv.is_empty() {
                        let mut desc = Vec::new();
                        for (tag, val) in &self.auxv {
                            desc.extend(tag.to_le_bytes());
                            desc.extend(val.to_le_bytes());
                        }
                        desc.extend(AT_NULL.to_le_bytes());
                        desc.extend(0u64.to_le_bytes());
                        out.extend(note(NT_AUXV, "CORE", &desc));
                    }
                }
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

    fn elf_header(phnum: u16) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EV_CURRENT
        out[16..18].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE
        out[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        out[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        out[56..58].copy_from_slice(&phnum.to_le_bytes());
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn phdr(
        ptype: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(56);
        out.extend(ptype.to_le_bytes());
        out.extend(flags.to_le_bytes());
        out.extend(offset.to_le_bytes());
        out.extend(vaddr.to_le_bytes());
        out.extend(vaddr.to_le_bytes()); // p_paddr
        out.extend(filesz.to_le_bytes());
        out.extend(memsz.to_le_bytes());
        out.extend(align.to_le_bytes());
        out
    }

    fn note(ntype: u32, name: &str, desc: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let namesz = name.len() + 1;
        out.extend((namesz as u32).to_le_bytes());
        out.extend((desc.len() as u32).to_le_bytes());
        out.extend(ntype.to_le_bytes());
        out.extend(name.as_bytes());
        out.push(0);
        while out.len() % NOTE_ALIGN != 0 {
            out.push(0);
        }
        out.extend(desc);
        while out.len() % NOTE_ALIGN != 0 {
            out.push(0);
        }
        out
    }

    fn prstatus(tid: u32, regs: &Regs) -> Vec<u8> {
        let mut out = vec![0u8; PRSTATUS_LEN];
        out[PR_PID..PR_PID + 4].copy_from_slice(&tid.to_le_bytes());
        let user = [
            regs.r15,
            regs.r14,
            regs.r13,
            regs.r12,
            regs.rbp,
            regs.rbx,
            regs.r11,
            regs.r10,
            regs.r9,
            regs.r8,
            regs.rax,
            regs.rcx,
            regs.rdx,
            regs.rsi,
            regs.rdi,
            0,
            regs.rip,
            regs.cs,
            regs.rfl,
            regs.rsp,
            regs.ss,
            regs.fsbase,
            regs.gsbase,
            regs.ds,
            regs.es,
            regs.fs,
            regs.gs,
        ];
        for (i, v) in user.iter().enumerate() {
            let at = PR_REG + i * 8;
            out[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    fn nt_file(files: &[(Range<u64>, u64, String)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend((files.len() as u64).to_le_bytes());
        out.extend(PAGE.to_le_bytes());
        for (range, offset, _) in files {
            out.extend(range.start.to_le_bytes());
            out.extend(range.end.to_le_bytes());
            out.extend((offset / PAGE).to_le_bytes());
        }
        for (_, _, path) in files {
            out.extend(path.as_bytes());
            out.push(0);
        }
        out
    }

    fn regs_at(rip: u64, rsp: u64) -> Regs {
        Regs {
            rip,
            rsp,
            ..Regs::default()
        }
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

        assert_eq!(p.read_bytes(0x9000, 16).unwrap(), bytes[..16]);
        assert_eq!(p.read_bytes(0x9100, 8).unwrap(), bytes[0x100..0x108]);
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

    /// The pages the dump filter drops — text and rodata, under the
    /// default `coredump_filter` — are still readable, because the file
    /// they came from has them unchanged.
    #[test]
    fn test_undumped_pages_come_from_disk() {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let on_disk = std::fs::read(&exe).expect("failed to read the test binary");
        const BASE: u64 = 0x40_0000;

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .undumped(BASE, 0x2000, PF_R | PF_X)
            .file(BASE..BASE + 0x2000, 0, exe.to_str().unwrap())
            .proc();

        // Straight out of the file, at the offset the mapping names.
        assert_eq!(p.read_bytes(BASE, 4).unwrap(), b"\x7fELF");
        assert_eq!(p.read_bytes(BASE + 0x40, 32).unwrap(), on_disk[0x40..0x60]);
    }

    /// A region that is both dumped and file-backed reads out of the
    /// core: a writable page may have changed since it was mapped, and
    /// the core holds what the process actually had.
    #[test]
    fn test_core_bytes_win_over_the_file() {
        let exe = std::env::current_exe().unwrap();
        const BASE: u64 = 0x40_0000;

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(BASE, PF_R | PF_W, vec![0x5a; PAGE as usize])
            .file(BASE..BASE + PAGE, 0, exe.to_str().unwrap())
            .proc();

        assert_eq!(p.read_bytes(BASE, 4).unwrap(), [0x5a; 4]);
    }

    /// One read, two sources: the dumped half comes from the core and
    /// the rest from the file, without the caller knowing.
    #[test]
    fn test_reads_span_sources() {
        let exe = std::env::current_exe().unwrap();
        let on_disk = std::fs::read(&exe).unwrap();
        const BASE: u64 = 0x40_0000;

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(BASE, PF_R | PF_W, vec![0x5a; PAGE as usize])
            .undumped(BASE + PAGE, PAGE, PF_R | PF_X)
            .file(BASE..BASE + 2 * PAGE, 0, exe.to_str().unwrap())
            .proc();

        let got = p.read_bytes(BASE + PAGE - 4, 8).unwrap();
        assert_eq!(&got[..4], [0x5a; 4]);
        assert_eq!(&got[4..], &on_disk[PAGE as usize..PAGE as usize + 4]);
    }

    /// A mapping the core mentions only in `NT_FILE`, with no program
    /// header of its own — which is how gdb's `gcore` writes the
    /// regions it leaves out, unlike the kernel's empty `PT_LOAD`. The
    /// file still has the bytes, so it is a mapping and not a hole.
    #[test]
    fn test_nt_file_only_regions_are_mapped() {
        let exe = std::env::current_exe().unwrap();
        let on_disk = std::fs::read(&exe).unwrap();
        const BASE: u64 = 0x40_0000;

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .file(BASE..BASE + PAGE, 0, exe.to_str().unwrap())
            .proc();

        let maps = p.mappings().unwrap();
        let m = maps
            .get(BASE)
            .expect("the NT_FILE-only region is not in the address space");
        assert_eq!(m.path.as_deref(), exe.to_str());
        assert_eq!(m.size, PAGE);
        assert!(!m.flags.is_anon());
        assert!(p.addr_is_mapped(BASE + PAGE - 1));
        assert!(!p.addr_is_mapped(BASE + PAGE));

        // And it reads, off the file.
        assert_eq!(p.read_bytes(BASE, 4).unwrap(), b"\x7fELF");
        assert_eq!(p.read_bytes(BASE + 0x40, 16).unwrap(), on_disk[0x40..0x50]);

        // The mapping list stays in address order however the entries
        // were reached.
        let vaddrs: Vec<u64> = maps.iter().map(|m| m.vaddr).collect();
        assert!(vaddrs.windows(2).all(|w| w[0] <= w[1]), "{vaddrs:#x?}");
    }

    /// A region with a program header is described by it, not by the
    /// `NT_FILE` entry that also covers it.
    #[test]
    fn test_program_headers_win_over_the_file_table() {
        let exe = std::env::current_exe().unwrap();
        const BASE: u64 = 0x40_0000;

        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .undumped(BASE, 2 * PAGE, PF_R | PF_X)
            .file(BASE..BASE + PAGE, 0, exe.to_str().unwrap())
            .proc();

        let maps = p.mappings().unwrap();
        assert_eq!(maps.iter().filter(|m| m.vaddr == BASE).count(), 1);
        let m = maps.get(BASE).unwrap();
        assert!(m.is_text(), "{m:?}");
        assert_eq!(m.size, 2 * PAGE, "the header's size was overwritten");
    }

    /// A core routinely names files that have since moved. Reads that
    /// land in one fail; everything else still works.
    #[test]
    fn test_missing_backing_file_is_not_fatal() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0x11; PAGE as usize])
            .undumped(0x40_0000, PAGE, PF_R | PF_X)
            .file(0x40_0000..0x40_0000 + PAGE, 0, "/nonexistent/libfoo.so")
            .proc();

        assert!(p.read_bytes(0x40_0000, 8).is_err());
        assert_eq!(p.read_bytes(0x9000, 4).unwrap(), [0x11; 4]);
        // It is still a mapping, with the name the core recorded.
        let m = p.mappings().unwrap();
        assert_eq!(
            m.get(0x40_0000).unwrap().path.as_deref(),
            Some("/nonexistent/libfoo.so")
        );
    }

    // -----------------------------------------------------------------------
    // Threads and mappings
    // -----------------------------------------------------------------------

    /// Every `NT_PRSTATUS` is a thread, its registers decoded from the
    /// x86-64 `user_regs_struct` and its stack taken to be the mapping
    /// holding `%rsp`.
    #[test]
    fn test_threads_decode_from_prstatus() {
        let regs = Regs {
            rip: 0x40_1000,
            rsp: 0x9800,
            rbp: 0x9900,
            rax: 0xaaaa,
            r15: 0xffff,
            fsbase: 0x7000,
            ..Regs::default()
        };
        let (_dir, p) = CoreBuilder::default()
            .thread(42, regs.clone())
            .thread(43, regs_at(0x40_2000, 0x18800))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(0x18000, PF_R | PF_W, vec![0; PAGE as usize])
            .proc();

        let lwps = p.lwps().unwrap();
        assert_eq!(lwps.len(), 2);
        assert_eq!(lwps[0].tid, 42);
        assert_eq!(lwps[0].regs, regs);
        assert_eq!(lwps[0].stack_range, 0x9000..0x9000 + PAGE);
        assert_eq!(lwps[1].tid, 43);
        assert_eq!(lwps[1].stack_range, 0x18000..0x18000 + PAGE);
        // Registers are also reachable by thread id.
        assert_eq!(p.regs(42).unwrap(), regs);
        assert!(p.regs(99).is_err());
        // The first thread is the one that died.
        assert_eq!(p.status().active_lwp, 42);
        assert_eq!(p.status().stack_range, 0x9000..0x9000 + PAGE);
    }

    /// `trapno` and `err` have no Linux counterpart, and `orig_rax`
    /// sits where they would: it must not be mistaken for either.
    #[test]
    fn test_orig_rax_is_not_read_as_a_register() {
        let mut desc = prstatus(7, &regs_at(0x1000, 0x2000));
        // Poison orig_rax, index 15 of user_regs_struct.
        let at = PR_REG + 15 * 8;
        desc[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());

        let mut builder = CoreBuilder::default().dumped(0x2000, PF_R | PF_W, vec![0; 8]);
        builder.raw_notes = Some(note(NT_PRSTATUS, "CORE", &desc));
        let (_dir, p) = builder.proc();

        let lwp = &p.lwps().unwrap()[0];
        assert_eq!(lwp.regs.trapno, 0);
        assert_eq!(lwp.regs.err, 0);
        assert_eq!(lwp.regs.rip, 0x1000);
        assert!(!format!("{:?}", lwp.regs).contains("ffffffffffffffff"));
    }

    /// The mapping table joins the `PT_LOAD` list to `NT_FILE`: ELF
    /// permission bits carry over as the procfs ones they coincide
    /// with, and a region no file claims is anonymous.
    #[test]
    fn test_mappings_join_the_file_table() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .undumped(0x40_0000, PAGE, PF_R | PF_X)
            .dumped(0x40_1000, PF_R | PF_W, vec![0; PAGE as usize])
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .file(0x40_0000..0x40_1000, 0, "/bin/prog")
            .file(0x40_1000..0x40_2000, PAGE, "/bin/prog")
            .proc();

        let maps = p.mappings().unwrap();
        assert_eq!(maps.len(), 3);

        let text = maps.get(0x40_0000).unwrap();
        assert!(text.is_text(), "{text:?}");
        assert_eq!(text.path.as_deref(), Some("/bin/prog"));
        assert!(!text.flags.is_anon());

        let data = maps.get(0x40_1000).unwrap();
        assert!(data.is_data(), "{data:?}");

        // No file claims the stack, so it is anonymous.
        let stack = maps.get(0x9000).unwrap();
        assert!(stack.flags.is_anon(), "{stack:?}");
        assert_eq!(stack.path, None);

        assert_eq!(p.addr_to_map(0x40_0000).unwrap().vaddr, 0x40_0000);
        assert!(p.addr_is_mapped(0x40_0fff));
        assert!(!p.addr_is_mapped(0x50_0000));
        assert!(p.addr_to_map(0x50_0000).is_none());
    }

    // -----------------------------------------------------------------------
    // Symbols and thread-locals
    // -----------------------------------------------------------------------

    /// Map the test binary — a real PIE with a real symtab — at a base
    /// of the test's choosing, and point `AT_PHDR` into it so it is
    /// taken for the executable.
    fn with_test_binary(base: u64) -> (tempfile::TempDir, Core, PathBuf) {
        let exe = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&exe).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let size = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| ph.p_vaddr + ph.p_memsz)
            .max()
            .unwrap()
            .next_multiple_of(PAGE);

        let (dir, p) = CoreBuilder::default()
            .thread(1, regs_at(base, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; PAGE as usize])
            .undumped(base, size, PF_R | PF_X)
            .file(base..base + size, 0, exe.to_str().unwrap())
            .auxv(AT_PHDR, base + elf.header.e_phoff)
            .proc();
        (dir, p, exe)
    }

    /// A PIE's symbols are link-time addresses; what a caller wants is
    /// where they actually landed.
    #[test]
    fn test_symbols_are_biased_to_where_the_object_landed() {
        const BASE: u64 = 0x5555_0000_0000;
        let (_dir, p, exe) = with_test_binary(BASE);
        assert_eq!(p.exec_name().unwrap(), exe);

        let bytes = std::fs::read(&exe).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let want: Vec<_> = elf
            .syms
            .iter()
            .filter(|s| s.st_type() == STT_FUNC && s.st_size > 0)
            .filter_map(|s| Some((elf.strtab.get_at(s.st_name)?.to_string(), s.st_value)))
            .take(20)
            .collect();
        assert!(!want.is_empty(), "the test binary has no function symbols");

        // The bias is where the object landed less where it was linked,
        // which is zero for a position-dependent executable and its
        // whole base for a PIE. Worked out here rather than assumed, so
        // this holds whichever kind the test binary happens to be.
        let lowest = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| ph.p_vaddr)
            .min()
            .unwrap();
        let bias = BASE - lowest;

        for (name, link_value) in want {
            let sym = p
                .lookup_symbol_by_name(&name)
                .unwrap_or_else(|| panic!("{name} did not resolve"));
            assert_eq!(sym.st_value, link_value + bias, "{name} has the wrong bias");
            // And back again, from an address inside the function.
            assert_eq!(
                p.lookup_symbol_by_addr(sym.st_value)
                    .as_ref()
                    .map(|s| &s.name),
                Some(&sym.name)
            );
        }
        assert!(p.lookup_symbol_by_name("no_such_symbol_anywhere").is_none());
        assert!(p.lookup_symbol_by_addr(0x9000).is_none());
        assert!(!p.symbols().unwrap().is_empty());
    }

    /// A thread-local's `st_value` is an offset into a TLS block, so
    /// the load bias must not touch it — biasing would leave it neither
    /// an offset nor an address.
    ///
    /// Stands in the test binary for the object a Linux core names, so
    /// it needs one built the way those are: with native ELF TLS. That
    /// is what the toolchain produces here and not what it produces on
    /// illumos, where std compiles a `thread_local!` to a pthread key
    /// and emits no `STT_TLS` symbol at all. The reader's other tests
    /// are platform-neutral and do run everywhere.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_symbols_keep_their_offsets() {
        const BASE: u64 = 0x5555_0000_0000;
        let (_dir, p, exe) = with_test_binary(BASE);

        let bytes = std::fs::read(&exe).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let tls: Vec<_> = elf
            .syms
            .iter()
            .filter(|s| s.st_type() == STT_TLS)
            .filter_map(|s| Some((elf.strtab.get_at(s.st_name)?.to_string(), s.st_value)))
            .collect();
        assert!(!tls.is_empty(), "the test binary has no thread-locals");

        for (name, offset) in &tls {
            let sym = p.lookup_symbol_by_name(name).unwrap();
            assert_eq!(sym.st_value, *offset, "{name} was biased");
        }
    }

    /// x86-64 puts the static TLS block below the thread pointer, so a
    /// thread-local is at `%fsbase - block + offset` — different in
    /// every thread, and never confused with the symbol's own value.
    ///
    /// Needs a binary with native ELF TLS; see
    /// [`test_tls_symbols_keep_their_offsets`].
    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_var_addr_is_per_thread() {
        const BASE: u64 = 0x5555_0000_0000;
        let (_dir, p, exe) = with_test_binary(BASE);

        let bytes = std::fs::read(&exe).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let block = elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_TLS)
            .map(|ph| ph.p_memsz.next_multiple_of(ph.p_align.max(1)))
            .expect("the test binary has a PT_TLS");

        let sym = p
            .object_symbols()
            .unwrap()
            .into_iter()
            .find(|s| s.st_info & 0xf == STT_TLS)
            .expect("the test binary has a thread-local");

        for fsbase in [0x7f00_0000_0000u64, 0x7f00_0010_0000] {
            let regs = Regs {
                fsbase,
                ..Regs::default()
            };
            assert_eq!(
                p.tls_var_addr(&regs, &sym).unwrap(),
                Some(fsbase - block + sym.st_value)
            );
        }

        // A thread with no thread pointer holds no thread-locals.
        let none = Regs::default();
        assert_eq!(p.tls_var_addr(&none, &sym).unwrap(), None);

        // And a symbol that names ordinary storage is not a
        // thread-local, however much a caller would like it to be.
        let plain = p
            .symbols()
            .unwrap()
            .into_iter()
            .next()
            .expect("the test binary has functions");
        let err = p
            .tls_var_addr(&Regs::default(), &plain)
            .expect_err("a function resolved as a thread-local");
        assert!(
            err.to_string().contains("not a thread-local symbol"),
            "{err}"
        );
    }

    // -----------------------------------------------------------------------
    // Malformed cores
    // -----------------------------------------------------------------------

    #[test]
    fn test_open_rejects_what_is_not_a_core() {
        let dir = tempfile::tempdir().unwrap();

        let path = dir.path().join("garbage");
        std::fs::write(&path, b"not an elf file at all").unwrap();
        assert!(Core::open(&path).is_err());

        assert!(Core::open(&dir.path().join("no-such-file")).is_err());

        // A well-formed ELF that is not a core.
        let path = dir.path().join("exe");
        std::fs::write(
            &path,
            std::fs::read(std::env::current_exe().unwrap()).unwrap(),
        )
        .unwrap();
        let err = Core::open(&path).unwrap_err();
        assert_eq!(err.to_string(), "malformed core file: not a core file");
    }

    #[test]
    fn test_open_rejects_a_core_with_no_threads() {
        let (_dir, res) = CoreBuilder::default()
            .dumped(0x9000, PF_R | PF_W, vec![0; 8])
            .open();
        assert_eq!(
            res.unwrap_err().to_string(),
            "malformed core file: no NT_PRSTATUS note"
        );
    }

    #[test]
    fn test_open_rejects_truncated_notes() {
        // A note header promising a descriptor that is not there.
        let mut builder = CoreBuilder::default().dumped(0x9000, PF_R | PF_W, vec![0; 8]);
        let mut truncated = note(NT_PRSTATUS, "CORE", &prstatus(1, &regs_at(0, 0x9000)));
        truncated.truncate(truncated.len() / 2);
        builder.raw_notes = Some(truncated);
        assert!(builder.open().1.is_err());

        // A PRSTATUS too short to hold a register set.
        let mut builder = CoreBuilder::default().dumped(0x9000, PF_R | PF_W, vec![0; 8]);
        builder.raw_notes = Some(note(NT_PRSTATUS, "CORE", &[0u8; 16]));
        assert_eq!(
            builder.open().1.unwrap_err().to_string(),
            "malformed core file: NT_PRSTATUS is not the size Linux writes; \
             this core came from another system"
        );
    }

    /// An illumos core reaching this reader is a dispatch failure, and
    /// it must not be read anyway: illumos writes the SVR4 `prstatus_t`,
    /// 824 bytes with its thread id and registers at other offsets, and
    /// reading that at Linux's offsets yields a plausible core full of
    /// zeroed threads rather than an error.
    #[test]
    fn test_open_rejects_a_foreign_core() {
        const ILLUMOS_PRSTATUS_LEN: usize = 824;

        let mut builder = CoreBuilder::default().dumped(0x9000, PF_R | PF_W, vec![0; 8]);
        builder.raw_notes = Some(note(NT_PRSTATUS, "CORE", &vec![0u8; ILLUMOS_PRSTATUS_LEN]));
        assert_eq!(
            builder.open().1.unwrap_err().to_string(),
            "malformed core file: NT_PRSTATUS is not the size Linux writes; \
             this core came from another system"
        );
    }

    /// Which system wrote a core, answered before anything commits to
    /// reading it, from the notes each system writes and the other does
    /// not.
    #[test]
    fn test_flavour_tells_the_two_apart() {
        use crate::coredump::{Flavour, flavour_of};

        /// `NT_PSINFO`: illumos writes it, Linux has no note of that
        /// number.
        const ILLUMOS_PSINFO: u32 = 13;
        const ILLUMOS_PRSTATUS_LEN: usize = 824;

        // NT_FILE marks the Linux core, whatever else it holds.
        let linux = CoreBuilder::default()
            .thread(1, regs_at(0x1000, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; 8])
            .file(0x40_0000..0x40_1000, 0, "/bin/prog");
        assert_eq!(flavour_of(&linux.build()).unwrap(), Flavour::Linux);

        // An illumos core says so with its own status notes, and its
        // NT_PRSTATUS is a different size besides.
        let mut illumos = CoreBuilder::default().dumped(0x9000, PF_R | PF_W, vec![0; 8]);
        let mut notes = note(NT_PRSTATUS, "CORE", &vec![0u8; ILLUMOS_PRSTATUS_LEN]);
        notes.extend(note(ILLUMOS_PSINFO, "CORE", &[0u8; 16]));
        illumos.raw_notes = Some(notes);
        assert_eq!(flavour_of(&illumos.build()).unwrap(), Flavour::Illumos);

        // With nothing distinctive left, the register-set size still
        // answers: a Linux core of a process that mapped no files.
        let mut bare = CoreBuilder::default()
            .thread(1, regs_at(0x1000, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0; 8]);
        bare.raw_notes = Some(note(NT_PRSTATUS, "CORE", &prstatus(1, &regs_at(0, 0x9000))));
        assert_eq!(flavour_of(&bare.build()).unwrap(), Flavour::Linux);

        // A core with no notes at all names no system, and neither does
        // something that is not a core.
        let mut headless = CoreBuilder::default().dumped(0x9000, PF_R | PF_W, vec![0; 8]);
        headless.raw_notes = Some(Vec::new());
        assert!(flavour_of(&headless.build()).is_err());
        assert!(flavour_of(b"not an elf").is_err());
    }

    /// A core with no `AT_PHDR`, or one pointing nowhere, has no
    /// executable to take symbols from — but its memory still reads.
    #[test]
    fn test_core_without_an_executable_still_reads() {
        let (_dir, p) = CoreBuilder::default()
            .thread(1, regs_at(0, 0x9000))
            .dumped(0x9000, PF_R | PF_W, vec![0x77; PAGE as usize])
            .proc();

        assert!(p.exec_name().is_err());
        assert!(p.symbols().unwrap().is_empty());
        assert!(p.object_symbols().unwrap().is_empty());
        assert!(p.lookup_symbol_by_name("main").is_none());
        assert_eq!(p.read_bytes(0x9000, 4).unwrap(), [0x77; 4]);
    }
}

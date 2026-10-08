// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Source lines for native code: `::whatline`, `::srclist`,
//! `::srcstack` and `::srcpath`.
//!
//! mdb resolves an address to `object`symbol+offset` and stops there:
//! system objects carry CTF, which has no line tables. A Rust program
//! built with debug info carries DWARF, so these dcmds read it straight
//! from the object mdb says the address is in, and answer with the
//! function, `file:line:col`, and every frame inlined at that address.
//!
//! They need no hansei session: they read the object files and the
//! stack, nothing tokio. Objects without DWARF (libc, the linker) still
//! get their symbol, as `$C` gives it.

use crate::ffi::*;
use crate::target::{Object, loaded_objects, mdb_lock};
use crate::{guard, words};

use object::{Object as _, ObjectSegment};

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, c_int, c_uint};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Result, anyhow, bail};

const PAGE: u64 = 0x1000;

// ---------------------------------------------------------------------
// DWARF per object

/// One frame of an address's answer; inlining gives several, innermost
/// first.
struct Frame {
    function: Option<String>,
    file: Option<String>,
    line: Option<u32>,
    column: Option<u32>,
    inlined: bool,
}

impl Frame {
    fn location(&self) -> Option<String> {
        let file = self.file.as_ref()?;
        Some(match (self.line, self.column) {
            (Some(l), Some(c)) if c > 0 => format!("{file}:{l}:{c}"),
            (Some(l), _) => format!("{file}:{l}"),
            _ => file.clone(),
        })
    }
}

/// An object file's DWARF, and where it was linked to run.
struct ObjectIndex {
    loader: addr2line::Loader,
    /// Lowest `PT_LOAD`, page-aligned: what mdb's base for the object
    /// corresponds to.
    link_base: u64,
    link_end: u64,
    has_dwarf: bool,
}

impl ObjectIndex {
    fn open(path: &Path) -> Result<Self> {
        let data = fs::read(path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
        let obj = object::File::parse(&*data).map_err(|e| anyhow!("{}: {e}", path.display()))?;
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        for seg in obj.segments().filter(|s| s.size() > 0) {
            lo = lo.min(seg.address());
            hi = hi.max(seg.address() + seg.size());
        }
        if lo == u64::MAX {
            bail!("{}: no loadable segments", path.display());
        }
        let has_dwarf = obj.section_by_name(".debug_line").is_some();
        drop(obj);
        let loader =
            addr2line::Loader::new(path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
        Ok(ObjectIndex {
            loader,
            link_base: lo & !(PAGE - 1),
            link_end: hi,
            has_dwarf,
        })
    }

    fn to_link_addr(&self, runtime: u64, load_base: u64) -> Option<u64> {
        let svma = runtime
            .checked_sub(load_base)?
            .checked_add(self.link_base)?;
        (svma < self.link_end).then_some(svma)
    }

    fn frames(&self, svma: u64) -> Vec<Frame> {
        let mut out = Vec::new();
        if let Ok(mut it) = self.loader.find_frames(svma) {
            while let Ok(Some(f)) = it.next() {
                let function = f
                    .function
                    .as_ref()
                    .and_then(|n| n.demangle().ok().map(|s| s.into_owned()));
                let (file, line, column) = match f.location {
                    Some(l) => (l.file.map(str::to_owned), l.line, l.column),
                    None => (None, None, None),
                };
                out.push(Frame {
                    function,
                    file,
                    line,
                    column,
                    inlined: true,
                });
            }
        }
        if let Some(last) = out.last_mut() {
            last.inlined = false;
        }
        out
    }

    fn symbol_offset(&self, svma: u64) -> Option<(String, u64)> {
        let s = self.loader.find_symbol_info(svma)?;
        Some((
            addr2line::demangle_auto(s.name().into(), None).into_owned(),
            svma - s.address(),
        ))
    }
}

/// Where to look for sources whose recorded paths are not on this
/// machine.
#[derive(Default)]
struct SourcePath {
    substitutions: Vec<(String, String)>,
    dirs: Vec<PathBuf>,
}

impl SourcePath {
    fn resolve(&self, recorded: &str) -> Option<PathBuf> {
        let p = Path::new(recorded);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
        for (from, to) in &self.substitutions {
            if let Some(rest) = recorded.strip_prefix(from.as_str()) {
                let cand = PathBuf::from(format!("{to}{rest}"));
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
        let comps: Vec<_> = p.components().collect();
        for d in &self.dirs {
            // The recorded path under d, then ever shorter suffixes of it.
            for i in 0..comps.len() {
                let suffix: PathBuf = comps[i..].iter().collect();
                if suffix.is_absolute() {
                    continue;
                }
                let cand = d.join(&suffix);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
        None
    }
}

#[derive(Default)]
struct State {
    /// Object path -> its index, rebuilt when the file changes.
    objects: HashMap<PathBuf, (Option<SystemTime>, ObjectIndex)>,
    srcpath: SourcePath,
}

impl State {
    fn index(&mut self, path: &Path) -> Result<&ObjectIndex> {
        let mtime = fs::metadata(path).and_then(|m| m.modified()).ok();
        if self.objects.get(path).is_none_or(|(t, _)| *t != mtime) {
            let index = ObjectIndex::open(path)?;
            self.objects.insert(path.to_path_buf(), (mtime, index));
        }
        Ok(&self.objects[path].1)
    }
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State {
        srcpath: SourcePath {
            dirs: std::env::var("MDB_SRCPATH")
                .map(|v| v.split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect())
                .unwrap_or_default(),
            ..SourcePath::default()
        },
        ..State::default()
    });
}

/// What an address is: the object, its symbol, and its frames.
struct Answer {
    symbol: String,
    frames: Vec<Frame>,
    has_dwarf: bool,
}

/// Resolve `probe` (the address looked up) and name `shown` (the
/// address printed: a return address, where `probe` is the call just
/// before it).
fn answer(state: &mut State, objects: &[Object], probe: u64, shown: u64) -> Option<Answer> {
    // The object loaded nearest below the address that also extends
    // over it: mdb's base for an object is its first mapping.
    let mut candidates: Vec<&Object> = objects.iter().filter(|o| o.base <= probe).collect();
    candidates.sort_by_key(|o| std::cmp::Reverse(o.base));
    for object in candidates {
        let Ok(index) = state.index(Path::new(&object.path)) else {
            continue;
        };
        let Some(svma) = index.to_link_addr(probe, object.base) else {
            continue;
        };
        let name = object.path.rsplit('/').next().unwrap_or(&object.path);
        let at = svma.wrapping_add(shown.wrapping_sub(probe));
        let symbol = match index.symbol_offset(at) {
            Some((s, 0)) => format!("{name}`{s}"),
            Some((s, off)) => format!("{name}`{s}+{off:#x}"),
            None => format!("{shown:#x}"),
        };
        return Some(Answer {
            symbol,
            frames: if index.has_dwarf {
                index.frames(svma)
            } else {
                Vec::new()
            },
            has_dwarf: index.has_dwarf,
        });
    }
    None
}

fn frames_text(frames: &[Frame], indent: &str) -> String {
    let mut out = String::new();
    for f in frames {
        let tag = if f.inlined { " [inlined]" } else { "" };
        out.push_str(&format!(
            "{indent}{}{tag}\n",
            f.function.as_deref().unwrap_or("??")
        ));
        if let Some(loc) = f.location() {
            out.push_str(&format!("{indent}    at {loc}\n"));
        }
    }
    out
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

// ---------------------------------------------------------------------
// dcmds

pub(crate) unsafe extern "C" fn dcmd_whatline(
    addr: usize,
    flags: c_uint,
    argc: c_int,
    _argv: *const mdb_arg_t,
) -> c_int {
    guard(|| {
        if flags & DCMD_ADDRSPEC == 0 || argc != 0 {
            return Ok((DCMD_USAGE, String::new()));
        }
        let addr = addr as u64;
        let objects = loaded_objects();
        let text = with_state(|st| match answer(st, &objects, addr, addr) {
            None => Err(anyhow!("{addr:#x} is in no object mdb has loaded")),
            Some(a) => {
                let mut out = format!("{addr:#x} {}\n", a.symbol);
                if !a.has_dwarf {
                    out.push_str("    no line information: this object carries no DWARF\n");
                } else if a.frames.is_empty() {
                    out.push_str("    no line information for this address\n");
                }
                out.push_str(&frames_text(&a.frames, "    "));
                Ok(out)
            }
        })?;
        Ok((DCMD_OK, text))
    })
}

pub(crate) unsafe extern "C" fn dcmd_srclist(
    addr: usize,
    flags: c_uint,
    argc: c_int,
    argv: *const mdb_arg_t,
) -> c_int {
    let words = unsafe { words(argc, argv) };
    guard(|| {
        if flags & DCMD_ADDRSPEC == 0 {
            return Ok((DCMD_USAGE, String::new()));
        }
        let ctx = match words.as_slice() {
            [] => 5,
            [flag, n] if flag == "-n" => {
                parse_decimal(n).ok_or_else(|| anyhow!("bad -n value {n}"))? as u32
            }
            _ => return Ok((DCMD_USAGE, String::new())),
        };
        let addr = addr as u64;
        let objects = loaded_objects();
        let text = with_state(|st| -> Result<String> {
            let a = answer(st, &objects, addr, addr)
                .ok_or_else(|| anyhow!("{addr:#x} is in no object mdb has loaded"))?;
            // The innermost frame is the code actually at the address.
            let f = a
                .frames
                .first()
                .ok_or_else(|| anyhow!("no line information for {addr:#x}"))?;
            let (Some(file), Some(line)) = (&f.file, f.line) else {
                bail!("no line information for {addr:#x}");
            };
            let mut out = format!(
                "{} at {}\n",
                f.function.as_deref().unwrap_or("??"),
                f.location().unwrap_or_default()
            );
            let Some(path) = st.srcpath.resolve(file) else {
                out.push_str(&format!("    source not found: {file} (see ::srcpath)\n"));
                return Ok(out);
            };
            let source =
                fs::read_to_string(&path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
            let (lo, hi) = (line.saturating_sub(ctx).max(1), line.saturating_add(ctx));
            for (i, text) in source.lines().enumerate() {
                let n = i as u32 + 1;
                if (lo..=hi).contains(&n) {
                    let mark = if n == line { "=>" } else { "  " };
                    out.push_str(&format!("{mark}{n:>6}  {text}\n"));
                }
            }
            Ok(out)
        })?;
        Ok((DCMD_OK, text))
    })
}

fn parse_decimal(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.strip_prefix("0t").unwrap_or(s).parse().ok(),
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    match s.strip_prefix("0t") {
        Some(dec) => dec.parse().ok(),
        None => u64::from_str_radix(s.trim_start_matches("0x"), 16).ok(),
    }
}

fn read_u64(addr: u64) -> Option<u64> {
    let mut v = 0u64;
    let _g = mdb_lock();
    let n = unsafe { mdb_vread((&raw mut v).cast(), 8, addr as usize) };
    (n == 8).then_some(v)
}

fn getreg(tid: usize, name: &CStr) -> Result<u64> {
    let mut v = 0u64;
    let rc = {
        let _g = mdb_lock();
        unsafe { mdb_getareg(tid, name.as_ptr(), &mut v) }
    };
    if rc != 0 {
        bail!("can't read %{} of thread {tid}", name.to_string_lossy());
    }
    Ok(v)
}

pub(crate) unsafe extern "C" fn dcmd_srcstack(
    addr: usize,
    flags: c_uint,
    argc: c_int,
    argv: *const mdb_arg_t,
) -> c_int {
    let words = unsafe { words(argc, argv) };
    guard(|| {
        let (mut tid, mut pc) = (1usize, None);
        let mut i = 0;
        while i < words.len() {
            match (words[i].as_str(), words.get(i + 1)) {
                ("-t", Some(v)) => {
                    tid = parse_decimal(v).ok_or_else(|| anyhow!("bad -t value {v}"))? as usize
                }
                ("-p", Some(v)) => {
                    pc = Some(parse_hex(v).ok_or_else(|| anyhow!("bad -p value {v}"))?)
                }
                _ => return Ok((DCMD_USAGE, String::new())),
            }
            i += 2;
        }
        // The first frame: an explicit frame pointer (and pc), or the
        // thread's registers, as `$C` starts.
        let mut fp = match flags & DCMD_ADDRSPEC != 0 {
            true => addr as u64,
            false => getreg(tid, c"rbp")?,
        };
        let mut pc = match pc {
            Some(pc) => pc,
            None => getreg(tid, c"rip")?,
        };

        let objects = loaded_objects();
        let piped = flags & DCMD_PIPE_OUT != 0;
        let text = with_state(|st| {
            let mut out = String::new();
            for depth in 0..256 {
                if piped {
                    out.push_str(&format!("{pc:#x}\n"));
                } else {
                    // A return address is just past its call: look up
                    // the byte before it, which is the call's own line.
                    let probe = if depth == 0 { pc } else { pc - 1 };
                    match answer(st, &objects, probe, pc) {
                        Some(a) => {
                            out.push_str(&format!("{fp:016x} {}\n", a.symbol));
                            out.push_str(&frames_text(&a.frames, "    "));
                        }
                        None => out.push_str(&format!("{fp:016x} {pc:#x}\n")),
                    }
                }
                if fp == 0 {
                    break;
                }
                let (Some(next_fp), Some(ret)) = (read_u64(fp), read_u64(fp + 8)) else {
                    break;
                };
                // Callers live at higher addresses; anything else is the
                // end of the chain, or code without frame pointers.
                if ret == 0 || next_fp <= fp {
                    if next_fp != 0 && next_fp <= fp && !piped {
                        out.push_str("    (frame chain broken: built without frame pointers?)\n");
                    }
                    break;
                }
                (fp, pc) = (next_fp, ret);
            }
            out
        });
        Ok((DCMD_OK, text))
    })
}

pub(crate) unsafe extern "C" fn dcmd_srcpath(
    _addr: usize,
    flags: c_uint,
    argc: c_int,
    argv: *const mdb_arg_t,
) -> c_int {
    let words = unsafe { words(argc, argv) };
    guard(|| {
        if flags & DCMD_ADDRSPEC != 0 {
            return Ok((DCMD_USAGE, String::new()));
        }
        let text = with_state(|st| -> Result<Option<String>> {
            let mut i = 0;
            while i < words.len() {
                match (words[i].as_str(), words.get(i + 1)) {
                    ("-c", _) => {
                        st.srcpath = SourcePath::default();
                        st.objects.clear();
                        i += 1;
                    }
                    ("-d", Some(dir)) => {
                        st.srcpath.dirs.push(dir.into());
                        i += 2;
                    }
                    ("-s", Some(sub)) => {
                        let (from, to) = sub
                            .split_once('=')
                            .ok_or_else(|| anyhow!("-s wants FROM=TO"))?;
                        st.srcpath.substitutions.push((from.into(), to.into()));
                        i += 2;
                    }
                    _ => return Ok(None),
                }
            }
            let mut out = String::new();
            for (from, to) in &st.srcpath.substitutions {
                out.push_str(&format!("substitute {from} -> {to}\n"));
            }
            for dir in &st.srcpath.dirs {
                out.push_str(&format!("search     {}\n", dir.display()));
            }
            if out.is_empty() {
                out.push_str("(no source path set: sources are read where DWARF recorded them)\n");
            }
            Ok(Some(out))
        })?;
        Ok(match text {
            Some(text) => (DCMD_OK, text),
            None => (DCMD_USAGE, String::new()),
        })
    })
}

pub(crate) unsafe extern "C" fn help_whatline() {
    crate::print(concat!(
        "The function and source file:line:col at an address, from the DWARF of\n",
        "the object it is in, with every frame inlined there, innermost first.\n",
        "Objects without DWARF (libc) give their symbol only.\n\n",
        "  <rip::whatline\n",
        "  ::srcstack | ::whatline\n",
    ));
}

pub(crate) unsafe extern "C" fn help_srclist() {
    crate::print(concat!(
        "List the source around an address, marking its line. -n N lines of\n",
        "context (default 5). Moved sources: see ::srcpath.\n\n",
        "  <rip::srclist -n 3\n",
    ));
}

pub(crate) unsafe extern "C" fn help_srcstack() {
    crate::print(concat!(
        "$C with source lines: walk the frame-pointer chain and give every frame\n",
        "its file:line, inlined frames included. Return addresses resolve to the\n",
        "line of the call.\n\n",
        "  ::srcstack             thread 1's %rbp/%rip (-t LWP for another)\n",
        "  fp::srcstack -p pc     start from an explicit frame\n",
        "Piped, it emits each frame's pc. Rust code needs\n",
        "-C force-frame-pointers=yes for the chain to hold.\n",
    ));
}

pub(crate) unsafe extern "C" fn help_srcpath() {
    crate::print(concat!(
        "Where ::srclist finds sources whose recorded paths are not here.\n",
        "  -d DIR         search DIR (the recorded path and its suffixes under it)\n",
        "  -s FROM=TO     rewrite a recorded prefix, e.g. Rust's std:\n",
        "                 -s /rustc/<hash>=$(rustc --print sysroot)/lib/rustlib/src/rust\n",
        "  -c             clear, and drop cached DWARF\n",
        "MDB_SRCPATH (colon-separated) seeds -d at load.\n",
    ));
}

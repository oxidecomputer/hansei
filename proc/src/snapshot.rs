//! Serializable target snapshots (`HANSEI_V0_MANGLING_PLAN.md` §11.3).
//!
//! A [`Snapshot`] captures the handful of things a debugger actually
//! read from a target — memory runs, symbol lookups, the function
//! symtab, mappings, and LWP state — into a compact file that
//! implements [`Target`] on any platform. [`Recorder`] wraps a real
//! target (a live process or core on illumos) and records everything
//! the wrapped reads touch, so capturing a snapshot is just driving
//! the ordinary analysis once with the recorder in place.
//!
//! Snapshots are test fixtures, not an interchange format: the same
//! tool version writes and reads them, and the version check rejects
//! everything else.

use crate::{
    Error as TargetError, LwpInfo, Mappings, Regs, Result as TargetResult, SymbolBuf, Target,
};

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Mutex;

/// Uncompressed file header: magic, then a little-endian format version,
/// then a zstd frame containing the postcard-encoded [`Snapshot`].
pub const MAGIC: [u8; 8] = *b"prosnap\0";

/// Bumped freely on schema change; there is no cross-version
/// compatibility requirement (same-tool-reads-it rule).
pub const FORMAT_VERSION: u32 = 3;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("i/o error")]
    Io(#[from] io::Error),
    #[error("not a target snapshot (bad magic)")]
    BadMagic,
    #[error("snapshot format version {found} != supported version {expected}")]
    VersionMismatch { found: u32, expected: u32 },
    #[error("failed to decode snapshot")]
    Decode(#[source] postcard::Error),
    #[error("failed to encode snapshot")]
    Encode(#[source] postcard::Error),
}

/// One contiguous run of captured target memory.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Segment {
    addr: u64,
    bytes: Vec<u8>,
}

impl Segment {
    fn end(&self) -> u64 {
        self.addr + self.bytes.len() as u64
    }
}

/// A captured target: everything [`Recorder`] saw the analysis read,
/// replayable through [`Target`] on any platform.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    /// Disjoint captured memory runs, sorted by address.
    memory: Vec<Segment>,
    /// The target executable's function symtab, sorted by value. Serves
    /// by-address lookups for addresses the capture never resolved, and
    /// the whole-symtab scan.
    functions: Vec<SymbolBuf>,
    /// The target executable's object symtab, used for normalized lookup of
    /// named statics whose crate disambiguators differ between builds.
    objects: Vec<SymbolBuf>,
    /// By-address lookups observed at capture time, including misses.
    /// Authoritative over `functions`: libproc may resolve an address
    /// to a symbol outside the function-symbol mask (weak symbols,
    /// aliases), and replay must agree with what the capture saw.
    by_addr: BTreeMap<u64, Option<SymbolBuf>>,
    /// By-name lookups observed at capture time, including misses.
    /// Authoritative for the same reason; notably the TLS-key static is
    /// an object symbol, which `functions` does not cover.
    by_name: BTreeMap<String, Option<SymbolBuf>>,
    /// Thread-local addresses observed at capture time, keyed by the
    /// thread's `%fsbase` and the symbol naming the variable. The answer
    /// is recorded rather than the bytes behind it because how a symbol
    /// reaches a thread-local is the capturing platform's business, and
    /// replay must not have to know it.
    tls: BTreeMap<(u64, String), Option<u64>>,
    mappings: Mappings,
    lwps: Vec<LwpInfo>,
}

impl Snapshot {
    /// Serialize into `w`: header, then zstd-compressed postcard payload.
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&MAGIC)?;
        w.write_all(&FORMAT_VERSION.to_le_bytes())?;
        let payload = postcard::to_allocvec(self).map_err(Error::Encode)?;
        zstd::stream::copy_encode(payload.as_slice(), &mut w, zstd::DEFAULT_COMPRESSION_LEVEL)?;
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.write(File::create(path)?)
    }

    /// Deserialize from `r`, rejecting wrong magic or version.
    pub fn read<R: Read>(mut r: R) -> Result<Self> {
        let mut header = [0u8; MAGIC.len() + size_of::<u32>()];
        r.read_exact(&mut header)?;
        if header[..MAGIC.len()] != MAGIC {
            return Err(Error::BadMagic);
        }
        let found = u32::from_le_bytes(header[MAGIC.len()..].try_into().unwrap());
        if found != FORMAT_VERSION {
            return Err(Error::VersionMismatch {
                found,
                expected: FORMAT_VERSION,
            });
        }
        let payload = zstd::stream::decode_all(r)?;
        postcard::from_bytes(&payload).map_err(Error::Decode)
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::read(File::open(path)?)
    }

    /// The segment containing `addr`, if captured.
    fn segment(&self, addr: u64) -> Option<&Segment> {
        let idx = self.memory.partition_point(|s| s.addr <= addr);
        let seg = &self.memory[idx.checked_sub(1)?];
        (addr < seg.end()).then_some(seg)
    }
}

// Snapshots replay and recorders capture under the same parallel
// renderer as any other target.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<Snapshot>();
    send_sync::<Recorder<'_, Snapshot>>();
};

impl Target for Snapshot {
    fn read_bytes(&self, addr: u64, len: u64) -> TargetResult<Vec<u8>> {
        // Merging made runs maximal, so any fully-captured read lies
        // within a single segment.
        let end = addr
            .checked_add(len)
            .ok_or_else(|| TargetError::unmapped(addr, len))?;
        let seg = self
            .segment(addr)
            .filter(|seg| end <= seg.end())
            .ok_or_else(|| TargetError::unmapped(addr, len))?;
        let start = (addr - seg.addr) as usize;
        Ok(seg.bytes[start..start + len as usize].to_vec())
    }

    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        if let Some(recorded) = self.by_addr.get(&addr) {
            return recorded.clone();
        }
        // Fall back to the nearest preceding function symbol, matching
        // libproc's containment rule.
        let idx = self.functions.partition_point(|s| s.st_value <= addr);
        let sym = &self.functions[idx.checked_sub(1)?];
        (addr < sym.st_value + sym.st_size).then(|| sym.clone())
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        if let Some(recorded) = self.by_name.get(name) {
            return recorded.clone();
        }
        self.functions
            .iter()
            .chain(&self.objects)
            .find(|s| s.name == name)
            .cloned()
    }

    fn symbols(&self) -> TargetResult<Vec<SymbolBuf>> {
        Ok(self.functions.clone())
    }

    fn object_symbols(&self) -> TargetResult<Vec<SymbolBuf>> {
        Ok(self.objects.clone())
    }

    fn mappings(&self) -> TargetResult<Mappings> {
        Ok(self.mappings.clone())
    }

    fn lwps(&self) -> TargetResult<Vec<LwpInfo>> {
        Ok(self.lwps.clone())
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> TargetResult<Option<u64>> {
        // There is no fallback: the capturing platform's TLS model is
        // exactly what a snapshot does not carry, so an unrecorded pair
        // is a hole in the capture rather than a thread without the
        // variable.
        self.tls
            .get(&(regs.fsbase, sym.name.clone()))
            .copied()
            .ok_or_else(|| TargetError::tls_not_recorded(&sym.name, regs.fsbase))
    }
}

/// A [`Target`] wrapper that records everything read through it, so a
/// [`Snapshot`] can replay the same analysis offline.
pub struct Recorder<'a, T> {
    target: &'a T,
    /// Every successful read, in order; overlaps are resolved at
    /// [`Recorder::snapshot`] time (later reads win).
    reads: Mutex<Vec<Segment>>,
    by_addr: Mutex<BTreeMap<u64, Option<SymbolBuf>>>,
    by_name: Mutex<BTreeMap<String, Option<SymbolBuf>>>,
    tls: Mutex<BTreeMap<(u64, String), Option<u64>>>,
}

impl<'a, T: Target> Recorder<'a, T> {
    pub fn new(target: &'a T) -> Self {
        Self {
            target,
            reads: Mutex::new(Vec::new()),
            by_addr: Mutex::new(BTreeMap::new()),
            by_name: Mutex::new(BTreeMap::new()),
            tls: Mutex::new(BTreeMap::new()),
        }
    }

    /// Assemble the snapshot: everything recorded so far, plus the
    /// function symtab, mappings, and LWPs read from the target now.
    pub fn snapshot(&self) -> TargetResult<Snapshot> {
        let mut functions = self.target.symbols()?;
        functions.sort_by_key(|s| s.st_value);
        let mut objects = self.target.object_symbols()?;
        objects.sort_by_key(|s| s.st_value);

        Ok(Snapshot {
            memory: merge_reads(&self.reads.lock().unwrap()),
            functions,
            objects,
            by_addr: self.by_addr.lock().unwrap().clone(),
            by_name: self.by_name.lock().unwrap().clone(),
            tls: self.tls.lock().unwrap().clone(),
            mappings: self.target.mappings()?,
            lwps: self.target.lwps()?,
        })
    }
}

/// Merge a read log into disjoint, maximal segments. Overlapping bytes
/// take the value of the *latest* read, matching what a re-run of the
/// same reads would observe.
fn merge_reads(reads: &[Segment]) -> Vec<Segment> {
    // Sweep the union of the read intervals into disjoint extents...
    let mut intervals: Vec<(u64, u64)> = reads
        .iter()
        .filter(|r| !r.bytes.is_empty())
        .map(|r| (r.addr, r.end()))
        .collect();
    intervals.sort_unstable();
    let mut extents: Vec<(u64, u64)> = Vec::new();
    for (start, end) in intervals {
        match extents.last_mut() {
            Some((_, last_end)) if start <= *last_end => *last_end = (*last_end).max(end),
            _ => extents.push((start, end)),
        }
    }

    // ...then replay the log in order on top of them. Every byte of an
    // extent is covered by at least one read, so none is left unwritten.
    let mut merged: Vec<Segment> = extents
        .into_iter()
        .map(|(start, end)| Segment {
            addr: start,
            bytes: vec![0; (end - start) as usize],
        })
        .collect();
    for read in reads {
        let idx = merged.partition_point(|s| s.addr <= read.addr);
        let Some(seg) = idx.checked_sub(1).map(|i| &mut merged[i]) else {
            continue;
        };
        let start = (read.addr - seg.addr) as usize;
        seg.bytes[start..start + read.bytes.len()].copy_from_slice(&read.bytes);
    }
    merged
}

impl<T: Target> Target for Recorder<'_, T> {
    fn read_bytes(&self, addr: u64, len: u64) -> TargetResult<Vec<u8>> {
        let bytes = self.target.read_bytes(addr, len)?;
        self.reads.lock().unwrap().push(Segment {
            addr,
            bytes: bytes.clone(),
        });
        Ok(bytes)
    }

    // Deliberately not forwarded: a borrowed read would bypass the
    // recording above, and a snapshot must carry every byte the caller
    // saw. Declining sends every read through `read_bytes`.
    fn pslice(&self, _addr: u64, _len: u64) -> Option<&[u8]> {
        None
    }

    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        let sym = self.target.lookup_symbol_by_addr(addr);
        self.by_addr.lock().unwrap().insert(addr, sym.clone());
        sym
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        let sym = self.target.lookup_symbol_by_name(name);
        self.by_name
            .lock()
            .unwrap()
            .insert(name.to_string(), sym.clone());
        sym
    }

    fn symbols(&self) -> TargetResult<Vec<SymbolBuf>> {
        self.target.symbols()
    }

    fn object_symbols(&self) -> TargetResult<Vec<SymbolBuf>> {
        self.target.object_symbols()
    }

    fn mappings(&self) -> TargetResult<Mappings> {
        self.target.mappings()
    }

    fn lwps(&self) -> TargetResult<Vec<LwpInfo>> {
        self.target.lwps()
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> TargetResult<Option<u64>> {
        // Only the answer is recorded. The wrapped target resolves this
        // through itself, so whatever bytes its TLS model walks — a
        // pthread key and the fast-TSD slots on illumos, nothing at all
        // on Linux — stay out of the snapshot's memory, which is what
        // lets a snapshot replay on a platform that models TLS
        // differently.
        let addr = self.target.tls_var_addr(regs, sym)?;
        self.tls
            .lock()
            .unwrap()
            .insert((regs.fsbase, sym.name.clone()), addr);
        Ok(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LoadedObjectWithPath, MapFlags, Regs};

    /// An in-memory fake target: one memory run, a few symbols.
    struct FakeTarget {
        base: u64,
        memory: Vec<u8>,
        functions: Vec<SymbolBuf>,
        objects: Vec<SymbolBuf>,
    }

    fn sym(name: &str, value: u64, size: u64) -> SymbolBuf {
        SymbolBuf {
            name: name.to_string(),
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 1,
            st_value: value,
            st_size: size,
        }
    }

    impl FakeTarget {
        fn new() -> Self {
            FakeTarget {
                base: 0x1000,
                memory: (0..=255).cycle().take(0x2000).collect(),
                functions: vec![sym("poll_a", 0x100, 0x40), sym("poll_b", 0x140, 0x10)],
                objects: vec![sym("TLS_KEY", 0x2000, 8)],
            }
        }
    }

    impl Target for FakeTarget {
        fn read_bytes(&self, addr: u64, len: u64) -> TargetResult<Vec<u8>> {
            let start = addr
                .checked_sub(self.base)
                .ok_or_else(|| TargetError::unmapped(addr, len))? as usize;
            self.memory
                .get(start..start + len as usize)
                .map(|b| b.to_vec())
                .ok_or_else(|| TargetError::unmapped(addr, len))
        }

        fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
            self.functions
                .iter()
                .find(|s| (s.st_value..s.st_value + s.st_size).contains(&addr))
                .cloned()
        }

        fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
            self.functions
                .iter()
                .chain(&self.objects)
                .find(|s| s.name == name)
                .cloned()
        }

        fn symbols(&self) -> TargetResult<Vec<SymbolBuf>> {
            Ok(self.functions.clone())
        }

        fn object_symbols(&self) -> TargetResult<Vec<SymbolBuf>> {
            Ok(self.objects.clone())
        }

        fn mappings(&self) -> TargetResult<Mappings> {
            Ok(Mappings {
                inner: vec![LoadedObjectWithPath {
                    path: Some("/bin/fake".to_string()),
                    vaddr: self.base,
                    size: self.memory.len() as u64,
                    flags: MapFlags(0x06),
                }],
            })
        }

        fn lwps(&self) -> TargetResult<Vec<LwpInfo>> {
            Ok(vec![])
        }

        /// The fake's TLS model, standing in for a real platform's: the
        /// variable sits a page above the thread pointer, so different
        /// threads give different answers and a thread without one says
        /// so.
        fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> TargetResult<Option<u64>> {
            if sym.name != "TLS_KEY" || regs.fsbase == 0 {
                return Ok(None);
            }
            Ok(Some(regs.fsbase + 0x1000))
        }
    }

    #[test]
    fn test_replay_recorded_reads() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        let want = rec.read_bytes(0x1100, 32).unwrap();
        let snap = rec.snapshot().unwrap();

        // The exact read, and any sub-range of it, replays.
        assert_eq!(snap.read_bytes(0x1100, 32).unwrap(), want);
        assert_eq!(snap.read_bytes(0x1108, 8).unwrap(), want[8..16]);
        // read_u64 (a provided method) reads through the same bytes.
        assert_eq!(
            snap.read_u64(0x1100).unwrap(),
            u64::from_le_bytes(want[..8].try_into().unwrap())
        );
    }

    #[test]
    fn test_uncaptured_reads_fail() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        rec.read_bytes(0x1100, 16).unwrap();
        let snap = rec.snapshot().unwrap();

        // Never-read ranges fail even though the fake target had them.
        assert!(snap.read_bytes(0x1200, 16).is_err());
        // So do reads extending past a captured run's edge.
        assert!(snap.read_bytes(0x1108, 16).is_err());
        assert!(snap.read_bytes(0x10f8, 16).is_err());
    }

    #[test]
    fn test_overlapping_reads_merge() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        // Overlapping and adjacent reads, out of address order.
        rec.read_bytes(0x1110, 0x20).unwrap();
        rec.read_bytes(0x1100, 0x18).unwrap();
        rec.read_bytes(0x1130, 0x10).unwrap();
        let snap = rec.snapshot().unwrap();

        assert_eq!(snap.memory.len(), 1);
        // The merged run serves a read no single original read covered.
        assert_eq!(
            snap.read_bytes(0x1100, 0x40).unwrap(),
            target.read_bytes(0x1100, 0x40).unwrap()
        );
    }

    #[test]
    fn test_later_reads_win_overlaps() {
        use std::cell::RefCell;

    struct Changing(RefCell<u8>);
        impl Target for Changing {
            fn read_bytes(&self, _addr: u64, len: u64) -> TargetResult<Vec<u8>> {
                let mut generation = self.0.borrow_mut();
                *generation += 1;
                Ok(vec![*generation; len as usize])
            }
            fn lookup_symbol_by_addr(&self, _: u64) -> Option<SymbolBuf> {
                None
            }
            fn lookup_symbol_by_name(&self, _: &str) -> Option<SymbolBuf> {
                None
            }
            fn symbols(&self) -> TargetResult<Vec<SymbolBuf>> {
                Ok(vec![])
            }
            fn mappings(&self) -> TargetResult<Mappings> {
                Ok(Mappings { inner: vec![] })
            }
            fn lwps(&self) -> TargetResult<Vec<LwpInfo>> {
                Ok(vec![])
            }
            fn tls_var_addr(&self, _: &Regs, _: &SymbolBuf) -> TargetResult<Option<u64>> {
                Ok(None)
            }
        }

        let target = Changing(RefCell::new(0));
        let rec = Recorder::new(&target);
        rec.read_bytes(0x1000, 8).unwrap(); // all 1s
        rec.read_bytes(0x1004, 8).unwrap(); // all 2s
        let snap = rec.snapshot().unwrap();
        assert_eq!(
            snap.read_bytes(0x1000, 12).unwrap(),
            [1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2]
        );
    }

    #[test]
    fn test_symbol_lookups_replay() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        // An object symbol: only in the recorded by-name results.
        let tls = rec.lookup_symbol_by_name("TLS_KEY").unwrap();
        // A recorded miss.
        assert!(rec.lookup_symbol_by_name("no_such_symbol").is_none());
        let snap = rec.snapshot().unwrap();

        assert_eq!(snap.lookup_symbol_by_name("TLS_KEY").unwrap(), tls);
        assert!(snap.lookup_symbol_by_name("no_such_symbol").is_none());
        // Never-queried function names fall back to the symtab.
        assert_eq!(
            snap.lookup_symbol_by_name("poll_b").unwrap().st_value,
            0x140
        );

        // By-address: mid-symbol hits resolve, gaps and past-the-end miss.
        assert_eq!(snap.lookup_symbol_by_addr(0x120).unwrap().name, "poll_a");
        assert_eq!(snap.lookup_symbol_by_addr(0x140).unwrap().name, "poll_b");
        assert!(snap.lookup_symbol_by_addr(0x150).is_none());
        assert!(snap.lookup_symbol_by_addr(0x50).is_none());
    }

    #[test]
    fn test_recorded_by_addr_beats_symtab() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        // The fake resolves this address, but pretend libproc knew
        // better than the function table by recording a miss there.
        assert_eq!(
            Target::lookup_symbol_by_addr(&rec, 0x120).unwrap().name,
            "poll_a"
        );
        let mut snap = rec.snapshot().unwrap();
        snap.by_addr.insert(0x130, None);

        assert_eq!(snap.lookup_symbol_by_addr(0x120).unwrap().name, "poll_a");
        assert!(snap.lookup_symbol_by_addr(0x130).is_none());
    }

    /// The recorder captures the answer, not the walk that produced it,
    /// so replay never needs the capturing platform's TLS model. A pair
    /// the capture never asked about is a hole in the snapshot, which is
    /// not the same as a thread that has no such variable.
    #[test]
    fn test_tls_lookups_replay() {
        let regs = |fsbase| Regs {
            fsbase,
            ..Regs::default()
        };
        let key = sym("TLS_KEY", 0x2000, 8);

        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        let want = rec.tls_var_addr(&regs(0x7000), &key).unwrap();
        let want_other = rec.tls_var_addr(&regs(0x9000), &key).unwrap();
        // A thread with no thread pointer holds nothing, and that
        // answer is recorded like any other.
        assert_eq!(rec.tls_var_addr(&regs(0), &key).unwrap(), None);
        assert!(want.is_some() && want != want_other);
        let snap = rec.snapshot().unwrap();

        assert_eq!(snap.tls_var_addr(&regs(0x7000), &key).unwrap(), want);
        assert_eq!(snap.tls_var_addr(&regs(0x9000), &key).unwrap(), want_other);
        assert_eq!(snap.tls_var_addr(&regs(0), &key).unwrap(), None);

        // An unseen thread, and an unseen variable in a seen thread.
        assert!(snap.tls_var_addr(&regs(0x1), &key).is_err());
        assert!(
            snap.tls_var_addr(&regs(0x7000), &sym("OTHER", 0x3000, 8))
                .is_err()
        );
    }

    #[test]
    fn test_roundtrip() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        rec.read_bytes(0x1000, 64).unwrap();
        rec.read_bytes(0x2000, 64).unwrap();
        rec.lookup_symbol_by_name("TLS_KEY");
        rec.lookup_symbol_by_addr(0x120);
        rec.tls_var_addr(
            &Regs {
                fsbase: 0x7000,
                ..Regs::default()
            },
            &sym("TLS_KEY", 0x2000, 8),
        )
        .unwrap();
        let snap = rec.snapshot().unwrap();

        let mut buf = Vec::new();
        snap.write(&mut buf).unwrap();
        let loaded = Snapshot::read(buf.as_slice()).unwrap();
        assert_eq!(snap, loaded);
    }

    #[test]
    fn test_load_rejects_garbage() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        rec.read_bytes(0x1000, 64).unwrap();
        let mut buf = Vec::new();
        rec.snapshot().unwrap().write(&mut buf).unwrap();

        // Wrong magic.
        let mut bad = buf.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            Snapshot::read(bad.as_slice()),
            Err(Error::BadMagic)
        ));

        // Wrong version.
        let mut bad = buf.clone();
        bad[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        assert!(matches!(
            Snapshot::read(bad.as_slice()),
            Err(Error::VersionMismatch { found, expected })
                if found == FORMAT_VERSION + 1 && expected == FORMAT_VERSION
        ));

        // Truncated payload.
        let bad = &buf[..buf.len() / 2];
        assert!(Snapshot::read(bad).is_err());

        // Truncated header.
        assert!(matches!(Snapshot::read(&buf[..6]), Err(Error::Io(_))));
    }
}

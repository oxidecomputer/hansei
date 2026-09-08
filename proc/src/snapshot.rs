// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Serializable target snapshots.
//!
//! A [`Snapshot`] captures the handful of things a debugger actually
//! read from a target — memory runs, symbol lookups, the function
//! symtab, mappings, and LWP state — into a compact file that
//! implements [`Target`] on any platform. [`Recorder`] wraps a real
//! target and records everything the wrapped reads touch, so capturing
//! a snapshot is just driving the ordinary analysis once with the
//! recorder in place.
//!
//! Snapshots are test fixtures, not an interchange format: the same
//! tool version writes and reads them, and the version check rejects
//! everything else.
//!
//! The payload is stored uncompressed, deliberately. The fixtures are
//! checked in and recaptured whenever their format moves, and git
//! delta-compresses consecutive versions of a raw payload down to the
//! bytes that changed — mostly addresses and a few words of runtime
//! state — while a compressed frame changes throughout and costs its
//! whole size in history every time. A single raw set also packs
//! smaller than the compressed files did, because the fixtures share
//! most of their symbol tables and git deltas across files where a
//! per-file frame cannot. The working tree pays for this in size, the
//! repository does not.
//!
//! A capture is bounded by [`CaptureLimits`]: what the recorder may
//! hold in its read log and how large the written file may grow. The
//! bounds are resource limits, not evidence policy — a capture that
//! reaches one fails whole, and never publishes the part it did
//! record. The header also says whether the capture built a usable
//! allocator index ([`RecordedHeapEvidence`]), so a replay knows
//! whether the corroboration the capture's reads were gated by can be
//! rebuilt from them.

use crate::{
    Error as TargetError, LwpInfo, Mappings, Regs, Result as TargetResult, SymbolBuf, Target,
};

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// File header: magic, then a little-endian format version, then the
/// postcard-encoded [`Snapshot`] as is (see the module docs for why it
/// is not compressed).
pub const MAGIC: [u8; 8] = *b"prosnap\0";

/// Bumped freely on schema change; there is no cross-version
/// compatibility requirement (same-tool-reads-it rule).
pub const FORMAT_VERSION: u32 = 8;

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
    #[error("{0}")]
    Limit(LimitExceeded),
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

/// Whether the capture built a usable allocator index over the target,
/// and so recorded the reads a replay needs to rebuild it.
///
/// `Available` is a claim: the capture's discovery and census were
/// gated by that index, and a replay that cannot rebuild it has an
/// incomplete capture in hand, not a target without an allocator.
/// `Unavailable` is neutral — nothing was learned about liveness, and
/// a replay treats every allocation the way a target with no allocator
/// evidence is treated. Neither is a switch a reader may flip to skip
/// a gate.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RecordedHeapEvidence {
    Available,
    Unavailable,
}

/// The resource bounds a capture runs under.
///
/// The recorder logs every successful read that reaches memory no
/// logged read covers whole, so a capture that walks an allocator's
/// caches and slabs, or reads the same wait queue once per task parked
/// on it, logs each byte about once — but a log of partial overlaps
/// can still hold more than the merged memory it ends up as. These
/// bound that log and the written file. They are bounds on resources,
/// not on evidence: reaching one fails the capture (see
/// [`LimitExceeded`]) rather than trimming what it records or relaxing
/// what its reads were gated by.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CaptureLimits {
    /// Bytes the read log may hold, charged per read before the bytes
    /// are copied into it.
    pub read_log_bytes: u64,
    /// Reads the log may hold, charged the same way.
    pub read_log_entries: u64,
    /// Bytes the serialized snapshot may occupy on disk.
    pub output_bytes: u64,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        CaptureLimits {
            read_log_bytes: 512 << 20,
            read_log_entries: 4_000_000,
            output_bytes: 512 << 20,
        }
    }
}

/// Which of a capture's [`CaptureLimits`] a charge exceeded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Limit {
    ReadLogBytes,
    ReadLogEntries,
    OutputBytes,
}

/// A capture that charged more against one of its limits than the
/// limit allows: which limit, what the charge would have brought the
/// total to, and the limit itself.
///
/// Sticky where it arises: a recorder that has exceeded a limit refuses
/// every later read and refuses to assemble a snapshot, so a consumer
/// that swallows the failed read — an allocator walk that answers
/// "no index" to any read it cannot make — cannot turn the violation
/// into a capture that merely lacks evidence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LimitExceeded {
    pub limit: Limit,
    /// The total the charge would have reached, saturated at `u64::MAX`
    /// when the addition itself overflowed.
    pub charged: u64,
    pub cap: u64,
}

impl fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unit = match self.limit {
            Limit::ReadLogBytes => "read-log bytes",
            Limit::ReadLogEntries => "read-log entries",
            Limit::OutputBytes => "serialized bytes",
        };
        write!(
            f,
            "the capture charged {} {unit} against its limit of {}",
            self.charged, self.cap
        )
    }
}

impl std::error::Error for LimitExceeded {}

/// What a recorder's read log holds: the totals its limits are charged
/// against, before merging.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReadLogSize {
    pub bytes: u64,
    pub entries: u64,
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
    /// The captured target's executable load bias. Recorded rather than
    /// derived because a snapshot carries no program headers to derive
    /// it from, and a debug-info address means nothing without it.
    exec_bias: Option<u64>,
    /// Whether the capture's reads were gated by an allocator index it
    /// built, and so carry what rebuilding one needs.
    heap_evidence: RecordedHeapEvidence,
}

impl Snapshot {
    /// Serialize into `w`: header, then the postcard payload.
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&MAGIC)?;
        w.write_all(&FORMAT_VERSION.to_le_bytes())?;
        let payload = postcard::to_allocvec(self).map_err(Error::Encode)?;
        w.write_all(&payload)?;
        Ok(())
    }

    /// Write the snapshot to `path`, replacing whatever is there only
    /// once the whole file is written within `output_limit` bytes.
    ///
    /// The bytes go to a sibling temporary file that is renamed over
    /// `path` at the end, so a capture that fails partway — the limit
    /// reached, the disk full — leaves the previous file as it was and
    /// no truncated one beside it.
    pub fn save(&self, path: &Path, output_limit: u64) -> Result<()> {
        let tmp = temporary_sibling(path);
        let written = self.write_bounded(&tmp, output_limit);
        if let Err(e) = written.and_then(|()| fs::rename(&tmp, path).map_err(Error::Io)) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    fn write_bounded(&self, path: &Path, output_limit: u64) -> Result<()> {
        let mut out = Bounded {
            inner: BufWriter::new(File::create(path)?),
            written: 0,
            cap: output_limit,
            exceeded: None,
        };
        let result = self
            .write(&mut out)
            .and_then(|()| out.flush().map_err(Error::Io));
        // The limit surfaces as an i/o error from inside the encoder;
        // what the caller is told is the limit itself.
        match out.exceeded {
            Some(exceeded) => Err(Error::Limit(exceeded)),
            None => result,
        }
    }

    /// Whether this capture built an allocator index over its target.
    pub fn heap_evidence(&self) -> RecordedHeapEvidence {
        self.heap_evidence
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
        let mut payload = Vec::new();
        r.read_to_end(&mut payload)?;
        postcard::from_bytes(&payload).map_err(Error::Decode)
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::read(File::open(path)?)
    }

    /// The recorded memory runs, in address order — what this capture
    /// actually holds, for diagnostics and for tests that corrupt a
    /// replay and must know where the recorded structures live.
    pub fn segments(&self) -> impl Iterator<Item = std::ops::Range<u64>> + '_ {
        self.memory.iter().map(|s| s.addr..s.end())
    }

    /// The segment containing `addr`, if captured.
    fn segment(&self, addr: u64) -> Option<&Segment> {
        let idx = self.memory.partition_point(|s| s.addr <= addr);
        let seg = &self.memory[idx.checked_sub(1)?];
        (addr < seg.end()).then_some(seg)
    }
}

/// `path` with `.tmp` appended to its file name: in the same directory,
/// so the rename that publishes it stays within one filesystem.
fn temporary_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// A writer that refuses the write taking it past `cap` bytes, and
/// remembers that it did: the encoder above it sees an i/o error, and
/// the save reads the limit back out.
struct Bounded<W> {
    inner: W,
    written: u64,
    cap: u64,
    exceeded: Option<LimitExceeded>,
}

impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Charged with the whole buffer before writing any of it; what
        // the inner writer took short is charged again when the caller
        // comes back with the rest.
        let charged = self.written.checked_add(buf.len() as u64);
        if charged.is_some_and(|total| total <= self.cap) {
            let n = self.inner.write(buf)?;
            self.written += n as u64;
            return Ok(n);
        }
        let exceeded = LimitExceeded {
            limit: Limit::OutputBytes,
            charged: charged.unwrap_or(u64::MAX),
            cap: self.cap,
        };
        self.exceeded = Some(exceeded);
        Err(io::Error::other(exceeded))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
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
    fn read_bytes(&self, addr: u64, len: u64) -> TargetResult<&[u8]> {
        // Merging made runs maximal, so any fully-captured read lies
        // within a single segment — what a snapshot cannot lend whole it
        // cannot serve at all.
        let lent = || {
            let end = addr.checked_add(len)?;
            let seg = self.segment(addr).filter(|seg| end <= seg.end())?;
            let start = (addr - seg.addr) as usize;
            Some(&seg.bytes[start..start + len as usize])
        };
        lent().ok_or_else(|| TargetError::unmapped(addr, len))
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        // Merging made runs maximal, so the segment holding `addr` holds
        // everything contiguously captured after it.
        match self.segment(addr) {
            Some(seg) => (seg.end() - addr).min(max),
            None => 0,
        }
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

    fn exec_bias(&self) -> Option<u64> {
        self.exec_bias
    }

    fn recorded_heap_evidence(&self) -> Option<RecordedHeapEvidence> {
        Some(self.heap_evidence)
    }
}

/// A [`Target`] wrapper that records everything read through it, so a
/// [`Snapshot`] can replay the same analysis offline.
pub struct Recorder<'a, T> {
    target: &'a T,
    limits: CaptureLimits,
    /// Every successful read that reached memory no earlier read
    /// covers whole, in order; partial overlaps are resolved at
    /// [`Recorder::snapshot`] time (later reads win).
    log: Mutex<ReadLog>,
    by_addr: Mutex<BTreeMap<u64, Option<SymbolBuf>>>,
    by_name: Mutex<BTreeMap<String, Option<SymbolBuf>>>,
    tls: Mutex<BTreeMap<(u64, String), Option<u64>>>,
}

/// The read log and the account its limits are charged against, under
/// one lock so a charge and the copy it admits are one step.
#[derive(Default)]
struct ReadLog {
    reads: Vec<Segment>,
    bytes: u64,
    /// The memory the log holds so far, as disjoint maximal runs keyed
    /// by start: what says a read is already recorded whole. An
    /// analysis reads the same bytes many times over — a wait queue
    /// once per task parked on it, a slab per buffer in it — and the
    /// snapshot they merge into is the same whether the log holds each
    /// read once or a thousand times; only the log's size is not. A
    /// target that changes between two reads of the same bytes would
    /// replay the first — no capture is taken from one.
    covered: BTreeMap<u64, u64>,
    /// The first limit the log exceeded. Set once and never cleared:
    /// from then on the log admits nothing and no snapshot assembles.
    failed: Option<LimitExceeded>,
}

impl ReadLog {
    /// Whether `addr..end` lies whole inside one run already logged.
    fn covers(&self, addr: u64, end: u64) -> bool {
        self.covered
            .range(..=addr)
            .next_back()
            .is_some_and(|(_, &run_end)| end <= run_end)
    }

    /// Fold `addr..end` into the runs, merging every run it touches.
    fn cover(&mut self, addr: u64, end: u64) {
        let (mut start, mut stop) = (addr, end);
        // The runs are disjoint and sorted, so those touching this one
        // are the last few starting at or before its end.
        let touching: Vec<u64> = self
            .covered
            .range(..=stop)
            .rev()
            .take_while(|&(_, &run_end)| run_end >= start)
            .map(|(&run_start, _)| run_start)
            .collect();
        for run_start in touching {
            let run_end = self.covered.remove(&run_start).unwrap();
            start = start.min(run_start);
            stop = stop.max(run_end);
        }
        self.covered.insert(start, stop);
    }

    /// Admit a read of `len` bytes, or say which limit it would take
    /// the log past. Charged before the bytes are copied, so a read the
    /// log cannot afford costs nothing but the check.
    fn charge(
        &mut self,
        limits: &CaptureLimits,
        len: u64,
    ) -> std::result::Result<(), LimitExceeded> {
        if let Some(failed) = self.failed {
            return Err(failed);
        }
        let entries = (self.reads.len() as u64).checked_add(1);
        let bytes = self.bytes.checked_add(len);
        let over = |limit, charged: Option<u64>, cap| LimitExceeded {
            limit,
            charged: charged.unwrap_or(u64::MAX),
            cap,
        };
        let exceeded = match (entries, bytes) {
            (Some(entries), Some(bytes))
                if entries <= limits.read_log_entries && bytes <= limits.read_log_bytes =>
            {
                self.bytes = bytes;
                return Ok(());
            }
            (Some(entries), _) if entries <= limits.read_log_entries => {
                over(Limit::ReadLogBytes, bytes, limits.read_log_bytes)
            }
            _ => over(Limit::ReadLogEntries, entries, limits.read_log_entries),
        };
        self.failed = Some(exceeded);
        Err(exceeded)
    }
}

impl<'a, T: Target> Recorder<'a, T> {
    /// A recorder under the default [`CaptureLimits`].
    pub fn new(target: &'a T) -> Self {
        Self::with_limits(target, CaptureLimits::default())
    }

    pub fn with_limits(target: &'a T, limits: CaptureLimits) -> Self {
        Self {
            target,
            limits,
            log: Mutex::new(ReadLog::default()),
            by_addr: Mutex::new(BTreeMap::new()),
            by_name: Mutex::new(BTreeMap::new()),
            tls: Mutex::new(BTreeMap::new()),
        }
    }

    /// What the read log holds so far, before merging — the totals the
    /// limits are charged against.
    pub fn charged(&self) -> ReadLogSize {
        let log = self.log.lock().unwrap();
        ReadLogSize {
            bytes: log.bytes,
            entries: log.reads.len() as u64,
        }
    }

    /// The limit this capture exceeded, if it has: the recorder is no
    /// longer recording, and [`Recorder::snapshot`] will refuse. A
    /// capture driver asks this wherever a consumer between it and the
    /// recorder may have swallowed the failed read.
    pub fn failure(&self) -> Option<LimitExceeded> {
        self.log.lock().unwrap().failed
    }

    /// Assemble the snapshot: everything recorded so far, plus the
    /// function symtab, mappings, and LWPs read from the target now,
    /// stamped with whether the capture built an allocator index.
    ///
    /// Refuses once a limit has been exceeded: what was recorded up to
    /// that point is a partial capture, and a partial capture published
    /// as a snapshot would replay as a target that read less.
    pub fn snapshot(&self, heap_evidence: RecordedHeapEvidence) -> TargetResult<Snapshot> {
        let log = self.log.lock().unwrap();
        if let Some(exceeded) = log.failed {
            return Err(TargetError::capture_limit(exceeded));
        }
        let mut functions = self.target.symbols()?;
        functions.sort_by_key(|s| s.st_value);
        let mut objects = self.target.object_symbols()?;
        objects.sort_by_key(|s| s.st_value);

        Ok(Snapshot {
            memory: merge_reads(&log.reads),
            functions,
            objects,
            by_addr: self.by_addr.lock().unwrap().clone(),
            by_name: self.by_name.lock().unwrap().clone(),
            tls: self.tls.lock().unwrap().clone(),
            mappings: self.target.mappings()?,
            lwps: self.target.lwps()?,
            exec_bias: self.target.exec_bias(),
            heap_evidence,
        })
    }
}

/// Merge a read log into disjoint, maximal segments. Overlapping bytes
/// take the value of the *latest* read, matching what a re-run of the
/// same reads would observe.
///
/// A read that served no bytes is not a read here: it stakes out no
/// extent and has nothing to write into one. Both passes below have to
/// agree about that, or the second addresses an extent the first never
/// made — which for an empty read past the last of them is an index
/// beyond that segment's end.
fn merge_reads(reads: &[Segment]) -> Vec<Segment> {
    let served = || reads.iter().filter(|r| !r.bytes.is_empty());

    // Sweep the union of the read intervals into disjoint extents...
    let mut intervals: Vec<(u64, u64)> = served().map(|r| (r.addr, r.end())).collect();
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
    for read in served() {
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
    fn read_bytes(&self, addr: u64, len: u64) -> TargetResult<&[u8]> {
        // Recording and lending are not in tension: log a copy, then
        // hand back the wrapped target's own storage. The copy is
        // charged against the limits first, and a read the log cannot
        // afford fails here — the wrapped target's answer is not lent
        // either, since a capture that reaches a limit is over. A read
        // the log already holds whole is lent without a copy or a
        // charge, but only while the capture is still one: past a
        // limit every read is refused, recorded or not.
        let bytes = self.target.read_bytes(addr, len)?;
        let mut log = self.log.lock().unwrap();
        if let Some(failed) = log.failed {
            return Err(TargetError::capture_limit(failed));
        }
        let end = addr.saturating_add(bytes.len() as u64);
        if log.covers(addr, end) {
            return Ok(bytes);
        }
        log.charge(&self.limits, bytes.len() as u64)
            .map_err(TargetError::capture_limit)?;
        log.reads.push(Segment {
            addr,
            bytes: bytes.to_vec(),
        });
        log.cover(addr, end);
        Ok(bytes)
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        self.target.readable_len(addr, max)
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

    fn lwp_name(&self, tid: u32) -> Option<String> {
        // Forwarded, not recorded: a snapshot does not carry lwp
        // names, so replay answers `None` and goldens the absence.
        self.target.lwp_name(tid)
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

    fn exec_bias(&self) -> Option<u64> {
        self.target.exec_bias()
    }

    fn recorded_heap_evidence(&self) -> Option<RecordedHeapEvidence> {
        // Forwarded: what the wrapped target records is what a driver
        // recapturing it prepares under. The recorder labels nothing
        // itself — the policy of the snapshot it assembles is the
        // argument to `snapshot`.
        self.target.recorded_heap_evidence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LoadedObjectWithPath, MapFlags, Regs};

    use proptest::prelude::*;

    /// The recorder forwards lwp names without recording them: the
    /// capture's own output may print them, and the snapshot — which
    /// does not carry names — answers `None` on replay.
    #[test]
    fn test_recorder_forwards_lwp_names_and_snapshots_drop_them() {
        let target = FakeTarget::new();
        let recorder = Recorder::new(&target);
        assert_eq!(recorder.lwp_name(7).as_deref(), Some("tokio-runtime-w"));
        assert_eq!(recorder.lwp_name(8), None);
        let snapshot = recorder
            .snapshot(RecordedHeapEvidence::Unavailable)
            .expect("snapshot assembles");
        assert_eq!(snapshot.lwp_name(7), None);
    }

    /// What a snapshot does not carry it answers as absent, through
    /// the trait defaults: no process identity, no fd table, no exec
    /// path, no build ids, and no attribution of symbols to objects.
    #[test]
    fn test_snapshots_answer_absent_process_facts() {
        let target = FakeTarget::new();
        let snapshot = Recorder::new(&target)
            .snapshot(RecordedHeapEvidence::Unavailable)
            .expect("snapshot assembles");
        assert_eq!(Target::process_facts(&snapshot), None);
        assert_eq!(Target::exec_path(&snapshot), None);
        assert_eq!(Target::build_ids(&snapshot), None);
    }

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

        /// The bytes at `addr`, when the fake maps them.
        fn at(&self, addr: u64, len: u64) -> Option<&[u8]> {
            let start = addr.checked_sub(self.base)? as usize;
            self.memory.get(start..start + len as usize)
        }
    }

    impl Target for FakeTarget {
        fn read_bytes(&self, addr: u64, len: u64) -> TargetResult<&[u8]> {
            self.at(addr, len)
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

        fn lwp_name(&self, tid: u32) -> Option<String> {
            (tid == 7).then(|| "tokio-runtime-w".to_string())
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

        /// The fake is a PIE, so a capture of it has a bias to carry
        /// rather than "cannot say".
        fn exec_bias(&self) -> Option<u64> {
            Some(self.base)
        }
    }

    /// The executable's load bias is a fact about the captured target
    /// and cannot be worked out from a snapshot's contents, so the
    /// capture records it — and a target that cannot say records
    /// nothing rather than a zero that would read as a claim.
    #[test]
    fn test_the_exec_bias_is_captured() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        assert_eq!(rec.exec_bias(), Some(target.base));
        assert_eq!(
            rec.snapshot(RecordedHeapEvidence::Unavailable)
                .unwrap()
                .exec_bias(),
            Some(target.base)
        );

        assert_eq!(Target::exec_bias(&snapshot_of(&[])), None);
    }

    #[test]
    fn test_replay_recorded_reads() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        let want = rec.read_bytes(0x1100, 32).unwrap().to_vec();
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();

        // The exact read, and any sub-range of it, replays.
        assert_eq!(snap.read_bytes(0x1100, 32).unwrap(), want);
        assert_eq!(snap.read_bytes(0x1108, 8).unwrap(), &want[8..16]);
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
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();

        // Never-read ranges fail even though the fake target had them.
        assert!(snap.read_bytes(0x1200, 16).is_err());
        // So do reads extending past a captured run's edge.
        assert!(snap.read_bytes(0x1108, 16).is_err());
        assert!(snap.read_bytes(0x10f8, 16).is_err());
    }

    /// A captured read is lent out of the snapshot's own segment rather
    /// than copied, and what it cannot lend whole it does not serve at
    /// all — the same rule the core readers follow.
    #[test]
    fn test_reads_lend_captured_runs() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        rec.read_bytes(0x1100, 32).unwrap();
        // A second run, past a gap the capture never touched.
        rec.read_bytes(0x1300, 32).unwrap();
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();
        assert_eq!(snap.memory.len(), 2);

        let lent = snap.read_bytes(0x1100, 32).unwrap();
        assert!(std::ptr::eq(lent.as_ptr(), snap.memory[0].bytes.as_ptr()));
        // Sub-ranges lend from the same run.
        let sub = snap.read_bytes(0x1108, 8).unwrap();
        assert_eq!(sub, &lent[8..16]);
        assert!(std::ptr::eq(sub.as_ptr(), lent[8..].as_ptr()));

        // A range spanning the gap belongs to no single run, so it is
        // not served...
        assert!(snap.read_bytes(0x1100, 0x240).is_err());
        // ...nor one running off a run's edge, or outside both.
        assert!(snap.read_bytes(0x1110, 32).is_err());
        assert!(snap.read_bytes(0x1200, 8).is_err());
    }

    /// Recording and lending are not in tension: a read is served as a
    /// borrow of the wrapped target's own storage, and captured
    /// byte-for-byte on the way through.
    #[test]
    fn test_recorder_records_lent_reads() {
        let reads = [(0x1100, 0x20), (0x1110, 0x20), (0x1300, 0x10)];

        let lending = FakeTarget::new();
        let rec = Recorder::new(&lending);
        // The lend is the wrapped target's own storage, not the copy
        // that went into the log.
        let lent = rec.read_bytes(0x1100, 0x20).unwrap();
        assert!(std::ptr::eq(
            lent.as_ptr(),
            lending.at(0x1100, 0x20).unwrap().as_ptr()
        ));
        let borrowed: Vec<Vec<u8>> = reads
            .iter()
            .map(|&(a, l)| rec.read_bytes(a, l).unwrap().to_vec())
            .collect();
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();

        // The replay serves those reads back unchanged.
        for (&(addr, len), want) in reads.iter().zip(&borrowed) {
            assert_eq!(&snap.read_bytes(addr, len).unwrap(), want);
            assert_eq!(want, &lending.read_bytes(addr, len).unwrap());
        }
    }

    #[test]
    fn test_overlapping_reads_merge() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        // Overlapping and adjacent reads, out of address order.
        rec.read_bytes(0x1110, 0x20).unwrap();
        rec.read_bytes(0x1100, 0x18).unwrap();
        rec.read_bytes(0x1130, 0x10).unwrap();
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();

        assert_eq!(snap.memory.len(), 1);
        // The merged run serves a read no single original read covered.
        assert_eq!(
            snap.read_bytes(0x1100, 0x40).unwrap(),
            target.read_bytes(0x1100, 0x40).unwrap()
        );
    }

    /// A read that served nothing has no bytes to place, wherever it sits
    /// relative to the reads that did. The one past every extent is the
    /// case that used to index off the end of the last segment: a
    /// zero-sized type read behind a dyn pointer is such a read, and its
    /// address need not be near anything else the analysis touched.
    #[test]
    fn test_an_empty_read_writes_nothing() {
        let reads = vec![
            Segment {
                addr: 0x1000,
                bytes: vec![1, 2, 3, 4],
            },
            Segment {
                addr: 0x9000,
                bytes: vec![],
            },
            Segment {
                addr: 0x1002,
                bytes: vec![],
            },
            Segment {
                addr: 0x0100,
                bytes: vec![],
            },
        ];
        assert_eq!(
            merge_reads(&reads),
            vec![Segment {
                addr: 0x1000,
                bytes: vec![1, 2, 3, 4],
            }]
        );
    }

    /// A read a logged run already covers whole is lent without being
    /// logged or charged again — and a run is what the reads merged
    /// into, so an overlap that joins two runs covers what spans them.
    /// A partial overlap is a new read, logged as ever. The snapshot is
    /// the same either way; the account is what differs.
    #[test]
    fn test_a_covered_read_is_not_logged_again() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        let size = |bytes, entries| ReadLogSize { bytes, entries };
        rec.read_bytes(0x1000, 8).unwrap();
        assert_eq!(rec.charged(), size(8, 1));
        // The same read, and reads inside it: nothing new.
        rec.read_bytes(0x1000, 8).unwrap();
        rec.read_bytes(0x1002, 4).unwrap();
        rec.read_bytes(0x1007, 1).unwrap();
        assert_eq!(rec.charged(), size(8, 1));
        // A partial overlap reaches memory the log lacks: logged whole.
        rec.read_bytes(0x1004, 8).unwrap();
        assert_eq!(rec.charged(), size(16, 2));
        // An adjacent run joins the merged one, and a read spanning
        // what were three reads is now covered by the one run.
        rec.read_bytes(0x100c, 4).unwrap();
        assert_eq!(rec.charged(), size(20, 3));
        rec.read_bytes(0x1000, 16).unwrap();
        assert_eq!(rec.charged(), size(20, 3));
        // A read bridging two separate runs is logged, and the runs
        // become one.
        rec.read_bytes(0x1020, 8).unwrap();
        rec.read_bytes(0x1010, 16).unwrap();
        assert_eq!(rec.charged(), size(44, 5));
        rec.read_bytes(0x1000, 40).unwrap();
        assert_eq!(rec.charged(), size(44, 5));
        assert_eq!(
            rec.log.lock().unwrap().covered,
            BTreeMap::from([(0x1000, 0x1028)])
        );

        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();
        assert_eq!(
            snap.read_bytes(0x1000, 40).unwrap(),
            target.at(0x1000, 40).unwrap()
        );
        assert_eq!(snap.segments().collect::<Vec<_>>(), vec![0x1000..0x1028]);
    }

    /// Past a limit, a covered read is refused like any other: the
    /// capture is over, and lending recorded bytes would let an
    /// analysis run on past the point the snapshot stops recording it.
    #[test]
    fn test_a_covered_read_is_refused_past_the_limit() {
        let target = FakeTarget::new();
        let rec = Recorder::with_limits(
            &target,
            CaptureLimits {
                read_log_entries: 1,
                ..CaptureLimits::default()
            },
        );
        rec.read_bytes(0x1000, 8).unwrap();
        rec.read_bytes(0x1000, 8).unwrap();
        let err = rec.read_bytes(0x1100, 8).unwrap_err();
        let exceeded = rec
            .failure()
            .expect("the second distinct read is the violation");
        assert_eq!(err.to_string(), exceeded.to_string());
        let err = rec.read_bytes(0x1000, 8).unwrap_err();
        assert_eq!(err.to_string(), exceeded.to_string());
        assert_eq!(
            rec.charged(),
            ReadLogSize {
                bytes: 8,
                entries: 1
            }
        );
    }

    /// A recorder answers the question about allocator evidence the
    /// way the target it wraps does: a snapshot's recorded policy, or
    /// nothing for a target that records none — so a driver
    /// recapturing a pair prepares under the policy the pair records.
    #[test]
    fn test_the_recorder_forwards_the_recorded_heap_policy() {
        let target = FakeTarget::new();
        assert_eq!(Recorder::new(&target).recorded_heap_evidence(), None);
        for evidence in [
            RecordedHeapEvidence::Available,
            RecordedHeapEvidence::Unavailable,
        ] {
            let snap = Recorder::new(&target).snapshot(evidence).unwrap();
            assert_eq!(snap.recorded_heap_evidence(), Some(evidence));
            assert_eq!(
                Recorder::new(&snap).recorded_heap_evidence(),
                Some(evidence)
            );
        }
    }

    #[test]
    fn test_later_reads_win_overlaps() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Lends a different pre-made buffer per read, so overlapping
        /// reads observe different bytes the way a changing target's
        /// would.
        struct Changing {
            generations: [Vec<u8>; 2],
            reads: AtomicUsize,
        }
        impl Target for Changing {
            fn read_bytes(&self, _addr: u64, len: u64) -> TargetResult<&[u8]> {
                let read = self.reads.fetch_add(1, Ordering::Relaxed);
                Ok(&self.generations[read][..len as usize])
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

        let target = Changing {
            generations: [vec![1; 8], vec![2; 8]],
            reads: AtomicUsize::new(0),
        };
        let rec = Recorder::new(&target);
        rec.read_bytes(0x1000, 8).unwrap(); // all 1s
        rec.read_bytes(0x1004, 8).unwrap(); // all 2s
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();
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
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();

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
        let mut snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();
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
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();

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
        let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();

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
        rec.snapshot(RecordedHeapEvidence::Unavailable)
            .unwrap()
            .write(&mut buf)
            .unwrap();

        // Wrong magic.
        let mut bad = buf.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            Snapshot::read(bad.as_slice()),
            Err(Error::BadMagic)
        ));

        // Wrong version, newer or older: a file from before the heap
        // policy was recorded is rejected at the header, not decoded
        // into a snapshot that answers `Unavailable` for a capture that
        // never said.
        for found in [FORMAT_VERSION + 1, FORMAT_VERSION - 1] {
            let mut bad = buf.clone();
            bad[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&found.to_le_bytes());
            assert!(matches!(
                Snapshot::read(bad.as_slice()),
                Err(Error::VersionMismatch { found: f, expected })
                    if f == found && expected == FORMAT_VERSION
            ));
        }

        // Truncated payload.
        let bad = &buf[..buf.len() / 2];
        assert!(Snapshot::read(bad).is_err());

        // Truncated header.
        assert!(matches!(Snapshot::read(&buf[..6]), Err(Error::Io(_))));
    }

    /// The heap policy is the capture's to state and the file's to
    /// keep: either value survives the format, and a reader gets back
    /// the one the capture recorded.
    #[test]
    fn test_the_heap_evidence_round_trips() {
        let target = FakeTarget::new();
        for evidence in [
            RecordedHeapEvidence::Available,
            RecordedHeapEvidence::Unavailable,
        ] {
            let rec = Recorder::new(&target);
            rec.read_bytes(0x1000, 16).unwrap();
            let snap = rec.snapshot(evidence).unwrap();
            assert_eq!(snap.heap_evidence(), evidence);
            let mut buf = Vec::new();
            snap.write(&mut buf).unwrap();
            let back = Snapshot::read(buf.as_slice()).unwrap();
            assert_eq!(back.heap_evidence(), evidence);
            assert_eq!(back, snap);
        }
    }

    /// The log is charged before a read is copied into it, and the
    /// first charge past a limit ends the capture: that read fails,
    /// every later one fails the same way without being logged, the
    /// failure names the limit and the totals, and no snapshot
    /// assembles from the part that was recorded.
    #[test]
    fn test_a_read_past_the_entry_limit_ends_the_capture() {
        let target = FakeTarget::new();
        let rec = Recorder::with_limits(
            &target,
            CaptureLimits {
                read_log_entries: 2,
                ..CaptureLimits::default()
            },
        );
        rec.read_bytes(0x1000, 8).unwrap();
        rec.read_bytes(0x1100, 8).unwrap();
        assert_eq!(rec.failure(), None);
        assert_eq!(
            rec.charged(),
            ReadLogSize {
                bytes: 16,
                entries: 2
            }
        );

        let exceeded = LimitExceeded {
            limit: Limit::ReadLogEntries,
            charged: 3,
            cap: 2,
        };
        let err = rec.read_bytes(0x1200, 8).unwrap_err();
        assert_eq!(err.to_string(), exceeded.to_string());
        assert_eq!(rec.failure(), Some(exceeded));
        // Sticky: a read the log could otherwise have afforded is
        // refused too, and the account is where the violation left it.
        let err = rec.read_bytes(0x1000, 1).unwrap_err();
        assert_eq!(err.to_string(), exceeded.to_string());
        assert_eq!(
            rec.charged(),
            ReadLogSize {
                bytes: 16,
                entries: 2
            }
        );
        let err = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap_err();
        assert_eq!(err.to_string(), exceeded.to_string());
    }

    /// The byte limit is charged with the bytes a read would add, so
    /// the read that would take the log past it is the one refused —
    /// however many entries remain — and the total reported is the one
    /// the read would have reached.
    #[test]
    fn test_a_read_past_the_byte_limit_ends_the_capture() {
        let target = FakeTarget::new();
        let rec = Recorder::with_limits(
            &target,
            CaptureLimits {
                read_log_bytes: 40,
                ..CaptureLimits::default()
            },
        );
        rec.read_bytes(0x1000, 32).unwrap();
        // Served no bytes, from memory nothing logged covers: an
        // entry, but no charge against the bytes.
        rec.read_bytes(0x2000, 0).unwrap();
        assert_eq!(
            rec.charged(),
            ReadLogSize {
                bytes: 32,
                entries: 2
            }
        );
        assert_eq!(rec.read_bytes(0x1100, 8).unwrap().len(), 8);

        let err = rec.read_bytes(0x1200, 1).unwrap_err();
        let exceeded = LimitExceeded {
            limit: Limit::ReadLogBytes,
            charged: 41,
            cap: 40,
        };
        assert_eq!(err.to_string(), exceeded.to_string());
        assert_eq!(rec.failure(), Some(exceeded));
        assert_eq!(
            exceeded.to_string(),
            "the capture charged 41 read-log bytes against its limit of 40"
        );
    }

    /// A read the wrapped target refuses is not a read of the log's:
    /// it is neither logged nor charged, and the target's own error is
    /// what comes back.
    #[test]
    fn test_a_refused_read_is_not_charged() {
        let target = FakeTarget::new();
        let rec = Recorder::with_limits(
            &target,
            CaptureLimits {
                read_log_entries: 1,
                ..CaptureLimits::default()
            },
        );
        assert!(rec.read_bytes(0x10, 8).is_err());
        assert_eq!(rec.charged(), ReadLogSize::default());
        assert_eq!(rec.failure(), None);
        rec.read_bytes(0x1000, 8).unwrap();
        assert_eq!(rec.failure(), None);
    }

    /// A save replaces the file at its path only once the whole
    /// snapshot is written within the output limit. One that reaches
    /// the limit fails, leaves the previous file byte for byte, and
    /// leaves no temporary beside it.
    #[test]
    fn test_a_save_publishes_only_a_complete_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.snapshot");
        let target = FakeTarget::new();

        let rec = Recorder::new(&target);
        rec.read_bytes(0x1000, 64).unwrap();
        let first = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();
        first
            .save(&path, CaptureLimits::default().output_bytes)
            .unwrap();
        let published = fs::read(&path).unwrap();
        assert_eq!(Snapshot::load(&path).unwrap(), first);

        let rec = Recorder::new(&target);
        rec.read_bytes(0x1000, 0x1000).unwrap();
        let second = rec.snapshot(RecordedHeapEvidence::Available).unwrap();
        let cap = published.len() as u64 / 2;
        match second.save(&path, cap).unwrap_err() {
            Error::Limit(exceeded) => {
                assert_eq!(exceeded.limit, Limit::OutputBytes);
                assert_eq!(exceeded.cap, cap);
                assert!(exceeded.charged > cap, "{exceeded}");
            }
            other => panic!("expected the output limit, got {other}"),
        }
        assert_eq!(fs::read(&path).unwrap(), published);
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["fixture.snapshot"]);

        // Within the limit, the new file takes the old one's place.
        second
            .save(&path, CaptureLimits::default().output_bytes)
            .unwrap();
        assert_eq!(Snapshot::load(&path).unwrap(), second);
        assert_eq!(
            Snapshot::load(&path).unwrap().heap_evidence(),
            RecordedHeapEvidence::Available
        );
    }

    /// A writer that takes one byte per call and notes being flushed:
    /// the short writes a file never gives, so the bound's account of
    /// what actually went out is checked here rather than assumed.
    #[derive(Default)]
    struct Trickle {
        bytes: Vec<u8>,
        flushed: bool,
    }

    impl Write for Trickle {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.extend(&buf[..1.min(buf.len())]);
            Ok(1.min(buf.len()))
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }

    /// The bound charges each write with the whole buffer offered, but
    /// counts only what the inner writer took — so a caller retrying
    /// the remainder of a short write is charged for the remainder,
    /// not twice for the whole, and the write refused is exactly the
    /// one that would carry the count past the cap. Flushing reaches
    /// the inner writer.
    #[test]
    fn test_the_bound_counts_what_was_written() {
        let mut out = Bounded {
            inner: Trickle::default(),
            written: 0,
            cap: 5,
            exceeded: None,
        };
        // Three bytes offered, one taken, one charged.
        assert_eq!(out.write(b"abc").unwrap(), 1);
        assert_eq!(out.written, 1);
        // The remainder, written whole through the retry loop.
        out.write_all(b"bc").unwrap();
        assert_eq!(out.written, 3);
        // Two more fit exactly.
        out.write_all(b"de").unwrap();
        assert_eq!(out.written, 5);
        assert_eq!(out.exceeded, None);

        let err = out.write(b"f").unwrap_err();
        let exceeded = LimitExceeded {
            limit: Limit::OutputBytes,
            charged: 6,
            cap: 5,
        };
        assert_eq!(err.to_string(), exceeded.to_string());
        assert_eq!(out.exceeded, Some(exceeded));
        assert_eq!(out.inner.bytes, b"abcde");

        assert!(!out.inner.flushed);
        out.flush().unwrap();
        assert!(out.inner.flushed);
    }

    /// The temporary is the output's sibling, named after it: the
    /// rename that publishes it never crosses a filesystem.
    #[test]
    fn test_the_temporary_is_a_sibling() {
        assert_eq!(
            temporary_sibling(Path::new("/fixtures/linux/a.snapshot")),
            Path::new("/fixtures/linux/a.snapshot.tmp")
        );
        assert_eq!(
            temporary_sibling(Path::new("a.snapshot")),
            Path::new("a.snapshot.tmp")
        );
    }

    /// A read log's bytes as a plain map: the log replayed one byte at a
    /// time, the later write winning. Far too slow to keep — a byte per
    /// entry, and a tree walk to read one — which is exactly what makes it
    /// worth checking the two-pass sweep against.
    fn byte_map(reads: &[Segment]) -> BTreeMap<u64, u8> {
        let mut map = BTreeMap::new();
        for read in reads {
            for (i, byte) in read.bytes.iter().enumerate() {
                map.insert(read.addr + i as u64, *byte);
            }
        }
        map
    }

    /// The maximal runs of consecutive addresses in `map` — what a merge of
    /// the log it came from has to produce, disjointness and maximality
    /// included, since a run here cannot abut the next one by construction.
    fn runs(map: &BTreeMap<u64, u8>) -> Vec<Segment> {
        let mut out: Vec<Segment> = Vec::new();
        for (&addr, &byte) in map {
            match out.last_mut() {
                Some(seg) if seg.end() == addr => seg.bytes.push(byte),
                _ => out.push(Segment {
                    addr,
                    bytes: vec![byte],
                }),
            }
        }
        out
    }

    /// Where a generated read starts: a small offset from one of a few
    /// bases, spread far enough apart to stay separate segments. Addresses
    /// drawn from the whole space would overlap about never, and a log
    /// whose reads all fall in their own segment is the one arrangement
    /// merging has nothing to do with.
    fn read_addr() -> impl Strategy<Value = u64> {
        (
            prop::sample::select(&[0x1000u64, 0x2000, 0x8000][..]),
            0u64..48,
        )
            .prop_map(|(base, offset)| base + offset)
    }

    /// One recorded read, up to 20 bytes — long enough to span a base's
    /// worth of offsets and overlap its neighbours several ways, and to be
    /// empty, which is a read that served nothing.
    fn read() -> impl Strategy<Value = Segment> {
        (read_addr(), 0usize..20, any::<u8>()).prop_map(|(addr, len, fill)| Segment {
            addr,
            // A ramp, not a constant: bytes that are all alike hide a read
            // replayed at the wrong offset within its segment, since the
            // wrong bytes are then the same as the right ones.
            bytes: (0..len).map(|i| fill.wrapping_add(i as u8)).collect(),
        })
    }

    fn read_log() -> impl Strategy<Value = Vec<Segment>> {
        prop::collection::vec(read(), 0..12)
    }

    /// A snapshot holding merged memory and nothing else; these properties
    /// ask it about bytes only.
    fn snapshot_of(reads: &[Segment]) -> Snapshot {
        Snapshot {
            memory: merge_reads(reads),
            functions: vec![],
            objects: vec![],
            by_addr: BTreeMap::new(),
            by_name: BTreeMap::new(),
            tls: BTreeMap::new(),
            mappings: Mappings { inner: vec![] },
            lwps: vec![],
            exec_bias: None,
            heap_evidence: RecordedHeapEvidence::Unavailable,
        }
    }

    proptest! {
        /// The sweep against the byte map, which settles at once that the
        /// merged runs are sorted, disjoint, maximal, and hold the bytes
        /// the last read to cover them served.
        #[test]
        fn test_merging_a_log_yields_its_byte_map(reads in read_log()) {
            prop_assert_eq!(merge_reads(&reads), runs(&byte_map(&reads)));
        }

        /// A read is served whole or not at all, and what comes back is
        /// what was captured there.
        #[test]
        fn test_a_snapshot_serves_exactly_what_it_captured(
            reads in read_log(),
            addr in read_addr(),
            len in 1u64..24,
        ) {
            let map = byte_map(&reads);
            let snap = snapshot_of(&reads);
            let want: Option<Vec<u8>> = (0..len)
                .map(|i| addr.checked_add(i).and_then(|a| map.get(&a).copied()))
                .collect();
            match want {
                Some(want) => prop_assert_eq!(snap.read_bytes(addr, len).unwrap(), &want[..]),
                None => prop_assert!(snap.read_bytes(addr, len).is_err()),
            }
        }

        /// `readable_len` is how far a read may reach: within the cap it
        /// asked for, a read succeeds exactly when it fits. (From one byte
        /// up — a zero-length read is a question about an address rather
        /// than about bytes, and the two answer it differently.)
        #[test]
        fn test_readable_len_bounds_what_a_read_can_serve(
            reads in read_log(),
            addr in read_addr(),
            max in 1u64..24,
        ) {
            let snap = snapshot_of(&reads);
            let reach = snap.readable_len(addr, max);
            prop_assert!(reach <= max);
            for len in 1..=max {
                prop_assert_eq!(
                    snap.read_bytes(addr, len).is_ok(),
                    len <= reach,
                    "{} of {} bytes at {:#x}, reach {}",
                    len,
                    max,
                    addr,
                    reach
                );
            }
        }

        /// A snapshot survives its own file format.
        #[test]
        fn test_a_snapshot_round_trips(reads in read_log()) {
            let snap = snapshot_of(&reads);
            let mut buf = Vec::new();
            snap.write(&mut buf).unwrap();
            prop_assert_eq!(Snapshot::read(&buf[..]).unwrap(), snap);
        }

        /// The point of the whole module: whatever the analysis read from
        /// the target, the replay answers the same.
        #[test]
        fn test_replay_answers_as_the_target_did(
            probes in prop::collection::vec((0x1000u64..0x2000, 1u64..32), 1..12),
        ) {
            let target = FakeTarget::new();
            let rec = Recorder::new(&target);
            let mut served = Vec::new();
            for (addr, len) in probes {
                if let Ok(bytes) = rec.read_bytes(addr, len) {
                    served.push((addr, len, bytes.to_vec()));
                }
            }
            let snap = rec.snapshot(RecordedHeapEvidence::Unavailable).unwrap();
            for (addr, len, bytes) in served {
                prop_assert_eq!(snap.read_bytes(addr, len).unwrap(), &bytes[..]);
            }
        }
    }
}

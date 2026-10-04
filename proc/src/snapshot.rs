// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! In-memory target snapshots, for tests.
//!
//! A [`Snapshot`] holds the handful of things a debugger actually read
//! from a target — memory runs, symbol lookups, the function symtab,
//! mappings, and LWP state — and implements [`Target`] over them.
//! [`Recorder`] wraps a real target and records everything the wrapped
//! reads touch, so taking a snapshot is just driving the ordinary
//! analysis once with the recorder in place.
//!
//! What a test does with one is edit it: a snapshot is a target whose
//! contents can be doctored after the fact, and whose memory is exactly
//! the runs the recorded analysis read. It also says whether the
//! recording built a usable allocator index ([`RecordedHeapEvidence`]),
//! so a replay knows whether the corroboration the recorded reads were
//! gated by can be rebuilt from them.

use crate::{
    Error as TargetError, LwpInfo, Mappings, RecordedHeapEvidence, Regs, Result as TargetResult,
    SymbolBuf, Target,
};

use std::collections::BTreeMap;
use std::sync::Mutex;

/// One contiguous run of captured target memory.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Segment {
    addr: u64,
    bytes: Vec<u8>,
}

impl Segment {
    fn end(&self) -> u64 {
        self.addr + self.bytes.len() as u64
    }
}

/// What a recorder's read log holds, before merging.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReadLogSize {
    pub bytes: u64,
    pub entries: u64,
}

/// A recorded target: everything [`Recorder`] saw the analysis read,
/// replayable through [`Target`].
#[derive(Clone, PartialEq, Debug)]
pub struct Snapshot {
    /// Disjoint captured memory runs, sorted by address.
    memory: Vec<Segment>,
    /// The target executable's function symtab, sorted by value. Serves
    /// by-address lookups for addresses the recording never resolved,
    /// and the whole-symtab scan.
    functions: Vec<SymbolBuf>,
    /// The target executable's object symtab, used for normalized lookup of
    /// named statics whose crate disambiguators differ between builds.
    objects: Vec<SymbolBuf>,
    /// By-address lookups observed while recording, including misses.
    /// Authoritative over `functions`: a target may resolve an address
    /// to a symbol outside the function-symbol mask (weak symbols,
    /// aliases), and replay must agree with what the recording saw.
    by_addr: BTreeMap<u64, Option<SymbolBuf>>,
    /// By-name lookups observed while recording, including misses.
    /// Authoritative for the same reason; notably the TLS-key static is
    /// an object symbol, which `functions` does not cover.
    by_name: BTreeMap<String, Option<SymbolBuf>>,
    /// Thread-local addresses observed while recording, keyed by the
    /// thread's `%fsbase` and the symbol naming the variable. The answer
    /// is recorded rather than the bytes behind it because how a symbol
    /// reaches a thread-local is the recorded target's business, and
    /// replay must not have to know it.
    tls: BTreeMap<(u64, String), Option<u64>>,
    mappings: Mappings,
    lwps: Vec<LwpInfo>,
    /// The recorded target's executable load bias. Recorded rather than
    /// derived because a snapshot carries no program headers to derive
    /// it from, and a debug-info address means nothing without it.
    exec_bias: Option<u64>,
    /// Whether the recorded reads were gated by an allocator index the
    /// recording built, and so carry what rebuilding one needs.
    heap_evidence: RecordedHeapEvidence,
    /// Which of `lwps` is the `/proc` agent ([`Target::agent_lwp`]).
    /// Recorded, unlike the lwp names, because it changes what the
    /// analysis counts: a replay that forgot it would count the agent
    /// as one of the program's threads.
    agent_lwp: Option<u32>,
}

impl Snapshot {
    /// Whether this recording built an allocator index over its target.
    pub fn heap_evidence(&self) -> RecordedHeapEvidence {
        self.heap_evidence
    }

    /// The recorded memory runs, in address order — what this snapshot
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

// Snapshots replay and recorders record under the same parallel
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

    fn captured_runs(&self) -> Option<Vec<std::ops::Range<u64>>> {
        Some(self.segments().collect())
    }

    fn lwps(&self) -> TargetResult<Vec<LwpInfo>> {
        Ok(self.lwps.clone())
    }

    fn agent_lwp(&self) -> Option<u32> {
        self.agent_lwp
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> TargetResult<Option<u64>> {
        // There is no fallback: the recorded target's TLS model is
        // exactly what a snapshot does not carry, so an unrecorded pair
        // is a hole in the recording rather than a thread without the
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
/// [`Snapshot`] can replay the same analysis.
pub struct Recorder<'a, T> {
    target: &'a T,
    /// Every successful read that reached memory no earlier read
    /// covers whole, in order; partial overlaps are resolved at
    /// [`Recorder::snapshot`] time (later reads win).
    log: Mutex<ReadLog>,
    by_addr: Mutex<BTreeMap<u64, Option<SymbolBuf>>>,
    by_name: Mutex<BTreeMap<String, Option<SymbolBuf>>>,
    tls: Mutex<BTreeMap<(u64, String), Option<u64>>>,
}

/// The read log and its running size, under one lock so a read and
/// the copy it logs are one step.
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
    /// replay the first — no recording is taken from one.
    covered: BTreeMap<u64, u64>,
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
}

impl<'a, T: Target> Recorder<'a, T> {
    pub fn new(target: &'a T) -> Self {
        Self {
            target,
            log: Mutex::new(ReadLog::default()),
            by_addr: Mutex::new(BTreeMap::new()),
            by_name: Mutex::new(BTreeMap::new()),
            tls: Mutex::new(BTreeMap::new()),
        }
    }

    /// What the read log holds so far, before merging.
    pub fn charged(&self) -> ReadLogSize {
        let log = self.log.lock().unwrap();
        ReadLogSize {
            bytes: log.bytes,
            entries: log.reads.len() as u64,
        }
    }

    /// Assemble the snapshot: everything recorded so far, plus the
    /// function symtab, mappings, and LWPs read from the target now,
    /// stamped with whether the recording built an allocator index.
    pub fn snapshot(&self, heap_evidence: RecordedHeapEvidence) -> TargetResult<Snapshot> {
        let log = self.log.lock().unwrap();
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
            agent_lwp: self.target.agent_lwp(),
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
        // hand back the wrapped target's own storage. A read the log
        // already holds whole is lent without a copy.
        let bytes = self.target.read_bytes(addr, len)?;
        let mut log = self.log.lock().unwrap();
        let end = addr.saturating_add(bytes.len() as u64);
        if log.covers(addr, end) {
            return Ok(bytes);
        }
        log.bytes += bytes.len() as u64;
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

    fn captured_runs(&self) -> Option<Vec<std::ops::Range<u64>>> {
        self.target.captured_runs()
    }

    fn lwps(&self) -> TargetResult<Vec<LwpInfo>> {
        self.target.lwps()
    }

    fn lwp_name(&self, tid: u32) -> Option<String> {
        // Forwarded, not recorded: a snapshot does not carry lwp
        // names, so replay answers `None` and goldens the absence.
        self.target.lwp_name(tid)
    }

    fn agent_lwp(&self) -> Option<u32> {
        self.target.agent_lwp()
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

    /// A target whose readable memory is its mappings answers no
    /// captured runs; a snapshot answers exactly the runs it holds, and
    /// so does a recorder wrapping one.
    #[test]
    fn test_captured_runs_are_a_snapshots_own_and_nobody_elses() {
        let target = FakeTarget::new();
        assert_eq!(target.captured_runs(), None);
        let snapshot = Recorder::new(&target)
            .snapshot(RecordedHeapEvidence::Unavailable)
            .expect("snapshot assembles");
        let runs = snapshot.captured_runs().expect("a snapshot has runs");
        assert_eq!(runs, snapshot.segments().collect::<Vec<_>>());
        assert_eq!(Recorder::new(&snapshot).captured_runs(), Some(runs));
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

    /// A read the wrapped target refuses is not a read of the log's:
    /// it is not logged, and the target's own error is what comes back.
    #[test]
    fn test_a_refused_read_is_not_logged() {
        let target = FakeTarget::new();
        let rec = Recorder::new(&target);
        assert!(rec.read_bytes(0x10, 8).is_err());
        assert_eq!(rec.charged(), ReadLogSize::default());
        rec.read_bytes(0x1000, 8).unwrap();
        assert_eq!(
            rec.charged(),
            ReadLogSize {
                bytes: 8,
                entries: 1
            }
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
            agent_lwp: None,
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

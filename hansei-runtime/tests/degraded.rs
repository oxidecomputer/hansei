// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The runtime walks over corrupt memory.
//!
//! Every guard in the task, chain, and census walks — the per-shard
//! error containment, the cycle checks, the unmapped-pointer ensures —
//! exists for a torn or damaged core, which no healthy fixture can
//! produce. These tests make one: a [`Corrupt`] target replays a real
//! captured snapshot with chosen faults layered on top — address
//! ranges that no longer read, and words that lie — and the walks are
//! held to their contract: degrade, contain, and say what happened,
//! never crash and never loop.
//!
//! The corruptions are aimed with addresses the healthy run reports
//! (task headers, set nodes, the semaphore), so they land on the exact
//! structures the guards watch, whatever the snapshot's layout.

use exegesis::bundle::{Bundle, BundleView};
use hansei_runtime::tokio::bundle::{ChainEnd, Context, TaskList, TaskStage};
use hansei_runtime::tokio::{census, graph};
use proc::snapshot::Snapshot;
use proc::{LwpInfo, Mappings, Regs, SymbolBuf, Target};

use std::ops::Range;
use std::path::{Path, PathBuf};

/// An address nothing in a small test program's address space reaches.
const NOWHERE: u64 = 0xdead_beef_0000;

/// A captured snapshot with faults baked into memory of its own: a
/// denied range is cut out of the segments, so every read touching it
/// fails, and a patched word is written over, so every read of it sees
/// the lie.
///
/// The faults live in the bytes rather than in a `read_bytes` that
/// doctors what it serves, because the renderer reads by borrowing: a
/// lent slice carries a corruption only if the storage behind it does.
struct Corrupt<'a> {
    inner: &'a Snapshot,
    /// The snapshot's captured runs, copied so they can be damaged, each
    /// as `(address, bytes)` and in ascending address order.
    memory: Vec<(u64, Vec<u8>)>,
}

impl<'a> Corrupt<'a> {
    fn new(inner: &'a Snapshot) -> Self {
        let memory = inner
            .segments()
            .map(|seg| {
                let bytes = inner
                    .read_bytes(seg.start, seg.end - seg.start)
                    .expect("a recorded segment");
                (seg.start, bytes)
            })
            .collect();
        Corrupt { inner, memory }
    }

    /// Reads overlapping `range` fail, as if the pages were not dumped.
    fn deny(self, range: Range<u64>) -> Self {
        let memory = self
            .memory
            .into_iter()
            .flat_map(|(addr, bytes)| {
                let len = bytes.len() as u64;
                // What the hole leaves of this run: the part before it
                // and the part after it, either of which may be empty.
                let head = range.start.saturating_sub(addr).min(len) as usize;
                let tail = range.end.saturating_sub(addr).min(len) as usize;
                [
                    (head > 0).then(|| (addr, bytes[..head].to_vec())),
                    (tail < bytes.len()).then(|| (addr + tail as u64, bytes[tail..].to_vec())),
                ]
            })
            .flatten()
            .collect();
        Corrupt { memory, ..self }
    }

    /// The word at `addr` reads back as `value`.
    fn patch(mut self, addr: u64, value: u64) -> Self {
        let patched = self.write(addr, value);
        assert!(patched, "no recorded segment holds {addr:#x}");
        self
    }

    /// Every recorded aligned word equal to `value` reads back as
    /// `lie` — how a pointer *to* a structure is corrupted when only
    /// the target's own memory says where that pointer lives (a shard
    /// head, an intrusive link).
    fn patch_words_equal(mut self, value: u64, lie: u64) -> Self {
        let mut patched = 0;
        for (addr, bytes) in &mut self.memory {
            let skew = (addr.next_multiple_of(8) - *addr) as usize;
            let Some(aligned) = bytes.get_mut(skew..) else {
                continue;
            };
            for word in aligned.chunks_exact_mut(8) {
                if u64::from_le_bytes(word.try_into().unwrap()) == value {
                    word.copy_from_slice(&lie.to_le_bytes());
                    patched += 1;
                }
            }
        }
        assert!(patched > 0, "no recorded word holds {value:#x}");
        self
    }

    /// Write `value` over the word at `addr`, reporting whether any
    /// captured run holds it.
    fn write(&mut self, addr: u64, value: u64) -> bool {
        for (base, bytes) in &mut self.memory {
            let Some(start) = addr.checked_sub(*base).map(|o| o as usize) else {
                continue;
            };
            if let Some(word) = bytes
                .get_mut(start..)
                .and_then(<[u8]>::first_chunk_mut::<8>)
            {
                *word = value.to_le_bytes();
                return true;
            }
        }
        false
    }

    /// The captured run holding `addr`, if the faults left one.
    fn segment(&self, addr: u64) -> Option<(u64, &[u8])> {
        self.memory
            .iter()
            .map(|(base, bytes)| (*base, &bytes[..]))
            .find(|(base, bytes)| addr >= *base && addr - base < bytes.len() as u64)
    }
}

impl Target for Corrupt<'_> {
    fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<Vec<u8>> {
        self.pslice(addr, len)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| proc::Error::unmapped(addr, len))
    }

    fn pslice(&self, addr: u64, len: u64) -> Option<&[u8]> {
        let end = addr.checked_add(len)?;
        let (base, bytes) = self.segment(addr)?;
        (end - base <= bytes.len() as u64)
            .then(|| &bytes[(addr - base) as usize..(end - base) as usize])
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        match self.segment(addr) {
            Some((base, bytes)) => (base + bytes.len() as u64 - addr).min(max),
            None => 0,
        }
    }

    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        self.inner.lookup_symbol_by_addr(addr)
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        self.inner.lookup_symbol_by_name(name)
    }

    fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
        self.inner.symbols()
    }

    fn object_symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
        self.inner.object_symbols()
    }

    fn mappings(&self) -> proc::Result<Mappings> {
        self.inner.mappings()
    }

    fn lwps(&self) -> proc::Result<Vec<LwpInfo>> {
        self.inner.lwps()
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> proc::Result<Option<u64>> {
        self.inner.tls_var_addr(regs, sym)
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn load(program: &str) -> (Bundle, Snapshot) {
    let bundle = Bundle::load(&fixture(&format!("{program}.bundle")))
        .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
    let snapshot = Snapshot::load(&fixture(&format!("{program}.snapshot")))
        .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
    (bundle, snapshot)
}

/// Discovery and enumeration against an arbitrary target.
fn tasks_of<'a, T: Target>(ctx: &Context<'a, T>, snapshot: &Snapshot) -> TaskList {
    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let shared = ctx.find_shared(&workers).expect("a MultiThread runtime");
    ctx.enumerate_tasks(shared).expect("the owned-task walk")
}

/// The healthy pipeline, run first to learn the addresses a corruption
/// should land on.
fn healthy<'a>(bundle: &'a Bundle, snapshot: &'a Snapshot) -> (Context<'a, Snapshot>, TaskList) {
    let ctx = Context::new(snapshot, BundleView::new(bundle)).expect("snapshot has mappings");
    let list = tasks_of(&ctx, snapshot);
    assert!(list.errors.is_empty(), "{:?}", list.errors);
    (ctx, list)
}

// ---------------------------------------------------------------------------
// Task enumeration
// ---------------------------------------------------------------------------

/// An unreadable task degrades its own shard and nothing else: the
/// error names the shard and the address, the other tasks still list,
/// and the analysis still runs over what remains.
#[test]
fn test_an_unreadable_task_degrades_only_its_shard() {
    let (bundle, snapshot) = load("joinset");
    let (_ctx, list) = healthy(&bundle, &snapshot);
    let victim = list.tasks.last().expect("the fixture has tasks").addr.0;

    let corrupt = Corrupt::new(&snapshot).deny(victim..victim + 0x40);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let degraded = tasks_of(&ctx, &snapshot);

    assert_eq!(degraded.errors.len(), 1, "{:?}", degraded.errors);
    let err = format!("{:#}", degraded.errors[0]);
    assert!(err.contains("task walk failed in shard"), "{err}");
    assert!(err.contains(&format!("{victim:#x}")), "{err}");

    // The victim is gone; every other task survived.
    assert!(degraded.tasks.iter().all(|t| t.addr.0 != victim));
    assert_eq!(degraded.tasks.len(), list.tasks.len() - 1);

    // The analysis takes the degraded list in stride.
    let analysis = graph::analyze(&ctx, &degraded);
    assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);
}

/// A link that points into unmapped memory is refused by the address
/// check before anything reads through it, and contained the same way.
#[test]
fn test_an_unmapped_task_pointer_is_reported() {
    let (bundle, snapshot) = load("joinset");
    let (_ctx, list) = healthy(&bundle, &snapshot);
    let victim = list.tasks.last().unwrap().addr.0;

    let corrupt = Corrupt::new(&snapshot).patch_words_equal(victim, NOWHERE);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let degraded = tasks_of(&ctx, &snapshot);

    let errs: Vec<String> = degraded.errors.iter().map(|e| format!("{e:#}")).collect();
    assert!(
        errs.iter()
            .any(|e| e.contains(&format!("task pointer {NOWHERE:#x} is unmapped"))),
        "{errs:?}"
    );
    assert!(degraded.tasks.iter().all(|t| t.addr.0 != victim));
}

/// A link bent back onto a task already walked trips the cycle guard
/// rather than listing forever.
#[test]
fn test_a_task_list_cycle_is_caught() {
    let (bundle, snapshot) = load("joinset");
    let (_ctx, list) = healthy(&bundle, &snapshot);
    let victim = list.tasks.last().unwrap().addr.0;
    let decoy = list.tasks.first().unwrap().addr.0;
    assert_ne!(victim, decoy);

    // Every pointer at the victim now points at the decoy: whichever
    // list reaches it second sees a task it has already walked.
    let corrupt = Corrupt::new(&snapshot).patch_words_equal(victim, decoy);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let degraded = tasks_of(&ctx, &snapshot);

    let errs: Vec<String> = degraded.errors.iter().map(|e| format!("{e:#}")).collect();
    assert!(
        errs.iter().any(|e| e.contains("owned-task list cycle")),
        "{errs:?}"
    );
    // The decoy was listed exactly once for all that two links name it.
    assert_eq!(
        degraded.tasks.iter().filter(|t| t.addr.0 == decoy).count(),
        1
    );
}

// ---------------------------------------------------------------------------
// Stage and chain
// ---------------------------------------------------------------------------

/// A task whose cell no longer reads fails its stage decode with an
/// error, not a panic — the shape `hansei` prints as a per-task
/// warning.
#[test]
fn test_an_unreadable_cell_fails_the_stage_read() {
    let (bundle, snapshot) = load("simple-await");
    let (_ctx, list) = healthy(&bundle, &snapshot);
    let task = &list.tasks[0];

    let corrupt = Corrupt::new(&snapshot).deny(task.addr.0..task.addr.0 + 0x2000);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    assert!(ctx.task_stage(task).is_err());
}

/// A dyn future whose box was overwritten ends its chain with
/// [`ChainEnd::Error`] naming the bad pointer; the frames before it
/// stand.
#[test]
fn test_a_corrupted_dyn_box_ends_the_chain_with_an_error() {
    let (bundle, snapshot) = load("dyn-future");
    let (ctx, list) = healthy(&bundle, &snapshot);
    let driver = list
        .tasks
        .iter()
        .find(|t| t.task_id == Some(3))
        .expect("the driver task");

    // The healthy chain locates the wide pointer: the driver frame's
    // `__awaitee` is the `Pin<Box<dyn Future>>` itself.
    let TaskStage::Running(future) = ctx.task_stage(driver).unwrap() else {
        panic!("the driver is parked");
    };
    let chain = ctx.await_chain(future);
    let state = chain.frames[0].state.as_ref().expect("a suspended driver");
    let awaitee = state
        .payload
        .ty
        .members()
        .find(|m| m.name() == "__awaitee")
        .expect("the driver awaits");
    let wide = state.payload.addr + awaitee.offset();

    // Both words of the wide pointer now point nowhere.
    let corrupt = Corrupt::new(&snapshot)
        .patch(wide, NOWHERE)
        .patch(wide + 8, NOWHERE);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let TaskStage::Running(future) = ctx.task_stage(driver).unwrap() else {
        panic!("the driver is parked");
    };
    let chain = ctx.await_chain(future);

    assert!(!chain.frames.is_empty(), "the outer frame still decodes");
    let ChainEnd::Error(e) = &chain.end else {
        panic!("expected an error end, got {:?}", chain.end);
    };
    assert!(format!("{e:#}").contains("unmapped"), "{e:#}");
}

// ---------------------------------------------------------------------------
// Analysis and census
// ---------------------------------------------------------------------------

/// An unreadable semaphore splits the analysis along its data's
/// provenance: the held acquire — read out of the holder's own frame —
/// is still diagnosed, while the wait queue behind the dead semaphore
/// degrades to an error and an empty blocked list rather than a
/// fabricated one.
#[test]
fn test_an_unreadable_semaphore_degrades_the_analysis() {
    let (bundle, snapshot) = load("futurelock");
    let (ctx, list) = healthy(&bundle, &snapshot);
    let analysis = graph::analyze(&ctx, &list);
    assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);
    assert!(!analysis.futurelocks[0].blocked.is_empty());
    let semaphore = analysis.futurelocks[0].acquire.semaphore;

    let corrupt = Corrupt::new(&snapshot).deny(semaphore..semaphore + 0x100);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let degraded = graph::analyze(&ctx, &list);

    let errs: Vec<String> = degraded.errors.iter().map(|e| format!("{e:#}")).collect();
    assert!(errs.iter().any(|e| e.contains("waits on")), "{errs:?}");
    let fl = &degraded.futurelocks[0];
    assert!(fl.blocked.is_empty(), "{fl:#?}");
}

/// An unreadable set node stops the set walk where it stands: the
/// children before it are kept, and the census error says the list is
/// incomplete.
#[test]
fn test_an_unreadable_set_node_keeps_the_walked_prefix() {
    let (bundle, snapshot) = load("unordered");
    let (ctx, list) = healthy(&bundle, &snapshot);
    let baseline = census::census(&ctx, &list);
    let node = baseline.sets[0].children[1].node;

    let corrupt = Corrupt::new(&snapshot).deny(node..node + 0x10);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let degraded = census::census(&ctx, &list);

    assert_eq!(degraded.sets.len(), 1);
    assert_eq!(degraded.sets[0].children.len(), 1, "{:#?}", degraded.sets);
    assert_eq!(degraded.errors.len(), 1, "{:?}", degraded.errors);
    let err = format!("{:#}", degraded.errors[0]);
    assert!(err.contains("lists only 1 of its children"), "{err}");
}

/// A set node chain bent into a loop trips the node cycle guard, with
/// the prefix kept the same way.
#[test]
fn test_a_set_node_cycle_is_bounded() {
    let (bundle, snapshot) = load("unordered");
    let (ctx, list) = healthy(&bundle, &snapshot);
    let baseline = census::census(&ctx, &list);
    let children: Vec<u64> = baseline.sets[0].children.iter().map(|c| c.node).collect();
    let [first, _, third] = children.as_slice() else {
        panic!("the fixture set holds three children");
    };

    // Every link to the third node now points back at the first: the
    // walk sees a node it has already visited.
    let corrupt = Corrupt::new(&snapshot).patch_words_equal(*third, *first);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let degraded = census::census(&ctx, &list);

    assert_eq!(degraded.sets[0].children.len(), 2, "{:#?}", degraded.sets);
    let err = format!("{:#}", degraded.errors[0]);
    assert!(err.contains("set node cycle"), "{err}");
}

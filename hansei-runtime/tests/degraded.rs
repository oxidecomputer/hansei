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
//! (task headers, set nodes, join set entries, the semaphore), so they
//! land on the exact structures the guards watch, whatever the
//! snapshot's layout.

use hansei_bundle::{Bundle, BundleTypeId, BundleView, DiscrValue};
use hansei_runtime::testkit::{load_any, tasks as tasks_of};
use hansei_runtime::tokio::bundle::{ChainEnd, Context, TaskList, TaskStage};
use hansei_runtime::tokio::{census, graph};
use proc::snapshot::Snapshot;
use proc::{LwpInfo, Mappings, Regs, SymbolBuf, Target};

use std::ops::Range;

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
                    .expect("a recorded segment")
                    .to_vec();
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
    fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
        let lent = || {
            let end = addr.checked_add(len)?;
            let (base, bytes) = self.segment(addr)?;
            (end - base <= bytes.len() as u64)
                .then(|| &bytes[(addr - base) as usize..(end - base) as usize])
        };
        lent().ok_or_else(|| proc::Error::unmapped(addr, len))
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
    let (bundle, snapshot) = load_any("joinset");
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
    let (bundle, snapshot) = load_any("joinset");
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
    let (bundle, snapshot) = load_any("joinset");
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
    let (bundle, snapshot) = load_any("simple-await");
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
    let (bundle, snapshot) = load_any("dyn-future");
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
    let (bundle, snapshot) = load_any("futurelock");
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
    let (bundle, snapshot) = load_any("unordered");
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

/// One held future, located healthy: the address of the `local` slot
/// in the frame the census found it in, and the address the census
/// recorded for it — the same place for a future held by value, the
/// slot and the boxed future behind it for a `Pin<Box<dyn Future>>`.
fn held_slot(bundle: &Bundle, snapshot: &Snapshot, local: &str) -> (u64, u64) {
    let ctx = Context::new(snapshot, BundleView::new(bundle)).expect("snapshot has mappings");
    let list = tasks_of(&ctx, snapshot);
    let census = census::census(&ctx, &list);
    let held = census
        // The task's own find, since the frame is looked up through its
        // chain below: a find the census reached through another lives
        // in that one's frames rather than in any of the task's.
        .held
        .iter()
        .find(|h| h.local == local && h.via.is_none())
        .unwrap_or_else(|| panic!("no held `{local}` in {:#?}", census.held));
    assert!(held.depth > 0, "the healthy chain resolves: {held:#?}");

    let task = &list.tasks[held.owner];
    let TaskStage::Running(root) = ctx.task_stage(task).unwrap() else {
        panic!("the holder is parked");
    };
    let chain = ctx.await_chain(root);
    let frame = &chain.frames[held.frame];
    let payload = match &frame.state {
        Some(state) => &state.payload,
        None => &frame.future,
    };
    let member = payload
        .ty
        .members()
        .find(|m| m.name() == local)
        .expect("the frame the census found it in holds it");
    (payload.addr + member.offset(), held.addr)
}

/// The census's own view of one held future, by the local holding it.
fn held_row(census: &census::FutureCensus, local: &str) -> (String, usize) {
    let held = census
        .held
        .iter()
        .find(|h| h.local == local)
        .unwrap_or_else(|| panic!("no held `{local}` in {:#?}", census.held));
    assert!(held.state.is_none(), "{held:#?}");
    assert!(held.waiting_on.is_none(), "{held:#?}");
    (held.future.clone(), held.depth)
}

/// A held future whose box points nowhere is still *found* — a wide
/// pointer is one by its type — and still listed. What the census
/// cannot say is what it is: the row degrades to `<undecoded>` and
/// stands on no frames, rather than the find being dropped.
#[test]
fn test_a_held_future_with_an_unmapped_box_is_listed_undecoded() {
    let (bundle, snapshot) = load_any("futurelock");
    let (wide, _) = held_slot(&bundle, &snapshot, "future1");

    let corrupt = Corrupt::new(&snapshot).patch(wide, NOWHERE);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let list = tasks_of(&ctx, &snapshot);
    let degraded = census::census(&ctx, &list);

    assert_eq!(
        held_row(&degraded, "future1"),
        ("<undecoded>".to_string(), 0)
    );
}

/// A held future whose vtable no longer names a future it knows is
/// listed as the trait object it is: the pointee's own type, which is
/// all a failed join leaves to say.
#[test]
fn test_a_held_future_with_an_unjoinable_vtable_is_listed_unresolved() {
    let (bundle, snapshot) = load_any("futurelock");
    let (wide, boxed) = held_slot(&bundle, &snapshot, "future1");

    // The vtable word now names the boxed future's own allocation, and
    // the two slots the join reads there — drop at +0, poll at +24 —
    // are zeroed, so neither resolves to a symbol any future was
    // extracted under. Both pointers stay mapped, which is what keeps
    // this an unresolved join rather than a read failure.
    let corrupt = Corrupt::new(&snapshot)
        .patch(wide + 8, boxed)
        .patch(boxed, 0)
        .patch(boxed + 24, 0);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let list = tasks_of(&ctx, &snapshot);
    let degraded = census::census(&ctx, &list);

    let (future, depth) = held_row(&degraded, "future1");
    assert_eq!(depth, 0, "{future}");
    assert!(future.starts_with("<unresolved: "), "{future}");
    assert!(future.contains("dyn "), "{future}");
}

/// Two slots naming one future are one row: a find is deduped by the
/// future it stands for, not by the slot standing for it.
///
/// A wide pointer's row *is* the future behind it, so two references
/// to one future — a `Pin<&mut dyn Future>` reborrowed from a local an
/// outer frame still holds — would be two rows for one future in a
/// listing whose three populations are meant not to overlap, and its
/// frames would be scanned twice over. No fixture holds that shape, so
/// it is made here: `unordered`'s driver holds a `set_member`
/// coroutine by value in `held` and a boxed one in `boxed`, and the
/// box's data word is pointed at the by-value one. The vtable is left
/// alone, so the join still resolves to the same `set_member` the
/// by-value local is declared as, which is what makes the two finds
/// name one future rather than one address twice.
#[test]
fn test_a_second_reference_to_one_future_is_not_a_second_row() {
    let (bundle, snapshot) = load_any("unordered");
    let (wide, _) = held_slot(&bundle, &snapshot, "boxed");
    let (by_value, root) = held_slot(&bundle, &snapshot, "held");
    // Held by value: the slot the census found it in is the future it
    // recorded, which is what the alias below points at.
    assert_eq!(by_value, root);

    let (ctx, list) = healthy(&bundle, &snapshot);
    let healthy_census = census::census(&ctx, &list);

    let corrupt = Corrupt::new(&snapshot).patch(wide, root);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let list = tasks_of(&ctx, &snapshot);
    let aliased = census::census(&ctx, &list);

    let rows: Vec<&census::HeldFuture> = aliased.held.iter().filter(|h| h.addr == root).collect();
    assert_eq!(rows.len(), 1, "{:#?}", aliased.held);
    assert!(rows[0].depth > 0, "{:#?}", rows[0]);
    // One row fewer than healthy, and only that one: the census lost
    // the duplicate, not the find.
    assert_eq!(aliased.held.len(), healthy_census.held.len() - 1);
    assert!(aliased.errors.is_empty(), "{:?}", aliased.errors);
    assert!(!aliased.capped.any(), "{:?}", aliased.capped);
}

/// The join set every corruption below is aimed at: the one the
/// driver joins, told apart by its local from the second set it holds
/// and never joins, whose own walk is undamaged and stands as the
/// control.
fn joined_set(census: &census::FutureCensus) -> &census::JoinSet {
    census
        .join_sets
        .iter()
        .find(|set| set.local == "set")
        .unwrap_or_else(|| {
            panic!(
                "expected the driver's joined set, got {:#?}",
                census.join_sets
            )
        })
}

/// The join set's entry list, walked healthy, so a corruption can be
/// aimed at one of its entries: the entry addresses in walk order and
/// the length the set keeps for itself.
fn join_set_entries(bundle: &Bundle, snapshot: &Snapshot) -> (Vec<u64>, u64) {
    let ctx = Context::new(snapshot, BundleView::new(bundle)).expect("snapshot has mappings");
    let list = tasks_of(&ctx, snapshot);
    let census = census::census(&ctx, &list);
    let set = joined_set(&census);
    (set.children.iter().map(|c| c.entry).collect(), set.length)
}

/// An unreadable join set entry stops the walk where it stands. The
/// members before it are kept, the error says the list is short, and
/// the set's own length — read before the walk — stands beside the
/// short list, so the disagreement is visible in the listing and not
/// only in the error.
#[test]
fn test_an_unreadable_join_set_entry_keeps_the_walked_prefix() {
    let (bundle, snapshot) = load_any("joinset");
    let (entries, length) = join_set_entries(&bundle, &snapshot);
    let [first, second, _] = entries.as_slice() else {
        panic!("the fixture set holds three tasks");
    };

    let corrupt = Corrupt::new(&snapshot).deny(*second..*second + 0x10);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let list = tasks_of(&ctx, &snapshot);
    let degraded = census::census(&ctx, &list);

    let set = joined_set(&degraded);
    assert_eq!(set.children.len(), 1, "{:#?}", set.children);
    assert_eq!(set.children[0].entry, *first);
    assert_eq!(set.length, length, "the length is read before the walk");

    assert_eq!(degraded.errors.len(), 1, "{:?}", degraded.errors);
    let err = format!("{:#}", degraded.errors[0]);
    assert!(err.contains("lists only 1 of its tasks"), "{err}");
    assert!(err.contains(&format!("{second:#x}")), "{err}");
}

/// An entry list bent back onto an entry already walked trips the
/// cycle guard, with the prefix kept the same way. Whichever of the
/// two lists the bent link is in, the walk stops there: a failure ends
/// the whole walk, not just the list it happened in.
#[test]
fn test_a_join_set_entry_cycle_is_bounded() {
    let (bundle, snapshot) = load_any("joinset");
    let (entries, length) = join_set_entries(&bundle, &snapshot);
    let [first, _, third] = entries.as_slice() else {
        panic!("the fixture set holds three tasks");
    };

    // Every pointer to the third entry now names the first, which the
    // walk has already seen by the time it reaches it.
    let corrupt = Corrupt::new(&snapshot).patch_words_equal(*third, *first);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let list = tasks_of(&ctx, &snapshot);
    let degraded = census::census(&ctx, &list);

    let set = joined_set(&degraded);
    assert_eq!(set.children.len(), 2, "{:#?}", set.children);
    assert_eq!(set.length, length);
    let err = format!("{:#}", degraded.errors[0]);
    assert!(
        err.contains(&format!("join set entry cycle at {first:#x}")),
        "{err}"
    );
}

/// An entry pointer into unmapped memory is refused by the address
/// check before anything reads through it. Corrupting the first entry
/// leaves the set listing no members at all, against a length that
/// still says three.
#[test]
fn test_an_unmapped_join_set_entry_is_reported() {
    let (bundle, snapshot) = load_any("joinset");
    let (entries, length) = join_set_entries(&bundle, &snapshot);
    let first = entries[0];

    let corrupt = Corrupt::new(&snapshot).patch_words_equal(first, NOWHERE);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let list = tasks_of(&ctx, &snapshot);
    let degraded = census::census(&ctx, &list);

    let set = joined_set(&degraded);
    assert!(set.children.is_empty(), "{:#?}", set.children);
    assert_eq!(set.length, length);
    let err = format!("{:#}", degraded.errors[0]);
    assert!(
        err.contains(&format!("join set entry pointer {NOWHERE:#x} is unmapped")),
        "{err}"
    );
    assert!(err.contains("lists only 0 of its tasks"), "{err}");
}

/// A set child the set has finished with — its `Option<Fut>` slot
/// reaped to `None` — is a row the walk keeps rather than a failure it
/// reports: the node is still in the list and still counted, with
/// nothing to say about a future that is no longer there. Nothing
/// descends into it either, so the set that child was holding goes
/// with it.
///
/// No real capture holds one: reaping needs a child that completed and
/// a set that has not yet dropped its node, which nothing here can
/// arrange to be true at the instant of the core. So the slot is
/// reaped here instead — the tag written to the value the bundle says
/// means `None`, which is as much of a completed child as the walk
/// ever sees.
#[test]
fn test_a_reaped_set_slot_lists_without_a_future() {
    let (bundle, snapshot) = load_any("unordered");
    let (ctx, list) = healthy(&bundle, &snapshot);
    let baseline = census::census(&ctx, &list);

    // The child holding a set of its own, so that what the reaping
    // costs the census — a whole find, not just this row — is visible.
    let [set, inner] = baseline.sets.as_slice() else {
        panic!("expected two sets, got {:#?}", baseline.sets);
    };
    let Some(census::Via::SetChild { child, .. }) = inner.via else {
        panic!("the nested set was not reached through a child: {inner:#?}");
    };
    let root = set.children[child].root.expect("a decoded child");

    // `Task.future` is an `UnsafeCell<Option<Fut>>` and the census
    // reports the payload's address, so the tag the walk decodes sits a
    // payload offset back from it — and what to write there is the
    // value the bundle records for `None`.
    let view = BundleView::new(&bundle);
    let slot = (0..bundle.types.types.len() as u32)
        .filter_map(|i| view.ty(BundleTypeId(i)))
        .find(|ty| ty.name() == "core::option::Option<unordered::set_member::{async_fn_env#0}>")
        .expect("the set holds one slot per child");
    let shape = slot.variant_shape().expect("the slot is an enum");
    let discr = shape.discr.as_ref().expect("the slot carries a tag");
    let some = slot
        .variants()
        .find(|variant| variant.name == "Some")
        .expect("the slot has a Some");
    let none = shape
        .variants
        .iter()
        .zip(slot.variants())
        .find(|(_, variant)| variant.name == "None")
        .and_then(|(def, _)| match def.discr_values.as_ref()?.0.as_slice() {
            [DiscrValue::Value(v)] => Some(*v as u64),
            other => panic!("None is selected by {other:?}"),
        })
        .expect("the slot has a None with a tag of its own");
    // The future the census reports is a member of the `Some` payload,
    // which is itself at an offset in the enum, so the tag is both of
    // those back from it.
    let held = some
        .ty
        .members()
        .next()
        .expect("Some carries the future")
        .offset();
    let base = root.addr - some.offset - held;
    let corrupt = Corrupt::new(&snapshot).patch(base + discr.offset, none);
    let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
    let degraded = census::census(&ctx, &list);

    // The reaped child is still a node the set lists, and says nothing
    // about a future rather than guessing at one.
    assert!(degraded.errors.is_empty(), "{:?}", degraded.errors);
    let [degraded_set] = degraded.sets.as_slice() else {
        panic!("the nested set outlived its holder: {:#?}", degraded.sets);
    };
    assert_eq!(degraded_set.children.len(), set.children.len());
    let reaped = &degraded_set.children[child];
    assert_eq!(reaped.node, set.children[child].node);
    assert_eq!(reaped.future, None, "{reaped:#?}");
    assert_eq!(reaped.root.map(|r| r.addr), None, "{reaped:#?}");
    assert_eq!(reaped.depth, 0, "{reaped:#?}");
    assert_eq!(reaped.state, None, "{reaped:#?}");
    assert_eq!(reaped.leaf, None, "{reaped:#?}");

    // Its neighbours are untouched, and only what the reaped child was
    // holding is gone: the future it held along with the set.
    for (i, other) in degraded_set.children.iter().enumerate() {
        if i != child {
            assert_eq!(other.future, set.children[i].future, "{other:#?}");
        }
    }
    assert_eq!(degraded.held.len(), baseline.held.len() - 1);
}

/// A set node chain bent into a loop trips the node cycle guard, with
/// the prefix kept the same way.
#[test]
fn test_a_set_node_cycle_is_bounded() {
    let (bundle, snapshot) = load_any("unordered");
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

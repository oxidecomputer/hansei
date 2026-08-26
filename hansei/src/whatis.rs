//! The `whatis` command: what an address is, outermost first.

use crate::Session;
use crate::tasks::{future_name, task_id, task_label};

use anyhow::Result;
use hansei_bundle::BundleView;
use hansei_bundle::names;
use hansei_runtime::heap::umem::{Allocation, Size};
use hansei_runtime::tokio::{bundle, census};

use std::io;

pub(crate) fn exec_whatis(session: &Session<'_>, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    report_whatis(
        &session.ctx.view,
        &session.runtimes,
        &session.local_sets,
        &session.tasks,
        session.extents(),
        session.census(),
        session
            .umem()
            .and_then(|heap| heap.allocation(session.proc(), addr)),
        region_of(session, addr),
        vtable_at(session.proc, addr).as_ref(),
        &session.impl_fold,
        addr,
        out,
    )
}

/// How the mapping holding `addr` is spelled, or `None` where nothing
/// maps it.
///
/// The register annotations classify a value against the task extents
/// and the stacks as well; this asks only what kind of memory it is,
/// because everything more specific is a block of its own above.
fn region_of(session: &Session<'_>, addr: u64) -> Option<String> {
    let mapping = session.ctx.mappings.get(addr)?;
    Some(match &mapping.path {
        Some(path) => {
            let base = path.rsplit('/').next().unwrap_or(path);
            format!("{base} {}", mapping.region())
        }
        None if mapping.is_heap() => "the heap".to_string(),
        None => match session
            .lwps
            .iter()
            .find(|l| !l.altstack.is_empty() && l.altstack.contains(&addr))
        {
            Some(lwp) => format!("lwp {}'s alternate signal stack", lwp.tid),
            None => match session.lwps.iter().find(|l| l.stack_range.contains(&addr)) {
                Some(lwp) => format!("lwp {}'s stack", lwp.tid),
                None => "anonymous memory".to_string(),
            },
        },
    })
}

/// What a static vtable holds, populated only when the memory at `addr`
/// proves to be one.
pub(crate) struct VtableAt {
    /// The erased concrete type the vtable dispatches for.
    concrete: String,
    /// The drop function's demangled symbol — the join's evidence.
    drop_symbol: String,
    size: u64,
    align: u64,
}

/// Read the memory at `addr` as a Rust vtable, believed only on the
/// join that cannot be coincidence: the first slot must resolve to a
/// `drop_in_place`/`drop_glue` function symbol, whose generic argument
/// names the erased concrete type — the same join `print` uses to name
/// a trait object, so it works even where the vtable static itself has
/// no symbol, as a stripped binary's does not. The size and align
/// words ride along once that holds; an align that is not a nonzero
/// power of two says this is not a vtable after all.
fn vtable_at<T: proc::Target>(proc: &T, addr: u64) -> Option<VtableAt> {
    let drop_fn = proc.read_u64(addr).ok()?;
    if drop_fn == 0 {
        return None;
    }
    let size = proc.read_u64(addr + 8).ok()?;
    let align = proc.read_u64(addr + 16).ok()?;
    if !align.is_power_of_two() {
        return None;
    }
    let symbol = proc.lookup_symbol_by_addr(drop_fn)?;
    let stripped = hansei_bundle::strip_llvm_suffix(&symbol.name);
    let demangled = rustc_demangle::try_demangle(stripped).ok()?;
    let drop_symbol = format!("{demangled:#}");
    let concrete =
        hansei_bundle::symbols::concrete_type_from_vtable_symbol(&drop_symbol)?.to_string();
    Some(VtableAt {
        concrete,
        drop_symbol,
        size,
        align,
    })
}

/// The `whatis` answer, apart from the session so the offline fixture
/// tests can drive it.
///
/// An address belongs to whatever contains it, and those things nest:
/// a held future lives in a frame of its task's allocation, a set in a
/// frame of whatever drives it, a set child in a heap node of its own.
/// So this reports every claim rather than the first one it finds, in
/// containment order — the task's allocation, then a set child's node,
/// then the held futures from widest to narrowest, then a set — which
/// makes reading down the report reading inward.
///
/// The executors come first, outside that nesting rather than at the
/// top of it: a runtime handle contains no task's memory and no task's
/// memory contains it, but it is the coarsest thing an address can be,
/// and the one a reader is least able to recognize by eye.
///
/// Ahead of all of it is what the target's own allocator says the
/// memory is, where it keeps an account worth reading: every block
/// below interprets those bytes, and whether they are still the ones
/// somebody wrote decides how much any of it is worth.
#[allow(clippy::too_many_arguments)]
fn report_whatis(
    view: &BundleView<'_>,
    runtimes: &[bundle::RuntimeRef<'_>],
    local_sets: &[bundle::LocalSetRef<'_>],
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &census::FutureCensus,
    alloc: Option<Allocation>,
    // What kind of mapping holds the address, spelled — the answer
    // of last resort, for an address nothing else claims.
    region: Option<String>,
    vtable: Option<&VtableAt>,
    impls: &names::ImplFold,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut blocks = 0;
    let owned = |group: usize| list.tasks.iter().filter(|t| t.group == group).count();

    // The allocation, in the terms the allocation has rather than the
    // allocator's: which cache a block came from is a fact about
    // libumem, and a line naming one is a line that trains people to
    // skip the block. `umem-audit` is where that belongs.
    if let Some(alloc) = alloc {
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "Status: {}",
            match alloc.live {
                true => "live",
                false => "freed",
            }
        )?;
        // The two sizes are different claims, so they are worded as
        // two: bare is what the program asked for, and `block` is the
        // block it sits in — the allocator's own number, rounded to a
        // size class and carrying the header — which is all a scrubbed
        // header leaves to measure.
        match alloc.size {
            Size::Requested(size) => writeln!(out, "Size:   {}", bytes(size))?,
            Size::Block(size) => writeln!(out, "Size:   {size} byte block")?,
        }
        // Zero is the pointer the program was given, so the line would
        // be saying nothing; its presence is what marks an address as
        // an interior one. What it counts from is whichever of the two
        // the size line just named, and it says which: they start 8 or
        // 16 bytes apart, so an offset naming neither would be
        // ambiguous by exactly a header.
        if alloc.offset > 0 {
            let whole = match alloc.size {
                Size::Requested(_) => "allocation",
                Size::Block(_) => "block",
            };
            writeln!(out, "Offset: +{} in {whole}", alloc.offset)?;
        }
    }

    // Every block below interprets the address, which the one above
    // does not: a live allocation nothing in the report claims is
    // still a miss, and says so.
    let uninterpreted = blocks;

    for (index, rt) in runtimes.iter().enumerate() {
        let Some(offset) = within(rt.handle.addr, rt.handle.ty.size(), addr) else {
            continue;
        };
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "{}: {}",
            capitalized(&crate::runtimes::runtime_label(index, rt)),
            rt.flavor
        )?;
        writeln!(out, "    At: offset {offset:#x} in the runtime's handle")?;
        let threads = match rt.worker_tids.is_empty() {
            true => "none inside it".to_string(),
            false => {
                let tids: Vec<String> = rt.worker_tids.iter().map(|t| t.to_string()).collect();
                format!("lwp {}", tids.join(", "))
            }
        };
        writeln!(out, "    Threads: {threads}")?;
        writeln!(out, "    Found via: {}", rt.route)?;
        writeln!(out, "    Tasks: {}", owned(index))?;
    }

    for (index, set) in local_sets.iter().enumerate() {
        let Some(offset) = within(set.shared.addr, set.shared.ty.size(), addr) else {
            continue;
        };
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "{}:",
            capitalized(&crate::runtimes::local_set_label(index, set))
        )?;
        writeln!(out, "    At: offset {offset:#x} in the set's shared state")?;
        let pinned = match set.owner_tid {
            Some(tid) => format!("lwp {tid}"),
            None => "no thread hansei can name".to_string(),
        };
        writeln!(out, "    Pinned to: {pinned}")?;
        writeln!(out, "    Found via: {}", set.route)?;
        writeln!(out, "    Tasks: {}", owned(runtimes.len() + index))?;
    }

    // A vtable is a static, outside every allocation the blocks below
    // nest through — the coarse answer for the second word of a trait
    // object, which is the pointer a reader most often has in hand.
    if let Some(vtable) = vtable {
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "Vtable {addr:#x}: erases {}",
            names::fold_type_name(&vtable.concrete, impls)
        )?;
        writeln!(out, "    Drop: {}", vtable.drop_symbol)?;
        writeln!(
            out,
            "    Erased size: {} bytes, align {}",
            vtable.size, vtable.align
        )?;
    }

    if let Some((index, offset)) = extents.locate(addr) {
        let task = &list.tasks[index];
        let id = task_id(list, index);
        separate(&mut blocks, out)?;
        writeln!(out, "Task {id}: {}", future_name(&task.future, impls))?;
        writeln!(
            out,
            "    At: offset {offset:#x} in the task's allocation (header {:?})",
            task.addr
        )?;
        writeln!(out, "    State: {}", task.state.lifecycle())?;
        if let Some(loc) = &task.spawn_location {
            writeln!(out, "    Spawned at: {loc}")?;
        }
    }

    // A set child's node is its own heap allocation, outside every
    // task's — but the task that polls the set is what a wake there
    // ultimately runs, so the block names it.
    if let Some((set_index, child_index, offset)) = census.locate(addr) {
        let set = &census.sets[set_index];
        let child = &set.children[child_index];
        separate(&mut blocks, out)?;
        let future = match &child.future {
            Some(future) => names::display_future_name(future, impls),
            None => "<completed, not yet reaped>".to_string(),
        };
        writeln!(out, "Future {:#x}: {future}", child.node)?;
        writeln!(
            out,
            "    At: offset {offset:#x} in a FuturesUnordered child node"
        )?;
        if let Some(state) = &child.state {
            writeln!(out, "    State: {state}")?;
        }
        if let Some(waiting) = &child.waiting_on {
            writeln!(out, "    Waiting on: {waiting}")?;
        }
        writeln!(
            out,
            "    Child of: {} at {:#x} (frame {}, `{}`{})",
            names::fold_type_name(&set.ty, impls),
            set.addr,
            set.frame,
            set.local,
            via_suffix(census, set.via)
        )?;
        writeln!(
            out,
            "    Polled by: {} — {}",
            task_label(list, set.owner),
            future_name(&list.tasks[set.owner].future, impls)
        )?;
    }

    // Widest first: a future awaited by value sits inside the one
    // awaiting it, so an interior address is claimed by each of them
    // and the narrowest is the future the address is really in.
    let mut held: Vec<(u64, &census::HeldFuture)> = census
        .held
        .iter()
        .filter_map(|h| {
            // A size the bundle does not carry leaves the future's own
            // address, which is what a reader pastes in anyway.
            let size = view.ty(h.ty).map_or(0, |ty| ty.size());
            let extent = h.addr..h.addr.saturating_add(size);
            (h.addr == addr || extent.contains(&addr)).then_some((size, h))
        })
        .collect();
    held.sort_by_key(|&(size, h)| (std::cmp::Reverse(size), h.addr));
    for (_, h) in held {
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "Future {:#x}: {}",
            h.addr,
            names::display_future_name(&h.future, impls)
        )?;
        writeln!(out, "    At: offset {:#x} in the future", addr - h.addr)?;
        if let Some(state) = &h.state {
            writeln!(out, "    State: {state}")?;
        }
        if let Some(waiting) = &h.waiting_on {
            writeln!(out, "    Waiting on: {waiting}")?;
        }
        writeln!(
            out,
            "    Held by: {} — {} (frame {}, `{}`{})",
            task_label(list, h.owner),
            future_name(&list.tasks[h.owner].future, impls),
            h.frame,
            h.local,
            via_suffix(census, h.via)
        )?;
    }

    // A set is claimed by its own address alone: the census records
    // where one starts but not how long it is, so an address inside one
    // is reported as whatever frame holds it instead.
    for set in census.sets.iter().filter(|s| s.addr == addr) {
        separate(&mut blocks, out)?;
        let live = set.children.iter().filter(|c| c.future.is_some()).count();
        let reaped = match set.children.len() - live {
            0 => String::new(),
            n => format!(", {n} completed and not yet reaped"),
        };
        writeln!(
            out,
            "Set {addr:#x}: {}",
            names::fold_type_name(&set.ty, impls)
        )?;
        writeln!(out, "    Children: {live} in flight{reaped}")?;
        writeln!(
            out,
            "    Driven by: {} — {} (frame {}, `{}`{})",
            task_label(list, set.owner),
            future_name(&list.tasks[set.owner].future, impls),
            set.frame,
            set.local,
            via_suffix(census, set.via)
        )?;
    }

    if blocks == uninterpreted {
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "no task's allocation and no future the census found contains {addr:#x}"
        )?;
        // Nothing above interpreted the address, so the coarsest fact
        // there is — which mapping holds it — is the whole answer
        // rather than a footnote to one. This is the vocabulary
        // `pmap` answers in, and for the same reason: naming every
        // anonymous mapping "heap" would be a false claim about all
        // but one of them.
        if let Some(region) = region {
            writeln!(out, "It is in {region}.")?;
        }
    }
    Ok(())
}

/// A byte count with its unit, singular where that is what one is.
fn bytes(count: u64) -> String {
    match count {
        1 => "1 byte".to_string(),
        count => format!("{count} bytes"),
    }
}

/// A group's label as a block heading: the listings spell it in
/// running prose, and every other heading here leads with a capital.
fn capitalized(label: &str) -> String {
    let mut chars = label.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Where `addr` falls in an object of `size` bytes at `start`, or
/// `None` when it falls outside it. A zero size claims the start
/// address alone: a type the bundle carries no size for still has an
/// address worth recognizing, and it is the one a reader pastes in.
fn within(start: u64, size: u64, addr: u64) -> Option<u64> {
    let end = start.saturating_add(size.max(1));
    (start..end).contains(&addr).then(|| addr - start)
}

/// Open a block, with a blank line between it and the one before.
fn separate(blocks: &mut usize, out: &mut dyn io::Write) -> Result<()> {
    if *blocks > 0 {
        writeln!(out)?;
    }
    *blocks += 1;
    Ok(())
}

/// How the census reached a find, for the line that says where it
/// lives: empty when it was found in a task's own frames, and naming
/// the future or set child whose frames it was found in otherwise.
pub(crate) fn via_suffix(census: &census::FutureCensus, via: Option<census::Via>) -> String {
    via.map(|v| format!(", via {}", census.describe(v)))
        .unwrap_or_default()
}

/// Offline `whatis` tests: what an address resolves to over a real
/// extracted bundle joined against a real captured snapshot.
#[cfg(test)]
mod whatis_tests {
    use super::{Allocation, Size, VtableAt, report_whatis, separate, vtable_at};
    use crate::parse_hex_addr;
    use hansei_bundle::BundleView;
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::bundle::{LocalSetRef, RuntimeRef, TaskExtents, TaskList};
    use hansei_runtime::tokio::census::{self, FutureCensus};

    /// Everything a report is made from: the whole of what an attach
    /// finds, so a test can point at any of it.
    struct Target<'a> {
        view: BundleView<'a>,
        runtimes: Vec<RuntimeRef<'a>>,
        local_sets: Vec<LocalSetRef<'a>>,
        list: TaskList,
        extents: TaskExtents,
        census: FutureCensus,
    }

    fn with_tasks(program: &str, check: impl FnOnce(&Target<'_>)) {
        let (bundle, snapshot) = testkit::load_any(program);
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        check(&Target {
            view: ctx.view,
            runtimes,
            local_sets,
            list,
            extents,
            census,
        });
    }

    fn report(target: &Target<'_>, addr: u64) -> String {
        reported(target, None, None, None, addr)
    }

    /// The report over everything an attach can hand it, including the
    /// two probes a fixture cannot supply: the checked-in snapshots
    /// were captured under a plain malloc and hold no vtable this test
    /// knows the address of, so both are staged rather than found.
    fn reported(
        target: &Target<'_>,
        alloc: Option<Allocation>,
        region: Option<&str>,
        vtable: Option<&VtableAt>,
        addr: u64,
    ) -> String {
        let mut out = Vec::new();
        report_whatis(
            &target.view,
            &target.runtimes,
            &target.local_sets,
            &target.list,
            &target.extents,
            &target.census,
            alloc,
            region.map(str::to_owned),
            vtable,
            &hansei_bundle::names::ImplFold::default(),
            addr,
            &mut out,
        )
        .expect("the report renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// A vtable block names what the vtable erases, the drop symbol
    /// that proved it, and the erased layout — and counts as an
    /// answer, so the miss line stays away.
    #[test]
    fn test_a_vtable_reports_what_it_erases() {
        with_tasks("sleep-join", |target| {
            let vtable = VtableAt {
                concrete: "app::Thing<u64>".to_string(),
                drop_symbol: "core::ptr::drop_glue::<app::Thing<u64>>".to_string(),
                size: 48,
                align: 8,
            };
            let out = reported(target, None, None, Some(&vtable), 0x9000_0000);
            assert!(
                out.contains("Vtable 0x90000000: erases app::Thing<u64>"),
                "{out}"
            );
            assert!(
                out.contains("Drop: core::ptr::drop_glue::<app::Thing<u64>>"),
                "{out}"
            );
            assert!(out.contains("Erased size: 48 bytes, align 8"), "{out}");
            assert!(!out.contains("no task's allocation"), "{out}");
        });
    }

    /// A fake serving three vtable words and one function symbol, for
    /// driving the probe's joins without a core.
    struct VtableMem {
        words: Vec<u8>,
        symbol: Option<(u64, String)>,
    }

    impl proc::Target for VtableMem {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            let start = addr
                .checked_sub(0x1000)
                .filter(|&s| s + len <= self.words.len() as u64)
                .ok_or_else(|| proc::Error::unmapped(addr, len))?;
            Ok(&self.words[start as usize..(start + len) as usize])
        }
        fn lookup_symbol_by_addr(&self, addr: u64) -> Option<proc::SymbolBuf> {
            let (at, name) = self.symbol.as_ref()?;
            (*at == addr).then(|| proc::SymbolBuf {
                name: name.clone(),
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: addr,
                st_size: 8,
            })
        }
        fn lookup_symbol_by_name(&self, _: &str) -> Option<proc::SymbolBuf> {
            None
        }
        fn symbols(&self) -> proc::Result<Vec<proc::SymbolBuf>> {
            Ok(Vec::new())
        }
        fn mappings(&self) -> proc::Result<proc::Mappings> {
            Ok(proc::Mappings::from_iter([]))
        }
        fn lwps(&self) -> proc::Result<Vec<proc::LwpInfo>> {
            Ok(Vec::new())
        }
        fn tls_var_addr(&self, _: &proc::Regs, _: &proc::SymbolBuf) -> proc::Result<Option<u64>> {
            Ok(None)
        }
    }

    /// The probe believes only the full join: a drop-glue symbol
    /// behind the first slot and a plausible align word. A slot
    /// resolving to no symbol, to a symbol that is not drop glue, or
    /// riding an align that is no power of two proves nothing.
    #[test]
    fn test_the_vtable_probe_requires_the_drop_glue_join() {
        // A genuine v0-mangled drop-glue monomorphization, lifted from
        // a real symtab, demangling to
        // `core::ptr::drop_glue::<[reedline::enums::EditCommand; 1]>`.
        const DROP: &str = "_RINvNtCs4gTh5wWLWvJ_4core3ptr9drop_glueANtNtCs1dINKnBl13J_8reedline5enums11EditCommandj1_EBG_";
        let mem = |drop_fn: u64, align: u64, symbol: Option<(u64, &str)>| VtableMem {
            words: [drop_fn, 48, align]
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect(),
            symbol: symbol.map(|(at, name)| (at, name.to_string())),
        };

        let found = vtable_at(&mem(0x5000, 8, Some((0x5000, DROP))), 0x1000)
            .expect("the full join is believed");
        assert_eq!(found.concrete, "[reedline::enums::EditCommand; 1]");
        assert_eq!((found.size, found.align), (48, 8));

        assert!(vtable_at(&mem(0x5000, 8, None), 0x1000).is_none());
        assert!(vtable_at(&mem(0x5000, 8, Some((0x5000, "malloc"))), 0x1000).is_none());
        assert!(vtable_at(&mem(0x5000, 7, Some((0x5000, DROP))), 0x1000).is_none());
        assert!(vtable_at(&mem(0, 8, Some((0x5000, DROP))), 0x1000).is_none());
        // Unreadable memory is no vtable either.
        assert!(vtable_at(&mem(0x5000, 8, Some((0x5000, DROP))), 0x9999).is_none());
    }

    /// What the allocator says leads the report, in the allocation's
    /// own terms: whether the block is still handed out, how big it is,
    /// and — only where the address is not the pointer the program was
    /// given — how far into it the address sits.
    #[test]
    fn test_the_allocation_leads_with_status_size_and_offset() {
        with_tasks("sleep-join", |t| {
            let alloc = |live, size, offset| Some(Allocation { live, size, offset });
            let task = t.list.tasks[0].addr.0;

            // The pointer the program was given: three facts minus the
            // offset, whose absence is what says the address is the
            // allocation rather than somewhere inside it.
            let shown = reported(t, alloc(true, Size::Requested(300), 0), None, None, task);
            assert!(
                shown.starts_with("Status: live\nSize:   300 bytes\n\n"),
                "{shown}"
            );
            assert!(!shown.contains("Offset:"), "{shown}");
            // And the report goes on to say what the memory holds.
            assert!(
                shown.contains("    At: offset 0x0 in the task's allocation"),
                "{shown}"
            );

            // A freed block: `free` scrubbed the header, so the block's
            // own size is all there is left to report, and the offset
            // counts from where the block starts — which is what the
            // line says, because the two starts are a header apart.
            let shown = reported(t, alloc(false, Size::Block(64), 16), None, None, task);
            assert!(
                shown.starts_with("Status: freed\nSize:   64 byte block\nOffset: +16 in block\n"),
                "{shown}"
            );

            // The block is about the memory, not about what claims it,
            // so an address nothing in the report claims still reports
            // the miss. An offset into a known allocation counts from
            // the pointer the program was given, and names it.
            let shown = reported(t, alloc(true, Size::Requested(1), 1), None, None, 0x10);
            assert_eq!(
                shown,
                "Status: live\nSize:   1 byte\nOffset: +1 in allocation\n\n\
                 no task's allocation and no future the census found contains 0x10\n"
            );

            // A target whose allocator keeps no account hansei can read
            // — every fixture snapshot, captured under a plain malloc —
            // says nothing rather than "unknown".
            let shown = report(t, task);
            assert!(!shown.contains("Status:"), "{shown}");
            assert!(!shown.contains("Size:"), "{shown}");
        });
    }

    /// The region is the answer of last resort: it speaks only when
    /// nothing above interpreted the address, because everything above
    /// is a more specific claim about the same bytes. An address a
    /// task owns is told what owns it, not which mapping it is in.
    #[test]
    fn test_the_region_answers_only_where_nothing_else_did() {
        with_tasks("sleep-join", |t| {
            let task = t.list.tasks[0].addr.0;
            let claimed = reported(t, None, Some("the heap"), None, task);
            assert!(!claimed.contains("It is in"), "{claimed}");

            // Nothing claims this one, so the mapping is what there is
            // to say — and it is said in pmap's vocabulary rather than
            // called "heap" for being anonymous.
            let loose = reported(t, None, Some("anonymous memory"), None, 0x9999_0000);
            assert!(loose.contains("It is in anonymous memory."), "{loose}");

            // And an address in no mapping at all keeps the bare miss:
            // silence beats inventing a region for it.
            let nowhere = reported(t, None, None, None, 0x9999_0000);
            assert!(nowhere.contains("no task's allocation"), "{nowhere}");
            assert!(!nowhere.contains("It is in"), "{nowhere}");
        });
    }

    /// An address inside a task's allocation — its header, or any
    /// offset short of the trailer's end — names that task; one
    /// outside every allocation reports the miss.
    #[test]
    fn test_addresses_resolve_to_the_containing_task() {
        with_tasks("sleep-join", |t| {
            let sleeper = t
                .list
                .tasks
                .iter()
                .find(|t| t.task_id == Some(3))
                .expect("the sleeper is task 3");
            let header = sleeper.addr.0;

            let shown = report(t, header);
            assert!(
                shown.contains("Task 3: async fn sleep_join::sleeper\n"),
                "{shown}"
            );
            assert!(
                shown.contains(&format!(
                    "    At: offset 0x0 in the task's allocation (header {header:#x})"
                )),
                "{shown}"
            );
            assert!(shown.contains("    State: idle"), "{shown}");

            let inside = report(t, header + 0x10);
            assert!(inside.contains("Task 3: "), "{inside}");
            assert!(
                inside.contains("    At: offset 0x10 in the task's allocation"),
                "{inside}"
            );

            let miss = report(t, 0x10);
            assert_eq!(
                miss,
                "no task's allocation and no future the census found contains 0x10\n"
            );
        });
    }

    /// An address is reported against the futures the census found as
    /// well as against the tasks, and a pointer *into* a future
    /// resolves to it the way one into a task's allocation does. This
    /// future is `.boxed()`, so it is a heap allocation of its own and
    /// no task's allocation claims it — the block naming what holds it
    /// is the only thing that says whose it is.
    #[test]
    fn test_addresses_resolve_to_the_containing_future() {
        with_tasks("futurelock", |t| {
            let future1 = t
                .census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", t.census.held));
            let owner = t.list.tasks[future1.owner]
                .task_id
                .expect("the holder is an owned task");
            let size = t
                .view
                .ty(future1.ty)
                .expect("the bundle carries the held future's type")
                .size();
            assert!(
                size > 0x10,
                "the fixture's future is too small to point into"
            );

            for offset in [0, 0x10] {
                let shown = report(t, future1.addr + offset);
                assert!(
                    shown.contains(&format!(
                        "Future {:#x}: {}",
                        future1.addr,
                        hansei_bundle::names::display_future_name(
                            &future1.future,
                            &hansei_bundle::names::ImplFold::default()
                        )
                    )),
                    "{shown}"
                );
                assert!(
                    shown.contains(&format!("    At: offset {offset:#x} in the future")),
                    "{shown}"
                );
                assert!(
                    shown.contains(&format!("    Held by: task {owner} — ")),
                    "{shown}"
                );
                assert!(shown.contains("(frame 1, `future1`)"), "{shown}");
            }

            // Past its end it is somebody else's memory, and this
            // heap allocation is nobody's as far as hansei can say.
            let past = report(t, future1.addr + size);
            assert!(
                past.starts_with("no task's allocation and no future"),
                "{past}"
            );
        });
    }

    /// The executors answer for their own addresses: the handle a
    /// `runtimes` row prints resolves to that runtime, an address
    /// inside the handle resolves to it the way one inside a task's
    /// allocation does, and a local set's shared state answers for
    /// itself. The fixture holds a runtime no thread is inside, which
    /// is the one whose block has a route to report and no threads.
    #[test]
    fn test_addresses_resolve_to_the_owning_executor() {
        with_tasks("foreign-runtime", |t| {
            let hidden = t
                .runtimes
                .iter()
                .position(|rt| rt.worker_tids.is_empty())
                .expect("the fixture hides a runtime from every thread's context");
            let handle = t.runtimes[hidden].handle.addr;

            let shown = report(t, handle);
            assert!(
                shown.contains(&format!("Runtime {hidden} @{handle:#x}: current_thread")),
                "{shown}"
            );
            assert!(
                shown.contains("    At: offset 0x0 in the runtime's handle"),
                "{shown}"
            );
            assert!(shown.contains("    Threads: none inside it"), "{shown}");
            assert!(
                shown.contains("    Found via: a JoinHandle held by an enumerated task"),
                "{shown}"
            );

            let inside = report(t, handle + 0x8);
            assert!(
                inside.contains(&format!("Runtime {hidden} @{handle:#x}: ")),
                "{inside}"
            );
            assert!(
                inside.contains("    At: offset 0x8 in the runtime's handle"),
                "{inside}"
            );

            let set = t.local_sets.first().expect("the fixture holds a local set");
            let shared = set.shared.addr;
            let shown = report(t, shared);
            assert!(
                shown.contains(&format!("Local set 0 @{shared:#x}:")),
                "{shown}"
            );
            assert!(shown.contains("    Tasks: 1"), "{shown}");
        });
    }

    /// Every task claims its own header and nothing claims the word
    /// before it: the extents tile the tasks without bleeding.
    #[test]
    fn test_extents_cover_each_task_exactly() {
        with_tasks("dyn-future", |t| {
            for (index, task) in t.list.tasks.iter().enumerate() {
                assert_eq!(
                    t.extents.locate(task.addr.0),
                    Some((index, 0)),
                    "task {:?} does not claim its own header",
                    task.addr
                );
                let before = t.extents.locate(task.addr.0 - 1);
                assert_ne!(
                    before.map(|(i, _)| i),
                    Some(index),
                    "task {:?} claims the byte before its header",
                    task.addr
                );
            }
        });
    }

    /// A set's own address names the set, counting the children in
    /// flight and the completed ones not yet reaped — the reaped count
    /// being the empty slots, not the sum of everything.
    #[test]
    fn test_a_sets_children_count_the_reaped() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let extents = ctx.task_extents(&list);
        let mut census = census::census(&ctx, &list);
        let child = |future: Option<&str>| census::SetChild {
            node: 0x2000,
            depth: usize::from(future.is_some()),
            future: future.map(str::to_string),
            root: None,
            state: None,
            waiting_on: None,
            wait: None,
            leaf: None,
        };
        census.sets.push(census::FutureSet {
            owner: 0,
            frame: 0,
            local: "set".to_string(),
            via: None,
            addr: 0xdead_0000,
            ty: "FuturesUnordered<F>".to_string(),
            children: vec![child(Some("f::{async_fn_env#0}")), child(None), child(None)],
        });
        let target = Target {
            view: ctx.view,
            runtimes,
            local_sets,
            list,
            extents,
            census,
        };
        let shown = report(&target, 0xdead_0000);
        assert!(
            shown.contains("Children: 1 in flight, 2 completed and not yet reaped\n"),
            "{shown}"
        );
    }

    /// A find reached through another find says so: the suffix names
    /// the route, and a find in the task's own frames adds nothing.
    #[test]
    fn test_the_via_suffix_names_the_route() {
        let (bundle, snapshot) = testkit::load_any("futurelock");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = census::census(&ctx, &list);
        assert!(!census.held.is_empty(), "the fixture holds a future");

        assert_eq!(super::via_suffix(&census, None), "");
        let via = super::via_suffix(&census, Some(census::Via::Held(0)));
        assert!(via.starts_with(", via "), "{via:?}");
        assert!(via.len() > ", via ".len(), "{via:?}");
    }

    /// Blocks are separated by one blank line between each other: none
    /// before the first, exactly one before each that follows.
    #[test]
    fn test_blocks_separate_only_between_each_other() {
        let mut out = Vec::new();
        let mut blocks = 0;
        separate(&mut blocks, &mut out).expect("separate writes");
        assert_eq!(out, b"", "a leading blank line before the first block");
        separate(&mut blocks, &mut out).expect("separate writes");
        assert_eq!(out, b"\n", "one blank line between two blocks");
        assert_eq!(blocks, 2);
    }

    /// The `0x` prefix is required, and the digits behind it parse as
    /// hex — the contract the command's help text states.
    #[test]
    fn test_addresses_parse_only_with_a_0x_prefix() {
        assert_eq!(parse_hex_addr("0x7fffb1c26100"), Ok(0x7fffb1c26100));
        assert_eq!(parse_hex_addr("0XFF"), Ok(0xff));
        assert!(parse_hex_addr("7fffb1c26100").is_err());
        assert!(parse_hex_addr("42").is_err());
        assert!(parse_hex_addr("0x").is_err());
        assert!(parse_hex_addr("0xzz").is_err());
    }
}

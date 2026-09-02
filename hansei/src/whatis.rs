//! The `whatis` command: what an address is, outermost first.

use crate::Session;
use crate::tasks::{future_name, task_id, task_label};
use crate::vtables::{Image, Placement, Standing};

use anyhow::Result;
use hansei_bundle::BundleView;
use hansei_bundle::{VtableEntry, names};
use hansei_runtime::heap::umem::{Allocation, Size};
use hansei_runtime::tokio::{bundle, census};

use std::io;

pub(crate) fn exec_whatis<T: proc::Target>(
    session: &Session<'_, T>,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let image = Image::of(session);
    let vtable = vtable_at(&session.ctx.view, &image, addr);
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
        vtable.as_ref(),
        &session.impl_fold,
        addr,
        out,
    )
}

/// How the mapping holding `addr` is spelled, or `None` where nothing
/// maps it.
///
/// The anonymous kinds are spelled exactly as `pmap` spells them —
/// `[ anon ]`, `[ heap ]`, `[ stack tid=N ]`, `[ altstack tid=N ]` —
/// so the answer can be matched by eye against the mapping table
/// someone debugging a core already has open. A file-backed mapping
/// gets its object and region instead, which is the more useful thing
/// to say and what the register annotations say of the same address.
///
/// The register annotations classify a value against the task extents
/// and the stacks as well; this asks only what kind of memory it is,
/// because everything more specific is a block of its own above.
fn region_of<T: proc::Target>(session: &Session<'_, T>, addr: u64) -> Option<String> {
    let mapping = session.ctx.mappings.get(addr)?;
    Some(match &mapping.path {
        Some(path) => {
            let base = path.rsplit('/').next().unwrap_or(path);
            format!("{base} {}", mapping.region())
        }
        None if mapping.is_heap() => "[ heap ]".to_string(),
        None => match session
            .lwps
            .iter()
            .find(|l| !l.altstack.is_empty() && l.altstack.contains(&addr))
        {
            Some(lwp) => format!("[ altstack tid={} ]", lwp.tid),
            None => match session.lwps.iter().find(|l| l.stack_range.contains(&addr)) {
                Some(lwp) => format!("[ stack tid={} ]", lwp.tid),
                None => "[ anon ]".to_string(),
            },
        },
    })
}

/// What a static vtable at an address is, by whichever of the two
/// routes could say — the table rustc's debug info recorded, and the
/// shape of the memory itself.
pub(crate) struct VtableAt {
    /// The erased concrete type the vtable dispatches for.
    concrete: String,
    /// The trait it dispatches, which only the recorded table names:
    /// a vtable's memory holds no trace of which trait it is for.
    trait_: Option<String>,
    /// Other `<Concrete as Trait>` pairs the table records at this same
    /// address — identical vtables the linker folded into one.
    folded: Vec<String>,
    /// The drop function's demangled symbol — the memory route's
    /// evidence, absent where no symbol resolved.
    drop_symbol: Option<String>,
    /// The erased type's size and alignment, out of the vtable's own
    /// header words.
    layout: Option<(u64, u64)>,
    /// What reading the address proved about the recorded entry, where
    /// one was believed. `None` where the memory answered alone — the
    /// drop-glue join is that route's own gate.
    standing: Option<Standing>,
}

/// What the memory at an address says it is, on its own.
struct FromMemory {
    concrete: String,
    drop_symbol: String,
    size: u64,
    align: u64,
}

/// What is at `addr`, by the two routes that can say.
///
/// The bundle carries the table rustc recorded — every `<Concrete as
/// Trait>` pair it instantiated, and where the vtable was linked — so
/// an address that unbiases to one of those is named outright, the
/// trait included, which no amount of reading the memory could yield.
/// That route needs no symbols, which is what keeps it answering on a
/// stripped target.
///
/// The memory route is the other, and the only one for a vtable
/// nothing recorded: read the words and believe them on the join that
/// cannot be coincidence — the first slot resolving to a
/// `drop_in_place`/`drop_glue` symbol whose generic argument names the
/// erased type, the same join `print` uses to name a trait object. The
/// size and align words ride along once that holds; an align that is
/// not a power of two says this is not a vtable after all.
///
/// Both routes are about the same bytes, so they make one block: the
/// recorded pair names the types, in the debug info's own spelling
/// rather than the mangler's, and the memory supplies the drop symbol
/// and the erased layout.
///
/// Which is to say the table is believed only where the memory does
/// not contradict it. `vtables` marks a contradicted entry and prints
/// it, because there it is the answer to the question asked; here the
/// question is about an arbitrary address, so an entry the words at it
/// deny is dropped outright rather than offered as a lead. That is
/// every entry, everywhere, when the tokio info came from a build this
/// target did not run — the addresses are fiction and the memory says
/// so. An address the target holds no word of is the case neither can
/// settle: the recorded pair is all there is, and it is marked.
fn vtable_at(view: &BundleView<'_>, image: &Image<'_>, addr: u64) -> Option<VtableAt> {
    let memory = from_memory(image, addr);
    let recorded = recorded_at(view, image, addr);
    let names = |entry: &VtableEntry| Some((view.str(entry.concrete)?, view.str(entry.trait_)?));
    let believed = recorded.first().and_then(|entry| {
        let words = image.words(addr, entry.slot_count);
        let standing = Standing::of(image, entry, &words);
        let (concrete, trait_) = names(entry)?;
        (standing != Standing::Unverified)
            .then(|| (concrete.to_string(), trait_.to_string(), standing))
    });

    let (concrete, trait_, standing) = match believed {
        Some((concrete, trait_, standing)) => (concrete, Some(trait_), Some(standing)),
        None => (memory.as_ref()?.concrete.clone(), None, None),
    };
    Some(VtableAt {
        concrete,
        trait_,
        folded: match standing {
            None => Vec::new(),
            Some(_) => recorded
                .iter()
                .skip(1)
                .filter_map(|entry| names(entry).map(|(c, t)| format!("{c} as {t}")))
                .collect(),
        },
        drop_symbol: memory.as_ref().map(|m| m.drop_symbol.clone()),
        layout: memory.map(|m| (m.size, m.align)),
        standing,
    })
}

/// The pairs the bundle's table has for `addr`, by whichever of the two
/// routes to the table this target allows.
///
/// Where the recorded addresses are this target's, the lookup is by
/// address: unbias `addr` to the one the vtable was linked at and take
/// the entries recorded there. Several is legal — identical vtables the
/// linker folded share an address, and the table keeps every name it
/// recorded for them. None where the target cannot say where its
/// executable landed, since then there is no link-time address to ask
/// by.
///
/// Where they are some other build's, an address hit would be a
/// coincidence between two layouts rather than a fact about this one,
/// so the lookup is by *content* instead: read the words here and take
/// the pair the first method slot's symbol names, which is
/// [`vtables::identify`] — the same join the listing's sweep makes,
/// made at one address. That is what keeps `whatis` able to name an
/// address the listing just printed.
///
/// [`vtables::identify`]: crate::vtables
fn recorded_at<'a>(view: &BundleView<'a>, image: &Image<'_>, addr: u64) -> Vec<&'a VtableEntry> {
    let entries = &view.bundle().vtables.entries;
    if !Placement::of(image, entries).applies() {
        return crate::vtables::identify_at(image, view, addr)
            .map(|index| &entries[index])
            .into_iter()
            .collect();
    }
    let Some(linked) = image.unbias(addr) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|entry| entry.address == linked)
        .collect()
}

/// Read the memory at `addr` as a Rust vtable, on the drop-glue join
/// described above. It works where the vtable static itself has no
/// symbol, as a stripped binary's does not — but not where the drop
/// glue has none either, and that is when the recorded table is all
/// there is.
fn from_memory(image: &Image<'_>, addr: u64) -> Option<FromMemory> {
    let drop_fn = image.target.read_u64(addr).ok()?;
    if drop_fn == 0 {
        return None;
    }
    let size = image.target.read_u64(addr + 8).ok()?;
    let align = image.target.read_u64(addr + 16).ok()?;
    if !align.is_power_of_two() {
        return None;
    }
    let drop_symbol = image.symbol(drop_fn)?;
    let concrete =
        hansei_bundle::symbols::concrete_type_from_vtable_symbol(&drop_symbol)?.to_string();
    Some(FromMemory {
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
    //
    // The mark on the address is the recorded route's, and says the
    // one thing that route can be unsure of: the table has the vtable
    // linked here and the target holds no word of it, so neither is
    // wrong and nothing bears the other out.
    if let Some(vtable) = vtable {
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "Vtable {addr:#x}{}: erases {}",
            vtable.standing.map_or("", Standing::mark),
            names::fold_type_name(&vtable.concrete, impls)
        )?;
        if let Some(trait_) = &vtable.trait_ {
            writeln!(
                out,
                "    Implements: {}",
                names::fold_type_name(trait_, impls)
            )?;
        }
        // Distinct pairs at one address are identical vtables the
        // linker folded, and any of them is as much what is here as
        // the one the heading names.
        for pair in &vtable.folded {
            writeln!(out, "    Folded with: {pair}")?;
        }
        if let Some(drop_symbol) = &vtable.drop_symbol {
            writeln!(out, "    Drop: {drop_symbol}")?;
        }
        if let Some((size, align)) = vtable.layout {
            writeln!(out, "    Erased size: {size} bytes, align {align}")?;
        }
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
    use super::{Allocation, Size, VtableAt, from_memory, report_whatis, separate, vtable_at};
    use crate::parse_hex_addr;
    use crate::vtables::{Image, Placement, Standing};
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
    /// answer, so the miss line stays away. What only the recorded
    /// table can say it says on lines of its own: the trait, and every
    /// other pair folded onto the same address.
    #[test]
    fn test_a_vtable_reports_what_it_erases() {
        with_tasks("sleep-join", |target| {
            let vtable = |trait_: Option<&str>, standing| VtableAt {
                concrete: "app::Thing<u64>".to_string(),
                trait_: trait_.map(str::to_owned),
                folded: Vec::new(),
                drop_symbol: Some("core::ptr::drop_glue::<app::Thing<u64>>".to_string()),
                layout: Some((48, 8)),
                standing,
            };

            // The memory route alone: no table entry, so no trait to
            // name and nothing qualifying the address.
            let out = reported(target, None, None, Some(&vtable(None, None)), 0x9000_0000);
            assert!(
                out.contains("Vtable 0x90000000: erases app::Thing<u64>"),
                "{out}"
            );
            assert!(!out.contains("Implements:"), "{out}");
            assert!(
                out.contains("Drop: core::ptr::drop_glue::<app::Thing<u64>>"),
                "{out}"
            );
            assert!(out.contains("Erased size: 48 bytes, align 8"), "{out}");
            assert!(!out.contains("no task's allocation"), "{out}");

            // With the table behind it, the trait as well — and the
            // mark where the target holds no word of what it records.
            let named = vtable(Some("app::Dyn"), Some(Standing::Unreadable));
            let out = reported(target, None, None, Some(&named), 0x9000_0000);
            assert!(
                out.contains("Vtable 0x90000000 (unreadable): erases app::Thing<u64>"),
                "{out}"
            );
            assert!(out.contains("    Implements: app::Dyn\n"), "{out}");

            // A folded address owns up to every pair recorded at it.
            let folded = VtableAt {
                folded: vec!["app::Other as app::Dyn".to_string()],
                ..vtable(Some("app::Dyn"), Some(Standing::Confirmed))
            };
            let out = reported(target, None, None, Some(&folded), 0x9000_0000);
            assert!(out.contains("Vtable 0x90000000: erases"), "{out}");
            assert!(
                out.contains("    Folded with: app::Other as app::Dyn\n"),
                "{out}"
            );
        });
    }

    /// Where the executable landed, so the address the table records
    /// and the address the vtable has in the target are not the same
    /// number and the lookup has to move one to the other.
    const BIAS: u64 = 0x400;
    /// Where `VtableMem` serves its words: the vtable's address in the
    /// target, which the table therefore records `BIAS` below.
    const AT: u64 = 0x1000;
    /// The target's text, where every function a vtable dispatches
    /// through has to be — and where the drop glue's symbol is.
    const TEXT: u64 = 0x5000;

    /// The same v0 mangling as `DROP` below for `a::One`, which is the
    /// concrete type the recorded fixture names: the two routes reach
    /// one type by two different means, which is the point of them.
    const DROP_ONE: &str = "_RINvNtCs4gTh5wWLWvJ_4core3ptr9drop_glueNtCs1dINKnBl13J_1a3OneEB1_";
    /// And v0 manglings of `<a::One as a::Dyn>::call` and its sibling
    /// for `a::Two` — a method symbol being the one place a symbol
    /// names a trait, and so the only way to the pair without an
    /// address.
    const ONE_CALL: &str = "_RNvXCs1dINKnBl13J_1aNtCs1dINKnBl13J_1a3OneNtCs1dINKnBl13J_1a3Dyn4call";
    const TWO_CALL: &str = "_RNvXCs1dINKnBl13J_1aNtCs1dINKnBl13J_1a3TwoNtCs1dINKnBl13J_1a3Dyn4call";

    /// A fake serving a vtable's words and one function symbol, for
    /// driving both routes' joins without a core.
    struct VtableMem {
        words: Vec<u8>,
        symbols: Vec<(u64, &'static str)>,
        /// What the target says about where its executable landed, on
        /// which the whole recorded route turns.
        bias: Option<u64>,
    }

    /// A target holding one vtable's words at `AT`, with the drop-glue
    /// symbol behind its first slot unless it has been stripped of it.
    fn target(words: &[u64], symbol: Option<&'static str>) -> VtableMem {
        VtableMem {
            words: words.iter().flat_map(|w| w.to_le_bytes()).collect(),
            symbols: symbol.map(|name| (TEXT, name)).into_iter().collect(),
            bias: Some(BIAS),
        }
    }

    /// The two mappings the checks read: the text everything a vtable
    /// dispatches to has to be in, and the image the vtable itself sits
    /// in — which is what says the recorded addresses are this
    /// target's rather than another build's.
    fn mappings() -> proc::Mappings {
        let map = |vaddr, flags| proc::LoadedObjectWithPath {
            path: Some("/bin/fake".to_string()),
            vaddr,
            size: 0x1000,
            flags: proc::MapFlags(flags),
        };
        proc::Mappings::from_iter([map(AT, 0x04), map(TEXT, 0x05)])
    }

    /// The target as both routes read it. The mappings have to outlive
    /// the borrow the image takes of them, which is what the closure
    /// is for.
    fn with_image(mem: &VtableMem, check: impl FnOnce(&Image<'_>)) {
        let mappings = mappings();
        check(&Image {
            target: mem,
            mappings: &mappings,
            bias: mem.bias,
        });
    }

    /// One entry, recorded at the address `AT` unbiases to.
    fn recorded() -> hansei_bundle::Bundle {
        crate::vtables::vtable_tests::bundle(&[("a::Dyn", "a::One", AT - BIAS, 4, &[])])
    }

    /// A whole vtable of the shape that entry describes: glue, size,
    /// align, and one method, everything callable in text.
    const WHOLE: [u64; 4] = [TEXT, 48, 8, TEXT + 0x10];

    impl proc::Target for VtableMem {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            let start = addr
                .checked_sub(0x1000)
                .filter(|&s| s + len <= self.words.len() as u64)
                .ok_or_else(|| proc::Error::unmapped(addr, len))?;
            Ok(&self.words[start as usize..(start + len) as usize])
        }
        fn lookup_symbol_by_addr(&self, addr: u64) -> Option<proc::SymbolBuf> {
            let &(at, name) = self.symbols.iter().find(|&&(at, _)| at == addr)?;
            (at == addr).then(|| proc::SymbolBuf {
                name: name.to_string(),
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
        fn exec_bias(&self) -> Option<u64> {
            self.bias
        }
    }

    /// The memory route over one arrangement of words.
    fn probe(mem: &VtableMem, addr: u64) -> Option<super::FromMemory> {
        let mappings = mappings();
        from_memory(
            &Image {
                target: mem,
                mappings: &mappings,
                bias: mem.bias,
            },
            addr,
        )
    }

    /// The memory route believes only the full join: a drop-glue symbol
    /// behind the first slot and a plausible align word. A slot
    /// resolving to no symbol, to a symbol that is not drop glue, or
    /// riding an align that is no power of two proves nothing.
    #[test]
    fn test_the_vtable_probe_requires_the_drop_glue_join() {
        // A genuine v0-mangled drop-glue monomorphization, lifted from
        // a real symtab, demangling to
        // `core::ptr::drop_glue::<[reedline::enums::EditCommand; 1]>`.
        const DROP: &str = "_RINvNtCs4gTh5wWLWvJ_4core3ptr9drop_glueANtNtCs1dINKnBl13J_8reedline5enums11EditCommandj1_EBG_";
        let mem = |drop_fn: u64, align: u64, symbol: Option<&'static str>| VtableMem {
            words: [drop_fn, 48, align]
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect(),
            symbols: symbol.map(|name| (TEXT, name)).into_iter().collect(),
            bias: None,
        };

        let found = probe(&mem(TEXT, 8, Some(DROP)), AT).expect("the full join is believed");
        assert_eq!(found.concrete, "[reedline::enums::EditCommand; 1]");
        assert_eq!((found.size, found.align), (48, 8));

        assert!(probe(&mem(TEXT, 8, None), AT).is_none());
        assert!(probe(&mem(TEXT, 8, Some("malloc")), AT).is_none());
        assert!(probe(&mem(TEXT, 7, Some(DROP)), AT).is_none());
        assert!(probe(&mem(0, 8, Some(DROP)), AT).is_none());
        // Unreadable memory is no vtable either.
        assert!(probe(&mem(TEXT, 8, Some(DROP)), 0x9999).is_none());
    }

    /// The bundle records every `<Concrete as Trait>` pair rustc
    /// instantiated and where it linked the vtable, so an address that
    /// unbiases to one of them is named outright — the trait included,
    /// which reading the memory could never yield, since a vtable's
    /// words hold no trace of which trait it is for.
    ///
    /// The memory route is about the same bytes, and where both speak
    /// they name the same concrete type. That agreement is what makes
    /// one block of the two.
    #[test]
    fn test_both_routes_name_the_same_vtable() {
        let bundle = recorded();
        let view = BundleView::new(&bundle);
        let mem = target(&WHOLE, Some(DROP_ONE));
        with_image(&mem, |image| {
            let found = vtable_at(&view, image, AT).expect("the recorded address is a vtable");
            assert_eq!(found.concrete, "a::One");
            assert_eq!(found.trait_.as_deref(), Some("a::Dyn"));
            assert_eq!(
                found.drop_symbol.as_deref(),
                Some("core::ptr::drop_glue::<a::One>")
            );
            assert_eq!(found.layout, Some((48, 8)));
            assert_eq!(found.standing, Some(Standing::Confirmed));
            assert!(found.folded.is_empty(), "{:?}", found.folded);

            let memory = from_memory(image, AT).expect("the memory route reads it too");
            assert_eq!(memory.concrete, found.concrete);
        });
    }

    /// A stripped target resolves no symbol behind the drop slot, so
    /// the memory route has nothing to join and says nothing. The
    /// recorded table needs no symbol and names the pair anyway, which
    /// is the whole reason for looking it up.
    #[test]
    fn test_the_table_answers_where_no_symbol_does() {
        let bundle = recorded();
        let view = BundleView::new(&bundle);
        let mem = target(&WHOLE, None);
        with_image(&mem, |image| {
            assert!(from_memory(image, AT).is_none(), "no symbol to join");
            let found = vtable_at(&view, image, AT).expect("the table names it regardless");
            assert_eq!(found.concrete, "a::One");
            assert_eq!(found.trait_.as_deref(), Some("a::Dyn"));
            assert_eq!(found.drop_symbol, None);
            assert_eq!(found.layout, None);
            // The shape check reads words, not names, so it still
            // bears the entry out.
            assert_eq!(found.standing, Some(Standing::Confirmed));
        });
    }

    /// A recorded address is where the vtable is only when the tokio
    /// info came from the build that ran, and the words at it are what
    /// says which. Where they deny the entry — the case a mismatched
    /// pair puts hansei in everywhere — it is dropped rather than
    /// offered as a lead, and only what the memory itself proved is
    /// reported. Where the target holds no word of it neither can
    /// settle it, so the pair stands and the address is marked.
    #[test]
    fn test_a_recorded_vtable_the_memory_denies_is_dropped() {
        let bundle = recorded();
        let view = BundleView::new(&bundle);

        // A method slot pointing outside text: not the words the
        // entry describes, whatever else they are. The drop-glue join
        // still holds, so the memory answers for itself and names no
        // trait, because memory never can.
        let mem = target(&[TEXT, 48, 8, 0x99], Some(DROP_ONE));
        with_image(&mem, |image| {
            let found = vtable_at(&view, image, AT).expect("the memory route still answers");
            assert_eq!(found.concrete, "a::One");
            assert_eq!(found.trait_, None);
            assert_eq!(found.standing, None);
        });

        // Denied with nothing else to say: no block at all rather than
        // a pair the address does not hold.
        let mem = target(&[0, 48, 8, 0x99], Some(DROP_ONE));
        with_image(&mem, |image| {
            assert!(vtable_at(&view, image, AT).is_none());
        });

        // And a target holding not one word of it.
        let mem = target(&[], Some(DROP_ONE));
        with_image(&mem, |image| {
            let found = vtable_at(&view, image, AT).expect("the table still names it");
            assert_eq!(found.trait_.as_deref(), Some("a::Dyn"));
            assert_eq!(found.standing, Some(Standing::Unreadable));
            assert_eq!(found.layout, None);
        });
    }

    /// An address the table records nothing at is the memory route's
    /// alone, and names no trait because nothing can. So is every
    /// address in a target that cannot say where its executable landed:
    /// there is no link-time address to look one up by.
    #[test]
    fn test_an_unrecorded_address_is_the_memory_routes_alone() {
        let alone = |bundle: &hansei_bundle::Bundle, mem: &VtableMem| {
            let view = BundleView::new(bundle);
            with_image(mem, |image| {
                let found = vtable_at(&view, image, AT).expect("the memory route answers");
                assert_eq!(found.concrete, "a::One");
                assert_eq!(found.trait_, None);
                assert_eq!(found.standing, None);
                assert_eq!(found.layout, Some((48, 8)));
            });
        };

        alone(
            &recorded(),
            &VtableMem {
                bias: None,
                ..target(&WHOLE, Some(DROP_ONE))
            },
        );
        // The second table's one entry is placed where this target's
        // image is — a word along from the address asked about — so
        // what leaves the memory route alone here is the address
        // missing the table, not the table missing the target.
        alone(
            &crate::vtables::vtable_tests::bundle(&[("a::Dyn", "a::One", AT - BIAS + 8, 4, &[])]),
            &target(&WHOLE, Some(DROP_ONE)),
        );
    }

    /// A table whose addresses land nowhere an image is mapped is some
    /// other build's, and is not consulted at all — not even for the
    /// address it appears to name, which on a mismatched pair is a
    /// coincidence between two layouts rather than a fact about this
    /// one. Without that gate the memory-denied case would still be
    /// caught per row, but the unreadable one would name a pair the
    /// target never held.
    #[test]
    fn test_a_table_from_another_build_is_not_consulted() {
        let bundle = recorded();
        let view = BundleView::new(&bundle);
        // The vtable's words are exactly what the entry describes, so
        // only the placement of the table as a whole can refuse it.
        let mem = target(&WHOLE, Some(DROP_ONE));
        with_image(&mem, |image| {
            assert_eq!(
                Placement::of(image, &bundle.vtables.entries),
                Placement::Placed
            );
            let found = vtable_at(&view, image, AT).expect("a placed table names it");
            assert_eq!(found.trait_.as_deref(), Some("a::Dyn"));
        });

        // The same table and the same words, against a target whose
        // mappings are elsewhere: nothing recorded is believed, and
        // only what the memory proved is left.
        let mappings = proc::Mappings::from_iter([proc::LoadedObjectWithPath {
            path: Some("/bin/fake".to_string()),
            vaddr: TEXT,
            size: 0x1000,
            flags: proc::MapFlags(0x05),
        }]);
        let image = Image {
            target: &mem,
            mappings: &mappings,
            bias: mem.bias,
        };
        assert_eq!(
            Placement::of(&image, &bundle.vtables.entries),
            Placement::OtherBuild {
                placed: 0,
                checked: 1
            }
        );
        let found = vtable_at(&view, &image, AT).expect("the memory route answers");
        assert_eq!(found.trait_, None);
        assert_eq!(found.standing, None);

        // And with no symbol to fall back on, nothing is claimed at all
        // — the case that used to name a pair under `(unreadable)`.
        let stripped = target(&[], None);
        let image = Image {
            target: &stripped,
            mappings: &mappings,
            bias: stripped.bias,
        };
        assert!(vtable_at(&view, &image, AT).is_none());
    }

    /// A table whose addresses are another build's can still name this
    /// one, by content instead of by address: the words here are read
    /// and the pair the first method slot's symbol spells is looked up.
    /// That is what keeps `whatis` able to name an address the listing
    /// just printed, which on such a target is a swept address rather
    /// than a recorded one.
    #[test]
    fn test_another_builds_table_still_names_a_vtable_by_its_method() {
        // Recorded a long way from anything this target maps, so the
        // address route is closed and only the method symbol is left.
        let bundle =
            crate::vtables::vtable_tests::bundle(&[("a::Dyn", "a::One", 0x9_0000, 4, &[])]);
        let view = BundleView::new(&bundle);
        let mut mem = target(&[0, 24, 8, TEXT + 0x40], None);
        mem.symbols.push((TEXT + 0x40, ONE_CALL));
        with_image(&mem, |image| {
            assert!(
                !Placement::of(image, &bundle.vtables.entries).applies(),
                "the fixture is meant to be another build's"
            );
            let found = vtable_at(&view, image, AT).expect("the method symbol names it");
            assert_eq!(found.concrete, "a::One");
            assert_eq!(found.trait_.as_deref(), Some("a::Dyn"));
            assert_eq!(found.standing, Some(Standing::Confirmed));
        });

        // A vtable whose method names a pair the table does not record
        // is not one of the table's, and nothing is claimed for it.
        let mut mem = target(&[0, 24, 8, TEXT + 0x40], None);
        mem.symbols.push((TEXT + 0x40, TWO_CALL));
        with_image(&mem, |image| {
            assert!(vtable_at(&view, image, AT).is_none());
        });
    }

    /// Identical vtables the linker folded share one address, and the
    /// table keeps every pair it recorded for them: the heading names
    /// the first and the block owns up to the rest.
    #[test]
    fn test_folded_pairs_are_all_named() {
        let bundle = crate::vtables::vtable_tests::bundle(&[
            ("a::Dyn", "a::One", AT - BIAS, 4, &[]),
            ("b::Other", "a::Two", AT - BIAS, 4, &[]),
        ]);
        let view = BundleView::new(&bundle);
        let mem = target(&WHOLE, Some(DROP_ONE));
        with_image(&mem, |image| {
            let found = vtable_at(&view, image, AT).expect("the folded address is named");
            assert_eq!(found.concrete, "a::One");
            assert_eq!(found.trait_.as_deref(), Some("a::Dyn"));
            assert_eq!(found.folded, ["a::Two as b::Other"]);
        });
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
            let claimed = reported(t, None, Some("[ heap ]"), None, task);
            assert!(!claimed.contains("It is in"), "{claimed}");

            // Nothing claims this one, so the mapping is what there is
            // to say — in pmap's own descriptor, so the two readings
            // of the same core can be matched by eye.
            let loose = reported(t, None, Some("[ anon ]"), None, 0x9999_0000);
            assert!(loose.contains("It is in [ anon ]."), "{loose}");

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
                assert!(shown.contains("(frame 5, `future1`)"), "{shown}");
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
                shown.contains(&format!("Runtime {hidden} @ {handle:#x}: current_thread")),
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
                inside.contains(&format!("Runtime {hidden} @ {handle:#x}: ")),
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
                shown.contains(&format!("Local set 0 @ {shared:#x}:")),
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

//! The `whatis` command: what an address is, outermost first.

use crate::Session;
use crate::tasks::{future_name, task_id, task_label};

use anyhow::Result;
use hansei_bundle::names;
use hansei_bundle::{BundleType, BundleView, TypeClass};
use hansei_runtime::tokio::{bundle, census, reach};

use std::fmt::Write as _;
use std::io;

pub(crate) fn exec_whatis(session: &Session<'_>, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    report_whatis(
        &session.ctx.view,
        &session.runtimes,
        &session.local_sets,
        &session.tasks,
        session.extents(),
        session.census(),
        vtable_at(session.proc, addr).as_ref(),
        &session.impl_fold,
        || session.reach(),
        addr,
        out,
    )
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
/// The reachability index is the last tier, consulted only when every
/// block above came up empty — so `reach` is a thunk: the index costs
/// seconds to build on a large target, and an address the direct joins
/// already claim never pays for it.
#[allow(clippy::too_many_arguments)]
fn report_whatis<'i>(
    view: &BundleView<'_>,
    runtimes: &[bundle::RuntimeRef<'_>],
    local_sets: &[bundle::LocalSetRef<'_>],
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &census::FutureCensus,
    vtable: Option<&VtableAt>,
    impls: &names::ImplFold,
    reach: impl FnOnce() -> &'i reach::ReachIndex,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut blocks = 0;
    let owned = |group: usize| list.tasks.iter().filter(|t| t.group == group).count();

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

    if blocks > 0 {
        return Ok(());
    }

    // Nothing claims the address directly; ask what can *reach* it.
    // Built here and not sooner, so every directly-claimed address —
    // the overwhelmingly common query — never pays for the walk.
    let index = reach();
    match index.locate(addr) {
        Some(hit) => report_reachable(view, list, impls, &hit, out)?,
        None => {
            writeln!(
                out,
                "no task's allocation, no future the census found, and nothing \
                 the reachability walk reached contains {addr:#x}"
            )?;
            if let Some(cut) = reach_cut_note(index) {
                writeln!(out, "    ({cut})")?;
            }
        }
    }
    Ok(())
}

/// The reachability block: the task whose future graph reaches the
/// containing allocation, the pointer path from its own frames down to
/// it, and where in the allocation the address lands — refined to the
/// member it falls in by offset math against the recorded type.
fn report_reachable(
    view: &BundleView<'_>,
    list: &bundle::TaskList,
    impls: &names::ImplFold,
    hit: &reach::ReachHit<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    writeln!(
        out,
        "Reachable from {}: {}",
        task_label(list, hit.root.owner),
        future_name(&list.tasks[hit.root.owner].future, impls)
    )?;
    if !hit.root.via.is_empty() {
        writeln!(out, "    Via: {}", hit.root.via)?;
    }
    writeln!(out, "    Path: {}", hit.path.join(" -> "))?;

    let record = hit.record;
    let ty = view.ty(record.ty);
    let name = match &ty {
        Some(ty) => names::fold_type_name(ty.name(), impls).into_owned(),
        None => "<type the bundle does not carry>".to_string(),
    };
    let (whole, refined) = extent_at(
        record.kind,
        ty,
        &name,
        hit.offset,
        record.end - record.start,
    );
    writeln!(out, "    At: offset {:#x} {whole}", hit.offset)?;
    if let Some((chain, rem)) = refined {
        let rem = match rem {
            0 => String::new(),
            rem => format!(" +{rem:#x}"),
        };
        writeln!(out, "    Member: `{chain}`{rem}")?;
    }
    Ok(())
}

/// The two lines that place an offset inside a recorded extent: the
/// phrase naming the whole (`in {type}`, `in a buffer of N × {type}`,
/// `in the bytes of a {type}`) and, where the layout gives one, the
/// member chain the offset refines to with whatever offset is left
/// past the last named member.
fn extent_at(
    kind: reach::ExtentKind,
    ty: Option<BundleType<'_>>,
    name: &str,
    offset: u64,
    len: u64,
) -> (String, Option<(String, u64)>) {
    match kind {
        reach::ExtentKind::Value => {
            let refined = ty
                .map(|ty| refine_offset(ty, offset))
                .filter(|(chain, _)| !chain.is_empty());
            (format!("in {name}"), refined)
        }
        reach::ExtentKind::Buffer { stride } => {
            let stride = stride.max(1);
            let index = offset / stride;
            let refined = match ty.map(|ty| refine_offset(ty, offset % stride)) {
                Some((chain, rem)) if !chain.is_empty() => {
                    Some((format!("[{index}].{chain}"), rem))
                }
                _ => Some((format!("[{index}]"), offset % stride)),
            };
            (format!("in a buffer of {} × {name}", len / stride), refined)
        }
        // The bytes are one homogeneous run; there is no member to
        // refine to, and the recorded type is the owner, not theirs.
        reach::ExtentKind::Bytes => (format!("in the bytes of a {name}"), None),
    }
}

/// The member chain `offset` lands in, by layout alone: descend structs
/// through the member spanning the offset and arrays through the
/// element index, until a type with no by-offset interior (a scalar, a
/// pointer, an enum whose live variant is a value-time question). The
/// leftover offset into the last named member rides along; a chain
/// stopping short is honest, never wrong.
fn refine_offset(ty: BundleType<'_>, offset: u64) -> (String, u64) {
    let mut chain = String::new();
    let mut ty = ty;
    let mut offset = offset;
    loop {
        match ty.classify() {
            TypeClass::Struct => {
                let member = ty
                    .members()
                    .filter(|m| m.ty().size() > 0)
                    .find(|m| m.offset() <= offset && offset - m.offset() < m.ty().size());
                let Some(m) = member else { break };
                if !chain.is_empty() {
                    chain.push('.');
                }
                chain.push_str(m.name());
                offset -= m.offset();
                ty = m.ty();
            }
            TypeClass::Array { element, .. } if element.size() > 0 => {
                let _ = write!(chain, "[{}]", offset / element.size());
                offset %= element.size();
                ty = element;
            }
            _ => break,
        }
    }
    (chain, offset)
}

/// Where the reach walk stopped short, for the miss answer: a cut walk
/// cannot rule an address out, and the depth limit is the one cut a
/// session can move.
fn reach_cut_note(index: &reach::ReachIndex) -> Option<String> {
    let capped = index.capped;
    let mut cuts = Vec::new();
    if capped.deep > 0 {
        cuts.push(format!(
            "its depth limit in {} place(s) (--reach-depth moves it)",
            capped.deep
        ));
    }
    if capped.elements > 0 {
        cuts.push(format!(
            "its element cap in {} sequence(s)",
            capped.elements
        ));
    }
    if capped.records {
        cuts.push(format!("its record cap of {}", index.bounds.max_records));
    }
    (!cuts.is_empty()).then(|| {
        format!(
            "the reachability walk stopped at {}; what it did not reach it cannot rule out",
            cuts.join(", ")
        )
    })
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
    use super::{VtableAt, report_whatis, separate, vtable_at};
    use crate::parse_hex_addr;
    use hansei_bundle::BundleView;
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::bundle::{LocalSetRef, RuntimeRef, TaskExtents, TaskList};
    use hansei_runtime::tokio::census::{self, FutureCensus};
    use hansei_runtime::tokio::reach::{ReachBounds, ReachIndex, reach_index};

    /// Everything a report is made from: the whole of what an attach
    /// finds, so a test can point at any of it.
    struct Target<'a> {
        view: BundleView<'a>,
        runtimes: Vec<RuntimeRef<'a>>,
        local_sets: Vec<LocalSetRef<'a>>,
        list: TaskList,
        extents: TaskExtents,
        census: FutureCensus,
        reach: ReachIndex,
    }

    fn with_tasks(program: &str, check: impl FnOnce(&Target<'_>)) {
        let (bundle, snapshot) = testkit::load_any(program);
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        let reach = reach_index(&ctx, &list, &census, &extents, ReachBounds::default());
        check(&Target {
            view: ctx.view,
            runtimes,
            local_sets,
            list,
            extents,
            census,
            reach,
        });
    }

    fn report(target: &Target<'_>, addr: u64) -> String {
        let mut out = Vec::new();
        report_whatis(
            &target.view,
            &target.runtimes,
            &target.local_sets,
            &target.list,
            &target.extents,
            &target.census,
            None,
            &hansei_bundle::names::ImplFold::default(),
            || &target.reach,
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
            let mut out = Vec::new();
            report_whatis(
                &target.view,
                &target.runtimes,
                &target.local_sets,
                &target.list,
                &target.extents,
                &target.census,
                Some(&vtable),
                &hansei_bundle::names::ImplFold::default(),
                || &target.reach,
                0x9000_0000,
                &mut out,
            )
            .expect("the report renders");
            let out = String::from_utf8(out).expect("rendered output is UTF-8");
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
            assert!(
                miss.starts_with(
                    "no task's allocation, no future the census found, and nothing \
                     the reachability walk reached contains 0x10\n"
                ),
                "{miss}"
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

            // Past its end it is somebody else's memory — unless the
            // reachability walk recorded whatever sits there, which is
            // its call to make, not this test's.
            let past = report(t, future1.addr + size);
            assert!(
                past.starts_with("no task's allocation, no future")
                    || past.starts_with("Reachable from"),
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
        let reach = reach_index(&ctx, &list, &census, &extents, ReachBounds::default());
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
            reach,
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

    /// The record the channels fixture reaches through `#0
    /// notify.ptr.pointer` — the `ArcInner<Notify>` behind the holder
    /// task's `Arc` — which every fixture set's reach golden pins.
    fn arc_inner_notify<'t>(t: &'t Target<'_>) -> &'t hansei_runtime::tokio::reach::ReachRecord {
        t.reach
            .records()
            .find(|r| {
                t.view
                    .ty(r.ty)
                    .is_some_and(|ty| ty.name().ends_with("ArcInner<tokio::sync::notify::Notify>"))
            })
            .expect("the walk reaches the notify ArcInner")
    }

    /// An address nothing claims directly is answered by the
    /// reachability tier: the owning task, the pointer path from its
    /// frames, the containing type — and, off the allocation's start,
    /// the member the offset refines to.
    #[test]
    fn test_a_reachable_address_reports_its_path() {
        with_tasks("channels", |t| {
            let record = arc_inner_notify(t);

            let shown = report(t, record.start);
            assert!(shown.starts_with("Reachable from task "), "{shown}");
            assert!(
                shown.contains("    Path: #0 notify.ptr.pointer\n"),
                "{shown}"
            );
            assert!(
                shown.contains(
                    "    At: offset 0x0 in alloc::sync::ArcInner<tokio::sync::notify::Notify>\n"
                ),
                "{shown}"
            );
            // A task-own root has no via to name.
            assert!(!shown.contains("    Via: "), "{shown}");

            // +0x8 is `weak` — inside the ArcInner but before the
            // `data` the narrower Notify record claims for itself.
            let inside = report(t, record.start + 0x8);
            assert!(inside.contains("    At: offset 0x8 in "), "{inside}");
            assert!(inside.contains("    Member: `weak"), "{inside}");
        });
    }

    /// The refinement is offset math against the layout: a member's
    /// offset descends into it as far as named members go, and
    /// whatever is left past the last name rides along as bytes.
    #[test]
    fn test_refinement_descends_by_offset() {
        with_tasks("channels", |t| {
            let record = arc_inner_notify(t);
            let ty = t.view.ty(record.ty).expect("the record's type resolves");

            let (chain, rem) = super::refine_offset(ty, 0x8);
            assert!(chain.starts_with("weak"), "{chain:?}");
            assert_eq!(rem, 0, "{chain:?}");

            // One byte into the word the chain bottoms out at.
            let (chain, rem) = super::refine_offset(ty, 0x9);
            assert!(chain.starts_with("weak"), "{chain:?}");
            assert_eq!(rem, 1, "{chain:?}");
        });
    }

    /// Each extent kind has its own placement spelling: a value names
    /// its type, a buffer counts its elements and leads the chain with
    /// the element index, the bytes of a string name their owner and
    /// refuse to invent a member.
    #[test]
    fn test_extent_kinds_spell_their_placement() {
        use hansei_runtime::tokio::reach::ExtentKind;
        with_tasks("channels", |t| {
            let record = arc_inner_notify(t);
            let ty = t.view.ty(record.ty);
            let size = ty.expect("the type resolves").size();

            let (whole, refined) = super::extent_at(ExtentKind::Value, ty, "T", 0x8, size);
            assert_eq!(whole, "in T");
            let (chain, _) = refined.expect("a struct offset refines");
            assert!(chain.starts_with("weak"), "{chain:?}");

            // Three elements of `size` bytes; an offset in the middle
            // element leads with its index.
            let stride = size;
            let (whole, refined) = super::extent_at(
                ExtentKind::Buffer { stride },
                ty,
                "T",
                stride + 0x8,
                3 * stride,
            );
            assert_eq!(whole, "in a buffer of 3 × T");
            let (chain, rem) = refined.expect("a buffer offset refines");
            assert!(chain.starts_with("[1].weak"), "{chain:?}");
            assert_eq!(rem, 0);

            // A type the bundle does not carry still places the index.
            let (_, refined) =
                super::extent_at(ExtentKind::Buffer { stride: 8 }, None, "T", 20, 40);
            assert_eq!(refined, Some(("[2]".to_string(), 4)));

            let (whole, refined) = super::extent_at(ExtentKind::Bytes, ty, "String", 0x5, 32);
            assert_eq!(whole, "in the bytes of a String");
            assert_eq!(refined, None);
        });
    }

    /// A miss over a cut walk says where the walk stopped, and only
    /// the depth limit — the one a session can move — names its knob.
    #[test]
    fn test_a_cut_walk_qualifies_its_miss() {
        let (bundle, snapshot) = testkit::load_any("channels");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        let shallow = ReachBounds {
            depth: 1,
            ..ReachBounds::default()
        };
        let reach = reach_index(&ctx, &list, &census, &extents, shallow);
        assert!(reach.capped.deep > 0, "depth 1 cuts the channels walk");
        let target = Target {
            view: ctx.view,
            runtimes,
            local_sets,
            list,
            extents,
            census,
            reach,
        };
        let miss = report(&target, 0x10);
        assert!(
            miss.contains("the reachability walk stopped at its depth limit in "),
            "{miss}"
        );
        assert!(miss.contains("(--reach-depth moves it)"), "{miss}");
        assert!(
            miss.contains("what it did not reach it cannot rule out"),
            "{miss}"
        );
    }

    /// The cut note names each limit that bound the walk and stays
    /// silent for one nothing cut.
    #[test]
    fn test_the_cut_note_names_each_limit() {
        with_tasks("channels", |t| {
            assert!(!t.reach.capped.any(), "the fixture walk runs to done");
            assert_eq!(super::reach_cut_note(&t.reach), None);
        });

        let (bundle, snapshot) = testkit::load_any("channels");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        let mut index = reach_index(&ctx, &list, &census, &extents, ReachBounds::default());
        index.capped.deep = 2;
        index.capped.elements = 3;
        index.capped.records = true;
        let note = super::reach_cut_note(&index).expect("three cuts note");
        assert!(
            note.contains("its depth limit in 2 place(s) (--reach-depth moves it)"),
            "{note}"
        );
        assert!(note.contains("its element cap in 3 sequence(s)"), "{note}");
        assert!(
            note.contains(&format!("its record cap of {}", index.bounds.max_records)),
            "{note}"
        );
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

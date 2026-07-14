// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bundle-based parsing of tokio runtime state (`HANSEI_V0_MANGLING_PLAN.md`
//! §9).
//!
//! Layouts come only from the bundle; addresses and bytes come only from the
//! target; the only thing that crosses between the two binaries is symbol
//! names (§2). Runtime discovery is the pthread-key flow ported from
//! spelunkio (§3.0): the bundle names the TLS-key static, the target's
//! symtab locates it, and its value indexes each LWP's fast-TSD slots to
//! find that thread's `tokio::runtime::context::Context`.

use super::{Location, TaskAddr, TaskState};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use exegesis::bundle::{
    BundleType, BundleTypeId, BundleView, DynPointer, FutureKind, StaticRole, TaskEntryId,
    TaskFutureEntry, TypeDef, strip_llvm_suffix,
};
use proc::{LwpInfo, Mappings, Target};
use reify::{ParseCtx, TypeInfo, TypeInfoRef};

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// Hard bound on await-chain depth: anything deeper indicates corrupt
/// memory (or a pathological program), and the walk must report it
/// rather than hang (§3.5).
const MAX_AWAIT_DEPTH: usize = 64;

/// Rust vtables place the drop-in-place glue in slot 0, size and align
/// in slots 1 and 2, and the trait's methods after; `Future`'s only
/// method is `poll`, so it is slot 3.
const VTABLE_SLOT_DROP: u64 = 0;
const VTABLE_SLOT_FUTURE_POLL: u64 = 3;

/// Everything needed to interpret a target process through a loaded bundle.
pub struct Context<'b, T> {
    pub proc: &'b T,
    pub view: BundleView<'b>,
    pub mappings: Mappings,
    /// Target text address → mangled symtab name (`None` when the address
    /// resolves to no symbol). Mangled names are the join keys; demangling
    /// is display-only.
    symbols: RefCell<HashMap<u64, Option<String>>>,
    /// Task vtables decoded from target memory, keyed by vtable address.
    vtables: RefCell<HashMap<u64, TaskVtable>>,
}

impl<'b, T: Target> Context<'b, T> {
    pub fn new(proc: &'b T, view: BundleView<'b>) -> Result<Self> {
        let mappings = proc.mappings().context("failed to read target mappings")?;
        Ok(Self {
            proc,
            view,
            mappings,
            symbols: RefCell::new(HashMap::new()),
            vtables: RefCell::new(HashMap::new()),
        })
    }

    /// Resolve an infra type id to a usable layout, rejecting the opaque
    /// placeholders `--allow-missing-infra` extraction leaves behind.
    fn infra_ty(&self, id: BundleTypeId, what: &str) -> Result<BundleType<'b>> {
        let ty = self
            .view
            .ty(id)
            .ok_or_else(|| anyhow!("bundle has no type entry for {what}"))?;
        if matches!(ty.def(), TypeDef::Opaque { .. }) {
            bail!(
                "bundle has no layout for {what} \
                 (was it extracted with --allow-missing-infra?)"
            );
        }
        Ok(ty)
    }

    /// The mangled symtab name covering `addr`, if any (cached).
    fn symbol_at(&self, addr: u64) -> Option<String> {
        if let Some(cached) = self.symbols.borrow().get(&addr) {
            return cached.clone();
        }
        let name = self.proc.lookup_symbol_by_addr(addr).map(|s| s.name);
        self.symbols.borrow_mut().insert(addr, name.clone());
        name
    }

    // -----------------------------------------------------------------------
    // Attach-time validation (§5.1)
    // -----------------------------------------------------------------------

    /// Resolve the bundle's symbol fingerprint against the target's symtab.
    ///
    /// A less-than-complete match means the target was not built from the
    /// same commit/toolchain/flags as the debug binary, and interpreting it
    /// with this bundle would misparse memory.
    pub fn validate_fingerprint(&self) -> Fingerprint {
        let syms = &self.view.bundle().meta.symbol_fingerprint;
        let mut missing: Vec<String> = syms
            .iter()
            .filter(|s| self.proc.lookup_symbol_by_name(s).is_none())
            .cloned()
            .collect();

        // A symbol may exist in the target only as `.llvm.<hash>`-suffixed
        // internalized copies; those still count as a match (the suffix is
        // path-sensitive and never participates in joins).
        if !missing.is_empty()
            && let Ok(all) = self.proc.symbols()
        {
            let stripped: HashSet<&str> = all.iter().map(|s| strip_llvm_suffix(&s.name)).collect();
            missing.retain(|s| !stripped.contains(s.as_str()));
        }

        Fingerprint {
            total: syms.len(),
            matched: syms.len() - missing.len(),
            missing,
        }
    }

    // -----------------------------------------------------------------------
    // Runtime discovery (§3.0)
    // -----------------------------------------------------------------------

    /// Read the pthread key under which each thread stores its
    /// `tokio::runtime::context::Context`: the bundle names the TLS-key
    /// static, the target's symtab locates it, and its u64 value is the key.
    pub fn tls_context_key(&self) -> Result<u64> {
        let def = self
            .view
            .bundle()
            .statics
            .entries
            .get(&StaticRole::TlsContextKey)
            .ok_or_else(|| {
                anyhow!(
                    "bundle records no TLS context key static \
                     (was it extracted with --allow-missing-infra?)"
                )
            })?;
        let sym = self
            .proc
            .lookup_symbol_by_name(&def.symbol)
            .ok_or_else(|| {
                anyhow!(
                    "TLS key static {} ({}) not found in the target's symtab; \
                 wrong binary, or symtab stripped?",
                    def.display,
                    def.symbol
                )
            })?;
        let key = self
            .proc
            .read_u64(sym.st_value)
            .with_context(|| format!("failed to read TLS key at {:#x}", sym.st_value))?;
        // ul_ftsd has 9 slots; a key outside that range would need the slow
        // TSD array, which no tokio process observed so far uses.
        ensure!(
            key < 9,
            "TLS key {key} is outside the fast-TSD range; slow TSD is unsupported"
        );
        Ok(key)
    }

    /// Probe every LWP's fast-TSD slot for a live `Context` (§13.3: all
    /// LWPs, never thread names). LWPs without one are skipped; an LWP whose
    /// `Context` fails to parse is an error, not a skip — the key told us it
    /// is one.
    pub fn find_workers(&self, lwps: &[LwpInfo]) -> Result<Vec<Worker>> {
        let key = self.tls_context_key()? as usize;
        let mut workers = Vec::new();
        for lwp in lwps {
            // Some LWPs (e.g. exiting ones) have no readable ulwp_t.
            let Ok(ftsd) = self.proc.tsd_from_regs(&lwp.regs) else {
                continue;
            };
            let addr = ftsd[key];
            if addr == 0 || !self.mappings.contains_addr(addr) {
                continue;
            }
            let worker = self
                .worker_at(lwp.tid, addr)
                .with_context(|| format!("failed to parse Context of LWP {}", lwp.tid))?;
            workers.push(worker);
        }
        Ok(workers)
    }

    /// Parse the thread-local `Context` at `context_addr` (e.g. found via
    /// the TSD key, or by the legacy byte-pattern heuristic).
    pub fn worker_at(&self, tid: u32, context_addr: u64) -> Result<Worker> {
        let info = self.context_info(context_addr)?;
        let current_task_id = info
            .member("current_task_id")?
            .parse(self)
            .context("failed to parse Context.current_task_id")?;
        Ok(Worker {
            tid,
            context_addr,
            current_task_id,
        })
    }

    fn context_info(&self, addr: u64) -> Result<TypeInfo<'b, BundleType<'b>>> {
        let ty = self.infra_ty(
            self.view.bundle().infra.context,
            "tokio::runtime::context::Context",
        )?;
        TypeInfo::from_addr(self, ty, addr)
            .with_context(|| format!("failed to read Context at {addr:#x}"))
    }

    /// Navigate from the workers' `Context`s to the multi_thread scheduler's
    /// `Shared` (`Context.current.handle` → `Option<scheduler::Handle>` →
    /// `MultiThread(Arc<Handle>)` → deref → `.shared`).
    pub fn find_shared(&self, workers: &[Worker]) -> Result<TypeInfo<'b, BundleType<'b>>> {
        let mut saw_other_scheduler = false;
        for worker in workers {
            let info = self.context_info(worker.context_addr)?;
            let handle = info.member("current")?.member("handle")?.member("value")?;
            let Some(some) = handle.try_select_variant("Some")? else {
                continue;
            };
            let Some(mt) = some.try_select_variant("MultiThread")? else {
                // current_thread is out of scope (§13.4).
                saw_other_scheduler = true;
                continue;
            };
            let inner = mt.deref_ptr(self)?; // ArcInner<multi_thread::Handle>
            let shared = inner.member("data")?.member("shared")?.to_owned();
            return Ok(shared);
        }
        if saw_other_scheduler {
            bail!("only MultiThread runtimes are supported, and none was found");
        }
        bail!("no worker thread has a runtime handle in its Context");
    }

    // -----------------------------------------------------------------------
    // Task enumeration (§3.1–§3.4)
    // -----------------------------------------------------------------------

    /// Walk `Shared.owned`'s sharded intrusive lists and parse every task.
    ///
    /// Corrupt memory degrades per shard: the failing shard contributes an
    /// error, the rest of the listing is unaffected (§11.5).
    pub fn enumerate_tasks(&self, shared: &TypeInfo<'b, BundleType<'b>>) -> Result<TaskList> {
        let list = shared.member("owned")?.member("list")?.to_owned();

        let mut tasks = Vec::new();
        let mut errors = Vec::new();
        // Guards against cycles from corrupt memory, across shards: the
        // same Header must never appear twice.
        let mut visited = HashSet::new();
        let mut shard = 0usize;

        list.as_ref()
            .member("lists")?
            .boxed_slice_elements(self, |elem| {
                let this_shard = shard;
                shard += 1;

                let head = elem.member("data")?.member("head")?;
                let head_addr = match head.try_select_variant("Some")? {
                    Some(ptr) => ptr.parse::<u64, _>(self)?,
                    None => return Ok(()),
                };

                let mut cur = Some(head_addr);
                while let Some(addr) = cur {
                    let step = (|| -> Result<Option<u64>> {
                        ensure!(
                            self.mappings.contains_addr(addr),
                            "task pointer {addr:#x} is unmapped"
                        );
                        ensure!(visited.insert(addr), "owned-task list cycle at {addr:#x}");
                        let (task, next) = self.parse_task(addr)?;
                        tasks.push(task);
                        Ok(next)
                    })();
                    match step {
                        Ok(next) => cur = next,
                        Err(e) => {
                            errors.push(e.context(format!(
                                "task walk failed in shard {this_shard} at {addr:#x}"
                            )));
                            break;
                        }
                    }
                }
                Ok(())
            })
            .context("failed to walk OwnedTasks shards")?;

        tasks.sort_by_key(|t| (t.task_id.is_none(), t.task_id, t.addr.0));
        Ok(TaskList { tasks, errors })
    }

    /// Parse one task from its `Header` address; returns the task and the
    /// next Header in the owned list (via `Trailer.owned`, §3.1).
    fn parse_task(&self, addr: u64) -> Result<(Task, Option<u64>)> {
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        let info = TypeInfo::from_addr(self, header_ty, addr)
            .with_context(|| format!("failed to read task Header at {addr:#x}"))?;

        let state = TaskState(info.member("state")?.parse(self)?);
        let owner_id = info.member("owner_id")?.parse(self)?;

        let vtable_addr: u64 = info.member("vtable")?.parse(self)?;
        let vtable = self
            .task_vtable(vtable_addr)
            .with_context(|| format!("failed to read task vtable at {vtable_addr:#x}"))?;

        let raw_id = self.proc.read_u64(addr + vtable.id_offset).map_err(|e| {
            anyhow!(e).context(format!(
                "failed to read task id at {addr:#x}+{:#x}",
                vtable.id_offset
            ))
        })?;
        // The id is a NonZeroU64; zero means we misread something.
        let task_id = (raw_id != 0).then_some(raw_id);

        let spawn_location = match vtable.spawn_location_offset {
            Some(off) => {
                let loc_ptr = self
                    .proc
                    .read_u64(addr + off)
                    .map_err(|e| anyhow!(e).context("failed to read spawn location pointer"))?;
                Some(self.read_location(loc_ptr)?)
            }
            None => None,
        };

        let future = self.resolve_future(&vtable);
        if let FutureInfo::Known(known) = &future {
            self.cross_check_offsets(&vtable, known)?;
        }

        let next = self
            .owned_next(addr + vtable.trailer_offset)
            .context("failed to read Trailer.owned links")?;

        let task = Task {
            addr: TaskAddr(addr),
            state,
            owner_id,
            task_id,
            spawn_location,
            future,
        };
        Ok((task, next))
    }

    /// Decode a `task::raw::Vtable` from target memory using the bundle's
    /// layout — the struct is `#[repr(Rust)]`, so offsets must never be
    /// assumed from declaration order (§3.3).
    fn task_vtable(&self, vtable_addr: u64) -> Result<TaskVtable> {
        if let Some(vt) = self.vtables.borrow().get(&vtable_addr) {
            return Ok(vt.clone());
        }

        let ty = self.infra_ty(self.view.bundle().infra.vtable, "task Vtable")?;
        let info = TypeInfo::from_addr(self, ty, vtable_addr)?;
        let field = |name: &str| -> Result<Option<u64>> {
            match info.try_member(name)? {
                Some(m) => Ok(Some(m.parse(self)?)),
                None => Ok(None),
            }
        };
        let required = |name: &str| -> Result<u64> {
            field(name)?.ok_or_else(|| anyhow!("bundle Vtable layout has no {name:?} member"))
        };

        let vt = TaskVtable {
            poll: required("poll")?,
            dealloc: field("dealloc")?,
            try_read_output: field("try_read_output")?,
            drop_join_handle_slow: field("drop_join_handle_slow")?,
            drop_abort_handle: field("drop_abort_handle")?,
            shutdown: field("shutdown")?,
            trailer_offset: required("trailer_offset")?,
            id_offset: required("id_offset")?,
            // Only present under `tokio_unstable` + task instrumentation.
            spawn_location_offset: field("spawn_location_offset")?,
        };
        self.vtables.borrow_mut().insert(vtable_addr, vt.clone());
        Ok(vt)
    }

    /// The v0 pivot (§3.3): resolve the vtable's monomorphized fns via the
    /// target's symtab and join them against the bundle's task table.
    /// Falls through the sibling vtable fns before giving up; never guesses.
    fn resolve_future(&self, vt: &TaskVtable) -> FutureInfo {
        let candidates = [
            Some(vt.poll),
            vt.dealloc,
            vt.try_read_output,
            vt.drop_join_handle_slow,
            vt.drop_abort_handle,
            vt.shutdown,
        ];
        for addr in candidates.into_iter().flatten() {
            let Some(symbol) = self.symbol_at(addr) else {
                continue;
            };
            let Some((entry_id, entry)) = self.view.task_entry_for_symbol(&symbol) else {
                continue;
            };
            let display_name = self
                .view
                .str(entry.display_name)
                .unwrap_or("<anon>")
                .to_owned();
            let provenance = self.view.provenance(entry_id);
            let decl = provenance
                .and_then(|p| p.decl)
                .and_then(|loc| Some((self.view.str(loc.file)?.to_owned(), loc.line)));
            let kind = provenance.map(|p| p.kind).unwrap_or(FutureKind::Manual);
            return FutureInfo::Known(KnownFuture {
                entry: entry_id,
                display_name,
                kind,
                decl,
                symbol,
            });
        }
        FutureInfo::Unknown {
            poll_symbol: self.symbol_at(vt.poll),
        }
    }

    /// Cheap bundle/target mismatch canary (§3.3): the offsets stored in the
    /// target's vtable must equal the ones computed from the bundle's
    /// `Cell<T, S>` layout. Disagreement is a hard diagnostic, not a silent
    /// misparse.
    fn cross_check_offsets(&self, vt: &TaskVtable, known: &KnownFuture) -> Result<()> {
        let entry = self.task_entry(known.entry);
        let Some(cell) = self.view.ty(entry.cell) else {
            return Ok(());
        };
        // The Cell may be an opaque placeholder if extraction could not
        // bind it; nothing to check then.
        let Some(trailer) = cell.member("trailer") else {
            return Ok(());
        };
        ensure!(
            trailer.offset() == vt.trailer_offset,
            "bundle/target layout mismatch for {}: bundle Cell.trailer at {:#x}, \
             target vtable trailer_offset {:#x}",
            known.display_name,
            trailer.offset(),
            vt.trailer_offset
        );
        if let Some(core) = cell.member("core")
            && let Some(task_id) = core.ty().member("task_id")
        {
            let expected = core.offset() + task_id.offset();
            ensure!(
                expected == vt.id_offset,
                "bundle/target layout mismatch for {}: bundle Core.task_id at {:#x}, \
                 target vtable id_offset {:#x}",
                known.display_name,
                expected,
                vt.id_offset
            );
        }
        Ok(())
    }

    fn task_entry(&self, id: TaskEntryId) -> &'b TaskFutureEntry {
        // Ids handed out by task_entry_for_symbol always index the table.
        &self.view.bundle().tasks.entries[id.0 as usize]
    }

    /// Read a `core::panic::Location` from target memory. The strings live
    /// in the *target's* rodata; the bundle only supplies the layout.
    fn read_location(&self, loc_ptr: u64) -> Result<Location> {
        let ty = self.infra_ty(self.view.bundle().infra.location, "core::panic::Location")?;
        let info = TypeInfo::from_addr(self, ty, loc_ptr)
            .with_context(|| format!("failed to read Location at {loc_ptr:#x}"))?;
        let file_info = match info.try_member("filename")? {
            Some(m) => m,
            // Pre-rename std spells the field `file`.
            None => info.member("file")?,
        };
        let filename = file_info.parse(self)?;
        let line = info.member("line")?.parse(self)?;
        let col = info.member("col")?.parse(self)?;
        Ok(Location {
            filename,
            line,
            col,
        })
    }

    /// Follow the owned-list link out of a task's `Trailer` (§3.1: the
    /// next/prev pointers live in `Trailer.owned`, not the Header).
    fn owned_next(&self, trailer_addr: u64) -> Result<Option<u64>> {
        let ty = self.infra_ty(self.view.bundle().infra.trailer, "task Trailer")?;
        let info = TypeInfo::from_addr(self, ty, trailer_addr)
            .with_context(|| format!("failed to read Trailer at {trailer_addr:#x}"))?;
        // Trailer.owned: linked_list::Pointers<Header>, which peels down to
        // its inner { prev, next } struct.
        let next = info
            .member("owned")?
            .member("next")?
            .try_select_variant("Some")?
            .map(|ptr| ptr.parse(self))
            .transpose()?;
        Ok(next)
    }

    // -----------------------------------------------------------------------
    // Task tracing (§3.4–§3.5)
    // -----------------------------------------------------------------------

    /// Decode a task's `Stage<T>` (§3.4): the future lives at
    /// `header_addr + offset(Cell.core) + offset(Core.stage)`, and the
    /// stage's discriminant says whether the state machine is resident.
    ///
    /// Requires the future type to have been resolved (§3.3); an unknown
    /// future has no `Cell` layout to interpret the memory with, and we
    /// never guess.
    pub fn task_stage(&self, task: &Task) -> Result<TaskStage<'b>> {
        let known = match &task.future {
            FutureInfo::Known(known) => known,
            FutureInfo::Unknown { poll_symbol } => {
                let sym = poll_symbol
                    .as_ref()
                    .map(|s| format!(" (poll symbol {s})"))
                    .unwrap_or_default();
                bail!("the task's future type is not in the bundle{sym}; nothing can be traced");
            }
        };
        let entry = self.task_entry(known.entry);
        let cell_ty = self.infra_ty(entry.cell, &format!("the Cell of {}", known.display_name))?;
        let cell = TypeInfo::from_addr(self, cell_ty, task.addr.0)
            .with_context(|| format!("failed to read the task Cell at {:?}", task.addr))?;
        // Cell.core.stage peels through CoreStage and the UnsafeCells down
        // to the Stage<T> enum.
        let stage = cell.member("core")?.member("stage")?;
        let (state, payload) = stage
            .active_variant()
            .context("failed to decode the task's Stage")?;
        match state {
            // The payload peels to its single sized member: T itself for
            // Running, Result<T::Output, JoinError> for Finished.
            "Running" => Ok(TaskStage::Running(payload.to_owned())),
            "Finished" => Ok(TaskStage::Finished(payload.to_owned())),
            "Consumed" => Ok(TaskStage::Consumed),
            other => bail!("unexpected Stage variant {other:?}"),
        }
    }

    /// Walk a resident future's await chain (§3.5), outermost future
    /// first.
    ///
    /// The walk never fails outright: whatever decoded cleanly is in
    /// [`AwaitChain::frames`], and [`AwaitChain::end`] says why it
    /// stopped. Corrupt memory is contained by the depth bound and an
    /// (address, type) cycle guard.
    pub fn await_chain(&self, root: TypeInfo<'b, BundleType<'b>>) -> AwaitChain<'b> {
        let mut frames: Vec<AwaitFrame<'b>> = Vec::new();
        let mut visited: HashSet<(u64, BundleTypeId)> = HashSet::new();
        let mut cur = root;
        // The dyn-vtable symbol that identified `cur`, when it was not
        // reached structurally.
        let mut dyn_symbol: Option<String> = None;

        let end = loop {
            if frames.len() >= MAX_AWAIT_DEPTH {
                break ChainEnd::DepthLimit;
            }
            if !visited.insert((cur.addr, cur.ty.id())) {
                break ChainEnd::Cycle { addr: cur.addr };
            }

            // A future that *is* a dyn wide pointer (a spawned
            // `Pin<Box<dyn Future>>`): resolve the concrete type through
            // its vtable before decoding anything.
            if let Some(dp) = cur.as_ref().peel().ty.dyn_pointer() {
                match self.resolve_dyn_future(&cur.as_ref().peel(), &dp) {
                    Ok(DynAwaitee::Resolved { future, symbol }) => {
                        cur = future;
                        dyn_symbol = Some(symbol);
                        continue;
                    }
                    Ok(DynAwaitee::Unknown { poll_symbol }) => {
                        break ChainEnd::UnknownDyn {
                            pointee: dp.pointee.name().to_owned(),
                            poll_symbol,
                        };
                    }
                    Err(e) => break ChainEnd::Error(e),
                }
            }

            // Decode the coroutine state. Non-enums are leaf futures:
            // sync primitives, I/O futures, combinator structs.
            let decoded = match cur.ty.active_variant(&cur.buf) {
                None => {
                    frames.push(AwaitFrame {
                        future: cur,
                        state: None,
                        dyn_symbol,
                    });
                    break ChainEnd::Leaf;
                }
                Some(Ok(v)) => v,
                Some(Err(e)) => {
                    let err = anyhow!(e).context(format!(
                        "failed to decode the state of {} at {:#x}",
                        cur.ty.name(),
                        cur.addr,
                    ));
                    frames.push(AwaitFrame {
                        future: cur,
                        state: None,
                        dyn_symbol,
                    });
                    break ChainEnd::Error(err);
                }
            };

            // Coroutine variant members are numbered; their state names
            // live on the payload structs (§5.5). Ordinary enums (sync
            // primitives, combinators like MaybeDone) are leaves: an
            // await chain is linear, while a combinator may hold several
            // pending futures — per-combinator knowledge is §9 scope.
            let is_coroutine_state =
                !decoded.name.is_empty() && decoded.name.bytes().all(|b| b.is_ascii_digit());

            // Slice out the variant payload *without* peeling: its
            // members are the state's live locals.
            let start = decoded.offset as usize;
            let size = decoded.ty.size() as usize;
            let Some(bytes) = cur.buf.get(start..start + size) else {
                let err = anyhow!(
                    "variant payload {}..{} does not fit {} bytes of {}",
                    start,
                    start + size,
                    cur.buf.len(),
                    cur.ty.name(),
                );
                frames.push(AwaitFrame {
                    future: cur,
                    state: None,
                    dyn_symbol,
                });
                break ChainEnd::Error(err);
            };
            let payload = TypeInfoRef::new(decoded.ty, cur.addr + decoded.offset, bytes).to_owned();
            frames.push(AwaitFrame {
                future: cur,
                state: Some(FrameState {
                    name: decoded.state_name(),
                    await_loc: decoded.decl,
                    payload,
                }),
                dyn_symbol: dyn_symbol.take(),
            });
            if !is_coroutine_state {
                break ChainEnd::Leaf;
            }

            // A suspended coroutine stores what it awaits in the
            // variant's `__awaitee` member; states that aren't waiting
            // (Unresumed, Returned, Panicked) have none.
            let payload = &frames.last().unwrap().state.as_ref().unwrap().payload;
            let Some(member) = payload.ty.member("__awaitee") else {
                break ChainEnd::Leaf;
            };
            let start = member.offset() as usize;
            let size = member.ty().size() as usize;
            let Some(bytes) = payload.buf.get(start..start + size) else {
                break ChainEnd::Error(anyhow!(
                    "__awaitee {}..{} does not fit {} bytes of {}",
                    start,
                    start + size,
                    payload.buf.len(),
                    payload.ty.name(),
                ));
            };
            let awaitee = TypeInfoRef::new(member.ty(), payload.addr + member.offset(), bytes);

            // Wrappers (Pin, mainly) hide what the pointer-shaped
            // awaitees really are; plain awaitees keep their own type so
            // the chain reports e.g. `oneshot::Receiver<u32>` rather than
            // whatever its innards peel down to.
            let peeled = awaitee.clone().peel();
            if let Some(dp) = peeled.ty.dyn_pointer() {
                // A boxed trait object: only its vtable knows the
                // concrete type (§3.5).
                match self.resolve_dyn_future(&peeled, &dp) {
                    Ok(DynAwaitee::Resolved { future, symbol }) => {
                        cur = future;
                        dyn_symbol = Some(symbol);
                    }
                    Ok(DynAwaitee::Unknown { poll_symbol }) => {
                        break ChainEnd::UnknownDyn {
                            pointee: dp.pointee.name().to_owned(),
                            poll_symbol,
                        };
                    }
                    Err(e) => break ChainEnd::Error(e),
                }
            } else if peeled.ty.pointer_target().is_some() {
                // `(&mut fut).await`, `Box<fut>`: follow the thin pointer.
                match peeled.deref_ptr(self) {
                    Ok(info) => cur = info,
                    Err(e) => {
                        break ChainEnd::Error(
                            anyhow!(e).context("failed to follow an awaited pointer"),
                        );
                    }
                }
            } else {
                cur = awaitee.to_owned();
            }
        };

        AwaitChain { frames, end }
    }

    /// Resolve a `dyn Future` wide pointer (§3.5): read its data and
    /// vtable pointers from the already-read payload bytes, resolve the
    /// vtable's poll fn — or its drop glue, for polls internalized out of
    /// the symtab — through the *target's* symtab, and join the mangled
    /// symbol against the bundle's dyn-future table. Never guesses.
    fn resolve_dyn_future(
        &self,
        ptr: &TypeInfoRef<'_, 'b, BundleType<'b>>,
        dp: &DynPointer<'b>,
    ) -> Result<DynAwaitee<'b>> {
        let word = |off: u64| -> Result<u64> {
            let bytes = ptr
                .bytes
                .get(off as usize..off as usize + 8)
                .ok_or_else(|| anyhow!("wide-pointer bytes truncated at +{off:#x}"))?;
            Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
        };
        let data = word(dp.data_offset)?;
        let vtable = word(dp.vtable_offset)?;
        ensure!(
            self.mappings.contains_addr(data),
            "dyn future data pointer {data:#x} is unmapped"
        );
        ensure!(
            self.mappings.contains_addr(vtable),
            "dyn future vtable pointer {vtable:#x} is unmapped"
        );

        let mut poll_symbol = None;
        for slot in [VTABLE_SLOT_FUTURE_POLL, VTABLE_SLOT_DROP] {
            let fn_addr = self.proc.read_u64(vtable + slot * 8).map_err(|e| {
                anyhow!(e).context(format!("failed to read slot {slot} of vtable {vtable:#x}"))
            })?;
            let Some(symbol) = self.symbol_at(fn_addr) else {
                continue;
            };
            if slot == VTABLE_SLOT_FUTURE_POLL {
                poll_symbol = Some(symbol.clone());
            }
            if let Some(ty) = self.view.dyn_future_for_symbol(&symbol) {
                let future = TypeInfo::from_addr(self, ty, data)
                    .with_context(|| format!("failed to read {} at {data:#x}", ty.name()))?;
                return Ok(DynAwaitee::Resolved { future, symbol });
            }
        }
        Ok(DynAwaitee::Unknown { poll_symbol })
    }
}

impl<T: Target> ParseCtx for Context<'_, T> {
    type Target = T;

    fn proc(&self) -> &T {
        self.proc
    }

    fn mappings(&self) -> &Mappings {
        &self.mappings
    }
}

/// Result of resolving the bundle's symbol fingerprint against the target
/// (§5.1).
#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub total: usize,
    pub matched: usize,
    pub missing: Vec<String>,
}

impl Fingerprint {
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// A thread with a live `tokio::runtime::context::Context`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Worker {
    pub tid: u32,
    pub context_addr: u64,
    /// The task this thread is polling right now, if any.
    pub current_task_id: Option<u64>,
}

/// A task vtable decoded from target memory (bundle layout, target values).
#[derive(Clone, Debug)]
struct TaskVtable {
    poll: u64,
    dealloc: Option<u64>,
    try_read_output: Option<u64>,
    drop_join_handle_slow: Option<u64>,
    drop_abort_handle: Option<u64>,
    shutdown: Option<u64>,
    trailer_offset: u64,
    id_offset: u64,
    spawn_location_offset: Option<u64>,
}

/// The result of walking every owned-task shard.
#[derive(Debug)]
pub struct TaskList {
    /// Sorted by task id (tasks with no readable id last, by address).
    pub tasks: Vec<Task>,
    /// Per-shard walk failures; the shards that produced `tasks` are
    /// unaffected by these.
    pub errors: Vec<anyhow::Error>,
}

/// One enumerated task.
#[derive(Debug)]
pub struct Task {
    pub addr: TaskAddr,
    pub state: TaskState,
    pub owner_id: Option<u64>,
    pub task_id: Option<u64>,
    /// Where the task was spawned, when the target records it
    /// (`tokio_unstable` task instrumentation).
    pub spawn_location: Option<Location>,
    pub future: FutureInfo,
}

/// The task's concrete future type, resolved via the symbol join — or not.
#[derive(Debug)]
pub enum FutureInfo {
    Known(KnownFuture),
    /// No vtable fn symbol matched the bundle's task table. The raw symbol
    /// is reported so the operator can see what the target called it;
    /// nothing is guessed.
    Unknown {
        poll_symbol: Option<String>,
    },
}

/// A future resolved through the bundle's task join table.
#[derive(Debug)]
pub struct KnownFuture {
    pub entry: TaskEntryId,
    /// Demangled name of the future type (display only).
    pub display_name: String,
    pub kind: FutureKind,
    /// Source file/line where the future is defined (§5.5 provenance).
    pub decl: Option<(String, u32)>,
    /// The mangled vtable-fn symbol the join matched on.
    pub symbol: String,
}

/// A task's decoded `Stage<T>` (§3.4).
#[derive(Debug)]
pub enum TaskStage<'b> {
    /// The state machine is resident; walk it with
    /// [`Context::await_chain`].
    Running(TypeInfo<'b, BundleType<'b>>),
    /// `Result<T::Output, JoinError>`: the task returned, panicked, or
    /// was cancelled, and the output has not been consumed yet.
    Finished(TypeInfo<'b, BundleType<'b>>),
    /// The output was already taken through the join handle.
    Consumed,
}

/// The await chain of a resident future (§3.5), outermost future first.
#[derive(Debug)]
pub struct AwaitChain<'b> {
    pub frames: Vec<AwaitFrame<'b>>,
    /// Why the walk stopped; anything but [`ChainEnd::Leaf`] left the
    /// chain incomplete.
    pub end: ChainEnd,
}

/// One future in an await chain.
#[derive(Debug)]
pub struct AwaitFrame<'b> {
    /// The future being polled at this depth.
    pub future: TypeInfo<'b, BundleType<'b>>,
    /// The decoded coroutine state; `None` for plain (leaf) futures.
    pub state: Option<FrameState<'b>>,
    /// The mangled symbol that identified this frame, when it was
    /// reached through a `dyn Future` vtable in target memory.
    pub dyn_symbol: Option<String>,
}

/// A coroutine frame's decoded state.
#[derive(Debug)]
pub struct FrameState<'b> {
    /// The human-readable state name (`Unresumed`, `Suspend0`, …).
    pub name: &'b str,
    /// The awaited expression's source location, when the debug info
    /// recorded it (§5.5).
    pub await_loc: Option<(&'b str, u32)>,
    /// The active variant's payload: the state's live locals, including
    /// compiler-generated `__…` slots and the `__awaitee` itself.
    pub payload: TypeInfo<'b, BundleType<'b>>,
}

/// Why an await-chain walk stopped.
#[derive(Debug)]
pub enum ChainEnd {
    /// Bottomed out normally: a non-coroutine leaf future, or a state
    /// with nothing awaited.
    Leaf,
    /// A `dyn Future` awaitee whose vtable symbols joined nothing in the
    /// bundle; the raw poll symbol is reported and nothing is guessed
    /// (§3.3).
    UnknownDyn {
        /// The `dyn Trait` spelling, for display.
        pointee: String,
        /// The mangled symbol the vtable's poll slot resolved to, if any.
        poll_symbol: Option<String>,
    },
    /// The depth bound was hit.
    DepthLimit,
    /// The same (address, type) pair reappeared.
    Cycle { addr: u64 },
    /// Reading or decoding below the last frame failed.
    Error(anyhow::Error),
}

/// The outcome of resolving one `dyn Future` awaitee.
enum DynAwaitee<'b> {
    /// The vtable joined: the concrete future, read from target memory,
    /// and the symbol that identified it.
    Resolved {
        future: TypeInfo<'b, BundleType<'b>>,
        symbol: String,
    },
    /// No vtable symbol joined the bundle's dyn-future table.
    Unknown { poll_symbol: Option<String> },
}

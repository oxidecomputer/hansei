//! Phase 1 of extraction: one sweep over every subprogram classifies task
//! vtable fns into per-`(T, S)` seeds, collects `<T as Future>::poll` impls
//! and `drop_glue::<T>` instantiations for the dyn-future table, and records
//! coroutine resume locations. The phase-2 binding helpers that recover a
//! seed's `Cell<T, S>` and `Stage<T>` live here too.

use super::paths::{OwnedLoc, owned_loc};
use super::strip;
use crate::detect::struct_of;
use crate::raw_types::{NsId, RawType};
use crate::view::{DwView, Func};
use crate::{DwReader, FuncId, TypeId};

use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use tracing::debug;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The task vtable functions (`tokio::runtime::task::raw`); any of their
/// symbols resolved from a target identifies the instantiation.
const VTABLE_FNS: [&str; 6] = [
    "poll",
    "dealloc",
    "try_read_output",
    "drop_join_handle_slow",
    "drop_abort_handle",
    "shutdown",
];

/// Demangled suffix of `<T as core::future::Future>::poll` impls.
const FUTURE_POLL_SUFFIX: &str = " as core::future::future::Future>::poll";

/// Below this many subprograms, sweeping them by hand beats spawning threads.
const SWEEP_PARALLEL_THRESHOLD: usize = 4096;

/// Contributions gathered by phase 1's subprogram sweep. Accumulated per
/// worker and merged so the sweep — dominated by demangling every `poll*`
/// symbol — can run in parallel.
#[derive(Default)]
pub(super) struct Sweep {
    /// (T, S) → accumulating seed.
    pub(super) seeds: BTreeMap<(TypeId, TypeId), TaskSeed>,
    /// Canonical T → mangled `<T as Future>::poll` symbols.
    pub(super) fut_polls: BTreeMap<TypeId, BTreeSet<String>>,
    /// Canonical T → mangled `drop_glue::<T>` symbols.
    pub(super) drop_glues: BTreeMap<TypeId, BTreeSet<String>>,
    /// `drop_glue<T>` display name's inner text → symbols, for glue DIEs
    /// without a template-parameter reference.
    pub(super) glue_by_name: BTreeMap<String, BTreeSet<String>>,
    /// Coroutine env → its resume fn's declaration coordinates.
    pub(super) resume_locs: BTreeMap<TypeId, OwnedLoc>,
    /// Coroutine env → the `__awaitee` locals of its resume fn: where each
    /// of its awaits is *written*, which for an await produced by a macro
    /// is not where the coroutine type says it is.
    pub(super) resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
    pub(super) vtable_missing_linkage: usize,
    pub(super) dyn_decl_only_self: usize,
    pub(super) dyn_unresolved_self: usize,
}

impl Sweep {
    /// Fold another worker's contributions in. Called in chunk (i.e. source)
    /// order, so the "first wins" fields resolve exactly as a serial sweep.
    fn merge(&mut self, other: Sweep) {
        for (key, seed) in other.seeds {
            let dst = self.seeds.entry(key).or_default();
            dst.symbols.extend(seed.symbols);
            dst.poll_symbols.extend(seed.poll_symbols);
            if dst.dealloc_param.is_none() {
                dst.dealloc_param = seed.dealloc_param;
            }
            if dst.poll_func_loc.is_none() {
                dst.poll_func_loc = seed.poll_func_loc;
            }
        }
        for (t, syms) in other.fut_polls {
            self.fut_polls.entry(t).or_default().extend(syms);
        }
        for (t, syms) in other.drop_glues {
            self.drop_glues.entry(t).or_default().extend(syms);
        }
        for (name, syms) in other.glue_by_name {
            self.glue_by_name.entry(name).or_default().extend(syms);
        }
        for (t, loc) in other.resume_locs {
            self.resume_locs.entry(t).or_insert(loc);
        }
        for (t, awaitees) in other.resume_awaitees {
            self.resume_awaitees.entry(t).or_insert(awaitees);
        }
        self.vtable_missing_linkage += other.vtable_missing_linkage;
        self.dyn_decl_only_self += other.dyn_decl_only_self;
        self.dyn_unresolved_self += other.dyn_unresolved_self;
    }
}

/// Sweep every subprogram into task seeds, dyn-future poll symbols, drop glue,
/// and coroutine resume locations. The per-function classification is
/// read-only over the reader and independent, so it is fanned out across a
/// thread pool and the per-worker [`Sweep`]s merged in source order.
pub(super) fn sweep_functions(
    view: &DwView<'_>,
    raw_ns: Option<NsId>,
    glue_ns: Option<NsId>,
) -> Sweep {
    let reader = view.collector();
    // Sorted by id, i.e. by `.debug_info` offset, because the sweep's
    // "first wins" fields make the order observable and the reader hands
    // functions out in the order of a randomly seeded hash map — the same
    // program would otherwise pick a different `__awaitee` list, resume
    // location, or `poll` declaration on each run.
    let mut funcs: Vec<(FuncId, Func)> = view.functions().collect();
    funcs.sort_unstable_by_key(|&(id, _)| id);
    let funcs: Vec<Func> = funcs.into_iter().map(|(_, func)| func).collect();

    if funcs.len() < SWEEP_PARALLEL_THRESHOLD {
        let mut out = Sweep::default();
        for func in &funcs {
            sweep_function(reader, raw_ns, glue_ns, func, &mut out);
        }
        return out;
    }

    // Collecting the per-chunk sweeps keeps the merge in chunk (i.e. source)
    // order, which the "first wins" fields require.
    let chunk = funcs.len().div_ceil(rayon::current_num_threads());
    let sweeps: Vec<Sweep> = funcs
        .par_chunks(chunk)
        .map(|chunk| {
            let mut out = Sweep::default();
            for func in chunk {
                sweep_function(reader, raw_ns, glue_ns, func, &mut out);
            }
            out
        })
        .collect();
    let mut merged = Sweep::default();
    for sweep in sweeps {
        merged.merge(sweep);
    }
    merged
}

/// Classify one subprogram into `out`: a task vtable fn, drop glue, a coroutine
/// resume fn, or a `Future::poll` impl.
fn sweep_function(
    reader: &DwReader<'_>,
    raw_ns: Option<NsId>,
    glue_ns: Option<NsId>,
    func: &Func<'_>,
    out: &mut Sweep,
) {
    let Some(name) = func.name() else { return };

    if func.namespace_id() == raw_ns && raw_ns.is_some() {
        let Some(vtable_fn) = VTABLE_FNS
            .iter()
            .find(|v| name.strip_prefix(*v).is_some_and(|r| r.starts_with('<')))
        else {
            return;
        };
        let Some(linkage) = func.linkage_name() else {
            out.vtable_missing_linkage += 1;
            return;
        };
        let mut t = None;
        let mut s = None;
        for p in func.template_params() {
            match p.name() {
                Some("T") => t = Some(reader.canonicalize(p.type_id())),
                Some("S") => s = Some(reader.canonicalize(p.type_id())),
                _ => {}
            }
        }
        let (Some(t), Some(s)) = (t, s) else {
            debug!("vtable fn without T/S template params: {name}");
            return;
        };
        let seed = out.seeds.entry((t, s)).or_default();
        seed.symbols.insert(strip(linkage).to_owned());
        if *vtable_fn == "poll" {
            seed.poll_symbols.insert(strip(linkage).to_owned());
            if seed.poll_func_loc.is_none() {
                seed.poll_func_loc = func.source_loc().map(|l| owned_loc(&l));
            }
        }
        if *vtable_fn == "dealloc" && seed.dealloc_param.is_none() {
            seed.dealloc_param = func.params().next().and_then(|p| p.raw().type_id);
        }
    } else if func.namespace_id() == glue_ns && glue_ns.is_some() && name.starts_with("drop_glue<")
    {
        let Some(linkage) = func.linkage_name() else {
            return;
        };
        let params: Vec<_> = func.template_params().collect();
        if let [p] = params.as_slice() {
            out.drop_glues
                .entry(reader.canonicalize(p.type_id()))
                .or_default()
                .insert(strip(linkage).to_owned());
        } else if let Some(inner) = name
            .strip_prefix("drop_glue<")
            .and_then(|r| r.strip_suffix('>'))
        {
            out.glue_by_name
                .entry(inner.to_owned())
                .or_default()
                .insert(strip(linkage).to_owned());
        }
    } else if name.starts_with("{async_fn#")
        || name.starts_with("{async_block#")
        || name.starts_with("{closure#")
    {
        // Coroutine resume functions are the compiler-generated
        // `<env as Future>::poll` bodies — the symbols `dyn Future` vtables
        // actually point at for async fn/block awaitees. Recognized by shape:
        // `fn(Pin<&mut T>) -> Poll<…>` with a coroutine-env self type.
        let Some(linkage) = func.linkage_name() else {
            return;
        };
        let poll_shaped = func
            .raw()
            .return_type_id
            .and_then(|id| reader.canonical_type(id))
            .and_then(|t| t.name())
            .is_some_and(|n| reader.strings.get(n).starts_with("Poll<"));
        if !poll_shaped {
            return;
        }
        match future_poll_self_type(reader, func) {
            Ok(t) if is_coroutine_env(reader, t) => {
                out.fut_polls
                    .entry(t)
                    .or_default()
                    .insert(strip(linkage).to_owned());
                if let Some(loc) = func.source_loc() {
                    out.resume_locs.entry(t).or_insert_with(|| owned_loc(&loc));
                }
                let awaitees = func.raw().awaitees.as_ref();
                if !awaitees.is_empty() {
                    out.resume_awaitees.entry(t).or_insert_with(|| {
                        awaitees
                            .iter()
                            .map(|a| {
                                let loc = a.source_loc.as_deref();
                                (
                                    a.type_id,
                                    OwnedLoc {
                                        file: loc
                                            .and_then(|l| l.file)
                                            .map(|f| reader.strings.get(f).to_owned()),
                                        dir: loc
                                            .and_then(|l| l.dir)
                                            .map(|d| reader.strings.get(d).to_owned()),
                                        comp_dir: loc
                                            .and_then(|l| l.comp_dir)
                                            .map(|d| reader.strings.get(d).to_owned()),
                                        line: loc.and_then(|l| l.line).map(|n| n.get()),
                                    },
                                )
                            })
                            .collect()
                    });
                }
            }
            _ => {}
        }
    } else if let Some(linkage) = func.linkage_name() {
        // `<T as Future>::poll` impls live in `{impl#N}` namespaces; the trait
        // path is only visible in the mangled name.
        if !name.starts_with("poll") {
            return;
        }
        let demangled = format!("{:#}", rustc_demangle::demangle(linkage));
        if !demangled.ends_with(FUTURE_POLL_SUFFIX) {
            return;
        }
        match future_poll_self_type(reader, func) {
            Ok(t) => {
                out.fut_polls
                    .entry(t)
                    .or_default()
                    .insert(strip(linkage).to_owned());
            }
            Err(SelfRecovery::DeclOnly) => {
                // Fully-inlined blanket impls (`Pin<P>`, `&mut F`) whose self
                // type DIE is a bare declaration. Those types never back a
                // `dyn Future` vtable, so nothing is lost.
                debug!("declaration-only Future::poll self type: {demangled}");
                out.dyn_decl_only_self += 1;
            }
            Err(SelfRecovery::Unresolved) => {
                debug!("cannot recover T from Future::poll self param: {demangled}");
                out.dyn_unresolved_self += 1;
            }
        }
    }
}

/// Accumulates the vtable fns of one `(T, S)` instantiation during the
/// subprogram sweep.
#[derive(Default)]
pub(super) struct TaskSeed {
    pub(super) symbols: BTreeSet<String>,
    pub(super) poll_symbols: BTreeSet<String>,
    pub(super) dealloc_param: Option<TypeId>,
    pub(super) poll_func_loc: Option<OwnedLoc>,
}

/// Recover `Cell<T, S>` from `dealloc`'s first parameter
/// (`NonNull<Cell<T, S>>` → member `pointer` → pointee).
pub(super) fn cell_from_dealloc_param(
    reader: &DwReader<'_>,
    core_ns: Option<NsId>,
    param: TypeId,
) -> Option<TypeId> {
    let non_null = struct_of(reader, param)?;
    let ptr_member = non_null.members.first()?;
    let RawType::Pointer(p) = reader.canonical_type(ptr_member.type_id)? else {
        return None;
    };
    let cell_id = reader.canonicalize(p.target_type_id);
    let cell = struct_of(reader, cell_id)?;
    let name = cell.name.map(|n| reader.strings.get(n)).unwrap_or_default();
    (cell.namespace == core_ns && name.starts_with("Cell<")).then_some(cell_id)
}

/// Find `Stage<T>` by walking the member graph from `Cell<T, S>`
/// (`Cell.core.stage.stage.value` in current tokio, but discovered
/// structurally: the first enum named `Stage<…>` in `task::core`).
pub(super) fn find_stage(
    reader: &DwReader<'_>,
    core_ns: Option<NsId>,
    cell: TypeId,
) -> Option<TypeId> {
    let mut queue = VecDeque::from([(cell, 0usize)]);
    let mut seen = BTreeSet::new();
    while let Some((id, depth)) = queue.pop_front() {
        if depth > 8 || !seen.insert(id) {
            continue;
        }
        match reader.canonical_type(id)? {
            RawType::Enum(e) => {
                let name = e.name.map(|n| reader.strings.get(n)).unwrap_or_default();
                if e.namespace == core_ns && name.starts_with("Stage<") {
                    return Some(reader.canonicalize(id));
                }
            }
            RawType::Struct(st) => {
                for m in st.members.iter() {
                    queue.push_back((reader.canonicalize(m.type_id), depth + 1));
                }
            }
            RawType::Union(u) => {
                for m in u.members.iter() {
                    queue.push_back((reader.canonicalize(m.type_id), depth + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Why `T` could not be recovered from a poll fn's self parameter.
enum SelfRecovery {
    /// The `Pin<…>` self type's DIE is a declaration with no members.
    DeclOnly,
    /// Anything else: missing parameter, unexpected shape.
    Unresolved,
}

/// Recover `T` from a `<T as Future>::poll` impl's `self: Pin<&mut T>`
/// parameter, as a DIE reference.
fn future_poll_self_type(
    reader: &DwReader<'_>,
    func: &Func<'_>,
) -> std::result::Result<TypeId, SelfRecovery> {
    let unresolved = SelfRecovery::Unresolved;
    let param = func.params().next().ok_or(SelfRecovery::Unresolved)?;
    let pin_id = param.raw().type_id.ok_or(SelfRecovery::Unresolved)?;
    let Some(RawType::Struct(pin)) = reader.canonical_type(pin_id) else {
        return Err(unresolved);
    };
    let name = pin.name.map(|n| reader.strings.get(n)).unwrap_or_default();
    if !name.starts_with("Pin<") {
        return Err(unresolved);
    }
    let inner = pin.members.first().ok_or(SelfRecovery::DeclOnly)?;
    let Some(RawType::Pointer(p)) = reader.canonical_type(inner.type_id) else {
        return Err(unresolved);
    };
    Ok(reader.canonicalize(p.target_type_id))
}

/// Is this type a compiler-generated coroutine environment?
fn is_coroutine_env(reader: &DwReader<'_>, id: TypeId) -> bool {
    let Some(raw) = reader.canonical_type(id) else {
        return false;
    };
    raw.name()
        .map(|n| reader.strings.get(n))
        .is_some_and(|n| n.starts_with("{async_fn_env#") || n.starts_with("{async_block_env#"))
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Phase 1 of extraction: one sweep over every subprogram classifies task
//! vtable fns into per-`(T, S)` seeds, collects `<T as Future>::poll` impls
//! and `drop_glue::<T>` instantiations for the dyn-future table, and records
//! coroutine resume locations. The phase-2 binding helpers that recover a
//! seed's `Cell<T, S>` and `Stage<T>` live here too.

use super::paths::{OwnedLoc, owned_loc};
use super::strip;
use crate::detect::struct_of;
use crate::raw_types::{NsId, RawType, SourceLoc};
use crate::view::{DwView, Func};
use crate::{DwReader, FuncId, StrId, TypeId};

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

/// Demangled suffix of `<T as futures_core::Stream>::poll_next` impls.
/// tokio-stream re-exports the trait, so its wrappers mangle the same.
const STREAM_POLL_NEXT_SUFFIX: &str = " as futures_core::stream::Stream>::poll_next";

/// Demangled suffix of `<T as hyper::rt::Read>::poll_read` impls: the
/// read method a stream trait object's vtable names its concrete
/// stream by.
const HYPER_READ_SUFFIX: &str = " as hyper::rt::io::Read>::poll_read";

/// Below this many subprograms, sweeping them by hand beats spawning threads.
const SWEEP_PARALLEL_THRESHOLD: usize = 4096;

/// Contributions gathered by phase 1's subprogram sweep. Accumulated per
/// worker and merged so the sweep — dominated by demangling every `poll*`
/// symbol — can run in parallel.
#[derive(Default)]
pub(super) struct Sweep {
    /// (T, S) → accumulating seed.
    pub(super) seeds: BTreeMap<(TypeId, TypeId), TaskSeed>,
    /// Legacy dynamic lookup candidates, including coroutine resume shapes.
    pub(super) fut_polls: BTreeMap<TypeId, BTreeSet<String>>,
    /// Exact Future-trait poll evidence, independent of resume-function shape.
    pub(super) explicit_polls: BTreeMap<TypeId, BTreeSet<String>>,
    /// Linkage names of every `hyper::rt::Read::poll_read` impl, by the
    /// self type: what a stream trait object's read slot names.
    pub(super) stream_reads: BTreeMap<TypeId, BTreeSet<String>>,
    /// Where each explicit poll was declared: the implementing file, as
    /// the line table spells it, with its checksum when the table
    /// carries one. A third-party rule reads its origin — which crate,
    /// which version — off this path.
    pub(super) poll_sources: BTreeMap<TypeId, BTreeSet<PollSource>>,
    /// Where each explicit `Future::poll` or `Stream::poll_next` is
    /// *written*: the `Future` ones are the DIEs `poll_sources` screens,
    /// kept with their line; the `Stream` ones are screened here alone.
    /// Separate from `PollSource` because that type's identity decides
    /// how the origin rules dedupe.
    pub(super) poll_decls: BTreeMap<TypeId, Vec<(PollTrait, OwnedLoc)>>,
    /// Resume shapes requiring a reviewed compiler convention before they
    /// establish future identity or initialized storage.
    pub(super) coroutine_candidates: BTreeSet<TypeId>,
    /// Canonical T → mangled `drop_glue::<T>` symbols.
    pub(super) drop_glues: BTreeMap<TypeId, BTreeSet<String>>,
    /// `drop_glue<T>` display name's inner text → symbols, for glue DIEs
    /// without a template-parameter reference.
    pub(super) glue_by_name: BTreeMap<String, BTreeSet<String>>,
    /// Coroutine env → the `__awaitee` locals of its resume fn: where each
    /// of its awaits is *written*, which for an await produced by a macro
    /// is not where the coroutine type says it is.
    pub(super) resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
    /// Coroutine env → the named locals of its resume fn, each with
    /// where it is declared: the `let` behind a payload member of the
    /// env, which is what a task block prints as `declared at` under a
    /// value held in that local. Every unit's copy of the function
    /// contributes, unlike `resume_awaitees`: an optimized copy keeps
    /// only the variables it still needs, and which copy sorts first
    /// varies by platform, so one copy alone would drop a local one
    /// system's build retains and another's does not. The copies of
    /// one name agree or decline at emission. Reader-interned, not
    /// owned: the sweep sees every coroutine in the binary and only
    /// the emitted ones' locals are ever joined, so the strings are
    /// resolved per emitted coroutine at emission. Locals with no
    /// coordinates are dropped here — nothing could be recorded for
    /// them.
    pub(super) resume_locals: BTreeMap<TypeId, Vec<(StrId, SourceLoc<StrId>)>>,
    pub(super) vtable_missing_linkage: usize,
    pub(super) dyn_decl_only_self: usize,
    pub(super) dyn_unresolved_self: usize,
    /// `{impl#N}` namespace → the impl's self type path, recovered by
    /// demangling one member subprogram's linkage name (the namespace
    /// DIE itself records nothing). `None` caches a failed recovery so
    /// an impl full of unparseable members costs one demangle, not one
    /// per member.
    pub(super) impl_selfs: BTreeMap<NsId, Option<String>>,
}

/// One `poll`'s declaration file: the full path the unit's line table
/// spells for it, and the MD5 the table carries beside it, if any.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) struct PollSource {
    pub(super) path: String,
    pub(super) md5: Option<[u8; 16]>,
}

/// Which trait method a poll declaration is. A `StreamMap`'s entries
/// are `Stream`s, and their line is `poll_next`'s.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) enum PollTrait {
    Future,
    Stream,
}

/// The declaration file of `func`, joined the way the line table meant
/// it: an absolute file as is, a relative one under its directory, a
/// relative directory under the unit's compilation directory. `None`
/// when the function records no file. Also the source a `select!`
/// closure's declaration is read as, for the binder's origin check.
pub(super) fn poll_source(reader: &DwReader<'_>, func: &Func<'_>) -> Option<PollSource> {
    source_of(reader, func.raw().source_loc.as_deref()?)
}

/// The file a recorded location names, joined the way [`poll_source`]
/// says; `None` when it records no file.
pub(super) fn source_of(reader: &DwReader<'_>, loc: &SourceLoc<StrId>) -> Option<PollSource> {
    let file = reader.strings.get(loc.file?);
    let dir = loc
        .dir
        .map(|d| reader.strings.get(d))
        .filter(|d| !d.is_empty());
    let comp_dir = loc
        .comp_dir
        .map(|d| reader.strings.get(d))
        .filter(|d| !d.is_empty());
    let path = if file.starts_with('/') {
        file.to_owned()
    } else {
        let under_dir = match dir {
            Some(dir) => format!("{dir}/{file}"),
            None => file.to_owned(),
        };
        match comp_dir {
            Some(comp_dir) if !under_dir.starts_with('/') => format!("{comp_dir}/{under_dir}"),
            _ => under_dir,
        }
    };
    let md5 = loc
        .file_id
        .and_then(|id| reader.source_file(id))
        .and_then(|file| file.md5);
    Some(PollSource { path, md5 })
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
        for (t, syms) in other.stream_reads {
            self.stream_reads.entry(t).or_default().extend(syms);
        }
        for (t, syms) in other.explicit_polls {
            self.explicit_polls.entry(t).or_default().extend(syms);
        }
        for (t, sources) in other.poll_sources {
            self.poll_sources.entry(t).or_default().extend(sources);
        }
        for (t, decls) in other.poll_decls {
            self.poll_decls.entry(t).or_default().extend(decls);
        }
        self.coroutine_candidates.extend(other.coroutine_candidates);
        for (t, syms) in other.drop_glues {
            self.drop_glues.entry(t).or_default().extend(syms);
        }
        for (name, syms) in other.glue_by_name {
            self.glue_by_name.entry(name).or_default().extend(syms);
        }
        for (t, awaitees) in other.resume_awaitees {
            self.resume_awaitees.entry(t).or_insert(awaitees);
        }
        for (t, locals) in other.resume_locals {
            self.resume_locals.entry(t).or_default().extend(locals);
        }
        self.vtable_missing_linkage += other.vtable_missing_linkage;
        self.dyn_decl_only_self += other.dyn_decl_only_self;
        self.dyn_unresolved_self += other.dyn_unresolved_self;
        for (ns, self_type) in other.impl_selfs {
            self.impl_selfs.entry(ns).or_insert(self_type);
        }
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

    note_impl_self(reader, name, func, out);

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
                out.coroutine_candidates.insert(t);
                out.fut_polls
                    .entry(t)
                    .or_default()
                    .insert(strip(linkage).to_owned());
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
                let locals = func.raw().locals.as_ref();
                if !locals.is_empty() {
                    out.resume_locals.entry(t).or_default().extend(
                        locals
                            .iter()
                            .filter_map(|l| Some((l.name, (**l.source_loc.as_ref()?).clone()))),
                    );
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
        // A stream's `poll_next` is recorded for where it is written and
        // nothing else: the dyn-future tables and the origin rules are
        // about futures, and must not learn a trait as a side effect.
        if demangled.ends_with(STREAM_POLL_NEXT_SUFFIX) {
            if let Ok(t) = future_poll_self_type(reader, func)
                && let Some(loc) = func.source_loc()
            {
                out.poll_decls
                    .entry(t)
                    .or_default()
                    .push((PollTrait::Stream, owned_loc(&loc)));
            }
            return;
        }
        // A stream's read method, recorded by its linkage name and
        // nothing else: the name a vtable's read slot is joined by.
        if demangled.ends_with(HYPER_READ_SUFFIX) {
            if let Ok(t) = future_poll_self_type(reader, func) {
                out.stream_reads
                    .entry(t)
                    .or_default()
                    .insert(strip(linkage).to_owned());
            }
            return;
        }
        if !demangled.ends_with(FUTURE_POLL_SUFFIX) {
            return;
        }
        match future_poll_self_type(reader, func) {
            Ok(t) => {
                out.explicit_polls
                    .entry(t)
                    .or_default()
                    .insert(strip(linkage).to_owned());
                if let Some(source) = poll_source(reader, func) {
                    out.poll_sources.entry(t).or_default().insert(source);
                }
                if let Some(loc) = func.source_loc() {
                    out.poll_decls
                        .entry(t)
                        .or_default()
                        .push((PollTrait::Future, owned_loc(&loc)));
                }
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
    // A `mut self` the optimizer moved into a local is recorded as a
    // variable of the body rather than a formal parameter, so the first
    // parameter is `cx` and the pin is nowhere in the signature; the
    // mangled name still carries the self type.
    let pin = func
        .params()
        .next()
        .and_then(|param| param.raw().type_id)
        .and_then(|pin_id| match reader.canonical_type(pin_id) {
            Some(RawType::Struct(pin))
                if pin
                    .name
                    .is_some_and(|n| reader.strings.get(n).starts_with("Pin<")) =>
            {
                Some(pin)
            }
            _ => None,
        });
    let Some(pin) = pin else {
        return self_type_by_name(reader, func).ok_or(unresolved);
    };
    let Some(inner) = pin.members.first() else {
        // The pin is a declaration in every unit — the impl was
        // inlined at each call and no unit needed the pin's layout —
        // so the self type is recovered from the one place that still
        // spells it, the mangled name.
        return self_type_by_name(reader, func).ok_or(SelfRecovery::DeclOnly);
    };
    let Some(RawType::Pointer(p)) = reader.canonical_type(inner.type_id) else {
        return Err(unresolved);
    };
    Ok(reader.canonicalize(p.target_type_id))
}

/// The `T` of a `<T as Future>::poll` whose `Pin<&mut T>` self type
/// has no definition, from the impl's mangled name: the concrete half
/// of the `<T as Trait>` it demangles to, joined to the defined
/// canonical type carrying exactly that fully qualified name. The join
/// is exact and must be unique — a name several defined types share
/// recovers nothing — and a declaration-shaped type (no size, no
/// members) is never a candidate, since the join exists to reach the
/// definition the pin could not.
fn self_type_by_name(reader: &DwReader<'_>, func: &Func<'_>) -> Option<TypeId> {
    let linkage = func.linkage_name()?;
    let demangled = format!("{:#}", rustc_demangle::demangle(linkage));
    let (concrete, _) = crate::symbols::trait_object_pair(&demangled)?;
    let short = reader.strings.find(short_type_name(concrete))?;
    let wanted = crate::symbols::normalized_rust_type_name(concrete);
    let mut found = reader
        .types_by_name
        .get(&short)?
        .iter()
        .copied()
        .filter(|&id| reader.is_canonical(id))
        .filter(|&id| match reader.canonical_type(id) {
            Some(RawType::Struct(st)) => st.size > 0 || !st.members.is_empty(),
            Some(RawType::Enum(en)) => en.size > 0,
            _ => false,
        })
        .filter(|&id| {
            super::fq_name(reader, id)
                .is_some_and(|name| crate::symbols::normalized_rust_type_name(&name) == wanted)
        });
    match (found.next(), found.next()) {
        (Some(id), None) => Some(id),
        _ => None,
    }
}

/// The last path segment of a fully qualified type name — what the
/// type's own DIE is named — with the `::` inside its generic
/// arguments left alone.
fn short_type_name(name: &str) -> &str {
    let mut depth = 0usize;
    let mut start = 0;
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth = depth.saturating_sub(1),
            b':' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                start = i + 2;
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    &name[start..]
}

/// Record the self type of the impl block enclosing `func`, when its
/// namespace chain passes through an `{impl#N}` namespace not yet
/// resolved. rustc invents those namespaces because a namespace cannot
/// spell a type, and records nothing else on them; the one place that
/// spells the real path is the mangled name of a member subprogram,
/// which demangles to `<tokio::sync::mutex::Mutex<T>>::lock…` (or
/// `<T as Trait>::method…`). The display fold substitutes the recovered
/// path back over the impl path. Recovery fails safe: an impl whose
/// members yield no plain self path stays unresolved, and names that
/// mention it display raw.
fn note_impl_self(reader: &DwReader<'_>, name: &str, func: &Func<'_>, out: &mut Sweep) {
    let mut ns = func.namespace_id();
    // The nearest `{impl#N}` ancestor, and the path segment the
    // demangled method chain must open with: the name of the chain
    // entry below that ancestor, or the subprogram's own name where it
    // is a direct member.
    let mut expected = name;
    let impl_ns = loop {
        let Some(id) = ns else { return };
        let entry = reader.namespaces.get(id);
        let ns_name = reader.strings.get(entry.name);
        if ns_name.starts_with("{impl#") {
            break id;
        }
        expected = ns_name;
        ns = entry.parent;
    };
    if out.impl_selfs.contains_key(&impl_ns) {
        return;
    }
    // Absence of a linkage name is not cached: a sibling that has one
    // can still resolve the block.
    let Some(linkage) = func.linkage_name() else {
        return;
    };
    let demangled = format!("{:#}", rustc_demangle::demangle(linkage));
    let recovered = impl_self_type(&demangled, expected);
    if recovered.is_none() {
        debug!("cannot recover impl self type: {demangled}");
    }
    out.impl_selfs.insert(impl_ns, recovered);
}

/// Recover the self type from a demangled impl-member symbol —
/// `<a::b::Type<T>>::method…` or `<Type as Trait>::method…` — as the
/// plain path with generic arguments stripped (`a::b::Type`).
/// `expected` is the path segment the method chain must open with,
/// guarding against a demangling this parser does not understand. A
/// member of a generic impl is named with the impl's arguments
/// (`poll_write<TcpStream>`), which the demangled chain writes on the
/// self type instead, so they are cut from it first.
/// `None` for a self type that is not a plain path (`&mut F`, a tuple,
/// `dyn …`) — or a legacy demangling, which writes no leading `<`.
fn impl_self_type(demangled: &str, expected: &str) -> Option<String> {
    let expected = expected.find('<').map_or(expected, |at| &expected[..at]);
    let inner = demangled.strip_prefix('<')?;
    let close = angle_close(inner)?;
    let chain = inner[close + 1..].strip_prefix("::")?;
    let boundary = chain.strip_prefix(expected).map(|r| r.chars().next());
    if !matches!(boundary, Some(next) if next.is_none_or(|c| !c.is_alphanumeric() && c != '_')) {
        return None;
    }
    // A plain find, not a depth-aware one: an ` as ` that is not the
    // trait separator sits inside a generic list — so anything before
    // it contains a `<`, and the strip below reduces either split to
    // the same base.
    let self_type = &inner[..close];
    let self_type = match self_type.find(" as ") {
        Some(at) => &self_type[..at],
        None => self_type,
    };
    let base = match self_type.find('<') {
        Some(at) => &self_type[..at],
        None => self_type,
    }
    .trim();
    is_plain_path(base).then(|| base.to_owned())
}

/// The index in `s` of the `>` matching an angle bracket already open
/// when it starts, skipping the `>` of `->` (a fn-pointer return type
/// inside the generic arguments).
pub(super) fn angle_close(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut prev = '\0';
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' if prev != '-' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        prev = c;
    }
    None
}

/// Whether `s` is a bare `a::b::C` path: identifier segments only, no
/// generics, references, or brace markers left.
fn is_plain_path(s: &str) -> bool {
    !s.is_empty()
        && s.split("::").all(|seg| {
            !seg.is_empty()
                && seg.chars().all(|c| c.is_alphanumeric() || c == '_')
                && !seg.starts_with(|c: char| c.is_ascii_digit())
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_types::{
        RawEnum, RawFunc, RawGenericParameter, RawLocal, RawMember, RawPointer, RawStruct,
        RawSubParameter, RawUnion, VariantShape,
    };
    use gimli::UnitSectionOffset;

    use std::num::NonZero;

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset(offset))
    }

    fn func_id(offset: usize) -> FuncId {
        FuncId(UnitSectionOffset(offset))
    }

    fn insert_struct(
        reader: &mut DwReader<'static>,
        id: TypeId,
        namespace: Option<NsId>,
        name: &'static str,
        members: &[(&'static str, TypeId)],
    ) {
        let members = members
            .iter()
            .enumerate()
            .map(|(index, &(name, type_id))| RawMember {
                name: Some(reader.strings.intern(name)),
                offset: index as u64 * 8,
                type_id,
                source_loc: None,
            })
            .collect();
        reader.types.insert(
            id,
            RawType::Struct(RawStruct {
                name: Some(reader.strings.intern(name)),
                namespace,
                size: 8,
                members,
                template_params: Box::new([]),
                source_loc: None,
            }),
        );
    }

    fn insert_union(
        reader: &mut DwReader<'static>,
        id: TypeId,
        name: &'static str,
        members: &[(&'static str, TypeId)],
    ) {
        let members = members
            .iter()
            .map(|&(name, type_id)| RawMember {
                name: Some(reader.strings.intern(name)),
                offset: 0,
                type_id,
                source_loc: None,
            })
            .collect();
        reader.types.insert(
            id,
            RawType::Union(RawUnion {
                name: Some(reader.strings.intern(name)),
                namespace: None,
                size: 8,
                members,
                template_params: Box::new([]),
                source_loc: None,
            }),
        );
    }

    fn insert_enum(
        reader: &mut DwReader<'static>,
        id: TypeId,
        namespace: Option<NsId>,
        name: &'static str,
    ) {
        reader.types.insert(
            id,
            RawType::Enum(RawEnum {
                name: Some(reader.strings.intern(name)),
                namespace,
                size: 8,
                alignment: None,
                shape: VariantShape::Zero,
                template_params: Box::new([]),
                source_loc: None,
            }),
        );
    }

    fn insert_pointer(reader: &mut DwReader<'static>, id: TypeId, target: TypeId) {
        reader.types.insert(
            id,
            RawType::Pointer(RawPointer {
                name: None,
                target_type_id: target,
            }),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_func(
        reader: &mut DwReader<'static>,
        id: FuncId,
        namespace: Option<NsId>,
        name: &'static str,
        linkage: Option<&'static str>,
        template_params: &[(&'static str, TypeId)],
        params: &[TypeId],
        return_type_id: Option<TypeId>,
    ) {
        let template_params = template_params
            .iter()
            .map(|&(name, type_id)| RawGenericParameter {
                name: Some(reader.strings.intern(name)),
                type_id,
            })
            .collect();
        let formal_parameters = params
            .iter()
            .map(|&type_id| RawSubParameter {
                name: None,
                type_id: Some(type_id),
                abstract_origin: None,
                const_value: None,
                source_loc: None,
            })
            .collect();
        reader.functions.insert(
            id,
            RawFunc {
                name: Some(reader.strings.intern(name)),
                namespace,
                source_loc: None,
                return_type_id,
                formal_parameters,
                abstract_origin: None,
                linkage_name: linkage.map(|l| reader.strings.intern(l)),
                template_params,
                noreturn: false,
                awaitees: Box::new([]),
                locals: Box::new([]),
                select_arms: Box::new([]),
            },
        );
    }

    fn symbols(set: &BTreeSet<String>) -> Vec<&str> {
        set.iter().map(String::as_str).collect()
    }

    #[test]
    fn test_sweep_collects_vtable_seeds_by_role() {
        let mut reader = DwReader::default();
        let raw = reader.strings.intern("raw");
        let raw_ns = reader.namespaces.insert(None, raw);
        let fut = type_id(0x10);
        let sched = type_id(0x20);
        insert_struct(&mut reader, fut, None, "Fut", &[]);
        insert_struct(&mut reader, sched, None, "Sched", &[]);
        let poll_param = type_id(0x30);
        let dealloc_param = type_id(0x40);
        let late_dealloc_param = type_id(0x50);
        insert_struct(&mut reader, poll_param, None, "PollArg", &[]);
        insert_struct(&mut reader, dealloc_param, None, "DeallocArg", &[]);
        insert_struct(&mut reader, late_dealloc_param, None, "LateArg", &[]);

        let t_s: &[(&str, TypeId)] = &[("T", fut), ("S", sched)];
        insert_func(
            &mut reader,
            func_id(0x100),
            Some(raw_ns),
            "poll<Fut, Sched>",
            Some("poll_sym"),
            t_s,
            &[poll_param],
            None,
        );
        insert_func(
            &mut reader,
            func_id(0x110),
            Some(raw_ns),
            "dealloc<Fut, Sched>",
            Some("dealloc_sym"),
            t_s,
            &[dealloc_param],
            None,
        );
        insert_func(
            &mut reader,
            func_id(0x120),
            Some(raw_ns),
            "dealloc<Fut, Sched>",
            Some("late_dealloc_sym"),
            t_s,
            &[late_dealloc_param],
            None,
        );
        insert_func(
            &mut reader,
            func_id(0x130),
            Some(raw_ns),
            "shutdown<Fut, Sched>",
            None,
            t_s,
            &[],
            None,
        );

        let view = reader.view();
        let sweep = sweep_functions(&view, Some(raw_ns), None);

        assert_eq!(sweep.seeds.len(), 1);
        let seed = &sweep.seeds[&(fut, sched)];
        assert_eq!(
            symbols(&seed.symbols),
            ["dealloc_sym", "late_dealloc_sym", "poll_sym"]
        );
        // Only the poll vtable fn contributes a poll symbol.
        assert_eq!(symbols(&seed.poll_symbols), ["poll_sym"]);
        // The first dealloc's parameter wins; a later one never replaces it.
        assert_eq!(seed.dealloc_param, Some(dealloc_param));
        // The linkage-less vtable fn is counted, not seeded.
        assert_eq!(sweep.vtable_missing_linkage, 1);
    }

    #[test]
    fn test_sweep_records_drop_glue_only_under_its_namespace_and_name() {
        let mut reader = DwReader::default();
        let glue = reader.strings.intern("glue");
        let glue_ns = reader.namespaces.insert(None, glue);
        let fut = type_id(0x10);
        insert_struct(&mut reader, fut, None, "Fut", &[]);

        insert_func(
            &mut reader,
            func_id(0x100),
            Some(glue_ns),
            "drop_glue<Fut>",
            Some("glue_sym"),
            &[("T", fut)],
            &[],
            None,
        );
        insert_func(
            &mut reader,
            func_id(0x110),
            Some(glue_ns),
            "drop_glue<foo::Bar>",
            Some("named_glue_sym"),
            &[],
            &[],
            None,
        );
        // In the glue namespace but not glue: never recorded.
        insert_func(
            &mut reader,
            func_id(0x120),
            Some(glue_ns),
            "other<Fut>",
            Some("other_sym"),
            &[("T", fut)],
            &[],
            None,
        );

        let view = reader.view();
        let sweep = sweep_functions(&view, None, Some(glue_ns));
        assert_eq!(sweep.drop_glues.len(), 1);
        assert_eq!(symbols(&sweep.drop_glues[&fut]), ["glue_sym"]);
        assert_eq!(sweep.glue_by_name.len(), 1);
        assert_eq!(symbols(&sweep.glue_by_name["foo::Bar"]), ["named_glue_sym"]);

        // Without a glue namespace nothing is glue, whatever its spelling.
        let mut reader = DwReader::default();
        let fut = type_id(0x10);
        insert_struct(&mut reader, fut, None, "Fut", &[]);
        insert_func(
            &mut reader,
            func_id(0x100),
            None,
            "drop_glue<Fut>",
            Some("glue_sym"),
            &[("T", fut)],
            &[],
            None,
        );
        let view = reader.view();
        let sweep = sweep_functions(&view, None, None);
        assert!(sweep.drop_glues.is_empty());
        assert!(sweep.glue_by_name.is_empty());
    }

    /// A `Pin<&mut T>`-shaped self parameter: the `Pin` struct, its pointer
    /// member, and the pointee, returning the `Pin` type's id.
    fn insert_pin_of(
        reader: &mut DwReader<'static>,
        pin: TypeId,
        pointer: TypeId,
        target: TypeId,
    ) -> TypeId {
        insert_pointer(reader, pointer, target);
        insert_struct(reader, pin, None, "Pin<&mut T>", &[("__pointer", pointer)]);
        pin
    }

    #[test]
    fn test_sweep_keeps_non_coroutine_resume_shapes_out_of_the_dyn_table() {
        let mut reader = DwReader::default();
        let poll_ret = type_id(0x10);
        insert_struct(&mut reader, poll_ret, None, "Poll<()>", &[]);
        let env = type_id(0x20);
        insert_struct(&mut reader, env, None, "{async_fn_env#0}", &[]);
        let env_pin = insert_pin_of(&mut reader, type_id(0x30), type_id(0x40), env);
        let plain = type_id(0x50);
        insert_struct(&mut reader, plain, None, "Plain", &[]);
        let plain_pin = insert_pin_of(&mut reader, type_id(0x60), type_id(0x70), plain);

        insert_func(
            &mut reader,
            func_id(0x100),
            None,
            "{async_fn#0}",
            Some("resume_sym"),
            &[],
            &[env_pin],
            Some(poll_ret),
        );
        // Poll-shaped, but over a self type that is no coroutine env.
        insert_func(
            &mut reader,
            func_id(0x110),
            None,
            "{closure#0}",
            Some("closure_sym"),
            &[],
            &[plain_pin],
            Some(poll_ret),
        );

        let view = reader.view();
        let sweep = sweep_functions(&view, None, None);
        assert_eq!(sweep.fut_polls.len(), 1);
        assert_eq!(symbols(&sweep.fut_polls[&env]), ["resume_sym"]);
        assert!(sweep.explicit_polls.is_empty());
        assert_eq!(sweep.coroutine_candidates, BTreeSet::from([env]));
    }

    /// Every unit's copy of a resume function contributes its named
    /// locals: an optimized copy keeps only the variables it still
    /// needs, so two copies of one body can name different subsets, and
    /// the coroutine's list is their union — the copies of one name are
    /// left for emission to agree on. Locals with no coordinates are
    /// dropped at the sweep.
    #[test]
    fn test_sweep_unions_a_resume_functions_locals_across_its_copies() {
        let mut reader = DwReader::default();
        let poll_ret = type_id(0x10);
        insert_struct(&mut reader, poll_ret, None, "Poll<()>", &[]);
        let env = type_id(0x20);
        insert_struct(&mut reader, env, None, "{async_fn_env#0}", &[]);
        let env_pin = insert_pin_of(&mut reader, type_id(0x30), type_id(0x40), env);
        let file = reader.strings.intern("src/bin/joinset.rs");
        let at = |line: u64| {
            Some(Box::new(SourceLoc {
                file_id: None,
                file: Some(file),
                dir: None,
                comp_dir: None,
                line: NonZero::new(line),
                column: None,
            }))
        };
        let set = reader.strings.intern("set");
        let kept = reader.strings.intern("kept");
        let sum = reader.strings.intern("sum");
        for (id, locals) in [
            (
                func_id(0x100),
                vec![
                    RawLocal {
                        name: set,
                        source_loc: at(52),
                    },
                    RawLocal {
                        name: sum,
                        source_loc: None,
                    },
                ],
            ),
            (
                func_id(0x110),
                vec![
                    RawLocal {
                        name: set,
                        source_loc: at(52),
                    },
                    RawLocal {
                        name: kept,
                        source_loc: at(60),
                    },
                ],
            ),
        ] {
            insert_func(
                &mut reader,
                id,
                None,
                "{async_fn#0}",
                Some("resume_sym"),
                &[],
                &[env_pin],
                Some(poll_ret),
            );
            reader.functions.get_mut(&id).unwrap().locals = locals.into_boxed_slice();
        }

        let view = reader.view();
        let sweep = sweep_functions(&view, None, None);
        let locals: Vec<(&str, u64)> = sweep.resume_locals[&env]
            .iter()
            .map(|(name, loc)| (reader.strings.get(*name), loc.line.unwrap().get()))
            .collect();
        assert_eq!(
            locals,
            [("set", 52), ("set", 52), ("kept", 60)],
            "both copies contribute; the unplaced `sum` is dropped"
        );

        // Merging two sweeps unions the same way.
        let mut halves = (Sweep::default(), Sweep::default());
        for (i, func) in view.functions().map(|(_, f)| f).enumerate() {
            let out = if i == 0 { &mut halves.0 } else { &mut halves.1 };
            sweep_function(view.collector(), None, None, &func, out);
        }
        let (mut merged, other) = halves;
        merged.merge(other);
        assert_eq!(merged.resume_locals[&env].len(), 3);
    }

    #[test]
    fn test_sweep_requires_the_exact_future_trait_for_poll_evidence() {
        let mut reader = DwReader::default();
        let future = type_id(0x10);
        insert_struct(&mut reader, future, None, "Manual", &[]);
        let pin = insert_pin_of(&mut reader, type_id(0x20), type_id(0x30), future);
        for (index, linkage) in [
            "<Manual as core::future::future::Future>::poll.llvm.123",
            "<Manual as app::Future>::poll",
            "<Manual as app::Stream>::poll",
            "Manual::poll",
        ]
        .into_iter()
        .enumerate()
        {
            insert_func(
                &mut reader,
                func_id(0x100 + index),
                None,
                "poll",
                Some(linkage),
                &[],
                &[pin],
                None,
            );
        }
        let view = reader.view();
        let sweep = sweep_functions(&view, None, None);
        assert_eq!(
            sweep.explicit_polls,
            BTreeMap::from([(
                future,
                BTreeSet::from(["<Manual as core::future::future::Future>::poll".into()]),
            )])
        );
        assert!(sweep.coroutine_candidates.is_empty());
    }

    /// An explicit poll's declaration file is recorded beside its symbol,
    /// joined as the line table meant it: a relative directory under the
    /// unit's compilation directory, an absolute one as is. A poll with no
    /// declaration records no source, and merging keeps every source.
    #[test]
    fn test_sweep_records_where_explicit_polls_are_declared() {
        let mut reader = DwReader::default();
        let future = type_id(0x10);
        insert_struct(&mut reader, future, None, "Instrumented<F>", &[]);
        let pin = insert_pin_of(&mut reader, type_id(0x20), type_id(0x30), future);
        let linkage = "<Instrumented<F> as core::future::future::Future>::poll";
        for (id, dir, comp_dir) in [
            (
                0x100,
                Some("/home/u/.cargo/registry/src/idx/tracing-0.1.40"),
                Some("/build"),
            ),
            (0x110, Some("vendor/tracing-0.1.40"), Some("/build")),
            (0x120, None, None),
        ] {
            insert_func(
                &mut reader,
                func_id(id),
                None,
                "poll",
                Some(linkage),
                &[],
                &[pin],
                None,
            );
            let file = reader.strings.intern("src/instrument.rs");
            let dir = dir.map(|d| reader.strings.intern(d));
            let comp_dir = comp_dir.map(|d| reader.strings.intern(d));
            reader.functions.get_mut(&func_id(id)).unwrap().source_loc =
                Some(Box::new(crate::raw_types::SourceLoc {
                    file: Some(file),
                    dir,
                    comp_dir,
                    ..Default::default()
                }));
        }
        // And one poll with no declaration at all.
        insert_func(
            &mut reader,
            func_id(0x130),
            None,
            "poll",
            Some(linkage),
            &[],
            &[pin],
            None,
        );
        let view = reader.view();
        let sweep = sweep_functions(&view, None, None);
        let paths: Vec<(&str, Option<[u8; 16]>)> = sweep.poll_sources[&future]
            .iter()
            .map(|s| (s.path.as_str(), s.md5))
            .collect();
        assert_eq!(
            paths,
            [
                ("/build/vendor/tracing-0.1.40/src/instrument.rs", None),
                (
                    "/home/u/.cargo/registry/src/idx/tracing-0.1.40/src/instrument.rs",
                    None
                ),
                ("src/instrument.rs", None),
            ]
        );
        let mut merged = Sweep::default();
        merged.merge(sweep);
        let mut again = Sweep::default();
        again.merge(Sweep {
            poll_sources: BTreeMap::from([(
                future,
                BTreeSet::from([PollSource {
                    path: "src/instrument.rs".into(),
                    md5: Some([1; 16]),
                }]),
            )]),
            ..Default::default()
        });
        again.merge(merged);
        assert_eq!(again.poll_sources[&future].len(), 4);
    }

    #[test]
    fn test_semantic_sweep_evidence_merges_independently_of_order() {
        let contributions = || {
            ["poll_b", "poll_a", "poll_a"].map(|symbol| Sweep {
                explicit_polls: BTreeMap::from([(type_id(1), BTreeSet::from([symbol.to_owned()]))]),
                coroutine_candidates: BTreeSet::from([type_id(2)]),
                ..Default::default()
            })
        };
        let mut forward = Sweep::default();
        for part in contributions() {
            forward.merge(part);
        }
        let mut reverse = Sweep::default();
        for part in contributions().into_iter().rev() {
            reverse.merge(part);
        }
        assert_eq!(forward.explicit_polls, reverse.explicit_polls);
        assert_eq!(forward.coroutine_candidates, reverse.coroutine_candidates);
        assert_eq!(
            symbols(&forward.explicit_polls[&type_id(1)]),
            ["poll_a", "poll_b"]
        );
        assert_eq!(forward.coroutine_candidates, BTreeSet::from([type_id(2)]));
    }

    #[test]
    fn test_sweep_counts_the_poll_impls_it_cannot_resolve() {
        let mut reader = DwReader::default();
        // A declaration-shaped `Pin`: no members to recover `T` through.
        let bare_pin = type_id(0x10);
        insert_struct(&mut reader, bare_pin, None, "Pin<&mut F>", &[]);
        insert_func(
            &mut reader,
            func_id(0x100),
            None,
            "poll",
            Some("<F as core::future::future::Future>::poll"),
            &[],
            &[bare_pin],
            None,
        );
        insert_func(
            &mut reader,
            func_id(0x110),
            None,
            "poll",
            Some("<G as core::future::future::Future>::poll"),
            &[],
            &[],
            None,
        );

        let view = reader.view();
        let sweep = sweep_functions(&view, None, None);
        assert!(sweep.fut_polls.is_empty());
        assert_eq!(sweep.dyn_decl_only_self, 1);
        assert_eq!(sweep.dyn_unresolved_self, 1);
    }

    /// A poll whose `Pin<&mut T>` self type is declared everywhere and
    /// defined nowhere — the impl inlined at every call — still names
    /// `T` in its mangled name, and the sweep joins that name to the
    /// one defined type carrying it; a name two defined types share,
    /// or one only a declaration carries, recovers nothing and counts
    /// as before.
    #[test]
    fn test_sweep_recovers_a_declaration_only_self_type_by_name() {
        let mut reader = DwReader::default();
        let tracing = reader.strings.intern("tracing");
        let tracing_ns = reader.namespaces.insert(None, tracing);
        let instrument = reader.strings.intern("instrument");
        let instrument_ns = reader.namespaces.insert(Some(tracing_ns), instrument);
        let fut = type_id(0x10);
        insert_struct(&mut reader, fut, None, "Fut", &[("state", fut)]);
        let wrapped = type_id(0x20);
        insert_struct(
            &mut reader,
            wrapped,
            Some(instrument_ns),
            "Instrumented<app::Fut>",
            &[("inner", fut)],
        );
        // The pin: a declaration, no members.
        let bare_pin = type_id(0x30);
        insert_struct(
            &mut reader,
            bare_pin,
            None,
            "Pin<&mut tracing::instrument::Instrumented<app::Fut>>",
            &[],
        );
        insert_func(
            &mut reader,
            func_id(0x100),
            None,
            "poll",
            Some(
                "<tracing::instrument::Instrumented<app::Fut> as core::future::future::Future>::poll",
            ),
            &[],
            &[bare_pin],
            None,
        );
        // A second defined type of the same name elsewhere: ambiguous,
        // so a poll naming *it* recovers nothing.
        let other = reader.strings.intern("other");
        let other_ns = reader.namespaces.insert(None, other);
        let twin_a = type_id(0x40);
        let twin_b = type_id(0x41);
        insert_struct(&mut reader, twin_a, Some(other_ns), "Twin", &[("a", fut)]);
        insert_struct(&mut reader, twin_b, Some(other_ns), "Twin", &[("b", fut)]);
        let twin_pin = type_id(0x42);
        insert_struct(&mut reader, twin_pin, None, "Pin<&mut other::Twin>", &[]);
        insert_func(
            &mut reader,
            func_id(0x110),
            None,
            "poll",
            Some("<other::Twin as core::future::future::Future>::poll"),
            &[],
            &[twin_pin],
            None,
        );
        // And one whose name only a declaration carries: no members,
        // and no size either.
        let ghost = type_id(0x50);
        insert_struct(&mut reader, ghost, Some(other_ns), "Ghost", &[]);
        if let Some(RawType::Struct(st)) = reader.types.get_mut(&ghost) {
            st.size = 0;
        }
        let ghost_pin = type_id(0x51);
        insert_struct(&mut reader, ghost_pin, None, "Pin<&mut other::Ghost>", &[]);
        insert_func(
            &mut reader,
            func_id(0x120),
            None,
            "poll",
            Some("<other::Ghost as core::future::future::Future>::poll"),
            &[],
            &[ghost_pin],
            None,
        );
        reader.types_by_name = reader.index_type_names();

        let view = reader.view();
        let sweep = sweep_functions(&view, None, None);
        assert_eq!(
            symbols(&sweep.explicit_polls[&wrapped]),
            ["<tracing::instrument::Instrumented<app::Fut> as core::future::future::Future>::poll"]
        );
        assert!(!sweep.explicit_polls.contains_key(&twin_a));
        assert!(!sweep.explicit_polls.contains_key(&twin_b));
        assert!(!sweep.explicit_polls.contains_key(&ghost));
        assert_eq!(sweep.dyn_decl_only_self, 2);
        assert_eq!(sweep.dyn_unresolved_self, 0);
    }

    /// A `mut self` the optimizer demoted to a body variable leaves the
    /// poll with `cx` as its only formal parameter; the self type is
    /// still recovered, by name, from the mangled linkage name — and a
    /// poll whose name matches no defined type stays unresolved.
    #[test]
    fn test_sweep_recovers_a_demoted_self_type_by_name() {
        let mut reader = DwReader::default();
        let oneshot = reader.strings.intern("oneshot");
        let oneshot_ns = reader.namespaces.insert(None, oneshot);
        let unit = type_id(0x1);
        insert_struct(&mut reader, unit, None, "()", &[]);
        let receiver = type_id(0x10);
        insert_struct(
            &mut reader,
            receiver,
            Some(oneshot_ns),
            "Receiver<()>",
            &[("inner", unit)],
        );
        let context = type_id(0x20);
        insert_struct(&mut reader, context, None, "Context", &[("waker", unit)]);
        let cx = type_id(0x21);
        reader.types.insert(
            cx,
            RawType::Pointer(RawPointer {
                name: None,
                target_type_id: context,
            }),
        );
        insert_func(
            &mut reader,
            func_id(0x100),
            None,
            "poll<()>",
            Some("<oneshot::Receiver<()> as core::future::future::Future>::poll"),
            &[],
            &[cx],
            None,
        );
        insert_func(
            &mut reader,
            func_id(0x110),
            None,
            "poll",
            Some("<oneshot::Nowhere as core::future::future::Future>::poll"),
            &[],
            &[cx],
            None,
        );
        // A first parameter that is a struct but not a `Pin<…>` — a
        // by-value `self` of some other shape — is not the pin either,
        // whatever pointer it happens to hold: the name decides, not
        // the first member's target.
        let decoy_target = type_id(0x30);
        insert_struct(&mut reader, decoy_target, None, "Decoy", &[("x", unit)]);
        let decoy_ptr = type_id(0x31);
        reader.types.insert(
            decoy_ptr,
            RawType::Pointer(RawPointer {
                name: None,
                target_type_id: decoy_target,
            }),
        );
        let not_pin = type_id(0x32);
        insert_struct(&mut reader, not_pin, None, "NotPin", &[("p", decoy_ptr)]);
        insert_func(
            &mut reader,
            func_id(0x120),
            None,
            "poll<()>",
            Some("<oneshot::Receiver<()> as core::future::future::Future>::poll"),
            &[],
            &[not_pin, cx],
            None,
        );
        reader.types_by_name = reader.index_type_names();

        let view = reader.view();
        let sweep = sweep_functions(&view, None, None);
        assert_eq!(
            symbols(&sweep.explicit_polls[&receiver]),
            ["<oneshot::Receiver<()> as core::future::future::Future>::poll"]
        );
        assert!(!sweep.explicit_polls.contains_key(&decoy_target));
        assert_eq!(sweep.dyn_decl_only_self, 0);
        assert_eq!(sweep.dyn_unresolved_self, 1);
    }

    #[test]
    fn test_short_type_name_keeps_generic_paths_whole() {
        assert_eq!(short_type_name("app::Fut"), "Fut");
        assert_eq!(
            short_type_name("tracing::instrument::Instrumented<delegation_cases::Probe<8>>"),
            "Instrumented<delegation_cases::Probe<8>>"
        );
        assert_eq!(
            short_type_name("core::pin::Pin<alloc::boxed::Box<(dyn a::B + c::D)>>"),
            "Pin<alloc::boxed::Box<(dyn a::B + c::D)>>"
        );
        assert_eq!(short_type_name("Plain"), "Plain");
    }

    #[test]
    fn test_merge_sums_the_sweep_counters() {
        let mut left = Sweep {
            vtable_missing_linkage: 3,
            dyn_decl_only_self: 5,
            dyn_unresolved_self: 7,
            ..Sweep::default()
        };
        let right = Sweep {
            vtable_missing_linkage: 2,
            dyn_decl_only_self: 4,
            dyn_unresolved_self: 6,
            ..Sweep::default()
        };

        left.merge(right);
        assert_eq!(left.vtable_missing_linkage, 5);
        assert_eq!(left.dyn_decl_only_self, 9);
        assert_eq!(left.dyn_unresolved_self, 13);
    }

    #[test]
    fn test_find_stage_screens_on_namespace_and_name() {
        let mut reader = DwReader::default();
        let core = reader.strings.intern("core");
        let core_ns = reader.namespaces.insert(None, core);
        let stage = type_id(0x10);
        insert_enum(&mut reader, stage, Some(core_ns), "Stage<Fut>");
        let cell = type_id(0x20);
        insert_struct(
            &mut reader,
            cell,
            Some(core_ns),
            "Cell<Fut>",
            &[("stage", stage)],
        );
        assert_eq!(find_stage(&reader, Some(core_ns), cell), Some(stage));

        // The right name outside the namespace, the right namespace under
        // another name: neither is the stage.
        let mut reader = DwReader::default();
        let core = reader.strings.intern("core");
        let core_ns = reader.namespaces.insert(None, core);
        let stray = type_id(0x10);
        insert_enum(&mut reader, stray, None, "Stage<Fut>");
        let renamed = type_id(0x20);
        insert_enum(&mut reader, renamed, Some(core_ns), "Phase<Fut>");
        let cell = type_id(0x30);
        insert_struct(
            &mut reader,
            cell,
            Some(core_ns),
            "Cell<Fut>",
            &[("a", stray), ("b", renamed)],
        );
        assert_eq!(find_stage(&reader, Some(core_ns), cell), None);
    }

    /// A chain of alternating structs and unions `length` links long,
    /// ending at a `Stage<…>` enum in `core_ns`; returns the head and the
    /// stage id. The head is depth 0, so the stage sits at depth `length`.
    fn insert_stage_chain(
        reader: &mut DwReader<'static>,
        core_ns: NsId,
        length: usize,
    ) -> (TypeId, TypeId) {
        let stage = type_id(0x1000);
        insert_enum(reader, stage, Some(core_ns), "Stage<Fut>");
        let mut next = stage;
        for link in (0..length).rev() {
            let id = type_id(0x100 + link);
            if link % 2 == 0 {
                insert_struct(reader, id, None, "Link", &[("next", next)]);
            } else {
                insert_union(reader, id, "LinkUnion", &[("next", next)]);
            }
            next = id;
        }
        (next, stage)
    }

    #[test]
    fn test_find_stage_traverses_to_the_depth_cap_and_no_further() {
        let mut reader = DwReader::default();
        let core = reader.strings.intern("core");
        let core_ns = reader.namespaces.insert(None, core);
        // Head at depth 0, eight links, stage at depth 8: the last depth
        // the walk still visits.
        let (head, stage) = insert_stage_chain(&mut reader, core_ns, 8);
        assert_eq!(find_stage(&reader, Some(core_ns), head), Some(stage));

        let mut reader = DwReader::default();
        let core = reader.strings.intern("core");
        let core_ns = reader.namespaces.insert(None, core);
        // One more link puts the stage at depth 9, past the cap.
        let (head, _stage) = insert_stage_chain(&mut reader, core_ns, 9);
        assert_eq!(find_stage(&reader, Some(core_ns), head), None);
    }

    #[test]
    fn test_cell_is_recovered_through_the_dealloc_parameter() {
        let mut reader = DwReader::default();
        let core = reader.strings.intern("core");
        let core_ns = reader.namespaces.insert(None, core);
        let cell = type_id(0x10);
        insert_struct(&mut reader, cell, Some(core_ns), "Cell<Fut, Sched>", &[]);
        let cell_ptr = type_id(0x20);
        insert_pointer(&mut reader, cell_ptr, cell);
        let non_null = type_id(0x30);
        insert_struct(
            &mut reader,
            non_null,
            None,
            "NonNull<Cell<Fut, Sched>>",
            &[("pointer", cell_ptr)],
        );
        assert_eq!(
            cell_from_dealloc_param(&reader, Some(core_ns), non_null),
            Some(cell)
        );

        // The same shape outside the task-core namespace is not a cell.
        let stray_cell = type_id(0x40);
        insert_struct(&mut reader, stray_cell, None, "Cell<Fut, Sched>", &[]);
        let stray_ptr = type_id(0x50);
        insert_pointer(&mut reader, stray_ptr, stray_cell);
        let stray_non_null = type_id(0x60);
        insert_struct(
            &mut reader,
            stray_non_null,
            None,
            "NonNull<Cell<Fut, Sched>>",
            &[("pointer", stray_ptr)],
        );
        assert_eq!(
            cell_from_dealloc_param(&reader, Some(core_ns), stray_non_null),
            None
        );
    }

    #[test]
    fn test_impl_self_type_parses_demangled_members() {
        // Inherent impl, generic self type.
        assert_eq!(
            impl_self_type("<tokio::sync::mutex::Mutex<()>>::lock", "lock").as_deref(),
            Some("tokio::sync::mutex::Mutex")
        );
        // Trait impl: the ` as Trait` half is dropped.
        assert_eq!(
            impl_self_type(
                "<core::task::wake::Waker as core::ops::drop::Drop>::drop",
                "drop"
            )
            .as_deref(),
            Some("core::task::wake::Waker")
        );
        // A method's inner item: the chain check matches the segment
        // below the impl, not the leaf.
        assert_eq!(
            impl_self_type("<core::alloc::layout::Layout>::array::inner", "array").as_deref(),
            Some("core::alloc::layout::Layout")
        );
        // A generic method's turbofish, and a fn-pointer's `->` inside
        // the self type's arguments.
        assert_eq!(
            impl_self_type(
                "<crossbeam_epoch::guard::Guard>::defer_unchecked::<foo::{closure#0}, ()>",
                "defer_unchecked"
            )
            .as_deref(),
            Some("crossbeam_epoch::guard::Guard")
        );
        assert_eq!(
            impl_self_type("<h::Handler<fn(u8) -> u16, ()> as t::T>::go", "go").as_deref(),
            Some("h::Handler")
        );
        // An ` as ` inside the self type's generic arguments is not
        // the trait separator, but everything before it is inside the
        // generics too, so the base is the same either way.
        assert_eq!(
            impl_self_type("<h::H<<x::X as y::Y>::Out> as t::T>::go", "go").as_deref(),
            Some("h::H")
        );
        // A member of a generic impl is named with the impl's
        // arguments, which the chain does not repeat.
        assert_eq!(
            impl_self_type(
                "<tokio_rustls::client::TlsStream<tokio::net::tcp::stream::TcpStream> \
                 as tokio::io::async_write::AsyncWrite>::poll_write",
                "poll_write<tokio::net::tcp::stream::TcpStream>"
            )
            .as_deref(),
            Some("tokio_rustls::client::TlsStream")
        );
    }

    /// Whatever the parser does not positively understand resolves to
    /// nothing: the impl stays unresolved and displays raw.
    #[test]
    fn test_impl_self_type_declines_what_it_cannot_parse() {
        // Blanket impls on non-path self types.
        for demangled in [
            "<&mut F as core::future::future::Future>::poll",
            "<(A, B) as t::T>::go",
            "<dyn core::fmt::Debug as t::T>::go",
        ] {
            assert_eq!(impl_self_type(demangled, "poll"), None, "{demangled}");
            assert_eq!(impl_self_type(demangled, "go"), None, "{demangled}");
        }
        // Legacy demangling spells no leading `<`.
        assert_eq!(
            impl_self_type("tokio::sync::mutex::Mutex<()>::lock", "lock"),
            None
        );
        // A chain that does not open with the expected segment.
        assert_eq!(
            impl_self_type("<a::A>::other", "lock"),
            None,
            "chain mismatch"
        );
        assert_eq!(
            impl_self_type("<a::A>::locker", "lock"),
            None,
            "segment boundary"
        );
        // An unclosed self type.
        assert_eq!(impl_self_type("<a::A<()>::lock", "lock"), None);
    }

    #[test]
    fn test_coroutine_envs_are_recognized_by_name() {
        let mut reader = DwReader::default();
        let async_fn = type_id(0x10);
        let async_block = type_id(0x20);
        let plain = type_id(0x30);
        insert_struct(&mut reader, async_fn, None, "{async_fn_env#0}", &[]);
        insert_struct(&mut reader, async_block, None, "{async_block_env#0}", &[]);
        insert_struct(&mut reader, plain, None, "Plain", &[]);

        assert!(is_coroutine_env(&reader, async_fn));
        assert!(is_coroutine_env(&reader, async_block));
        assert!(!is_coroutine_env(&reader, plain));
        assert!(!is_coroutine_env(&reader, type_id(0xdead)));
    }
}

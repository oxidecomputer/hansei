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
    /// `{impl#N}` namespace → the impl's self type path, recovered by
    /// demangling one member subprogram's linkage name (the namespace
    /// DIE itself records nothing). `None` caches a failed recovery so
    /// an impl full of unparseable members costs one demangle, not one
    /// per member.
    pub(super) impl_selfs: BTreeMap<NsId, Option<String>>,
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
/// guarding against a demangling this parser does not understand.
/// `None` for a self type that is not a plain path (`&mut F`, a tuple,
/// `dyn …`) — or a legacy demangling, which spells no leading `<`.
fn impl_self_type(demangled: &str, expected: &str) -> Option<String> {
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
fn angle_close(s: &str) -> Option<usize> {
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
        RawEnum, RawFunc, RawGenericParameter, RawMember, RawPointer, RawStruct, RawSubParameter,
        RawUnion, VariantShape,
    };
    use gimli::{DebugInfoOffset, UnitSectionOffset};

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(offset)))
    }

    fn func_id(offset: usize) -> FuncId {
        FuncId(UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(offset)))
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

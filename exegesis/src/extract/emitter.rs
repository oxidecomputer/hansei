// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Phase 3 of extraction: the [`Emitter`] drains a worklist of reachable
//! DWARF types into bundle [`TypeDef`]s, attaches each type's display
//! program through the detection layer, pairs coroutine awaits with the
//! places they are written, and finishes into the bundle's type table.

use super::fq_name;
use super::passes::{
    StatePass, demote_types_with_members_out_of_bounds, drop_members_of_other_states,
};
use super::paths::{OwnedLoc, display_path};
use crate::bundle::{
    BundleTypeId, DiscrDef, DiscrValue, DiscrValues, DisplayNode, ImplTable, MemberDef, MemberRef,
    SourceLoc, StrRef, StringInterner, TypeDef, TypeTable, VariantDef, VariantShape,
};
use crate::detect::{Family, FormatExplanation, trace, unique_member};
use crate::raw_types::{RawType, VariantShape as RawVariantShape};
use crate::{DwReader, Encoding, TypeId};

use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSliceMut;

use std::collections::{BTreeMap, VecDeque};

/// Placeholder name for type references that do not resolve to a parsed
/// DIE (e.g. `DW_TAG_subroutine_type` behind fn pointers).
const UNRESOLVED: &str = "<unresolved>";

/// Converts reachable DWARF types into bundle [`TypeDef`]s: assigns dense
/// ids up front, then drains a worklist so deep type graphs cannot
/// overflow the stack.
pub(crate) struct Emitter<'a> {
    pub(crate) reader: &'a DwReader<'a>,
    /// Coroutine env → the `__awaitee` locals of its resume fn, used to
    /// report an await at the place it is written rather than the place a
    /// macro expanded it.
    resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
    pub(crate) interner: StringInterner,
    /// Report formatter attachment for types whose name contains this
    /// substring; see [`crate::detect::trace`].
    pub(crate) explain_format: Option<String>,
    /// The tokio version recovered from the target's DWARF, as the family
    /// dispatch and its `--explain-format` lines report it.
    pub(crate) tokio_version: Option<semver::Version>,
    /// The [`Family`] the version selects, applied to every versioned
    /// dispatch row for this target.
    pub(crate) family: Family,
    /// Whether any versioned row was consulted — what turns an unrecovered
    /// tokio version into a warning, since only then did the family guess
    /// affect output.
    pub(crate) versioned_dispatch: bool,
    /// One trace per explained type, in emission order.
    pub(super) explanations: Vec<FormatExplanation>,
    ids: BTreeMap<TypeId, BundleTypeId>,
    defs: Vec<TypeDef>,
    /// Declaration sites of closure/coroutine environment types, keyed
    /// by their emitted id — the type table's `env_decls`.
    env_decls: BTreeMap<BundleTypeId, SourceLoc>,
    debug_formats: BTreeMap<BundleTypeId, DisplayNode>,
    /// Fully-qualified names for the name index, parallel to `defs`.
    names: Vec<Option<String>>,
    pending: VecDeque<(TypeId, BundleTypeId)>,
    unresolved: Option<BundleTypeId>,
    pub(super) unresolved_refs: usize,
    pub(super) cenum_synth_repr: usize,
}

impl<'a> Emitter<'a> {
    pub(crate) fn new(
        reader: &'a DwReader<'a>,
        resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
        explain_format: Option<String>,
        tokio_version: Option<semver::Version>,
    ) -> Self {
        Self {
            reader,
            resume_awaitees,
            interner: StringInterner::new(),
            explain_format,
            family: Family::select(tokio_version.as_ref()),
            tokio_version,
            versioned_dispatch: false,
            explanations: Vec::new(),
            ids: BTreeMap::new(),
            defs: Vec::new(),
            env_decls: BTreeMap::new(),
            debug_formats: BTreeMap::new(),
            names: Vec::new(),
            pending: VecDeque::new(),
            unresolved: None,
            unresolved_refs: 0,
            cenum_synth_repr: 0,
        }
    }

    /// Intern a string for the bundle's string table.
    pub(crate) fn intern(&mut self, s: &str) -> StrRef {
        self.interner.intern(s)
    }

    /// The bundle id `id` was emitted under, if it has been emitted.
    pub(crate) fn bundle_id_of(&self, id: TypeId) -> Option<BundleTypeId> {
        self.ids.get(&self.reader.canonicalize(id)).copied()
    }

    /// Every emitted type that carries a fully-qualified name — the walk
    /// binder's leaf scan, mirroring the runtime scan of the bundle's own
    /// name index.
    pub(crate) fn emitted_named(&self) -> impl Iterator<Item = (TypeId, &str)> {
        self.ids.iter().filter_map(|(&tid, &bid)| {
            self.names[bid.0 as usize]
                .as_deref()
                .map(|name| (tid, name))
        })
    }

    /// How to address `members[index]`: by its name when it has one no sibling
    /// shares, and by position otherwise.
    ///
    /// This is where a member a detector *found* — by shape, by offset, by
    /// whatever screen it applied — becomes something the bundle can address.
    /// A name is preferred because a member list is still rewritten after the
    /// program is attached, which shifts positions but not names; an unnamed
    /// member (they all intern as `<anon>`) or one of several spelled the same
    /// has no name to use and keeps its position.
    pub(crate) fn address(
        &mut self,
        members: &[crate::raw_types::RawMember<crate::StrId>],
        index: u32,
    ) -> MemberRef {
        let reader = self.reader;
        let named = members
            .get(index as usize)
            .and_then(|member| member.name)
            .map(|name| reader.strings.get(name))
            .filter(|name| unique_member(reader, members, name).is_some());
        match named {
            Some(name) => MemberRef::Named(self.intern(name)),
            None => MemberRef::Index(index),
        }
    }

    /// Emit a type (and, transitively, everything it references),
    /// returning its bundle id.
    pub(super) fn emit(&mut self, id: TypeId) -> BundleTypeId {
        let root = self.reserve(id);
        while let Some((tid, bid)) = self.pending.pop_front() {
            let def = self.convert(tid);
            self.defs[bid.0 as usize] = def;
            let name = fq_name(self.reader, tid);
            let node = match self.explained(name.as_deref()) {
                Some(wanted) => {
                    let (node, trace) =
                        trace::capture(|| self.debug_format_of(tid, name.as_deref()));
                    self.explanations.push(FormatExplanation {
                        name: wanted,
                        id: bid,
                        trace,
                    });
                    node
                }
                None => self.debug_format_of(tid, name.as_deref()),
            };
            if let Some(node) = node {
                self.debug_formats.insert(bid, node);
            }
        }
        root
    }

    /// Assign a bundle id for a type, queueing its conversion if new.
    pub(crate) fn reserve(&mut self, id: TypeId) -> BundleTypeId {
        let id = self.reader.canonicalize(id);
        if let Some(&bid) = self.ids.get(&id) {
            return bid;
        }
        if !self.reader.types.contains_key(&id) {
            // A reference to a DIE the reader did not model (fn-pointer
            // targets, mainly). All such references share one explicit
            // `Opaque` entry.
            self.unresolved_refs += 1;
            return self.unresolved_placeholder();
        }
        // A placeholder def `emit` overwrites once the conversion is
        // drained; the name recorded beside it is already final.
        let fq = self.fq_name(id);
        let name = self.interner.intern(UNRESOLVED);
        let bid = self.push_def(TypeDef::Opaque { name, size: None }, fq);
        self.ids.insert(id, bid);
        self.pending.push_back((id, bid));
        bid
    }

    /// Append a definition, keeping the parallel `names` slot — what the
    /// `finish` index and the walk binder's leaf scan read — in step with
    /// it. Every definition enters the table through here.
    fn push_def(&mut self, def: TypeDef, fq: Option<String>) -> BundleTypeId {
        let bid = BundleTypeId(self.defs.len() as u32);
        self.defs.push(def);
        self.names.push(fq);
        bid
    }

    /// The shared `<unresolved>` opaque entry.
    fn unresolved_placeholder(&mut self) -> BundleTypeId {
        if let Some(bid) = self.unresolved {
            return bid;
        }
        let bid = self.placeholder(UNRESOLVED);
        self.unresolved = Some(bid);
        bid
    }

    /// A named opaque placeholder (missing Cell/Stage/infra).
    pub(super) fn placeholder(&mut self, name: &str) -> BundleTypeId {
        let name = self.interner.intern(name);
        self.push_def(TypeDef::Opaque { name, size: None }, None)
    }

    /// The fully-qualified name of a named type, if it has one.
    fn fq_name(&self, id: TypeId) -> Option<String> {
        fq_name(self.reader, id)
    }

    /// Like [`Emitter::fq_name`], but falls back to `<anon>` for unnamed
    /// types — used for display names, which must always exist.
    pub(super) fn fq_name_of(&self, id: TypeId) -> String {
        self.fq_name(id).unwrap_or_else(|| "<anon>".to_owned())
    }

    fn intern_opt(&mut self, name: Option<crate::StrId>) -> StrRef {
        let s = name.map(|n| self.reader.strings.get(n)).unwrap_or("<anon>");
        self.interner.intern(s)
    }

    fn convert_member(&mut self, m: &crate::raw_types::RawMember<crate::StrId>) -> MemberDef {
        MemberDef {
            name: self.intern_opt(m.name),
            ty: self.reserve(m.type_id),
            offset: m.offset,
        }
    }

    /// A variant member's declaration coordinates — for coroutines, the
    /// awaited expression's file and line.
    fn member_decl(&mut self, m: &crate::raw_types::RawMember<crate::StrId>) -> Option<SourceLoc> {
        self.bundle_loc(m.source_loc.as_deref()?)
    }

    /// Intern a raw DWARF source location as a bundle [`SourceLoc`].
    fn bundle_loc(&mut self, loc: &crate::raw_types::SourceLoc<crate::StrId>) -> Option<SourceLoc> {
        let file = loc.file.map(|f| self.reader.strings.get(f))?;
        let line = loc.line?;
        let dir = loc.dir.map(|d| self.reader.strings.get(d));
        let comp_dir = loc.comp_dir.map(|d| self.reader.strings.get(d));
        let file = self.interner.intern(&display_path(comp_dir, dir, file));
        Some(SourceLoc {
            file,
            line: line.get() as u32,
        })
    }

    /// Record the declaration site recovered for a closure/coroutine
    /// environment type — the type table's `env_decls`, the anchor
    /// behind a combinator frame's `constructed at` line. The env DIEs
    /// carry no coordinates of their own, so the caller recovers each
    /// from the defining subprogram.
    pub(super) fn record_env_decl(&mut self, bid: BundleTypeId, loc: SourceLoc) {
        self.env_decls.insert(bid, loc);
    }

    /// The type a coroutine suspend variant awaits, from the `__awaitee`
    /// member of its payload.
    fn awaited_type(&self, payload: TypeId) -> Option<TypeId> {
        let RawType::Struct(s) = self.reader.canonical_type(payload)? else {
            return None;
        };
        s.members
            .iter()
            .find(|m| {
                m.name
                    .is_some_and(|n| self.reader.strings.get(n) == "__awaitee")
            })
            .map(|m| self.reader.canonicalize(m.type_id))
    }

    /// Pair a coroutine's suspend variants with the `__awaitee` locals of
    /// its resume function, so each await can say where it is written
    /// rather than where it expanded.
    ///
    /// The two sides describe the same awaits in different orders, and
    /// the awaited type is what they share — but a coroutine may await
    /// the same type at several points, so type alone does not decide.
    /// Take the unambiguous evidence first: pairs whose coordinates
    /// already agree are the awaits rustc attributed to the code that
    /// wrote them, and matching those removes them from contention.
    /// Among what is left, pair only where a type picks out exactly one
    /// variant and one local.
    ///
    /// Anything still ambiguous stays unmatched. A suspend point
    /// reporting some other await's line would be worse than one
    /// reporting the macro's, which is at least true.
    fn await_sites(
        &mut self,
        coroutine: TypeId,
        members: &[&crate::raw_types::RawMember<crate::StrId>],
    ) -> Vec<Option<SourceLoc>> {
        let mut out = vec![None; members.len()];
        let Some(locals) = self
            .resume_awaitees
            .get(&self.reader.canonicalize(coroutine))
        else {
            return out;
        };
        let locals: Vec<(Option<TypeId>, &OwnedLoc)> = locals
            .iter()
            .map(|(t, loc)| (t.map(|t| self.reader.canonicalize(t)), loc))
            .collect();
        let awaited: Vec<Option<TypeId>> = members
            .iter()
            .map(|m| self.awaited_type(m.type_id))
            .collect();

        let mut taken = vec![false; locals.len()];
        let mut matched: Vec<Option<usize>> = vec![None; members.len()];

        // Pass one: the awaits whose two descriptions already agree.
        for (v, want) in awaited.iter().enumerate() {
            let Some(want) = want else { continue };
            let decl = self.member_loc(members[v]);
            for (l, (ty, loc)) in locals.iter().enumerate() {
                if taken[l] || *ty != Some(*want) {
                    continue;
                }
                if decl.as_ref().is_some_and(|(f, n)| {
                    loc.line == Some(*n as u64) && loc.file.as_deref() == Some(f.as_str())
                }) {
                    taken[l] = true;
                    matched[v] = Some(l);
                    break;
                }
            }
        }

        // Pass two: of what remains, only where the type is decisive on
        // both sides.
        for (v, want) in awaited.iter().enumerate() {
            let Some(want) = want else { continue };
            if matched[v].is_some() {
                continue;
            }
            if awaited
                .iter()
                .enumerate()
                .any(|(o, t)| o != v && matched[o].is_none() && *t == Some(*want))
            {
                continue;
            }
            let mut candidates = locals
                .iter()
                .enumerate()
                .filter(|(l, (ty, _))| !taken[*l] && *ty == Some(*want));
            if let (Some((l, _)), None) = (candidates.next(), candidates.next()) {
                taken[l] = true;
                matched[v] = Some(l);
            }
        }

        for (v, m) in matched.into_iter().enumerate() {
            let Some(l) = m else { continue };
            let (_, loc) = locals[l];
            let (Some(file), Some(line)) = (loc.file.as_deref(), loc.line) else {
                continue;
            };
            let file = self.interner.intern(&display_path(
                loc.comp_dir.as_deref(),
                loc.dir.as_deref(),
                file,
            ));
            out[v] = Some(SourceLoc {
                file,
                line: line as u32,
            });
        }
        out
    }

    /// A variant member's declaration coordinates as plain strings, for
    /// comparing against a resume-function local's.
    fn member_loc(&self, m: &crate::raw_types::RawMember<crate::StrId>) -> Option<(String, u32)> {
        let loc = m.source_loc.as_deref()?;
        let file = loc.file.map(|f| self.reader.strings.get(f))?;
        Some((file.to_owned(), loc.line?.get() as u32))
    }

    fn convert(&mut self, id: TypeId) -> TypeDef {
        // Copying the reader reference out of `self` gives the type a
        // borrow independent of `&mut self`, so no clone is needed.
        let reader = self.reader;
        // `reserve` only queues ids present in the reader.
        let raw = reader.types.get(&id).expect("queued type must exist");
        match raw {
            RawType::Base(b) => TypeDef::Base {
                name: self.intern_opt(b.name),
                size: b.size,
                encoding: b.encoding,
            },
            RawType::Pointer(p) => TypeDef::Pointer {
                name: p.name.map(|n| self.interner.intern(reader.strings.get(n))),
                target: self.reserve(p.target_type_id),
            },
            RawType::Array(a) => TypeDef::Array {
                elem: self.reserve(a.elem_type_id),
                count: a.count,
            },
            RawType::Struct(st) => {
                let name = self.fq_name(id).unwrap_or_else(|| "<anon>".to_owned());
                TypeDef::Struct {
                    name: self.interner.intern(&name),
                    size: st.size,
                    members: st.members.iter().map(|m| self.convert_member(m)).collect(),
                }
            }
            RawType::Union(u) => {
                let name = self.fq_name(id).unwrap_or_else(|| "<anon>".to_owned());
                TypeDef::Union {
                    name: self.interner.intern(&name),
                    size: u.size,
                    members: u.members.iter().map(|m| self.convert_member(m)).collect(),
                }
            }
            RawType::Enum(e) => {
                let name = self.fq_name(id).unwrap_or_else(|| "<anon>".to_owned());
                let name = self.interner.intern(&name);
                match &e.shape {
                    RawVariantShape::CStyle {
                        repr_type_id,
                        enumerators,
                    } => {
                        let repr = match repr_type_id {
                            Some(r) => self.reserve(*r),
                            None => {
                                // No DW_AT_type on the enumeration: the
                                // repr is implied by the size. Synthesize
                                // an unsigned base of that width.
                                self.cenum_synth_repr += 1;
                                let n = self.interner.intern("<enum-repr>");
                                self.push_def(
                                    TypeDef::Base {
                                        name: n,
                                        size: e.size,
                                        encoding: Encoding::Unsigned,
                                    },
                                    None,
                                )
                            }
                        };
                        TypeDef::CEnum {
                            name,
                            size: e.size,
                            repr,
                            enumerators: enumerators
                                .iter()
                                .map(|en| {
                                    let n = self.intern_opt(Some(en.name));
                                    (n, en.value as i128)
                                })
                                .collect(),
                        }
                    }
                    RawVariantShape::Zero => TypeDef::Enum {
                        name,
                        size: e.size,
                        shape: VariantShape {
                            discr: None,
                            variants: Vec::new(),
                        },
                    },
                    RawVariantShape::One(v) => {
                        let sites = self.await_sites(id, &[&v.member]);
                        TypeDef::Enum {
                            name,
                            size: e.size,
                            shape: VariantShape {
                                discr: None,
                                variants: vec![VariantDef {
                                    name: self.intern_opt(v.member.name),
                                    discr_values: None,
                                    payload: self.convert_member(&v.member),
                                    decl: self.member_decl(&v.member),
                                    await_site: sites[0],
                                }],
                            },
                        }
                    }
                    RawVariantShape::Many { discr, variants } => {
                        let members: Vec<_> = variants.iter().map(|(_, v)| &v.member).collect();
                        let sites = self.await_sites(id, &members);
                        TypeDef::Enum {
                            name,
                            size: e.size,
                            shape: VariantShape {
                                discr: discr.as_ref().map(|d| DiscrDef {
                                    offset: d.offset,
                                    ty: self.reserve(d.type_id),
                                }),
                                variants: variants
                                    .iter()
                                    .zip(sites)
                                    .map(|((value, v), await_site)| VariantDef {
                                        name: self.intern_opt(v.member.name),
                                        discr_values: value
                                            .map(|x| DiscrValues(vec![DiscrValue::Value(x)])),
                                        payload: self.convert_member(&v.member),
                                        decl: self.member_decl(&v.member),
                                        await_site,
                                    })
                                    .collect(),
                            },
                        }
                    }
                }
            }
        }
    }

    /// Finish emission: build the sorted name index, the impl table,
    /// and the string table. `impl_selfs` is the sweep's impl-path →
    /// self-type map; only the paths some interned string mentions are
    /// recorded, so the table stays proportional to the names that will
    /// display, not to the binary's impl count.
    pub(super) fn finish(
        mut self,
        impl_selfs: &BTreeMap<String, String>,
    ) -> (TypeTable, crate::bundle::StringTable, ImplTable, Emitted) {
        let mut index: Vec<(String, BundleTypeId)> = self
            .names
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.as_ref().map(|n| (n.clone(), BundleTypeId(i as u32))))
            .collect();
        index.par_sort();
        let name_index = index
            .into_iter()
            .map(|(n, id)| (self.interner.intern(&n), id))
            .collect();

        let mut types = TypeTable {
            types: self.defs,
            debug_formats: self.debug_formats,
            name_index,
            env_decls: self.env_decls,
            ..Default::default()
        };
        let demoted = demote_types_with_members_out_of_bounds(&mut types, &self.names);
        let states = drop_members_of_other_states(&mut types, &self.names);

        let opaque = types
            .types
            .iter()
            .filter(|d| matches!(d, TypeDef::Opaque { .. }))
            .count();

        let counts = Emitted {
            opaque,
            demoted,
            states,
        };

        // Which recovered impl paths the bundle's strings mention. The
        // scan collects before interning: pushing entries grows the
        // very table being iterated. A `BTreeSet` hands the keys back
        // sorted, which is the order the validator requires.
        let mentioned: std::collections::BTreeSet<String> = self
            .interner
            .par_iter()
            .flat_map_iter(|s| crate::bundle::names::impl_paths(s))
            .filter(|path| impl_selfs.contains_key(*path))
            .map(str::to_owned)
            .collect();
        let impls = ImplTable {
            entries: mentioned
                .iter()
                .map(|path| {
                    let self_type = &impl_selfs[path];
                    (self.interner.intern(path), self.interner.intern(self_type))
                })
                .collect(),
        };

        let strings = self.interner.finish();
        types.build_normalized_index(&strings);
        (types, strings, impls, counts)
    }
}

/// What the closing passes over the emitted table found.
pub(super) struct Emitted {
    pub(super) opaque: usize,
    pub(super) demoted: usize,
    pub(super) states: StatePass,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_types::{
        RawEnum, RawEnumerator, RawMember, RawStruct, RawType, SourceLoc as RawSourceLoc,
        VariantShape,
    };
    use crate::{DwReader, StrId, TypeId};

    use gimli::UnitSectionOffset;

    use std::collections::BTreeMap;
    use std::num::NonZero;

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset(offset))
    }

    fn insert_struct(
        reader: &mut DwReader<'static>,
        id: TypeId,
        name: &'static str,
        members: &[(&'static str, TypeId)],
    ) {
        let members: Box<[RawMember<StrId>]> = members
            .iter()
            .map(|&(name, type_id)| RawMember {
                name: Some(reader.strings.intern(name)),
                offset: 0,
                type_id,
                source_loc: None,
            })
            .collect();
        let name = Some(reader.strings.intern(name));
        reader.types.insert(
            id,
            RawType::Struct(RawStruct {
                name,
                namespace: None,
                size: 8,
                members,
                template_params: Box::new([]),
                source_loc: None,
            }),
        );
    }

    /// A variant member awaiting `awaitee` (through a payload struct whose
    /// `__awaitee` member holds it), declared at `file:line` when given.
    fn awaiting_member(
        reader: &mut DwReader<'static>,
        payload: TypeId,
        awaitee: TypeId,
        loc: Option<(&'static str, u64)>,
    ) -> RawMember<StrId> {
        insert_struct(
            reader,
            payload,
            "{async_fn_env#0}::Suspend0",
            &[("__awaitee", awaitee)],
        );
        let source_loc = loc.map(|(file, line)| {
            Box::new(RawSourceLoc {
                file: Some(reader.strings.intern(file)),
                dir: None,
                comp_dir: None,
                line: NonZero::new(line),
                column: None,
            })
        });
        RawMember {
            name: Some(reader.strings.intern("0")),
            offset: 0,
            type_id: payload,
            source_loc,
        }
    }

    fn local(awaitee: TypeId, file: &str, line: u64) -> (Option<TypeId>, OwnedLoc) {
        (
            Some(awaitee),
            OwnedLoc {
                file: Some(file.to_owned()),
                dir: None,
                comp_dir: None,
                line: Some(line),
            },
        )
    }

    #[test]
    fn test_unresolved_references_are_counted_per_reference() {
        let reader = DwReader::default();
        let mut em = Emitter::new(&reader, BTreeMap::new(), None, None);
        em.reserve(type_id(0x10));
        em.reserve(type_id(0x20));
        assert_eq!(em.unresolved_refs, 2);
    }

    #[test]
    fn test_a_cstyle_enum_without_a_repr_synthesizes_one_each_time() {
        let mut reader = DwReader::default();
        for offset in [0x10usize, 0x20] {
            let name = reader.strings.intern("Bare");
            reader.types.insert(
                type_id(offset),
                RawType::Enum(RawEnum {
                    name: Some(name),
                    namespace: None,
                    size: 1,
                    alignment: None,
                    shape: VariantShape::CStyle {
                        repr_type_id: None,
                        enumerators: Box::new([RawEnumerator {
                            name: reader.strings.intern("Red"),
                            value: 0,
                        }]),
                    },
                    template_params: Box::new([]),
                    source_loc: None,
                }),
            );
        }
        let mut em = Emitter::new(&reader, BTreeMap::new(), None, None);
        em.emit(type_id(0x10));
        em.emit(type_id(0x20));
        assert_eq!(em.cenum_synth_repr, 2);
    }

    #[test]
    fn test_awaits_pair_only_where_type_and_coordinates_agree() {
        let mut reader = DwReader::default();
        let t1 = type_id(1);
        let t2 = type_id(2);
        insert_struct(&mut reader, t1, "T1", &[]);
        insert_struct(&mut reader, t2, "T2", &[]);
        let env = type_id(3);
        insert_struct(&mut reader, env, "{async_fn_env#0}", &[]);
        // Member A: rustc already attributed the await to main.rs:5,
        // which local 0 confirms; local 1 shares the type but not the
        // line, so coordinates decide. Member B awaits a type no local
        // carries and must stay unmatched, whatever its coordinates say.
        let a = awaiting_member(&mut reader, type_id(0x10), t1, Some(("main.rs", 5)));
        let b = awaiting_member(&mut reader, type_id(0x11), t2, Some(("main.rs", 9)));

        let locals =
            BTreeMap::from([(env, vec![local(t1, "main.rs", 5), local(t1, "main.rs", 9)])]);
        let mut em = Emitter::new(&reader, locals, None, None);
        let sites = em.await_sites(env, &[&a, &b]);
        let [site_a, site_b] = sites.as_slice() else {
            panic!("one site per member");
        };
        let site_a = site_a.as_ref().expect("agreeing coordinates pair");
        assert_eq!(site_a.line, 5);
        assert_eq!(em.interner.get(site_a.file), Some("main.rs"));
        assert!(site_b.is_none(), "no local carries T2");
    }

    #[test]
    fn test_a_shared_awaited_type_needs_agreeing_coordinates() {
        let mut reader = DwReader::default();
        let t = type_id(1);
        insert_struct(&mut reader, t, "T", &[]);
        let env = type_id(2);
        insert_struct(&mut reader, env, "{async_fn_env#0}", &[]);
        // Two awaits of one type, neither agreeing with the local's
        // coordinates (the file differs): matching either would be a
        // guess, so both stay unmatched.
        let c = awaiting_member(&mut reader, type_id(0x10), t, Some(("x.rs", 5)));
        let d = awaiting_member(&mut reader, type_id(0x11), t, Some(("y.rs", 6)));

        let locals = BTreeMap::from([(env, vec![local(t, "main.rs", 5)])]);
        let mut em = Emitter::new(&reader, locals, None, None);
        let sites = em.await_sites(env, &[&c, &d]);
        assert_eq!(sites, vec![None, None]);
    }

    #[test]
    fn test_a_decisive_type_pairs_without_coordinates() {
        let mut reader = DwReader::default();
        let t4 = type_id(1);
        let t5 = type_id(2);
        insert_struct(&mut reader, t4, "T4", &[]);
        insert_struct(&mut reader, t5, "T5", &[]);
        let env = type_id(3);
        insert_struct(&mut reader, env, "{async_fn_env#0}", &[]);
        // Neither member carries coordinates. T4 has no local; T5 picks
        // out exactly one on each side, which is enough.
        let e = awaiting_member(&mut reader, type_id(0x10), t4, None);
        let f = awaiting_member(&mut reader, type_id(0x11), t5, None);

        let locals = BTreeMap::from([(env, vec![local(t5, "main.rs", 7)])]);
        let mut em = Emitter::new(&reader, locals, None, None);
        let sites = em.await_sites(env, &[&e, &f]);
        let [site_e, site_f] = sites.as_slice() else {
            panic!("one site per member");
        };
        assert!(site_e.is_none(), "T4 has no local");
        let site_f = site_f.as_ref().expect("a decisive type pairs");
        assert_eq!(site_f.line, 7);
    }
}

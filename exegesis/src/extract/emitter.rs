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
    BundleTypeId, DiscrDef, DiscrValue, DiscrValues, DisplayNode, MemberDef, MemberRef, SourceLoc,
    StrRef, StringInterner, TypeDef, TypeTable, VariantDef, VariantShape,
};
use crate::detect::{Family, FormatExplanation, trace, unique_member};
use crate::raw_types::{RawType, VariantShape as RawVariantShape};
use crate::{DwReader, Encoding, TypeId};

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
        let fq = self.fq_name(id);
        let bid = self.push_placeholder(fq);
        self.ids.insert(id, bid);
        self.pending.push_back((id, bid));
        bid
    }

    /// The shared `<unresolved>` opaque entry.
    fn unresolved_placeholder(&mut self) -> BundleTypeId {
        if let Some(bid) = self.unresolved {
            return bid;
        }
        let name = self.interner.intern(UNRESOLVED);
        let bid = BundleTypeId(self.defs.len() as u32);
        self.defs.push(TypeDef::Opaque { name, size: None });
        self.names.push(None);
        self.unresolved = Some(bid);
        bid
    }

    /// A named opaque placeholder (missing Cell/Stage/infra).
    pub(super) fn placeholder(&mut self, name: &str) -> BundleTypeId {
        let name = self.interner.intern(name);
        let bid = BundleTypeId(self.defs.len() as u32);
        self.defs.push(TypeDef::Opaque { name, size: None });
        self.names.push(None);
        bid
    }

    fn push_placeholder(&mut self, name: Option<String>) -> BundleTypeId {
        let bid = BundleTypeId(self.defs.len() as u32);
        let n = self.interner.intern(UNRESOLVED);
        self.defs.push(TypeDef::Opaque {
            name: n,
            size: None,
        });
        self.names.push(name);
        bid
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
        let loc = m.source_loc.as_deref()?;
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
                                let bid = BundleTypeId(self.defs.len() as u32);
                                self.defs.push(TypeDef::Base {
                                    name: n,
                                    size: e.size,
                                    encoding: Encoding::Unsigned,
                                });
                                self.names.push(None);
                                bid
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

    /// Finish emission: build the sorted name index and the string table.
    pub(super) fn finish(mut self) -> (TypeTable, crate::bundle::StringTable, Emitted) {
        let mut index: Vec<(String, BundleTypeId)> = self
            .names
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.as_ref().map(|n| (n.clone(), BundleTypeId(i as u32))))
            .collect();
        index.sort();
        let name_index = index
            .into_iter()
            .map(|(n, id)| (self.interner.intern(&n), id))
            .collect();

        let mut types = TypeTable {
            types: self.defs,
            debug_formats: self.debug_formats,
            name_index,
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
        let strings = self.interner.finish();
        types.build_normalized_index(&strings);
        (types, strings, counts)
    }
}

/// What the closing passes over the emitted table found.
pub(super) struct Emitted {
    pub(super) opaque: usize,
    pub(super) demoted: usize,
    pub(super) states: StatePass,
}

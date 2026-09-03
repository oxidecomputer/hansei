// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::raw_types::{
    CommonAttrs, Encoding, NamespaceTable, NsId, RawArray, RawAwaitee, RawBase, RawEnum,
    RawEnumerator, RawFunc, RawGenericParameter, RawMember, RawPointer, RawStaticVariable,
    RawStruct, RawSubParameter, RawType, RawUnion, RawVariant, SourceLoc, VariantShape,
};
use crate::{Error, FuncId, Result, Slice, TypeId, VarId};

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use gimli::{
    Attribute, AttributeValue, DebuggingInformationEntry, EntriesCursor, EvaluationResult, Reader,
    UnitRef, UnitSectionOffset,
};
use tracing::debug;

const ANON: &str = "<anon>";
const UNNAMED_CGU: &str = "<unnamed_cgu>";

/// The unit being parsed, carrying the constant that places its DIE
/// offsets in the reader's one id space.
///
/// A unit read from a plain `.debug_info` needs no help: gimli's
/// section offsets are unique across the whole file, and `bias` is 0.
/// A unit resolved out of a DWARF package is handed *sliced* sections —
/// each contribution's offsets restart near zero — so equal ids from
/// different units would silently alias distinct types through the
/// dedup. `bias` is a per-unit constant the reader allocates to keep
/// every unit's ids disjoint (see `read_types_package` for how the
/// constants are chosen), and adding one per-unit constant preserves
/// every equality because split DWARF forbids cross-unit references:
/// nothing a unit can spell escapes its own contribution.
///
/// Every conversion from a DIE or attribute to a [`UnitSectionOffset`]
/// must go through [`Self::die_offset`] / [`Self::attr_ref`]; one raw
/// `to_unit_section_offset` call is a silent cross-unit aliasing bug in
/// package mode.
pub(crate) struct UnitCtx<'a, 'dw> {
    unit: UnitRef<'a, Slice<'dw>>,
    bias: usize,
}

impl<'a, 'dw> UnitCtx<'a, 'dw> {
    pub(crate) fn new(unit: UnitRef<'a, Slice<'dw>>, bias: usize) -> Self {
        Self { unit, bias }
    }

    fn biased(&self, offset: UnitSectionOffset) -> UnitSectionOffset {
        match offset {
            UnitSectionOffset::DebugInfoOffset(o) => {
                UnitSectionOffset::DebugInfoOffset(gimli::DebugInfoOffset(o.0 + self.bias))
            }
            UnitSectionOffset::DebugTypesOffset(o) => {
                UnitSectionOffset::DebugTypesOffset(gimli::DebugTypesOffset(o.0 + self.bias))
            }
        }
    }

    /// The id-space offset of a DIE in this unit.
    pub(crate) fn die_offset(
        &self,
        entry: &DebuggingInformationEntry<'_, '_, Slice<'dw>>,
    ) -> UnitSectionOffset {
        self.biased(entry.offset().to_unit_section_offset(&self.unit))
    }

    /// The id-space offset a reference attribute points at, under either
    /// spelling a same-file reference can take (`DW_FORM_ref*` relative
    /// to the unit, `DW_FORM_ref_addr` relative to the section). `None`
    /// for any other value class.
    pub(crate) fn attr_ref(&self, value: AttributeValue<Slice<'dw>>) -> Option<UnitSectionOffset> {
        match value {
            AttributeValue::UnitRef(o) => Some(self.biased(o.to_unit_section_offset(&self.unit))),
            AttributeValue::DebugInfoRef(o) => Some(self.biased(o.into())),
            _ => None,
        }
    }
}

impl<'a, 'dw> std::ops::Deref for UnitCtx<'a, 'dw> {
    type Target = UnitRef<'a, Slice<'dw>>;

    fn deref(&self) -> &Self::Target {
        &self.unit
    }
}

/// The parsed contents of a single DWARF codegen unit.
#[derive(Debug)]
pub struct CodegenUnit<'dw> {
    /// Name of this codegen unit.
    pub name: &'dw str,
    /// The `DW_AT_producer` string (compiler identification), if present.
    pub producer: Option<&'dw str>,
    /// Starting offset of this unit in the debug info section.
    #[allow(dead_code)]
    pub offset: UnitSectionOffset,
    /// Current namespace context.
    pub(crate) ns: Option<NsId>,
    /// Namespace table for this codegen unit.
    pub namespaces: NamespaceTable<&'dw str>,
    /// All collected types, indexed by `TypeId`.
    pub types: HashMap<TypeId, RawType<&'dw str>>,
    /// DIEs describing function signatures. Their details are deliberately
    /// not modeled, but pointers targeting them are function pointers.
    pub subroutine_types: HashSet<TypeId>,
    /// Static variables collected.
    pub variables: HashMap<VarId, RawStaticVariable<&'dw str>>,
    /// Type DIEs marked with `DW_AT_declaration`.
    pub type_declarations: HashSet<TypeId>,
    /// Type DIE → declaration DIE from `DW_AT_specification`.
    pub type_specifications: HashMap<TypeId, TypeId>,
    /// Functions.
    pub funcs: HashMap<FuncId, RawFunc<&'dw str>>,
}

impl<'dw> CodegenUnit<'dw> {
    pub fn add_type<T: Into<RawType<&'dw str>>>(&mut self, offset: UnitSectionOffset, ty: T) {
        let ty = ty.into();
        let id = TypeId(offset);

        if ty.name().is_none() && ty.namespace().is_none() {
            debug!(ty = ?ty, "no name or namespace");
        }
        self.types.insert(id, ty);
    }

    pub fn add_var(&mut self, offset: UnitSectionOffset, var: RawStaticVariable<&'dw str>) {
        let id = offset.into();
        self.variables.insert(id, var);
    }

    fn record_type_attrs(&mut self, common: &CommonAttrs<'dw>) {
        let id = TypeId(common.debug_offset);
        if common.is_decl {
            self.type_declarations.insert(id);
        }
        if let Some(specification) = common.specification {
            self.type_specifications.insert(id, TypeId(specification));
        }
    }

    pub fn add_function(&mut self, offset: UnitSectionOffset, func: RawFunc<&'dw str>) {
        let id = offset.into();
        self.funcs.insert(id, func);
    }

    /// Pushes a path component onto the namespace path stack and runs `body`,
    /// popping the stack when it completes.
    pub(crate) fn with_namespace<F, T>(&mut self, ns: NsId, body: F) -> T
    where
        F: FnOnce(&mut Self) -> T,
    {
        let old_ns = self.ns.replace(ns);
        let result = body(self);
        self.ns = old_ns;
        result
    }

    /// Parse a compile unit from the cursor, which must be positioned at a
    /// `DW_TAG_compile_unit` entry. Returns a fully initialized
    /// [`CodegenUnit`].
    pub fn from_cursor(
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<Self> {
        let entry = cursor
            .current()
            .expect("cursor must be positioned at a compile unit entry");
        assert_eq!(entry.tag(), gimli::DW_TAG_compile_unit);

        let offset = unit.die_offset(entry);
        let name = match entry.attr(gimli::DW_AT_name)? {
            Some(attr) => attr.attr_str(unit)?,
            None => UNNAMED_CGU,
        };
        let producer = match entry.attr(gimli::DW_AT_producer)? {
            Some(attr) => Some(attr.attr_str(unit)?),
            None => None,
        };

        let mut cgu = Self {
            name,
            producer,
            offset,
            ns: None,
            namespaces: NamespaceTable::new(),
            types: HashMap::new(),
            subroutine_types: HashSet::new(),
            variables: HashMap::new(),
            type_declarations: HashSet::new(),
            type_specifications: HashMap::new(),
            funcs: HashMap::new(),
        };

        if entry.has_children() {
            while let Some(()) = cursor.next_entry()? {
                if cursor.current().is_some() {
                    cgu.parse_nested_types(unit, cursor)?;
                } else {
                    break;
                }
            }
        }

        Ok(cgu)
    }

    fn parse_nested_types(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let Some(entry) = cursor.current() else {
            return Ok(());
        };

        match entry.tag() {
            gimli::DW_TAG_base_type => self.parse_base(unit, cursor),
            gimli::DW_TAG_namespace => self.parse_namespace(unit, cursor),
            gimli::DW_TAG_pointer_type => self.parse_pointer_type(unit, cursor),
            gimli::DW_TAG_subroutine_type => {
                let id = TypeId(unit.die_offset(entry));
                self.subroutine_types.insert(id);
                cursor.consume_entry()
            }
            gimli::DW_TAG_structure_type => self.process_struct(unit, cursor),
            gimli::DW_TAG_union_type => self.process_union(unit, cursor),
            gimli::DW_TAG_array_type => self.parse_array_type(unit, cursor),
            gimli::DW_TAG_enumeration_type => self.parse_enumeration_type(unit, cursor),
            gimli::DW_TAG_variable => self.process_static_variable(unit, cursor),
            gimli::DW_TAG_subprogram => self.process_function(unit, cursor),
            _ => cursor.consume_entry(),
        }
    }

    fn parse_base(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let Some(entry) = cursor.current() else {
            return Ok(());
        };
        assert!(entry.tag() == gimli::DW_TAG_base_type);

        let mut encoding = None;
        let skip = false; // TODO make this needed

        let common = CommonAttrs::from_entry(unit, entry, |attr| {
            if attr.name() == gimli::DW_AT_encoding {
                if let AttributeValue::Encoding(e) = attr.value() {
                    encoding = Some(match e {
                        gimli::DW_ATE_unsigned => Encoding::Unsigned,
                        gimli::DW_ATE_signed => Encoding::Signed,
                        gimli::DW_ATE_boolean => Encoding::Boolean,
                        gimli::DW_ATE_unsigned_char => Encoding::UnsignedChar,
                        gimli::DW_ATE_signed_char => Encoding::SignedChar,
                        gimli::DW_ATE_float => Encoding::Float,
                        gimli::DW_ATE_UTF => Encoding::UtfChar,
                        _ => {
                            panic!("unexpected encoding for Base type: {:?}", attr.value());
                        }
                    });
                }
            } else {
                panic!("Unused attr for Base type: {attr:?}");
            }
            Ok(())
        })?;

        self.record_type_attrs(&common);

        if skip {
            return cursor.consume_entry();
        }

        self.add_type(
            common.debug_offset,
            RawBase {
                name: common.name,
                namespace: self.ns,
                encoding: encoding.unwrap(),
                size: common.size.unwrap(),
                alignment: common.alignment,
            },
        );

        Ok(())
    }

    fn parse_pointer_type(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let entry = cursor.current().unwrap();
        assert!(entry.tag() == gimli::DW_TAG_pointer_type);

        let common = CommonAttrs::from_entry(unit, entry, |_| Ok(()))?;

        self.record_type_attrs(&common);

        if common.is_decl {
            //self.add_decl(common.debug_offset, common.name);
            return cursor.consume_entry();
        }

        if common.type_id.is_none() {
            debug!(
                "pointer type missing pointee typeid at: {:x?}",
                common.debug_offset
            );
            return cursor.consume_entry();
        }

        let target_type_id = TypeId(common.type_id.unwrap());

        // TODO: why consume everything?
        if entry.has_children() {
            while let Some(()) = cursor.next_entry()? {
                if cursor.current().is_some() {
                    cursor.consume_entry()?;
                } else {
                    break;
                }
            }
        }

        self.add_type(
            common.debug_offset,
            RawPointer {
                name: common.name,
                target_type_id,
            },
        );
        Ok(())
    }

    fn parse_namespace(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let entry = cursor.current().unwrap();
        assert!(entry.tag() == gimli::DW_TAG_namespace);

        let common = CommonAttrs::from_entry(unit, entry, |_| Ok(()))?;

        let ns = self.namespaces.insert(self.ns, common.name.unwrap_or(ANON));

        if entry.has_children() {
            self.with_namespace(ns, |this| {
                while cursor.next_entry()?.is_some() {
                    if cursor.current().is_some() {
                        this.parse_nested_types(unit, cursor)?;
                    } else {
                        break;
                    }
                }
                Ok(())
            })
        } else {
            Ok(())
        }
    }

    fn process_struct(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let Some(entry) = cursor.current() else {
            return Ok(());
        };
        assert!(entry.tag() == gimli::DW_TAG_structure_type);

        let mut members = Vec::new();
        let mut template_params = Vec::new();
        let mut variant_shape: Option<VariantShape<&'dw str>> = None;
        let common = CommonAttrs::from_entry(unit, entry, |_| Ok(()))?;

        self.record_type_attrs(&common);

        let ns = self.namespaces.insert(self.ns, common.name.unwrap_or(ANON));

        if entry.has_children() {
            self.with_namespace(ns, |this| {
                while let Some(()) = cursor.next_entry()? {
                    if let Some(child) = cursor.current() {
                        match child.tag() {
                            gimli::DW_TAG_variant_part => {
                                variant_shape = Some(parse_variant_part(unit, cursor)?);
                            }
                            gimli::DW_TAG_member => {
                                let m = process_member(unit, cursor)?;
                                members.push(m);
                            }
                            gimli::DW_TAG_template_type_parameter => {
                                template_params.extend(process_generic_parameter(unit, cursor)?);
                            }
                            _ => {
                                this.parse_nested_types(unit, cursor)?;
                            }
                        }
                    } else {
                        break;
                    }
                }
                Ok::<_, Error>(())
            })?;
        }

        let source_loc = boxed_source_loc(common.source_loc);
        if let Some(shape) = variant_shape {
            self.add_type(
                common.debug_offset,
                RawEnum {
                    name: common.name,
                    namespace: self.ns,
                    size: common.size.unwrap_or_default(),
                    alignment: common.alignment,
                    shape,
                    template_params: template_params.into_boxed_slice(),
                    source_loc,
                },
            );
        } else {
            self.add_type(
                common.debug_offset,
                RawStruct {
                    name: common.name,
                    namespace: self.ns,
                    size: common.size.unwrap_or_default(),
                    members: members.into_boxed_slice(),
                    template_params: template_params.into_boxed_slice(),
                    source_loc,
                },
            );
        }

        Ok(())
    }

    /// Parse a `DW_TAG_union_type` into a [`RawUnion`]. Structurally a
    /// struct without variant parts: members, template parameters, and
    /// nested type definitions.
    fn process_union(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let Some(entry) = cursor.current() else {
            return Ok(());
        };
        assert!(entry.tag() == gimli::DW_TAG_union_type);

        let mut members = Vec::new();
        let mut template_params = Vec::new();
        let common = CommonAttrs::from_entry(unit, entry, |_| Ok(()))?;

        self.record_type_attrs(&common);

        let ns = self.namespaces.insert(self.ns, common.name.unwrap_or(ANON));

        if entry.has_children() {
            self.with_namespace(ns, |this| {
                while let Some(()) = cursor.next_entry()? {
                    if let Some(child) = cursor.current() {
                        match child.tag() {
                            gimli::DW_TAG_member => {
                                let m = process_member(unit, cursor)?;
                                members.push(m);
                            }
                            gimli::DW_TAG_template_type_parameter => {
                                template_params.extend(process_generic_parameter(unit, cursor)?);
                            }
                            _ => {
                                this.parse_nested_types(unit, cursor)?;
                            }
                        }
                    } else {
                        break;
                    }
                }
                Ok::<_, Error>(())
            })?;
        }

        self.add_type(
            common.debug_offset,
            RawUnion {
                name: common.name,
                namespace: self.ns,
                size: common.size.unwrap_or_default(),
                members: members.into_boxed_slice(),
                template_params: template_params.into_boxed_slice(),
                source_loc: boxed_source_loc(common.source_loc),
            },
        );

        Ok(())
    }

    /// Parse a `DW_TAG_array_type` into a [`RawArray`]: the element type
    /// from `DW_AT_type`, the length from the `DW_AT_count` of the
    /// `DW_TAG_subrange_type` child.
    fn parse_array_type(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let entry = cursor.current().unwrap();
        assert!(entry.tag() == gimli::DW_TAG_array_type);

        let common = CommonAttrs::from_entry(unit, entry, |_| Ok(()))?;

        self.record_type_attrs(&common);

        let Some(elem) = common.type_id else {
            debug!(
                "array type missing element typeid at {:x?}",
                common.debug_offset
            );
            return cursor.consume_entry();
        };

        let mut count = None;
        if entry.has_children() {
            while let Some(()) = cursor.next_entry()? {
                if let Some(child) = cursor.current() {
                    if child.tag() == gimli::DW_TAG_subrange_type
                        && count.is_none()
                        && let Some(attr) = child.attr(gimli::DW_AT_count)?
                    {
                        count = attr.value().udata_value();
                    }
                    cursor.consume_entry()?;
                } else {
                    break;
                }
            }
        }

        self.add_type(
            common.debug_offset,
            RawArray {
                elem_type_id: TypeId(elem),
                // A subrange without DW_AT_count means the length is
                // unknown (C flexible arrays); model it as zero-length.
                count: count.unwrap_or(0),
            },
        );

        Ok(())
    }

    /// Parse a `DW_TAG_enumeration_type` (C-style enum) into a `RawEnum`
    /// with `VariantShape::CStyle`.
    fn parse_enumeration_type(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let entry = cursor.current().unwrap();
        assert!(entry.tag() == gimli::DW_TAG_enumeration_type);

        let common = CommonAttrs::from_entry(unit, entry, |_| Ok(()))?;

        self.record_type_attrs(&common);

        if common.is_decl {
            return cursor.consume_entry();
        }

        let repr_type_id = common.type_id.map(crate::TypeId);

        let mut enumerators = Vec::new();
        if entry.has_children() {
            while let Some(()) = cursor.next_entry()? {
                if let Some(child) = cursor.current() {
                    match child.tag() {
                        gimli::DW_TAG_enumerator => {
                            enumerators.push(parse_enumerator(unit, cursor)?);
                        }
                        _ => {
                            cursor.consume_entry()?;
                        }
                    }
                } else {
                    break;
                }
            }
        }

        self.add_type(
            common.debug_offset,
            RawEnum {
                name: common.name,
                namespace: self.ns,
                size: common.size.unwrap_or_default(),
                alignment: common.alignment,
                shape: VariantShape::CStyle {
                    repr_type_id,
                    enumerators: enumerators.into_boxed_slice(),
                },
                template_params: Box::default(),
                source_loc: boxed_source_loc(common.source_loc),
            },
        );

        Ok(())
    }

    fn process_static_variable(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let entry = cursor.current().unwrap();
        assert!(entry.tag() == gimli::DW_TAG_variable);

        let mut linkage_name = None;
        let mut addr = None;

        let offset = unit.die_offset(entry);
        let common = CommonAttrs::from_entry(unit, entry, |attr| {
            match attr.name() {
                gimli::DW_AT_linkage_name => {
                    linkage_name = Some(attr.attr_str(unit)?);
                }
                gimli::DW_AT_location => {
                    let Some(e) = attr.exprloc_value() else {
                        debug!("non-exprloc static location at {offset:#x?}");
                        return Ok(());
                    };
                    let mut eval = e.evaluation(unit.encoding());
                    let mut result = eval.evaluate()?;
                    loop {
                        match result {
                            gimli::EvaluationResult::Complete => {
                                let r = eval.result();
                                if let [piece] = &r[..] {
                                    match &piece.location {
                                        gimli::Location::Address { address } => {
                                            addr = Some(*address);
                                        }
                                        x => {
                                            debug!("unexpected static location: {x:?}");
                                        }
                                    }
                                } else {
                                    // TODO handle u128s
                                    debug!("unhandled eval results for {:?}: {r:?}", linkage_name);
                                }
                                break;
                            }
                            EvaluationResult::RequiresRelocatedAddress(a) => {
                                result = eval.resume_with_relocated_address(a)?;
                            }
                            // A split unit spells the address as an index
                            // into the binary's `.debug_addr` (the unit's
                            // addr base was copied over from its skeleton).
                            EvaluationResult::RequiresIndexedAddress { index, relocate: _ } => {
                                result = eval.resume_with_indexed_address(unit.address(index)?)?;
                            }
                            other => {
                                // TLS statics land here (their locations
                                // need a runtime TLS base); keep the
                                // variable with no address.
                                debug!("unhandled location expression at {offset:#x?}: {other:?}");
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
            Ok(())
        })?;

        // Variables with unresolvable locations (TLS statics, in
        // particular) are kept: their linkage names are still meaningful
        // to extraction even when no static address exists.
        if addr.is_none() {
            debug!("no addr for static {:?}", common.name);
        }

        let type_id = match common.type_id {
            Some(t) => TypeId(t),
            None => return cursor.consume_entry(),
        };

        self.add_var(
            offset,
            RawStaticVariable {
                name: common.name,
                namespace: self.ns,
                type_id,
                source_loc: common.source_loc,
                addr,
                linkage_name,
            },
        );
        Ok(())
    }

    fn process_function(
        &mut self,
        unit: &UnitCtx<'_, 'dw>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let entry = cursor.current().unwrap();
        assert!(entry.tag() == gimli::DW_TAG_subprogram);
        let mut linkage_name = None;
        let mut lo_pc = None;
        let mut hi_pc = None;
        let mut abstract_origin = None;
        let mut noreturn = false;

        let common = CommonAttrs::from_entry(unit, entry, |attr| {
            match attr.name() {
                gimli::DW_AT_linkage_name => {
                    linkage_name = Some(attr.attr_str(unit)?);
                }
                gimli::DW_AT_noreturn => match attr.value() {
                    gimli::AttributeValue::Flag(f) => {
                        noreturn = f;
                    }
                    v => panic!("unexpected noreturn value: {:?}", v),
                },
                gimli::DW_AT_low_pc => match attr.value() {
                    gimli::AttributeValue::Addr(a) => lo_pc = Some(a),
                    // Split units index `.debug_addr` instead; nothing
                    // reads `lo_pc`, so it is not worth resolving.
                    gimli::AttributeValue::DebugAddrIndex(_) => {}
                    v => debug!("unexpected low_pc type: {v:?}"),
                },
                gimli::DW_AT_high_pc => {
                    hi_pc = attr.value().udata_value();
                    if hi_pc.is_none() {
                        debug!("non udata hi_pc {:?}", attr.value());
                    }
                }
                gimli::DW_AT_abstract_origin => match unit.attr_ref(attr.value()) {
                    Some(o) => abstract_origin = Some(o),
                    None => panic!("unexpected abstract_origin type: {:?}", attr.value()),
                },
                // sibling
                // inline
                // prototyped
                // external
                // frame_base
                _ => {
                    //println!("skipping function attr: {:x?}", attr.name());
                }
            }
            Ok(())
        })?;

        // A coroutine's resume function is the only place `__awaitee`
        // locals exist, and reaching them means walking into the lexical
        // blocks the body nests one per suspend point. Every other
        // function's blocks stay unvisited: on a large binary that walk
        // would cost far more than the handful of awaits it would find.
        let resume_fn = common
            .name
            .is_some_and(|n| n.starts_with("{async_fn#") || n.starts_with("{async_block#"));

        let mut formal_parameters = vec![];
        let mut template_params = vec![];
        let mut awaitees = vec![];
        if entry.has_children() {
            while let Some(()) = cursor.next_entry()? {
                if let Some(child) = cursor.current() {
                    match child.tag() {
                        gimli::DW_TAG_formal_parameter => {
                            formal_parameters.push(process_sub_parameter(unit, cursor)?);
                        }
                        gimli::DW_TAG_template_type_parameter => {
                            template_params.extend(process_generic_parameter(unit, cursor)?);
                        }
                        gimli::DW_TAG_lexical_block if resume_fn => {
                            collect_awaitees(unit, cursor, &mut awaitees)?;
                        }
                        gimli::DW_TAG_variable if resume_fn => {
                            if let Some(awaitee) = process_awaitee(unit, cursor)? {
                                awaitees.push(awaitee);
                            }
                        }
                        _ => {
                            //println!("skipping function content: {:x?}", child.tag());
                            cursor.consume_entry()?;
                        }
                    }
                } else {
                    break;
                }
            }
        }

        //let name = self.format_path(common.name);
        let source_loc = if !common.source_loc.is_empty() {
            Some(Box::new(common.source_loc))
        } else {
            None
        };

        self.add_function(
            common.debug_offset,
            RawFunc {
                namespace: self.ns,
                name: common.name,
                source_loc,
                return_type_id: common.type_id.map(TypeId),
                formal_parameters: formal_parameters.into_boxed_slice(),
                abstract_origin,
                linkage_name,
                template_params: template_params.into_boxed_slice(),
                noreturn,
                awaitees: awaitees.into_boxed_slice(),
            },
        );

        Ok(())
    }
}

/// Walk a lexical block and everything under it, gathering `__awaitee`
/// locals. A resume body nests one block per suspend point, so the
/// awaits of a coroutine with several of them sit at different depths.
fn collect_awaitees<'dw>(
    unit: &UnitCtx<'_, 'dw>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
    out: &mut Vec<RawAwaitee<&'dw str>>,
) -> Result<()> {
    debug_assert!(cursor.current().unwrap().tag() == gimli::DW_TAG_lexical_block);
    if !cursor.current().unwrap().has_children() {
        cursor.consume_entry()?;
        return Ok(());
    }
    // Blocks left open, closed one at a time by the null entry that ends
    // each one's children. Leaving a block unconsumed is what makes the
    // next step descend into it.
    let mut depth = 1usize;
    while depth > 0 {
        let Some(()) = cursor.next_entry()? else {
            break;
        };
        match cursor.current() {
            None => depth -= 1,
            Some(child) => match child.tag() {
                gimli::DW_TAG_lexical_block if child.has_children() => depth += 1,
                gimli::DW_TAG_variable => {
                    if let Some(awaitee) = process_awaitee(unit, cursor)? {
                        out.push(awaitee);
                    }
                }
                _ => cursor.consume_entry()?,
            },
        }
    }
    Ok(())
}

/// Read a `DW_TAG_variable` if it is an `__awaitee`, else skip it.
fn process_awaitee<'dw>(
    unit: &UnitCtx<'_, 'dw>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<Option<RawAwaitee<&'dw str>>> {
    let entry = cursor.current().unwrap();
    debug_assert!(entry.tag() == gimli::DW_TAG_variable);
    let common = CommonAttrs::from_entry(unit, entry, |_| Ok(()))?;
    if common.name != Some("__awaitee") {
        cursor.consume_entry()?;
        return Ok(None);
    }
    let awaitee = RawAwaitee {
        source_loc: boxed_source_loc(common.source_loc),
        type_id: common.type_id.map(TypeId),
    };
    cursor.consume_entry()?;
    Ok(Some(awaitee))
}

/// Box a [`SourceLoc`] for storage, or `None` if it carries no information.
fn boxed_source_loc<S>(loc: SourceLoc<S>) -> Option<Box<SourceLoc<S>>> {
    if loc.is_empty() {
        None
    } else {
        Some(Box::new(loc))
    }
}

fn process_member<'dw>(
    unit: &UnitCtx<'_, 'dw>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<RawMember<&'dw str>> {
    let entry = cursor.current().unwrap();
    assert!(entry.tag() == gimli::DW_TAG_member);

    let mut offset = None;

    let common = CommonAttrs::from_entry(unit, entry, |attr| {
        if attr.name() == gimli::DW_AT_data_member_location {
            if attr.value().udata_value().is_none() {
                debug!("non udata value {:?}", attr.value());
            }
            offset = attr.value().udata_value();
        }

        Ok(())
    })?;

    // Data members without a `DW_AT_data_member_location` can be assumed to be
    // at the start of the parent struct.
    // Section 5.7.6, page 118.
    let offset = offset.unwrap_or(0);
    let target_debug_offset = common.type_id.unwrap();

    // TODO: handle partial resolution of types.
    let type_id = TypeId(target_debug_offset);

    Ok(RawMember {
        name: common.name,
        offset,
        type_id,
        source_loc: boxed_source_loc(common.source_loc),
    })
}

/// Parse a `DW_TAG_variant_part` entry and its children into a
/// [`VariantShape`].
///
/// The cursor must be positioned at the `DW_TAG_variant_part` entry.
fn parse_variant_part<'dw>(
    unit: &UnitCtx<'_, 'dw>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<VariantShape<&'dw str>> {
    let entry = cursor.current().unwrap();
    assert!(entry.tag() == gimli::DW_TAG_variant_part);

    // DW_AT_discr is a reference to the discriminant member DIE.
    let mut discr_ref = None;
    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next()? {
        if attr.name() == gimli::DW_AT_discr {
            match unit.attr_ref(attr.value()) {
                Some(o) => discr_ref = Some(o),
                None => debug!("unexpected DW_AT_discr value: {:?}", attr.value()),
            }
        }
    }

    let mut discr_members = Vec::new();
    let mut variants = Vec::new();

    if entry.has_children() {
        while let Some(()) = cursor.next_entry()? {
            if let Some(child) = cursor.current() {
                match child.tag() {
                    gimli::DW_TAG_member => {
                        discr_members.push(process_member(unit, cursor)?);
                    }
                    gimli::DW_TAG_variant => {
                        variants.push(parse_variant(unit, cursor)?);
                    }
                    _ => {
                        cursor.consume_entry()?;
                    }
                }
            } else {
                break;
            }
        }
    }

    if variants.is_empty() {
        Ok(VariantShape::Zero)
    } else if variants.len() == 1 && discr_ref.is_none() {
        let (_, variant) = variants.into_iter().next().unwrap();
        Ok(VariantShape::One(variant))
    } else {
        Ok(VariantShape::Many {
            discr: discr_members.into_iter().next(),
            variants: variants.into_boxed_slice(),
        })
    }
}

/// Parse a `DW_TAG_variant` entry and its single `DW_TAG_member` child.
///
/// Returns `(discriminant_value, variant)`. A `None` discriminant value
/// indicates the default/niche variant.
fn parse_variant<'dw>(
    unit: &UnitCtx<'_, 'dw>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<(Option<u128>, RawVariant<&'dw str>)> {
    let entry = cursor.current().unwrap();
    assert!(entry.tag() == gimli::DW_TAG_variant);

    let mut discr_value = None;

    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next()? {
        if attr.name() == gimli::DW_AT_discr_value {
            discr_value = Some(attr_discr_value(&attr));
        }
    }

    let mut member = None;
    if entry.has_children() {
        while let Some(()) = cursor.next_entry()? {
            if let Some(child) = cursor.current() {
                match child.tag() {
                    gimli::DW_TAG_member => {
                        member = Some(process_member(unit, cursor)?);
                    }
                    _ => {
                        cursor.consume_entry()?;
                    }
                }
            } else {
                break;
            }
        }
    }

    let member = member.expect("DW_TAG_variant must have a DW_TAG_member child");
    Ok((discr_value, RawVariant { member }))
}

/// Parse a `DW_AT_discr_value` attribute into a `u128`.
///
/// In DWARFv4 (which rustc targets), u128 discriminants are encoded as
/// `DW_FORM_block` containing 16 bytes in **target byte order**. The
/// endianness is extracted from the block data itself (it is an
/// `EndianSlice` that carries the target's byte order).
fn attr_discr_value(attr: &Attribute<Slice<'_>>) -> u128 {
    match attr.value() {
        AttributeValue::Udata(v) => v as u128,
        AttributeValue::Sdata(v) => v as u128,
        AttributeValue::Data1(v) => v as u128,
        AttributeValue::Data2(v) => v as u128,
        AttributeValue::Data4(v) => v as u128,
        AttributeValue::Data8(v) => v as u128,
        AttributeValue::Block(ref data) => {
            let endian = data.endian();
            let slice = data.slice();
            let mut buf = [0u8; 16];
            match endian {
                gimli::RunTimeEndian::Little => {
                    buf[..slice.len()].copy_from_slice(slice);
                }
                gimli::RunTimeEndian::Big => {
                    buf[16 - slice.len()..].copy_from_slice(slice);
                }
            }
            match endian {
                gimli::RunTimeEndian::Little => u128::from_le_bytes(buf),
                gimli::RunTimeEndian::Big => u128::from_be_bytes(buf),
            }
        }
        other => panic!("unexpected DW_AT_discr_value form: {:?}", other),
    }
}

/// Parse a `DW_TAG_enumerator` entry into a `RawEnumerator`.
fn parse_enumerator<'dw>(
    unit: &UnitCtx<'_, 'dw>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<RawEnumerator<&'dw str>> {
    let entry = cursor.current().unwrap();
    assert!(entry.tag() == gimli::DW_TAG_enumerator);

    let mut name = None;
    let mut value = None;

    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next()? {
        match attr.name() {
            gimli::DW_AT_name => {
                name = Some(attr.attr_str(unit)?);
            }
            gimli::DW_AT_const_value => {
                value = Some(attr_discr_value(&attr));
            }
            _ => {}
        }
    }

    Ok(RawEnumerator {
        name: name.expect("DW_TAG_enumerator must have DW_AT_name"),
        value: value.expect("DW_TAG_enumerator must have DW_AT_const_value"),
    })
}

/// Parse a `DW_TAG_template_type_parameter` into a [`RawGenericParameter`].
///
/// Returns `None` for parameters with no `DW_AT_type` (e.g. bindings rustc
/// chooses not to describe); the caller records what is present rather than
/// failing the whole DIE.
fn process_generic_parameter<'dw>(
    unit: &UnitCtx<'_, 'dw>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<Option<RawGenericParameter<&'dw str>>> {
    let entry = cursor.current().unwrap();
    assert!(entry.tag() == gimli::DW_TAG_template_type_parameter);

    let common = CommonAttrs::from_entry(unit, entry, |_| Ok(()))?;

    let Some(type_id) = common.type_id else {
        debug!("template type parameter {:?} has no type", common.name);
        return Ok(None);
    };

    Ok(Some(RawGenericParameter {
        name: common.name,
        type_id: type_id.into(),
    }))
}

fn process_sub_parameter<'dw>(
    unit: &UnitCtx<'_, 'dw>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<RawSubParameter<&'dw str>> {
    let entry = cursor.current().unwrap();
    assert!(entry.tag() == gimli::DW_TAG_formal_parameter);

    let mut abstract_origin = None;
    let mut const_value = None;

    let common = CommonAttrs::from_entry(unit, entry, |attr| {
        match attr.name() {
            gimli::DW_AT_abstract_origin => match unit.attr_ref(attr.value()) {
                Some(o) => abstract_origin = Some(o),
                None => panic!("unexpected abstract_origin type: {:?}", attr.value()),
            },
            gimli::DW_AT_const_value => {
                const_value = attr.value().udata_value();
            }
            _ => {}
        }
        Ok(())
    })?;

    let source_loc = if !common.source_loc.is_empty() {
        Some(Box::new(common.source_loc))
    } else {
        None
    };

    Ok(RawSubParameter {
        name: common.name,
        source_loc,
        type_id: common.type_id.map(|t| t.into()),
        abstract_origin,
        const_value,
    })
}

/// Extension trait to simplify reading to the end of a DIE.
trait ConsumeEntry {
    /// Move the `EntriesCursor` to the end of the current entry, ignoring any
    /// remaining child entries.
    fn consume_entry(&mut self) -> Result<()>;
}

impl ConsumeEntry for EntriesCursor<'_, '_, Slice<'_>> {
    fn consume_entry(&mut self) -> Result<()> {
        let Some(entry) = self.current() else {
            return Ok(());
        };

        if entry.has_children() {
            while let Some(()) = self.next_entry()? {
                if self.current().is_some() {
                    self.consume_entry()?;
                } else {
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Extension trait to simplify reading strings from an `Attribute`.
pub(crate) trait DwString<'dw> {
    /// Read the `AttributeValue` as an `&str`, returning an error if it
    /// does not have a string form or is not UTF-8 encoded.
    fn attr_str(&self, unit: &UnitRef<Slice<'dw>>) -> Result<&'dw str>;
}

impl<'dw> DwString<'dw> for Attribute<Slice<'dw>> {
    fn attr_str(&self, unit: &UnitRef<Slice<'dw>>) -> Result<&'dw str> {
        let raw = unit.dwarf.attr_string(unit.unit, self.value())?;
        let s = std::str::from_utf8(raw.slice()).map_err(|_| Error::InvalidUtf8)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use crate::StrId;
    use crate::raw_types::{RawType, VariantShape};
    use crate::reader::{DwReader, ReadArgs};

    use gimli::write as gwrite;
    use gimli::write::AttributeValue as W;

    use std::collections::HashMap;

    /// Build a unit with `build`, write it, parse it back with the real
    /// reader, and hand the result to `check`.
    fn parsed<R>(
        endian: gimli::RunTimeEndian,
        build: impl FnOnce(&mut gwrite::Dwarf, gwrite::UnitId),
        check: impl FnOnce(&DwReader<'_>) -> R,
    ) -> R {
        let encoding = gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        };
        let mut dwarf = gwrite::Dwarf::new();
        let unit_id = dwarf
            .units
            .add(gwrite::Unit::new(encoding, gwrite::LineProgram::none()));
        build(&mut dwarf, unit_id);

        let mut data: HashMap<gimli::SectionId, Vec<u8>> = HashMap::new();
        match endian {
            gimli::RunTimeEndian::Little => {
                let mut sections =
                    gwrite::Sections::new(gwrite::EndianVec::new(gimli::LittleEndian));
                dwarf.write(&mut sections).expect("the unit assembles");
                sections
                    .for_each(|id, vec| -> Result<(), ()> {
                        data.insert(id, vec.slice().to_vec());
                        Ok(())
                    })
                    .unwrap();
            }
            gimli::RunTimeEndian::Big => {
                let mut sections = gwrite::Sections::new(gwrite::EndianVec::new(gimli::BigEndian));
                dwarf.write(&mut sections).expect("the unit assembles");
                sections
                    .for_each(|id, vec| -> Result<(), ()> {
                        data.insert(id, vec.slice().to_vec());
                        Ok(())
                    })
                    .unwrap();
            }
        }
        let empty = Vec::new();
        let dwarf = gimli::Dwarf::load(|id| -> Result<crate::Slice<'_>, gimli::Error> {
            Ok(gimli::EndianSlice::new(
                data.get(&id).unwrap_or(&empty).as_slice(),
                endian,
            ))
        })
        .expect("the sections load");
        let reader = DwReader::read_types(&dwarf, ReadArgs::default()).expect("the unit parses");
        check(&reader)
    }

    fn type_named<'r>(reader: &'r DwReader<'_>, want: &str) -> &'r RawType<StrId> {
        let mut named = reader
            .canonical_types()
            .filter(|(_, ty)| ty.name().map(|n| reader.strings.get(n)) == Some(want));
        let (_, found) = named
            .next()
            .unwrap_or_else(|| panic!("no type named {want}"));
        assert!(
            named.next().is_none(),
            "several canonical types named {want}"
        );
        found
    }

    #[test]
    fn test_synthetic_unit_parses_functions_statics_and_specifications() {
        parsed(
            gimli::RunTimeEndian::Little,
            |dwarf, unit_id| {
                let unit = dwarf.units.get_mut(unit_id);
                let root = unit.root();

                let word = unit.add(root, gimli::DW_TAG_base_type);
                let entry = unit.get_mut(word);
                entry.set(gimli::DW_AT_name, W::String(b"u64".to_vec()));
                entry.set(gimli::DW_AT_byte_size, W::Udata(8));
                entry.set(gimli::DW_AT_encoding, W::Encoding(gimli::DW_ATE_unsigned));
                entry.set(gimli::DW_AT_alignment, W::Udata(16));

                let var = unit.add(root, gimli::DW_TAG_variable);
                let mut location = gwrite::Expression::new();
                location.op_addr(gwrite::Address::Constant(0x1234));
                let entry = unit.get_mut(var);
                entry.set(gimli::DW_AT_name, W::String(b"MY_STATIC".to_vec()));
                entry.set(gimli::DW_AT_type, W::UnitRef(word));
                entry.set(
                    gimli::DW_AT_linkage_name,
                    W::String(b"my_static_sym".to_vec()),
                );
                entry.set(gimli::DW_AT_location, W::Exprloc(location));

                let die = unit.add(root, gimli::DW_TAG_subprogram);
                let entry = unit.get_mut(die);
                entry.set(gimli::DW_AT_name, W::String(b"die".to_vec()));
                entry.set(gimli::DW_AT_noreturn, W::Flag(true));

                let proto = unit.add(root, gimli::DW_TAG_subprogram);
                let entry = unit.get_mut(proto);
                entry.set(gimli::DW_AT_name, W::String(b"proto".to_vec()));

                let specialized = unit.add(root, gimli::DW_TAG_subprogram);
                let entry = unit.get_mut(specialized);
                entry.set(gimli::DW_AT_name, W::String(b"specialized".to_vec()));
                entry.set(gimli::DW_AT_abstract_origin, W::UnitRef(proto));

                let with_params = unit.add(root, gimli::DW_TAG_subprogram);
                let entry = unit.get_mut(with_params);
                entry.set(gimli::DW_AT_name, W::String(b"with_params".to_vec()));
                let located = unit.add(with_params, gimli::DW_TAG_formal_parameter);
                let entry = unit.get_mut(located);
                entry.set(gimli::DW_AT_name, W::String(b"located".to_vec()));
                entry.set(gimli::DW_AT_type, W::UnitRef(word));
                entry.set(gimli::DW_AT_abstract_origin, W::UnitRef(proto));
                entry.set(gimli::DW_AT_const_value, W::Udata(7));
                entry.set(gimli::DW_AT_decl_line, W::Udata(9));
                let bare = unit.add(with_params, gimli::DW_TAG_formal_parameter);
                let entry = unit.get_mut(bare);
                entry.set(gimli::DW_AT_name, W::String(b"bare".to_vec()));
                entry.set(gimli::DW_AT_type, W::UnitRef(word));

                // A definition inheriting its identity through each
                // reference form DW_AT_specification is spelled with.
                let decl_a = unit.add(root, gimli::DW_TAG_structure_type);
                let entry = unit.get_mut(decl_a);
                entry.set(gimli::DW_AT_name, W::String(b"SpecA".to_vec()));
                entry.set(gimli::DW_AT_declaration, W::Flag(true));
                let def_a = unit.add(root, gimli::DW_TAG_structure_type);
                let entry = unit.get_mut(def_a);
                entry.set(gimli::DW_AT_byte_size, W::Udata(8));
                entry.set(gimli::DW_AT_specification, W::UnitRef(decl_a));

                let decl_b = unit.add(root, gimli::DW_TAG_structure_type);
                let entry = unit.get_mut(decl_b);
                entry.set(gimli::DW_AT_name, W::String(b"SpecB".to_vec()));
                entry.set(gimli::DW_AT_declaration, W::Flag(true));
                let def_b = unit.add(root, gimli::DW_TAG_structure_type);
                let entry = unit.get_mut(def_b);
                entry.set(gimli::DW_AT_byte_size, W::Udata(8));
                entry.set(
                    gimli::DW_AT_specification,
                    W::DebugInfoRef(gwrite::Reference::Entry(unit_id, decl_b)),
                );

                let coords = unit.add(root, gimli::DW_TAG_structure_type);
                let entry = unit.get_mut(coords);
                entry.set(gimli::DW_AT_name, W::String(b"Located".to_vec()));
                entry.set(gimli::DW_AT_byte_size, W::Udata(8));
                entry.set(gimli::DW_AT_decl_line, W::Udata(3));
                entry.set(gimli::DW_AT_decl_column, W::Udata(7));
            },
            |reader| {
                let RawType::Base(word) = type_named(reader, "u64") else {
                    panic!("u64 parses as a base type");
                };
                assert_eq!(word.alignment.map(u64::from), Some(16));

                let statics: Vec<_> = reader
                    .variables
                    .values()
                    .filter(|v| v.name.map(|n| reader.strings.get(n)) == Some("MY_STATIC"))
                    .collect();
                let [my_static] = statics.as_slice() else {
                    panic!("one static parses");
                };
                assert_eq!(my_static.addr, Some(0x1234));
                assert_eq!(
                    my_static.linkage_name.map(|n| reader.strings.get(n)),
                    Some("my_static_sym")
                );

                let func = |want: &str| {
                    reader
                        .functions
                        .values()
                        .find(|f| f.name.map(|n| reader.strings.get(n)) == Some(want))
                        .unwrap_or_else(|| panic!("no function named {want}"))
                };
                assert!(func("die").noreturn);
                assert!(!func("proto").noreturn);
                assert!(func("specialized").abstract_origin.is_some());

                let [located, bare] = func("with_params").formal_parameters.as_ref() else {
                    panic!("both parameters parse");
                };
                assert!(located.abstract_origin.is_some());
                assert_eq!(located.const_value, Some(7));
                let loc = located
                    .source_loc
                    .as_deref()
                    .expect("the decl line is kept");
                assert_eq!(loc.line.map(u64::from), Some(9));
                assert!(bare.source_loc.is_none());

                // Each specification pair collapsed to one canonical type
                // carrying the declaration's name and the definition's size.
                for name in ["SpecA", "SpecB"] {
                    let RawType::Struct(spec) = type_named(reader, name) else {
                        panic!("{name} stays a struct");
                    };
                    assert_eq!(spec.size, 8, "{name}");
                }

                let RawType::Struct(coords) = type_named(reader, "Located") else {
                    panic!("Located parses as a struct");
                };
                let loc = coords.source_loc.as_deref().expect("decl coords are kept");
                assert_eq!(loc.line.map(u64::from), Some(3));
                assert_eq!(loc.column.map(u64::from), Some(7));
            },
        );
    }

    /// A variant-part-bearing struct with `shape(...)`'s discriminant
    /// arrangement: `discr` says whether the variant part carries a
    /// `DW_AT_discr` reference, and each entry in `values` is one
    /// variant's optional `DW_AT_discr_value`.
    fn variant_struct(
        unit: &mut gwrite::Unit,
        name: &'static [u8],
        word: gwrite::UnitEntryId,
        discr: bool,
        values: &[Option<u64>],
    ) {
        let root = unit.root();
        let outer = unit.add(root, gimli::DW_TAG_structure_type);
        let entry = unit.get_mut(outer);
        entry.set(gimli::DW_AT_name, W::String(name.to_vec()));
        entry.set(gimli::DW_AT_byte_size, W::Udata(16));

        let part = unit.add(outer, gimli::DW_TAG_variant_part);
        if discr {
            let member = unit.add(part, gimli::DW_TAG_member);
            let entry = unit.get_mut(member);
            entry.set(gimli::DW_AT_name, W::String(b"discr".to_vec()));
            entry.set(gimli::DW_AT_type, W::UnitRef(word));
            let entry = unit.get_mut(part);
            entry.set(gimli::DW_AT_discr, W::UnitRef(member));
        }
        for (index, value) in values.iter().enumerate() {
            let variant = unit.add(part, gimli::DW_TAG_variant);
            if let Some(value) = value {
                let entry = unit.get_mut(variant);
                entry.set(gimli::DW_AT_discr_value, W::Udata(*value));
            }
            let payload = unit.add(variant, gimli::DW_TAG_member);
            let entry = unit.get_mut(payload);
            entry.set(
                gimli::DW_AT_name,
                W::String(format!("V{index}").into_bytes()),
            );
            entry.set(gimli::DW_AT_type, W::UnitRef(word));
            entry.set(gimli::DW_AT_data_member_location, W::Udata(8));
        }
    }

    fn shape<'r>(reader: &'r DwReader<'_>, name: &str) -> &'r VariantShape<StrId> {
        let RawType::Enum(en) = type_named(reader, name) else {
            panic!("{name} parses as an enum");
        };
        &en.shape
    }

    #[test]
    fn test_variant_parts_parse_into_their_shapes() {
        parsed(
            gimli::RunTimeEndian::Little,
            |dwarf, unit_id| {
                let unit = dwarf.units.get_mut(unit_id);
                let root = unit.root();
                let word = unit.add(root, gimli::DW_TAG_base_type);
                let entry = unit.get_mut(word);
                entry.set(gimli::DW_AT_name, W::String(b"u64".to_vec()));
                entry.set(gimli::DW_AT_byte_size, W::Udata(8));
                entry.set(gimli::DW_AT_encoding, W::Encoding(gimli::DW_ATE_unsigned));

                // One variant, no discriminant: the single-variant shape.
                variant_struct(unit, b"OneShape", word, false, &[None]);
                // Two discriminated variants: Many, keyed by value.
                variant_struct(unit, b"TwoShape", word, true, &[Some(0), Some(3)]);
                // One variant under a recorded discriminant: still Many —
                // a niche single-variant enum reads its discriminant.
                variant_struct(unit, b"PinnedShape", word, true, &[Some(3)]);
                // Two variants with no discriminant member at all.
                variant_struct(unit, b"LooseShape", word, false, &[None, None]);
            },
            |reader| {
                assert!(matches!(shape(reader, "OneShape"), VariantShape::One(_)));

                let VariantShape::Many { discr, variants } = shape(reader, "TwoShape") else {
                    panic!("two discriminated variants are Many");
                };
                assert!(discr.is_some());
                let keys: Vec<Option<u128>> = variants.iter().map(|(value, _)| *value).collect();
                assert_eq!(keys, [Some(0), Some(3)]);

                let VariantShape::Many { variants, .. } = shape(reader, "PinnedShape") else {
                    panic!("a discriminated single variant stays Many");
                };
                assert_eq!(variants.len(), 1);

                let VariantShape::Many { discr, variants } = shape(reader, "LooseShape") else {
                    panic!("two undiscriminated variants are Many");
                };
                assert!(discr.is_none());
                assert_eq!(variants.len(), 2);
            },
        );
    }

    #[test]
    fn test_u128_discriminants_decode_from_blocks_in_either_byte_order() {
        let value = (1u128 << 64) | 5;
        for endian in [gimli::RunTimeEndian::Little, gimli::RunTimeEndian::Big] {
            let block = match endian {
                gimli::RunTimeEndian::Little => value.to_le_bytes(),
                gimli::RunTimeEndian::Big => value.to_be_bytes(),
            };
            parsed(
                endian,
                |dwarf, unit_id| {
                    let unit = dwarf.units.get_mut(unit_id);
                    let root = unit.root();
                    let word = unit.add(root, gimli::DW_TAG_base_type);
                    let entry = unit.get_mut(word);
                    entry.set(gimli::DW_AT_name, W::String(b"u64".to_vec()));
                    entry.set(gimli::DW_AT_byte_size, W::Udata(8));
                    entry.set(gimli::DW_AT_encoding, W::Encoding(gimli::DW_ATE_unsigned));

                    let outer = unit.add(root, gimli::DW_TAG_structure_type);
                    let entry = unit.get_mut(outer);
                    entry.set(gimli::DW_AT_name, W::String(b"Wide".to_vec()));
                    entry.set(gimli::DW_AT_byte_size, W::Udata(32));
                    let part = unit.add(outer, gimli::DW_TAG_variant_part);
                    let member = unit.add(part, gimli::DW_TAG_member);
                    let entry = unit.get_mut(member);
                    entry.set(gimli::DW_AT_name, W::String(b"discr".to_vec()));
                    entry.set(gimli::DW_AT_type, W::UnitRef(word));
                    let entry = unit.get_mut(part);
                    entry.set(gimli::DW_AT_discr, W::UnitRef(member));
                    for value in [W::Block(block.to_vec()), W::Udata(0)] {
                        let variant = unit.add(part, gimli::DW_TAG_variant);
                        let entry = unit.get_mut(variant);
                        entry.set(gimli::DW_AT_discr_value, value);
                        let payload = unit.add(variant, gimli::DW_TAG_member);
                        let entry = unit.get_mut(payload);
                        entry.set(gimli::DW_AT_name, W::String(b"V".to_vec()));
                        entry.set(gimli::DW_AT_type, W::UnitRef(word));
                    }
                },
                |reader| {
                    let VariantShape::Many { variants, .. } = shape(reader, "Wide") else {
                        panic!("the discriminated pair is Many");
                    };
                    let keys: Vec<Option<u128>> =
                        variants.iter().map(|(value, _)| *value).collect();
                    assert_eq!(keys, [Some(value), Some(0)], "{endian:?}");
                },
            );
        }
    }

    #[test]
    fn test_awaitees_are_collected_only_from_resume_functions() {
        parsed(
            gimli::RunTimeEndian::Little,
            |dwarf, unit_id| {
                let unit = dwarf.units.get_mut(unit_id);
                let root = unit.root();
                let word = unit.add(root, gimli::DW_TAG_base_type);
                let entry = unit.get_mut(word);
                entry.set(gimli::DW_AT_name, W::String(b"u64".to_vec()));
                entry.set(gimli::DW_AT_byte_size, W::Udata(8));
                entry.set(gimli::DW_AT_encoding, W::Encoding(gimli::DW_ATE_unsigned));

                // The resume body: a block holding an empty block and an
                // awaitee, then a formal parameter and a direct awaitee.
                let body = |unit: &mut gwrite::Unit, name: &[u8]| {
                    let fn_die = unit.add(unit.root(), gimli::DW_TAG_subprogram);
                    let entry = unit.get_mut(fn_die);
                    entry.set(gimli::DW_AT_name, W::String(name.to_vec()));
                    let block = unit.add(fn_die, gimli::DW_TAG_lexical_block);
                    unit.add(block, gimli::DW_TAG_lexical_block);
                    let nested = unit.add(block, gimli::DW_TAG_variable);
                    let entry = unit.get_mut(nested);
                    entry.set(gimli::DW_AT_name, W::String(b"__awaitee".to_vec()));
                    entry.set(gimli::DW_AT_type, W::UnitRef(word));
                    let param = unit.add(fn_die, gimli::DW_TAG_formal_parameter);
                    let entry = unit.get_mut(param);
                    entry.set(gimli::DW_AT_name, W::String(b"p".to_vec()));
                    entry.set(gimli::DW_AT_type, W::UnitRef(word));
                    let direct = unit.add(fn_die, gimli::DW_TAG_variable);
                    let entry = unit.get_mut(direct);
                    entry.set(gimli::DW_AT_name, W::String(b"__awaitee".to_vec()));
                    entry.set(gimli::DW_AT_type, W::UnitRef(word));
                };
                body(unit, b"{async_fn#0}");
                body(unit, b"ordinary");
            },
            |reader| {
                let func = |want: &str| {
                    reader
                        .functions
                        .values()
                        .find(|f| f.name.map(|n| reader.strings.get(n)) == Some(want))
                        .unwrap_or_else(|| panic!("no function named {want}"))
                };
                // The resume fn yields both awaitees and keeps the
                // parameter that follows the block.
                let resume = func("{async_fn#0}");
                assert_eq!(resume.awaitees.len(), 2);
                assert_eq!(resume.formal_parameters.len(), 1);
                // An ordinary fn collects no awaitees, wherever they sit.
                let ordinary = func("ordinary");
                assert_eq!(ordinary.awaitees.len(), 0);
                assert_eq!(ordinary.formal_parameters.len(), 1);
            },
        );
    }
}

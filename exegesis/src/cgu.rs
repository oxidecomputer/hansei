use crate::raw_types::{
    CommonAttrs, Encoding, NamespaceTable, NsId, RawArray, RawAwaitee, RawBase, RawEnum,
    RawEnumerator, RawFunc, RawGenericParameter, RawMember, RawPointer, RawStaticVariable,
    RawStruct, RawSubParameter, RawType, RawUnion, RawVariant, SourceLoc, VariantShape,
};
use crate::{Error, FuncId, Result, Slice, TypeId, VarId};

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use gimli::{
    Attribute, AttributeValue, EntriesCursor, EvaluationResult, Reader, UnitRef, UnitSectionOffset,
};
use tracing::debug;

const ANON: &str = "<anon>";
const UNNAMED_CGU: &str = "<unnamed_cgu>";

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
        unit: &UnitRef<Slice<'dw>>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<Self> {
        let entry = cursor
            .current()
            .expect("cursor must be positioned at a compile unit entry");
        assert_eq!(entry.tag(), gimli::DW_TAG_compile_unit);

        let offset = entry.offset().to_unit_section_offset(unit);
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
        unit: &UnitRef<Slice<'dw>>,
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
                let id = TypeId(entry.offset().to_unit_section_offset(unit));
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
        unit: &UnitRef<Slice<'dw>>,
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
        unit: &UnitRef<Slice<'dw>>,
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
        unit: &UnitRef<Slice<'dw>>,
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
        unit: &UnitRef<Slice<'dw>>,
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
        unit: &UnitRef<Slice<'dw>>,
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
        unit: &UnitRef<Slice<'dw>>,
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
        unit: &UnitRef<Slice<'dw>>,
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
        unit: &UnitRef<Slice<'dw>>,
        cursor: &mut EntriesCursor<Slice<'dw>>,
    ) -> Result<()> {
        let entry = cursor.current().unwrap();
        assert!(entry.tag() == gimli::DW_TAG_variable);

        let mut linkage_name = None;
        let mut addr = None;

        let offset = entry.offset().to_unit_section_offset(unit);
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
        unit: &UnitRef<Slice<'dw>>,
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
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(a) = attr.value() {
                        lo_pc = Some(a);
                    } else {
                        debug!("unexpected low_pc type: {:?}", attr.value());
                    }
                }
                gimli::DW_AT_high_pc => {
                    hi_pc = attr.value().udata_value();
                    if hi_pc.is_none() {
                        debug!("non udata hi_pc {:?}", attr.value());
                    }
                }
                gimli::DW_AT_abstract_origin => {
                    if let gimli::AttributeValue::UnitRef(o) = attr.value() {
                        abstract_origin = Some(o.to_unit_section_offset(unit));
                    } else if let gimli::AttributeValue::DebugInfoRef(o) = attr.value() {
                        abstract_origin = Some(o.into());
                    } else {
                        panic!("unexpected abstract_origin type: {:?}", attr.value());
                    }
                }
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
    unit: &UnitRef<Slice<'dw>>,
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
    unit: &UnitRef<Slice<'dw>>,
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
    unit: &UnitRef<Slice<'dw>>,
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
    unit: &UnitRef<Slice<'dw>>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<VariantShape<&'dw str>> {
    let entry = cursor.current().unwrap();
    assert!(entry.tag() == gimli::DW_TAG_variant_part);

    // DW_AT_discr is a reference to the discriminant member DIE.
    let mut discr_ref = None;
    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next()? {
        if attr.name() == gimli::DW_AT_discr {
            match attr.value() {
                AttributeValue::UnitRef(o) => {
                    discr_ref = Some(o.to_unit_section_offset(unit));
                }
                _ => {
                    debug!("unexpected DW_AT_discr value: {:?}", attr.value());
                }
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
    unit: &UnitRef<Slice<'dw>>,
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
    unit: &UnitRef<Slice<'dw>>,
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
    unit: &UnitRef<Slice<'dw>>,
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
    unit: &UnitRef<Slice<'dw>>,
    cursor: &mut EntriesCursor<Slice<'dw>>,
) -> Result<RawSubParameter<&'dw str>> {
    let entry = cursor.current().unwrap();
    assert!(entry.tag() == gimli::DW_TAG_formal_parameter);

    let mut abstract_origin = None;
    let mut const_value = None;

    let common = CommonAttrs::from_entry(unit, entry, |attr| {
        match attr.name() {
            gimli::DW_AT_abstract_origin => {
                if let gimli::AttributeValue::UnitRef(o) = attr.value() {
                    abstract_origin = Some(o.to_unit_section_offset(unit));
                } else if let gimli::AttributeValue::DebugInfoRef(o) = attr.value() {
                    abstract_origin = Some(o.into());
                } else {
                    panic!("unexpected abstract_origin type: {:?}", attr.value());
                }
            }
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

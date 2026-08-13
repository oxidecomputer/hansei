use crate::TypeId;
use crate::raw_types::{NsId, RawFunc, RawGenericParameter, RawSubParameter, SourceLoc};
use crate::reader::DwReader;
use crate::string_table::StrId;

use std::num::NonZero;

// --- Namespace ---

#[derive(Copy, Clone)]
pub struct Namespace<'a> {
    id: NsId,
    collector: &'a DwReader<'a>,
}

impl<'a> Namespace<'a> {
    pub(crate) fn new(id: NsId, collector: &'a DwReader<'a>) -> Self {
        Self { id, collector }
    }

    /// Returns the [`NsId`] of this namespace.
    pub fn id(&self) -> NsId {
        self.id
    }

    /// Returns the direct name of this namespace segment.
    pub fn name(&self) -> &'a str {
        let entry = self.collector.namespaces.get(self.id);
        self.collector.strings.get(entry.name)
    }

    /// Returns the parent namespace, if any.
    pub fn parent(&self) -> Option<Namespace<'a>> {
        let entry = self.collector.namespaces.get(self.id);
        entry.parent.map(|id| Namespace {
            id,
            collector: self.collector,
        })
    }

    /// Returns the depth of this namespace (1 for a root namespace).
    pub fn depth(&self) -> u32 {
        self.collector.namespaces.depth(self.id)
    }

    /// Builds the fully-qualified namespace path, e.g. `"foo::bar::baz"`.
    pub fn full_name(&self) -> String {
        let depth = self.collector.namespaces.depth(self.id);
        let mut segments = Vec::with_capacity(depth as usize);
        let mut current = Some(*self);
        while let Some(ns) = current {
            segments.push(ns.name());
            current = ns.parent();
        }
        segments.reverse();
        segments.join("::")
    }
}

// --- Func ---

#[derive(Copy, Clone)]
pub struct Func<'a> {
    raw: &'a RawFunc<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Func<'a> {
    pub(crate) fn new(raw: &'a RawFunc<StrId>, collector: &'a DwReader<'a>) -> Self {
        Self { raw, collector }
    }

    pub(crate) fn namespace_id(&self) -> Option<NsId> {
        self.raw.namespace
    }

    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    pub fn linkage_name(&self) -> Option<&'a str> {
        self.raw
            .linkage_name
            .map(|id| self.collector.strings.get(id))
    }

    /// Return an iterator over formal parameters.
    pub fn params(&self) -> ParamIter<'a> {
        ParamIter {
            params: &self.raw.formal_parameters,
            index: 0,
            collector: self.collector,
        }
    }

    /// Return an iterator over the generic type arguments of this
    /// instantiation, in declaration order.
    pub fn template_params(&self) -> TemplateParamIter<'a> {
        TemplateParamIter::new(&self.raw.template_params, self.collector)
    }

    /// Declaration coordinates of this function, if recorded.
    pub fn source_loc(&self) -> Option<SourceLocView<'a>> {
        self.raw
            .source_loc
            .as_deref()
            .map(|loc| SourceLocView::new(loc, self.collector))
    }

    pub fn noreturn(&self) -> bool {
        self.raw.noreturn
    }

    pub fn raw(&self) -> &RawFunc<StrId> {
        self.raw
    }
}

// --- Param ---

#[derive(Copy, Clone)]
pub struct Param<'a> {
    raw: &'a RawSubParameter<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Param<'a> {
    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    pub fn raw(&self) -> &RawSubParameter<StrId> {
        self.raw
    }
}

// --- ParamIter ---

#[derive(Clone)]
pub struct ParamIter<'a> {
    params: &'a [RawSubParameter<StrId>],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> Iterator for ParamIter<'a> {
    type Item = Param<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let param = self.params.get(self.index)?;
        self.index += 1;
        Some(Param {
            raw: param,
            collector: self.collector,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.params.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ParamIter<'_> {}

// --- TemplateParam ---

/// A generic type argument binding (`DW_TAG_template_type_parameter`) on a
/// monomorphized function or type instantiation: the parameter's declared
/// name (e.g. `T`) and the concrete type bound in this instantiation.
#[derive(Copy, Clone)]
pub struct TemplateParam<'a> {
    raw: &'a RawGenericParameter<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> TemplateParam<'a> {
    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    pub fn type_id(&self) -> TypeId {
        self.raw.type_id
    }
}

// --- TemplateParamIter ---

#[derive(Clone)]
pub struct TemplateParamIter<'a> {
    params: &'a [RawGenericParameter<StrId>],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> TemplateParamIter<'a> {
    pub(crate) fn new(
        params: &'a [RawGenericParameter<StrId>],
        collector: &'a DwReader<'a>,
    ) -> Self {
        Self {
            params,
            index: 0,
            collector,
        }
    }
}

impl<'a> Iterator for TemplateParamIter<'a> {
    type Item = TemplateParam<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let param = self.params.get(self.index)?;
        self.index += 1;
        Some(TemplateParam {
            raw: param,
            collector: self.collector,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.params.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for TemplateParamIter<'_> {}

// --- SourceLocView ---

/// Declaration coordinates (`DW_AT_decl_file`/`line`/`column`) with the
/// file and directory resolved through the unit's line-program file table.
#[derive(Copy, Clone)]
pub struct SourceLocView<'a> {
    raw: &'a SourceLoc<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> SourceLocView<'a> {
    pub(crate) fn new(raw: &'a SourceLoc<StrId>, collector: &'a DwReader<'a>) -> Self {
        Self { raw, collector }
    }

    /// The source file name, as recorded in the line-program file table.
    pub fn file(&self) -> Option<&'a str> {
        self.raw.file.map(|id| self.collector.strings.get(id))
    }

    /// The directory of the source file, if recorded.
    pub fn dir(&self) -> Option<&'a str> {
        self.raw.dir.map(|id| self.collector.strings.get(id))
    }

    /// The compilation directory a relative [`dir`](Self::dir) is relative
    /// to, if recorded.
    pub fn comp_dir(&self) -> Option<&'a str> {
        self.raw.comp_dir.map(|id| self.collector.strings.get(id))
    }

    /// 1-indexed line number.
    pub fn line(&self) -> Option<NonZero<u64>> {
        self.raw.line
    }
}

#[cfg(test)]
mod tests {
    use super::Namespace;
    use crate::raw_types::{
        Encoding, RawBase, RawEnum, RawEnumerator, RawGenericParameter, RawMember,
        RawStaticVariable, RawStruct, RawType, RawUnion, RawVariant, VariantShape,
    };
    use crate::reader::DwReader;
    use crate::string_table::StrId;
    use crate::view::DwView;
    use crate::{TypeId, testhelper};

    /// Set up the view test fixture. Object bytes are cached across calls;
    /// only DWARF parsing and collection run per test.
    fn setup() -> (testhelper::TestDwarf,) {
        (testhelper::get_test_dwarf(),)
    }

    macro_rules! with_view {
        ($view:ident => $body:block) => {{
            let (td,) = setup();
            let dwarf = td.dwarf();
            let collector = DwReader::read_types(&dwarf, Default::default()).unwrap();
            let $view = collector.view();
            $body
        }};
    }

    // ---- Raw-table lookup helpers ----
    //
    // The assertions below work on the raw types the reader parses, not a
    // wrapper API, so a few small lookups keep them readable: resolve a
    // path to raw definitions of a given kind, a member by name, an
    // interned string.

    /// Resolve an interned string.
    fn str_of<'a>(reader: &'a DwReader<'a>, id: Option<StrId>) -> Option<&'a str> {
        id.map(|id| reader.strings.get(id))
    }

    /// A type's name, resolved through the string table.
    fn name_of<'a>(reader: &'a DwReader<'a>, ty: &RawType<StrId>) -> Option<&'a str> {
        str_of(reader, ty.name())
    }

    /// Resolve a type reference to its canonical raw definition.
    fn ty_of<'a>(reader: &'a DwReader<'a>, id: TypeId) -> &'a RawType<StrId> {
        reader
            .canonical_type(id)
            .expect("type reference should resolve")
    }

    /// All canonical types matching a path, as raw definitions.
    fn find_all<'a>(view: &DwView<'a>, path: &str) -> Vec<&'a RawType<StrId>> {
        let reader = view.collector();
        view.find_all_ids(path)
            .into_iter()
            .map(|id| ty_of(reader, id))
            .collect()
    }

    /// The type at `path` that `pick` accepts (e.g. the struct, the enum).
    fn find_type<'a, T>(
        view: &DwView<'a>,
        path: &str,
        pick: impl Fn(&'a RawType<StrId>) -> Option<T>,
    ) -> T {
        find_all(view, path)
            .into_iter()
            .find_map(pick)
            .unwrap_or_else(|| panic!("{path} not found with the expected kind"))
    }

    fn find_base<'a>(view: &DwView<'a>, path: &str) -> &'a RawBase<StrId> {
        find_type(view, path, |t| match t {
            RawType::Base(b) => Some(b),
            _ => None,
        })
    }

    fn find_struct<'a>(view: &DwView<'a>, path: &str) -> &'a RawStruct<StrId> {
        find_type(view, path, |t| match t {
            RawType::Struct(s) => Some(s),
            _ => None,
        })
    }

    fn find_enum<'a>(view: &DwView<'a>, path: &str) -> &'a RawEnum<StrId> {
        find_type(view, path, |t| match t {
            RawType::Enum(e) => Some(e),
            _ => None,
        })
    }

    fn find_union<'a>(view: &DwView<'a>, path: &str) -> &'a RawUnion<StrId> {
        find_type(view, path, |t| match t {
            RawType::Union(u) => Some(u),
            _ => None,
        })
    }

    /// The static variable at a fully-qualified path.
    fn find_var<'a>(view: &DwView<'a>, path: &str) -> &'a RawStaticVariable<StrId> {
        let reader = view.collector();
        reader
            .variables
            .values()
            .find(|v| {
                let Some(name) = str_of(reader, v.name) else {
                    return false;
                };
                match v.namespace {
                    Some(ns) => {
                        let full = Namespace::new(ns, reader).full_name();
                        path == format!("{full}::{name}")
                    }
                    None => path == name,
                }
            })
            .unwrap_or_else(|| panic!("{path} not found"))
    }

    /// A member by name.
    fn member<'a>(
        reader: &DwReader<'_>,
        members: &'a [RawMember<StrId>],
        name: &str,
    ) -> Option<&'a RawMember<StrId>> {
        members
            .iter()
            .find(|m| m.name.map(|id| reader.strings.get(id)) == Some(name))
    }

    /// How many variants (or enumerators) an enum has, whatever its shape.
    fn variant_count(e: &RawEnum<StrId>) -> usize {
        match &e.shape {
            VariantShape::Zero => 0,
            VariantShape::One(_) => 1,
            VariantShape::Many { variants, .. } => variants.len(),
            VariantShape::CStyle { enumerators, .. } => enumerators.len(),
        }
    }

    /// The variant names of a Many-shaped enum.
    fn variant_names<'a>(
        reader: &'a DwReader<'a>,
        variants: &[(Option<u128>, RawVariant<StrId>)],
    ) -> Vec<&'a str> {
        variants
            .iter()
            .filter_map(|(_, v)| str_of(reader, v.member.name))
            .collect()
    }

    /// A template parameter's (name, bound type name).
    fn tp_binding<'a>(
        reader: &'a DwReader<'a>,
        p: &RawGenericParameter<StrId>,
    ) -> (Option<&'a str>, Option<&'a str>) {
        (
            str_of(reader, p.name),
            name_of(reader, ty_of(reader, p.type_id)),
        )
    }

    // ---- A. Base types & encoding ----

    #[test]
    fn test_base_type_bool() {
        with_view!(view => {
            let reader = view.collector();
            let base = find_base(&view, "bool");
            assert_eq!(base.encoding, Encoding::Boolean);
            assert_eq!(base.size, 1);
            assert_eq!(str_of(reader, base.name), Some("bool"));
        });
    }

    #[test]
    fn test_base_type_unsigned() {
        with_view!(view => {
            let base = find_base(&view, "u32");
            assert_eq!(base.encoding, Encoding::Unsigned);
            assert_eq!(base.size, 4);
        });
    }

    #[test]
    fn test_base_type_signed() {
        with_view!(view => {
            let base = find_base(&view, "i32");
            assert_eq!(base.encoding, Encoding::Signed);
            assert_eq!(base.size, 4);
        });
    }

    #[test]
    fn test_base_type_float() {
        with_view!(view => {
            let base = find_base(&view, "f64");
            assert_eq!(base.encoding, Encoding::Float);
            assert_eq!(base.size, 8);
        });
    }

    #[test]
    fn test_base_type_u8() {
        with_view!(view => {
            let base = find_base(&view, "u8");
            assert_eq!(base.encoding, Encoding::Unsigned);
            assert_eq!(base.size, 1);
        });
    }

    // ---- B. Type kinds ----

    #[test]
    fn test_type_kind() {
        with_view!(view => {
            // The lookups themselves assert the kind: u32 parses as a base
            // type, Point as a struct.
            find_base(&view, "u32");
            find_struct(&view, "testlib::shapes::Point");
        });
    }

    #[test]
    fn test_type_kind_is_exclusive() {
        with_view!(view => {
            // Point is a struct and nothing else: every type matching the
            // path is the Struct variant.
            let all = find_all(&view, "testlib::shapes::Point");
            assert!(!all.is_empty());
            for ty in all {
                assert!(matches!(ty, RawType::Struct(_)));
            }
        });
    }

    #[test]
    fn test_type_name() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Point");
            assert_eq!(str_of(reader, s.name), Some("Point"));
        });
    }

    #[test]
    fn test_base_type_is_not_member_bearing() {
        with_view!(view => {
            // A base type carries no members by construction; what matters
            // is that "u32" resolves as Base, not some member-bearing kind.
            let all = find_all(&view, "u32");
            assert!(!all.is_empty());
            for ty in all {
                assert!(matches!(ty, RawType::Base(_)));
            }
        });
    }

    // ---- C. Struct & Member ----

    #[test]
    fn test_struct_properties() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Point");
            assert_eq!(str_of(reader, s.name), Some("Point"));
            assert_eq!(s.size, 8); // repr(C): two i32s
            assert_eq!(s.members.len(), 2);
        });
    }

    #[test]
    fn test_struct_member_by_name() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Point");

            let x = member(reader, &s.members, "x").expect("member x not found");
            assert_eq!(str_of(reader, x.name), Some("x"));
            assert_eq!(x.offset, 0);

            let y = member(reader, &s.members, "y").expect("member y not found");
            assert_eq!(str_of(reader, y.name), Some("y"));
            assert_eq!(y.offset, 4);

            assert!(member(reader, &s.members, "nonexistent").is_none());
        });
    }

    #[test]
    fn test_struct_member_type_resolution() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Mixed");

            let count = member(reader, &s.members, "count").unwrap();
            let ty = ty_of(reader, count.type_id);
            assert!(matches!(ty, RawType::Base(_)));
            assert_eq!(name_of(reader, ty), Some("u32"));
        });
    }

    #[test]
    fn test_struct_member_offsets_repr_c() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Mixed");

            // #[repr(C)] layout: bool(1) pad(3) u32(4) f64(8) u8(1) pad(7) = 24
            let flag = member(reader, &s.members, "flag").unwrap();
            assert_eq!(flag.offset, 0);

            let count = member(reader, &s.members, "count").unwrap();
            assert_eq!(count.offset, 4);

            let value = member(reader, &s.members, "value").unwrap();
            assert_eq!(value.offset, 8);

            let letter = member(reader, &s.members, "letter").unwrap();
            assert_eq!(letter.offset, 16);
        });
    }

    #[test]
    fn test_struct_empty() {
        with_view!(view => {
            let s = find_struct(&view, "testlib::shapes::Empty");
            assert_eq!(s.members.len(), 0);
            assert_eq!(s.size, 0);
        });
    }

    #[test]
    fn test_struct_namespace() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Point");
            let ns = s.namespace.expect("Point should have a namespace");
            let ns = Namespace::new(ns, reader);
            assert_eq!(ns.full_name(), "testlib::shapes");
            assert_eq!(ns.depth(), 2);
        });
    }

    // ---- D. Member lists ----

    #[test]
    fn test_struct_member_count() {
        with_view!(view => {
            let s = find_struct(&view, "testlib::shapes::Point");
            assert_eq!(s.members.len(), 2);
        });
    }

    #[test]
    fn test_struct_members_are_complete() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Mixed");
            let names: Vec<_> = s.members.iter().filter_map(|m| str_of(reader, m.name)).collect();
            assert_eq!(names.len(), s.members.len());
            assert!(names.contains(&"flag"));
            assert!(names.contains(&"count"));
            assert!(names.contains(&"value"));
            assert!(names.contains(&"letter"));
        });
    }

    // ---- E. Pointer ----

    #[test]
    fn test_pointer_target_resolution() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Wrapper");
            let inner = member(reader, &s.members, "inner").expect("inner member not found");
            let RawType::Pointer(ptr) = ty_of(reader, inner.type_id) else {
                panic!("inner should be a pointer");
            };

            let target = ty_of(reader, ptr.target_type_id);
            assert!(matches!(target, RawType::Struct(_)));
            assert_eq!(name_of(reader, target), Some("Point"));
        });
    }

    #[test]
    fn test_pointer_has_name() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Wrapper");
            let inner = member(reader, &s.members, "inner").unwrap();
            let RawType::Pointer(ptr) = ty_of(reader, inner.type_id) else {
                panic!("inner should be a pointer");
            };
            // Rust emits DW_AT_name for pointer types (e.g. "*const Point").
            let name = str_of(reader, ptr.name).expect("Rust pointer types have names");
            assert!(
                name.contains("Point"),
                "pointer name {name:?} should reference Point"
            );
        });
    }

    // ---- F. Namespace ----

    #[test]
    fn test_namespace_depth_and_parent_chain() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::outer::inner::Deep");
            let ns = s.namespace.expect("Deep should have a namespace");
            let ns = Namespace::new(ns, reader);
            assert_eq!(ns.full_name(), "testlib::outer::inner");
            assert_eq!(ns.depth(), 3);

            // Walk parent chain.
            let outer = ns.parent().expect("inner should have parent");
            assert_eq!(outer.name(), "outer");
            assert_eq!(outer.depth(), 2);

            let root = outer.parent().expect("outer should have parent");
            assert_eq!(root.name(), "testlib");
            assert_eq!(root.depth(), 1);

            assert!(root.parent().is_none());
        });
    }

    #[test]
    fn test_namespace_full_name() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Point");
            let ns = Namespace::new(s.namespace.unwrap(), reader);
            assert_eq!(ns.full_name(), "testlib::shapes");
        });
    }

    #[test]
    fn test_namespace_root_has_no_parent() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::shapes::Point");
            let ns = Namespace::new(s.namespace.unwrap(), reader);
            let root = ns.parent().unwrap(); // "testlib"
            assert!(root.parent().is_none());
        });
    }

    // ---- G. Static variables ----

    #[test]
    fn test_static_variable_properties() {
        with_view!(view => {
            let reader = view.collector();
            let v = find_var(&view, "testlib::shapes::GLOBAL_COUNT");
            assert_eq!(str_of(reader, v.name), Some("GLOBAL_COUNT"));
        });
    }

    #[test]
    fn test_static_variable_type() {
        with_view!(view => {
            let reader = view.collector();
            let v = find_var(&view, "testlib::shapes::GLOBAL_COUNT");
            let ty = ty_of(reader, v.type_id);
            assert!(matches!(ty, RawType::Base(_)));
            assert_eq!(name_of(reader, ty), Some("u32"));
        });
    }

    #[test]
    fn test_static_variable_namespace() {
        with_view!(view => {
            let reader = view.collector();
            let v = find_var(&view, "testlib::shapes::GLOBAL_COUNT");
            let ns = v.namespace.expect("GLOBAL_COUNT should have namespace");
            assert_eq!(Namespace::new(ns, reader).full_name(), "testlib::shapes");
        });
    }

    // ---- H. Func & Param ----

    #[test]
    fn test_function_basic() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::add_points")
                .expect("add_points not found");
            assert_eq!(f.name(), Some("add_points"));
            assert!(!f.noreturn());
        });
    }

    #[test]
    fn test_function_return_type() {
        with_view!(view => {
            let reader = view.collector();
            let f = view
                .find_func("testlib::shapes::add_points")
                .unwrap();
            let ret = f
                .raw()
                .return_type_id
                .expect("add_points should have return type");
            let ret = ty_of(reader, ret);
            assert!(matches!(ret, RawType::Struct(_)));
            assert_eq!(name_of(reader, ret), Some("Point"));
        });
    }

    #[test]
    fn test_function_void_return() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::noop")
                .expect("noop not found");
            assert!(f.raw().return_type_id.is_none());
        });
    }

    #[test]
    fn test_function_params() {
        with_view!(view => {
            let reader = view.collector();
            let f = view
                .find_func("testlib::shapes::add_points")
                .unwrap();
            let params: Vec<_> = f.params().collect();
            assert_eq!(params.len(), 2);

            let names: Vec<_> = params.iter().filter_map(|p| p.name()).collect();
            assert!(names.contains(&"a"));
            assert!(names.contains(&"b"));

            // Parameters are &Point references, which appear as pointers in DWARF.
            for p in &params {
                let ty = p.raw().type_id.expect("param should have a type");
                assert!(matches!(ty_of(reader, ty), RawType::Pointer(_)));
            }
        });
    }

    #[test]
    fn test_function_linkage_name() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::add_points")
                .unwrap();
            let linkage = f.linkage_name().expect("should have linkage name");
            assert!(
                linkage.contains("add_points"),
                "linkage name {linkage:?} should contain 'add_points'"
            );
        });
    }

    // ---- I. ParamIter ----

    #[test]
    fn test_param_iter_exact_size() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::multi_param")
                .unwrap();
            let mut iter = f.params();
            assert_eq!(iter.len(), 3);
            iter.next();
            assert_eq!(iter.len(), 2);
        });
    }

    #[test]
    fn test_param_iter_types() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::multi_param")
                .unwrap();
            for p in f.params() {
                assert!(
                    p.raw().type_id.is_some(),
                    "param {:?} should have a type",
                    p.name()
                );
            }
        });
    }

    // ---- J. DwView lookups ----

    #[test]
    fn test_view_find_qualified() {
        with_view!(view => {
            assert!(!view.find_all_ids("testlib::shapes::Point").is_empty());
        });
    }

    #[test]
    fn test_view_find_bare_name_misses_namespaced() {
        with_view!(view => {
            // Bare name lookup requires namespace == None, so a namespaced
            // type like Point won't match.
            assert!(view.find_all_ids("Point").is_empty());
        });
    }

    #[test]
    fn test_view_find_nonexistent() {
        with_view!(view => {
            assert!(view.find_all_ids("DoesNotExist").is_empty());
        });
    }

    #[test]
    fn test_view_find_wrong_kind() {
        with_view!(view => {
            // Nothing named Point in that namespace is a base type.
            let all = find_all(&view, "testlib::shapes::Point");
            assert!(!all.iter().any(|ty| matches!(ty, RawType::Base(_))));
        });
    }

    #[test]
    fn test_view_find_all() {
        with_view!(view => {
            let reader = view.collector();
            let results = find_all(&view, "testlib::shapes::Point");
            assert!(!results.is_empty());
            for ty in &results {
                assert_eq!(name_of(reader, ty), Some("Point"));
            }
        });
    }

    // ---- L. Enum ----

    #[test]
    fn test_enum_shape_is_enum() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Shape");
            assert_eq!(str_of(reader, e.name), Some("Shape"));
        });
    }

    #[test]
    fn test_enum_not_struct() {
        with_view!(view => {
            let all = find_all(&view, "testlib::enums::Shape");
            assert!(
                !all.iter().any(|ty| matches!(ty, RawType::Struct(_))),
                "Shape should not be found as Struct"
            );
        });
    }

    #[test]
    fn test_enum_message_variant_count() {
        with_view!(view => {
            let e = find_enum(&view, "testlib::enums::Message");
            assert_eq!(variant_count(e), 3);
        });
    }

    #[test]
    fn test_enum_message_shape_many() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Message");
            let VariantShape::Many { discr, variants } = &e.shape else {
                panic!("expected Many shape");
            };
            // Discriminant should exist and have an integer type.
            let discr = discr
                .as_ref()
                .expect("Message should have an explicit discriminant");
            assert!(matches!(ty_of(reader, discr.type_id), RawType::Base(_)));

            // Collect variant names.
            let names = variant_names(reader, variants);
            assert!(names.contains(&"Quit"));
            assert!(names.contains(&"Echo"));
            assert!(names.contains(&"Move"));
        });
    }

    #[test]
    fn test_enum_message_discr_values() {
        with_view!(view => {
            let e = find_enum(&view, "testlib::enums::Message");
            let VariantShape::Many { variants, .. } = &e.shape else {
                panic!("expected Many shape");
            };
            // All variants should have explicit discriminant values.
            for (dv, _) in variants.iter() {
                assert!(dv.is_some(), "all Message variants should have explicit discriminants");
            }
        });
    }

    #[test]
    fn test_enum_message_large_enum() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Large");
            let VariantShape::Many { discr, variants } = &e.shape else {
                panic!("expected Many shape");
            };
            // Discriminant should exist and have an integer type.
            let discr = discr
                .as_ref()
                .expect("Message should have an explicit discriminant");
            let discr_ty = ty_of(reader, discr.type_id);
            assert!(matches!(discr_ty, RawType::Base(_)));
            assert_eq!(name_of(reader, discr_ty), Some("u128"));

            // Collect variant names.
            let names = variant_names(reader, variants);
            assert!(names.contains(&"Big"));
            assert!(names.contains(&"Empty"));
        });
    }

    #[test]
    fn test_enum_message_discriminant_member() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Message");
            let VariantShape::Many { discr: Some(discr), .. } = &e.shape else {
                panic!("Message should have a discriminant");
            };
            assert!(matches!(ty_of(reader, discr.type_id), RawType::Base(_)));
        });
    }

    #[test]
    fn test_enum_shape_payloads() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Shape");
            assert_eq!(variant_count(e), 2);

            let VariantShape::Many { variants, .. } = &e.shape else {
                panic!("expected Many shape");
            };

            let names = variant_names(reader, variants);
            assert!(names.contains(&"Circle"));
            assert!(names.contains(&"Rect"));
        });
    }

    #[test]
    fn test_enum_single_variant() {
        with_view!(view => {
            let e = find_enum(&view, "testlib::enums::Single");
            // Single-variant enums may be One or Many depending on the
            // compiler. Just verify it is found as an enum with 1 variant.
            assert_eq!(variant_count(e), 1);
        });
    }

    #[test]
    fn test_enum_repr_u8_discr_type() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::SmallTagged");
            let VariantShape::Many { discr: Some(discr), .. } = &e.shape else {
                panic!("SmallTagged should have a discriminant");
            };
            let RawType::Base(discr_ty) = ty_of(reader, discr.type_id) else {
                panic!("discriminant should be a base type");
            };
            assert_eq!(discr_ty.size, 1, "repr(u8) discriminant should be 1 byte");
        });
    }

    #[test]
    fn test_enum_namespace() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Shape");
            let ns = e.namespace.expect("Shape should have a namespace");
            assert_eq!(Namespace::new(ns, reader).full_name(), "testlib::enums");
        });
    }

    // ---- M. Niche-optimized Enum ----

    #[test]
    fn test_niche_enum_is_enum() {
        with_view!(view => {
            let reader = view.collector();
            // Option<NonZeroU64> is niche-optimized; the compiler embeds
            // it in NicheHolder.opt_ref as a structure_type with a
            // variant_part that has NO discriminant member.
            let holder = find_struct(&view, "testlib::enums::NicheHolder");
            let opt_ref = member(reader, &holder.members, "opt_ref")
                .expect("opt_ref member should exist");
            assert!(
                matches!(ty_of(reader, opt_ref.type_id), RawType::Enum(_)),
                "Option<NonZeroU64> should be Enum"
            );
        });
    }

    #[test]
    fn test_niche_enum_is_many_with_two_variants() {
        with_view!(view => {
            let reader = view.collector();
            let holder = find_struct(&view, "testlib::enums::NicheHolder");
            let opt_ref = member(reader, &holder.members, "opt_ref").unwrap();
            let RawType::Enum(e) = ty_of(reader, opt_ref.type_id) else {
                panic!("expected enum");
            };
            assert_eq!(variant_count(e), 2);

            let VariantShape::Many { discr, variants } = &e.shape else {
                panic!("expected Many shape for niche-optimized enum");
            };
            // Niche-optimized: discriminant overlaps with payload data.
            let discr = discr
                .as_ref()
                .expect("Option<NonZeroU64> should have a discriminant member");
            assert_eq!(discr.offset, 0);

            let names = variant_names(reader, variants);
            assert!(names.contains(&"Some"));
            assert!(names.contains(&"None"));
        });
    }

    #[test]
    fn test_niche_enum_has_default_variant() {
        with_view!(view => {
            let reader = view.collector();
            let holder = find_struct(&view, "testlib::enums::NicheHolder");
            let opt_ref = member(reader, &holder.members, "opt_ref").unwrap();
            let RawType::Enum(e) = ty_of(reader, opt_ref.type_id) else {
                panic!("expected enum");
            };
            let VariantShape::Many { variants, .. } = &e.shape else {
                panic!("expected Many shape");
            };
            // Niche optimization: one variant has an explicit discriminant
            // value (None=0), the other is the default (Some, matched when
            // the discriminant doesn't equal any explicit value).
            let vals: Vec<_> = variants.iter().map(|(dv, _)| dv).collect();
            let has_default = vals.iter().any(|dv| dv.is_none());
            let has_explicit = vals.iter().any(|dv| dv.is_some());
            assert!(has_default, "niche enum should have a default variant");
            assert!(has_explicit, "niche enum should have an explicit variant");
        });
    }

    // ---- N. C-style Enum ----

    #[test]
    fn test_clike_enum_color_is_enum() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Color");
            assert_eq!(str_of(reader, e.name), Some("Color"));
        });
    }

    #[test]
    fn test_clike_enum_color_not_struct() {
        with_view!(view => {
            let all = find_all(&view, "testlib::enums::Color");
            assert!(
                !all.iter().any(|ty| matches!(ty, RawType::Struct(_))),
                "Color should not be found as Struct"
            );
        });
    }

    /// The enumerators of a C-style enum, as `(name, value)` pairs.
    fn enumerator_pairs<'a>(
        reader: &'a DwReader<'a>,
        enumerators: &[RawEnumerator<StrId>],
    ) -> Vec<(&'a str, u128)> {
        enumerators
            .iter()
            .map(|e| (reader.strings.get(e.name), e.value))
            .collect()
    }

    #[test]
    fn test_clike_enum_color_shape() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Color");
            let VariantShape::CStyle { enumerators, .. } = &e.shape else {
                panic!("expected CStyle shape for Color");
            };
            let names: Vec<_> = enumerator_pairs(reader, enumerators)
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            assert!(names.contains(&"Red"));
            assert!(names.contains(&"Green"));
            assert!(names.contains(&"Blue"));
        });
    }

    #[test]
    fn test_clike_enum_color_variant_count() {
        with_view!(view => {
            let e = find_enum(&view, "testlib::enums::Color");
            assert_eq!(variant_count(e), 3);
        });
    }

    #[test]
    fn test_clike_enum_color_values() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Color");
            let VariantShape::CStyle { enumerators, .. } = &e.shape else {
                panic!("expected CStyle shape");
            };
            let pairs = enumerator_pairs(reader, enumerators);
            assert!(pairs.contains(&("Red", 0)));
            assert!(pairs.contains(&("Green", 1)));
            assert!(pairs.contains(&("Blue", 2)));
        });
    }

    #[test]
    fn test_clike_enum_small_repr_u8() {
        with_view!(view => {
            let e = find_enum(&view, "testlib::enums::SmallEnum");
            assert_eq!(e.size, 1, "repr(u8) enum should be 1 byte");
            assert_eq!(variant_count(e), 3);
        });
    }

    #[test]
    fn test_clike_enum_namespace() {
        with_view!(view => {
            let reader = view.collector();
            let e = find_enum(&view, "testlib::enums::Color");
            let ns = e.namespace.expect("Color should have a namespace");
            assert_eq!(Namespace::new(ns, reader).full_name(), "testlib::enums");
        });
    }

    // ---- N. Namespace queries ----

    #[test]
    fn test_find_ns() {
        with_view!(view => {
            let ns = view.find_ns("testlib::shapes").expect("shapes ns not found");
            assert_eq!(ns.full_name(), "testlib::shapes");
            assert_eq!(ns.depth(), 2);

            assert!(view.find_ns("nonexistent").is_none());
            assert!(view.find_ns("testlib::nonexistent").is_none());
        });
    }

    #[test]
    fn test_find_ns_deep() {
        with_view!(view => {
            let ns = view.find_ns("testlib::outer::inner").expect("inner ns not found");
            assert_eq!(ns.full_name(), "testlib::outer::inner");
            assert_eq!(ns.depth(), 3);
        });
    }

    // ---- Template parameters ----

    #[test]
    fn test_func_template_params() {
        with_view!(view => {
            let reader = view.collector();
            let f = view
                .find_func("testlib::generics::swap<u32, u64>")
                .expect("swap<u32, u64> not found");
            let params: Vec<_> = f.template_params().collect();
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].name(), Some("A"));
            let a = ty_of(reader, params[0].type_id());
            assert_eq!(name_of(reader, a), Some("u32"));
            assert!(matches!(a, RawType::Base(_)));
            assert_eq!(params[1].name(), Some("B"));
            assert_eq!(name_of(reader, ty_of(reader, params[1].type_id())), Some("u64"));
        });
    }

    #[test]
    fn test_template_param_iter_exact_size() {
        with_view!(view => {
            let f = view
                .find_func("testlib::generics::swap<u32, u64>")
                .unwrap();
            let mut iter = f.template_params();
            assert_eq!(iter.len(), 2);
            iter.next();
            assert_eq!(iter.len(), 1);
        });
    }

    #[test]
    fn test_non_generic_func_has_no_template_params() {
        with_view!(view => {
            let f = view.find_func("testlib::shapes::add_points").unwrap();
            assert_eq!(f.template_params().len(), 0);
        });
    }

    #[test]
    fn test_struct_template_params() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::generics::Pair<u32, u64>");
            assert_eq!(s.template_params.len(), 2);
            assert_eq!(tp_binding(reader, &s.template_params[0]), (Some("A"), Some("u32")));
            assert_eq!(tp_binding(reader, &s.template_params[1]), (Some("B"), Some("u64")));

            // The two instantiations are distinct types with distinct
            // bindings, not deduplicated into one.
            let s = find_struct(&view, "testlib::generics::Pair<u64, u32>");
            assert_eq!(tp_binding(reader, &s.template_params[0]).1, Some("u64"));
            assert_eq!(tp_binding(reader, &s.template_params[1]).1, Some("u32"));
        });
    }

    #[test]
    fn test_enum_template_params() {
        with_view!(view => {
            let reader = view.collector();
            // rustc (1.97) does not put DW_TAG_template_type_parameter on
            // the enum DIE itself; this assertion is the drift canary.
            let e = find_enum(&view, "testlib::generics::Either<u32, u64>");
            assert_eq!(e.template_params.len(), 0);

            // The bindings ARE recorded on each variant payload struct,
            // which is nested in the enum's namespace. This is how an
            // enum instantiation's generic arguments are recovered (e.g.
            // T from Stage<T>'s Running payload).
            let s = find_struct(&view, "testlib::generics::Either<u32, u64>::Left");
            assert_eq!(s.template_params.len(), 2);
            assert_eq!(tp_binding(reader, &s.template_params[0]), (Some("L"), Some("u32")));
            assert_eq!(tp_binding(reader, &s.template_params[1]), (Some("R"), Some("u64")));
        });
    }

    #[test]
    fn test_generic_fn_linkage_name_is_v0() {
        with_view!(view => {
            let f = view
                .find_func("testlib::generics::swap<u32, u64>")
                .unwrap();
            let linkage = f.linkage_name().expect("swap should have linkage name");
            assert!(
                linkage.starts_with("_R"),
                "expected v0-mangled linkage name, got {linkage:?}"
            );
            assert!(linkage.contains("4swap"), "linkage {linkage:?} should encode 'swap'");
        });
    }

    // ---- Declaration coordinates ----

    /// 1-indexed line of the first fixture-source line containing `needle`.
    fn src_line(needle: &str) -> u64 {
        let pos = testhelper::shared_src()
            .lines()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{needle:?} not found in fixture source"));
        pos as u64 + 1
    }

    #[test]
    fn test_func_decl_coords() {
        with_view!(view => {
            let f = view
                .find_func("testlib::generics::swap<u32, u64>")
                .unwrap();
            let loc = f.source_loc().expect("swap should have decl coords");
            assert_eq!(loc.file(), Some("lib.rs"));
            assert_eq!(loc.line().unwrap().get(), src_line("pub fn swap<A, B>"));
        });
    }

    #[test]
    fn test_type_decl_coords_absent() {
        with_view!(view => {
            // rustc (1.97) does not emit DW_AT_decl_file/line on type DIEs
            // (that's behind -Zdebug-info-type-line-numbers), so future
            // provenance must come from the defining subprogram or static
            // instead. These assertions are the drift canary: if a rustc
            // bump starts emitting type decl coords, the reader already
            // carries them and this test tells us to start using them.
            let s = find_struct(&view, "testlib::generics::Pair<u32, u64>");
            assert!(s.source_loc.is_none());

            let e = find_enum(&view, "testlib::generics::Either<u32, u64>");
            assert!(e.source_loc.is_none());
        });
    }

    #[test]
    fn test_static_decl_coords() {
        with_view!(view => {
            let reader = view.collector();
            let v = find_var(&view, "testlib::generics::PAIR");
            let loc = &v.source_loc;
            assert!(!loc.is_empty(), "PAIR should have decl coords");
            assert_eq!(str_of(reader, loc.file), Some("lib.rs"));
            assert_eq!(loc.line.unwrap().get(), src_line("pub static PAIR:"));
        });
    }

    // ---- Async coroutine types ----

    #[test]
    fn test_async_fn_env_is_enum_with_decl_coords() {
        with_view!(view => {
            let reader = view.collector();
            // The coroutine type lives in a namespace named after the
            // async fn itself.
            let e = find_enum(&view, "testlib::asyncs::chain::{async_fn_env#0}");

            // The coroutine type itself has no decl coords (see
            // test_type_decl_coords_absent); provenance comes from the
            // async fn's subprogram, which does.
            assert!(e.source_loc.is_none());
            let f = view
                .find_func("testlib::asyncs::chain")
                .expect("chain subprogram not found");
            let loc = f.source_loc().expect("async fn should have decl coords");
            assert_eq!(loc.file(), Some("lib.rs"));
            assert_eq!(loc.line().unwrap().get(), src_line("pub async fn chain"));

            // And it has the coroutine variant set, including a suspend
            // point for the single await. The variant *members* are named
            // "0", "1", ...; the human-readable state names are the
            // payload struct types.
            let VariantShape::Many { variants, .. } = &e.shape else {
                panic!("expected Many shape for a coroutine enum");
            };
            let names: Vec<_> = variants
                .iter()
                .filter_map(|(_, v)| name_of(reader, ty_of(reader, v.member.type_id)))
                .collect();
            for expected in ["Unresumed", "Returned", "Panicked", "Suspend0"] {
                assert!(
                    names.contains(&expected),
                    "coroutine variants {names:?} missing {expected:?}"
                );
            }
        });
    }

    #[test]
    fn test_await_point_decl_coords() {
        with_view!(view => {
            let reader = view.collector();
            // Coroutine variant members carry the decl coordinates of the
            // suspend point itself — the awaited expression's source line.
            // This is the raw material for await-point → source-line
            // reporting.
            let e = find_enum(&view, "testlib::asyncs::chain::{async_fn_env#0}");
            let VariantShape::Many { variants, .. } = &e.shape else {
                panic!("expected Many shape for a coroutine enum");
            };
            let suspend = variants
                .iter()
                .map(|(_, v)| v)
                .find(|v| name_of(reader, ty_of(reader, v.member.type_id)) == Some("Suspend0"))
                .expect("no Suspend0 variant");
            let loc = suspend
                .member
                .source_loc
                .as_deref()
                .expect("suspend variant member should have decl coords");
            assert_eq!(str_of(reader, loc.file), Some("lib.rs"));
            assert_eq!(loc.line.unwrap().get(), src_line("leaf(x).await"));
        });
    }

    #[test]
    fn test_drop_glue_template_param_binds_coroutine() {
        with_view!(view => {
            let reader = view.collector();
            // The dyn-future join resolves a vtable's
            // drop_glue<T> symbol and needs T as a DIE reference: the
            // instantiation's template parameter binds the coroutine
            // type directly.
            let f = view
                .functions()
                .map(|(_, f)| f)
                .find(|f| {
                    f.name()
                        .is_some_and(|n| n.starts_with("drop_glue<testlib::asyncs::leaf"))
                })
                .expect("drop_glue<leaf coroutine> not found");
            assert!(f.linkage_name().is_some_and(|l| l.starts_with("_R")));

            let params: Vec<_> = f.template_params().collect();
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name(), Some("T"));
            let ty = ty_of(reader, params[0].type_id());
            assert!(matches!(ty, RawType::Enum(_)));
            assert_eq!(name_of(reader, ty), Some("{async_fn_env#0}"));
        });
    }

    // ---- L. Unions and arrays ----

    #[test]
    fn test_union_members() {
        with_view!(view => {
            let reader = view.collector();
            let u = find_union(&view, "testlib::blobs::IntOrFloat");
            assert_eq!(str_of(reader, u.name), Some("IntOrFloat"));
            assert_eq!(u.size, 4);
            assert_eq!(u.members.len(), 2);

            let i = member(reader, &u.members, "i").expect("member i");
            assert_eq!(i.offset, 0);
            assert_eq!(name_of(reader, ty_of(reader, i.type_id)), Some("u32"));
            let f = member(reader, &u.members, "f").expect("member f");
            assert_eq!(f.offset, 0);
            assert_eq!(name_of(reader, ty_of(reader, f.type_id)), Some("f32"));
        });
    }

    #[test]
    fn test_union_template_params() {
        with_view!(view => {
            let reader = view.collector();
            let u = find_union(&view, "testlib::blobs::Slot<u32>");
            assert_eq!(u.template_params.len(), 1);
            assert_eq!(tp_binding(reader, &u.template_params[0]), (Some("T"), Some("u32")));
        });
    }

    #[test]
    fn test_union_namespace() {
        with_view!(view => {
            let reader = view.collector();
            let u = find_union(&view, "testlib::blobs::IntOrFloat");
            let ns = u.namespace.expect("IntOrFloat should have a namespace");
            assert_eq!(Namespace::new(ns, reader).full_name(), "testlib::blobs");
        });
    }

    #[test]
    fn test_array_members() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::blobs::Buffers");

            // Arrays are anonymous in DWARF: element type and count are
            // their identity.
            let bytes = member(reader, &s.members, "bytes").unwrap();
            let RawType::Array(arr) = ty_of(reader, bytes.type_id) else {
                panic!("bytes should be an array");
            };
            assert_eq!(arr.count, 16);
            assert_eq!(name_of(reader, ty_of(reader, arr.elem_type_id)), Some("u8"));

            let words = member(reader, &s.members, "words").unwrap();
            let RawType::Array(arr) = ty_of(reader, words.type_id) else {
                panic!("words should be an array");
            };
            assert_eq!(arr.count, 3);
            assert_eq!(name_of(reader, ty_of(reader, arr.elem_type_id)), Some("u64"));
        });
    }

    #[test]
    fn test_array_dedup_by_elem_and_count() {
        with_view!(view => {
            let reader = view.collector();
            let s = find_struct(&view, "testlib::blobs::Buffers");

            // Same (element, count) → one canonical array type.
            let a = reader.canonicalize(member(reader, &s.members, "bytes").unwrap().type_id);
            let b = reader.canonicalize(member(reader, &s.members, "more_bytes").unwrap().type_id);
            assert_eq!(a, b);

            // Different count → different canonical type.
            let c = reader.canonicalize(member(reader, &s.members, "words").unwrap().type_id);
            assert_ne!(a, c);
        });
    }

    #[test]
    fn test_static_of_array_type() {
        with_view!(view => {
            let reader = view.collector();
            let v = find_var(&view, "testlib::blobs::RAW_TABLE");
            let RawType::Array(arr) = ty_of(reader, v.type_id) else {
                panic!("RAW_TABLE should be an array");
            };
            assert_eq!(arr.count, 4);
            assert_eq!(name_of(reader, ty_of(reader, arr.elem_type_id)), Some("u32"));
        });
    }

    // ---- M. Static linkage names and producer ----

    #[test]
    fn test_static_variable_linkage_name() {
        with_view!(view => {
            let reader = view.collector();
            let v = find_var(&view, "testlib::shapes::GLOBAL_COUNT");
            // v0 mangled (the fixture pins a ≥1.97 toolchain), and the
            // demangled form round-trips to the full path.
            let mangled =
                str_of(reader, v.linkage_name).expect("static should have linkage name");
            assert!(mangled.starts_with("_R"), "not v0-mangled: {mangled}");
            let demangled = format!("{:#}", rustc_demangle::demangle(mangled));
            assert_eq!(demangled, "testlib::shapes::GLOBAL_COUNT");
        });
    }

    #[test]
    fn test_producer_records_rustc_version() {
        with_view!(view => {
            let producer = view
                .collector()
                .producer
                .map(|id| view.collector().strings.get(id))
                .expect("fixture CU should carry DW_AT_producer");
            assert!(
                producer.contains("rustc version"),
                "unexpected producer: {producer}"
            );
        });
    }
}

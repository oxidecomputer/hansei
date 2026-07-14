mod types;

pub use types::{
    Array, Base, Enum, Enumerator, EnumeratorIter, Func, Member, MemberIter, Namespace,
    NsFuncIter, NsTypeIter, NsVarIter, Param, ParamIter, Pointer, SourceLocView, StaticVariable,
    Struct, TemplateParam, TemplateParamIter, Type, Union, Variant, VariantIter, VariantShapeView,
};

use crate::raw_types::NsId;
use crate::reader::DwReader;
use crate::{FuncId, TypeId, TypeKind, VarId};

use foldhash::{HashMap, HashMapExt};

/// An indexed, read-only view into the deduplicated DWARF type data.
///
/// `DwView` borrows from a [`DwReader`] and provides efficient
/// name-based type lookups over canonical (deduplicated) types,
/// static variables, and functions.
pub struct DwView<'a> {
    collector: &'a DwReader<'a>,
    by_name: HashMap<&'a str, Vec<TypeId>>,
    vars_by_name: HashMap<&'a str, Vec<VarId>>,
    funcs_by_name: HashMap<&'a str, Vec<FuncId>>,
}

impl<'a> DwView<'a> {
    /// Build an indexed view from a collector.
    pub fn new(collector: &'a DwReader<'a>) -> Self {
        let mut by_name: HashMap<&'a str, Vec<TypeId>> = HashMap::new();
        for (id, raw_ty) in collector.canonical_types() {
            if let Some(str_id) = raw_ty.name() {
                let name = collector.strings.get(str_id);
                by_name.entry(name).or_default().push(id);
            }
        }

        let mut vars_by_name: HashMap<&'a str, Vec<VarId>> = HashMap::new();
        for (&id, var) in &collector.variables {
            if let Some(str_id) = var.name {
                let name = collector.strings.get(str_id);
                vars_by_name.entry(name).or_default().push(id);
            }
        }

        let mut funcs_by_name: HashMap<&'a str, Vec<FuncId>> = HashMap::new();
        for (&id, func) in &collector.functions {
            if let Some(str_id) = func.name {
                let name = collector.strings.get(str_id);
                funcs_by_name.entry(name).or_default().push(id);
            }
        }

        Self {
            collector,
            by_name,
            vars_by_name,
            funcs_by_name,
        }
    }

    // --- Types ---

    /// Get a type by its ID (automatically canonicalized).
    pub fn get(&self, id: TypeId) -> Type<'a> {
        let canonical_id = self.collector.canonicalize(id);
        let raw = self
            .collector
            .types
            .get(&canonical_id)
            .expect("TypeId not found in collector");
        Type::from_raw(raw, self.collector)
    }

    /// Find a type by path and kind.
    ///
    /// The path may be a bare name (`"Foo"`) or a fully-qualified path
    /// (`"foo::bar::Foo"`). If multiple types share the same name, only
    /// the first matching the given kind is returned.
    pub fn find(&self, path: &str, kind: TypeKind) -> Option<Type<'a>> {
        let (ns_id, type_name) = self.resolve_path(path)?;
        self.by_name
            .get(type_name)?
            .iter()
            .map(|&id| self.get(id))
            .find(|ty| ty.kind() == kind && ty.namespace_id() == ns_id)
    }

    /// Find all canonical types matching a path.
    ///
    /// The path may be a bare name (`"Foo"`) or a fully-qualified path
    /// (`"foo::bar::Foo"`).
    pub fn find_all(&self, path: &str) -> Vec<Type<'a>> {
        let Some((ns_id, type_name)) = self.resolve_path(path) else {
            return Vec::new();
        };
        self.by_name
            .get(type_name)
            .map(|ids| {
                ids.iter()
                    .map(|&id| self.get(id))
                    .filter(|ty| ty.namespace_id() == ns_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find the canonical [`TypeId`]s of all types matching a path.
    ///
    /// Like [`DwView::find_all`], but returns the ids for callers that
    /// need to track type identity (e.g. extraction).
    pub fn find_all_ids(&self, path: &str) -> Vec<TypeId> {
        let Some((ns_id, type_name)) = self.resolve_path(path) else {
            return Vec::new();
        };
        self.by_name
            .get(type_name)
            .map(|ids| {
                ids.iter()
                    .filter(|&&id| self.get(id).namespace_id() == ns_id)
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Iterate over all canonical types.
    pub fn types(&self) -> impl Iterator<Item = (TypeId, Type<'a>)> + '_ {
        self.collector
            .canonical_types()
            .map(|(id, raw)| (id, Type::from_raw(raw, self.collector)))
    }

    // --- Variables ---

    /// Get a static variable by its ID.
    pub fn get_var(&self, id: VarId) -> StaticVariable<'a> {
        let raw = self
            .collector
            .variables
            .get(&id)
            .expect("VarId not found in collector");
        StaticVariable::new(raw, self.collector)
    }

    /// Find a static variable by path.
    ///
    /// The path may be a bare name (`"X"`) or a fully-qualified path
    /// (`"foo::bar::X"`).
    pub fn find_var(&self, path: &str) -> Option<StaticVariable<'a>> {
        let (ns_id, var_name) = self.resolve_path(path)?;
        self.vars_by_name
            .get(var_name)?
            .iter()
            .map(|&id| self.get_var(id))
            .find(|v| v.namespace_id() == ns_id)
    }

    /// Find all static variables matching a path.
    pub fn find_all_vars(&self, path: &str) -> Vec<StaticVariable<'a>> {
        let Some((ns_id, var_name)) = self.resolve_path(path) else {
            return Vec::new();
        };
        self.vars_by_name
            .get(var_name)
            .map(|ids| {
                ids.iter()
                    .map(|&id| self.get_var(id))
                    .filter(|v| v.namespace_id() == ns_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Iterate over all static variables.
    pub fn variables(&self) -> impl Iterator<Item = (VarId, StaticVariable<'a>)> + '_ {
        self.collector
            .variables
            .iter()
            .map(|(&id, raw)| (id, StaticVariable::new(raw, self.collector)))
    }

    // --- Funcs ---

    /// Get a function by its ID.
    pub fn get_func(&self, id: FuncId) -> Func<'a> {
        let raw = self
            .collector
            .functions
            .get(&id)
            .expect("FuncId not found in collector");
        Func::new(raw, self.collector)
    }

    /// Find a function by path.
    ///
    /// The path may be a bare name (`"bar"`) or a fully-qualified path
    /// (`"foo::bar"`).
    pub fn find_func(&self, path: &str) -> Option<Func<'a>> {
        let (ns_id, func_name) = self.resolve_path(path)?;
        self.funcs_by_name
            .get(func_name)?
            .iter()
            .map(|&id| self.get_func(id))
            .find(|f| f.namespace_id() == ns_id)
    }

    /// Find all functions matching a path.
    pub fn find_all_funcs(&self, path: &str) -> Vec<Func<'a>> {
        let Some((ns_id, func_name)) = self.resolve_path(path) else {
            return Vec::new();
        };
        self.funcs_by_name
            .get(func_name)
            .map(|ids| {
                ids.iter()
                    .map(|&id| self.get_func(id))
                    .filter(|f| f.namespace_id() == ns_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Iterate over all functions.
    pub fn functions(&self) -> impl Iterator<Item = (FuncId, Func<'a>)> + '_ {
        self.collector
            .functions
            .iter()
            .map(|(&id, raw)| (id, Func::new(raw, self.collector)))
    }

    // --- Namespace queries ---

    /// Resolve a namespace path to a [`Namespace`] wrapper.
    ///
    /// The path is a `::` separated sequence such as `"testlib::shapes"`.
    /// Returns `None` if any segment does not exist.
    pub fn find_ns(&self, path: &str) -> Option<Namespace<'a>> {
        let ns_id = self.resolve_ns(path)?;
        Some(Namespace::new(ns_id, self.collector))
    }

    // --- Shared ---

    /// Resolve a namespace path such as `"foo::bar"` to its [`NsId`].
    ///
    /// Returns `None` if any segment does not exist in the namespace table.
    fn resolve_ns(&self, path: &str) -> Option<NsId> {
        let mut ns_id: Option<NsId> = None;
        for segment in path.split("::") {
            let str_id = self.collector.strings.find(segment)?;
            ns_id = Some(self.collector.namespaces.find(ns_id, str_id)?);
        }
        ns_id
    }

    /// Resolve a `"foo::bar::Baz"` path into a namespace and leaf name.
    ///
    /// Returns `(None, path)` for bare names, or
    /// `(Some(ns_id), leaf_name)` for qualified paths. Returns `None`
    /// if any namespace segment doesn't exist.
    fn resolve_path<'p>(&self, path: &'p str) -> Option<(Option<NsId>, &'p str)> {
        let Some(sep) = path.rfind("::") else {
            return Some((None, path));
        };

        let ns_path = &path[..sep];
        let leaf_name = &path[sep + 2..];

        let mut ns_id: Option<NsId> = None;
        for segment in ns_path.split("::") {
            let str_id = self.collector.strings.find(segment)?;
            ns_id = Some(self.collector.namespaces.find(ns_id, str_id)?);
        }

        Some((ns_id, leaf_name))
    }

    /// Returns a reference to the underlying collector.
    pub fn collector(&self) -> &'a DwReader<'a> {
        self.collector
    }
}

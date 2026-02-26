//! Indexed view into CTF data for efficient lookups.

use super::{CtfMember, CtfReader, CtfType};
use crate::{StrId, TypeId, TypeKind};

use std::collections::HashMap;

/// An indexed view into CTF data.
///
/// `CtfView` borrows from a [`CtfReader`] and provides efficient name-based
/// type lookups.
///
/// # Example
///
/// ```ignore
/// let reader = CtfReader::load(&data)?;
/// let view = reader.view();
///
/// if let Some(ty) = view.find_ty("MyStruct", TypeKind::Struct) {
///     println!("Found struct with size {}", view.ty_size(ty.id()));
/// }
/// ```
pub struct CtfView<'a> {
    reader: &'a CtfReader,
    by_name: HashMap<&'a str, Vec<TypeId>>,
}

impl<'a> CtfView<'a> {
    /// Build an indexed view from a reader.
    pub fn new(reader: &'a CtfReader) -> Self {
        let mut by_name: HashMap<&'a str, Vec<TypeId>> = HashMap::new();

        for ty in reader.types() {
            let name = ty.name(reader);
            // Don't index empty names (anonymous types)
            if !name.is_empty() {
                by_name.entry(name).or_default().push(ty.id());
            }
        }

        Self { reader, by_name }
    }

    /// Look up a type by its ID.
    pub fn ty(&self, id: TypeId) -> &'a CtfType {
        self.reader.ty(id)
    }

    /// Find a type by name and kind.
    ///
    /// If multiple types have the same name (but different kinds), only the first match is returned.
    pub fn find_ty(&self, name: &str, kind: TypeKind) -> Option<&'a CtfType> {
        self.by_name
            .get(name)?
            .iter()
            .map(|&id| self.get(id))
            .find(|ty| ty.kind() == kind)
    }

    /// Find a type by name and kind.
    ///
    /// This is useful when multiple types share a name (e.g., a struct and
    /// a typedef with the same name).
    pub fn find_all_by_name(&self, name: &str) -> impl Iterator<Item = &'a CtfType> {
        self.by_name
            .get(name)
            .into_iter()
            .flatten()
            .map(|&id| self.ty(id))
    }

    /// Iterate over all types.
    pub fn types(&self) -> &'a [CtfType] {
        self.reader.types()
    }

    /// Get the size in bytes of a type, following references as needed.
    pub fn ty_size(&self, id: TypeId) -> u64 {
        self.reader.ty_size(id)
    }

    /// Resolve a string ID to a string.
    pub fn str(&self, id: StrId) -> &'a str {
        self.reader.str(id)
    }

    /// Iterate over labels with resolved names and optional types.
    pub fn labels(&self) -> impl Iterator<Item = (&'a str, Option<&'a CtfType>)> {
        self.reader.labels().iter().map(|label| {
            let name = self.str(label.name);
            let ty = label.typeidx.map(|id| self.ty(id));
            (name, ty)
        })
    }

    /// Iterate over object types.
    pub fn objects(&self) -> impl Iterator<Item = &'a CtfType> {
        self.reader.objects().iter().map(|&id| self.ty(id))
    }

    /// Iterate over function types.
    pub fn functions(&self) -> impl Iterator<Item = &'a CtfType> {
        self.reader.funcs().iter().map(|&id| self.ty(id))
    }

    /// Get the name of a type.
    pub fn type_name(&self, ty: &CtfType) -> &'a str {
        ty.name(self.reader)
    }

    /// Get resolved members of a struct or union as (name, type) pairs.
    ///
    /// Returns an empty vector for non-aggregate types.
    pub fn members_resolved(&self, ty: &'a CtfType) -> Vec<(&'a str, &'a CtfType)> {
        ty.members()
            .iter()
            .map(|m| (self.str(m.name), self.ty(m.type_id)))
            .collect()
    }

    /// Find a member by name in a struct or union.
    ///
    /// Returns `None` for non-aggregate types or if the member is not found.
    pub fn find_member(&self, ty: &'a CtfType, name: &str) -> Option<&'a CtfMember> {
        ty.members().iter().find(|m| self.str(m.name) == name)
    }

    /// Iterate over enumerators with resolved names and values.
    ///
    /// Returns an empty iterator for non-enum types.
    pub fn enumerators(&self, ty: &'a CtfType) -> impl Iterator<Item = (&'a str, u64)> {
        ty.enumerators().iter().map(|e| (self.str(e.name), e.value))
    }

    /// Follow typedef/const/volatile/restrict chain to the underlying type.
    ///
    /// For non-reference types, returns the type itself.
    pub fn resolve_type(&self, id: TypeId) -> &'a CtfType {
        let ty = self.ty(id);
        match ty {
            CtfType::Typedef { ty: inner, .. } => self.resolve_type(inner.target_type),
            CtfType::Const { ty: inner, .. } => self.resolve_type(inner.target_type),
            CtfType::Volatile { ty: inner, .. } => self.resolve_type(inner.target_type),
            CtfType::Restrict { ty: inner, .. } => self.resolve_type(inner.target_type),
            _ => ty,
        }
    }

    /// Get the target type of a pointer, typedef, const, volatile, or restrict.
    ///
    /// Returns `None` for types that don't have a target type.
    pub fn target_type(&self, ty: &'a CtfType) -> Option<&'a CtfType> {
        let target_id = match ty {
            CtfType::Pointer { ty: inner, .. } => inner.target_type,
            CtfType::Typedef { ty: inner, .. } => inner.target_type,
            CtfType::Const { ty: inner, .. } => inner.target_type,
            CtfType::Volatile { ty: inner, .. } => inner.target_type,
            CtfType::Restrict { ty: inner, .. } => inner.target_type,
            _ => return None,
        };
        Some(self.ty(target_id))
    }

    /// Get the element type of an array.
    ///
    /// Returns `None` for non-array types.
    pub fn array_element_type(&self, ty: &'a CtfType) -> Option<&'a CtfType> {
        match ty {
            CtfType::Array { ty: inner, .. } => Some(self.ty(inner.element_type)),
            _ => None,
        }
    }

    /// Get function signature details.
    ///
    /// Returns `None` for non-function types.
    pub fn function_signature(&self, ty: &'a CtfType) -> Option<FunctionSig<'a>> {
        match ty {
            CtfType::Function { ty: inner, .. } => {
                let return_type = self.ty(inner.return_type);
                let args = inner.args.iter().map(|&id| self.ty(id)).collect();
                Some(FunctionSig {
                    return_type,
                    args,
                    is_varargs: inner.is_varargs,
                })
            }
            _ => None,
        }
    }
}

/// Function signature details.
#[derive(Debug, Clone)]
pub struct FunctionSig<'a> {
    /// The return type of the function.
    pub return_type: &'a CtfType,
    /// The argument types.
    pub args: Vec<&'a CtfType>,
    /// Whether the function accepts variadic arguments.
    pub is_varargs: bool,
}

#[cfg(test)]
mod tests {
    use crate::read::CtfReader;
    use crate::write::{CtfMember, CtfType, CtfWriter};
    use crate::{IntegerEncoding, IntegerFlags, TypeKind};

    /// Helper to create CTF data and return an indexed view.
    fn create_reader_from_writer(writer: &mut CtfWriter) -> CtfReader {
        let ctf_bytes = writer.generate_ctf().unwrap();
        CtfReader::load(&ctf_bytes).unwrap()
    }

    #[test]
    fn test_find_ty_by_name() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(CtfType::Integer {
                name: "my_int".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        let ty = view.find("my_int", TypeKind::Integer);
        assert!(ty.is_some());
        assert_eq!(ty.unwrap().name(), "my_int");
    }

    #[test]
    fn test_find_ty_filters_by_kind() {
        let mut writer = CtfWriter::new();

        // Add an integer named "foo"
        let int_id = writer
            .add_type(CtfType::Integer {
                name: "foo".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new(),
                },
            })
            .unwrap();

        // Add a typedef also named "foo"
        writer
            .add_type(CtfType::Typedef {
                name: "foo".to_string(),
                target_type: int_id,
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        // Should find the integer
        let int_ty = view.find("foo", TypeKind::Integer);
        assert!(int_ty.is_some());
        assert_eq!(int_ty.unwrap().kind(), TypeKind::Integer);

        // Should find the typedef
        let typedef_ty = view.find("foo", TypeKind::Typedef);
        assert!(typedef_ty.is_some());
        assert_eq!(typedef_ty.unwrap().kind(), TypeKind::Typedef);

        // Should not find a struct named "foo"
        let struct_ty = view.find("foo", TypeKind::Struct);
        assert!(struct_ty.is_none());
    }

    #[test]
    fn test_find_nonexistent_returns_none() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(CtfType::Integer {
                name: "exists".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        assert!(view.find("does_not_exist", TypeKind::Integer).is_none());
    }

    #[test]
    fn test_find_all_by_name_single() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(CtfType::Integer {
                name: "unique".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        let types: Vec<_> = view.find_all("unique").collect();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name(), "unique");
    }

    #[test]
    fn test_find_all_by_name_multiple() {
        let mut writer = CtfWriter::new();

        let int_id = writer
            .add_type(CtfType::Integer {
                name: "shared_name".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();

        writer
            .add_type(CtfType::Typedef {
                name: "shared_name".to_string(),
                target_type: int_id,
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        let types: Vec<_> = view.find_all("shared_name").collect();
        assert_eq!(types.len(), 2);

        let kinds: Vec<_> = types.iter().map(|t| t.kind()).collect();
        assert!(kinds.contains(&TypeKind::Integer));
        assert!(kinds.contains(&TypeKind::Typedef));
    }

    #[test]
    fn test_empty_name_not_indexed() {
        let mut writer = CtfWriter::new();

        // Anonymous pointer (empty name)
        let int_id = writer
            .add_type(CtfType::Integer {
                name: "int".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();

        writer
            .add_type(CtfType::Pointer {
                name: "".to_string(),
                target_type: int_id,
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        // Empty name should not be in the index
        let types: Vec<_> = view.find_all("").collect();
        assert!(types.is_empty());
    }

    #[test]
    fn test_ty_by_id() {
        let mut writer = CtfWriter::new();
        let id = writer
            .add_type(CtfType::Integer {
                name: "test_int".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        let ty = view.get(id);
        assert_eq!(ty.name(), "test_int");
    }

    #[test]
    fn test_types_returns_all() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(CtfType::Integer {
                name: "int1".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        writer
            .add_type(CtfType::Integer {
                name: "int2".to_string(),
                size: 8,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        // Should have: placeholder + void + int1 + int2
        let types = view.types();
        assert!(types.count() >= 4);
    }

    #[test]
    fn test_ty_size_integer() {
        let mut writer = CtfWriter::new();
        let id = writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        assert_eq!(view.get(id).size(), 4);
    }

    #[test]
    fn test_duplicate_names_different_kinds() {
        let mut writer = CtfWriter::new();

        let int_id = writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();

        // Struct named "Foo"
        writer
            .add_type(CtfType::Struct {
                name: "Foo".to_string(),
                size: 4,
                members: vec![CtfMember {
                    name: "x".to_string(),
                    type_id: int_id,
                    offset_bits: 0,
                }],
            })
            .unwrap();

        // Typedef also named "Foo"
        writer
            .add_type(CtfType::Typedef {
                name: "Foo".to_string(),
                target_type: int_id,
            })
            .unwrap();

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        // Should be able to find both
        assert!(view.find("Foo", TypeKind::Struct).is_some());
        assert!(view.find("Foo", TypeKind::Typedef).is_some());

        // find_all_by_name should return both
        let all: Vec<_> = view.find_all("Foo").collect();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_self_referential_struct() {
        let mut writer = CtfWriter::new();

        // Reserve ID for the struct
        let struct_id = writer.reserve_type_id().unwrap();

        // Create pointer to the struct
        let ptr_id = writer
            .add_type(CtfType::Pointer {
                name: "".to_string(),
                target_type: struct_id,
            })
            .unwrap();

        // Now set the struct with a member pointing to itself via pointer
        writer.set_type(
            struct_id,
            CtfType::Struct {
                name: "Node".to_string(),
                size: 16,
                members: vec![CtfMember {
                    name: "next".to_string(),
                    type_id: ptr_id,
                    offset_bits: 0,
                }],
            },
        );

        let reader = create_reader_from_writer(&mut writer);
        let view = reader.view();

        let node = view.find("Node", TypeKind::Struct).unwrap();
        let members: Vec<_> = node.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name(), "next");
        assert_eq!(members[0].ty().kind(), TypeKind::Pointer);

        // Follow the pointer to verify it points back to Node
        let next_target = members[0].ty().as_pointer().unwrap().target();
        assert_eq!(next_target.name(), "Node");
    }
}

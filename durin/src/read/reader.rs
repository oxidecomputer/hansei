use super::Error;
use super::*;
use crate::read::raw_types::{RawCtfType, RawCtfTypedef, RawCtfUnion};
use crate::{CtfHeader, CtfPreamble, HEADER_SIZE, StrId, TypeId, TypeKind};

use std::fmt;

pub struct CtfReader {
    preamble: CtfPreamble,
    header: CtfHeader,
    labels: Vec<CtfLabel>,
    objects: Vec<TypeId>,
    functions: Vec<TypeId>,
    types: TypeTable,
    strings: StringTable,
}

impl fmt::Debug for CtfReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct TypeWrapper<'a> {
            table: &'a TypeTable,
            ctf: &'a CtfReader,
        }

        impl fmt::Debug for TypeWrapper<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let iter = self.table.types.iter().map(|ty| (ty.name(self.ctf), ty));
                f.debug_map().entries(iter).finish()
            }
        }
        f.debug_struct("CtfReader")
            .field("preamble", &self.preamble)
            .field("header", &self.header)
            .field("labels", &self.labels)
            .field("objects", &self.objects)
            .field("functions", &self.functions)
            .field(
                "types",
                &TypeWrapper {
                    table: &self.types,
                    ctf: self,
                },
            )
            .field("strings", &self.strings)
            .finish()
    }
}

impl CtfReader {
    pub fn load(input: &[u8]) -> Result<Self> {
        let offset = &mut 0;

        if input.len() < HEADER_SIZE {
            return Err(Error::too_short(input.len() as u32, HEADER_SIZE as u32));
        }

        let magic: u16 = input.gread(offset)?;
        let endian = match magic.to_ne_bytes() {
            CTF_MAGIC_BYTES_BE => Endian::Big,
            CTF_MAGIC_BYTES_LE => Endian::Little,
            _ => return Err(Error::invalid_magic(magic)),
        };

        let preamble: CtfPreamble = input.gread_with(offset, endian)?;
        let header: CtfHeader = input.gread_with(offset, endian)?;

        let expected_len = header.stroff + header.strlen;
        let data = if preamble.flags.is_compressed() {
            let mut decompressor = ZlibDecoder::new(&input[HEADER_SIZE..]);
            let mut buf = Vec::new();

            decompressor
                .read_to_end(&mut buf)
                .map_err(Error::decompress)?;
            if expected_len as usize > buf.len() {
                return Err(Error::too_short(buf.len() as u32, expected_len));
            }
            buf
        } else {
            if expected_len as usize > input.len() {
                return Err(Error::too_short(input.len() as u32, expected_len));
            }
            let data = input.get(HEADER_SIZE..).unwrap();
            data.to_vec()
        };

        let labels = read_labels(&header, &data, endian)?;
        let objects = read_objects(&header, &data, endian)?;
        let functions = Vec::new(); // TODO
        let mut types = TypeTable::load(&header, &data, endian)?;

        // Strings are endian-agnostic.
        let unchecked_strings = UncheckedStringTable::new(&header, &data);

        // TODO how expensive is this check? Do we care?
        // If this is a real library we should make this optional.
        validate_labels(&labels, &types, &unchecked_strings)?;
        validate_objects(&objects, &types)?;
        validate_functions(&functions, &types)?;
        validate_types(&types, &unchecked_strings)?;

        // We've now checked every source of StrIds and know that all
        // ids present point to a valid `&str`.
        let strings = StringTable::from(unchecked_strings);

        update_large_enums(&mut types, &strings)?;

        Ok(Self {
            preamble,
            header,
            labels,
            objects,
            functions,
            types,
            strings,
        })
    }

    pub fn preamble(&self) -> &CtfPreamble {
        &self.preamble
    }

    pub fn header(&self) -> &CtfHeader {
        &self.header
    }

    pub fn ty(&self, id: TypeId) -> &RawCtfType {
        // UNWRAP: We validate all type ids are valid during construction.
        self.types.ty_checked(id).unwrap()
    }

    /// Return the size of bytes of the type by id, following referenced
    /// types as needed.
    pub fn ty_size(&self, id: TypeId) -> u64 {
        match self.ty(id) {
            RawCtfType::Unknown(..) => 0,
            RawCtfType::Integer(RawCtfInteger { size, .. }) => *size,
            RawCtfType::Float(RawCtfFloat { size, .. }) => *size,
            RawCtfType::Pointer(..) => POINTER_SIZE,
            RawCtfType::Array(RawCtfArray {
                element_type,
                nelems,
                ..
            }) => {
                let elem_size = self.ty_size(*element_type);
                elem_size * *nelems as u64
            }
            RawCtfType::Function(..) => POINTER_SIZE,
            RawCtfType::Struct(RawCtfStruct { size, .. }) => *size,
            RawCtfType::Union(RawCtfUnion { size, .. }) => *size,
            RawCtfType::Enum(RawCtfEnum { size, .. }) => *size,
            RawCtfType::Forward(..) => 0,
            RawCtfType::Typedef(RawCtfTypedef { target_type, .. }) => self.ty_size(*target_type),
            RawCtfType::Volatile(RawCtfVolatile { target_type, .. }) => self.ty_size(*target_type),
            RawCtfType::Const(RawCtfConst { target_type, .. }) => self.ty_size(*target_type),
            RawCtfType::Restrict(RawCtfRestrict { target_type, .. }) => self.ty_size(*target_type),
        }
    }

    pub fn types(&self) -> &[RawCtfType] {
        self.types.as_slice()
    }

    pub fn find_ty<'ctf>(&'ctf self, name: &str, kind: TypeKind) -> Option<&'ctf RawCtfType> {
        self.types()
            .iter()
            .find(|t| t.kind() == kind && t.name(self) == name)
    }

    pub fn labels(&self) -> &[CtfLabel] {
        &self.labels
    }

    pub fn objects(&self) -> &[TypeId] {
        &self.objects
    }

    pub fn funcs(&self) -> &[TypeId] {
        &self.functions
    }

    pub fn str(&self, id: StrId) -> &str {
        self.strings.get(id)
    }

    pub fn string_table(&self) -> &StringTable {
        &self.strings
    }

    /// Build an indexed view for efficient lookups.
    ///
    /// The returned `CtfView` provides fast name-based type lookups and access
    /// to `CtfType`.
    pub fn view(&self) -> CtfView<'_> {
        CtfView::new(self)
    }
}

fn read_labels(header: &CtfHeader, data: &[u8], endian: Endian) -> Result<Vec<CtfLabel>> {
    let labels_start = header.lbloff as usize;
    let labels_end = header.objtoff as usize;
    let labels_data = &data[labels_start..labels_end];

    let offset = &mut 0;

    let mut labels = Vec::new();
    while *offset < labels_data.len() {
        let label = labels_data.gread_with(offset, endian)?;
        labels.push(label);
    }

    Ok(labels)
}

fn read_objects(header: &CtfHeader, data: &[u8], endian: Endian) -> Result<Vec<TypeId>> {
    let obj_start = header.objtoff as usize;
    let obj_end = header.funcoff as usize;
    let obj_data = &data[obj_start..obj_end];

    let offset = &mut 0;

    let mut objects = Vec::new();
    while *offset < obj_data.len() {
        let raw_id: u16 = obj_data.gread_with(offset, endian)?;
        let object = TypeId::from_u16(raw_id)?;

        objects.push(object);
    }

    Ok(objects)
}

/// Iterate over labels and confirm that all type and string references are
/// valid.
fn validate_labels(
    labels: &[CtfLabel],
    types: &TypeTable,
    strings: &UncheckedStringTable,
) -> Result<()> {
    for label in labels {
        strings.check(label.name)?;
        if let Some(ty) = label.typeidx {
            types.check(ty)?;
        }
    }

    Ok(())
}

/// Iterate over objects and confirm that all type references are valid.
fn validate_objects(objects: &[TypeId], types: &TypeTable) -> Result<()> {
    for ty in objects {
        types.check(*ty)?;
    }

    Ok(())
}

/// Iterate over functions and confirm that all type and string references are
/// valid.
fn validate_functions(functions: &[TypeId], _types: &TypeTable) -> Result<()> {
    // TODO
    for _func in functions {
        // TODO
    }

    Ok(())
}

/// Iterate over types and confirm that all type and string references are
/// valid.
fn validate_types(types: &TypeTable, strings: &UncheckedStringTable) -> Result<()> {
    for ty in types.as_slice() {
        if let Some(id) = ty.name_id() {
            strings.check(id)?;
        };
        match ty {
            RawCtfType::Unknown(..) => {}
            RawCtfType::Integer(..) => {}
            RawCtfType::Float(..) => {}
            RawCtfType::Pointer(RawCtfPointer { target_type, .. }) => {
                types.check(*target_type)?;
            }
            RawCtfType::Array(RawCtfArray {
                element_type,
                index_type,
                ..
            }) => {
                types.check(*element_type)?;
                types.check(*index_type)?;
            }
            RawCtfType::Function(RawCtfFunction {
                return_type, args, ..
            }) => {
                types.check(*return_type)?;
                for arg in args {
                    types.check(*arg)?;
                }
            }
            RawCtfType::Struct(RawCtfStruct { members, .. }) => {
                for RawCtfMember { name, type_id, .. } in members {
                    strings.check(*name)?;
                    types.check(*type_id)?;
                }
            }
            RawCtfType::Union(RawCtfUnion { members, .. }) => {
                for RawCtfMember { name, type_id, .. } in members {
                    strings.check(*name)?;
                    types.check(*type_id)?;
                }
            }
            RawCtfType::Enum(RawCtfEnum { enumerators, .. }) => {
                for RawCtfEnumerator { name, .. } in enumerators {
                    strings.check(*name)?;
                }
            }
            RawCtfType::Forward(..) => {}
            RawCtfType::Typedef(RawCtfTypedef { target_type, .. }) => {
                types.check(*target_type)?;
            }
            RawCtfType::Volatile(RawCtfVolatile { target_type, .. }) => {
                types.check(*target_type)?;
            }
            RawCtfType::Const(RawCtfConst { target_type, .. }) => {
                types.check(*target_type)?;
            }
            RawCtfType::Restrict(RawCtfRestrict { target_type, .. }) => {
                types.check(*target_type)?;
            }
        }
    }

    Ok(())
}

/// CTF requires that enum values be 4 bytes, but we're going to work around
/// this by passing longer values in the name. Parse the inline value as an
/// i32. Once all strings are parsed, take a second pass to update the values as
/// necessary.
fn update_large_enums(types: &mut TypeTable, strings: &StringTable) -> Result<()> {
    let iter = types.as_slice_mut().iter_mut().filter_map(|t| match t {
        RawCtfType::Enum(ty) => Some(ty),
        _ => None,
    });

    for ty in iter {
        for enm in &mut ty.enumerators {
            let name = strings.get(enm.name);
            if name.ends_with("@@") {
                let hex_num = name
                    .split("@@")
                    .nth(1)
                    .ok_or_else(|| Error::invalid_enum_format(name.to_string()))?;
                let bare_hex = hex_num.trim_start_matches("0x");

                // The Rust standard says the default representation of
                // discriminants is isize, but top-bit niches will result in
                // a value > isize::MAX, so we use u64.
                let full_value = u64::from_str_radix(bare_hex, 16)
                    .map_err(|_| Error::invalid_enum_value(name.to_string()))?;
                enm.value = full_value
            }
        }
    }

    Ok(())
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct TypeTable {
    types: Vec<RawCtfType>,
}

impl TypeTable {
    pub fn load(header: &CtfHeader, data: &[u8], endian: Endian) -> Result<Self> {
        let types_start = header.typeoff as usize;
        let types_end = header.stroff as usize;
        let types_data = &data[types_start..types_end];

        let offset = &mut 0;
        let mut id = TypeId::from_u16(1).unwrap();

        let mut types = Vec::new();
        // First slot is empty, but we use Unknown as a placeholder
        types.push(RawCtfType::Unknown(RawCtfUnknown { id }));

        while *offset < types_data.len() {
            let ty = types_data.gread_with(offset, (id, endian))?;
            types.push(ty);
            let new_id = TypeId::from_u16(id.get() + 1)?;
            id = new_id;
        }

        Ok(Self { types })
    }

    pub fn ty_checked(&self, id: TypeId) -> Result<&RawCtfType> {
        let Some(ty) = self.types.get(id.get() as usize) else {
            return Err(Error::missing_type(id));
        };

        Ok(ty)
    }

    pub fn check(&self, id: TypeId) -> Result<()> {
        let _ = self.ty_checked(id)?;
        Ok(())
    }

    pub fn as_slice(&self) -> &[RawCtfType] {
        &self.types
    }

    pub fn as_slice_mut(&mut self) -> &mut [RawCtfType] {
        &mut self.types
    }
}

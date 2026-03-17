use durin::read::{CtfEnum, CtfType, CtfView};
use durin::{TypeId, TypeKind};
use proc::{Mappings, Proc};

use std::fmt;
use std::str;

#[cfg(not(target_os = "illumos"))]
compile_error!("this crate only supports illumos");

pub type Result<T> = std::result::Result<T, Error>;

/// TODO
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    backtrace: std::backtrace::Backtrace,
}

#[derive(thiserror::Error, Debug)]
enum ErrorKind {
    #[error("invalid discriminant value {discrim} for type {ty:?}")]
    InvalidDiscriminantValue { ty: TypeId, discrim: i64 },
    #[error("unable to read member at range {start}..{end} from buf with len {len}")]
    InvalidMemberRange { start: u16, end: u16, len: u16 },
    #[error("enumerator {enum_name} not found for type {ty:?}")]
    NoEnumerator { ty: TypeId, enum_name: String },
    #[error("member {member_name} not found for type {ty:?}")]
    NoMember { ty: TypeId, member_name: String },
    #[error("attempted to dereference invalid address {addr:#x}")]
    InvalidAddr { addr: u64 },
    #[error("failed to parse type {0}")]
    ParseType(String),
    #[error("data length {actual} is does not match expected {expected} length")]
    UnexpectedLen { actual: u32, expected: u32 },
    #[error("expected a {expected:?} but found a {actual:?} when parsing {name}")]
    UnexpectedType {
        actual: TypeKind,
        expected: TypeKind,
        name: String,
    },
    #[error("expected enum variant {expected} was not active")]
    UnexpectedVariant { expected: String },
}

impl Error {
    /// Creates a new error with backtrace capture.
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            source: None,
            backtrace: std::backtrace::Backtrace::capture(),
        }
    }

    /// Attaches a source error to this error.
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// Returns the backtrace captured when the error was created.
    pub fn backtrace(&self) -> &std::backtrace::Backtrace {
        &self.backtrace
    }

    pub fn invalid_discriminant_value(ty: TypeId, discrim: i64) -> Self {
        Self::new(ErrorKind::InvalidDiscriminantValue { ty, discrim })
    }

    pub fn invalid_member_range(start: u16, end: u16, len: u16) -> Self {
        Self::new(ErrorKind::InvalidMemberRange { start, end, len })
    }

    pub fn no_enumerator(ty: TypeId, enum_name: String) -> Self {
        Self::new(ErrorKind::NoEnumerator { ty, enum_name })
    }

    pub fn no_member(ty: TypeId, member_name: String) -> Self {
        Self::new(ErrorKind::NoMember { ty, member_name })
    }

    pub fn invalid_addr(addr: u64) -> Self {
        Self::new(ErrorKind::InvalidAddr { addr })
    }

    pub fn parse_type(ty: impl Into<String>) -> Self {
        Self::new(ErrorKind::ParseType(ty.into()))
    }

    pub fn unexpected_len(actual: u32, expected: u32) -> Self {
        Self::new(ErrorKind::UnexpectedLen { actual, expected })
    }

    pub fn unexpected_type(actual: TypeKind, expected: TypeKind, name: String) -> Self {
        Self::new(ErrorKind::UnexpectedType {
            actual,
            expected,
            name,
        })
    }

    pub fn unexpected_variant(expected: String) -> Self {
        Self::new(ErrorKind::UnexpectedVariant { expected })
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

#[derive(Clone)]
pub struct TypeInfo<'ctf> {
    pub ty: CtfType<'ctf>,
    pub addr: u64,
    pub buf: Box<[u8]>,
}

impl<'buf, 'ctf: 'buf> TypeInfo<'ctf> {
    /// Read the type directly at the address provided.
    /// Wrapper types will be unwrapped if present. TODO
    pub fn from_addr<Ctx: ParseCtx<'ctf>>(ctx: &Ctx, ty: CtfType<'ctf>, addr: u64) -> Result<Self> {
        let vec = ctx.proc().read_type(ctx, addr, ty)?;
        let buf = vec.into_boxed_slice();

        Ok(Self { ty, addr, buf })
    }

    pub fn as_ref(&'buf self) -> TypeInfoRef<'buf, 'ctf> {
        self.into()
    }

    /// Refresh the contents of the buffer from `Proc` memory from the current
    /// address.
    pub fn refresh<Ctx: ParseCtx<'ctf>>(&mut self, ctx: &Ctx) -> Result<()> {
        let vec = ctx.proc().read_type(ctx, self.addr, self.ty)?;
        let buf = vec.into_boxed_slice();

        self.buf = buf;
        Ok(())
    }

    pub fn try_member(&'buf self, name: &str) -> Result<Option<TypeInfoRef<'buf, 'ctf>>> {
        self.as_ref().try_member(name)
    }

    pub fn member(&'buf self, name: &str) -> Result<TypeInfoRef<'buf, 'ctf>> {
        self.as_ref().member(name)
    }

    pub fn try_deref_ptr<Ctx: ParseCtx<'ctf>>(&self, ctx: &Ctx) -> Result<Option<TypeInfo<'ctf>>> {
        self.as_ref().try_deref_ptr(ctx)
    }

    pub fn deref_ptr<Ctx: ParseCtx<'ctf>>(&self, ctx: &Ctx) -> Result<TypeInfo<'ctf>> {
        self.as_ref().deref_ptr(ctx)
    }

    pub fn try_select_variant(&'buf self, name: &str) -> Result<Option<TypeInfoRef<'buf, 'ctf>>> {
        self.as_ref().try_select_variant(name)
    }

    pub fn select_variant(&'buf self, name: &str) -> Result<TypeInfoRef<'buf, 'ctf>> {
        self.as_ref().select_variant(name)
    }

    pub fn array_elements(&'buf self) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>> {
        array_elements(self.ty, self.addr, &self.buf)
    }

    pub fn parse<T, Ctx>(&self, ctx: &Ctx) -> Result<T>
    where
        T: ParseWithCtf<'ctf, Ctx>,
        Ctx: ParseCtx<'ctf>,
    {
        self.as_ref().parse(ctx)
    }

    pub fn box2<Ctx: ParseCtx<'ctf>>(
        &'buf self,
        ctx: &Ctx,
    ) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>>
    where
        'ctf: 'buf,
    {
        boxed_slice_elements(&self, ctx)
    }

    /// Parse the elements of a boxed slice, returning them in a Vec.
    pub fn boxed_slice_elements<T, Ctx, F>(&self, ctx: &Ctx, mut f: F) -> Result<()>
    where
        F: FnMut(&TypeInfoRef<'_, '_>) -> Result<()>,
        Ctx: ParseCtx<'ctf>,
    {
        let proc = ctx.proc();

        let len: u64 = self.member("length")?.parse(ctx)?;
        let ptr = self.member("data_ptr")?;
        let Some(pointer) = self.ty.as_pointer() else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                self.ty.name().to_string(),
            ));
        };

        let param_ty = pointer.target();
        let elem_size = param_ty.size();

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size();

        let raw = proc.read_bytes(ctx, p, total_len)?;

        for (i, chunk) in raw.chunks(elem_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: p + (i as u64) * elem_size,
                bytes: chunk,
            }
            .peel();
            f(&item_info)?;
        }

        Ok(())
    }
}

impl<'buf, 'ctf: 'buf> From<TypeInfoRef<'buf, 'ctf>> for TypeInfo<'ctf> {
    #[inline]
    fn from(TypeInfoRef { ty, addr, bytes }: TypeInfoRef<'buf, 'ctf>) -> Self {
        Self {
            ty,
            addr,
            buf: bytes.to_vec().into_boxed_slice(),
        }
    }
}

impl fmt::Debug for TypeInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeInfo")
            .field("ty", &format_args!("TypeId({})", self.ty.id().get()))
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("buf", &self.buf)
            .finish()
    }
}

#[derive(Clone)]
pub struct TypeInfoRef<'buf, 'ctf: 'buf> {
    pub ty: CtfType<'ctf>,
    pub addr: u64,
    pub bytes: &'buf [u8],
}

impl Eq for TypeInfoRef<'_, '_> {}

impl PartialEq for TypeInfoRef<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        self.ty == other.ty && self.addr == other.addr && self.bytes == other.bytes
    }
}

impl<'buf, 'ctf: 'buf> TypeInfoRef<'buf, 'ctf> {
    pub fn try_member(&self, name: &str) -> Result<Option<TypeInfoRef<'buf, 'ctf>>> {
        let Some(member) = self.ty.member(name) else {
            return Ok(None);
        };
        let ty = member.ty();

        let start = member.offset() as u16;
        let end = start + ty.size() as u16;
        let Some(bytes) = self.bytes.get(start as usize..end as usize) else {
            let len = self.bytes.len() as u16;
            return Err(Error::invalid_member_range(start, end, len));
        };
        let addr = self.addr + member.offset();

        Ok(Some(TypeInfoRef { ty, addr, bytes }.peel()))
    }

    pub fn member(&self, name: &str) -> Result<TypeInfoRef<'buf, 'ctf>> {
        let Some(member) = self.try_member(name)? else {
            return Err(Error::no_member(self.ty.id(), name.to_string()));
        };

        Ok(member)
    }

    pub fn try_deref_ptr<Ctx: ParseCtx<'ctf>>(&self, ctx: &Ctx) -> Result<Option<TypeInfo<'ctf>>> {
        let proc = ctx.proc();

        let peeled = self.clone().peel();
        let Some(ptr_ty) = peeled.ty.as_pointer() else {
            return Err(Error::unexpected_type(
                self.ty.kind(),
                TypeKind::Pointer,
                format!("{} ({:?})", self.ty.name(), self.ty.id()),
            ));
        };
        let target_ty = ptr_ty.target();

        let Some(&bytes) = self.bytes.first_chunk::<8>() else {
            return Err(Error::unexpected_len(self.bytes.len() as u32, 8));
        };

        let addr = u64::from_le_bytes(bytes);
        let Ok(vec) = proc.read_type(ctx, addr, target_ty) else {
            // TODO return an error?
            return Ok(None);
        };
        let buf = vec.into_boxed_slice();

        // Remove any wrapper types.
        let unwrapped = TypeInfoRef {
            ty: target_ty,
            addr,
            bytes: &buf,
        }
        .peel();

        Ok(Some(TypeInfo {
            ty: unwrapped.ty,
            addr,
            buf,
        }))
    }

    pub fn deref_ptr<Ctx: ParseCtx<'ctf>>(&self, ctx: &Ctx) -> Result<TypeInfo<'ctf>> {
        match self.try_deref_ptr(ctx) {
            Ok(Some(i)) => Ok(i),
            Ok(None) => Err(Error::invalid_addr(self.addr)),
            Err(e) => Err(Error::invalid_addr(self.addr).with_source(e)),
        }
    }

    pub fn is_enum(&self) -> bool {
        self.member("__discr").ok().is_some()
    }

    pub fn try_select_variant(&self, name: &str) -> Result<Option<TypeInfoRef<'buf, 'ctf>>> {
        let (discrim_value, discrim_ty) = self.read_discriminant()?;

        let Some(variants_member) = self.ty.member("__variants") else {
            return Err(Error::no_member(self.ty.id(), "__variants".to_string()));
        };
        let variants = variants_member.ty();

        // In niche-optimized enums only one enumerator will be defined, with two
        // possible variants.
        let is_niche_optimized =
            variants.members().len() == 2 && discrim_ty.enumerators().len() == 1;

        // Find the enumerator whose name matches our expected value. It is common
        // common for our expected name to be missing due to niche-optimized enums.
        let enumerator = discrim_ty.enumerators().find(|e| e.name() == name);

        match (enumerator, is_niche_optimized) {
            (Some(e), _) => {
                if e.value() != discrim_value {
                    return Ok(None);
                }
            }
            (None, true) => {
                // The single defined enumerator for a niche-optimized enum matches
                // the discriminant, but we're looking for an undefined variant. We
                // can deduce that we've hit the variant we don't want.
                if discrim_value == discrim_ty.enumerators().nth(0).unwrap().value() {
                    return Ok(None);
                }
            }
            (None, false) => {
                // Not a niche-optimized enum, so each variant should have a
                // matching enumerator, but we didn't find it. User error.
                return Err(Error::no_enumerator(variants.id(), name.to_string()));
            }
        }

        let Some(selected_variant) = variants.member(name) else {
            return Err(Error::no_member(self.ty.id(), name.to_string()));
        };
        let ty = selected_variant.ty();

        let start = selected_variant.offset() as u16;
        let end = start + ty.size() as u16;
        let Some(bytes) = self.bytes.get(start as usize..end as usize) else {
            let len = self.bytes.len() as u16;
            return Err(Error::invalid_member_range(start, end, len));
        };
        let addr = self.addr + selected_variant.offset();

        Ok(Some(TypeInfoRef { ty, addr, bytes }.peel()))
    }

    pub fn select_variant(&self, name: &str) -> Result<TypeInfoRef<'buf, 'ctf>> {
        let Some(info) = self.try_select_variant(name)? else {
            return Err(Error::unexpected_variant(name.to_string()));
        };

        Ok(info)
    }

    pub fn parse<T: ParseWithCtf<'ctf, Ctx>, Ctx: ParseCtx<'ctf>>(&self, ctx: &Ctx) -> Result<T> {
        T::parse_with_ctf(ctx, &self).map_err(|e| Error::parse_type(self.ty.name()).with_source(e))
    }

    pub fn to_owned(&self) -> TypeInfo<'ctf> {
        self.clone().into()
    }

    pub fn with_ty(mut self, ty: CtfType<'ctf>) -> TypeInfoRef<'buf, 'ctf> {
        self.ty = ty;
        self
    }

    pub fn with_addr(mut self, addr: u64) -> TypeInfoRef<'buf, 'ctf> {
        self.addr = addr;
        self
    }

    pub fn with_buf(mut self, buf: &'buf [u8]) -> TypeInfoRef<'buf, 'ctf> {
        self.bytes = &buf;
        self
    }

    /// Get an iterator of `TypeInfoRef`s over the elements of an array.
    pub fn array_elements(&self) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>> {
        array_elements(self.ty, self.addr, self.bytes)
    }

    /// Pass the `TypeInfoRef` of the elements of a boxed slice to the provided closure.
    pub fn boxed_slice_elements<T, Ctx, F>(&self, ctx: &Ctx, mut f: F) -> Result<Vec<T>>
    where
        F: FnMut(&TypeInfoRef<'_, '_>) -> Result<T>,
        Ctx: ParseCtx<'ctf>,
    {
        let proc = ctx.proc();

        let len: u64 = self.member("length")?.parse(ctx)?;
        let ptr = self.member("data_ptr")?;
        let Some(ptr_ty) = ptr.ty.as_pointer() else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                self.ty.name().to_string(),
            ));
        };
        let param_ty = ptr_ty.target();
        let elem_size = param_ty.size();

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size();

        let mut out = Vec::with_capacity(len as usize);
        let raw = proc.read_bytes(ctx, p, total_len)?;

        for (i, chunk) in raw.chunks(elem_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: p + (i as u64) * elem_size,
                bytes: chunk,
            }
            .peel();
            let item = f(&item_info)?;
            out.push(item);
        }

        Ok(out)
    }

    pub fn active_variant(&'buf self) -> Result<(&'ctf str, TypeInfoRef<'buf, 'ctf>)> {
        let (discrim, discrim_ty) = self.read_discriminant()?;

        let Some(variants_member) = self.ty.member("__variants") else {
            return Err(Error::no_member(self.ty.id(), "__variants".to_string()));
        };
        let variants = variants_member.ty();

        // In niche-optimized enums only one enumerator will be defined, with two
        // possible variants.
        let is_niche_optimized =
            variants.members().len() == 2 && discrim_ty.enumerators().len() == 1;

        // Find the enumerator whose name matches our expected value. It is common
        // common for our expected name to be missing due to niche-optimized enums.
        let enumerator = discrim_ty.enumerators().find(|e| e.value() == discrim);

        let name = match (enumerator, is_niche_optimized) {
            (Some(e), _) => e.name(),
            (None, true) => {
                // UNWRAP: We know there are only two variants as this is
                // niche-optimized, so the one that doesn't match the only
                // enumerator must be active.
                let var = variants
                    .members()
                    .find(|m| m.name() != discrim_ty.enumerators().nth(0).unwrap().name())
                    .unwrap();
                var.name()
            }
            (None, false) => {
                // Not a niche-optimized enum, so each variant should have a
                // matching enumerator, but we didn't find it. The discriminant
                // value is incorrect.
                return Err(Error::invalid_discriminant_value(self.ty.id(), discrim));
            }
        };

        let Some(selected_variant) = variants.member(name) else {
            return Err(Error::no_member(self.ty.id(), name.to_string()));
        };
        let ty = selected_variant.ty();

        let start = selected_variant.offset() as u16;
        let end = start + ty.size() as u16;
        let Some(bytes) = self.bytes.get(start as usize..end as usize) else {
            let len = self.bytes.len() as u16;
            return Err(Error::invalid_member_range(start, end, len));
        };
        let addr = self.addr + selected_variant.offset();

        Ok((name, TypeInfoRef { ty, addr, bytes }.peel()))
    }

    /// Check if the type is a wrapper struct, and return its inner type is it
    /// is. This are defined as a struct with only a single sized member. The
    /// buffer will be adjusted if the member is smaller than the parent
    /// struct.
    pub fn peel(self) -> TypeInfoRef<'buf, 'ctf> {
        let mut info = self;

        loop {
            if info.ty.kind() != TypeKind::Struct {
                break;
            }

            let members = info.ty.members();

            // Zero-sized struct members have no impact on memory layout
            // and can be ignored. Check if there is only one sized member, and
            // peel to it if yes.
            let mut iter = members.map(|m| (m, m.ty())).filter(|(_m, t)| t.size() > 0);

            let (member, mem_ty) = match (iter.next(), iter.next()) {
                (Some((member, mem_ty)), None) => (member, mem_ty),
                _ => break,
            };

            let start = member.offset() as usize;
            let end = start + mem_ty.size() as usize;

            // TODO VALIDATE AHEAD OF TIME
            info.bytes = info.bytes.get(start..end).unwrap();
            info.ty = mem_ty;
        }

        info
    }

    fn read_discriminant(&self) -> Result<(i64, CtfEnum<'ctf>)> {
        let size = self.ty.size();
        if self.bytes.len() < size as usize {
            return Err(Error::unexpected_len(self.bytes.len() as u32, size as u32));
        }

        let Some(discriminant) = self.ty.member("__discr") else {
            return Err(Error::no_member(self.ty.id(), "__discr".to_string()));
        };

        let discr_enum = discriminant.ty();
        let Some(discr_ty) = discr_enum.as_enum() else {
            return Err(Error::unexpected_type(
                self.ty.kind(),
                TypeKind::Enum,
                format!("{} ({:?})", self.ty.name(), self.ty.id()),
            ));
        };
        let offset = discriminant.offset() as usize;
        let discrim_value = match discr_enum.size() {
            1 => self.bytes[offset] as i64,
            2 => i16::from_le_bytes(*self.bytes[offset..].first_chunk::<2>().unwrap()) as i64,
            4 => i32::from_le_bytes(*self.bytes[offset..].first_chunk::<4>().unwrap()) as i64,
            8 => i64::from_le_bytes(*self.bytes[offset..].first_chunk::<8>().unwrap()),
            _ => unreachable!(), // validated during parsing
        };
        Ok((discrim_value, discr_ty))
    }
}

impl fmt::Debug for TypeInfoRef<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeInfoRef")
            .field("ty", &format_args!("TypeId({})", self.ty.id().get()))
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl fmt::Display for TypeInfoRef<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(f, self, 0, 16)
    }
}

impl fmt::Display for TypeInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_ref(), f)
    }
}

pub struct DisplayValue<'a, 'buf, 'ctf: 'buf> {
    info: &'a TypeInfoRef<'buf, 'ctf>,
    depth: usize,
    max_depth: usize,
}

impl fmt::Display for DisplayValue<'_, '_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(f, self.info, self.depth, self.max_depth)
    }
}

impl<'buf, 'ctf: 'buf> TypeInfoRef<'buf, 'ctf> {
    pub fn display(&self) -> DisplayValue<'_, 'buf, 'ctf> {
        DisplayValue {
            info: self,
            depth: 0,
            max_depth: 8,
        }
    }

    pub fn display_with_depth(&self, max_depth: usize) -> DisplayValue<'_, 'buf, 'ctf> {
        DisplayValue {
            info: self,
            depth: 0,
            max_depth,
        }
    }
}

/// Wrapper that carries depth state for recursive formatting.
struct DisplayRecurse<'buf, 'ctf: 'buf> {
    info: TypeInfoRef<'buf, 'ctf>,
    depth: usize,
    max_depth: usize,
}

impl fmt::Display for DisplayRecurse<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(f, &self.info, self.depth, self.max_depth)
    }
}

fn write_display_value(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, '_>,
    depth: usize,
    max_depth: usize,
) -> fmt::Result {
    let ty = info.ty;
    let bytes = info.bytes;

    if bytes.is_empty() && ty.size() == 0 {
        return write!(f, "{}", ty.name());
    }

    if depth >= max_depth {
        return write!(f, "...");
    }

    if (bytes.len() as u64) < ty.size() {
        return write!(f, "<truncated>");
    }

    match ty {
        CtfType::Integer(int_ty) => {
            let enc = int_ty.encoding();
            let flags = enc.flags;
            let size = int_ty.size();

            if flags.is_bool() {
                return write!(f, "{}", bytes[0] != 0);
            }

            if flags.is_char() {
                let ch = bytes[0];
                return if ch.is_ascii_graphic() || ch == b' ' {
                    write!(f, "'{}'", ch as char)
                } else {
                    write!(f, "'\\x{:02x}'", ch)
                };
            }

            if flags.is_signed() {
                match size {
                    1 => write!(f, "{}", bytes[0] as i8),
                    2 => write!(f, "{}", i16::from_le_bytes(bytes[..2].try_into().unwrap())),
                    4 => write!(f, "{}", i32::from_le_bytes(bytes[..4].try_into().unwrap())),
                    8 => write!(f, "{}", i64::from_le_bytes(bytes[..8].try_into().unwrap())),
                    _ => write_hex_bytes(f, bytes),
                }
            } else {
                match size {
                    1 => write!(f, "{}", bytes[0]),
                    2 => write!(f, "{}", u16::from_le_bytes(bytes[..2].try_into().unwrap())),
                    4 => write!(f, "{}", u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                    8 => write!(f, "{}", u64::from_le_bytes(bytes[..8].try_into().unwrap())),
                    _ => write_hex_bytes(f, bytes),
                }
            }
        }

        CtfType::Float(float_ty) => match float_ty.size() {
            4 => write!(f, "{}", f32::from_le_bytes(bytes[..4].try_into().unwrap())),
            8 => write!(f, "{}", f64::from_le_bytes(bytes[..8].try_into().unwrap())),
            _ => write_hex_bytes(f, bytes),
        },

        CtfType::Pointer(_) => {
            if bytes.len() < 8 {
                return write!(f, "<truncated>");
            }
            let addr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if addr == 0 {
                write!(f, "null")
            } else {
                write!(f, "0x{:x}", addr)
            }
        }

        CtfType::Struct(_) => {
            let name = ty.name();
            let pretty = f.alternate();

            // Rust enum: has __discr member
            if ty.member("__discr").is_some() {
                return write_rust_enum(f, info, name, pretty, depth, max_depth);
            }

            // Regular struct
            write_struct_fields(f, info, name, pretty, depth, max_depth)
        }

        CtfType::Union(_) => {
            // Rust enum tagged union pattern (e.g. __tagged unions with
            // __discr + __variants).
            if ty.member("__discr").is_some() && ty.member("__variants").is_some() {
                let name = ty.name();
                let enum_name = name.strip_suffix("::__tagged").unwrap_or(name);
                let pretty = f.alternate();
                return write_rust_enum(f, info, enum_name, pretty, depth, max_depth);
            }

            let name = ty.name();
            if !name.is_empty() {
                write!(f, "{} ", name)?;
            }
            write!(f, "{{ ")?;
            write_hex_bytes(f, bytes)?;
            write!(f, " }}")
        }

        CtfType::Enum(enum_ty) => {
            let size = enum_ty.size();
            let discrim = match size {
                1 => bytes[0] as i64,
                2 => i16::from_le_bytes(bytes[..2].try_into().unwrap()) as i64,
                4 => i32::from_le_bytes(bytes[..4].try_into().unwrap()) as i64,
                8 => i64::from_le_bytes(bytes[..8].try_into().unwrap()),
                _ => return write_hex_bytes(f, bytes),
            };

            for e in enum_ty.enumerators() {
                if e.value() == discrim {
                    return write!(f, "{}", e.name());
                }
            }
            write!(f, "{}", discrim)
        }

        CtfType::Array(arr_ty) => {
            let elem_ty = arr_ty.element_type();
            let elem_size = elem_ty.size() as usize;
            let count = arr_ty.len() as usize;
            let pretty = f.alternate();

            write!(f, "[")?;
            for i in 0..count {
                let start = i * elem_size;
                let end = start + elem_size;
                if let Some(elem_bytes) = bytes.get(start..end) {
                    if pretty {
                        writeln!(f)?;
                        write_indent(f, depth + 1)?;
                    } else if i > 0 {
                        write!(f, ", ")?;
                    }

                    let child = DisplayRecurse {
                        info: TypeInfoRef {
                            ty: elem_ty,
                            addr: info.addr + start as u64,
                            bytes: elem_bytes,
                        },
                        depth: depth + 1,
                        max_depth,
                    };
                    if pretty {
                        write!(f, "{:#},", child)?;
                    } else {
                        write!(f, "{}", child)?;
                    }
                } else {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "<truncated>")?;
                    break;
                }
            }
            if pretty && count > 0 {
                writeln!(f)?;
                write_indent(f, depth)?;
            }
            write!(f, "]")
        }

        CtfType::Typedef(_) | CtfType::Volatile(_) | CtfType::Const(_) | CtfType::Restrict(_) => {
            if let Some(target) = ty.target() {
                let child = DisplayRecurse {
                    info: TypeInfoRef {
                        ty: target,
                        addr: info.addr,
                        bytes,
                    },
                    depth: depth + 1,
                    max_depth,
                };
                if f.alternate() {
                    write!(f, "{:#}", child)
                } else {
                    write!(f, "{}", child)
                }
            } else {
                let name = ty.name();
                if !name.is_empty() {
                    write!(f, "{} ", name)?;
                }
                write_hex_bytes(f, bytes)
            }
        }

        _ => {
            let name = ty.name();
            if !name.is_empty() {
                write!(f, "{} ", name)?;
            }
            write_hex_bytes(f, bytes)
        }
    }
}

fn write_struct_fields(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, '_>,
    name: &str,
    pretty: bool,
    depth: usize,
    max_depth: usize,
) -> fmt::Result {
    let members: Vec<_> = info.ty.members().filter(|m| m.ty().size() > 0).collect();

    if !name.is_empty() {
        write!(f, "{}", name)?;
    }
    write!(f, " {{")?;

    for (i, member) in members.iter().enumerate() {
        let mem_ty = member.ty();
        let start = member.offset() as usize;
        let end = start + mem_ty.size() as usize;

        if pretty {
            writeln!(f)?;
            write_indent(f, depth + 1)?;
        } else if i > 0 {
            write!(f, ",")?;
        }
        write!(f, " {}: ", member.name())?;

        if let Some(mem_bytes) = info.bytes.get(start..end) {
            let child = DisplayRecurse {
                info: TypeInfoRef {
                    ty: mem_ty,
                    addr: info.addr + member.offset(),
                    bytes: mem_bytes,
                },
                depth: depth + 1,
                max_depth,
            };
            if pretty {
                write!(f, "{:#}", child)?;
            } else {
                write!(f, "{}", child)?;
            }
        } else {
            write!(f, "<truncated>")?;
        }

        if pretty {
            write!(f, ",")?;
        }
    }

    if pretty {
        writeln!(f)?;
        write_indent(f, depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

fn write_rust_enum(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, '_>,
    name: &str,
    pretty: bool,
    depth: usize,
    max_depth: usize,
) -> fmt::Result {
    // Resolve variant without peeling so we preserve the full struct for
    // display (active_variant calls .peel() which collapses wrapper structs
    // and can land on inner tagged unions, losing structural info).
    let Ok((discrim, discrim_ty)) = info.read_discriminant() else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };

    let Some(variants_member) = info.ty.member("__variants") else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };
    let variants = variants_member.ty();

    let is_niche_optimized = variants.members().len() == 2 && discrim_ty.enumerators().len() == 1;

    let enumerator = discrim_ty.enumerators().find(|e| e.value() == discrim);

    write!(f, "{name} ")?;
    let variant_name = match (enumerator, is_niche_optimized) {
        (Some(e), _) => e.name(),
        (None, true) => {
            let Some(var) = variants
                .members()
                .find(|m| m.name() != discrim_ty.enumerators().nth(0).unwrap().name())
            else {
                if !name.is_empty() {
                    write!(f, "{} ", name)?;
                }
                return Ok(()); // write_hex_bytes(f, info.bytes);
            };
            var.name()
        }
        (None, false) => {
            if !name.is_empty() {
                write!(f, "{} ", name)?;
            }
            return Ok(()); // write_hex_bytes(f, info.bytes);
        }
    };

    let Some(selected_variant) = variants.member(variant_name) else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };
    let variant_ty = selected_variant.ty();
    let start = selected_variant.offset() as usize;
    let end = start + variant_ty.size() as usize;
    let Some(variant_bytes) = info.bytes.get(start..end) else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };
    let variant_addr = info.addr + selected_variant.offset();
    // NOTE: no .peel() — we keep the variant struct intact for display.
    let variant_info = TypeInfoRef {
        ty: variant_ty,
        addr: variant_addr,
        bytes: variant_bytes,
    }
    .peel();

    if !name.is_empty() {
        write!(f, "{}::", name)?;
    }
    write!(f, "{}", variant_name)?;

    // Zero-sized variant (unit variant)
    if variant_ty.size() == 0 {
        return Ok(());
    }

    let members: Vec<_> = variant_info
        .ty
        .members()
        .filter(|m| m.ty().size() > 0)
        .collect();

    if members.is_empty() {
        return Ok(());
    }

    write!(f, " {{")?;
    for (i, member) in members.iter().enumerate() {
        let mem_ty = member.ty();
        let mem_start = member.offset() as usize;
        let mem_end = mem_start + mem_ty.size() as usize;

        if pretty {
            writeln!(f)?;
            write_indent(f, depth + 1)?;
        } else if i > 0 {
            write!(f, ",")?;
        }
        write!(f, " {}: ", member.name())?;

        if let Some(mem_bytes) = variant_info.bytes.get(mem_start..mem_end) {
            let child = DisplayRecurse {
                info: TypeInfoRef {
                    ty: mem_ty,
                    addr: variant_info.addr + member.offset(),
                    bytes: mem_bytes,
                },
                depth: depth + 1,
                max_depth,
            };
            if pretty {
                write!(f, "{:#}", child)?;
            } else {
                write!(f, "{}", child)?;
            }
        } else {
            write!(f, "<truncated>")?;
        }

        if pretty {
            write!(f, ",")?;
        }
    }

    if pretty {
        writeln!(f)?;
        write_indent(f, depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

fn write_indent(f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    for _ in 0..depth {
        write!(f, "    ")?;
    }
    Ok(())
}

fn write_hex_bytes(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    write!(f, "[")?;
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            write!(f, ", ")?;
        }
        write!(f, "0x{:02x}", b)?;
    }
    write!(f, "]")
}

impl<'buf, 'ctf: 'buf> From<&'buf TypeInfo<'ctf>> for TypeInfoRef<'buf, 'ctf> {
    #[inline]
    fn from(TypeInfo { ty, addr, buf }: &'buf TypeInfo<'ctf>) -> Self {
        Self {
            ty: *ty,
            addr: *addr,
            bytes: &buf,
        }
    }
}

pub trait ParseCtx<'ctf> {
    fn ctf(&self) -> &CtfView<'ctf>;
    fn proc(&self) -> &'ctf Proc;
    fn mappings(&self) -> &Mappings;
}

/// Parse a byte slice as a type using CTF.
pub trait ParseWithCtf<'ctf, Ctx>: Sized
where
    Ctx: ParseCtx<'ctf>,
{
    /// Attempt to read `Self` from the CTF type information.
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self>;
}

impl<'ctf, Ctx: ParseCtx<'ctf>> ParseWithCtf<'ctf, Ctx> for u8 {
    fn parse_with_ctf(_ctx: &Ctx, info: &TypeInfoRef) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0])
    }
}

impl<'ctf, Ctx: ParseCtx<'ctf>> ParseWithCtf<'ctf, Ctx> for i8 {
    fn parse_with_ctf(_ctx: &Ctx, info: &TypeInfoRef) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0] as i8)
    }
}

impl<'ctf, Ctx: ParseCtx<'ctf>> ParseWithCtf<'ctf, Ctx> for bool {
    fn parse_with_ctf(_ctx: &Ctx, info: &TypeInfoRef) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0] == 1)
    }
}

macro_rules! ctf_num_impl {
    ($num_ty:ty) => {
        impl<'ctf, Ctx: ParseCtx<'ctf>> ParseWithCtf<'ctf, Ctx> for $num_ty {
            fn parse_with_ctf(_ctx: &Ctx, info: &TypeInfoRef) -> Result<Self> {
                if info.bytes.len() != size_of::<Self>() {
                    return Err(Error::unexpected_len(
                        info.bytes.len() as u32,
                        size_of::<Self>() as u32,
                    ));
                }
                Ok(Self::from_le_bytes(info.bytes.try_into().unwrap()))
            }
        }
    };
}
ctf_num_impl!(u16);
ctf_num_impl!(u32);
ctf_num_impl!(u64);
ctf_num_impl!(i16);
ctf_num_impl!(i32);
ctf_num_impl!(i64);
ctf_num_impl!(f32);
ctf_num_impl!(f64);

impl<'ctf, T, Ctx> ParseWithCtf<'ctf, Ctx> for Option<T>
where
    T: ParseWithCtf<'ctf, Ctx>,
    Ctx: ParseCtx<'ctf>,
{
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        let var = info.active_variant()?;
        let value = match var {
            ("Some", var_info) => T::parse_with_ctf(ctx, &var_info)?,
            ("None", _) => return Ok(None),
            (s, _) => {
                return Err(Error::no_enumerator(info.ty.id(), s.to_string()));
            }
        };

        Ok(Some(value))
    }
}

impl<'ctf, T, Ctx> ParseWithCtf<'ctf, Ctx> for Vec<T>
where
    T: ParseWithCtf<'ctf, Ctx>,
    Ctx: ParseCtx<'ctf>,
{
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        let proc = ctx.proc();

        let len: u64 = info.member("len")?.parse(ctx)?;
        if len == 0 {
            return Ok(Vec::new());
        }

        let param_member = info.ty.member("__type_param_T").unwrap();
        let param_ty = param_member.ty();
        let param_size = param_ty.size();

        let ptr = info.member("buf")?.member("ptr")?;

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size();

        let raw = proc.read_bytes(ctx, p, total_len)?;
        let mut out = Vec::with_capacity(len as usize);
        for (i, chunk) in raw.chunks(param_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: info.addr + (i as u64) * param_size,
                bytes: chunk,
            };
            let item = T::parse_with_ctf(ctx, &item_info)?;
            out.push(item);
        }

        Ok(out)
    }
}

impl<'ctf, T, Ctx> ParseWithCtf<'ctf, Ctx> for Box<[T]>
where
    T: ParseWithCtf<'ctf, Ctx>,
    Ctx: ParseCtx<'ctf>,
{
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        let proc = ctx.proc();

        let len: u64 = info.member("length")?.parse(ctx)?;
        let ptr = info.member("data_ptr")?;
        let Some(ptr_ty) = ptr.ty.as_pointer() else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                info.ty.name().to_string(),
            ));
        };
        let param_ty = ptr_ty.target();
        let param_size = param_ty.size();

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size();

        let raw = proc.read_bytes(ctx, p, total_len)?;
        let mut out = Vec::with_capacity(len as usize);
        for (i, chunk) in raw.chunks(param_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: info.addr + (i as u64) * param_size,
                bytes: chunk,
            };
            let item = T::parse_with_ctf(ctx, &item_info)?;
            out.push(item);
        }

        Ok(out.into_boxed_slice())
    }
}

impl<'ctf, T, Ctx, const N: usize> ParseWithCtf<'ctf, Ctx> for [T; N]
where
    T: ParseWithCtf<'ctf, Ctx>,
    Ctx: ParseCtx<'ctf>,
{
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        let Some(array_ty) = info.ty.as_array() else {
            return Err(Error::unexpected_type(
                info.ty.kind(),
                TypeKind::Array,
                info.ty.name().to_string(),
            ));
        };

        let elem_ty = array_ty.element_type();
        let size = elem_ty.size() as usize;
        let len = array_ty.len() as usize;

        let mut items = Vec::with_capacity(len);
        for (i, slice) in info.bytes.chunks(size).enumerate() {
            let slice_info = TypeInfoRef {
                ty: elem_ty,
                addr: info.addr + (i * size) as u64,
                bytes: slice,
            };
            let item = T::parse_with_ctf(ctx, &slice_info)?;
            items.push(item);
        }
        let Ok(arr) = items.try_into() else {
            unreachable!();
        };
        Ok(arr)
    }
}

impl<'ctf, Ctx: ParseCtx<'ctf>> ParseWithCtf<'ctf, Ctx> for String {
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        let proc = ctx.proc();

        let len: u64 = info.member("length")?.parse(ctx)?;
        let ptr: u64 = info.member("data_ptr")?.parse(ctx)?;
        let data = proc.read_bytes(ctx, ptr, len)?;

        let out = String::from_utf8_lossy(&data).to_string();

        Ok(out)
    }
}

// Split this into a free function to fix lifetime issues from calling
// `TypeInfoRef` methods from `TypeInfo`.
fn array_elements<'buf, 'ctf: 'buf>(
    ty: CtfType<'ctf>,
    addr: u64,
    bytes: &'buf [u8],
) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>> {
    let Some(array) = ty.as_array() else {
        return Err(Error::unexpected_type(
            ty.kind(),
            TypeKind::Array,
            ty.name().to_string(),
        ));
    };

    let elem_size = array.element_type().size() as usize;
    let iter = bytes
        .chunks_exact(elem_size)
        .enumerate()
        .map(move |(i, chunk)| {
            TypeInfoRef {
                ty: array.element_type(),
                addr: addr + (i * elem_size) as u64,
                bytes: chunk,
            }
            .peel()
        });
    Ok(iter)
}

/// Parse the elements of a boxed slice, returning them in a Vec.
fn boxed_slice_elements<'buf, 'ctf: 'buf, Ctx: ParseCtx<'ctf>>(
    ptr_info: &'buf TypeInfo<'ctf>,
    _ctx: &Ctx, //TODO REMOVE ME
) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>> {
    // todo check len?
    let elem_size = ptr_info.ty.size();
    let iter = ptr_info
        .buf
        .chunks(elem_size as usize)
        .enumerate()
        .map(move |(i, chunk)| {
            TypeInfoRef {
                ty: ptr_info.ty,
                addr: ptr_info.addr + (i as u64) * elem_size,
                bytes: chunk,
            }
            .peel()
        });
    Ok(iter)
}

pub trait ReadFromProc<'ctf, Ctx>
where
    Ctx: ParseCtx<'ctf>,
{
    /// Read the size of the provided type at address, returning None if the
    /// address is unmapped.
    fn read_type(&self, ctx: &Ctx, addr: u64, ty: CtfType<'ctf>) -> Result<Vec<u8>>;

    /// Read `len` bytes at address, returning None if the address is unmapped.
    fn read_bytes(&self, ctx: &Ctx, addr: u64, len: u64) -> Result<Vec<u8>>;
}

impl<'ctf, Ctx> ReadFromProc<'ctf, Ctx> for Proc
where
    Ctx: ParseCtx<'ctf>,
{
    fn read_type(&self, ctx: &Ctx, addr: u64, ty: CtfType<'ctf>) -> Result<Vec<u8>> {
        self.read_bytes(ctx, addr, ty.size() as u64)
    }

    fn read_bytes(&self, _ctx: &Ctx, addr: u64, len: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];

        // TODO we may also receive an EOF here, need better error
        self.pread_exact(&mut buf, addr)
            .map_err(|e| Error::invalid_addr(addr).with_source(e))?;
        Ok(buf)
    }
}

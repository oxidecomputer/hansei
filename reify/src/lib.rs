pub mod debug_type;

pub use debug_type::TypeKind;
use debug_type::{DebugFormat, DebugMember, DebugType, KnownFormat, TypeClass};

use proc::Mappings;

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::str;

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
    #[error("invalid discriminant value {discrim} for type {ty}")]
    InvalidDiscriminantValue { ty: String, discrim: i64 },
    #[error("unable to read member at range {start}..{end} from buf with len {len}")]
    InvalidMemberRange { start: u16, end: u16, len: u16 },
    #[error("enumerator {enum_name} not found for type {ty}")]
    NoEnumerator { ty: String, enum_name: String },
    #[error("member {member_name} not found for type {ty}")]
    NoMember { ty: String, member_name: String },
    #[error("attempted to dereference invalid address {addr:#x}")]
    InvalidAddr { addr: u64 },
    #[error("failed to parse type {0}")]
    ParseType(String),
    #[error("data length {actual} is does not match expected {expected} length")]
    UnexpectedLen { actual: u32, expected: u32 },
    #[error("expected a {expected} but found a {actual} when parsing {name}")]
    UnexpectedType {
        actual: TypeKind,
        expected: TypeKind,
        name: String,
    },
    #[error("expected enum variant {expected} was not active")]
    UnexpectedVariant { expected: String },
    #[error("{0} is not an enum type")]
    NotAnEnum(String),
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

    pub fn invalid_discriminant_value(ty: String, discrim: i64) -> Self {
        Self::new(ErrorKind::InvalidDiscriminantValue { ty, discrim })
    }

    pub fn invalid_member_range(start: u16, end: u16, len: u16) -> Self {
        Self::new(ErrorKind::InvalidMemberRange { start, end, len })
    }

    pub fn no_enumerator(ty: String, enum_name: String) -> Self {
        Self::new(ErrorKind::NoEnumerator { ty, enum_name })
    }

    pub fn no_member(ty: String, member_name: String) -> Self {
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

    pub fn not_an_enum(ty: String) -> Self {
        Self::new(ErrorKind::NotAnEnum(ty))
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

// ---------------------------------------------------------------------------
// TypeInfo — owned typed buffer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TypeInfo<'a, T: DebugType<'a>> {
    pub ty: T,
    pub addr: u64,
    pub buf: Box<[u8]>,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'buf, 'a: 'buf, T: DebugType<'a>> TypeInfo<'a, T> {
    /// Read the type directly at the address provided.
    pub fn from_addr<Ctx: ParseCtx>(ctx: &Ctx, ty: T, addr: u64) -> Result<Self> {
        let vec = ctx.proc().read_bytes(addr, ty.size())?;
        let buf = vec.into_boxed_slice();

        Ok(Self {
            ty,
            addr,
            buf,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn as_ref(&'buf self) -> TypeInfoRef<'buf, 'a, T> {
        self.into()
    }

    /// Refresh the contents of the buffer from `Proc` memory from the current
    /// address.
    pub fn refresh<Ctx: ParseCtx>(&mut self, ctx: &Ctx) -> Result<()> {
        let vec = ctx.proc().read_bytes(self.addr, self.ty.size())?;
        let buf = vec.into_boxed_slice();

        self.buf = buf;
        Ok(())
    }

    pub fn try_member(&'buf self, name: &str) -> Result<Option<TypeInfoRef<'buf, 'a, T>>> {
        self.as_ref().try_member(name)
    }

    pub fn member(&'buf self, name: &str) -> Result<TypeInfoRef<'buf, 'a, T>> {
        self.as_ref().member(name)
    }

    pub fn try_deref_ptr<Ctx: ParseCtx>(&self, ctx: &Ctx) -> Result<Option<TypeInfo<'a, T>>> {
        self.as_ref().try_deref_ptr(ctx)
    }

    pub fn deref_ptr<Ctx: ParseCtx>(&self, ctx: &Ctx) -> Result<TypeInfo<'a, T>> {
        self.as_ref().deref_ptr(ctx)
    }

    pub fn try_select_variant(&'buf self, name: &str) -> Result<Option<TypeInfoRef<'buf, 'a, T>>> {
        self.as_ref().try_select_variant(name)
    }

    pub fn select_variant(&'buf self, name: &str) -> Result<TypeInfoRef<'buf, 'a, T>> {
        self.as_ref().select_variant(name)
    }

    pub fn array_elements(&'buf self) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'a, T>>> {
        array_elements(self.ty, self.addr, &self.buf)
    }

    pub fn parse<V, Ctx>(&self, ctx: &Ctx) -> Result<V>
    where
        V: ParseWithCtf<'a, T, Ctx>,
        Ctx: ParseCtx,
    {
        self.as_ref().parse(ctx)
    }

    pub fn box2<Ctx: ParseCtx>(
        &'buf self,
        ctx: &Ctx,
    ) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'a, T>>>
    where
        'a: 'buf,
    {
        boxed_slice_elements(self, ctx)
    }

    /// Pass the elements of a boxed slice to the provided closure.
    pub fn boxed_slice_elements<Ctx, F>(&self, ctx: &Ctx, mut f: F) -> Result<()>
    where
        F: FnMut(&TypeInfoRef<'_, 'a, T>) -> Result<()>,
        Ctx: ParseCtx,
    {
        let proc = ctx.proc();

        let len: u64 = self.member("length")?.parse(ctx)?;
        let ptr = self.member("data_ptr")?;
        let Some(param_ty) = ptr.ty.pointer_target() else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                self.ty.name().to_string(),
            ));
        };

        let elem_size = param_ty.size();

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size();

        let raw = proc.read_bytes(p, total_len)?;

        for (i, chunk) in raw.chunks(elem_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: p + (i as u64) * elem_size,
                bytes: chunk,
                _marker: std::marker::PhantomData,
            }
            .peel();
            f(&item_info)?;
        }

        Ok(())
    }
}

impl<'buf, 'a: 'buf, T: DebugType<'a>> From<TypeInfoRef<'buf, 'a, T>> for TypeInfo<'a, T> {
    #[inline]
    fn from(
        TypeInfoRef {
            ty, addr, bytes, ..
        }: TypeInfoRef<'buf, 'a, T>,
    ) -> Self {
        Self {
            ty,
            addr,
            buf: bytes.to_vec().into_boxed_slice(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, T: DebugType<'a>> fmt::Debug for TypeInfo<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeInfo")
            .field("ty", &self.ty)
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("buf", &self.buf)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TypeInfoRef — borrowed typed buffer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TypeInfoRef<'buf, 'a: 'buf, T: DebugType<'a>> {
    pub ty: T,
    pub addr: u64,
    pub bytes: &'buf [u8],
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'buf, 'a: 'buf, T: DebugType<'a> + PartialEq> Eq for TypeInfoRef<'buf, 'a, T> {}

impl<'buf, 'a: 'buf, T: DebugType<'a> + PartialEq> PartialEq for TypeInfoRef<'buf, 'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.ty == other.ty && self.addr == other.addr && self.bytes == other.bytes
    }
}

impl<'buf, 'a: 'buf, T: DebugType<'a>> TypeInfoRef<'buf, 'a, T> {
    /// Wrap an already-read buffer. Useful when the bytes come from
    /// somewhere other than a live target (tests, snapshots).
    pub fn new(ty: T, addr: u64, bytes: &'buf [u8]) -> Self {
        Self {
            ty,
            addr,
            bytes,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn try_member(&self, name: &str) -> Result<Option<TypeInfoRef<'buf, 'a, T>>> {
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

        Ok(Some(
            TypeInfoRef {
                ty,
                addr,
                bytes,
                _marker: std::marker::PhantomData,
            }
            .peel(),
        ))
    }

    pub fn member(&self, name: &str) -> Result<TypeInfoRef<'buf, 'a, T>> {
        let Some(member) = self.try_member(name)? else {
            return Err(Error::no_member(
                self.ty.name().to_string(),
                name.to_string(),
            ));
        };

        Ok(member)
    }

    pub fn try_deref_ptr<Ctx: ParseCtx>(&self, ctx: &Ctx) -> Result<Option<TypeInfo<'a, T>>> {
        let proc = ctx.proc();

        let peeled = self.clone().peel();
        let Some(target_ty) = peeled.ty.pointer_target() else {
            return Err(Error::unexpected_type(
                self.ty.kind(),
                TypeKind::Pointer,
                format!("{} ({:?})", self.ty.name(), self.ty),
            ));
        };

        let Some(&bytes) = self.bytes.first_chunk::<8>() else {
            return Err(Error::unexpected_len(self.bytes.len() as u32, 8));
        };

        let addr = u64::from_le_bytes(bytes);
        let Ok(vec) = proc.read_bytes(addr, target_ty.size()) else {
            // TODO return an error?
            return Ok(None);
        };
        let buf = vec.into_boxed_slice();

        // Remove any wrapper types.
        let unwrapped = TypeInfoRef {
            ty: target_ty,
            addr,
            bytes: &buf,
            _marker: std::marker::PhantomData,
        }
        .peel();

        Ok(Some(TypeInfo {
            ty: unwrapped.ty,
            addr,
            buf,
            _marker: std::marker::PhantomData,
        }))
    }

    pub fn deref_ptr<Ctx: ParseCtx>(&self, ctx: &Ctx) -> Result<TypeInfo<'a, T>> {
        match self.try_deref_ptr(ctx) {
            Ok(Some(i)) => Ok(i),
            Ok(None) => Err(Error::invalid_addr(self.addr)),
            Err(e) => Err(Error::invalid_addr(self.addr).with_source(e)),
        }
    }

    pub fn is_enum(&self) -> bool {
        self.ty.active_variant(self.bytes).is_some()
    }

    pub fn try_select_variant(&self, name: &str) -> Result<Option<TypeInfoRef<'buf, 'a, T>>> {
        let Some(result) = self.ty.check_variant(self.bytes, name) else {
            return Err(Error::not_an_enum(self.ty.name().to_string()));
        };
        let Some((var_ty, offset)) = result? else {
            return Ok(None);
        };

        let start = offset as u16;
        let end = start + var_ty.size() as u16;
        let Some(bytes) = self.bytes.get(start as usize..end as usize) else {
            let len = self.bytes.len() as u16;
            return Err(Error::invalid_member_range(start, end, len));
        };
        let addr = self.addr + offset;

        Ok(Some(
            TypeInfoRef {
                ty: var_ty,
                addr,
                bytes,
                _marker: std::marker::PhantomData,
            }
            .peel(),
        ))
    }

    pub fn select_variant(&self, name: &str) -> Result<TypeInfoRef<'buf, 'a, T>> {
        let Some(info) = self.try_select_variant(name)? else {
            return Err(Error::unexpected_variant(name.to_string()));
        };

        Ok(info)
    }

    pub fn parse<V: ParseWithCtf<'a, T, Ctx>, Ctx: ParseCtx>(&self, ctx: &Ctx) -> Result<V> {
        V::parse_with_ctf(ctx, self).map_err(|e| Error::parse_type(self.ty.name()).with_source(e))
    }

    pub fn to_owned(&self) -> TypeInfo<'a, T> {
        self.clone().into()
    }

    pub fn with_ty(mut self, ty: T) -> TypeInfoRef<'buf, 'a, T> {
        self.ty = ty;
        self
    }

    pub fn with_addr(mut self, addr: u64) -> TypeInfoRef<'buf, 'a, T> {
        self.addr = addr;
        self
    }

    pub fn with_buf(mut self, buf: &'buf [u8]) -> TypeInfoRef<'buf, 'a, T> {
        self.bytes = buf;
        self
    }

    /// Get an iterator of `TypeInfoRef`s over the elements of an array.
    pub fn array_elements(&self) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'a, T>>> {
        array_elements(self.ty, self.addr, self.bytes)
    }

    /// Pass the `TypeInfoRef` of the elements of a boxed slice to the
    /// provided closure.
    pub fn boxed_slice_elements<V, Ctx, F>(&self, ctx: &Ctx, mut f: F) -> Result<Vec<V>>
    where
        F: FnMut(&TypeInfoRef<'_, 'a, T>) -> Result<V>,
        Ctx: ParseCtx,
    {
        let proc = ctx.proc();

        let len: u64 = self.member("length")?.parse(ctx)?;
        let ptr = self.member("data_ptr")?;
        let Some(param_ty) = ptr.ty.pointer_target() else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                self.ty.name().to_string(),
            ));
        };
        let elem_size = param_ty.size();

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size();

        let mut out = Vec::with_capacity(len as usize);
        let raw = proc.read_bytes(p, total_len)?;

        for (i, chunk) in raw.chunks(elem_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: p + (i as u64) * elem_size,
                bytes: chunk,
                _marker: std::marker::PhantomData,
            }
            .peel();
            let item = f(&item_info)?;
            out.push(item);
        }

        Ok(out)
    }

    pub fn active_variant(&'buf self) -> Result<(&'a str, TypeInfoRef<'buf, 'a, T>)> {
        let (name, var_ty, offset) = self
            .ty
            .active_variant(self.bytes)
            .ok_or_else(|| Error::not_an_enum(self.ty.name().to_string()))??;

        let start = offset as usize;
        let end = start + var_ty.size() as usize;
        let Some(bytes) = self.bytes.get(start..end) else {
            let len = self.bytes.len() as u16;
            return Err(Error::invalid_member_range(start as u16, end as u16, len));
        };
        let addr = self.addr + offset;

        Ok((
            name,
            TypeInfoRef {
                ty: var_ty,
                addr,
                bytes,
                _marker: std::marker::PhantomData,
            }
            .peel(),
        ))
    }

    /// Check if the type is a wrapper struct, and return its inner type if it
    /// is. These are defined as a struct with only a single sized member. The
    /// buffer will be adjusted if the member is smaller than the parent
    /// struct.
    pub fn peel(self) -> TypeInfoRef<'buf, 'a, T> {
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
            info.addr += start as u64;
            info.ty = mem_ty;
        }

        info
    }
}

impl<'buf, 'a: 'buf, T: DebugType<'a>> From<&'buf TypeInfo<'a, T>> for TypeInfoRef<'buf, 'a, T> {
    #[inline]
    fn from(TypeInfo { ty, addr, buf, .. }: &'buf TypeInfo<'a, T>) -> Self {
        Self {
            ty: *ty,
            addr: *addr,
            bytes: buf,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, T: DebugType<'a>> fmt::Debug for TypeInfoRef<'_, 'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeInfoRef")
            .field("ty", &self.ty)
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("bytes", &self.bytes)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl<'a, T: DebugType<'a>> fmt::Display for TypeInfoRef<'_, 'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(f, self, 0, 16, None, None, false)
    }
}

impl<'a, T: DebugType<'a>> fmt::Display for TypeInfo<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_ref(), f)
    }
}

pub struct DisplayValue<'r, 'buf, 'a: 'buf, T: DebugType<'a>> {
    info: &'r TypeInfoRef<'buf, 'a, T>,
    depth: usize,
    max_depth: usize,
}

impl<'a, T: DebugType<'a>> fmt::Display for DisplayValue<'_, '_, 'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(f, self.info, self.depth, self.max_depth, None, None, false)
    }
}

pub struct DisplayTargetValue<'r, 'buf, 'a: 'buf, T: DebugType<'a>, P: ReadFromProc> {
    info: &'r TypeInfoRef<'buf, 'a, T>,
    proc: &'r P,
    max_depth: usize,
    visited: RefCell<HashSet<(u64, &'a str)>>,
}

impl<'a, T: DebugType<'a>, P: ReadFromProc> fmt::Display for DisplayTargetValue<'_, '_, 'a, T, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(
            f,
            self.info,
            0,
            self.max_depth,
            Some(self.proc),
            Some(&self.visited),
            false,
        )
    }
}

impl<'buf, 'a: 'buf, T: DebugType<'a>> TypeInfoRef<'buf, 'a, T> {
    pub fn display(&self) -> DisplayValue<'_, 'buf, 'a, T> {
        DisplayValue {
            info: self,
            depth: 0,
            max_depth: 8,
        }
    }

    pub fn display_with_depth(&self, max_depth: usize) -> DisplayValue<'_, 'buf, 'a, T> {
        DisplayValue {
            info: self,
            depth: 0,
            max_depth,
        }
    }

    /// Format this value while recursively reading typed pointees from a
    /// target. Pointer traversal consumes one level of the depth budget.
    pub fn display_from_target<'r, P: ReadFromProc>(
        &'r self,
        proc: &'r P,
        max_depth: usize,
    ) -> DisplayTargetValue<'r, 'buf, 'a, T, P> {
        DisplayTargetValue {
            info: self,
            proc,
            max_depth,
            visited: RefCell::new(HashSet::new()),
        }
    }
}

/// Wrapper that carries depth state for recursive formatting.
struct DisplayRecurse<'buf, 'a: 'buf, T: DebugType<'a>> {
    info: TypeInfoRef<'buf, 'a, T>,
    depth: usize,
    max_depth: usize,
    proc: Option<&'buf dyn ReadFromProc>,
    visited: Option<&'buf RefCell<HashSet<(u64, &'a str)>>>,
    hex_integers: bool,
}

impl<'a, T: DebugType<'a>> fmt::Display for DisplayRecurse<'_, 'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(
            f,
            &self.info,
            self.depth,
            self.max_depth,
            self.proc,
            self.visited,
            self.hex_integers,
        )
    }
}

fn write_display_value<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    depth: usize,
    max_depth: usize,
    proc: Option<&dyn ReadFromProc>,
    visited: Option<&RefCell<HashSet<(u64, &'a str)>>>,
    hex_integers: bool,
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

    if let Some(format) = ty.debug_format() {
        if let DebugFormat::Known(KnownFormat::FunctionPointer) = format {
            return write_function_pointer(f, info.bytes, proc);
        }
        if let DebugFormat::Known(KnownFormat::DynPointer {
            pointer_offset,
            vtable,
            vtable_offset,
            drop_in_place,
            size,
            align,
            tail_offset,
        }) = format
        {
            return write_dyn_pointer(
                f,
                info,
                Some(ty.name()),
                pointer_offset,
                vtable,
                vtable_offset,
                drop_in_place,
                size,
                align,
                tail_offset,
                depth,
                max_depth,
                proc,
                visited,
                hex_integers,
            );
        }
        if let DebugFormat::Known(KnownFormat::RawWakerVTable {
            clone_offset,
            wake_offset,
            wake_by_ref_offset,
            drop_offset,
        }) = format
        {
            return write_raw_waker_vtable(
                f,
                info,
                clone_offset,
                wake_offset,
                wake_by_ref_offset,
                drop_offset,
                depth,
                proc,
            );
        }
        if let DebugFormat::Known(KnownFormat::RawMutex { state_offset }) = format {
            return write_raw_mutex(f, ty.name(), info.bytes, state_offset);
        }
        if let DebugFormat::Known(KnownFormat::Notify { state_member, state_offset }) = format {
            return write_notify(
                f,
                info,
                ty.name(),
                state_member,
                state_offset,
                depth,
                max_depth,
                proc,
                visited,
                hex_integers,
            );
        }
        if let DebugFormat::Known(KnownFormat::IpAddress { octets, offset }) = format {
            let Some(bytes) = byte_range(bytes, offset, octets.size()) else {
                return write!(f, "<truncated>");
            };
            return match <&[u8; 4]>::try_from(bytes) {
                Ok(octets) => write!(f, "{}", std::net::Ipv4Addr::from(*octets)),
                Err(_) => match <&[u8; 16]>::try_from(bytes) {
                    Ok(octets) => write!(f, "{}", std::net::Ipv6Addr::from(*octets)),
                    Err(_) => write!(f, "<invalid IP address layout>"),
                },
            };
        }
        if let DebugFormat::Known(format @ KnownFormat::Vec { .. }) = format {
            return write_vec(
                f,
                info,
                format,
                depth,
                max_depth,
                proc,
                visited,
            );
        }
        if let DebugFormat::Known(KnownFormat::Str {
            pointer_offset,
            length,
            length_offset,
        }) = format
        {
            return write_utf8_string(
                f,
                info.bytes,
                pointer_offset,
                length,
                length_offset,
                None,
                proc,
            );
        }
        if let DebugFormat::Known(KnownFormat::String {
            pointer_offset,
            length,
            length_offset,
            capacity,
            capacity_offset,
        }) = format
        {
            return write_utf8_string(
                f,
                info.bytes,
                pointer_offset,
                length,
                length_offset,
                Some((capacity, capacity_offset)),
                proc,
            );
        }
        if let DebugFormat::Known(format @ KnownFormat::BTreeMap { .. }) = format {
            return write_btree_map(
                f,
                info,
                format,
                depth,
                max_depth,
                proc,
                visited,
                hex_integers,
            );
        }

        let (target, offset, child_proc, child_visited) = match format {
            DebugFormat::Transparent { target, offset } => (target, offset, proc, visited),
            DebugFormat::Known(KnownFormat::Atomic { value, offset }) => {
                // AtomicPtr's Debug implementation reports the stored
                // address; it does not dereference it.
                (value, offset, None, None)
            }
            DebugFormat::Known(KnownFormat::FunctionPointer) => unreachable!(),
            DebugFormat::Known(KnownFormat::DynPointer { .. }) => unreachable!(),
            DebugFormat::Known(KnownFormat::RawWakerVTable { .. }) => unreachable!(),
            DebugFormat::Known(KnownFormat::RawMutex { .. }) => unreachable!(),
            DebugFormat::Known(KnownFormat::Notify { .. }) => unreachable!(),
            DebugFormat::Known(KnownFormat::IpAddress { .. }) => unreachable!(),
            DebugFormat::Known(KnownFormat::Vec { .. }) => unreachable!(),
            DebugFormat::Known(KnownFormat::Str { .. }) => unreachable!(),
            DebugFormat::Known(KnownFormat::String { .. }) => unreachable!(),
            DebugFormat::Known(KnownFormat::BTreeMap { .. }) => unreachable!(),
        };
        let start = offset as usize;
        let Some(end) = start.checked_add(target.size() as usize) else {
            return write!(f, "<truncated>");
        };
        let Some(child_bytes) = bytes.get(start..end) else {
            return write!(f, "<truncated>");
        };
        let child = DisplayRecurse {
            info: TypeInfoRef {
                ty: target,
                addr: info.addr + offset,
                bytes: child_bytes,
                _marker: std::marker::PhantomData,
            },
            // Eliding a representation detail does not consume the user's
            // value-depth budget.
            depth,
            max_depth,
            proc: child_proc,
            visited: child_visited,
            hex_integers,
        };
        return if f.alternate() { write!(f, "{child:#}") } else { write!(f, "{child}") };
    }

    match ty.classify() {
        TypeClass::Integer {
            size,
            is_signed,
            is_bool,
            is_char,
        } => {
            if is_bool {
                return write!(f, "{}", bytes[0] != 0);
            }

            if is_char {
                let ch = bytes[0];
                return if ch.is_ascii_graphic() || ch == b' ' {
                    write!(f, "'{}'", ch as char)
                } else {
                    write!(f, "'\\x{:02x}'", ch)
                };
            }

            if hex_integers {
                return match size {
                    1 => write!(f, "0x{:02x}", bytes[0]),
                    2 => write!(
                        f,
                        "0x{:04x}",
                        u16::from_le_bytes(bytes[..2].try_into().unwrap())
                    ),
                    4 => write!(
                        f,
                        "0x{:08x}",
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    ),
                    8 => write!(
                        f,
                        "0x{:016x}",
                        u64::from_le_bytes(bytes[..8].try_into().unwrap())
                    ),
                    _ => write_hex_bytes(f, bytes),
                };
            }

            if is_signed {
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

        TypeClass::Float { size } => match size {
            4 => write!(f, "{}", f32::from_le_bytes(bytes[..4].try_into().unwrap())),
            8 => write!(f, "{}", f64::from_le_bytes(bytes[..8].try_into().unwrap())),
            _ => write_hex_bytes(f, bytes),
        },

        TypeClass::Pointer { target } => {
            if bytes.len() < 8 {
                return write!(f, "<truncated>");
            }
            let addr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if addr == 0 {
                return write!(f, "null");
            }
            // A pointer to a zero-sized type (e.g. `RawWaker`'s `*const ()`
            // data pointer) has no meaningful pointee to follow — reading it
            // would only ever print the type's name (`-> ()`). Show just the
            // address.
            if target.size() == 0 {
                return write!(f, "0x{addr:x}");
            }
            let (Some(proc), Some(visited)) = (proc, visited) else {
                return write!(f, "0x{addr:x}");
            };
            let key = (addr, target.name());
            if !visited.borrow_mut().insert(key) {
                return write!(f, "0x{addr:x} -> <cycle>");
            }
            let result = match proc.read_bytes(addr, target.size()) {
                Ok(pointee_bytes) => {
                    let pointee = DisplayRecurse {
                        info: TypeInfoRef {
                            ty: target,
                            addr,
                            bytes: &pointee_bytes,
                            _marker: std::marker::PhantomData,
                        },
                        depth: depth + 1,
                        max_depth,
                        proc: Some(proc),
                        visited: Some(visited),
                        hex_integers,
                    };
                    if f.alternate() {
                        write!(f, "0x{addr:x} -> {pointee:#}")
                    } else {
                        write!(f, "0x{addr:x} -> {pointee}")
                    }
                }
                Err(_) => write!(f, "0x{addr:x} -> <unreadable>"),
            };
            visited.borrow_mut().remove(&key);
            result
        }

        TypeClass::Struct => {
            let name = ty.name();
            let pretty = f.alternate();
            write_struct_fields(
                f,
                info,
                name,
                pretty,
                depth,
                max_depth,
                proc,
                visited,
                hex_integers,
                None,
            )
        }

        TypeClass::Union => {
            let name = ty.name();
            if !name.is_empty() {
                write!(f, "{} ", name)?;
            }
            write!(f, "{{ ")?;
            write_hex_bytes(f, bytes)?;
            write!(f, " }}")
        }

        TypeClass::RustEnum => {
            let name = ty.name();
            let pretty = f.alternate();
            write_rust_enum(
                f,
                info,
                name,
                pretty,
                depth,
                max_depth,
                proc,
                visited,
                hex_integers,
            )
        }

        TypeClass::CEnum => {
            // For C-style enums, try to find the active variant name.
            if let Some(Ok((name, _, _))) = ty.active_variant(bytes) {
                write!(f, "{}", name)
            } else {
                write_hex_bytes(f, bytes)
            }
        }

        TypeClass::Array { element, count } => {
            let elem_size = element.size() as usize;
            let count = count as usize;
            let pretty = f.alternate();
            let hex_elements = matches!(
                element.classify(),
                TypeClass::Integer {
                    is_bool: false,
                    is_char: false,
                    ..
                }
            );

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
                            ty: element,
                            addr: info.addr + start as u64,
                            bytes: elem_bytes,
                            _marker: std::marker::PhantomData,
                        },
                        depth: depth + 1,
                        max_depth,
                        proc,
                        visited,
                        hex_integers: hex_elements,
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

        TypeClass::Wrapper(inner) => {
            let child = DisplayRecurse {
                info: TypeInfoRef {
                    ty: inner,
                    addr: info.addr,
                    bytes,
                    _marker: std::marker::PhantomData,
                },
                depth: depth + 1,
                max_depth,
                proc,
                visited,
                hex_integers,
            };
            if f.alternate() {
                write!(f, "{:#}", child)
            } else {
                write!(f, "{}", child)
            }
        }

        TypeClass::Opaque => {
            let name = ty.name();
            if !name.is_empty() {
                write!(f, "{} ", name)?;
            }
            write_hex_bytes(f, bytes)
        }
    }
}

#[derive(Debug)]
struct VtableFunction {
    slot: u32,
    display: String,
    concrete: Option<String>,
}

/// Render a parking_lot `RawMutex` as its decoded lock state, e.g.
/// `parking_lot::raw_mutex::RawMutex (locked, parked)`. parking_lot uses a
/// fixed bit layout for the state byte.
fn write_raw_mutex(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    bytes: &[u8],
    state_offset: u64,
) -> fmt::Result {
    const LOCKED_BIT: u8 = 0b01;
    const PARKED_BIT: u8 = 0b10;

    let Some(&state) = bytes.get(state_offset as usize) else {
        return write!(f, "<truncated>");
    };
    write!(f, "{name} (")?;
    match (state & LOCKED_BIT != 0, state & PARKED_BIT != 0) {
        (false, false) => write!(f, "unlocked")?,
        (true, false) => write!(f, "locked")?,
        (false, true) => write!(f, "parked")?,
        (true, true) => write!(f, "locked, parked")?,
    }
    write!(f, ")")
}

/// Render a `tokio::sync::notify::Notify`, showing its `state` member as the
/// decoded notification state instead of a raw atomic word.
#[allow(clippy::too_many_arguments)]
fn write_notify<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    name: &str,
    state_member: u32,
    state_offset: u64,
    depth: usize,
    max_depth: usize,
    proc: Option<&dyn ReadFromProc>,
    visited: Option<&RefCell<HashSet<(u64, &'a str)>>>,
    hex_integers: bool,
) -> fmt::Result {
    let decoded = decode_notify_state(info.bytes, state_offset);
    let state_name = info.ty.members().nth(state_member as usize).map(|m| m.name());
    let override_field = state_name.map(|field| (field, decoded.as_str()));
    write_struct_fields(
        f,
        info,
        name,
        f.alternate(),
        depth,
        max_depth,
        proc,
        visited,
        hex_integers,
        override_field,
    )
}

/// Decode tokio's `Notify` state word: the low two bits are the notification
/// state and the rest counts `notify_waiters()` calls.
fn decode_notify_state(bytes: &[u8], state_offset: u64) -> String {
    let Some(raw) = read_u64_at(bytes, state_offset) else {
        return "<truncated>".to_string();
    };
    let state = match raw & 0b11 {
        0 => "idle",
        1 => "waiting",
        2 => "notified",
        _ => "<invalid>",
    };
    match raw >> 2 {
        0 => state.to_string(),
        1 => format!("{state} (1 notify_waiters call)"),
        calls => format!("{state} ({calls} notify_waiters calls)"),
    }
}

fn write_function_pointer(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    proc: Option<&dyn ReadFromProc>,
) -> fmt::Result {
    let Some(address) = read_u64_at(bytes, 0) else {
        return write!(f, "<truncated>");
    };
    if address == 0 {
        return write!(f, "null");
    }
    write!(f, "0x{address:x}")?;
    if let Some(symbol) = resolve_function_symbol(proc, address) {
        write!(f, " -> {symbol}")?;
    } else if proc.is_some() {
        write!(f, " -> <unknown symbol>")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_raw_waker_vtable<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    clone_offset: u64,
    wake_offset: u64,
    wake_by_ref_offset: u64,
    drop_offset: u64,
    depth: usize,
    proc: Option<&dyn ReadFromProc>,
) -> fmt::Result {
    let fields = [
        ("clone", clone_offset),
        ("wake", wake_offset),
        ("wake_by_ref", wake_by_ref_offset),
        ("drop", drop_offset),
    ];
    let pretty = f.alternate();
    write!(f, "{} {{", info.ty.name())?;
    for (index, (name, offset)) in fields.into_iter().enumerate() {
        if pretty {
            writeln!(f)?;
            write_indent(f, depth + 1)?;
        } else if index == 0 {
            write!(f, " ")?;
        } else {
            write!(f, ", ")?;
        }
        write!(f, "{name}: ")?;
        if let Some(address) = read_u64_at(info.bytes, offset) {
            write!(f, "0x{address:x}")?;
            if let Some(symbol) = resolve_function_symbol(proc, address) {
                write!(f, " -> {symbol}")?;
            } else if proc.is_some() && address != 0 {
                write!(f, " -> <unknown symbol>")?;
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

fn write_utf8_string<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    pointer_offset: u64,
    length: T,
    length_offset: u64,
    capacity: Option<(T, u64)>,
    proc: Option<&dyn ReadFromProc>,
) -> fmt::Result {
    let Some(len) = read_unsigned_at(bytes, length_offset, length.size()) else {
        return write!(f, "<truncated string length>");
    };
    if let Some((capacity, offset)) = capacity {
        let Some(capacity) = read_unsigned_at(bytes, offset, capacity.size()) else {
            return write!(f, "<truncated String capacity>");
        };
        if len > capacity {
            return write!(f, "<invalid String: length exceeds capacity>");
        }
    }
    if len == 0 {
        return write!(f, "\"\"");
    }
    let Some(pointer) = read_u64_at(bytes, pointer_offset) else {
        return write!(f, "<truncated string pointer>");
    };
    if pointer == 0 {
        return write!(f, "<invalid string: null data pointer>");
    }
    let Some(proc) = proc else {
        return write!(f, "<target unavailable>");
    };
    let Ok(bytes) = proc.read_bytes(pointer, len) else {
        return write!(f, "<unreadable string data>");
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return write!(f, "<invalid UTF-8 string>");
    };
    write!(f, "{text:?}")
}

#[allow(clippy::too_many_arguments)]
fn write_vec<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    format: KnownFormat<T>,
    depth: usize,
    max_depth: usize,
    proc: Option<&dyn ReadFromProc>,
    visited: Option<&RefCell<HashSet<(u64, &'a str)>>>,
) -> fmt::Result {
    let KnownFormat::Vec {
        pointer_offset,
        length,
        length_offset,
        capacity,
        capacity_offset,
        element,
    } = format
    else {
        unreachable!()
    };

    let Some(len) = read_unsigned_at(info.bytes, length_offset, length.size()) else {
        return write!(f, "<truncated Vec length>");
    };
    let Some(capacity) = read_unsigned_at(info.bytes, capacity_offset, capacity.size()) else {
        return write!(f, "<truncated Vec capacity>");
    };
    let element_size = element.size();
    if element_size != 0 && len > capacity {
        return write!(f, "<invalid Vec: length exceeds capacity>");
    }
    if len == 0 {
        return write!(f, "[]");
    }
    let Some(pointer) = read_u64_at(info.bytes, pointer_offset) else {
        return write!(f, "<truncated Vec pointer>");
    };

    let allocation;
    if element_size == 0 {
        allocation = Vec::new();
    } else {
        if pointer == 0 {
            return write!(f, "<invalid Vec: null allocation pointer>");
        }
        let Some(byte_len) = len.checked_mul(element_size) else {
            return write!(f, "<invalid Vec: allocation size overflow>");
        };
        let Some(proc) = proc else {
            return write!(f, "<target unavailable>");
        };
        let Ok(bytes) = proc.read_bytes(pointer, byte_len) else {
            return write!(f, "<unreadable Vec allocation>");
        };
        allocation = bytes;
    }

    let pretty = f.alternate();
    write!(f, "[")?;
    for index in 0..len {
        if pretty {
            writeln!(f)?;
            write_indent(f, depth + 1)?;
        } else if index != 0 {
            write!(f, ", ")?;
        }
        let Some(offset) = index.checked_mul(element_size) else {
            return write!(f, "<invalid element offset>");
        };
        let Some(bytes) = byte_range(&allocation, offset, element_size) else {
            return write!(f, "<truncated element>");
        };
        let Some(address) = pointer.checked_add(offset) else {
            return write!(f, "<invalid element address>");
        };
        let child = DisplayRecurse {
            info: TypeInfoRef {
                ty: element,
                addr: address,
                bytes,
                _marker: std::marker::PhantomData,
            },
            depth: depth + 1,
            max_depth,
            proc,
            visited,
            hex_integers: false,
        };
        if pretty {
            write!(f, "{child:#},")?;
        } else {
            write!(f, "{child}")?;
        }
    }
    if pretty {
        writeln!(f)?;
        write_indent(f, depth)?;
    }
    write!(f, "]")
}

#[derive(Copy, Clone)]
struct BTreeNodeLayout<T> {
    key: T,
    value: T,
    leaf: T,
    leaf_len: T,
    leaf_len_offset: u64,
    keys_offset: u64,
    key_slots: u64,
    values_offset: u64,
    internal: T,
    edges_offset: u64,
    edge: T,
    edge_pointer_offset: u64,
}

enum BTreeWalkError {
    Format,
    Invalid(&'static str),
}

impl From<fmt::Error> for BTreeWalkError {
    fn from(_: fmt::Error) -> Self {
        Self::Format
    }
}

#[allow(clippy::too_many_arguments)]
fn write_btree_map<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    format: KnownFormat<T>,
    depth: usize,
    max_depth: usize,
    proc: Option<&dyn ReadFromProc>,
    visited: Option<&RefCell<HashSet<(u64, &'a str)>>>,
    hex_integers: bool,
) -> fmt::Result {
    let KnownFormat::BTreeMap {
        root,
        root_offset,
        root_node,
        root_node_offset,
        length,
        length_offset,
        height,
        height_offset,
        node_offset,
        key,
        value,
        leaf,
        leaf_len,
        leaf_len_offset,
        keys_offset,
        key_slots,
        values_offset,
        internal,
        edges_offset,
        edge,
        edge_pointer_offset,
    } = format
    else {
        unreachable!()
    };

    let Some(map_length) = read_unsigned_at(info.bytes, length_offset, length.size()) else {
        return write!(f, "<truncated>");
    };
    let pretty = f.alternate();
    write!(f, "{} {{", info.ty.name())?;
    if map_length == 0 {
        return write!(f, "}}");
    }

    let root_start = root_offset as usize;
    let Some(root_end) = root_start.checked_add(root.size() as usize) else {
        return write!(f, " <invalid root> }}");
    };
    let Some(root_bytes) = info.bytes.get(root_start..root_end) else {
        return write!(f, " <truncated root> }}");
    };
    if !matches!(root.check_variant(root_bytes, "Some"), Some(Ok(Some(_)))) {
        return write!(f, " <invalid missing root> }}");
    }

    let root_node_start = root_node_offset as usize;
    let Some(root_node_end) = root_node_start.checked_add(root_node.size() as usize) else {
        return write!(f, " <invalid root node> }}");
    };
    let Some(root_node_bytes) = info.bytes.get(root_node_start..root_node_end) else {
        return write!(f, " <truncated root node> }}");
    };
    let Some(height) = read_unsigned_at(root_node_bytes, height_offset, height.size()) else {
        return write!(f, " <truncated height> }}");
    };
    let Some(root_address) = read_u64_at(root_node_bytes, node_offset) else {
        return write!(f, " <truncated node pointer> }}");
    };
    let Some(proc) = proc else {
        return write!(f, " <target unavailable> }}");
    };

    let layout = BTreeNodeLayout {
        key,
        value,
        leaf,
        leaf_len,
        leaf_len_offset,
        keys_offset,
        key_slots,
        values_offset,
        internal,
        edges_offset,
        edge,
        edge_pointer_offset,
    };
    let mut remaining = map_length;
    let mut node_addresses = HashSet::new();
    let mut entries = 0usize;
    let walk = walk_btree_node(
        proc,
        layout,
        root_address,
        height,
        &mut remaining,
        &mut node_addresses,
        &mut |key_addr, key_bytes, value_addr, value_bytes| {
            write_btree_entry_prefix(f, pretty, depth, entries)?;
            entries += 1;
            let key = DisplayRecurse {
                info: TypeInfoRef {
                    ty: layout.key,
                    addr: key_addr,
                    bytes: key_bytes,
                    _marker: std::marker::PhantomData,
                },
                depth: depth + 1,
                max_depth,
                proc: Some(proc),
                visited,
                hex_integers,
            };
            let value = DisplayRecurse {
                info: TypeInfoRef {
                    ty: layout.value,
                    addr: value_addr,
                    bytes: value_bytes,
                    _marker: std::marker::PhantomData,
                },
                depth: depth + 1,
                max_depth,
                proc: Some(proc),
                visited,
                hex_integers,
            };
            if pretty {
                write!(f, "{key:#}: {value:#},")?;
            } else {
                write!(f, "{key}: {value}")?;
            }
            Ok(())
        },
    );

    match walk {
        Ok(()) if remaining == 0 => {}
        Ok(()) => {
            write_btree_entry_prefix(f, pretty, depth, entries)?;
            write!(f, "<invalid: tree contains fewer entries than length>")?;
        }
        Err(BTreeWalkError::Invalid(reason)) => {
            write_btree_entry_prefix(f, pretty, depth, entries)?;
            write!(f, "<invalid: {reason}>")?;
        }
        Err(BTreeWalkError::Format) => return Err(fmt::Error),
    }

    if pretty {
        writeln!(f)?;
        write_indent(f, depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

fn write_btree_entry_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
    entry: usize,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, depth + 1)
    } else if entry == 0 {
        write!(f, " ")
    } else {
        write!(f, ", ")
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_btree_node<'a, T: DebugType<'a>>(
    proc: &dyn ReadFromProc,
    layout: BTreeNodeLayout<T>,
    address: u64,
    height: u64,
    remaining: &mut u64,
    visited: &mut HashSet<u64>,
    emit: &mut impl FnMut(u64, &[u8], u64, &[u8]) -> fmt::Result,
) -> std::result::Result<(), BTreeWalkError> {
    if address == 0 {
        return Err(BTreeWalkError::Invalid("null node pointer"));
    }
    if height > 64 {
        return Err(BTreeWalkError::Invalid("implausible tree height"));
    }
    if !visited.insert(address) {
        return Err(BTreeWalkError::Invalid("node cycle"));
    }

    let result = (|| {
        let node_type = if height == 0 { layout.leaf } else { layout.internal };
        let bytes = proc
            .read_bytes(address, node_type.size())
            .map_err(|_| BTreeWalkError::Invalid("unreadable node"))?;
        let Some(len) = read_unsigned_at(&bytes, layout.leaf_len_offset, layout.leaf_len.size())
        else {
            return Err(BTreeWalkError::Invalid("truncated node length"));
        };
        if len > layout.key_slots {
            return Err(BTreeWalkError::Invalid("node length exceeds capacity"));
        }

        for index in 0..len {
            if height > 0 {
                let child = btree_edge_address(&bytes, layout, index)?;
                walk_btree_node(proc, layout, child, height - 1, remaining, visited, emit)?;
            }
            if *remaining == 0 {
                return Err(BTreeWalkError::Invalid("tree contains more entries than length"));
            }
            let key_start = layout
                .keys_offset
                .checked_add(index.checked_mul(layout.key.size()).ok_or(
                    BTreeWalkError::Invalid("key offset overflow"),
                )?)
                .ok_or(BTreeWalkError::Invalid("key offset overflow"))?;
            let value_start = layout
                .values_offset
                .checked_add(index.checked_mul(layout.value.size()).ok_or(
                    BTreeWalkError::Invalid("value offset overflow"),
                )?)
                .ok_or(BTreeWalkError::Invalid("value offset overflow"))?;
            let key_bytes = byte_range(&bytes, key_start, layout.key.size())
                .ok_or(BTreeWalkError::Invalid("truncated key slot"))?;
            let value_bytes = byte_range(&bytes, value_start, layout.value.size())
                .ok_or(BTreeWalkError::Invalid("truncated value slot"))?;
            emit(address + key_start, key_bytes, address + value_start, value_bytes)?;
            *remaining -= 1;
        }
        if height > 0 {
            let child = btree_edge_address(&bytes, layout, len)?;
            walk_btree_node(proc, layout, child, height - 1, remaining, visited, emit)?;
        }
        Ok(())
    })();
    visited.remove(&address);
    result
}

fn btree_edge_address<'a, T: DebugType<'a>>(
    bytes: &[u8],
    layout: BTreeNodeLayout<T>,
    index: u64,
) -> std::result::Result<u64, BTreeWalkError> {
    let offset = layout
        .edges_offset
        .checked_add(
            index
                .checked_mul(layout.edge.size())
                .ok_or(BTreeWalkError::Invalid("edge offset overflow"))?,
        )
        .and_then(|offset| offset.checked_add(layout.edge_pointer_offset))
        .ok_or(BTreeWalkError::Invalid("edge offset overflow"))?;
    read_u64_at(bytes, offset).ok_or(BTreeWalkError::Invalid("truncated edge slot"))
}

fn byte_range(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    bytes.get(start..end)
}

fn read_unsigned_at(bytes: &[u8], offset: u64, size: u64) -> Option<u64> {
    let bytes = byte_range(bytes, offset, size)?;
    Some(match size {
        1 => u64::from(bytes[0]),
        2 => u64::from(u16::from_le_bytes(bytes.try_into().ok()?)),
        4 => u64::from(u32::from_le_bytes(bytes.try_into().ok()?)),
        8 => u64::from_le_bytes(bytes.try_into().ok()?),
        _ => return None,
    })
}

#[allow(clippy::too_many_arguments)]
fn write_dyn_pointer<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    name: Option<&str>,
    pointer_offset: u64,
    vtable: T,
    vtable_offset: u64,
    drop_in_place_slot: u32,
    size_slot: u32,
    align_slot: u32,
    tail_offset: u64,
    depth: usize,
    max_depth: usize,
    proc: Option<&dyn ReadFromProc>,
    visited: Option<&RefCell<HashSet<(u64, &'a str)>>>,
    hex_integers: bool,
) -> fmt::Result {
    let Some(pointer_address) = read_u64_at(info.bytes, pointer_offset) else {
        return write!(f, "<truncated>");
    };
    let Some(vtable_address) = read_u64_at(info.bytes, vtable_offset) else {
        return write!(f, "<truncated>");
    };
    let words = read_vtable_words(vtable, vtable_address, proc);

    let mut functions = Vec::new();
    if let (Some(proc), Some(words)) = (proc, words.as_deref()) {
        for (slot, &address) in words.iter().enumerate() {
            let slot = slot as u32;
            if slot == size_slot || slot == align_slot || address == 0 {
                continue;
            }
            let Some(display) = resolve_function_symbol(Some(proc), address) else {
                continue;
            };
            let concrete = exegesis::symbols::concrete_type_from_vtable_symbol(&display)
                .map(str::to_owned);
            functions.push(VtableFunction { slot, display, concrete });
        }
    }

    let concrete = infer_concrete_type(info.ty, words.as_deref(), size_slot, &functions);
    let concrete_ty = concrete.as_deref().and_then(|name| info.ty.type_by_name(name));
    let pretty = f.alternate();
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        write!(f, "{name}")?;
    }
    write!(f, " {{")?;

    write_dyn_field_prefix(f, pretty, depth)?;
    write!(f, "pointer: 0x{pointer_address:x}")?;
    // The vtable resolves the erased *tail* type; when the pointer targets an
    // unsized wrapper (e.g. `ArcInner<dyn Trait>`) the value lives past a
    // sized header, so read the pointee at the tail offset, not the raw
    // pointer.
    let pointee_address = pointer_address.wrapping_add(tail_offset);
    // A zero-sized concrete type (e.g. slog's `()` list terminator) has no
    // pointee worth following — the `concrete type:` line below already names
    // it. Showing `-> ()` would only add noise.
    if let (Some(concrete_ty), Some(proc), Some(visited)) =
        (concrete_ty.filter(|ty| ty.size() > 0), proc, visited)
    {
        let key = (pointee_address, concrete_ty.name());
        if !visited.borrow_mut().insert(key) {
            write!(f, " -> <cycle>")?;
        } else {
            match proc.read_bytes(pointee_address, concrete_ty.size()) {
                Ok(pointee_bytes) => {
                    let pointee = DisplayRecurse {
                        info: TypeInfoRef {
                            ty: concrete_ty,
                            addr: pointee_address,
                            bytes: &pointee_bytes,
                            _marker: std::marker::PhantomData,
                        },
                        depth: depth + 1,
                        max_depth,
                        proc: Some(proc),
                        visited: Some(visited),
                        hex_integers,
                    };
                    if pretty {
                        write!(f, " -> {pointee:#}")?;
                    } else {
                        write!(f, " -> {pointee}")?;
                    }
                }
                Err(_) => write!(f, " -> <unreadable>")?,
            }
            visited.borrow_mut().remove(&key);
        }
    }
    write!(f, ",")?;
    write_dyn_field_prefix(f, pretty, depth)?;
    write!(f, "concrete type: {},", concrete.as_deref().unwrap_or("<unknown>"))?;
    write_dyn_field_prefix(f, pretty, depth)?;
    write!(f, "vtable: ")?;

    match words.as_deref() {
        Some(words) if depth + 1 < max_depth => {
            write!(f, "{{")?;
            write_vtable_field_prefix(f, pretty, depth)?;
            let drop_address = words.get(drop_in_place_slot as usize).copied().unwrap_or(0);
            write!(f, "drop_in_place: 0x{drop_address:x}")?;
            if let Some(function) = functions.iter().find(|function| function.slot == drop_in_place_slot)
            {
                write!(f, " -> {}", function.display)?;
            }
            write!(f, ",")?;

            write_vtable_field_prefix(f, pretty, depth)?;
            match words.get(size_slot as usize) {
                Some(size) => write!(f, "size: {size},")?,
                None => write!(f, "size: <unavailable>,")?,
            }
            write_vtable_field_prefix(f, pretty, depth)?;
            match words.get(align_slot as usize) {
                Some(align) => write!(f, "align: {align},")?,
                None => write!(f, "align: <unavailable>,")?,
            }

            for (slot, &address) in words.iter().enumerate() {
                let slot = slot as u32;
                if slot == drop_in_place_slot || slot == size_slot || slot == align_slot {
                    continue;
                }
                write_vtable_field_prefix(f, pretty, depth)?;
                if let Some(function) = functions.iter().find(|function| function.slot == slot) {
                    write!(f, "method[{slot}]: 0x{address:x} -> {},", function.display)?;
                } else {
                    write!(f, "entry[{slot}]: 0x{address:016x},")?;
                }
            }

            if pretty {
                writeln!(f)?;
                write_indent(f, depth + 1)?;
            } else {
                write!(f, " ")?;
            }
            write!(f, "}},")?;
        }
        Some(_) => write!(f, "0x{vtable_address:x} -> ...,")?,
        None if vtable_address == 0 => write!(f, "0x0,")?,
        None => write!(f, "0x{vtable_address:x} -> <unreadable>,")?,
    }

    if pretty {
        writeln!(f)?;
        write_indent(f, depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

fn resolve_function_symbol(proc: Option<&dyn ReadFromProc>, address: u64) -> Option<String> {
    if address == 0 {
        return None;
    }
    let symbol = proc?.function_symbol(address)?;
    let stripped = exegesis::bundle::strip_llvm_suffix(&symbol);
    Some(
        rustc_demangle::try_demangle(stripped)
            .map(|symbol| format!("{symbol:#}"))
            .unwrap_or_else(|_| stripped.to_owned()),
    )
}

fn write_dyn_field_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, depth + 1)
    } else {
        write!(f, " ")
    }
}

fn write_vtable_field_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, depth + 2)
    } else {
        write!(f, " ")
    }
}

fn read_u64_at(bytes: &[u8], offset: u64) -> Option<u64> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(start..end)?.try_into().ok()?))
}

fn read_vtable_words<'a, T: DebugType<'a>>(
    vtable: T,
    address: u64,
    proc: Option<&dyn ReadFromProc>,
) -> Option<Vec<u64>> {
    if address == 0 {
        return None;
    }
    let (element, count) = vtable.pointer_target()?.array_info()?;
    if element.size() != 8 {
        return None;
    }
    let byte_len = count.checked_mul(8)?;
    let bytes = proc?.read_bytes(address, byte_len).ok()?;
    if bytes.len() != byte_len as usize {
        return None;
    }
    Some(
        bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect(),
    )
}

fn infer_concrete_type<'a, T: DebugType<'a>>(
    ty: T,
    words: Option<&[u64]>,
    size_slot: u32,
    functions: &[VtableFunction],
) -> Option<String> {
    let mut concrete = functions.iter().filter_map(|function| function.concrete.as_deref());
    let candidate = concrete.next()?.to_owned();
    if concrete.any(|other| other != candidate) {
        return None;
    }
    if let (Some(expected), Some(actual)) =
        (ty.size_by_name(&candidate), words?.get(size_slot as usize).copied())
        && expected != actual
    {
        return None;
    }
    Some(candidate)
}

fn write_struct_fields<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    name: &str,
    pretty: bool,
    depth: usize,
    max_depth: usize,
    proc: Option<&dyn ReadFromProc>,
    visited: Option<&RefCell<HashSet<(u64, &'a str)>>>,
    hex_integers: bool,
    // When set, the named member is rendered as the given text rather than
    // recursing into its bytes — used to display a decoded field (e.g. a
    // `Notify`'s state) in place of its raw representation.
    override_field: Option<(&str, &str)>,
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

        if let Some((_, text)) = override_field.filter(|(field, _)| *field == member.name()) {
            write!(f, "{text}")?;
        } else if let Some(mem_bytes) = info.bytes.get(start..end) {
            let child = DisplayRecurse {
                info: TypeInfoRef {
                    ty: mem_ty,
                    addr: info.addr + member.offset(),
                    bytes: mem_bytes,
                    _marker: std::marker::PhantomData,
                },
                depth: depth + 1,
                max_depth,
                proc,
                visited,
                hex_integers,
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

fn write_rust_enum<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    name: &str,
    pretty: bool,
    depth: usize,
    max_depth: usize,
    proc: Option<&dyn ReadFromProc>,
    visited: Option<&RefCell<HashSet<(u64, &'a str)>>>,
    hex_integers: bool,
) -> fmt::Result {
    let Ok((variant_name, var_ty, offset)) = info
        .ty
        .active_variant(info.bytes)
        .unwrap_or_else(|| Err(Error::not_an_enum(name.to_string())))
    else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };

    let start = offset as usize;
    let end = start + var_ty.size() as usize;
    let Some(variant_bytes) = info.bytes.get(start..end) else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };
    let variant_addr = info.addr + offset;
    let variant_info = TypeInfoRef {
        ty: var_ty,
        addr: variant_addr,
        bytes: variant_bytes,
        _marker: std::marker::PhantomData,
    }
    .peel();

    if !name.is_empty() {
        write!(f, "{}::", name)?;
    }
    write!(f, "{}", variant_name)?;

    // Zero-sized variant (unit variant)
    if var_ty.size() == 0 {
        return Ok(());
    }

    if let Some(DebugFormat::Known(KnownFormat::DynPointer {
        pointer_offset,
        vtable,
        vtable_offset,
        drop_in_place,
        size,
        align,
        tail_offset,
    })) = variant_info.ty.debug_format()
    {
        return write_dyn_pointer(
            f,
            &variant_info,
            None,
            pointer_offset,
            vtable,
            vtable_offset,
            drop_in_place,
            size,
            align,
            tail_offset,
            depth,
            max_depth,
            proc,
            visited,
            hex_integers,
        );
    }

    // A payload carrying a semantic display format (a `&str`/`String`, a
    // `Vec`, an IP address, ...) should render as that value, not as its
    // raw representation fields. `Cow<str>::Borrowed("x")` reads far better
    // than `Borrowed { data_ptr: .., length: .. }`. Delegating to the value
    // formatter keeps this general across every known format (trait objects
    // are handled above, with their own layout).
    if variant_info.ty.debug_format().is_some() {
        let child = DisplayRecurse {
            info: variant_info,
            depth,
            max_depth,
            proc,
            visited,
            hex_integers,
        };
        write!(f, "(")?;
        if pretty {
            write!(f, "{child:#}")?;
        } else {
            write!(f, "{child}")?;
        }
        return write!(f, ")");
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
                    _marker: std::marker::PhantomData,
                },
                depth: depth + 1,
                max_depth,
                proc,
                visited,
                hex_integers,
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

// ---------------------------------------------------------------------------
// ParseCtx & ParseWithCtf
// ---------------------------------------------------------------------------

pub trait ParseCtx {
    /// The target being read: a live process or core on illumos, or a
    /// captured snapshot anywhere.
    type Target: ReadFromProc;

    fn proc(&self) -> &Self::Target;
    fn mappings(&self) -> &Mappings;
}

/// Parse a byte slice as a type using debug type information.
pub trait ParseWithCtf<'a, Ty: DebugType<'a>, Ctx>: Sized
where
    Ctx: ParseCtx,
{
    /// Attempt to read `Self` from the debug type information.
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self>;
}

impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithCtf<'a, Ty, Ctx> for u8 {
    fn parse_with_ctf(_ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0])
    }
}

impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithCtf<'a, Ty, Ctx> for i8 {
    fn parse_with_ctf(_ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0] as i8)
    }
}

impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithCtf<'a, Ty, Ctx> for bool {
    fn parse_with_ctf(_ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0] == 1)
    }
}

macro_rules! num_impl {
    ($num_ty:ty) => {
        impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithCtf<'a, Ty, Ctx> for $num_ty {
            fn parse_with_ctf(_ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
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
num_impl!(u16);
num_impl!(u32);
num_impl!(u64);
num_impl!(i16);
num_impl!(i32);
num_impl!(i64);
num_impl!(f32);
num_impl!(f64);

impl<'a, Ty: DebugType<'a>, V, Ctx> ParseWithCtf<'a, Ty, Ctx> for Option<V>
where
    V: ParseWithCtf<'a, Ty, Ctx>,
    Ctx: ParseCtx,
{
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        let var = info.active_variant()?;
        let value = match var {
            ("Some", var_info) => V::parse_with_ctf(ctx, &var_info)?,
            ("None", _) => return Ok(None),
            (s, _) => {
                return Err(Error::no_enumerator(
                    info.ty.name().to_string(),
                    s.to_string(),
                ));
            }
        };

        Ok(Some(value))
    }
}

impl<'a, Ty: DebugType<'a>, V, Ctx> ParseWithCtf<'a, Ty, Ctx> for Vec<V>
where
    V: ParseWithCtf<'a, Ty, Ctx>,
    Ctx: ParseCtx,
{
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
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

        let raw = proc.read_bytes(p, total_len)?;
        let mut out = Vec::with_capacity(len as usize);
        for (i, chunk) in raw.chunks(param_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: info.addr + (i as u64) * param_size,
                bytes: chunk,
                _marker: std::marker::PhantomData,
            };
            let item = V::parse_with_ctf(ctx, &item_info)?;
            out.push(item);
        }

        Ok(out)
    }
}

impl<'a, Ty: DebugType<'a>, V, Ctx> ParseWithCtf<'a, Ty, Ctx> for Box<[V]>
where
    V: ParseWithCtf<'a, Ty, Ctx>,
    Ctx: ParseCtx,
{
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        let proc = ctx.proc();

        let len: u64 = info.member("length")?.parse(ctx)?;
        let ptr = info.member("data_ptr")?;
        let Some(param_ty) = ptr.ty.pointer_target() else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                info.ty.name().to_string(),
            ));
        };
        let param_size = param_ty.size();

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size();

        let raw = proc.read_bytes(p, total_len)?;
        let mut out = Vec::with_capacity(len as usize);
        for (i, chunk) in raw.chunks(param_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: info.addr + (i as u64) * param_size,
                bytes: chunk,
                _marker: std::marker::PhantomData,
            };
            let item = V::parse_with_ctf(ctx, &item_info)?;
            out.push(item);
        }

        Ok(out.into_boxed_slice())
    }
}

impl<'a, Ty: DebugType<'a>, V, Ctx, const N: usize> ParseWithCtf<'a, Ty, Ctx> for [V; N]
where
    V: ParseWithCtf<'a, Ty, Ctx>,
    Ctx: ParseCtx,
{
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }

        let Some((elem_ty, _count)) = info.ty.array_info() else {
            return Err(Error::unexpected_type(
                info.ty.kind(),
                TypeKind::Array,
                info.ty.name().to_string(),
            ));
        };
        let size = elem_ty.size() as usize;

        let mut items = Vec::with_capacity(N);
        for (i, slice) in info.bytes.chunks(size).enumerate() {
            let slice_info = TypeInfoRef {
                ty: elem_ty,
                addr: info.addr + (i * size) as u64,
                bytes: slice,
                _marker: std::marker::PhantomData,
            };
            let item = V::parse_with_ctf(ctx, &slice_info)?;
            items.push(item);
        }
        let Ok(arr) = items.try_into() else {
            unreachable!();
        };
        Ok(arr)
    }
}

impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithCtf<'a, Ty, Ctx> for String {
    fn parse_with_ctf(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        let proc = ctx.proc();

        let len: u64 = info.member("length")?.parse(ctx)?;
        let ptr: u64 = info.member("data_ptr")?.parse(ctx)?;
        let data = proc.read_bytes(ptr, len)?;

        let out = String::from_utf8_lossy(&data).to_string();

        Ok(out)
    }
}

// Split this into a free function to fix lifetime issues from calling
// `TypeInfoRef` methods from `TypeInfo`.
fn array_elements<'buf, 'a: 'buf, T: DebugType<'a>>(
    ty: T,
    addr: u64,
    bytes: &'buf [u8],
) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'a, T>>> {
    let Some((elem_ty, _count)) = ty.array_info() else {
        return Err(Error::unexpected_type(
            ty.kind(),
            TypeKind::Array,
            ty.name().to_string(),
        ));
    };

    let elem_size = elem_ty.size() as usize;
    let iter = bytes
        .chunks_exact(elem_size)
        .enumerate()
        .map(move |(i, chunk)| {
            TypeInfoRef {
                ty: elem_ty,
                addr: addr + (i * elem_size) as u64,
                bytes: chunk,
                _marker: std::marker::PhantomData,
            }
            .peel()
        });
    Ok(iter)
}

/// Parse the elements of a boxed slice, returning them in a Vec.
fn boxed_slice_elements<'buf, 'a: 'buf, T: DebugType<'a>, Ctx: ParseCtx>(
    ptr_info: &'buf TypeInfo<'a, T>,
    _ctx: &Ctx, //TODO REMOVE ME
) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'a, T>>> {
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
                _marker: std::marker::PhantomData,
            }
            .peel()
        });
    Ok(iter)
}

// ---------------------------------------------------------------------------
// ReadFromProc
// ---------------------------------------------------------------------------

pub trait ReadFromProc {
    /// Read `len` bytes at address, returning an error if the address is
    /// unmapped.
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>>;

    /// The mangled function symbol beginning exactly at `addr`, if one is
    /// available from the target. Display-only readers can leave this
    /// unresolved; vtable formatting then preserves the raw entry.
    fn function_symbol(&self, _addr: u64) -> Option<String> {
        None
    }
}

impl<T: proc::Target> ReadFromProc for T {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        proc::Target::read_bytes(self, addr, len)
            .map_err(|e| Error::invalid_addr(addr).with_source(e))
    }

    fn function_symbol(&self, addr: u64) -> Option<String> {
        let symbol = proc::Target::lookup_symbol_by_addr(self, addr)?;
        (symbol.st_value == addr && symbol.st_info & 0x0f == 2).then_some(symbol.name)
    }
}

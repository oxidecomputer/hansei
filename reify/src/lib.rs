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
                depth,
                max_depth,
                proc,
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
                        hex_integers,
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
    depth: usize,
    max_depth: usize,
    proc: Option<&dyn ReadFromProc>,
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
            let concrete = concrete_type_from_symbol(&display);
            functions.push(VtableFunction { slot, display, concrete });
        }
    }

    let concrete = infer_concrete_type(info.ty, words.as_deref(), size_slot, &functions);
    let pretty = f.alternate();
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        write!(f, "{name}")?;
    }
    write!(f, " {{")?;

    write_dyn_field_prefix(f, pretty, depth)?;
    write!(f, "pointer: 0x{pointer_address:x},")?;
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

fn concrete_type_from_symbol(symbol: &str) -> Option<String> {
    for marker in ["core::ptr::drop_glue::<", "core::ptr::drop_in_place::<"] {
        if let Some(rest) = symbol.strip_prefix(marker).and_then(|rest| rest.strip_suffix('>')) {
            return Some(rest.to_owned());
        }
    }

    let rest = symbol.strip_prefix('<')?;
    let mut depth = 1usize;
    for (index, ch) in rest.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 1 && rest[index..].starts_with(" as ") {
            return Some(rest[..index].to_owned());
        }
        if depth == 0 {
            break;
        }
    }
    None
}

#[cfg(test)]
mod vtable_symbol_tests {
    use super::concrete_type_from_symbol;

    #[test]
    fn concrete_type_from_drop_glue() {
        assert_eq!(
            concrete_type_from_symbol("core::ptr::drop_glue::<app::Thing<u64>>").as_deref(),
            Some("app::Thing<u64>")
        );
    }

    #[test]
    fn concrete_type_from_trait_method_with_nested_generics() {
        assert_eq!(
            concrete_type_from_symbol(
                "<app::Thing<alloc::vec::Vec<u8>> as app::Trait>::method"
            )
            .as_deref(),
            Some("app::Thing<alloc::vec::Vec<u8>>")
        );
    }
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
            depth,
            max_depth,
            proc,
        );
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

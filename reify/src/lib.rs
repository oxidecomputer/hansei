pub mod debug_type;

pub use debug_type::TypeKind;
use debug_type::{
    Arm, BitField, DebugMember, DebugType, DisplayNode, Field, FieldRender, MapEntries, Place,
    ScalarDecode, Stmt, TypeClass, ValueExpr,
};

use proc::Mappings;

use std::borrow::Cow;
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
        V: ParseWithDbgInfo<'a, T, Ctx>,
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

    pub fn parse<V: ParseWithDbgInfo<'a, T, Ctx>, Ctx: ParseCtx>(&self, ctx: &Ctx) -> Result<V> {
        V::parse_with_dbg(ctx, self).map_err(|e| Error::parse_type(self.ty.name()).with_source(e))
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
        write_display_value(f, self, RenderCtx::plain(0, 16))
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
        write_display_value(f, self.info, RenderCtx::plain(self.depth, self.max_depth))
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
        let ctx = RenderCtx {
            depth: 0,
            max_depth: self.max_depth,
            proc: Some(self.proc),
            visited: Some(&self.visited),
            hex_integers: false,
        };
        write_display_value(f, self.info, ctx)
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

/// The context threaded through the recursive `write_*` renderers: recursion
/// depth bookkeeping, the optional target reader and cycle-guard used to
/// follow pointers into the process, and whether integers render in hex.
/// Bundling these keeps the renderer signatures small (they otherwise take the
/// same five trailing arguments everywhere).
#[derive(Copy, Clone)]
struct RenderCtx<'buf, 'a> {
    depth: usize,
    max_depth: usize,
    proc: Option<&'buf dyn ReadFromProc>,
    visited: Option<&'buf RefCell<HashSet<(u64, &'a str)>>>,
    hex_integers: bool,
}

impl<'buf, 'a> RenderCtx<'buf, 'a> {
    /// A context with no target to read from (structural rendering only).
    fn plain(depth: usize, max_depth: usize) -> Self {
        Self {
            depth,
            max_depth,
            proc: None,
            visited: None,
            hex_integers: false,
        }
    }

    /// The context for a value nested one level deeper.
    fn deeper(self) -> Self {
        Self {
            depth: self.depth + 1,
            ..self
        }
    }

    /// The same context with the hex-integer flag overridden — array and `Vec`
    /// elements choose their own rendering independent of the parent.
    fn with_hex(self, hex_integers: bool) -> Self {
        Self {
            hex_integers,
            ..self
        }
    }
}

/// Wrapper that carries [`RenderCtx`] for recursive formatting.
struct DisplayRecurse<'buf, 'a: 'buf, T: DebugType<'a>> {
    info: TypeInfoRef<'buf, 'a, T>,
    ctx: RenderCtx<'buf, 'a>,
}

impl<'a, T: DebugType<'a>> fmt::Display for DisplayRecurse<'_, 'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(f, &self.info, self.ctx)
    }
}

fn write_display_value<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    ctx: RenderCtx<'_, 'a>,
) -> fmt::Result {
    let ty = info.ty;
    let bytes = info.bytes;

    if bytes.is_empty() && ty.size() == 0 {
        return write!(f, "{}", ty.name());
    }

    if ctx.depth >= ctx.max_depth {
        return write!(f, "...");
    }

    if (bytes.len() as u64) < ty.size() {
        return write!(f, "<truncated>");
    }

    if let Some(node) = ty.debug_format() {
        // A top-level `Scalar` formatter (e.g. a parking_lot `RawMutex`)
        // has no enclosing field label to give it context, so it is prefixed
        // with the type name — `<name>: <decoded>`. Other nodes name (or
        // elide) themselves as they render.
        if let DisplayNode::Scalar { .. } = node {
            write!(f, "{}: ", ty.name())?;
        }
        return eval_node(f, &node, &ty, info.bytes, info.addr, ctx, f.alternate());
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

            if ctx.hex_integers {
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
            let (Some(proc), Some(visited)) = (ctx.proc, ctx.visited) else {
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
                        ctx: ctx.deeper(),
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
            write_struct_fields(f, info, name, pretty, ctx)
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
            write_rust_enum(f, info, name, pretty, ctx)
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
                        write_indent(f, ctx.depth + 1)?;
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
                        ctx: ctx.deeper().with_hex(hex_elements),
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
                write_indent(f, ctx.depth)?;
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
                ctx: ctx.deeper(),
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

/// Render one machine `word` through a resolved [`ScalarDecode`], producing the
/// canonical `field=value, …` form. Enforces the two "no silent state" rules:
/// an [`FieldRender::Enum`] value absent from its table renders `<unknown: N>`,
/// and any word bit no field covers renders a trailing `<unknown bits: 0xNN>` —
/// so upstream layout drift surfaces rather than being dropped.
fn apply(decode: &ScalarDecode, word: u64) -> String {
    let fields = match decode {
        ScalarDecode::Raw => return word.to_string(),
        ScalarDecode::Bits(fields) => fields,
    };
    let mut parts = Vec::with_capacity(fields.len() + 1);
    let mut covered = 0u64;
    for BitField {
        name,
        shift,
        width,
        render,
    } in fields
    {
        let shift = *shift;
        // `None` width means "all bits at and above `shift`".
        let value_mask = match width {
            Some(w) if w.get() >= 64 => u64::MAX,
            Some(w) => (1u64 << w.get()) - 1,
            None => u64::MAX >> shift,
        };
        covered |= value_mask << shift;
        let value = (word >> shift) & value_mask;
        let rendered = match render {
            FieldRender::Uint => value.to_string(),
            FieldRender::Enum(table) => match table.iter().find(|(v, _)| *v == value) {
                Some((_, label)) => label.clone(),
                None => format!("<unknown: {value}>"),
            },
        };
        // An empty name renders the sub-value bare, for a field the enclosing
        // record already labels (e.g. a boolean shown as just `false`); a named
        // field prefixes it as `name=value`.
        if name.is_empty() {
            parts.push(rendered);
        } else {
            parts.push(format!("{name}={rendered}"));
        }
    }
    let leftover = word & !covered;
    if leftover != 0 {
        parts.push(format!("<unknown bits: {leftover:#x}>"));
    }
    parts.join(", ")
}

/// Render the code pointer in `bytes` at `offset` as `0x<addr> -> <symbol>`,
/// resolving the address to a function symbol without ever following it as a
/// data pointer. A null pointer is `null`; an address that resolves appends
/// ` -> <symbol>`, and one that does not appends ` -> <unknown symbol>` only
/// when a target is attached to resolve against.
fn write_symbol(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    offset: u64,
    proc: Option<&dyn ReadFromProc>,
) -> fmt::Result {
    let Some(address) = read_u64_at(bytes, offset) else {
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

fn write_utf8_string(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    pointer_offset: u64,
    length_offset: u64,
    length_size: u64,
    capacity: Option<(u64, u64)>,
    proc: Option<&dyn ReadFromProc>,
) -> fmt::Result {
    let Some(len) = read_unsigned_at(bytes, length_offset, length_size) else {
        return write!(f, "<truncated string length>");
    };
    if let Some((capacity_offset, capacity_size)) = capacity {
        let Some(capacity) = read_unsigned_at(bytes, capacity_offset, capacity_size) else {
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

/// Follow a `(data, len)` fat pointer to a contiguous buffer and render its
/// first `len` `element`s as `[e, e, …]`. `capacity`, when present, bounds
/// `len` (skipped for a zero-sized element, whose buffer is not read). Unlike
/// [`eval_list`] the elements are contiguous, read in one target access.
#[allow(clippy::too_many_arguments)]
fn eval_slice<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    pointer_offset: u64,
    length_offset: u64,
    length_size: u32,
    capacity: Option<(u64, u32)>,
    element: &T,
    element_size: u32,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    let Some(len) = read_unsigned_at(bytes, length_offset, u64::from(length_size)) else {
        return write!(f, "<truncated slice length>");
    };
    let element_size = u64::from(element_size);
    if let Some((capacity_offset, capacity_size)) = capacity {
        let Some(capacity) = read_unsigned_at(bytes, capacity_offset, u64::from(capacity_size))
        else {
            return write!(f, "<truncated slice capacity>");
        };
        if element_size != 0 && len > capacity {
            return write!(f, "<invalid slice: length exceeds capacity>");
        }
    }
    if len == 0 {
        return write!(f, "[]");
    }
    let Some(pointer) = read_u64_at(bytes, pointer_offset) else {
        return write!(f, "<truncated slice pointer>");
    };

    let allocation = if element_size == 0 {
        Vec::new()
    } else {
        if pointer == 0 {
            return write!(f, "<invalid slice: null data pointer>");
        }
        let Some(byte_len) = len.checked_mul(element_size) else {
            return write!(f, "<invalid slice: buffer size overflow>");
        };
        let Some(proc) = ctx.proc else {
            return write!(f, "<target unavailable>");
        };
        let Ok(bytes) = proc.read_bytes(pointer, byte_len) else {
            return write!(f, "<unreadable slice buffer>");
        };
        bytes
    };

    // Vec elements pick their own integer rendering (never hex).
    let element_ctx = ctx.deeper().with_hex(false);
    write!(f, "[")?;
    for index in 0..len {
        write_seq_prefix(f, pretty, ctx.depth, index == 0)?;
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
                ty: *element,
                addr: address,
                bytes,
                _marker: std::marker::PhantomData,
            },
            ctx: element_ctx,
        };
        if pretty {
            write!(f, "{child:#},")?;
        } else {
            write!(f, "{child}")?;
        }
    }
    write_seq_close(f, pretty, ctx.depth, true)?;
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

enum MapWalkError {
    Format,
    Invalid(&'static str),
    Marker(&'static str),
}

impl From<fmt::Error> for MapWalkError {
    fn from(_: fmt::Error) -> Self {
        Self::Format
    }
}

/// Render the presentation shared by associative collections. The entry source
/// owns storage traversal; this function owns recursive key/value display,
/// exact-length accounting, and inline/pretty punctuation.
#[allow(clippy::too_many_arguments)]
fn eval_map<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    ty: &T,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
    length_offset: u64,
    length_size: u32,
    key: T,
    value: T,
    entries: &MapEntries<T>,
) -> fmt::Result {
    let Some(map_length) = read_unsigned_at(bytes, length_offset, u64::from(length_size)) else {
        return write!(f, "<truncated>");
    };
    write!(f, "{} {{", ty.name())?;
    if map_length == 0 {
        return write!(f, "}}");
    }

    let entry_ctx = ctx.deeper();
    let mut emitted = 0u64;
    let walk = walk_map_entries(
        bytes,
        ctx.proc,
        key,
        value,
        entries,
        &mut |key_addr, key_bytes, value_addr, value_bytes| {
            if emitted == map_length {
                return Err(MapWalkError::Invalid(
                    "tree contains more entries than length",
                ));
            }
            write_map_entry_prefix(f, pretty, ctx.depth, emitted)?;
            let key = DisplayRecurse {
                info: TypeInfoRef {
                    ty: key,
                    addr: key_addr,
                    bytes: key_bytes,
                    _marker: std::marker::PhantomData,
                },
                ctx: entry_ctx,
            };
            let value = DisplayRecurse {
                info: TypeInfoRef {
                    ty: value,
                    addr: value_addr,
                    bytes: value_bytes,
                    _marker: std::marker::PhantomData,
                },
                ctx: entry_ctx,
            };
            if pretty {
                write!(f, "{key:#}: {value:#},")?;
            } else {
                write!(f, "{key}: {value}")?;
            }
            emitted += 1;
            Ok(())
        },
    );

    match walk {
        Ok(()) if emitted == map_length => {}
        Ok(()) => {
            write_map_entry_prefix(f, pretty, ctx.depth, emitted)?;
            write!(f, "<invalid: tree contains fewer entries than length>")?;
        }
        Err(MapWalkError::Invalid(reason)) => {
            write_map_entry_prefix(f, pretty, ctx.depth, emitted)?;
            write!(f, "<invalid: {reason}>")?;
        }
        Err(MapWalkError::Marker(marker)) => {
            write_map_entry_prefix(f, pretty, ctx.depth, emitted)?;
            write!(f, "{marker}")?;
        }
        Err(MapWalkError::Format) => return Err(fmt::Error),
    }

    if pretty {
        writeln!(f)?;
        write_indent(f, ctx.depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

fn write_map_entry_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
    entry: u64,
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

fn walk_map_entries<'a, T: DebugType<'a>>(
    bytes: &[u8],
    proc: Option<&dyn ReadFromProc>,
    key: T,
    value: T,
    entries: &MapEntries<T>,
    emit: &mut impl FnMut(u64, &[u8], u64, &[u8]) -> std::result::Result<(), MapWalkError>,
) -> std::result::Result<(), MapWalkError> {
    let MapEntries::BTree {
        root,
        root_offset,
        root_node,
        root_node_offset,
        height,
        height_offset,
        node_offset,
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
    } = entries;

    let root_start =
        usize::try_from(*root_offset).map_err(|_| MapWalkError::Marker("<invalid root>"))?;
    let root_end = root_start
        .checked_add(root.size() as usize)
        .ok_or(MapWalkError::Marker("<invalid root>"))?;
    let root_bytes = bytes
        .get(root_start..root_end)
        .ok_or(MapWalkError::Marker("<truncated root>"))?;
    if !matches!(root.check_variant(root_bytes, "Some"), Some(Ok(Some(_)))) {
        return Err(MapWalkError::Marker("<invalid missing root>"));
    }

    let root_node_start = usize::try_from(*root_node_offset)
        .map_err(|_| MapWalkError::Marker("<invalid root node>"))?;
    let root_node_end = root_node_start
        .checked_add(root_node.size() as usize)
        .ok_or(MapWalkError::Marker("<invalid root node>"))?;
    let root_node_bytes = bytes
        .get(root_node_start..root_node_end)
        .ok_or(MapWalkError::Marker("<truncated root node>"))?;
    let height = read_unsigned_at(root_node_bytes, *height_offset, height.size())
        .ok_or(MapWalkError::Marker("<truncated height>"))?;
    let root_address = read_u64_at(root_node_bytes, *node_offset)
        .ok_or(MapWalkError::Marker("<truncated node pointer>"))?;
    let proc = proc.ok_or(MapWalkError::Marker("<target unavailable>"))?;

    let layout = BTreeNodeLayout {
        key,
        value,
        leaf: *leaf,
        leaf_len: *leaf_len,
        leaf_len_offset: *leaf_len_offset,
        keys_offset: *keys_offset,
        key_slots: *key_slots,
        values_offset: *values_offset,
        internal: *internal,
        edges_offset: *edges_offset,
        edge: *edge,
        edge_pointer_offset: *edge_pointer_offset,
    };
    walk_btree_node(
        proc,
        layout,
        root_address,
        height,
        &mut HashSet::new(),
        emit,
    )
}

fn walk_btree_node<'a, T: DebugType<'a>>(
    proc: &dyn ReadFromProc,
    layout: BTreeNodeLayout<T>,
    address: u64,
    height: u64,
    visited: &mut HashSet<u64>,
    emit: &mut impl FnMut(u64, &[u8], u64, &[u8]) -> std::result::Result<(), MapWalkError>,
) -> std::result::Result<(), MapWalkError> {
    if address == 0 {
        return Err(MapWalkError::Invalid("null node pointer"));
    }
    if height > 64 {
        return Err(MapWalkError::Invalid("implausible tree height"));
    }
    if !visited.insert(address) {
        return Err(MapWalkError::Invalid("node cycle"));
    }

    let result = (|| {
        let node_type = if height == 0 {
            layout.leaf
        } else {
            layout.internal
        };
        let bytes = proc
            .read_bytes(address, node_type.size())
            .map_err(|_| MapWalkError::Invalid("unreadable node"))?;
        let len = read_unsigned_at(&bytes, layout.leaf_len_offset, layout.leaf_len.size())
            .ok_or(MapWalkError::Invalid("truncated node length"))?;
        if len > layout.key_slots {
            return Err(MapWalkError::Invalid("node length exceeds capacity"));
        }

        for index in 0..len {
            if height > 0 {
                let child = btree_edge_address(&bytes, layout, index)?;
                walk_btree_node(proc, layout, child, height - 1, visited, emit)?;
            }
            let key_start = layout
                .keys_offset
                .checked_add(
                    index
                        .checked_mul(layout.key.size())
                        .ok_or(MapWalkError::Invalid("key offset overflow"))?,
                )
                .ok_or(MapWalkError::Invalid("key offset overflow"))?;
            let value_start = layout
                .values_offset
                .checked_add(
                    index
                        .checked_mul(layout.value.size())
                        .ok_or(MapWalkError::Invalid("value offset overflow"))?,
                )
                .ok_or(MapWalkError::Invalid("value offset overflow"))?;
            let key_bytes = byte_range(&bytes, key_start, layout.key.size())
                .ok_or(MapWalkError::Invalid("truncated key slot"))?;
            let value_bytes = byte_range(&bytes, value_start, layout.value.size())
                .ok_or(MapWalkError::Invalid("truncated value slot"))?;
            let key_addr = address
                .checked_add(key_start)
                .ok_or(MapWalkError::Invalid("key address overflow"))?;
            let value_addr = address
                .checked_add(value_start)
                .ok_or(MapWalkError::Invalid("value address overflow"))?;
            emit(key_addr, key_bytes, value_addr, value_bytes)?;
        }
        if height > 0 {
            let child = btree_edge_address(&bytes, layout, len)?;
            walk_btree_node(proc, layout, child, height - 1, visited, emit)?;
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
) -> std::result::Result<u64, MapWalkError> {
    let offset = layout
        .edges_offset
        .checked_add(
            index
                .checked_mul(layout.edge.size())
                .ok_or(MapWalkError::Invalid("edge offset overflow"))?,
        )
        .and_then(|offset| offset.checked_add(layout.edge_pointer_offset))
        .ok_or(MapWalkError::Invalid("edge offset overflow"))?;
    read_u64_at(bytes, offset).ok_or(MapWalkError::Invalid("truncated edge slot"))
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

fn eval_dyn_pointer<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    ty: T,
    name: Option<&str>,
    node: &DisplayNode<T>,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a>,
) -> fmt::Result {
    let DisplayNode::DynPointer {
        pointer_offset,
        vtable,
        vtable_offset,
        drop_in_place: drop_in_place_slot,
        size: size_slot,
        align: align_slot,
        tail_offset,
    } = node
    else {
        unreachable!()
    };

    let Some(pointer_address) = read_u64_at(bytes, *pointer_offset) else {
        return write!(f, "<truncated>");
    };
    let Some(vtable_address) = read_u64_at(bytes, *vtable_offset) else {
        return write!(f, "<truncated>");
    };
    let words = read_vtable_words(*vtable, vtable_address, ctx.proc);

    let mut functions = Vec::new();
    if let (Some(proc), Some(words)) = (ctx.proc, words.as_deref()) {
        for (slot, &address) in words.iter().enumerate() {
            let slot = slot as u32;
            if slot == *size_slot || slot == *align_slot || address == 0 {
                continue;
            }
            let Some(display) = resolve_function_symbol(Some(proc), address) else {
                continue;
            };
            let concrete =
                exegesis::symbols::concrete_type_from_vtable_symbol(&display).map(str::to_owned);
            functions.push(VtableFunction {
                slot,
                display,
                concrete,
            });
        }
    }

    let concrete = infer_concrete_type(ty, words.as_deref(), *size_slot, &functions);
    let concrete_ty = concrete.as_deref().and_then(|name| ty.type_by_name(name));
    let pretty = f.alternate();
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        write!(f, "{name}")?;
    }
    write!(f, " {{")?;

    write_dyn_field_prefix(f, pretty, ctx.depth)?;
    write!(f, "pointer: 0x{pointer_address:x}")?;
    // The vtable resolves the erased *tail* type; when the pointer targets an
    // unsized wrapper (e.g. `ArcInner<dyn Trait>`) the value lives past a
    // sized header, so read the pointee at the tail offset, not the raw
    // pointer.
    let pointee_address = pointer_address.wrapping_add(*tail_offset);
    // A zero-sized concrete type (e.g. slog's `()` list terminator) has no
    // pointee worth following — the `concrete type:` line below already names
    // it. Showing `-> ()` would only add noise.
    if let (Some(concrete_ty), Some(proc), Some(visited)) = (
        concrete_ty.filter(|ty| ty.size() > 0),
        ctx.proc,
        ctx.visited,
    ) {
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
                        ctx: ctx.deeper(),
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
    write_dyn_field_prefix(f, pretty, ctx.depth)?;
    write!(
        f,
        "concrete type: {},",
        concrete.as_deref().unwrap_or("<unknown>")
    )?;
    write_dyn_field_prefix(f, pretty, ctx.depth)?;
    write!(f, "vtable: ")?;

    match words.as_deref() {
        Some(words) if ctx.depth + 1 < ctx.max_depth => {
            write!(f, "{{")?;
            write_vtable_field_prefix(f, pretty, ctx.depth)?;
            let drop_address = words
                .get(*drop_in_place_slot as usize)
                .copied()
                .unwrap_or(0);
            write!(f, "drop_in_place: 0x{drop_address:x}")?;
            if let Some(function) = functions
                .iter()
                .find(|function| function.slot == *drop_in_place_slot)
            {
                write!(f, " -> {}", function.display)?;
            }
            write!(f, ",")?;

            write_vtable_field_prefix(f, pretty, ctx.depth)?;
            match words.get(*size_slot as usize) {
                Some(size) => write!(f, "size: {size},")?,
                None => write!(f, "size: <unavailable>,")?,
            }
            write_vtable_field_prefix(f, pretty, ctx.depth)?;
            match words.get(*align_slot as usize) {
                Some(align) => write!(f, "align: {align},")?,
                None => write!(f, "align: <unavailable>,")?,
            }

            for (slot, &address) in words.iter().enumerate() {
                let slot = slot as u32;
                if slot == *drop_in_place_slot || slot == *size_slot || slot == *align_slot {
                    continue;
                }
                write_vtable_field_prefix(f, pretty, ctx.depth)?;
                if let Some(function) = functions.iter().find(|function| function.slot == slot) {
                    write!(f, "method[{slot}]: 0x{address:x} -> {},", function.display)?;
                } else {
                    write!(f, "entry[{slot}]: 0x{address:016x},")?;
                }
            }

            if pretty {
                writeln!(f)?;
                write_indent(f, ctx.depth + 1)?;
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
        write_indent(f, ctx.depth)?;
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

fn write_dyn_field_prefix(f: &mut fmt::Formatter<'_>, pretty: bool, depth: usize) -> fmt::Result {
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
    let mut concrete = functions
        .iter()
        .filter_map(|function| function.concrete.as_deref());
    let candidate = concrete.next()?.to_owned();
    if concrete.any(|other| other != candidate) {
        return None;
    }
    if let (Some(expected), Some(actual)) = (
        ty.size_by_name(&candidate),
        words?.get(size_slot as usize).copied(),
    ) && expected != actual
    {
        return None;
    }
    Some(candidate)
}

/// True when `members` are a Rust tuple aggregate — a tuple struct or a tuple
/// enum variant — whose fields rustc names `__0, __1, …` in declaration order.
/// Such a value renders positionally (`Name(v0, v1)`), eliding the synthetic
/// labels, to match `rustc`/gdb/lldb `Debug` output. A regular struct names a
/// field something other than `__i`, so one non-matching member rules it out.
/// Detection runs on the *full* member list so a `(ZST, T)` tuple is still
/// recognized even though the ZST is not displayed.
fn is_tuple<'a, M: DebugMember<'a>>(members: &[M]) -> bool {
    !members.is_empty()
        && members.iter().enumerate().all(|(i, m)| {
            m.name()
                .strip_prefix("__")
                .and_then(|rest| rest.parse::<usize>().ok())
                == Some(i)
        })
}

/// Render one member's value (or `<truncated>`) at its offset, recursing with
/// the deeper context. Shared by the tuple and named aggregate bodies.
fn write_member_value<'a, M: DebugMember<'a>>(
    f: &mut fmt::Formatter<'_>,
    member: &M,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    let mem_ty = member.ty();
    let start = member.offset() as usize;
    let end = start + mem_ty.size() as usize;
    match bytes.get(start..end) {
        Some(mem_bytes) => {
            let child = DisplayRecurse {
                info: TypeInfoRef {
                    ty: mem_ty,
                    addr: addr + member.offset(),
                    bytes: mem_bytes,
                    _marker: std::marker::PhantomData,
                },
                ctx: ctx.deeper(),
            };
            if pretty {
                write!(f, "{:#}", child)
            } else {
                write!(f, "{}", child)
            }
        }
        None => write!(f, "<truncated>"),
    }
}

/// Render the body of a struct or enum-variant payload after its name/variant
/// has been written: a tuple aggregate as `(v0, v1)` (labels elided), a named
/// aggregate as ` { field: v, … }`, and an empty/all-ZST aggregate as nothing
/// (a unit). Zero-sized members are never displayed.
fn write_aggregate_body<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    ty: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    let all: Vec<_> = ty.members().collect();
    let tuple = is_tuple(&all);
    let shown: Vec<_> = all.into_iter().filter(|m| m.ty().size() > 0).collect();

    if shown.is_empty() {
        return Ok(());
    }

    if tuple {
        write!(f, "(")?;
        for (i, member) in shown.iter().enumerate() {
            if pretty {
                writeln!(f)?;
                write_indent(f, ctx.depth + 1)?;
            } else if i > 0 {
                write!(f, ", ")?;
            }
            write_member_value(f, member, bytes, addr, ctx, pretty)?;
            if pretty {
                write!(f, ",")?;
            }
        }
        if pretty {
            writeln!(f)?;
            write_indent(f, ctx.depth)?;
        }
        write!(f, ")")
    } else {
        write!(f, " {{")?;
        for (i, member) in shown.iter().enumerate() {
            if pretty {
                writeln!(f)?;
                write_indent(f, ctx.depth + 1)?;
            } else if i > 0 {
                write!(f, ",")?;
            }
            write!(f, " {}: ", member.name())?;
            write_member_value(f, member, bytes, addr, ctx, pretty)?;
            if pretty {
                write!(f, ",")?;
            }
        }
        if pretty {
            writeln!(f)?;
            write_indent(f, ctx.depth)?;
        } else {
            write!(f, " ")?;
        }
        write!(f, "}}")
    }
}

fn write_struct_fields<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    name: &str,
    pretty: bool,
    ctx: RenderCtx<'_, 'a>,
) -> fmt::Result {
    if !name.is_empty() {
        write!(f, "{}", name)?;
    }
    write_aggregate_body(f, &info.ty, info.bytes, info.addr, ctx, pretty)
}

/// Interpret a resolved [`DisplayNode`] tree — the single generic evaluator
/// that stands in for the per-type `write_*` renderers on node-based formats.
///
/// `ty` is the type the node is rendered against: its name titles a `Struct`
/// record and its members back `Field::Structural`. `bytes`/`addr` are that
/// value's buffer and target address; a node's offsets are relative to them.
/// `pretty` requests multi-line layout. All pretty-vs-inline, cycle-guard, and
/// degradation-string handling lives here, written once.
fn eval_node<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    node: &DisplayNode<T>,
    ty: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    match node {
        DisplayNode::Scalar {
            offset,
            word_size,
            decode,
        } => match read_unsigned_at(bytes, *offset, u64::from(*word_size)) {
            Some(word) => write!(f, "{}", apply(decode, word)),
            None => write!(f, "<truncated>"),
        },
        DisplayNode::Symbol { offset } => write_symbol(f, bytes, *offset, ctx.proc),
        DisplayNode::Struct { fields } => {
            eval_struct(f, fields, ty, None, bytes, addr, ctx, pretty)
        }
        DisplayNode::List {
            head_offset,
            next_offset,
            node,
            node_ty,
            node_size,
        } => eval_list(
            f,
            *head_offset,
            *next_offset,
            node,
            node_ty,
            *node_size,
            bytes,
            ctx,
            pretty,
        ),
        DisplayNode::Str {
            pointer_offset,
            length_offset,
            length_size,
            capacity,
        } => write_utf8_string(
            f,
            bytes,
            *pointer_offset,
            *length_offset,
            u64::from(*length_size),
            capacity.map(|(offset, size)| (offset, u64::from(size))),
            ctx.proc,
        ),
        DisplayNode::Slice {
            pointer_offset,
            length_offset,
            length_size,
            capacity,
            element,
            element_size,
        } => eval_slice(
            f,
            *pointer_offset,
            *length_offset,
            *length_size,
            *capacity,
            element,
            *element_size,
            bytes,
            ctx,
            pretty,
        ),
        DisplayNode::IpAddr {
            octets_offset,
            octets_size,
        } => eval_ip_addr(f, bytes, *octets_offset, u64::from(*octets_size)),
        DisplayNode::Alias {
            target,
            place,
            follow_pointers,
        } => {
            // Peeling a wrapper elides a representation detail, so it does not
            // consume the value-depth budget: `ctx` (and its `depth`) threads
            // through unchanged. An atomic snapshot (`follow_pointers` false)
            // shows a stored pointer's address rather than its pointee. Nulling
            // `proc` also stops a place from crossing a pointer, which a
            // non-following alias never does (its place is a local offset).
            let child_ctx = if *follow_pointers {
                ctx
            } else {
                RenderCtx {
                    proc: None,
                    visited: None,
                    ..ctx
                }
            };
            match read_place_bytes(place, bytes, addr, child_ctx, target.size()) {
                Ok((child_addr, child_bytes)) => {
                    let child = DisplayRecurse {
                        info: TypeInfoRef {
                            ty: *target,
                            addr: child_addr,
                            bytes: child_bytes.as_ref(),
                            _marker: std::marker::PhantomData,
                        },
                        ctx: child_ctx,
                    };
                    if pretty {
                        write!(f, "{child:#}")
                    } else {
                        write!(f, "{child}")
                    }
                }
                Err(marker) => write!(f, "{marker}"),
            }
        }
        DisplayNode::SlotCount {
            bitmap_offset,
            bitmap_size,
            count,
        } => {
            let ready =
                read_unsigned_at(bytes, *bitmap_offset, u64::from(*bitmap_size)).unwrap_or(0);
            // Only the low `count` bits are per-slot readiness; the rest are
            // the released/closed flags.
            let mask = if *count >= 64 {
                u64::MAX
            } else {
                (1u64 << count) - 1
            };
            let written = (ready & mask).count_ones();
            write!(f, "[{written} slots]")
        }
        DisplayNode::Pointer {
            pointer_offset,
            via_offset,
            target,
            then,
        } => {
            // The record reads as its target but keeps the enclosing name, so a
            // degraded read still reports as e.g. `Receiver<T> { <null> }`.
            let name = ty.name();
            let Some(pointer) = read_u64_at(bytes, *pointer_offset) else {
                return write!(f, "{name} {{ <truncated> }}");
            };
            // Both accessors must be present to follow the pointer into the
            // process; without them the target cannot be read.
            let (Some(proc), Some(_visited)) = (ctx.proc, ctx.visited) else {
                return write!(f, "{name} {{ <target unavailable> }}");
            };
            if pointer == 0 {
                return write!(f, "{name} {{ <null> }}");
            }
            let addr = pointer.wrapping_add(*via_offset);
            let Ok(target_bytes) = proc.read_bytes(addr, target.size()) else {
                return write!(f, "{name} {{ <unreadable> }}");
            };
            // Render the target against its own bytes, titled with this type's
            // name. `then` is a `Struct` for the receiver, but any node works.
            match then.as_ref() {
                DisplayNode::Struct { fields } => eval_struct(
                    f,
                    fields,
                    target,
                    Some(name),
                    &target_bytes,
                    addr,
                    ctx,
                    pretty,
                ),
                other => eval_node(f, other, target, &target_bytes, addr, ctx, pretty),
            }
        }
        DisplayNode::DynPointer { .. } => {
            eval_dyn_pointer(f, *ty, Some(ty.name()), node, bytes, ctx)
        }
        DisplayNode::Map {
            length_offset,
            length_size,
            key,
            value,
            entries,
        } => eval_map(
            f,
            ty,
            bytes,
            ctx,
            pretty,
            *length_offset,
            *length_size,
            *key,
            *value,
            entries,
        ),
        DisplayNode::Variant {
            discriminant,
            arms,
            default,
        } => eval_variant(
            f,
            discriminant,
            arms,
            default.as_deref(),
            ty,
            bytes,
            addr,
            ctx,
            pretty,
        ),
        DisplayNode::CustomList {
            vars,
            condition,
            body,
            element,
        } => eval_custom_list(f, vars, condition, body, element, bytes, addr, ctx, pretty),
    }
}

/// Read the `size`-byte machine word at `place`, following any pointer hops
/// through `proc`. Empty `hops` is the common case: a borrowed local slice, no
/// process read. On failure the `Err` carries the exact degradation marker to
/// print in the value's place.
fn read_place_bytes<'b>(
    place: &Place,
    bytes: &'b [u8],
    addr: u64,
    ctx: RenderCtx<'_, '_>,
    size: u64,
) -> std::result::Result<(u64, Cow<'b, [u8]>), &'static str> {
    if place.hops.is_empty() {
        let slice = byte_range(bytes, place.root_offset, size).ok_or("<truncated>")?;
        return Ok((addr.wrapping_add(place.root_offset), Cow::Borrowed(slice)));
    }
    let proc = ctx.proc.ok_or("<target unavailable>")?;
    let mut pointer = read_u64_at(bytes, place.root_offset).ok_or("<truncated>")?;
    let (last, intermediate) = place.hops.split_last().expect("hops is non-empty");
    for hop in intermediate {
        if pointer == 0 {
            return Err("<null>");
        }
        let addr = pointer.checked_add(*hop).ok_or("<invalid address>")?;
        let word = proc.read_bytes(addr, 8).map_err(|_| "<unreadable>")?;
        pointer = read_u64_at(&word, 0).ok_or("<unreadable>")?;
    }
    if pointer == 0 {
        return Err("<null>");
    }
    let target = pointer.checked_add(*last).ok_or("<invalid address>")?;
    let read = if size == 0 {
        Vec::new()
    } else {
        proc.read_bytes(target, size).map_err(|_| "<unreadable>")?
    };
    Ok((target, Cow::Owned(read)))
}

/// Evaluate a resolved [`ValueExpr`] against `bytes`, crossing pointer hops via
/// `ctx.proc`. `Err` carries a degradation marker for a failed read.
fn eval_expr(
    expr: &ValueExpr,
    vars: &[u64],
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, '_>,
) -> std::result::Result<u64, &'static str> {
    Ok(match expr {
        ValueExpr::Const(value) => *value,
        ValueExpr::Read(place, size) => {
            let (_, word) = read_place_bytes(place, bytes, addr, ctx, u64::from(*size))?;
            read_unsigned_at(word.as_ref(), 0, u64::from(*size)).ok_or("<unreadable>")?
        }
        ValueExpr::And(a, b) => {
            eval_expr(a, vars, bytes, addr, ctx)? & eval_expr(b, vars, bytes, addr, ctx)?
        }
        ValueExpr::Not(inner) => !eval_expr(inner, vars, bytes, addr, ctx)?,
        ValueExpr::Ne(a, b) => u64::from(
            eval_expr(a, vars, bytes, addr, ctx)? != eval_expr(b, vars, bytes, addr, ctx)?,
        ),
        ValueExpr::Var(id) => *vars.get(*id as usize).ok_or("<invalid var>")?,
        ValueExpr::Load {
            addr: addr_expr,
            size,
        } => {
            let target = eval_expr(addr_expr, vars, bytes, addr, ctx)?;
            let proc = ctx.proc.ok_or("<target unavailable>")?;
            let word = proc
                .read_bytes(target, u64::from(*size))
                .map_err(|_| "<unreadable>")?;
            read_unsigned_at(&word, 0, u64::from(*size)).ok_or("<unreadable>")?
        }
        ValueExpr::Add(a, b) => eval_expr(a, vars, bytes, addr, ctx)?
            .wrapping_add(eval_expr(b, vars, bytes, addr, ctx)?),
        ValueExpr::Sub(a, b) => eval_expr(a, vars, bytes, addr, ctx)?
            .wrapping_sub(eval_expr(b, vars, bytes, addr, ctx)?),
        ValueExpr::Mul(a, b) => eval_expr(a, vars, bytes, addr, ctx)?
            .wrapping_mul(eval_expr(b, vars, bytes, addr, ctx)?),
        ValueExpr::Lt(a, b) => {
            u64::from(eval_expr(a, vars, bytes, addr, ctx)? < eval_expr(b, vars, bytes, addr, ctx)?)
        }
    })
}

/// Cap on [`DisplayNode::CustomList`] loop iterations. A body has no inner loop,
/// so this hard-bounds the emitted items (and any cyclic pointer walk) without a
/// per-node `visited` set: a malformed or cyclic program stops here instead of
/// spinning. A live tokio mpsc queue is a few blocks of ≤32 slots, far under it.
const MAX_CUSTOM_LIST_ITERS: u32 = 1000;

/// Result of running a [`Stmt`] sequence: whether to run the next loop iteration
/// or stop — a `Break` fired, or a read degraded to a marker already written.
enum Flow {
    Next,
    Stop,
}

/// Write a degradation marker as a pseudo-element in a sequence body: an inline
/// `, ` separator when elements precede it, then the marker. Matches the
/// `<unreadable>` handling in the list and mpsc-queue renderers.
fn write_seq_marker(f: &mut fmt::Formatter<'_>, marker: &str, any: bool) -> fmt::Result {
    write!(f, "{}{marker}", if any { ", " } else { "" })
}

/// Render a [`DisplayNode::CustomList`]: seed the loop variables from the value,
/// then interpret `body` each iteration while `condition` holds, emitting one
/// `element` per [`Stmt::Emit`]. Owns the iteration cap and reuses the shared
/// sequence punctuation; a failed read degrades to a marker like the other list
/// nodes. This is the general escape hatch a windowed/paged walk (the mpsc block
/// chain) uses in place of a bespoke leaf.
#[allow(clippy::too_many_arguments)]
fn eval_custom_list<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    vars_init: &[ValueExpr],
    condition: &ValueExpr,
    body: &[Stmt],
    element: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    // Seeds read the value alone (no variables exist yet); a failed seed read
    // degrades the whole list before any bracket, like the other list nodes.
    let mut vars: Vec<u64> = Vec::with_capacity(vars_init.len());
    for init in vars_init {
        match eval_expr(init, &[], bytes, addr, ctx) {
            Ok(value) => vars.push(value),
            Err(marker) => return write!(f, "{marker}"),
        }
    }

    write!(f, "[")?;
    let mut any = false;
    for _ in 0..MAX_CUSTOM_LIST_ITERS {
        match eval_expr(condition, &vars, bytes, addr, ctx) {
            Ok(0) => break,
            Ok(_) => {}
            Err(marker) => {
                write_seq_marker(f, marker, any)?;
                break;
            }
        }
        match eval_stmts(
            f, body, &mut vars, element, bytes, addr, ctx, pretty, &mut any,
        )? {
            Flow::Next => {}
            Flow::Stop => break,
        }
    }
    write_seq_close(f, pretty, ctx.depth, any)?;
    write!(f, "]")
}

/// Run one [`Stmt`] sequence for a [`DisplayNode::CustomList`] iteration,
/// mutating `vars`, emitting elements, and returning whether the loop continues.
/// A read that degrades writes its marker inline and stops the loop.
#[allow(clippy::too_many_arguments)]
fn eval_stmts<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    stmts: &[Stmt],
    vars: &mut Vec<u64>,
    element: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
    any: &mut bool,
) -> std::result::Result<Flow, fmt::Error> {
    for stmt in stmts {
        match stmt {
            Stmt::Set { var, value } => {
                let value = match eval_expr(value, vars, bytes, addr, ctx) {
                    Ok(value) => value,
                    Err(marker) => {
                        write_seq_marker(f, marker, *any)?;
                        return Ok(Flow::Stop);
                    }
                };
                if let Some(slot) = vars.get_mut(*var as usize) {
                    *slot = value;
                }
            }
            Stmt::If {
                cond,
                then,
                otherwise,
            } => {
                let cond = match eval_expr(cond, vars, bytes, addr, ctx) {
                    Ok(cond) => cond,
                    Err(marker) => {
                        write_seq_marker(f, marker, *any)?;
                        return Ok(Flow::Stop);
                    }
                };
                let branch = if cond != 0 { then } else { otherwise };
                if let Flow::Stop =
                    eval_stmts(f, branch, vars, element, bytes, addr, ctx, pretty, any)?
                {
                    return Ok(Flow::Stop);
                }
            }
            Stmt::Break { cond } => {
                let cond = match eval_expr(cond, vars, bytes, addr, ctx) {
                    Ok(cond) => cond,
                    Err(marker) => {
                        write_seq_marker(f, marker, *any)?;
                        return Ok(Flow::Stop);
                    }
                };
                if cond != 0 {
                    return Ok(Flow::Stop);
                }
            }
            Stmt::Emit { at } => {
                let target = match eval_expr(at, vars, bytes, addr, ctx) {
                    Ok(target) => target,
                    Err(marker) => {
                        write_seq_marker(f, marker, *any)?;
                        return Ok(Flow::Stop);
                    }
                };
                let Some(proc) = ctx.proc else {
                    write_seq_marker(f, "<target unavailable>", *any)?;
                    return Ok(Flow::Stop);
                };
                let Ok(element_bytes) = proc.read_bytes(target, element.size()) else {
                    write_seq_marker(f, "<unreadable>", *any)?;
                    return Ok(Flow::Stop);
                };
                write_seq_prefix(f, pretty, ctx.depth, !*any)?;
                *any = true;
                let child = DisplayRecurse {
                    info: TypeInfoRef {
                        ty: *element,
                        addr: target,
                        bytes: &element_bytes,
                        _marker: std::marker::PhantomData,
                    },
                    ctx: ctx.deeper(),
                };
                if pretty {
                    write!(f, "{child:#},")?;
                } else {
                    write!(f, "{child}")?;
                }
            }
        }
    }
    Ok(Flow::Next)
}

/// Render a [`DisplayNode::Variant`]: evaluate the discriminant, then render the
/// first arm whose value matches (else `default`, else `<unknown: N>` — the
/// same no-silent-state contract the scalar decoder follows). Only the selected
/// arm is evaluated, so an unseen watch receiver never reads its value.
#[allow(clippy::too_many_arguments)]
fn eval_variant<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    discriminant: &ValueExpr,
    arms: &[Arm<T>],
    default: Option<&DisplayNode<T>>,
    ty: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    let value = match eval_expr(discriminant, &[], bytes, addr, ctx) {
        Ok(value) => value,
        Err(marker) => return write!(f, "{marker}"),
    };
    if let Some(arm) = arms.iter().find(|arm| arm.value == value) {
        // `label`, `label(<payload>)`, or `<payload>` — covering a unit variant
        // (`None`), a tuple variant (`Some(x)`), and a bare label (`false`).
        if let Some(label) = &arm.label {
            write!(f, "{label}")?;
        }
        if let Some(payload) = &arm.payload {
            if arm.label.is_some() {
                write!(f, "(")?;
            }
            eval_node(f, payload, ty, bytes, addr, ctx.deeper(), pretty)?;
            if arm.label.is_some() {
                write!(f, ")")?;
            }
        }
        return Ok(());
    }
    match default {
        Some(node) => eval_node(f, node, ty, bytes, addr, ctx, pretty),
        None => write!(f, "<unknown: {value}>"),
    }
}

/// Render the inline octets at `offset` as an IPv4 (4 octets) or IPv6 (16
/// octets) address in standard notation; the version is inferred from the octet
/// count that resolution validated to be 4 or 16.
fn eval_ip_addr(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    offset: u64,
    octets_size: u64,
) -> fmt::Result {
    let Some(bytes) = byte_range(bytes, offset, octets_size) else {
        return write!(f, "<truncated>");
    };
    match <&[u8; 4]>::try_from(bytes) {
        Ok(octets) => write!(f, "{}", std::net::Ipv4Addr::from(*octets)),
        Err(_) => match <&[u8; 16]>::try_from(bytes) {
            Ok(octets) => write!(f, "{}", std::net::Ipv6Addr::from(*octets)),
            Err(_) => write!(f, "<invalid IP address layout>"),
        },
    }
}

/// Render a [`DisplayNode::Struct`] record: `<ty> { field, … }`, each field
/// either a real member shown structurally or a label whose value is a nested
/// node.
#[allow(clippy::too_many_arguments)]
fn eval_struct<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    fields: &[Field<T>],
    ty: &T,
    name: Option<&str>,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    // A `Pointer` re-roots the record at its target but titles it with the
    // enclosing type's name (a `Receiver` reads as its `Chan`); every other
    // caller titles it with the rendered type's own name.
    write!(f, "{} {{", name.unwrap_or_else(|| ty.name()))?;
    for (i, field) in fields.iter().enumerate() {
        // Field prefix: pretty starts a fresh indented line; inline opens with
        // a space after `{` and separates subsequent fields with `, `.
        if pretty {
            writeln!(f)?;
            write_indent(f, ctx.depth + 1)?;
        } else if i > 0 {
            write!(f, ", ")?;
        } else {
            write!(f, " ")?;
        }
        match field {
            Field::Structural {
                name,
                ty: mem_ty,
                offset,
            } => {
                write!(f, "{name}: ")?;
                match byte_range(bytes, *offset, mem_ty.size()) {
                    Some(mem_bytes) => {
                        let child = DisplayRecurse {
                            info: TypeInfoRef {
                                ty: *mem_ty,
                                addr: addr + offset,
                                bytes: mem_bytes,
                                _marker: std::marker::PhantomData,
                            },
                            ctx: ctx.deeper(),
                        };
                        if pretty {
                            write!(f, "{child:#}")?
                        } else {
                            write!(f, "{child}")?
                        }
                    }
                    None => write!(f, "<truncated>")?,
                }
            }
            Field::Computed { label, node } => {
                write!(f, "{label}: ")?;
                eval_node(f, node, ty, bytes, addr, ctx.deeper(), pretty)?;
            }
        }
        if pretty {
            write!(f, ",")?;
        }
    }
    if pretty {
        writeln!(f)?;
        write_indent(f, ctx.depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

/// Walk the intrusive linked list at `head_offset` (0 = empty), rendering each
/// `node_ty` element via `node`. Each node is read from the target and the walk
/// follows the successor word at `next_offset`, guarded against cycles and
/// runaway length — the shared successor of the old `write_*_waiters` pair.
///
/// Elements render compactly (inline) regardless of `pretty`; `pretty` only
/// puts each on its own indented line. A queue entry is small, so this reads
/// far better than expanding every entry across several lines.
#[allow(clippy::too_many_arguments)]
fn eval_list<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    head_offset: u64,
    next_offset: u64,
    node: &DisplayNode<T>,
    node_ty: &T,
    node_size: u32,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    let Some(head) = read_u64_at(bytes, head_offset) else {
        return write!(f, "<truncated>");
    };
    // An empty list is known from the head word alone; a populated one needs
    // the target to read each node.
    if head == 0 {
        return write!(f, "[]");
    }
    let Some(proc) = ctx.proc else {
        return write!(f, "<target unavailable>");
    };
    write!(f, "[")?;

    let mut cur = head;
    let mut any = false;
    let mut seen = HashSet::new();
    let mut guard = 4096u32;
    while cur != 0 && guard > 0 {
        guard -= 1;
        if !seen.insert(cur) {
            break;
        }
        let Ok(node_bytes) = proc.read_bytes(cur, u64::from(node_size)) else {
            write!(f, "{}<unreadable>", if any { ", " } else { "" })?;
            break;
        };
        write_seq_prefix(f, pretty, ctx.depth, !any)?;
        any = true;
        // Each element renders inline (`pretty = false`) even in pretty mode.
        eval_node(f, node, node_ty, &node_bytes, cur, ctx.deeper(), false)?;
        if pretty {
            write!(f, ",")?;
        }
        match read_u64_at(&node_bytes, next_offset) {
            Some(next) => cur = next,
            None => break,
        }
    }
    write_seq_close(f, pretty, ctx.depth, any)?;
    write!(f, "]")
}

fn write_rust_enum<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    name: &str,
    pretty: bool,
    ctx: RenderCtx<'_, 'a>,
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

    if let Some(node @ DisplayNode::DynPointer { .. }) = variant_info.ty.debug_format() {
        return eval_dyn_pointer(f, variant_info.ty, None, &node, variant_info.bytes, ctx);
    }

    // A payload carrying a semantic display format (a `&str`/`String`, a
    // `Vec`, an IP address, ...) should render as that value, not as its
    // raw representation fields. `Cow<str>::Borrowed("x")` reads far better
    // than `Borrowed { data_ptr: .., length: .. }`. Delegating to the value
    // formatter keeps this general across every known format (trait objects
    // are handled above, with their own layout).
    if variant_info.ty.debug_format().is_some() {
        // Peeling into the payload's own formatter is a representation detail,
        // so it stays at the same depth.
        let child = DisplayRecurse {
            info: variant_info,
            ctx,
        };
        write!(f, "(")?;
        if pretty {
            write!(f, "{child:#}")?;
        } else {
            write!(f, "{child}")?;
        }
        return write!(f, ")");
    }

    // A tuple variant (`Some(x)`, `Ok(x)`) renders positionally; a struct
    // variant (`Variant { field: x }`) keeps its labels. Both share the
    // aggregate body renderer, so the `__N` elision is applied in one place.
    write_aggregate_body(
        f,
        &variant_info.ty,
        variant_info.bytes,
        variant_info.addr,
        ctx,
        pretty,
    )
}

fn write_indent(f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    for _ in 0..depth {
        write!(f, "    ")?;
    }
    Ok(())
}

/// Prefix punctuation before one element of a `[e, e, …]` sequence. In pretty
/// mode: a newline and one deeper indent so each element sits on its own line.
/// Inline: a `, ` separator before every element but the first (`first` is
/// whether no element has been written yet). Shared by the slice, list, and
/// mpsc-queue renderers so the bracket/indent/comma dance lives in one place.
fn write_seq_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
    first: bool,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, depth + 1)
    } else if first {
        Ok(())
    } else {
        write!(f, ", ")
    }
}

/// Whitespace closing a `[e, e, …]` sequence body, written before the caller's
/// `]`. In pretty mode, once `any` element has been emitted, a newline and an
/// indent back to `depth` so the bracket lines up with the opener; inline (or
/// when empty), nothing.
fn write_seq_close(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
    any: bool,
) -> fmt::Result {
    if pretty && any {
        writeln!(f)?;
        write_indent(f, depth)?;
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
// ParseCtx & ParseWithDbgInfo
// ---------------------------------------------------------------------------

pub trait ParseCtx {
    /// The target being read: a live process or core on illumos, or a
    /// captured snapshot anywhere.
    type Target: ReadFromProc;

    fn proc(&self) -> &Self::Target;
    fn mappings(&self) -> &Mappings;
}

/// Parse a byte slice as a type using debug type information.
pub trait ParseWithDbgInfo<'a, Ty: DebugType<'a>, Ctx>: Sized
where
    Ctx: ParseCtx,
{
    /// Attempt to read `Self` from the debug type information.
    fn parse_with_dbg(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self>;
}

impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithDbgInfo<'a, Ty, Ctx> for u8 {
    fn parse_with_dbg(_ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0])
    }
}

impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithDbgInfo<'a, Ty, Ctx> for i8 {
    fn parse_with_dbg(_ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        if info.bytes.len() != size_of::<Self>() {
            return Err(Error::unexpected_len(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0] as i8)
    }
}

impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithDbgInfo<'a, Ty, Ctx> for bool {
    fn parse_with_dbg(_ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
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
        impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithDbgInfo<'a, Ty, Ctx> for $num_ty {
            fn parse_with_dbg(_ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
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

impl<'a, Ty: DebugType<'a>, V, Ctx> ParseWithDbgInfo<'a, Ty, Ctx> for Option<V>
where
    V: ParseWithDbgInfo<'a, Ty, Ctx>,
    Ctx: ParseCtx,
{
    fn parse_with_dbg(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
        let var = info.active_variant()?;
        let value = match var {
            ("Some", var_info) => V::parse_with_dbg(ctx, &var_info)?,
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

impl<'a, Ty: DebugType<'a>, V, Ctx> ParseWithDbgInfo<'a, Ty, Ctx> for Vec<V>
where
    V: ParseWithDbgInfo<'a, Ty, Ctx>,
    Ctx: ParseCtx,
{
    fn parse_with_dbg(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
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
            let item = V::parse_with_dbg(ctx, &item_info)?;
            out.push(item);
        }

        Ok(out)
    }
}

impl<'a, Ty: DebugType<'a>, V, Ctx> ParseWithDbgInfo<'a, Ty, Ctx> for Box<[V]>
where
    V: ParseWithDbgInfo<'a, Ty, Ctx>,
    Ctx: ParseCtx,
{
    fn parse_with_dbg(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
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
            let item = V::parse_with_dbg(ctx, &item_info)?;
            out.push(item);
        }

        Ok(out.into_boxed_slice())
    }
}

impl<'a, Ty: DebugType<'a>, V, Ctx, const N: usize> ParseWithDbgInfo<'a, Ty, Ctx> for [V; N]
where
    V: ParseWithDbgInfo<'a, Ty, Ctx>,
    Ctx: ParseCtx,
{
    fn parse_with_dbg(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
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
            let item = V::parse_with_dbg(ctx, &slice_info)?;
            items.push(item);
        }
        let Ok(arr) = items.try_into() else {
            unreachable!();
        };
        Ok(arr)
    }
}

impl<'a, Ty: DebugType<'a>, Ctx: ParseCtx> ParseWithDbgInfo<'a, Ty, Ctx> for String {
    fn parse_with_dbg(ctx: &Ctx, info: &TypeInfoRef<'_, 'a, Ty>) -> Result<Self> {
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

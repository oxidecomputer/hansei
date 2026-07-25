//! Typed views over a buffer of target memory: [`TypeInfo`] owns its bytes,
//! [`TypeInfoRef`] borrows them. Both navigate a value's structure -- members,
//! pointees, array elements, enum variants -- without rendering anything.

use crate::debug_type::{DebugMember, DebugType, TypeKind};
use crate::parse::{ParseCtx, ParseWithDbgInfo};
use crate::target::ReadFromProc;
use crate::{Error, Result};

use std::fmt;

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
    pub(crate) _marker: std::marker::PhantomData<&'a ()>,
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
    ///
    /// Peeling stops early at a member the buffer cannot cover, returning the
    /// outermost type whose bytes are intact rather than descending past the
    /// end of the value.
    pub fn peel(self) -> TypeInfoRef<'buf, 'a, T> {
        let mut info = self;

        loop {
            // A type whose own display format is a leaf (a `Str`, a `Slice`, …)
            // must render through that format, not be peeled into its
            // representation. Without this, a `String`/`Utf8PathBuf` payload — a
            // single-member wrapper around `Vec<u8>` — peels past its `Str`
            // format down to the inner `Vec`, rendering as a byte slice instead
            // of a string. A transparent `Alias` format is not a leaf, so peeling
            // still descends through atomics and newtype wrappers.
            if info.ty.is_display_leaf() {
                break;
            }

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

            // A member the buffer does not cover means the bytes in hand are
            // not the whole value — a short read, most often. Stop at the
            // outermost type whose bytes are intact and let the caller see a
            // buffer too short for its type, which the renderer reports as
            // `<truncated>`.
            let Some(bytes) = info.bytes.get(start..end) else {
                break;
            };
            info.bytes = bytes;
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

// ---------------------------------------------------------------------------
// ReadFromProc
// ---------------------------------------------------------------------------

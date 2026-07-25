//! Parsing Rust values out of a typed buffer.

use crate::debug_type::{DebugMember, DebugType, TypeKind};
use crate::target::ReadFromProc;
use crate::value::TypeInfoRef;
use crate::{Error, Result};

use proc::Mappings;

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

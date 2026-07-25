//! Parsing Rust values out of a typed buffer.

use crate::debug_type::{DebugType, TypeKind};
use crate::target::ReadFromProc;
use crate::value::TypeInfoRef;
use crate::{Error, Result};

pub trait ParseCtx {
    /// The target being read: a live process or core on illumos, or a
    /// captured snapshot anywhere.
    type Target: ReadFromProc;

    fn proc(&self) -> &Self::Target;
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
                addr: p + (i as u64) * param_size,
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

#[cfg(test)]
mod tests {
    use crate::TypeInfoRef;
    use crate::testhelper::*;

    use exegesis::bundle::BundleView;

    /// Every scalar parses from its own bytes, little-endian, and a buffer of
    /// the wrong width is an error rather than a silent misread.
    #[test]
    fn test_scalars_parse_from_their_own_bytes() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ctx = TestCtx::new(FakeMem::new());
        let u8_ty = v.ty(U8).unwrap();
        let u32_ty = v.ty(U32).unwrap();
        let u64_ty = v.ty(U64).unwrap();
        let bool_ty = v.ty(BOOL).unwrap();

        assert_eq!(
            TypeInfoRef::new(u8_ty, 0, &[7])
                .parse::<u8, _>(&ctx)
                .unwrap(),
            7
        );
        assert_eq!(
            TypeInfoRef::new(u8_ty, 0, &[0xff])
                .parse::<i8, _>(&ctx)
                .unwrap(),
            -1
        );
        assert!(
            TypeInfoRef::new(bool_ty, 0, &[1])
                .parse::<bool, _>(&ctx)
                .unwrap()
        );
        assert!(
            !TypeInfoRef::new(bool_ty, 0, &[0])
                .parse::<bool, _>(&ctx)
                .unwrap()
        );
        assert_eq!(
            TypeInfoRef::new(u32_ty, 0, &7u32.to_le_bytes())
                .parse::<u32, _>(&ctx)
                .unwrap(),
            7
        );
        assert_eq!(
            TypeInfoRef::new(u64_ty, 0, &(-2i64).to_le_bytes())
                .parse::<i64, _>(&ctx)
                .unwrap(),
            -2
        );
        assert_eq!(
            TypeInfoRef::new(u64_ty, 0, &1.5f64.to_le_bytes())
                .parse::<f64, _>(&ctx)
                .unwrap(),
            1.5
        );

        // A width mismatch is reported, not truncated or padded.
        assert!(
            TypeInfoRef::new(u32_ty, 0, &7u64.to_le_bytes())
                .parse::<u32, _>(&ctx)
                .is_err()
        );
        assert!(
            TypeInfoRef::new(u8_ty, 0, &[])
                .parse::<u8, _>(&ctx)
                .is_err()
        );
        assert!(
            TypeInfoRef::new(u8_ty, 0, &[])
                .parse::<i8, _>(&ctx)
                .is_err()
        );
        assert!(
            TypeInfoRef::new(bool_ty, 0, &[0, 0])
                .parse::<bool, _>(&ctx)
                .is_err()
        );
    }

    /// `Option<V>` reads the active variant and parses the payload, and says so
    /// when the enum is not an option at all.
    #[test]
    fn test_option_parses_through_its_variant() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ctx = TestCtx::new(FakeMem::new());
        let opt = v.ty(OPT).unwrap();

        // Opt is a niche enum: discriminant 0 is None, anything else is Some.
        let none_bytes = 0u64.to_le_bytes();
        let none = TypeInfoRef::new(opt, 0, &none_bytes);
        assert_eq!(none.parse::<Option<u64>, _>(&ctx).unwrap(), None);
        let some_bytes = 42u64.to_le_bytes();
        let some = TypeInfoRef::new(opt, 0, &some_bytes);
        assert_eq!(some.parse::<Option<u64>, _>(&ctx).unwrap(), Some(42));

        // A two-variant enum whose variants are not None/Some is rejected by
        // name rather than guessed at.
        let msg = TypeInfoRef::new(v.ty(MSG).unwrap(), 0, &[1u8; 16]);
        assert!(msg.parse::<Option<u64>, _>(&ctx).is_err());
    }

    /// A fixed-size array parses element by element from its own bytes.
    #[test]
    fn test_array_parses_each_element() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ctx = TestCtx::new(FakeMem::new());
        let bytes = u32s(&[10, 20, 30]);
        let arr = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &bytes);
        assert_eq!(arr.parse::<[u32; 3], _>(&ctx).unwrap(), [10, 20, 30]);

        // The buffer must be exactly the array; a short one is an error.
        let short = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &bytes[..8]);
        assert!(short.parse::<[u32; 3], _>(&ctx).is_err());
    }

    /// A boxed slice and a string both follow a `(data_ptr, length)` pair into
    /// the target. The elements are addressed from the buffer they were read
    /// from, not from the fat pointer's own address.
    #[test]
    fn test_boxed_slice_and_string_read_through_the_target() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ctx = TestCtx::new(
            FakeMem::new()
                .at(0x2000, vec![1u8, 2, 3, 4])
                .at(0x3000, b"hello".to_vec()),
        );

        // `&[u32]` in the fixture is (data_ptr: *u8, length), so it parses as a
        // boxed slice of bytes.
        let fat = u64s(&[0x2000, 4]);
        let slice = TypeInfoRef::new(v.ty(SLICE).unwrap(), 0x9000, &fat);
        assert_eq!(
            slice.parse::<Box<[u8]>, _>(&ctx).unwrap().as_ref(),
            &[1u8, 2, 3, 4]
        );

        let fat = u64s(&[0x3000, 5]);
        let text = TypeInfoRef::new(v.ty(SLICE).unwrap(), 0x9000, &fat);
        assert_eq!(text.parse::<String, _>(&ctx).unwrap(), "hello");

        // An unreadable buffer is an error, not an empty result.
        let ctx = TestCtx::new(FakeMem::new().unreadable());
        let fat = u64s(&[0x2000, 4]);
        let slice = TypeInfoRef::new(v.ty(SLICE).unwrap(), 0, &fat);
        assert!(slice.parse::<Box<[u8]>, _>(&ctx).is_err());
    }
}

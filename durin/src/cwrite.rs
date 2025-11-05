use crate::Endian;
use crate::error::{Error, Result};

use std::borrow::Cow;

// TODO just use a fixed context?
pub(crate) trait TryIntoBytes<Ctx = (), Bytes: ?Sized = [u8]>: Sized {
    fn try_into_bytes(&self, bytes: &mut Bytes, ctx: Ctx) -> Result<usize>;
}

impl TryIntoBytes for &[u8] {
    #[inline]
    fn try_into_bytes(&self, bytes: &mut [u8], _ctx: ()) -> Result<usize> {
        let Some(target) = bytes.get_mut(..self.len()) else {
            return Err(Error::too_large(self.len(), bytes.len()));
        };

        target.copy_from_slice(self);

        Ok(self.len())
    }
}

impl TryIntoBytes for &str {
    #[inline]
    fn try_into_bytes(&self, bytes: &mut [u8], ctx: ()) -> Result<usize> {
        self.as_bytes().try_into_bytes(bytes, ctx)
    }
}

impl TryIntoBytes for String {
    #[inline]
    fn try_into_bytes(&self, bytes: &mut [u8], ctx: ()) -> Result<usize> {
        self.as_bytes().try_into_bytes(bytes, ctx)
    }
}

impl TryIntoBytes for Cow<'_, str> {
    #[inline]
    fn try_into_bytes(&self, bytes: &mut [u8], ctx: ()) -> Result<usize> {
        self.as_bytes().try_into_bytes(bytes, ctx)
    }
}

impl TryIntoBytes for Cow<'_, [u8]> {
    #[inline]
    fn try_into_bytes(&self, bytes: &mut [u8], ctx: ()) -> Result<usize> {
        self.as_ref().try_into_bytes(bytes, ctx)
    }
}

macro_rules! numeric_try_into_bytes_impl {
    ($num_ty:ty) => {
        impl TryIntoBytes<Endian> for $num_ty {
            #[inline]
            fn try_into_bytes(&self, bytes: &mut [u8], endian: Endian) -> Result<usize> {
                self.to_endian_bytes(endian)
                    .as_slice()
                    .try_into_bytes(bytes, ())
            }
        }
    };
}

numeric_try_into_bytes_impl!(i32);
numeric_try_into_bytes_impl!(u32);
numeric_try_into_bytes_impl!(i64);
numeric_try_into_bytes_impl!(u64);
numeric_try_into_bytes_impl!(f64);

/// TODO
pub trait IsUnit: private::Sealed {}

impl IsUnit for () {}
impl private::Sealed for () {}

mod private {
    pub trait Sealed {}
}

/// Write an object into a byte slice, advancing a cursor on success.
pub(crate) trait CursorWrite<Ctx> {
    fn cwrite_ctx<T: TryIntoBytes<Ctx, Self>>(
        &mut self,
        n: &T,
        offset: &mut usize,
        ctx: Ctx,
    ) -> Result<()>;

    fn cwrite<T>(&mut self, n: &T, offset: &mut usize) -> Result<()>
    where
        T: TryIntoBytes<Ctx, Self>,
        Ctx: IsUnit + Default,
    {
        self.cwrite_ctx(n, offset, Ctx::default())
    }
}

impl<Ctx> CursorWrite<Ctx> for [u8] {
    fn cwrite_ctx<T: TryIntoBytes<Ctx>>(
        &mut self,
        n: &T,
        offset: &mut usize,
        ctx: Ctx,
    ) -> Result<()> {
        let start = *offset;

        let Some(bytes) = self.get_mut(start..) else {
            return Err(Error::out_of_bounds(start, self.len()));
        };

        let len = n.try_into_bytes(bytes, ctx)?;
        *offset = offset
            .checked_add(len)
            .ok_or_else(|| Error::offset_overflow(*offset, len))?;
        Ok(())
    }
}

pub(crate) trait ToEndianBytes: Sized {
    type ByteArray;

    fn to_endian_bytes(&self, endian: Endian) -> Self::ByteArray;
}

macro_rules! to_endian_bytes_impl {
    ($num_ty:ty) => {
        impl ToEndianBytes for $num_ty {
            type ByteArray = [u8; size_of::<$num_ty>()];

            fn to_endian_bytes(&self, endian: Endian) -> Self::ByteArray {
                match endian {
                    Endian::Big => self.to_be_bytes(),
                    Endian::Little => self.to_le_bytes(),
                }
            }
        }
    };
}

to_endian_bytes_impl!(u64);
to_endian_bytes_impl!(i64);
to_endian_bytes_impl!(u32);
to_endian_bytes_impl!(i32);
to_endian_bytes_impl!(f64);

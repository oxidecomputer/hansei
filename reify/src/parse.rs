//! Parsing Rust values out of a typed buffer.

use crate::target::ReadFromProc;
use crate::value::Value;
use crate::{Error, Result};

/// Parse a byte slice as a type using debug type information.
///
/// `proc` lends borrows good for `'a` rather than ones tied to the call, so
/// the bytes a read serves outlive it — which is what lets a parsed view keep
/// pointing at the mapped core instead of at a copy.
pub trait ParseWithDbgInfo<'a>: Sized {
    /// Attempt to read `Self` from the debug type information.
    fn parse_with_dbg(proc: &'a dyn ReadFromProc, info: &Value<'a>) -> Result<Self>;
}

impl<'a> ParseWithDbgInfo<'a> for bool {
    fn parse_with_dbg(_proc: &'a dyn ReadFromProc, info: &Value<'a>) -> Result<Self> {
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
        impl<'a> ParseWithDbgInfo<'a> for $num_ty {
            fn parse_with_dbg(_proc: &'a dyn ReadFromProc, info: &Value<'a>) -> Result<Self> {
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
num_impl!(u8);
num_impl!(u16);
num_impl!(u32);
num_impl!(u64);
num_impl!(i8);
num_impl!(i16);
num_impl!(i32);
num_impl!(i64);
num_impl!(f32);
num_impl!(f64);

impl<'a, V> ParseWithDbgInfo<'a> for Option<V>
where
    V: ParseWithDbgInfo<'a>,
{
    fn parse_with_dbg(proc: &'a dyn ReadFromProc, info: &Value<'a>) -> Result<Self> {
        let var = info.active_variant()?;
        let value = match var {
            ("Some", var_info) => V::parse_with_dbg(proc, &var_info)?,
            ("None", _) => return Ok(None),
            (s, _) => {
                return Err(Error::no_variant(info.ty.name().to_string(), s.to_string()));
            }
        };

        Ok(Some(value))
    }
}

/// Every sequence parses the same way — an owned `Vec`, a boxed or borrowed
/// slice, an inline array — because [`Elements`](crate::Elements) has already
/// reduced them all to a count, a stride and the bytes.
///
/// A sequence the target could not serve whole is an error rather than a
/// short `Vec`: a caller collecting into one has no way to notice the
/// difference, and quietly dropping the tail of a task list is worse than
/// failing to read it.
impl<'a, V> ParseWithDbgInfo<'a> for Vec<V>
where
    V: ParseWithDbgInfo<'a>,
{
    fn parse_with_dbg(proc: &'a dyn ReadFromProc, info: &Value<'a>) -> Result<Self> {
        let elements = info.elements(proc)?;
        if let Some(claimed) = elements.truncated() {
            return Err(Error::short_sequence(
                info.ty.name(),
                claimed,
                elements.len(),
            ));
        }
        elements
            .iter()
            .map(|element| V::parse_with_dbg(proc, &element))
            .collect()
    }
}

impl<'a, V> ParseWithDbgInfo<'a> for Box<[V]>
where
    V: ParseWithDbgInfo<'a>,
{
    fn parse_with_dbg(proc: &'a dyn ReadFromProc, info: &Value<'a>) -> Result<Self> {
        Ok(Vec::<V>::parse_with_dbg(proc, info)?.into_boxed_slice())
    }
}

impl<'a, V, const N: usize> ParseWithDbgInfo<'a> for [V; N]
where
    V: ParseWithDbgInfo<'a>,
{
    fn parse_with_dbg(proc: &'a dyn ReadFromProc, info: &Value<'a>) -> Result<Self> {
        let items = Vec::<V>::parse_with_dbg(proc, info)?;
        // The array's own length is the type's, not the target's, so a
        // count that disagrees is a type mismatch rather than bad data.
        items
            .try_into()
            .map_err(|items: Vec<V>| Error::unexpected_len(items.len() as u32, N as u32))
    }
}

/// A UTF-8 buffer reads through the `Str` display program the bundle carries,
/// which is what knows where a `String` keeps its pointer — the same
/// arrangement, and the same refusal to believe a length further than the
/// target corroborates it, as the sequences above.
impl<'a> ParseWithDbgInfo<'a> for String {
    fn parse_with_dbg(proc: &'a dyn ReadFromProc, info: &Value<'a>) -> Result<Self> {
        let text = crate::elements::utf8(info, proc)?;
        if let Some(claimed) = text.claimed {
            return Err(Error::short_sequence(info.ty.name(), claimed, text.count));
        }
        Ok(String::from_utf8_lossy(text.bytes).to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::Value;
    use crate::testhelper::*;

    use exegesis::bundle::BundleView;

    /// Every scalar parses from its own bytes, little-endian, and a buffer of
    /// the wrong width is an error rather than a silent misread.
    #[test]
    fn test_scalars_parse_from_their_own_bytes() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new();
        let u8_ty = v.ty(U8).unwrap();
        let u32_ty = v.ty(U32).unwrap();
        let u64_ty = v.ty(U64).unwrap();
        let bool_ty = v.ty(BOOL).unwrap();

        assert_eq!(Value::new(u8_ty, 0, &[7]).parse::<u8>(&mem).unwrap(), 7);
        assert_eq!(Value::new(u8_ty, 0, &[0xff]).parse::<i8>(&mem).unwrap(), -1);
        assert!(Value::new(bool_ty, 0, &[1]).parse::<bool>(&mem).unwrap());
        assert!(!Value::new(bool_ty, 0, &[0]).parse::<bool>(&mem).unwrap());
        assert_eq!(
            Value::new(u32_ty, 0, &7u32.to_le_bytes())
                .parse::<u32>(&mem)
                .unwrap(),
            7
        );
        assert_eq!(
            Value::new(u64_ty, 0, &(-2i64).to_le_bytes())
                .parse::<i64>(&mem)
                .unwrap(),
            -2
        );
        assert_eq!(
            Value::new(u64_ty, 0, &1.5f64.to_le_bytes())
                .parse::<f64>(&mem)
                .unwrap(),
            1.5
        );

        // A width mismatch is reported, not truncated or padded.
        assert!(
            Value::new(u32_ty, 0, &7u64.to_le_bytes())
                .parse::<u32>(&mem)
                .is_err()
        );
        assert!(Value::new(u8_ty, 0, &[]).parse::<u8>(&mem).is_err());
        assert!(Value::new(u8_ty, 0, &[]).parse::<i8>(&mem).is_err());
        assert!(Value::new(bool_ty, 0, &[0, 0]).parse::<bool>(&mem).is_err());
    }

    /// `Option<V>` reads the active variant and parses the payload, and says so
    /// when the enum is not an option at all.
    #[test]
    fn test_option_parses_through_its_variant() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new();
        let opt = v.ty(OPT).unwrap();

        // Opt is a niche enum: discriminant 0 is None, anything else is Some.
        let none_bytes = 0u64.to_le_bytes();
        let none = Value::new(opt, 0, &none_bytes);
        assert_eq!(none.parse::<Option<u64>>(&mem).unwrap(), None);
        let some_bytes = 42u64.to_le_bytes();
        let some = Value::new(opt, 0, &some_bytes);
        assert_eq!(some.parse::<Option<u64>>(&mem).unwrap(), Some(42));

        // A two-variant enum whose variants are not None/Some is rejected by
        // name rather than guessed at.
        let msg = Value::new(v.ty(MSG).unwrap(), 0, &[1u8; 16]);
        assert!(msg.parse::<Option<u64>>(&mem).is_err());
    }

    /// A fixed-size array parses element by element from its own bytes.
    #[test]
    fn test_array_parses_each_element() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new();
        let bytes = u32s(&[10, 20, 30]);
        let arr = Value::new(v.ty(ARR).unwrap(), 0, &bytes);
        assert_eq!(arr.parse::<[u32; 3]>(&mem).unwrap(), [10, 20, 30]);

        // The buffer must be exactly the array; a short one is an error.
        let short = Value::new(v.ty(ARR).unwrap(), 0, &bytes[..8]);
        assert!(short.parse::<[u32; 3]>(&mem).is_err());
    }

    /// A sequence and a string both follow a `(data_ptr, length)` pair into
    /// the target. The elements are addressed from the buffer they were read
    /// from, not from the fat pointer's own address.
    #[test]
    fn test_boxed_slice_and_string_read_through_the_target() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new()
            .at(0x2000, u32s(&[1, 2, 3, 4]))
            .at(0x3000, b"hello".to_vec());

        // The fixture's `&[u32]` carries a byte-erased `data_ptr`, as a `Vec`
        // does; the element type comes from its display program, so this is a
        // sequence of `u32` and not of the pointer's bytes. Owned or boxed is
        // the caller's choice, over the same read.
        let fat = u64s(&[0x2000, 4]);
        let slice = Value::new(v.ty(SLICE).unwrap(), 0x9000, &fat);
        assert_eq!(
            slice.parse::<Box<[u32]>>(&mem).unwrap().as_ref(),
            &[1u32, 2, 3, 4]
        );
        assert_eq!(slice.parse::<Vec<u32>>(&mem).unwrap(), vec![1u32, 2, 3, 4]);

        let fat = u64s(&[0x3000, 5]);
        let text = Value::new(v.ty(SLICE).unwrap(), 0x9000, &fat);
        assert_eq!(text.parse::<String>(&mem).unwrap(), "hello");

        // An unreadable buffer is an error, not an empty result.
        let mem = FakeMem::new().unreadable();
        let fat = u64s(&[0x2000, 4]);
        let slice = Value::new(v.ty(SLICE).unwrap(), 0, &fat);
        assert!(slice.parse::<Box<[u32]>>(&mem).is_err());
    }
}

//! Reading the elements of a sequence-shaped value.
//!
//! A `Vec<T>`, a `Box<[T]>`, a `&[T]` and a `[T; N]` differ only in where they
//! keep their elements and how they say how many there are. [`Elements`]
//! answers both questions once, so nothing downstream has to know which
//! spelling it was handed — or where in the layout that spelling hides its
//! pointer, which is the bundle's business and not reify's.

use crate::debug_type::{DisplayNode, FatHeader, TypeKind};
use crate::parse::ParseCtx;
use crate::render::scalar::{read_u64_at, read_unsigned_at};
use crate::target::ReadFromProc;
use crate::value::TypeInfoRef;
use crate::{Error, Result};

use exegesis::bundle::BundleType;

use std::borrow::Cow;

/// The most bytes one sequence read asks a target for, whatever the value's
/// length claims.
///
/// The length that sizes the read is itself read out of the target, so
/// corrupt memory names whatever its bits say. [`ReadFromProc::readable_len`]
/// cuts that claim to what the target can actually serve, which settles it for
/// a core; a live process cannot answer cheaply and does not try, so this
/// ceiling is what stands between a garbage length and an allocation the size
/// it asked for. Override it per context with
/// [`ParseCtx::max_sequence_bytes`].
pub const MAX_SEQUENCE_BYTES: u64 = 64 * 1024 * 1024;

/// The elements of one sequence-shaped value, read and addressed.
///
/// Held rather than iterated directly because a buffered sequence's bytes are
/// read once, up front: the elements borrow from that read, and on a mapped
/// core it costs no copy at all.
#[derive(Clone, Debug)]
pub struct Elements<'buf, 'a> {
    element: BundleType<'a>,
    /// The address of element zero.
    base: u64,
    /// Bytes between successive elements; zero for a zero-sized element.
    stride: u64,
    /// How many elements `bytes` actually holds.
    count: u64,
    /// What the value's length said, when the target could not serve it.
    claimed: Option<u64>,
    bytes: Cow<'buf, [u8]>,
}

impl<'buf, 'a: 'buf> Elements<'buf, 'a> {
    /// How many elements are here to be read.
    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The type of the elements, as the sequence declares it.
    pub fn element_ty(&self) -> BundleType<'a> {
        self.element
    }

    /// The length the value claimed, when that is more than is here.
    ///
    /// A length believed no further than the target corroborates it is the
    /// only defence against a corrupt one, but a short read is not the same
    /// as a short sequence — so the shortfall is reported rather than
    /// silently rendered as the whole. What to do about it is the caller's:
    /// a parse fails, a display says how much it is showing.
    pub fn truncated(&self) -> Option<u64> {
        self.claimed
    }

    /// The element at `index`, handed over as the sequence's own element
    /// type, *unpeeled*: a recorded walk binding roots at that type, so
    /// descending a transparent wrapper here would start the walk below its
    /// root. A caller that wants the peeled view calls [`TypeInfoRef::peel`]
    /// itself.
    pub fn get(&self, index: u64) -> TypeInfoRef<'_, 'a> {
        // A zero-sized element has no bytes of its own; every one of
        // them sits at the base address with an empty buffer.
        let offset = index * self.stride;
        let slot = self
            .bytes
            .get(offset as usize..(offset + self.stride) as usize)
            .unwrap_or(&[]);
        TypeInfoRef::new(self.element, self.base + offset, slot)
    }

    /// The elements, in order; see [`Elements::get`] for what each is.
    pub fn iter(&self) -> impl Iterator<Item = TypeInfoRef<'_, 'a>> {
        (0..self.count).map(move |index| self.get(index))
    }

    /// Resolve `info` to its elements, reading a buffered sequence's bytes.
    ///
    /// Three shapes answer, in this order: the `Slice` display program the
    /// bundle carries, which is how every sequence whose elements live
    /// elsewhere is described and the only one that knows where a `Vec` keeps
    /// its pointer; an inline array, whose elements are the value's own
    /// bytes; and, for a bundle whose detector declined or predates the
    /// formatter, the bare `(data_ptr, length)` fat pointer.
    pub(crate) fn of<Ctx: ParseCtx>(
        info: &TypeInfoRef<'buf, 'a>,
        ctx: &'buf Ctx,
    ) -> Result<Elements<'buf, 'a>> {
        let ty = info.ty;
        let proc: &dyn ReadFromProc = ctx.proc();
        let max_bytes = ctx.max_sequence_bytes();

        if let Some(DisplayNode::Slice {
            header,
            element,
            element_size,
        }) = DisplayNode::resolve(ty)
        {
            let stride = u64::from(element_size);
            return Self::read_fat(&header, element, stride, info.bytes, Some(proc), max_bytes)
                .map_err(|e| e.into_error(ty.name()));
        }

        if let Some((element, count)) = ty.array_info() {
            return Ok(Elements {
                element,
                base: info.addr,
                stride: element.size(),
                count,
                claimed: None,
                bytes: Cow::Borrowed(info.bytes),
            });
        }

        let (Some(pointer), Some(length)) =
            (info.try_member("data_ptr")?, info.try_member("length")?)
        else {
            return Err(Error::not_a_sequence(ty.name()));
        };
        let Some(element) = pointer.ty.pointer_target() else {
            return Err(Error::unexpected_type(
                pointer.ty.kind(),
                TypeKind::Pointer,
                ty.name().to_string(),
            ));
        };
        let count: u64 = length.parse(ctx)?;
        let base: u64 = pointer.parse(ctx)?;
        let stride = element.size();
        let buffer = read_buffer(Some(proc), max_bytes, base, stride, count)
            .map_err(|e| e.into_error(ty.name()))?;
        Ok(Self::over(buffer, element, base, stride))
    }

    /// Resolve a `Slice` display program's header against `bytes` and read
    /// the buffer it describes — the one sequence read both the parse path
    /// and the slice renderer perform, so the validation of a header and the
    /// refusal to believe an uncorroborated length are written once.
    pub(crate) fn read_fat(
        header: &FatHeader,
        element: BundleType<'a>,
        stride: u64,
        bytes: &[u8],
        proc: Option<&'buf dyn ReadFromProc>,
        max_bytes: u64,
    ) -> std::result::Result<Elements<'buf, 'a>, SeqError> {
        let (base, count) = decode_header(bytes, header, stride)?;
        let buffer = read_buffer(proc, max_bytes, base, stride, count)?;
        Ok(Self::over(buffer, element, base, stride))
    }

    /// The elements a read buffer holds.
    fn over(buffer: Buffer<'buf>, element: BundleType<'a>, base: u64, stride: u64) -> Self {
        let Buffer {
            bytes,
            count,
            claimed,
        } = buffer;
        Elements {
            element,
            base,
            stride,
            count,
            claimed,
            bytes,
        }
    }
}

/// Why a sequence could not be read, shaped for either consumer: the parse
/// path upgrades it to an [`Error`] naming the sequence type, the render
/// path prints a degradation marker in the value's place.
pub(crate) enum SeqError {
    /// The header cannot describe a sequence; the reason, in prose.
    Invalid(&'static str),
    /// The target refused the buffer read outright.
    Unreadable(Error),
    /// A read was needed and no target is attached.
    NoTarget,
}

impl SeqError {
    /// The parse-path spelling.
    fn into_error(self, ty: &str) -> Error {
        match self {
            SeqError::Invalid(why) => Error::invalid_sequence(ty, why),
            SeqError::Unreadable(e) => e,
            // The parse path always attaches a target, so a read that found
            // none never actually reaches this.
            SeqError::NoTarget => Error::invalid_sequence(ty, "no target to read through"),
        }
    }
}

/// Decode and validate the `(pointer, length[, capacity])` words of `header`
/// against the value's own bytes, to the address of element zero and the
/// count the value claims. `stride` is the element width; a zero-sized
/// element allocates nothing, so its capacity bounds nothing (`Vec<()>`
/// reports `usize::MAX`).
fn decode_header(
    bytes: &[u8],
    header: &FatHeader,
    stride: u64,
) -> std::result::Result<(u64, u64), SeqError> {
    let count = read_unsigned_at(bytes, header.length_offset, u64::from(header.length_size))
        .ok_or(SeqError::Invalid("the length does not fit the value"))?;
    if let Some((offset, size)) = header.capacity {
        let capacity = read_unsigned_at(bytes, offset, u64::from(size))
            .ok_or(SeqError::Invalid("the capacity does not fit the value"))?;
        if stride != 0 && count > capacity {
            return Err(SeqError::Invalid("the length exceeds the capacity"));
        }
    }
    let base = read_u64_at(bytes, header.pointer_offset)
        .ok_or(SeqError::Invalid("the data pointer does not fit the value"))?;
    Ok((base, count))
}

/// One buffer read out of the target: the bytes served, how many whole units
/// of the requested stride they hold, and what the value's length claimed
/// when that is more than was served.
pub(crate) struct Buffer<'buf> {
    pub(crate) bytes: Cow<'buf, [u8]>,
    pub(crate) count: u64,
    pub(crate) claimed: Option<u64>,
}

/// The bytes of a UTF-8 buffer — a `String`, a `&str`, an owned path — read
/// through the `Str` display program the bundle carries, or through the bare
/// `(data_ptr, length)` pair where it carries none.
///
/// This is [`Elements::of`] for a sequence whose elements are bytes and whose
/// point is the bytes rather than the elements: same header, same validation,
/// same bound on a length that cannot be trusted, but one bulk read instead
/// of a typed view per byte.
pub(crate) fn utf8<'buf, Ctx: ParseCtx>(
    info: &TypeInfoRef<'buf, '_>,
    ctx: &'buf Ctx,
) -> Result<Buffer<'buf>> {
    let ty = info.ty;
    let proc: &dyn ReadFromProc = ctx.proc();
    let max_bytes = ctx.max_sequence_bytes();

    if let Some(DisplayNode::Str { header }) = DisplayNode::resolve(ty) {
        return utf8_buffer(&header, info.bytes, Some(proc), max_bytes)
            .map_err(|e| e.into_error(ty.name()));
    }

    let (Some(pointer), Some(length)) = (info.try_member("data_ptr")?, info.try_member("length")?)
    else {
        return Err(Error::not_a_sequence(ty.name()));
    };
    let length: u64 = length.parse(ctx)?;
    let base: u64 = pointer.parse(ctx)?;
    read_buffer(Some(proc), max_bytes, base, 1, length).map_err(|e| e.into_error(ty.name()))
}

/// Resolve a `Str` display program's header against `bytes` and read the
/// buffer it describes — [`Elements::read_fat`] for the string renderer and
/// parser, sharing the same header validation and length corroboration.
pub(crate) fn utf8_buffer<'buf>(
    header: &FatHeader,
    bytes: &[u8],
    proc: Option<&'buf dyn ReadFromProc>,
    max_bytes: u64,
) -> std::result::Result<Buffer<'buf>, SeqError> {
    let (base, length) = decode_header(bytes, header, 1)?;
    read_buffer(proc, max_bytes, base, 1, length)
}

/// Read `count` units of `stride` bytes from `base`, believing the count only
/// as far as it can be corroborated.
fn read_buffer<'buf>(
    proc: Option<&'buf dyn ReadFromProc>,
    max_bytes: u64,
    base: u64,
    stride: u64,
    count: u64,
) -> std::result::Result<Buffer<'buf>, SeqError> {
    let empty = |count, claimed| Buffer {
        bytes: Cow::Borrowed(&[][..]),
        count,
        claimed,
    };

    if count == 0 {
        return Ok(empty(0, None));
    }
    if base == 0 {
        return Err(SeqError::Invalid("the data pointer is null"));
    }
    if stride == 0 {
        // Nothing to read: a zero-sized element is entirely described by how
        // many of it there are. The ceiling still applies, since a corrupt
        // count would otherwise be iterated in full.
        return Ok(match count > max_bytes {
            true => empty(max_bytes, Some(count)),
            false => empty(count, None),
        });
    }

    let want = count
        .checked_mul(stride)
        .ok_or(SeqError::Invalid("the buffer size overflows"))?;
    base.checked_add(want)
        .ok_or(SeqError::Invalid("the buffer wraps the address space"))?;
    let proc = proc.ok_or(SeqError::NoTarget)?;

    // What the target says it can serve, capped: a length out of corrupt
    // memory otherwise sizes an allocation before the read that would have
    // refused it. Round down, so a partial trailing unit is not passed off
    // as a whole one.
    let servable = proc.readable_len(base, want.min(max_bytes));
    let served = servable - servable % stride;
    if served == 0 {
        return Ok(empty(0, Some(count)));
    }
    let bytes = proc
        .read_bytes(base, served)
        .map_err(SeqError::Unreadable)?;
    let got = served / stride;
    Ok(Buffer {
        bytes,
        count: got,
        claimed: (got < count).then_some(count),
    })
}

#[cfg(test)]
mod tests {
    use crate::TypeInfoRef;
    use crate::testhelper::*;

    use exegesis::bundle::BundleView;

    /// The elements of an owned buffer come from the display program the
    /// bundle carries, not from the pointer: a `Vec`'s is byte-erased, so the
    /// declared element type is the only thing that knows the stride.
    #[test]
    fn test_a_vec_reads_through_its_display_program() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ctx = TestCtx::new(FakeMem::new().at(0x2000, u32s(&[7, 8, 9])));

        // Vec { ptr: *u8 @0, len @8, capacity @16 }, elements `u32`.
        let header = u64s(&[0x2000, 3, 4]);
        let vec = TypeInfoRef::new(v.ty(VEC).unwrap(), 0x1000, &header);
        let elements = vec.elements(&ctx).expect("vec elements");
        assert_eq!(elements.len(), 3);
        assert_eq!(elements.element_ty().size(), 4);
        assert_eq!(
            elements
                .iter()
                .map(|e| (e.addr, format!("{}", e.display())))
                .collect::<Vec<_>>(),
            [
                (0x2000, "7".to_owned()),
                (0x2004, "8".to_owned()),
                (0x2008, "9".to_owned())
            ]
        );
        assert_eq!(vec.parse::<Vec<u32>, _>(&ctx).unwrap(), [7, 8, 9]);
    }

    /// A length is read out of the target like any other word, so a corrupt
    /// one names whatever its bits say. It is believed only as far as the
    /// target corroborates it, and never past the ceiling -- and the
    /// shortfall is reported rather than passed off as the whole sequence.
    #[test]
    fn test_a_length_is_believed_only_as_far_as_it_is_served() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = || FakeMem::new().at(0x2000, u32s(&[7, 8, 9]));

        // A thousand elements claimed, three there to be read.
        let header = u64s(&[0x2000, 1000]);
        let ctx = TestCtx::new(mem());
        let slice = TypeInfoRef::new(v.ty(SLICE).unwrap(), 0x1000, &header);
        let elements = slice.elements(&ctx).expect("slice elements");
        assert_eq!(elements.len(), 3);
        assert_eq!(elements.truncated(), Some(1000));

        // Where the target cannot say -- a live process -- the ceiling is
        // what bounds the read. Two whole elements fit in eight bytes.
        let ctx = TestCtx::new(mem()).with_max_sequence_bytes(8);
        let elements = slice.elements(&ctx).expect("slice elements");
        assert_eq!(elements.len(), 2);
        assert_eq!(elements.truncated(), Some(1000));

        // A short read is not a short sequence: collecting one is an error,
        // not a `Vec` quietly missing its tail.
        assert!(slice.parse::<Vec<u32>, _>(&ctx).is_err());
    }

    /// A header that cannot describe any sequence is refused before it is
    /// used to size a read.
    #[test]
    fn test_an_impossible_header_is_refused() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ctx = TestCtx::new(FakeMem::new().at(0x2000, u32s(&[7, 8, 9])));
        let vec = |header: &[u8]| {
            TypeInfoRef::new(v.ty(VEC).unwrap(), 0x1000, header)
                .elements(&ctx)
                .map(|e| e.len())
        };

        // More elements than the allocation they claim to live in.
        assert!(vec(&u64s(&[0x2000, 5, 3])).is_err());
        // A null buffer with elements in it.
        assert!(vec(&u64s(&[0, 3, 3])).is_err());
        // A length whose buffer does not fit the address space.
        assert!(vec(&u64s(&[0x2000, u64::MAX / 2, u64::MAX])).is_err());
        // A header the value's own bytes do not cover.
        assert!(vec(&u64s(&[0x2000, 3])).is_err());

        // An empty sequence is not read at all, whatever its pointer says.
        let ctx = TestCtx::new(FakeMem::new().panic_on_unmapped());
        let header = u64s(&[0xdead_0000, 0, 0]);
        let empty = TypeInfoRef::new(v.ty(VEC).unwrap(), 0x1000, &header)
            .elements(&ctx)
            .expect("an empty vec");
        assert!(empty.is_empty());
        assert_eq!(empty.iter().count(), 0);
    }

    /// A UTF-8 buffer reads through its own display program and gets the same
    /// checks a sequence does: an owned `String` names a capacity to be held
    /// to, a borrowed `&str` does not, and neither believes a length past
    /// what the target can serve.
    #[test]
    fn test_a_string_reads_through_its_display_program() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ctx = TestCtx::new(FakeMem::new().at(0x2000, b"hello".to_vec()));
        let text = |id, header: &[u8]| {
            TypeInfoRef::new(v.ty(id).unwrap(), 0x1000, header).parse::<String, _>(&ctx)
        };

        // String { ptr @0, len @8, capacity @16 }, then &str { ptr, len }.
        assert_eq!(text(STRING, &u64s(&[0x2000, 5, 8])).unwrap(), "hello");
        assert_eq!(text(STR, &u64s(&[0x2000, 5])).unwrap(), "hello");

        // More bytes than the allocation that holds them.
        assert!(text(STRING, &u64s(&[0x2000, 9, 8])).is_err());
        // A length the target cannot serve is an error, not a short string.
        assert!(text(STRING, &u64s(&[0x2000, 500, 500])).is_err());
        assert!(text(STR, &u64s(&[0x2000, 500])).is_err());
    }

    /// A type with no sequence shape at all says so, rather than reading
    /// whatever happens to sit at its first two words.
    #[test]
    fn test_a_type_that_is_not_a_sequence_declines() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ctx = TestCtx::new(FakeMem::new());
        let bytes = u32s(&[1, 2]);
        let point = TypeInfoRef::new(v.ty(POINT).unwrap(), 0x1000, &bytes);
        assert!(point.elements(&ctx).is_err());
    }
}

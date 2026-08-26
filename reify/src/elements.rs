//! Reading the elements of a sequence-shaped value.
//!
//! A `Vec<T>`, a `Box<[T]>`, a `&[T]` and a `[T; N]` differ only in where they
//! keep their elements and how they say how many there are. [`Elements`]
//! answers both questions once, so nothing downstream has to know which
//! spelling it was handed — or where in the layout that spelling hides its
//! pointer, which is the bundle's business and not reify's.

use crate::debug_type::{DisplayNode, FatHeader, TypeKind};
use crate::heap::{Gate, Heap, Liveness};
use crate::render::scalar::{read_u64_at, read_unsigned_at};
use crate::value::Value;
use crate::{Error, Result};
use proc::Target;

use hansei_bundle::BundleType;

/// The most elements a zero-sized sequence is credited with.
///
/// A sequence of sized elements is believed only as far as the target can
/// serve its bytes, but a zero-sized element has no bytes to corroborate a
/// count with — any claim at all costs nothing to read and everything to
/// iterate. This is the one place a count is bounded by fiat.
const MAX_ZST_ELEMENTS: u64 = 64 * 1024 * 1024;

/// Why a sequence rendered shorter than it said it was.
///
/// Only meaningful beside a claimed length; the three are different
/// facts about the same shortfall and a reader should not have to guess
/// which one happened. [`Unreadable`](Shortfall::Unreadable) is the
/// target's answer, [`PastAllocation`](Shortfall::PastAllocation) the
/// allocator's, and [`PastCap`](Shortfall::PastCap) this renderer's own
/// choice — the only one of the three that says nothing is wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum Shortfall {
    /// The target could not serve the rest.
    #[default]
    Unreadable,
    /// The rest lies outside the allocation the buffer starts in, so it
    /// was never this sequence's however readable it is.
    PastAllocation,
    /// The rest was never asked for: the value is longer than the
    /// display cap. The bytes are presumably fine.
    PastCap,
}

/// The allocator's say in one buffer read.
///
/// A length word is read out of the target like any other, so a length
/// out of dead bytes claims whatever its bits say — and the target
/// happily serves the pages under the claim, because they are mapped
/// and belong to somebody. The allocation the buffer starts in is the
/// bound that catches it: a sequence cannot run past the end of its own
/// allocation and still be that sequence.
///
/// `owning` says whether the pointer being read from is one that owns
/// its whole allocation — a `Vec`'s or a `String`'s, which a capacity in
/// the header marks — as against a borrow legitimately pointing into
/// the middle of one. Only the first is expected to sit at an
/// allocation's base, and only for the first is a mismatch worth
/// counting.
#[derive(Clone, Copy, Default)]
pub(crate) struct HeapGate<'h> {
    heap: Option<&'h dyn Heap>,
    owning: bool,
}

impl<'h> HeapGate<'h> {
    /// The gate for reading the buffer `header` describes, which owns
    /// its allocation exactly when it carries a capacity.
    pub(crate) fn for_header(heap: Option<&'h dyn Heap>, header: &FatHeader) -> Self {
        HeapGate {
            heap,
            owning: header.capacity.is_some(),
        }
    }

    /// The gate for a read nothing corroborates: the parse path, and
    /// every render against a target whose allocator keeps no metadata.
    pub(crate) fn none() -> Self {
        HeapGate::default()
    }
}

/// The elements of one sequence-shaped value, read and addressed.
///
/// Held rather than iterated directly because a buffered sequence's bytes are
/// read once, up front: the elements borrow from that read, so it costs no
/// copy at all.
#[derive(Clone, Debug)]
pub struct Elements<'a> {
    element: BundleType<'a>,
    /// The address of element zero.
    base: u64,
    /// Bytes between successive elements; zero for a zero-sized element.
    stride: u64,
    /// How many elements `bytes` actually holds.
    count: u64,
    /// What the value's length said, when the target could not serve it.
    claimed: Option<u64>,
    /// Why the claim was not met, where it was not; see
    /// [`Elements::shortfall`].
    shortfall: Shortfall,
    bytes: &'a [u8],
}

impl<'a> Elements<'a> {
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

    /// Why [`truncated`](Elements::truncated) reports a shortfall, for
    /// a caller spelling one. Meaningless without a claim.
    pub(crate) fn shortfall(&self) -> Shortfall {
        self.shortfall
    }

    /// The element at `index`, handed over as the sequence's own element
    /// type, *unpeeled*: a recorded walk binding roots at that type, so
    /// descending a transparent wrapper here would start the walk below its
    /// root. A caller that wants the peeled view calls [`Value::peel`]
    /// itself.
    pub fn get(&self, index: u64) -> Value<'a> {
        // A zero-sized element has no bytes of its own; every one of
        // them sits at the base address with an empty buffer.
        let offset = index * self.stride;
        let slot = self
            .bytes
            .get(offset as usize..(offset + self.stride) as usize)
            .unwrap_or(&[]);
        Value::new(self.element, self.base + offset, slot)
    }

    /// The elements, in order; see [`Elements::get`] for what each is.
    pub fn iter(&self) -> impl Iterator<Item = Value<'a>> {
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
    pub(crate) fn of<T: Target>(info: &Value<'a>, proc: &'a T) -> Result<Elements<'a>> {
        let ty = info.ty;

        if let Some(DisplayNode::Slice {
            header,
            element,
            element_size,
        }) = DisplayNode::resolve(ty)
        {
            let stride = u64::from(element_size);
            // No cap on the parse path; see `utf8` below.
            return Self::read_fat(
                &header,
                element,
                stride,
                info.bytes,
                Some(proc),
                HeapGate::none(),
                None,
            )
            .map_err(|e| e.into_error(ty.name()));
        }

        if let Some((element, count)) = ty.array_info() {
            return Ok(Elements {
                element,
                base: info.addr,
                stride: element.size(),
                count,
                claimed: None,
                shortfall: Shortfall::default(),
                bytes: info.bytes,
            });
        }

        let (pointer, base, count) = bare_fat_pointer(info, proc)?;
        let Some(element) = pointer.ty.pointer_target() else {
            return Err(Error::unexpected_type(
                pointer.ty.kind(),
                TypeKind::Pointer,
                ty.name().to_string(),
            ));
        };
        let stride = element.size();
        let buffer = read_buffer(Some(proc), base, stride, count, HeapGate::none(), None)
            .map_err(|e| e.into_error(ty.name()))?;
        Ok(Self::over(buffer, element, base, stride))
    }

    /// Resolve a `Slice` display program's header against `bytes` and read
    /// the buffer it describes — the one sequence read both the parse path
    /// and the slice renderer perform, so the validation of a header and the
    /// refusal to believe an uncorroborated length are written once.
    pub(crate) fn read_fat<T: Target>(
        header: &FatHeader,
        element: BundleType<'a>,
        stride: u64,
        bytes: &[u8],
        proc: Option<&'a T>,
        gate: HeapGate<'_>,
        cap: Option<u64>,
    ) -> std::result::Result<Elements<'a>, SeqError> {
        let (base, count) = decode_header(bytes, header, stride)?;
        // `cap` is already the right budget for this stride: only the
        // caller knows whether a one-byte element makes this a string
        // in all but type.
        let buffer = read_buffer(proc, base, stride, count, gate, cap)?;
        Ok(Self::over(buffer, element, base, stride))
    }

    /// The elements a read buffer holds.
    fn over(buffer: Buffer<'a>, element: BundleType<'a>, base: u64, stride: u64) -> Self {
        let Buffer {
            bytes,
            count,
            claimed,
            shortfall,
        } = buffer;
        Elements {
            element,
            base,
            stride,
            count,
            claimed,
            shortfall,
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
    /// The allocator says the buffer has been freed. Its bytes are
    /// whatever the last owner left, and none of them is this value.
    Freed,
    /// A read was needed and no target is attached.
    NoTarget,
}

impl SeqError {
    /// The parse-path spelling.
    fn into_error(self, ty: &str) -> Error {
        match self {
            SeqError::Invalid(why) => Error::invalid_sequence(ty, why),
            SeqError::Unreadable(e) => e,
            SeqError::Freed => Error::invalid_sequence(ty, "its buffer has been freed"),
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
pub(crate) struct Buffer<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) count: u64,
    pub(crate) claimed: Option<u64>,
    /// Why the claim was not met; see [`Elements::shortfall`].
    pub(crate) shortfall: Shortfall,
}

/// The bytes of a UTF-8 buffer — a `String`, a `&str`, an owned path — read
/// through the `Str` display program the bundle carries, or through the bare
/// `(data_ptr, length)` pair where it carries none.
///
/// This is [`Elements::of`] for a sequence whose elements are bytes and whose
/// point is the bytes rather than the elements: same header, same validation,
/// same bound on a length that cannot be trusted, but one bulk read instead
/// of a typed view per byte.
pub(crate) fn utf8<'a, T: Target>(info: &Value<'a>, proc: &'a T) -> Result<Buffer<'a>> {
    let ty = info.ty;

    if let Some(DisplayNode::Str { header }) = DisplayNode::resolve(ty) {
        // No cap on the parse path: a caller collecting a `String` is
        // reading a datum, not showing one, and a quietly shortened
        // one would be wrong rather than merely abbreviated.
        return utf8_buffer(&header, info.bytes, Some(proc), HeapGate::none(), None)
            .map_err(|e| e.into_error(ty.name()));
    }

    let (_, base, length) = bare_fat_pointer(info, proc)?;
    read_buffer(Some(proc), base, 1, length, HeapGate::none(), None)
        .map_err(|e| e.into_error(ty.name()))
}

/// Decode the bare `(data_ptr, length)` members of `info` — the shared
/// fallback for a bundle whose detector declined or predates the `Str`/
/// `Slice` formatters — to the pointer's own view (whose type names the
/// element), the base address, and the claimed count. A value without the
/// pair is not a sequence at all.
fn bare_fat_pointer<'a, T: Target>(info: &Value<'a>, proc: &'a T) -> Result<(Value<'a>, u64, u64)> {
    let (Some(pointer), Some(length)) = (info.try_member("data_ptr")?, info.try_member("length")?)
    else {
        return Err(Error::not_a_sequence(info.ty.name()));
    };
    let count: u64 = length.parse(proc)?;
    let base: u64 = pointer.parse(proc)?;
    Ok((pointer, base, count))
}

/// Resolve a `Str` display program's header against `bytes` and read the
/// buffer it describes — [`Elements::read_fat`] for the string renderer and
/// parser, sharing the same header validation and length corroboration.
pub(crate) fn utf8_buffer<'a, T: Target>(
    header: &FatHeader,
    bytes: &[u8],
    proc: Option<&'a T>,
    gate: HeapGate<'_>,
    cap: Option<u64>,
) -> std::result::Result<Buffer<'a>, SeqError> {
    let (base, length) = decode_header(bytes, header, 1)?;
    // The cap bounds the *read*, not the write: a length out of dead
    // bytes otherwise reaches the target for every mapped page it
    // claims, and the escaped rendering of what comes back is several
    // times the size again. Bounding it here is what keeps a corrupt
    // header from costing gigabytes to print.
    read_buffer(proc, base, 1, length, gate, cap)
}

/// Read `count` units of `stride` bytes from `base`, believing the count only
/// as far as it can be corroborated.
fn read_buffer<'a, T: Target>(
    proc: Option<&'a T>,
    base: u64,
    stride: u64,
    count: u64,
    gate: HeapGate<'_>,
    cap: Option<u64>,
) -> std::result::Result<Buffer<'a>, SeqError> {
    let empty = |count, claimed, shortfall| Buffer {
        bytes: &[][..],
        count,
        claimed,
        shortfall,
    };

    if count == 0 {
        return Ok(empty(0, None, Shortfall::default()));
    }
    if base == 0 {
        return Err(SeqError::Invalid("the data pointer is null"));
    }
    if stride == 0 {
        // Nothing to read: a zero-sized element is entirely described by how
        // many of it there are — which also means nothing corroborates the
        // count, so it alone gets a ceiling rather than a read's refusal.
        return Ok(match count > MAX_ZST_ELEMENTS {
            true => empty(MAX_ZST_ELEMENTS, Some(count), Shortfall::default()),
            false => empty(count, None, Shortfall::default()),
        });
    }

    // Judged before it is cut down: a header that cannot describe any
    // sequence says so whatever the display budget is, and clipping
    // first would hide an impossible length behind a short read.
    let want = count
        .checked_mul(stride)
        .ok_or(SeqError::Invalid("the buffer size overflows"))?;
    base.checked_add(want)
        .ok_or(SeqError::Invalid("the buffer wraps the address space"))?;
    let proc = proc.ok_or(SeqError::NoTarget)?;

    // Now the budget, in elements — which for a one-byte element is the
    // same number of bytes.
    let (want, capped) = match cap {
        Some(cap) if cap < count => (cap * stride, true),
        _ => (want, false),
    };
    let (want, allocation) = bound_to_allocation(gate, base, want)?;
    // The allocator's verdict outranks the budget: one says these bytes
    // were never the value's, the other only that they were not asked
    // for.
    let shortfall = match (allocation, capped) {
        (Shortfall::PastAllocation, _) => Shortfall::PastAllocation,
        (_, true) => Shortfall::PastCap,
        _ => Shortfall::default(),
    };

    // What the target says it can serve: a length out of corrupt memory
    // otherwise sizes an allocation before the read that would have refused
    // it. Round down, so a partial trailing unit is not passed off as a
    // whole one.
    let servable = proc.readable_len(base, want);
    let served = servable - servable % stride;
    // Coming up short of what was *asked for* outranks both of the
    // reasons above: they explain the part deliberately not asked for,
    // and a reader told "not shown" would take the rest to be fine.
    // Asking for nothing and getting nothing is not coming up short.
    let short_read = served < want;
    if served == 0 {
        let why = match want {
            0 => shortfall,
            _ => Shortfall::Unreadable,
        };
        return Ok(empty(0, Some(count), why));
    }
    let bytes = crate::target::read_bytes(proc, base, served).map_err(SeqError::Unreadable)?;
    let got = served / stride;
    Ok(Buffer {
        bytes,
        count: got,
        claimed: (got < count).then_some(count),
        shortfall: match short_read {
            true => Shortfall::Unreadable,
            false => shortfall,
        },
    })
}

/// Cut `want` bytes at `base` down to what the allocation holding `base`
/// actually has room for, and say whether anything was cut.
///
/// This runs *before* the read, so it also caps what a length out of dead
/// bytes can make the reader ask for — until now that was
/// [`Target::readable_len`]'s job alone, and a mapped page is readable
/// whoever it belongs to.
fn bound_to_allocation(
    gate: HeapGate<'_>,
    base: u64,
    want: u64,
) -> std::result::Result<(u64, Shortfall), SeqError> {
    let Some(heap) = gate.heap else {
        return Ok((want, Shortfall::default()));
    };
    // Whether the buffer starts where its allocation does is evidence
    // about the pointer, not yet grounds to refuse it: an owning pointer
    // that sits mid-allocation is one that was never this value's.
    if gate.owning && heap.owns(base) == Some(false) {
        heap.note(Gate::BaseMismatch);
    }
    match heap.locate(base) {
        Liveness::Freed => {
            heap.note(Gate::Freed);
            Err(SeqError::Freed)
        }
        Liveness::Live { block } if block.end - base < want => {
            heap.note(Gate::Clipped);
            Ok((block.end - base, Shortfall::PastAllocation))
        }
        _ => Ok((want, Shortfall::default())),
    }
}

#[cfg(test)]
mod tests {
    use crate::Value;
    use crate::testhelper::*;

    use hansei_bundle::BundleView;

    /// The elements of an owned buffer come from the display program the
    /// bundle carries, not from the pointer: a `Vec`'s is byte-erased, so the
    /// declared element type is the only thing that knows the stride.
    #[test]
    fn test_a_vec_reads_through_its_display_program() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x2000, u32s(&[7, 8, 9]));

        // Vec { ptr: *u8 @0, len @8, capacity @16 }, elements `u32`.
        let header = u64s(&[0x2000, 3, 4]);
        let vec = Value::new(v.ty(VEC).unwrap(), 0x1000, &header);
        let elements = vec.elements(&mem).expect("vec elements");
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
        assert_eq!(vec.parse::<Vec<u32>>(&mem).unwrap(), [7, 8, 9]);
    }

    /// A zero-sized element leaves nothing for a read to corroborate, so the
    /// count alone is capped at the ceiling — at it, believed whole; past
    /// it, cut to the ceiling with the claim reported.
    #[test]
    fn test_a_zst_count_is_believed_only_to_the_ceiling() {
        let mem = FakeMem::new();
        let Ok(at) = super::read_buffer(
            Some(&mem),
            0x1000,
            0,
            super::MAX_ZST_ELEMENTS,
            super::HeapGate::none(),
            None,
        ) else {
            panic!("a count at the ceiling is served");
        };
        assert_eq!((at.count, at.claimed), (super::MAX_ZST_ELEMENTS, None));

        let Ok(past) = super::read_buffer(
            Some(&mem),
            0x1000,
            0,
            super::MAX_ZST_ELEMENTS + 1,
            super::HeapGate::none(),
            None,
        ) else {
            panic!("a count past the ceiling is capped, not refused");
        };
        assert_eq!(
            (past.count, past.claimed),
            (super::MAX_ZST_ELEMENTS, Some(super::MAX_ZST_ELEMENTS + 1))
        );
    }

    /// A length is read out of the target like any other word, so a corrupt
    /// one names whatever its bits say. It is believed only as far as the
    /// target corroborates it, and never past the ceiling -- and the
    /// shortfall is reported rather than passed off as the whole sequence.
    #[test]
    fn test_a_length_is_believed_only_as_far_as_it_is_served() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let fake = || FakeMem::new().at(0x2000, u32s(&[7, 8, 9]));

        // A thousand elements claimed, three there to be read.
        let header = u64s(&[0x2000, 1000]);
        let mem = fake();
        let slice = Value::new(v.ty(SLICE).unwrap(), 0x1000, &header);
        let elements = slice.elements(&mem).expect("slice elements");
        assert_eq!(elements.len(), 3);
        assert_eq!(elements.truncated(), Some(1000));

        // A short read is not a short sequence: collecting one is an error,
        // not a `Vec` quietly missing its tail.
        assert!(slice.parse::<Vec<u32>>(&mem).is_err());

        // A target that cannot bound a read refuses the whole read
        // instead of coming up short, and the claim is an error rather
        // than a truncation.
        let mem = fake().no_bounds();
        assert!(slice.elements(&mem).is_err());
    }

    /// A header that cannot describe any sequence is refused before it is
    /// used to size a read.
    #[test]
    fn test_an_impossible_header_is_refused() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x2000, u32s(&[7, 8, 9]));
        let vec = |header: &[u8]| {
            Value::new(v.ty(VEC).unwrap(), 0x1000, header)
                .elements(&mem)
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
        let mem = FakeMem::new().panic_on_unmapped();
        let header = u64s(&[0xdead_0000, 0, 0]);
        let empty = Value::new(v.ty(VEC).unwrap(), 0x1000, &header)
            .elements(&mem)
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
        let mem = FakeMem::new().at(0x2000, b"hello".to_vec());
        let text =
            |id, header: &[u8]| Value::new(v.ty(id).unwrap(), 0x1000, header).parse::<String>(&mem);

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
        let mem = FakeMem::new();
        let bytes = u32s(&[1, 2]);
        let point = Value::new(v.ty(POINT).unwrap(), 0x1000, &bytes);
        assert!(point.elements(&mem).is_err());
    }
}

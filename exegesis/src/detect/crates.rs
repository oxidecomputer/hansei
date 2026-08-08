//! Detectors for third-party crates (camino, uuid, parking_lot,
//! allocator-api2, digest newtypes). Each layout here moves on its own
//! crate's release cadence, independent of both the toolchain and tokio.

use super::ReachStep::{Named, PeelTo, Resolved};
use super::std::{VecShape, buffer_node, vec_shape};
use super::{
    Reach, Through, Want, find_unique, is_byte_array, is_unsigned_integer, reach, struct_of,
    unique_member,
};
use crate::bundle::{DisplayNode, Notation, ScalarDecode, Shape};
use crate::extract::{Emitter, fq_name};
use crate::{DwReader, TypeId};

/// Recognize `allocator_api2::stable::vec::Vec<T, A>`, the `allocator-api2`
/// crate's stable-channel reimplementation of `Vec`. It renders through the
/// same `Slice` node as [`vec_shape`]'s `alloc::vec::Vec`, but its buffer
/// has the pre-`RawVecInner` shape and so needs its own navigation: `buf` is a
/// `RawVec<T, A>` holding `ptr: NonNull<T>` and a plain `cap: usize` directly,
/// with no type-erased `Unique<u8>` and no `Cap` niche newtype. Because the
/// pointer is `NonNull<T>` over the real element (not a `u8` byte pointer), the
/// buffer pointer is matched by its element target rather than by width.
pub(super) fn allocator_api2_vec_shape(emitter: &mut Emitter<'_>, id: TypeId) -> Option<VecShape> {
    let reader = emitter.reader;
    let vec = struct_of(reader, id)?;
    if fq_name(reader, id)?.split('<').next()? != "allocator_api2::stable::vec::Vec" {
        return None;
    }
    let [element_param, alloc_param] = vec.template_params.as_ref() else {
        return None;
    };
    if element_param.name.map(|name| reader.strings.get(name)) != Some("T")
        || alloc_param.name.map(|name| reader.strings.get(name)) != Some("A")
    {
        return None;
    }
    let element = reader.canonicalize(element_param.type_id);
    let alloc = reader.canonicalize(alloc_param.type_id);

    let (_, buf_member) = unique_member(reader, &vec.members, "buf")?;
    unique_member(reader, &vec.members, "len")?;

    let raw_vec = struct_of(reader, buf_member.type_id)?;
    if fq_name(reader, buf_member.type_id)?.split('<').next()?
        != "allocator_api2::stable::raw_vec::RawVec"
    {
        return None;
    }
    let [raw_element, raw_alloc] = raw_vec.template_params.as_ref() else {
        return None;
    };
    if reader.canonicalize(raw_element.type_id) != element
        || reader.canonicalize(raw_alloc.type_id) != alloc
    {
        return None;
    }

    // `ptr` and `cap` sit at fixed offsets in `RawVec`, so a zero-offset walk
    // from the buffer yields exactly the one pointer that targets the element
    // type — `ptr.pointer` through the `NonNull<T>` wrapper.
    let is_element = |target| target == element;
    let (pointer_path, _) = find_unique(
        reader,
        buf_member.type_id,
        Want::PointerTo(&is_element),
        Through::ZeroOffset,
    )?;

    unique_member(reader, &raw_vec.members, "cap")?;

    let mut pointer = reach![Named("buf")];
    pointer.push(Resolved(pointer_path));
    Some(VecShape {
        pointer: emitter.walk(id, &pointer)?.0,
        length: emitter.walk(id, &reach![Named("len")])?.0,
        capacity: emitter.walk(id, &reach![Named("buf"), Named("cap")])?.0,
        element,
    })
}

/// A `uuid::Uuid` is a newtype over `[u8; 16]`, rendered in the hyphenated form
/// its own `Display` produces. Sixteen bytes is also an `Ipv6Addr`, so the
/// notation is what separates them, not the layout.
pub(super) fn uuid_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let bytes = || reach![Named("__0")];
    if !is_byte_array(emitter, id, &bytes(), Some(16)) {
        return None;
    }
    Some(DisplayNode::Bytes {
        at: emitter.walk(id, &bytes())?.0,
        notation: Notation::Uuid,
    })
}

/// A newtype over a byte array whose value is a digest — a TUF artifact hash, a
/// build id — rendered as the lowercase hex everything else that prints one
/// uses, so an id read out of a core can be matched against a log line or a
/// manifest. Any length: SHA-1 is 20 bytes, SHA-256 and BLAKE3 are 32.
pub(super) fn hex_bytes_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let bytes = || reach![Named("__0")];
    if !is_byte_array(emitter, id, &bytes(), None) {
        return None;
    }
    Some(DisplayNode::Bytes {
        at: emitter.walk(id, &bytes())?.0,
        notation: Notation::Hex,
    })
}

/// A borrowed `&camino::Utf8Path` is a `{ data_ptr, length }` fat pointer over a
/// guaranteed-UTF-8 byte buffer, laid out exactly like `&str` — only the data
/// pointer is typed `*Utf8Path` rather than `*u8`. It renders through the same
/// `Str` node with no capacity.
pub(super) fn utf8_path_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Str {
        pointer: emitter.walk(id, &reach![Named("data_ptr")])?.0,
        length: emitter.walk(id, &reach![Named("length")])?.0,
        capacity: None,
    })
}

/// An owned `camino::Utf8PathBuf` wraps a `std::path::PathBuf`, which nests
/// `OsString`/`Buf` down to a `Vec<u8>` behind four transparent single-member
/// wrappers (`__0` → `inner` → `inner` → `inner`). Like `String` it is a
/// guaranteed-UTF-8 `Vec<u8>`, so it reuses the same `Str` node with the
/// capacity checked, prefixing the Vec's own paths with the wrapper chain.
pub(super) fn utf8_path_buf_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let prefix = reach![Named("__0"), Named("inner"), Named("inner"), Named("inner"),];
    let vec = emitter.landed(id, &prefix)?;
    let shape = vec_shape(emitter, vec)?;
    if !is_unsigned_integer(emitter.reader, shape.element, 1) {
        return None;
    }
    buffer_node(emitter, id, &prefix, shape)
}

/// Whether `id` is parking_lot's raw mutex. A caller that reached one behind
/// tokio's loom shim has had no dispatch key screen it.
pub(super) fn is_raw_mutex(reader: &DwReader<'_>, id: TypeId) -> bool {
    fq_name(reader, id).as_deref() == Some("parking_lot::raw_mutex::RawMutex")
}

/// The raw mutex's single lock-state byte, reached under `prefix`. It sits in
/// a one-byte atomic, which the compiler spells either generically or as a
/// concrete `AtomicU8`, so the byte is peeled to rather than named.
pub(super) fn mutex_byte_path(mut prefix: Reach<'_>) -> Reach<'_> {
    prefix.push(PeelTo(Shape::Uint(1)));
    prefix
}

/// A `parking_lot::raw_mutex::RawMutex` is a single decoded lock-state byte
/// (`LOCKED_BIT`/`PARKED_BIT`), shown in place of the whole value.
pub(super) fn raw_mutex_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // The dispatch table screens by name; this describes only the structure.
    // The state is a single-byte atomic, whichever way the compiler spelled it.
    let decode = emitter.mutex_byte_decode();
    Some(DisplayNode::Scalar {
        at: emitter
            .walk(id, &mutex_byte_path(reach![Named("state")]))?
            .0,
        decode,
    })
}

impl Emitter<'_> {
    /// parking_lot mutex state byte: bit 0 locked, bit 1 parked.
    pub(super) fn mutex_byte_decode(&mut self) -> ScalarDecode {
        let locked = self.bool_field("locked", 0);
        let parked = self.bool_field("parked", 1);
        ScalarDecode::Bits(vec![locked, parked])
    }
}

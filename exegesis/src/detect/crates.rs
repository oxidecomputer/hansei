// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
        nul_terminated: false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DwReader;
    use crate::raw_types::{
        NsId, RawBase, RawGenericParameter, RawMember, RawPointer, RawStruct, RawType,
    };
    use crate::{Encoding, StrId};

    use gimli::UnitSectionOffset;

    use std::collections::BTreeMap;

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset(offset))
    }

    #[derive(Default)]
    struct Fx {
        reader: DwReader<'static>,
    }

    impl Fx {
        fn ns(&mut self, path: &'static str) -> NsId {
            let mut ns = None;
            for seg in path.split("::") {
                let name = self.reader.strings.intern(seg);
                ns = Some(self.reader.namespaces.insert(ns, name));
            }
            ns.unwrap()
        }

        fn base(&mut self, id: TypeId, name: &'static str, encoding: Encoding, size: u64) {
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Base(RawBase {
                    name,
                    namespace: None,
                    encoding,
                    size,
                    alignment: None,
                }),
            );
        }

        fn strukt(
            &mut self,
            id: TypeId,
            namespace: Option<NsId>,
            name: &'static str,
            members: &[(&'static str, TypeId, u64)],
            params: &[(&'static str, TypeId)],
        ) {
            let members: Box<[RawMember<StrId>]> = members
                .iter()
                .map(|&(name, type_id, offset)| RawMember {
                    name: Some(self.reader.strings.intern(name)),
                    offset,
                    type_id,
                    source_loc: None,
                })
                .collect();
            let template_params: Box<[RawGenericParameter<StrId>]> = params
                .iter()
                .map(|&(name, type_id)| RawGenericParameter {
                    name: Some(self.reader.strings.intern(name)),
                    type_id,
                })
                .collect();
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Struct(RawStruct {
                    name,
                    namespace,
                    size: 8,
                    members,
                    template_params,
                    source_loc: None,
                }),
            );
        }

        fn pointer(&mut self, id: TypeId, target: TypeId) {
            self.reader.types.insert(
                id,
                RawType::Pointer(RawPointer {
                    name: None,
                    target_type_id: target,
                }),
            );
        }

        fn emitter(&self) -> Emitter<'_> {
            Emitter::new(&self.reader, BTreeMap::new(), None, None)
        }
    }

    fn api2_vec(param_t: &'static str, retarget_element: bool) -> (Fx, TypeId) {
        let mut fx = Fx::default();
        let vec_ns = fx.ns("allocator_api2::stable::vec");
        let raw_vec_ns = fx.ns("allocator_api2::stable::raw_vec");
        let elem = type_id(1);
        let other = type_id(2);
        let global = type_id(3);
        let u64t = type_id(4);
        let usize_t = type_id(5);
        fx.base(elem, "i64", Encoding::Signed, 8);
        fx.base(other, "i32", Encoding::Signed, 4);
        fx.strukt(global, None, "Global", &[], &[]);
        fx.base(u64t, "u64", Encoding::Unsigned, 8);
        fx.base(usize_t, "usize", Encoding::Unsigned, 8);

        let vec = type_id(0x10);
        let raw_vec = type_id(0x11);
        let non_null = type_id(0x12);
        let elem_ptr = type_id(0x13);
        fx.strukt(
            vec,
            Some(vec_ns),
            "Vec<i64, Global>",
            &[("buf", raw_vec, 0), ("len", u64t, 8)],
            &[(param_t, elem), ("A", global)],
        );
        fx.strukt(
            raw_vec,
            Some(raw_vec_ns),
            "RawVec<i64, Global>",
            &[("ptr", non_null, 0), ("cap", usize_t, 8)],
            &[
                ("T", if retarget_element { other } else { elem }),
                ("A", global),
            ],
        );
        fx.strukt(
            non_null,
            None,
            "NonNull<i64>",
            &[("pointer", elem_ptr, 0)],
            &[],
        );
        fx.pointer(elem_ptr, elem);
        (fx, vec)
    }

    #[test]
    fn test_allocator_api2_vec_validates_its_buffer() {
        let (fx, vec) = api2_vec("T", false);
        assert!(allocator_api2_vec_shape(&mut fx.emitter(), vec).is_some());

        let (fx, vec) = api2_vec("X", false);
        assert!(allocator_api2_vec_shape(&mut fx.emitter(), vec).is_none());

        let (fx, vec) = api2_vec("T", true);
        assert!(allocator_api2_vec_shape(&mut fx.emitter(), vec).is_none());
    }

    #[test]
    fn test_utf8_path_is_a_str_fat_pointer() {
        let mut fx = Fx::default();
        let path = type_id(1);
        let data_ptr = type_id(2);
        let u64t = type_id(3);
        let wide = type_id(0x10);
        fx.strukt(path, None, "Utf8Path", &[], &[]);
        fx.pointer(data_ptr, path);
        fx.base(u64t, "u64", Encoding::Unsigned, 8);
        fx.strukt(
            wide,
            None,
            "&camino::Utf8Path",
            &[("data_ptr", data_ptr, 0), ("length", u64t, 8)],
            &[],
        );
        assert!(matches!(
            utf8_path_node(&mut fx.emitter(), wide),
            Some(DisplayNode::Str { capacity: None, .. })
        ));
    }

    fn path_buf(element: &'static str) -> (Fx, TypeId) {
        let mut fx = Fx::default();
        let vec_ns = fx.ns("alloc::vec");
        let raw_vec_ns = fx.ns("alloc::raw_vec");
        let niche_ns = fx.ns("core::num::niche_types");
        let elem = type_id(1);
        let global = type_id(2);
        let u8t = type_id(3);
        let u64t = type_id(4);
        let usize_t = type_id(5);
        let signed = element == "i64";
        fx.base(
            elem,
            element,
            if signed {
                Encoding::Signed
            } else {
                Encoding::Unsigned
            },
            if signed { 8 } else { 1 },
        );
        fx.strukt(global, None, "Global", &[], &[]);
        fx.base(u8t, "u8", Encoding::Unsigned, 1);
        fx.base(u64t, "u64", Encoding::Unsigned, 8);
        fx.base(usize_t, "usize", Encoding::Unsigned, 8);

        let vec = type_id(0x10);
        let raw_vec = type_id(0x11);
        let inner = type_id(0x12);
        let byte_ptr = type_id(0x13);
        let cap = type_id(0x14);
        fx.strukt(
            vec,
            Some(vec_ns),
            "Vec<u8, alloc::alloc::Global>",
            &[("buf", raw_vec, 0), ("len", u64t, 8)],
            &[("T", elem), ("A", global)],
        );
        fx.strukt(
            raw_vec,
            Some(raw_vec_ns),
            "RawVec<u8, alloc::alloc::Global>",
            &[("inner", inner, 0)],
            &[("T", elem), ("A", global)],
        );
        fx.strukt(
            inner,
            Some(raw_vec_ns),
            "RawVecInner<alloc::alloc::Global>",
            &[("ptr", byte_ptr, 0), ("cap", cap, 8)],
            &[("A", global)],
        );
        fx.pointer(byte_ptr, u8t);
        fx.strukt(
            cap,
            Some(niche_ns),
            "UsizeNoHighBit",
            &[("__0", usize_t, 0)],
            &[],
        );

        let os_buf = type_id(0x20);
        let os_string = type_id(0x21);
        let path_inner = type_id(0x22);
        let path_buf = type_id(0x23);
        fx.strukt(os_buf, None, "Buf", &[("inner", vec, 0)], &[]);
        fx.strukt(os_string, None, "OsString", &[("inner", os_buf, 0)], &[]);
        fx.strukt(path_inner, None, "PathBuf", &[("inner", os_string, 0)], &[]);
        fx.strukt(
            path_buf,
            None,
            "Utf8PathBuf",
            &[("__0", path_inner, 0)],
            &[],
        );
        (fx, path_buf)
    }

    #[test]
    fn test_utf8_path_buf_reaches_the_vec_through_its_wrappers() {
        let (fx, buf) = path_buf("u8");
        assert!(matches!(
            utf8_path_buf_node(&mut fx.emitter(), buf),
            Some(DisplayNode::Str {
                capacity: Some(_),
                ..
            })
        ));

        // A Vec over anything but bytes is not a UTF-8 buffer.
        let (fx, buf) = path_buf("i64");
        assert!(utf8_path_buf_node(&mut fx.emitter(), buf).is_none());
    }

    #[test]
    fn test_raw_mutex_is_recognized_by_its_full_name() {
        let mut fx = Fx::default();
        let mutex_ns = fx.ns("parking_lot::raw_mutex");
        let mutex = type_id(1);
        let plain = type_id(2);
        fx.strukt(mutex, Some(mutex_ns), "RawMutex", &[], &[]);
        fx.strukt(plain, None, "RawMutex", &[], &[]);
        assert!(is_raw_mutex(&fx.reader, mutex));
        assert!(!is_raw_mutex(&fx.reader, plain));
    }
}

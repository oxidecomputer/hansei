// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Detectors for third-party crates (camino, uuid, parking_lot,
//! allocator-api2, digest newtypes, hyper and hyper-util). Each layout
//! here moves on its own crate's release cadence, independent of both
//! the toolchain and tokio.

use super::ReachStep::{Named, PeelTo, Resolved};
use super::std::{VecShape, buffer_node, vec_shape};
use super::{
    Reach, Through, Want, find_unique, is_byte_array, is_unsigned_integer, reach,
    sole_param_target, struct_of, unique_member,
};
use crate::bundle::{DisplayNode, Field, Notation, ScalarDecode, Shape};
use crate::extract::{Emitter, fq_name};
use crate::raw_types::RawStruct;
use crate::{DwReader, StrId, TypeId};

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
        offset: 0,
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

/// Which end of an HTTP/1 exchange a `hyper::proto::h1` type drives, from
/// its `T: Http1Transaction` parameter. hyper's two roles are the empty
/// enums `role::Client` and `role::Server`; a type whose `T` is neither is
/// not one the detectors below know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum H1Role {
    Client,
    Server,
}

fn h1_role(reader: &DwReader<'_>, st: &RawStruct<StrId>) -> Option<H1Role> {
    let param = st
        .template_params
        .iter()
        .find(|param| param.name.map(|name| reader.strings.get(name)) == Some("T"))?;
    match fq_name(reader, reader.canonicalize(param.type_id))?.as_str() {
        "hyper::proto::h1::role::Client" => Some(H1Role::Client),
        "hyper::proto::h1::role::Server" => Some(H1Role::Server),
        _ => None,
    }
}

/// `hyper::proto::h1::conn::Conn<I, B, T>`, the HTTP/1 connection state
/// machine both hyper's client and its server drive, as the words that say
/// where a connection stands: the protocol version, the keep-alive state,
/// what the connection is reading and writing, the method of the message
/// in flight, how much of the read buffer is filled, and — for the server,
/// which alone arms one — whether the header-read timer is running.
/// Everything else in its `State` and its buffered io (the write buffer,
/// the read strategy, the cached headers, the parser configuration) is
/// hidden; `config ugly on` shows it.
///
/// Each state word is aliased to the member holding it and rendered as its
/// own type, so a `Reading`/`Writing` payload — a body's decoder or
/// encoder — prints as it does structurally.
pub(super) fn hyper_h1_conn_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let role = h1_role(reader, struct_of(reader, id)?)?;
    let mut fields = Vec::new();
    for word in ["version", "keep_alive", "reading", "writing", "method"] {
        let at = emitter.walk(id, &reach![Named("state"), Named(word)])?.0;
        fields.push(Field::Synth {
            label: emitter.intern(word),
            node: DisplayNode::Alias {
                at,
                follow_pointers: true,
            },
        });
    }
    for (label, word) in [("read_buf_len", "len"), ("read_buf_cap", "cap")] {
        let at = emitter
            .walk(id, &reach![Named("io"), Named("read_buf"), Named(word)])?
            .0;
        fields.push(emitter.named_scalar(label, at, ScalarDecode::Raw));
    }
    if role == H1Role::Server {
        let at = emitter
            .walk(
                id,
                &reach![Named("state"), Named("h1_header_read_timeout_running")],
            )?
            .0;
        let decode = ScalarDecode::Bits(vec![emitter.enum_field(
            "",
            0,
            1,
            &[(0, "idle"), (1, "armed")],
        )]);
        fields.push(emitter.named_scalar("header_read_timer", at, decode));
    }
    Some(DisplayNode::Struct { fields })
}

/// `hyper::proto::h1::dispatch::Dispatcher<D, Bs, I, T>`, the future a
/// hyper HTTP/1 connection task polls: the connection, the role's dispatch
/// (the client's response callback and request receiver, the server's
/// service and in-flight handler), and the closing flag. The body plumbing
/// between them — the guard on the incoming body's sender, the boxed
/// outgoing body — is hidden: it says nothing about the connection the
/// connection's own words do not, and it is the part of the layout hyper
/// has changed between releases, so it is never addressed.
pub(super) fn hyper_h1_dispatcher_node(
    emitter: &mut Emitter<'_>,
    id: TypeId,
) -> Option<DisplayNode> {
    let mut fields = Vec::new();
    for member in ["conn", "dispatch", "is_closing"] {
        fields.push(Field::member(emitter.member_named(id, member)?));
    }
    Some(DisplayNode::Struct { fields })
}

/// hyper-util's transparent io wrappers: `rt::tokio::TokioIo<T>`, which
/// adapts a tokio socket to hyper's io traits, and `common::rewind::Rewind<T>`,
/// which replays the bytes the version-choosing server read ahead. Each
/// holds its `T` as `inner` and displays as that value — the socket behind
/// it — so a connection's io reads as what it is connected to rather than
/// the adapter around it.
pub(super) fn hyper_util_io_wrapper_node(
    emitter: &mut Emitter<'_>,
    id: TypeId,
) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let inner = sole_param_target(reader, struct_of(reader, id)?)?;
    let (at, landed) = emitter.walk(id, &reach![Named("inner")])?;
    (landed == inner).then_some(DisplayNode::Alias {
        at,
        follow_pointers: true,
    })
}

#[cfg(test)]
mod tests {
    use super::super::Detector;
    use super::*;
    use crate::DwReader;
    use crate::bundle::MemberRef;
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
                offset: 0,
                capacity: Some(_),
                ..
            })
        ));

        // A Vec over anything but bytes is not a UTF-8 buffer.
        let (fx, buf) = path_buf("i64");
        assert!(utf8_path_buf_node(&mut fx.emitter(), buf).is_none());
    }

    /// A `Conn<I, B, T>` over the members the detector reaches, with
    /// `T` the role named. `timer` leaves out the server's
    /// header-read flag when false.
    fn h1_conn(role: &'static str, timer: bool) -> (Fx, TypeId) {
        let mut fx = Fx::default();
        let conn_ns = fx.ns("hyper::proto::h1::conn");
        let role_ns = fx.ns("hyper::proto::h1::role");
        let u8t = type_id(1);
        let usize_t = type_id(2);
        let boolean = type_id(3);
        fx.base(u8t, "u8", Encoding::Unsigned, 1);
        fx.base(usize_t, "usize", Encoding::Unsigned, 8);
        fx.base(boolean, "bool", Encoding::Unsigned, 1);
        let io_ty = type_id(4);
        let body = type_id(5);
        let role_ty = type_id(6);
        fx.strukt(io_ty, None, "Io", &[], &[]);
        fx.strukt(body, None, "Bytes", &[], &[]);
        fx.strukt(role_ty, Some(role_ns), role, &[], &[]);

        let state = type_id(0x10);
        let mut members = vec![
            ("version", u8t, 0),
            ("keep_alive", u8t, 1),
            ("reading", u8t, 2),
            ("writing", u8t, 3),
            ("method", u8t, 4),
        ];
        if timer {
            members.push(("h1_header_read_timeout_running", boolean, 5));
        }
        fx.strukt(state, Some(conn_ns), "State", &members, &[]);
        let bytes_mut = type_id(0x11);
        fx.strukt(
            bytes_mut,
            None,
            "BytesMut",
            &[("len", usize_t, 0), ("cap", usize_t, 8)],
            &[],
        );
        let buffered = type_id(0x12);
        fx.strukt(
            buffered,
            None,
            "Buffered",
            &[("read_buf", bytes_mut, 0)],
            &[],
        );
        let conn = type_id(0x13);
        fx.strukt(
            conn,
            Some(conn_ns),
            "Conn<Io, Bytes, Role>",
            &[("io", buffered, 0), ("state", state, 16)],
            &[("I", io_ty), ("B", body), ("T", role_ty)],
        );
        (fx, conn)
    }

    /// The labels of the curated record `detector` builds for `id`, in
    /// order, resolved through the emitter that interned them.
    fn labels(detector: Detector, fx: &Fx, id: TypeId) -> Vec<String> {
        let mut emitter = fx.emitter();
        let node = detector(&mut emitter, id);
        let Some(DisplayNode::Struct { fields }) = node else {
            panic!("not a curated record: {node:?}");
        };
        fields
            .iter()
            .map(|field| match field {
                Field::Synth { label, .. } => emitter.interner.get(*label).unwrap().to_owned(),
                Field::Member {
                    at: MemberRef::Named(name),
                    ..
                } => emitter.interner.get(*name).unwrap().to_owned(),
                Field::Member {
                    at: MemberRef::Index(index),
                    ..
                } => format!("#{index}"),
            })
            .collect()
    }

    #[test]
    fn test_h1_conn_shows_the_header_read_timer_to_the_server_alone() {
        let (fx, conn) = h1_conn("Client", true);
        assert_eq!(
            labels(hyper_h1_conn_node, &fx, conn),
            [
                "version",
                "keep_alive",
                "reading",
                "writing",
                "method",
                "read_buf_len",
                "read_buf_cap",
            ]
        );

        let (fx, conn) = h1_conn("Server", true);
        assert_eq!(
            labels(hyper_h1_conn_node, &fx, conn),
            [
                "version",
                "keep_alive",
                "reading",
                "writing",
                "method",
                "read_buf_len",
                "read_buf_cap",
                "header_read_timer",
            ]
        );
    }

    #[test]
    fn test_h1_conn_declines_an_unknown_role_and_a_missing_word() {
        let (fx, conn) = h1_conn("Proxy", true);
        assert_eq!(hyper_h1_conn_node(&mut fx.emitter(), conn), None);

        // The client never addresses the timer flag; the server needs it.
        let (fx, conn) = h1_conn("Client", false);
        assert!(hyper_h1_conn_node(&mut fx.emitter(), conn).is_some());
        let (fx, conn) = h1_conn("Server", false);
        assert_eq!(hyper_h1_conn_node(&mut fx.emitter(), conn), None);
    }

    #[test]
    fn test_h1_dispatcher_needs_each_member_it_names() {
        let mut fx = Fx::default();
        let word = type_id(1);
        fx.base(word, "u64", Encoding::Unsigned, 8);
        let whole = type_id(0x10);
        fx.strukt(
            whole,
            None,
            "Dispatcher",
            &[
                ("conn", word, 0),
                ("dispatch", word, 8),
                ("body_tx", word, 16),
                ("body_rx", word, 24),
                ("is_closing", word, 32),
            ],
            &[],
        );
        assert_eq!(
            labels(hyper_h1_dispatcher_node, &fx, whole),
            ["conn", "dispatch", "is_closing"]
        );

        let partial = type_id(0x11);
        fx.strukt(
            partial,
            None,
            "Dispatcher",
            &[("conn", word, 0), ("dispatch", word, 8)],
            &[],
        );
        assert_eq!(hyper_h1_dispatcher_node(&mut fx.emitter(), partial), None);
    }

    #[test]
    fn test_hyper_util_io_wrapper_aliases_only_its_parameter() {
        let mut fx = Fx::default();
        let socket = type_id(1);
        let other = type_id(2);
        fx.strukt(socket, None, "TcpStream", &[], &[]);
        fx.strukt(other, None, "Bytes", &[], &[]);

        let wrapper = type_id(0x10);
        fx.strukt(
            wrapper,
            None,
            "TokioIo<TcpStream>",
            &[("inner", socket, 0)],
            &[("T", socket)],
        );
        assert!(matches!(
            hyper_util_io_wrapper_node(&mut fx.emitter(), wrapper),
            Some(DisplayNode::Alias { .. })
        ));

        // `inner` holding something other than the declared `T`, and a
        // wrapper declaring two parameters, are not the layout.
        let retargeted = type_id(0x11);
        fx.strukt(
            retargeted,
            None,
            "TokioIo<TcpStream>",
            &[("inner", other, 0)],
            &[("T", socket)],
        );
        assert_eq!(
            hyper_util_io_wrapper_node(&mut fx.emitter(), retargeted),
            None
        );
        let two = type_id(0x12);
        fx.strukt(
            two,
            None,
            "Rewind<TcpStream>",
            &[("inner", socket, 8)],
            &[("T", socket), ("U", other)],
        );
        assert_eq!(hyper_util_io_wrapper_node(&mut fx.emitter(), two), None);
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

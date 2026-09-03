// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Leaf renderers: one machine word decoded through a
//! [`ScalarDecode`](crate::debug_type::ScalarDecode), a code pointer resolved
//! to a symbol, a UTF-8 string, a byte array in a standard notation -- plus the
//! byte-slicing primitives the other render modules read words with.

use crate::debug_type::{BitField, FatHeader, FieldRender, ScalarDecode};
use crate::elements::{HeapGate, SeqError, Shortfall, decode_header, utf8_buffer};
use proc::Target;

use hansei_bundle::Notation;

use std::fmt;

use super::dyn_ptr::resolve_function_symbol;
use super::{hex_pair, write_hex_u64};

/// Render one machine `word` through a resolved [`ScalarDecode`], producing the
/// canonical `field=value, …` form. Enforces the two "no silent state" rules:
/// an [`FieldRender::Enum`] value absent from its table renders `<unknown: N>`,
/// and any word bit no field covers renders a trailing `<unknown bits: 0xNN>` —
/// so upstream layout drift surfaces rather than being dropped.
pub(crate) fn apply(decode: &ScalarDecode, word: u64) -> String {
    let fields = match decode {
        ScalarDecode::Raw => return word.to_string(),
        // A millisecond count, signed so a raced difference reads as a small
        // negative duration rather than a wrapped one.
        ScalarDecode::Millis => {
            let ms = word as i64;
            let sign = if ms < 0 { "-" } else { "" };
            let ms = ms.unsigned_abs();
            return format!("{sign}{}.{:03}s", ms / 1000, ms % 1000);
        }
        ScalarDecode::Bits(fields) => fields,
    };
    let mut parts = Vec::with_capacity(fields.len() + 1);
    let mut covered = 0u64;
    for BitField {
        name,
        shift,
        width,
        render,
    } in fields
    {
        let shift = *shift;
        // `None` width means "all bits at and above `shift`".
        let value_mask = match width {
            Some(w) if w.get() >= 64 => u64::MAX,
            Some(w) => (1u64 << w.get()) - 1,
            None => u64::MAX >> shift,
        };
        covered |= value_mask << shift;
        let value = (word >> shift) & value_mask;
        let rendered = match render {
            FieldRender::Uint => value.to_string(),
            FieldRender::Enum(table) => match table.iter().find(|(v, _)| *v == value) {
                Some((_, label)) => label.clone(),
                None => format!("<unknown: {value}>"),
            },
        };
        // An empty name renders the sub-value bare, for a field the enclosing
        // record already labels (e.g. a boolean shown as just `false`); a named
        // field prefixes it as `name=value`.
        if name.is_empty() {
            parts.push(rendered);
        } else {
            parts.push(format!("{name}={rendered}"));
        }
    }
    let leftover = word & !covered;
    if leftover != 0 {
        parts.push(format!("<unknown bits: {leftover:#x}>"));
    }
    parts.join(", ")
}

/// Render the code pointer in `bytes` at `offset` as `0x<addr> -> <symbol>`,
/// resolving the address to a function symbol without ever following it as a
/// data pointer. A null pointer is `null`; an address that resolves appends
/// ` -> <symbol>`, and one that does not appends ` -> <unknown symbol>` only
/// when a target is attached to resolve against.
pub(crate) fn write_symbol<T: Target>(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    offset: u64,
    proc: Option<&T>,
) -> fmt::Result {
    let Some(address) = read_u64_at(bytes, offset) else {
        return write!(f, "<truncated>");
    };
    if address == 0 {
        return write!(f, "null");
    }
    write_hex_u64(f, address)?;
    if let Some(symbol) = resolve_function_symbol(proc, address) {
        write!(f, " -> {symbol}")?;
    } else if proc.is_some() {
        write!(f, " -> <unknown symbol>")?;
    }
    Ok(())
}

/// Render the UTF-8 buffer `header` describes as a quoted, escaped string,
/// read through the same [`utf8_buffer`] the parse path uses — one header
/// validation, and one refusal to believe a length further than the target
/// corroborates it. A shortfall renders the bytes that are there and says
/// how many are missing; nothing served at all degrades whole.
///
/// `nul_terminated` says the length counts a trailing NUL that is not part of
/// the string: the terminator is left out of the rendering, and — when the
/// whole string was served — read back and checked, so a value whose last
/// byte is not NUL is flagged rather than trusted to be the C string its
/// type claims.
pub(crate) fn write_utf8_string<T: Target>(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    header: &FatHeader,
    nul_terminated: bool,
    proc: Option<&T>,
    heap: Option<&dyn crate::heap::Heap>,
    cap: Option<u64>,
) -> fmt::Result {
    let gate = HeapGate::for_header(heap, header);
    let text = match utf8_buffer(header, nul_terminated, bytes, proc, gate, cap) {
        Ok(text) => text,
        Err(SeqError::Invalid(why)) => return write!(f, "<invalid string: {why}>"),
        Err(SeqError::Unreadable(_)) => return write!(f, "<unreadable string data>"),
        Err(SeqError::Freed) => return write!(f, "<freed string data>"),
        Err(SeqError::NoTarget) => return write!(f, "<target unavailable>"),
    };
    if text.count == 0 && text.claimed.is_some() {
        let claimed = text.claimed.unwrap_or_default();
        return match text.shortfall {
            Shortfall::PastAllocation => write!(f, "<string data overruns its allocation>"),
            // A cap of zero asked for nothing and got it: the caller's
            // instruction carried out, not a failure to read.
            Shortfall::PastCap => write!(f, "\"\" <{claimed} bytes not shown>"),
            Shortfall::Unreadable => write!(f, "<unreadable string data>"),
        };
    }
    match std::str::from_utf8(text.bytes) {
        Ok(text) => write!(f, "{text:?}")?,
        // A corrupted string is most useful mostly-shown: the valid
        // runs render escaped as usual and each bad byte renders as
        // `\xNN`, so the salvageable text survives the damage instead
        // of vanishing behind a marker. (Tried as a bstr single pass
        // eliding the validation entirely: measured CPU parity — the
        // validation's cost is first touch of the buffer, paid by
        // whichever pass runs first — so the valid path stays `str`'s
        // own `Debug`, and this arm stays the rare one.)
        Err(_) => {
            use std::fmt::Write as _;

            f.write_str("\"")?;
            for chunk in text.bytes.utf8_chunks() {
                for ch in chunk.valid().chars() {
                    // `escape_debug` would escape a bare `'`, which
                    // `str`'s `Debug` on the valid path leaves alone;
                    // keep the two spellings aligned.
                    if ch == '\'' {
                        f.write_char('\'')?;
                    } else {
                        for esc in ch.escape_debug() {
                            f.write_char(esc)?;
                        }
                    }
                }
                for byte in chunk.invalid() {
                    f.write_str("\\x")?;
                    f.write_str(hex_pair(*byte))?;
                }
            }
            f.write_str("\"")?;
        }
    }
    if let Some(claimed) = text.claimed {
        let more = claimed - text.count;
        // Three different facts about the same shortfall; see
        // `Shortfall`. Only the last of them says nothing is wrong.
        match text.shortfall {
            Shortfall::PastAllocation => write!(f, " <{more} more bytes past its allocation>")?,
            Shortfall::PastCap => write!(f, " <{more} more bytes not shown>")?,
            Shortfall::Unreadable => write!(f, " <{more} more bytes unreadable>")?,
        }
    } else if nul_terminated {
        // The whole string was served, so the terminator is the next byte.
        // Read it back rather than trusting the layout: a last byte that is
        // not NUL says this is not the C string its type claims — stale
        // memory, or a length out of dead bytes. The header decoded once
        // already to produce `text`, so it cannot fail here.
        if let (Some(proc), Ok((base, _))) = (proc, decode_header(bytes, header, 1)) {
            let terminator = base
                .checked_add(text.count)
                .and_then(|at| crate::target::read_bytes(proc, at, 1).ok());
            match terminator {
                Some([0]) => {}
                Some(_) => write!(f, " <no NUL terminator>")?,
                None => write!(f, " <NUL terminator unreadable>")?,
            }
        }
    }
    Ok(())
}

pub(crate) fn byte_range(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    bytes.get(start..end)
}

pub(crate) fn read_unsigned_at(bytes: &[u8], offset: u64, size: u64) -> Option<u64> {
    let bytes = byte_range(bytes, offset, size)?;
    Some(match size {
        1 => u64::from(bytes[0]),
        2 => u64::from(u16::from_le_bytes(bytes.try_into().ok()?)),
        4 => u64::from(u32::from_le_bytes(bytes.try_into().ok()?)),
        8 => u64::from_le_bytes(bytes.try_into().ok()?),
        _ => return None,
    })
}

pub(crate) fn read_u64_at(bytes: &[u8], offset: u64) -> Option<u64> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(start..end)?.try_into().ok()?))
}

/// Render the inline octets at `offset` as an IPv4 (4 octets) or IPv6 (16
/// octets) address in standard notation; the version is inferred from the octet
/// count that resolution validated to be 4 or 16.
pub(crate) fn eval_bytes(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    offset: u64,
    size: u64,
    notation: Notation,
) -> fmt::Result {
    let Some(bytes) = byte_range(bytes, offset, size) else {
        return write!(f, "<truncated>");
    };
    match notation {
        Notation::IpAddr => match <&[u8; 4]>::try_from(bytes) {
            Ok(octets) => write!(f, "{}", std::net::Ipv4Addr::from(*octets)),
            Err(_) => match <&[u8; 16]>::try_from(bytes) {
                Ok(octets) => write!(f, "{}", std::net::Ipv6Addr::from(*octets)),
                Err(_) => write!(f, "<invalid IP address layout>"),
            },
        },
        Notation::Uuid => match <&[u8; 16]>::try_from(bytes) {
            Ok(uuid) => write_uuid(f, uuid),
            Err(_) => write!(f, "<invalid UUID layout>"),
        },
        Notation::Hex => {
            for byte in bytes {
                f.write_str(hex_pair(*byte))?;
            }
            Ok(())
        }
    }
}

/// Write 16 bytes as a hyphenated lowercase UUID: the bytes in order, grouped
/// 8-4-4-4-12 hex digits, which is what `uuid::Uuid`'s own `Display` produces.
/// Spelled here rather than taken from the crate so reify does not depend on a
/// target's choice of uuid version.
fn write_uuid(f: &mut fmt::Formatter<'_>, uuid: &[u8; 16]) -> fmt::Result {
    for (i, byte) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            f.write_str("-")?;
        }
        f.write_str(hex_pair(*byte))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::Value;
    use crate::testhelper::*;

    use hansei_bundle::BundleView;

    #[test]
    fn test_ip_addresses_use_standard_notation() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ipv4 = [192, 0, 2, 1];
        assert_eq!(
            format!("{}", Value::new(v.ty(IPV4).unwrap(), 0, &ipv4).display()),
            "192.0.2.1"
        );

        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            format!("{}", Value::new(v.ty(IPV6).unwrap(), 0, &ipv6).display()),
            "2001:db8::1"
        );
    }

    /// A `Uuid` and an `Ipv6Addr` are both `[u8; 16]`, so the same sixteen bytes
    /// must render two ways — and the hyphens must land where `uuid::Uuid`'s own
    /// `Display` puts them, or a UUID read out of a core will not match the one
    /// in a log line.
    #[test]
    fn test_a_uuid_renders_hyphenated_where_an_address_would_not() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = [
            0x67, 0xe5, 0x50, 0x44, 0x10, 0xb1, 0x42, 0x6f, 0x92, 0x47, 0xbb, 0x68, 0x0e, 0x5f,
            0xe0, 0xc8,
        ];
        assert_eq!(
            format!("{}", Value::new(v.ty(UUID).unwrap(), 0, &bytes).display()),
            "67e55044-10b1-426f-9247-bb680e5fe0c8"
        );
        assert_eq!(
            format!("{}", Value::new(v.ty(IPV6).unwrap(), 0, &bytes).display()),
            "67e5:5044:10b1:426f:9247:bb68:e5f:e0c8"
        );

        // Too few bytes to read: a marker, not a panic and not a short UUID.
        assert_eq!(
            format!(
                "{}",
                Value::new(v.ty(UUID).unwrap(), 0, &bytes[..8]).display()
            ),
            "<truncated>"
        );
    }

    /// A digest is spelled the way every tool that prints one spells it:
    /// lowercase, unseparated, unprefixed, so it can be pasted into a search.
    #[test]
    fn test_a_digest_renders_as_plain_lowercase_hex() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        bytes[31] = 0xff;
        assert_eq!(
            format!("{}", Value::new(v.ty(HASH).unwrap(), 0, &bytes).display()),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1eff"
        );
    }

    #[test]
    fn test_str_and_string_display_quoted_utf8() {
        let mem = FakeMem::new()
            .at(0x3000, b"hi\nthere".to_vec())
            .at(0x4000, b"owned\ttext".to_vec())
            .panic_on_unmapped();

        let b = test_bundle();
        let v = BundleView::new(&b);
        let str_bytes: Vec<u8> = [0x3000u64, 8]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(STR).unwrap(), 0, &str_bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "\"hi\\nthere\""
        );

        let string_bytes: Vec<u8> = [0x4000u64, 10, 16]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(STRING).unwrap(), 0, &string_bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "\"owned\\ttext\""
        );
    }

    #[test]
    fn test_raw_mutex_decodes_lock_state() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let cases = [
            (
                0u8,
                "parking_lot::raw_mutex::RawMutex: locked=false, parked=false",
            ),
            (
                1,
                "parking_lot::raw_mutex::RawMutex: locked=true, parked=false",
            ),
            (
                2,
                "parking_lot::raw_mutex::RawMutex: locked=false, parked=true",
            ),
            (
                3,
                "parking_lot::raw_mutex::RawMutex: locked=true, parked=true",
            ),
        ];
        for (state, expected) in cases {
            let value = Value::new(v.ty(RAW_MUTEX).unwrap(), 0, std::slice::from_ref(&state));
            assert_eq!(format!("{}", value.display()), expected, "state={state}");
        }
    }

    #[test]
    fn test_watch_state_decodes_version_and_closed() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let cases = [
            // Bit 0 is the closed flag; the version is the remaining bits, so
            // it reads as the update count (tokio steps the state by 2), e.g.
            // raw 4 → version 2.
            (
                0u64,
                "tokio::sync::watch::state::AtomicState: closed=false, version=0",
            ),
            (
                4,
                "tokio::sync::watch::state::AtomicState: closed=false, version=2",
            ),
            (
                1,
                "tokio::sync::watch::state::AtomicState: closed=true, version=0",
            ),
            (
                5,
                "tokio::sync::watch::state::AtomicState: closed=true, version=2",
            ),
        ];
        for (state, expected) in cases {
            let bytes = state.to_le_bytes();
            let value = Value::new(v.ty(WATCH_STATE).unwrap(), 0, &bytes);
            assert_eq!(format!("{}", value.display()), expected, "state={state}");
        }
    }

    #[test]
    fn test_raw_waker_vtable_resolves_function_symbols() {
        // No regions: a code pointer must be resolved as a symbol, never
        // followed as data, so any read at all is a failure.
        let mem = FakeMem::new()
            .symbol(0x1000, "tokio::runtime::task::waker::clone_waker")
            .symbol(0x2000, "tokio::runtime::task::waker::wake_by_val")
            .symbol(0x3000, "tokio::runtime::task::waker::wake_by_ref")
            .symbol(0x4000, "tokio::runtime::task::waker::drop_waker")
            .panic_on_unmapped();

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1000u64, 0x2000, 0x3000, 0x4000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(RAW_WAKER_VTABLE).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        assert_eq!(
            shown,
            concat!(
                "core::task::wake::RawWakerVTable {\n",
                "    clone: 0x1000 -> tokio::runtime::task::waker::clone_waker,\n",
                "    wake: 0x2000 -> tokio::runtime::task::waker::wake_by_val,\n",
                "    wake_by_ref: 0x3000 -> tokio::runtime::task::waker::wake_by_ref,\n",
                "    drop: 0x4000 -> tokio::runtime::task::waker::drop_waker,\n",
                "}"
            )
        );
    }

    #[test]
    fn test_function_pointer_resolves_symbol_without_dereference() {
        let mem = FakeMem::new()
            .symbol(0x5000, "app::callback")
            .panic_on_unmapped();

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x5000u64.to_le_bytes();
        let value = Value::new(v.ty(FUNCTION_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "0x5000 -> app::callback"
        );
        assert_eq!(format!("{}", value.display()), "0x5000");

        let null = 0u64.to_le_bytes();
        let value = Value::new(v.ty(FUNCTION_PTR).unwrap(), 0, &null);
        assert_eq!(format!("{}", value.display_from_target(&mem, 8)), "null");
    }

    /// The two "no silent state" rules the scalar decoder exists to enforce: a
    /// value with no entry in its field's table renders `<unknown: N>`, and any
    /// bit no field covers renders a trailing `<unknown bits: 0xNN>`. Without
    /// both, layout drift in a future tokio would be dropped rather than shown.
    #[test]
    fn test_scalar_decode_reports_unmapped_values_and_stray_bits() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        // RawMutex covers bit 0 (locked) and bit 1 (parked) of a byte; the top
        // six bits belong to no field.
        let mutex = v.ty(RAW_MUTEX).unwrap();
        let show = |state: u8| {
            format!(
                "{}",
                Value::new(mutex, 0, std::slice::from_ref(&state)).display()
            )
        };
        assert_eq!(
            show(0x84),
            "parking_lot::raw_mutex::RawMutex: locked=false, parked=false, \
             <unknown bits: 0x84>"
        );
        assert_eq!(
            show(0xff),
            "parking_lot::raw_mutex::RawMutex: locked=true, parked=true, \
             <unknown bits: 0xfc>"
        );

        // Thing's `state` is a two-bit field with three enumerated values, so 3
        // is in range for the field but absent from its table.
        let nb = node_bundle();
        let nv = BundleView::new(&nb);
        let state_bytes = thing_bytes(3, 0, 0, 0, 0);
        let thing = Value::new(nv.ty(N_THING).unwrap(), 0, &state_bytes);
        let shown = format!("{}", thing.display());
        assert!(
            shown.contains("state: state=<unknown: 3>, generation=0"),
            "{shown}"
        );
    }

    /// A string whose bytes are not valid UTF-8 renders its valid runs
    /// escaped as usual with each bad byte as `\xNN` — a corrupted
    /// string survives mostly-shown rather than vanishing behind a
    /// marker. Escapable characters inside the valid runs still escape,
    /// and a string that is nothing but damage is just its bad bytes.
    #[test]
    fn test_invalid_utf8_string_degrades_per_byte() {
        let mem = FakeMem::new()
            .at(0x3000, vec![0x68, 0x69, 0xff, 0xfe, b'"', b'!'])
            .at(0x4000, vec![0xff, 0x80])
            .at(0x5000, vec![b'i', b't', b'\'', b's', 0xff]);

        let b = test_bundle();
        let v = BundleView::new(&b);
        let show = |addr: u64, len: u64| {
            let bytes: Vec<u8> = [addr, len].into_iter().flat_map(u64::to_le_bytes).collect();
            let value = Value::new(v.ty(STR).unwrap(), 0, &bytes);
            format!("{}", value.display_from_target(&mem, 8))
        };
        assert_eq!(show(0x3000, 6), r#""hi\xff\xfe\"!""#);
        assert_eq!(show(0x4000, 2), r#""\xff\x80""#);
        // A bare `'` stays bare, as it does on the valid path.
        assert_eq!(show(0x5000, 5), r#""it's\xff""#);
    }

    /// A NUL-terminated string (`CString`/`&CStr`) counts its terminator in
    /// the recorded length: the render trims it, keeps the lossy per-byte
    /// escaping for content no one promised was UTF-8, and reads the trimmed
    /// byte back — a last byte that is not NUL says the value is not the C
    /// string its type claims, and is flagged rather than trusted. A length
    /// of zero cannot hold the terminator it promises, and is refused whole.
    #[test]
    fn test_c_string_trims_and_verifies_its_terminator() {
        let mem = FakeMem::new()
            .at(0x3000, b"hello\0".to_vec())
            .at(0x4000, vec![b'h', b'i', 0xff, 0])
            .at(0x5000, vec![0])
            .at(0x6000, b"oops!".to_vec())
            .at(0x7000, b"edge".to_vec());

        let b = test_bundle();
        let v = BundleView::new(&b);
        let show = |addr: u64, len: u64| {
            let bytes: Vec<u8> = [addr, len].into_iter().flat_map(u64::to_le_bytes).collect();
            let value = Value::new(v.ty(C_STRING).unwrap(), 0, &bytes);
            format!("{}", value.display_from_target(&mem, 8))
        };
        assert_eq!(show(0x3000, 6), "\"hello\"");
        assert_eq!(show(0x4000, 4), r#""hi\xff""#);
        // The empty C string is its terminator alone.
        assert_eq!(show(0x5000, 1), "\"\"");
        // Content where the terminator should sit.
        assert_eq!(show(0x6000, 5), "\"oops\" <no NUL terminator>");
        // The mapping ends where the terminator should sit.
        assert_eq!(show(0x7000, 5), "\"edge\" <NUL terminator unreadable>");
        assert_eq!(
            show(0x3000, 0),
            "<invalid string: the length cannot hold the terminator>"
        );
    }

    /// A code pointer the target cannot name keeps its address and says so.
    /// With no target attached there is nothing to have failed, so the bare
    /// address is printed without a marker.
    #[test]
    fn test_unresolvable_symbol_is_reported() {
        // No symbols at all, and any read is a failure: a code pointer is
        // never followed as data.
        let mem = FakeMem::new().panic_on_unmapped();

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x5000u64.to_le_bytes();
        let value = Value::new(v.ty(FUNCTION_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "0x5000 -> <unknown symbol>"
        );
        assert_eq!(format!("{}", value.display()), "0x5000");
    }

    /// The remaining ways a string read degrades, in the order the renderer
    /// checks them. Each is a distinct marker so a bad render says which part
    /// of the fat pointer was wrong, rather than a single opaque failure.
    #[test]
    fn test_string_read_degradations_are_distinct() {
        let mem = FakeMem::new().unreadable();

        let b = test_bundle();
        let v = BundleView::new(&b);
        let str_ty = v.ty(STR).unwrap();
        let string_ty = v.ty(STRING).unwrap();
        let fat = |parts: &[u64]| -> Vec<u8> {
            parts.iter().copied().flat_map(u64::to_le_bytes).collect()
        };

        // A length of zero never reads, so it needs no pointer at all.
        assert_eq!(
            format!(
                "{}",
                Value::new(str_ty, 0, &fat(&[0, 0])).display_from_target(&mem, 8)
            ),
            "\"\""
        );
        // A non-empty string through a null pointer.
        assert_eq!(
            format!(
                "{}",
                Value::new(str_ty, 0, &fat(&[0, 4])).display_from_target(&mem, 8)
            ),
            "<invalid string: the data pointer is null>"
        );
        // A pointer the target cannot read.
        assert_eq!(
            format!(
                "{}",
                Value::new(str_ty, 0, &fat(&[0x3000, 4])).display_from_target(&mem, 8)
            ),
            "<unreadable string data>"
        );
        // No target at all is distinct from a failed read.
        assert_eq!(
            format!("{}", Value::new(str_ty, 0, &fat(&[0x3000, 4])).display()),
            "<target unavailable>"
        );
        // An owned String whose length exceeds its capacity cannot be trusted.
        assert_eq!(
            format!(
                "{}",
                Value::new(string_ty, 0, &fat(&[0x4000, 9, 4])).display_from_target(&mem, 8)
            ),
            "<invalid string: the length exceeds the capacity>"
        );
    }

    /// A length the target can only partly corroborate renders the bytes
    /// that are there and says how many are missing, rather than degrading
    /// whole or quietly passing the prefix off as the full string.
    #[test]
    fn test_string_render_reports_a_shortfall() {
        let mem = FakeMem::new().at(0x3000, b"hello".to_vec());

        let b = test_bundle();
        let v = BundleView::new(&b);
        let fat: Vec<u8> = [0x3000u64, 500]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(STR).unwrap(), 0, &fat);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "\"hello\" <495 more bytes unreadable>"
        );
    }
}

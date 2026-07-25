//! Leaf renderers: one machine word decoded through a
//! [`ScalarDecode`](crate::debug_type::ScalarDecode), a code pointer resolved
//! to a symbol, a UTF-8 string, an IP address -- plus the byte-slicing
//! primitives the other render modules read words with.

use crate::debug_type::{FieldRender, ScalarDecode};
use crate::target::ReadFromProc;

use crate::debug_type::BitField;

use std::fmt;

use super::dyn_ptr::resolve_function_symbol;

/// Render one machine `word` through a resolved [`ScalarDecode`], producing the
/// canonical `field=value, …` form. Enforces the two "no silent state" rules:
/// an [`FieldRender::Enum`] value absent from its table renders `<unknown: N>`,
/// and any word bit no field covers renders a trailing `<unknown bits: 0xNN>` —
/// so upstream layout drift surfaces rather than being dropped.
pub(crate) fn apply(decode: &ScalarDecode, word: u64) -> String {
    let fields = match decode {
        ScalarDecode::Raw => return word.to_string(),
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
pub(crate) fn write_symbol(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    offset: u64,
    proc: Option<&dyn ReadFromProc>,
) -> fmt::Result {
    let Some(address) = read_u64_at(bytes, offset) else {
        return write!(f, "<truncated>");
    };
    if address == 0 {
        return write!(f, "null");
    }
    write!(f, "0x{address:x}")?;
    if let Some(symbol) = resolve_function_symbol(proc, address) {
        write!(f, " -> {symbol}")?;
    } else if proc.is_some() {
        write!(f, " -> <unknown symbol>")?;
    }
    Ok(())
}

pub(crate) fn write_utf8_string(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    pointer_offset: u64,
    length_offset: u64,
    length_size: u64,
    capacity: Option<(u64, u64)>,
    proc: Option<&dyn ReadFromProc>,
) -> fmt::Result {
    let Some(len) = read_unsigned_at(bytes, length_offset, length_size) else {
        return write!(f, "<truncated string length>");
    };
    if let Some((capacity_offset, capacity_size)) = capacity {
        let Some(capacity) = read_unsigned_at(bytes, capacity_offset, capacity_size) else {
            return write!(f, "<truncated String capacity>");
        };
        if len > capacity {
            return write!(f, "<invalid String: length exceeds capacity>");
        }
    }
    if len == 0 {
        return write!(f, "\"\"");
    }
    let Some(pointer) = read_u64_at(bytes, pointer_offset) else {
        return write!(f, "<truncated string pointer>");
    };
    if pointer == 0 {
        return write!(f, "<invalid string: null data pointer>");
    }
    let Some(proc) = proc else {
        return write!(f, "<target unavailable>");
    };
    let Ok(bytes) = proc.read_bytes(pointer, len) else {
        return write!(f, "<unreadable string data>");
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return write!(f, "<invalid UTF-8 string>");
    };
    write!(f, "{text:?}")
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
pub(crate) fn eval_ip_addr(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    offset: u64,
    octets_size: u64,
) -> fmt::Result {
    let Some(bytes) = byte_range(bytes, offset, octets_size) else {
        return write!(f, "<truncated>");
    };
    match <&[u8; 4]>::try_from(bytes) {
        Ok(octets) => write!(f, "{}", std::net::Ipv4Addr::from(*octets)),
        Err(_) => match <&[u8; 16]>::try_from(bytes) {
            Ok(octets) => write!(f, "{}", std::net::Ipv6Addr::from(*octets)),
            Err(_) => write!(f, "<invalid IP address layout>"),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::testhelper::*;
    use crate::{ReadFromProc, TypeInfoRef};

    use exegesis::bundle::BundleView;

    #[test]
    fn test_ip_addresses_use_standard_notation() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ipv4 = [192, 0, 2, 1];
        assert_eq!(
            format!(
                "{}",
                TypeInfoRef::new(v.ty(IPV4).unwrap(), 0, &ipv4).display()
            ),
            "192.0.2.1"
        );

        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            format!(
                "{}",
                TypeInfoRef::new(v.ty(IPV6).unwrap(), 0, &ipv6).display()
            ),
            "2001:db8::1"
        );
    }

    #[test]
    fn test_str_and_string_display_quoted_utf8() {
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                let bytes: &[u8] = match addr {
                    0x3000 => b"hi\nthere",
                    0x4000 => b"owned\ttext",
                    _ => panic!("unexpected address 0x{addr:x}"),
                };
                assert_eq!(len, bytes.len() as u64);
                Ok(bytes.to_vec())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let str_bytes: Vec<u8> = [0x3000u64, 8]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(STR).unwrap(), 0, &str_bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "\"hi\\nthere\""
        );

        let string_bytes: Vec<u8> = [0x4000u64, 10, 16]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(STRING).unwrap(), 0, &string_bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
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
            let value = TypeInfoRef::new(v.ty(RAW_MUTEX).unwrap(), 0, std::slice::from_ref(&state));
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
            let value = TypeInfoRef::new(v.ty(WATCH_STATE).unwrap(), 0, &bytes);
            assert_eq!(format!("{}", value.display()), expected, "state={state}");
        }
    }

    #[test]
    fn test_raw_waker_vtable_resolves_function_symbols() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("function pointer at {addr:#x} must not be dereferenced")
            }

            fn function_symbol(&self, addr: u64) -> Option<String> {
                match addr {
                    0x1000 => Some("tokio::runtime::task::waker::clone_waker".to_owned()),
                    0x2000 => Some("tokio::runtime::task::waker::wake_by_val".to_owned()),
                    0x3000 => Some("tokio::runtime::task::waker::wake_by_ref".to_owned()),
                    0x4000 => Some("tokio::runtime::task::waker::drop_waker".to_owned()),
                    _ => None,
                }
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1000u64, 0x2000, 0x3000, 0x4000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(RAW_WAKER_VTABLE).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
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
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("function pointer at {addr:#x} must not be dereferenced")
            }

            fn function_symbol(&self, addr: u64) -> Option<String> {
                (addr == 0x5000).then(|| "app::callback".to_owned())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x5000u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(FUNCTION_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "0x5000 -> app::callback"
        );
        assert_eq!(format!("{}", value.display()), "0x5000");

        let null = 0u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(FUNCTION_PTR).unwrap(), 0, &null);
        assert_eq!(format!("{}", value.display_from_target(&Reader, 8)), "null");
    }
}

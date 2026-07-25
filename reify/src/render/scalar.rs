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

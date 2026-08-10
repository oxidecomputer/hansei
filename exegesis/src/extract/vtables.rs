//! Vtable-hinted concrete types: scan the object file's data sections for
//! Rust vtables (drop glue, size, align, then methods), name the concrete
//! type each belongs to from its function symbols, and resolve those hints
//! against DWARF so realized trait objects become bundle roots.

use super::{ExtractStats, fq_name, raw_type_size, strip};
use crate::{DwReader, TypeId};

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct VtableTypeHint {
    name: String,
    size: u64,
}

/// Find concrete types named by vtables that are actually present in the
/// debug executable. A Rust vtable begins with drop glue, size, and align;
/// the first method follows that header. Function symbols identify the
/// concrete type, while size and align keep ordinary function tables from
/// becoming roots accidentally.
pub(super) fn discover_vtable_types<'data, O: Object<'data>>(obj: &O) -> Vec<VtableTypeHint> {
    let mut text_addresses = BTreeSet::new();
    let mut concrete_by_address: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();

    for symbol in obj.symbols().chain(obj.dynamic_symbols()) {
        let address = symbol.address();
        if address == 0 {
            continue;
        }
        if symbol.kind() == SymbolKind::Text {
            text_addresses.insert(address);
        }
        let Some(name) = symbol.name().ok() else {
            continue;
        };
        let Ok(demangled) = rustc_demangle::try_demangle(strip(name)) else {
            continue;
        };
        let display = format!("{demangled:#}");
        let Some(concrete) = crate::symbols::concrete_type_from_vtable_symbol(&display) else {
            continue;
        };
        concrete_by_address
            .entry(address)
            .or_default()
            .insert(concrete.to_owned());
    }

    let mut hints = BTreeSet::new();
    for section in obj.sections() {
        if !matches!(
            section.kind(),
            SectionKind::Data | SectionKind::ReadOnlyData
        ) {
            continue;
        }
        let Ok(data) = section.uncompressed_data() else {
            continue;
        };
        scan_vtable_section(
            data.as_ref(),
            section.address(),
            obj.is_little_endian(),
            &text_addresses,
            &concrete_by_address,
            &mut hints,
        );
    }
    hints.into_iter().collect()
}

fn scan_vtable_section(
    data: &[u8],
    address: u64,
    little_endian: bool,
    text_addresses: &BTreeSet<u64>,
    concrete_by_address: &BTreeMap<u64, BTreeSet<String>>,
    hints: &mut BTreeSet<VtableTypeHint>,
) {
    let first = ((8 - (address & 7)) & 7) as usize;
    if data.len().saturating_sub(first) < 24 {
        return;
    }

    for offset in (first..=data.len() - 24).step_by(8) {
        let drop = read_object_word(&data[offset..offset + 8], little_endian);
        let size = read_object_word(&data[offset + 8..offset + 16], little_endian);
        let align = read_object_word(&data[offset + 16..offset + 24], little_endian);
        if align == 0 || !align.is_power_of_two() || align > (1 << 30) {
            continue;
        }
        if drop != 0 && !text_addresses.contains(&drop) {
            continue;
        }

        let mut concrete = BTreeSet::new();
        if let Some(names) = concrete_by_address.get(&drop) {
            concrete.extend(names.iter().cloned());
        }
        if let Some(method_bytes) = data.get(offset + 24..offset + 32) {
            let method = read_object_word(method_bytes, little_endian);
            if let Some(names) = concrete_by_address.get(&method) {
                concrete.extend(names.iter().cloned());
            }
        }
        hints.extend(
            concrete
                .into_iter()
                .map(|name| VtableTypeHint { name, size }),
        );
    }
}

fn read_object_word(bytes: &[u8], little_endian: bool) -> u64 {
    let bytes: [u8; 8] = bytes.try_into().expect("object word must be eight bytes");
    if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    }
}

/// Below this many types, indexing them by name is not worth spawning threads.
const VTABLE_INDEX_PARALLEL_THRESHOLD: usize = 4096;

/// Index a slice of type ids by their normalized fully-qualified name. Pulled
/// out so [`resolve_vtable_type_hints`] can run it on several threads and merge.
fn vtable_name_index(
    reader: &DwReader<'_>,
    ids: &[TypeId],
) -> foldhash::HashMap<String, Vec<(TypeId, u64)>> {
    let mut by_name: foldhash::HashMap<String, Vec<(TypeId, u64)>> = foldhash::HashMap::default();
    for &id in ids {
        let Some(name) = fq_name(reader, id) else {
            continue;
        };
        let Some(size) = raw_type_size(reader, id) else {
            continue;
        };
        by_name
            .entry(crate::symbols::normalized_rust_type_name(&name).into_owned())
            .or_default()
            .push((id, size));
    }
    by_name
}

pub(super) fn resolve_vtable_type_hints(
    reader: &DwReader<'_>,
    hints: &[VtableTypeHint],
    stats: &mut ExtractStats,
) -> BTreeSet<TypeId> {
    // Index every canonical type by its normalized fully-qualified name.
    // Computing those names -- a namespace walk, a format, and a normalization
    // pass per type -- over tens of thousands of types dominates emission and
    // is read-only, so fan it out and merge the per-thread shards.
    let ids: Vec<TypeId> = reader.canonical_types().map(|(id, _)| id).collect();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let by_name = if threads <= 1 || ids.len() < VTABLE_INDEX_PARALLEL_THRESHOLD {
        vtable_name_index(reader, &ids)
    } else {
        let chunk = ids.len().div_ceil(threads);
        std::thread::scope(|scope| {
            let handles: Vec<_> = ids
                .chunks(chunk)
                .map(|c| scope.spawn(move || vtable_name_index(reader, c)))
                .collect();
            let mut merged: foldhash::HashMap<String, Vec<(TypeId, u64)>> =
                foldhash::HashMap::default();
            for handle in handles {
                for (name, mut entries) in handle.join().expect("vtable-index thread panicked") {
                    merged.entry(name).or_default().append(&mut entries);
                }
            }
            merged
        })
    };

    stats.vtable_type_hints = hints.len();
    let mut roots = BTreeSet::new();
    for hint in hints {
        let name = crate::symbols::normalized_rust_type_name(&hint.name);
        let Some(candidates) = by_name.get(name.as_ref()) else {
            stats.vtable_types_missing += 1;
            continue;
        };
        let candidates: BTreeSet<_> = candidates
            .iter()
            .filter(|(_, size)| *size == hint.size)
            .map(|(id, _)| *id)
            .collect();
        let mut candidates = candidates.into_iter();
        match (candidates.next(), candidates.next()) {
            (Some(id), None) => {
                roots.insert(id);
            }
            (None, _) => stats.vtable_types_missing += 1,
            (Some(_), Some(_)) => stats.vtable_types_ambiguous += 1,
        }
    }
    stats.vtable_type_roots = roots.len();
    roots
}

#[cfg(test)]
mod tests {
    use super::{VtableTypeHint, scan_vtable_section};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn test_scan_vtable_section_uses_drop_and_method_symbols() {
        let drop = 0x1000;
        let method = 0x2000;
        let text_addresses = BTreeSet::from([drop, method]);
        let concrete_by_address = BTreeMap::from([
            (drop, BTreeSet::from(["app::Dropped".to_owned()])),
            (method, BTreeSet::from(["app::NullDrop".to_owned()])),
        ]);
        let data: Vec<u8> = [drop, 24, 8, 0, 0, 16, 8, method]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let mut hints = BTreeSet::new();

        scan_vtable_section(
            &data,
            0,
            true,
            &text_addresses,
            &concrete_by_address,
            &mut hints,
        );

        assert!(hints.contains(&VtableTypeHint {
            name: "app::Dropped".to_owned(),
            size: 24,
        }));
        assert!(hints.contains(&VtableTypeHint {
            name: "app::NullDrop".to_owned(),
            size: 16,
        }));
    }
}

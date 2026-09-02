//! Two things a target's trait-object vtables are good for.
//!
//! *Hints*, the older half: scan the object file's data sections for Rust
//! vtables (drop glue, size, align, then methods), name the concrete type
//! each belongs to from its function symbols, and resolve those hints
//! against DWARF so realized trait objects become bundle roots.
//!
use super::{ExtractStats, fq_name, raw_type_size, strip};
use crate::{DwReader, TypeId};

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct VtableTypeHint {
    name: String,
    size: u64,
}

/// The debug executable's own placed bytes, addressed the way the image
/// places them.
///
/// Both vtable passes read from here: the hint scan looks for whole
/// vtable images to name concrete types by, and the DWARF harvest checks
/// each vtable the debug info claims against the words actually at that
/// address. An empty image — a companion debug file has program sections
/// but no file bytes behind them — is not "the target disagrees", it is
/// nothing to compare with, and both passes say so instead of guessing.
#[derive(Default)]
pub(super) struct VtableImage<'data> {
    /// Every placed section, ascending by address and non-overlapping,
    /// which is what makes the last section starting at or below an
    /// address the only one that can cover it.
    sections: Vec<Placed<'data>>,
    little_endian: bool,
}

/// One placed section of the image.
struct Placed<'data> {
    address: u64,
    bytes: Cow<'data, [u8]>,
    /// Whether the hint scan reads this one.
    ///
    /// That scan reads every word of what it is given and is screened
    /// only by the shape of what it finds, so it stays on the sections
    /// `object` names as data outright. The harvest reads one word at an
    /// address DWARF has already named, which no amount of unrelated
    /// section content can mislead — and needs the wider set, because
    /// `object` has no rule for Mach-O's `__DATA_CONST`, which is where
    /// ld64 puts the vtables.
    scanned: bool,
}

impl<'data> VtableImage<'data> {
    /// Read an object's placed sections. A section whose contents will
    /// not decompress is left out rather than read as zeros.
    pub(super) fn read<O: Object<'data>>(obj: &O) -> Self {
        let mut sections: Vec<Placed<'data>> = obj
            .sections()
            .filter(|s| {
                matches!(
                    s.kind(),
                    // Initialized, placed, and not code: what a vtable
                    // can be in. `Unknown` is a section format the
                    // `object` crate has no rule for, which is a
                    // classification it lacks rather than one it made.
                    SectionKind::Data
                        | SectionKind::ReadOnlyData
                        | SectionKind::ReadOnlyString
                        | SectionKind::Unknown
                )
            })
            .filter_map(|s| {
                Some(Placed {
                    address: s.address(),
                    scanned: matches!(s.kind(), SectionKind::Data | SectionKind::ReadOnlyData),
                    bytes: s.uncompressed_data().ok()?,
                })
            })
            .collect();
        sections.sort_by_key(|s| s.address);
        Self {
            sections,
            little_endian: obj.is_little_endian(),
        }
    }
}

/// Find concrete types named by vtables that are actually present in the
/// debug executable. A Rust vtable begins with drop glue, size, and align;
/// the first method follows that header. Function symbols identify the
/// concrete type, while size and align keep ordinary function tables from
/// becoming roots accidentally.
pub(super) fn discover_vtable_types<'data, O: Object<'data>>(
    obj: &O,
    image: &VtableImage<'_>,
) -> Vec<VtableTypeHint> {
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
    for section in image.sections.iter().filter(|s| s.scanned) {
        scan_vtable_section(
            section.bytes.as_ref(),
            section.address,
            image.little_endian,
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
    let by_name = if ids.len() < VTABLE_INDEX_PARALLEL_THRESHOLD {
        vtable_name_index(reader, &ids)
    } else {
        let chunk = ids.len().div_ceil(rayon::current_num_threads());
        let shards: Vec<_> = ids
            .par_chunks(chunk)
            .map(|c| vtable_name_index(reader, c))
            .collect();
        let mut merged: foldhash::HashMap<String, Vec<(TypeId, u64)>> =
            foldhash::HashMap::default();
        for shard in shards {
            for (name, mut entries) in shard {
                merged.entry(name).or_default().append(&mut entries);
            }
        }
        merged
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
    use super::{
        VtableImage, VtableTypeHint, discover_vtable_types, resolve_vtable_type_hints,
        scan_vtable_section,
    };

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

    fn entry(drop: u64, size: u64, align: u64) -> Vec<u8> {
        [drop, size, align]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect()
    }

    fn scan(data: &[u8], address: u64) -> BTreeSet<VtableTypeHint> {
        let drop = 0x1000;
        let text_addresses = BTreeSet::from([drop]);
        let concrete_by_address =
            BTreeMap::from([(drop, BTreeSet::from(["app::Dropped".to_owned()]))]);
        let mut hints = BTreeSet::new();
        scan_vtable_section(
            data,
            address,
            true,
            &text_addresses,
            &concrete_by_address,
            &mut hints,
        );
        hints
    }

    #[test]
    fn test_scan_screens_the_alignment_word() {
        // A power of two up to 2^30 is an alignment; zero, a non-power,
        // and anything wider is not a vtable header.
        assert_eq!(scan(&entry(0x1000, 24, 8), 0).len(), 1);
        assert_eq!(scan(&entry(0x1000, 24, 1 << 30), 0).len(), 1);
        assert_eq!(scan(&entry(0x1000, 24, 0), 0).len(), 0);
        assert_eq!(scan(&entry(0x1000, 24, 3), 0).len(), 0);
        assert_eq!(scan(&entry(0x1000, 24, 1 << 31), 0).len(), 0);
    }

    #[test]
    fn test_scan_walks_word_aligned_addresses_only() {
        // A section based at address 2 has its first aligned word six
        // bytes in; an entry there is found, the misaligned start is not
        // read as one.
        let mut data = vec![0u8; 6];
        data.extend(entry(0x1000, 24, 8));
        assert_eq!(scan(&data, 2).len(), 1);

        // A section of exactly one entry is scanned.
        assert_eq!(scan(&entry(0x1000, 24, 8), 0).len(), 1);
    }

    #[test]
    fn test_hints_resolve_by_normalized_name_and_size() {
        use crate::raw_types::{RawStruct, RawType};
        use crate::{DwReader, TypeId};
        use gimli::{DebugInfoOffset, UnitSectionOffset};

        let type_id = |offset| TypeId(UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(offset)));
        let mut reader = DwReader::default();
        let strukt = |reader: &mut DwReader<'static>, id, name: &'static str, size| {
            let name = Some(reader.strings.intern(name));
            reader.types.insert(
                id,
                RawType::Struct(RawStruct {
                    name,
                    namespace: None,
                    size,
                    members: Box::new([]),
                    template_params: Box::new([]),
                    source_loc: None,
                }),
            );
        };
        let dropped = type_id(1);
        strukt(&mut reader, dropped, "Dropped", 24);
        // Two same-named, same-sized candidates: ambiguous.
        strukt(&mut reader, type_id(2), "Ambig", 8);
        strukt(&mut reader, type_id(3), "Ambig", 8);

        let hint = |name: &str, size| VtableTypeHint {
            name: name.to_owned(),
            size,
        };
        let hints = [
            hint("Dropped", 24),
            hint("Dropped", 999),
            hint("NoSuchType", 8),
            hint("Ambig", 8),
        ];
        let mut stats = super::ExtractStats::default();
        let roots = resolve_vtable_type_hints(&reader, &hints, &mut stats);

        assert_eq!(roots, BTreeSet::from([dropped]));
        assert_eq!(stats.vtable_type_hints, 4);
        assert_eq!(stats.vtable_types_missing, 2);
        assert_eq!(stats.vtable_types_ambiguous, 1);
        assert_eq!(stats.vtable_type_roots, 1);
    }

    /// Discovery over a synthetic relocatable ELF: a `.data` section
    /// holding two vtable images — one with null drop glue named by its
    /// method slot, one whose drop glue is the text symbol itself — and
    /// one legacy-mangled `<app::Foo as app::Trait>::poll` symbol naming
    /// the concrete type. On-disk fixtures cannot cover this pass: a PIE
    /// binary's vtable slots are relocation-filled at load time and zero
    /// in the file.
    #[test]
    fn test_discovery_scans_data_sections_by_symbol_kind() {
        use object::write::{Object as WriteObject, Symbol, SymbolSection};
        use object::{
            Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind,
            SymbolScope,
        };

        let method = 0x2000u64;
        let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section = obj.add_section(vec![], b".data".to_vec(), SectionKind::Data);
        let data: Vec<u8> = [0, 24, 8, method, method, 48, 8, 0]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        obj.append_section_data(section, &data, 8);
        obj.add_symbol(Symbol {
            name: b"_ZN39_$LT$app..Foo$u20$as$u20$app..Trait$GT$4poll17h0000000000000000E".to_vec(),
            value: method,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Absolute,
            flags: SymbolFlags::None,
        });
        let bytes = obj.write().expect("a synthetic ELF assembles");
        let file = object::File::parse(&*bytes).expect("the synthetic ELF parses");

        let hints = discover_vtable_types(&file, &VtableImage::read(&file));
        let hint = |size| VtableTypeHint {
            name: "app::Foo".to_owned(),
            size,
        };
        assert_eq!(hints, vec![hint(24), hint(48)]);
    }
}

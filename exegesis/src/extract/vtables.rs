//! Two things a target's trait-object vtables are good for.
//!
//! *Hints*, the older half: scan the object file's data sections for Rust
//! vtables (drop glue, size, align, then methods), name the concrete type
//! each belongs to from its function symbols, and resolve those hints
//! against DWARF so realized trait objects become bundle roots.
//!
//! *The harvest*, the newer half: rustc describes every vtable it emits
//! with a `DW_TAG_variable` whose name is the whole `<C as T>::{vtable}`
//! pair, so the (concrete, trait, address, slots) table an operator wants
//! to search is already in the debug info and needs no scanning at all.

use super::{ExtractStats, fq_name, raw_type_size, strip};
use crate::detect::struct_of;
use crate::{DwReader, TypeId};

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use tracing::debug;

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

/// The suffix rustc gives the `DW_TAG_variable` describing an emitted
/// vtable. The whole name is `<{concrete} as {trait}>::{vtable}`.
const VTABLE_SUFFIX: &str = ">::{vtable}";

/// The three words every Rust vtable opens with — drop glue, size, align —
/// before the first method slot.
const VTABLE_HEADER_SLOTS: u16 = 3;

/// One trait-object vtable, as DWARF describes it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct VtableRecord {
    /// The trait side of the pair, e.g. `core::future::future::Future`.
    pub trait_: String,
    /// The concrete side, e.g. `dyn_future::boxed_leaf::{async_fn_env#0}`.
    pub concrete: String,
    /// Static address of the vtable in the debug binary's address space.
    pub address: u64,
    /// Total slots, header included.
    pub slot_count: u16,
    /// Method slots for which the `{vtable_type}` names no member. rustc
    /// emits a vacant entry for a method the trait object cannot dispatch
    /// (`where Self: Sized`, say), and the debug info shows that
    /// statically; it is a neutral fact about the vtable, not a fault.
    pub undescribed_slots: Vec<u16>,
}

/// Harvest every vtable the target's DWARF describes, sorted by
/// `(trait, concrete)` and deduplicated.
///
/// The name split leans on the concrete type being named twice: once
/// inside the variable's name, once by the `{vtable_type}`'s
/// `DW_AT_containing_type`. Taking the concrete half from the attribute
/// and requiring it to be the literal prefix of the name leaves the trait
/// half without a parser — and makes a DIE that does not conform say so
/// instead of being guessed at. Every rejection is counted, never fatal:
/// this shape is rustc's internal convention, so a release that moves it
/// must cost the table, not the extraction.
pub(super) fn harvest_vtables(
    reader: &DwReader<'_>,
    stats: &mut ExtractStats,
) -> Vec<VtableRecord> {
    let mut records = Vec::new();

    for var in reader.variables.values() {
        let Some(name) = var.name.map(|n| reader.strings.get(n)) else {
            continue;
        };
        let Some(pair) = name
            .strip_suffix(VTABLE_SUFFIX)
            .and_then(|rest| rest.strip_prefix('<'))
        else {
            continue;
        };

        let Some(shape) = vtable_shape(reader, var.type_id) else {
            debug!("declined, no {{vtable_type}} layout: {name}");
            stats.vtables_unshaped += 1;
            continue;
        };
        let Some((concrete, trait_)) = split_pair(reader, var.type_id, pair) else {
            debug!("declined, name does not split: {name}");
            stats.vtables_unsplit += 1;
            continue;
        };
        // Zero is the linker's answer for a vtable whose section it
        // discarded: the relocation behind the location — the `DW_OP_addr`
        // operand, or the `.debug_addr` slot an indexed form points at —
        // has nothing left to name, and resolves to 0. Two thirds of a
        // `--gc-sections` binary's vtable DIEs can read that way, split
        // debug info or not. No image places a vtable at vaddr 0, so this
        // is an absent location like any other, not an address to hand an
        // operator.
        let Some(address) = var.addr.filter(|&a| a != 0) else {
            let why = match var.addr {
                Some(_) => "garbage-collected",
                None => "no static location",
            };
            debug!("declined, {why}: {name}");
            stats.vtables_no_location += 1;
            continue;
        };

        let (slot_count, undescribed_slots) = shape;
        records.push(VtableRecord {
            trait_,
            concrete,
            address,
            slot_count,
            undescribed_slots,
        });
    }

    // Embedded DWARF repeats a vtable's DIE in every CGU that referenced
    // it, so the same record arrives many times over; those are dropped.
    // Two records that agree on everything but the address are not
    // duplicates — the linker kept two copies of one vtable — and neither
    // are two names at one address, which is a fold and the ambiguity a
    // lookup has to show.
    records.sort();
    let before = records.len();
    records.dedup();
    stats.vtables_duplicate = before - records.len();

    let mut by_address: BTreeMap<u64, usize> = BTreeMap::new();
    for record in &records {
        *by_address.entry(record.address).or_default() += 1;
    }
    stats.vtables_folded = by_address.values().filter(|&&n| n > 1).count();
    stats.vtables_harvested = records.len();
    stats.vtables_vacant = records
        .iter()
        .filter(|r| !r.undescribed_slots.is_empty())
        .count();

    for record in &records {
        debug!(
            address = format_args!("{:#x}", record.address),
            slots = record.slot_count,
            vacant = ?record.undescribed_slots,
            "<{} as {}>",
            record.concrete,
            record.trait_,
        );
    }
    records
}

/// The slot count and vacant slots of a `{vtable_type}` structure, or
/// `None` if the DIE is not one: a vtable is whole words, and always has
/// room for the drop-glue, size and align the layout opens with.
fn vtable_shape(reader: &DwReader<'_>, id: TypeId) -> Option<(u16, Vec<u16>)> {
    let st = struct_of(reader, id)?;
    if st.size % 8 != 0 {
        return None;
    }
    let slot_count = u16::try_from(st.size / 8).ok()?;
    if slot_count < VTABLE_HEADER_SLOTS {
        return None;
    }

    let described: BTreeSet<u64> = st.members.iter().map(|m| m.offset).collect();
    let undescribed = (VTABLE_HEADER_SLOTS..slot_count)
        .filter(|slot| !described.contains(&(u64::from(*slot) * 8)))
        .collect();
    Some((slot_count, undescribed))
}

/// Split `{concrete} as {trait}` — the inside of a vtable variable's name
/// — using the concrete type the `{vtable_type}`'s `DW_AT_containing_type`
/// names as the prefix to strip.
fn split_pair(reader: &DwReader<'_>, id: TypeId, pair: &str) -> Option<(String, String)> {
    let concrete = fq_name(reader, *reader.containing_types.get(&id)?)?;
    let trait_ = pair.strip_prefix(&concrete)?.strip_prefix(" as ")?;
    Some((concrete, trait_.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{
        ExtractStats, VtableRecord, VtableTypeHint, discover_vtable_types, harvest_vtables,
        resolve_vtable_type_hints, scan_vtable_section,
    };
    use crate::raw_types::{RawMember, RawStaticVariable, RawStruct, RawType};
    use crate::{DwReader, TypeId, VarId};

    use gimli::{DebugInfoOffset, UnitSectionOffset};

    use std::collections::{BTreeMap, BTreeSet};

    /// One hand-built vtable DIE trio: the concrete type, the
    /// `{vtable_type}` structure carrying the slot layout and the
    /// `DW_AT_containing_type` edge, and the variable whose name is the
    /// whole `<C as T>::{vtable}` pair.
    struct Vtable {
        /// The containing type's name. `None` models a concrete type no
        /// namespace path can spell, which is what an array — `[u8; 4]`,
        /// the case real binaries carry — looks like here.
        concrete: Option<&'static str>,
        /// Whether the `{vtable_type}` carries the containing-type edge
        /// at all.
        containing: bool,
        /// The variable's `DW_AT_name`.
        name: &'static str,
        addr: Option<u64>,
        /// The `{vtable_type}`'s byte size.
        size: u64,
        /// Slots the `{vtable_type}` names a member for.
        described: &'static [u16],
    }

    /// A four-word vtable, whole and located, of `concrete` for
    /// `app::Dyn`. Tests vary one field off this.
    fn vt(concrete: &'static str, name: &'static str, addr: u64) -> Vtable {
        Vtable {
            concrete: Some(concrete),
            containing: true,
            name,
            addr: Some(addr),
            size: 32,
            described: &[3],
        }
    }

    /// A reader holding whatever vtables a test added.
    #[derive(Default)]
    struct Vtables {
        reader: DwReader<'static>,
        next: usize,
    }

    impl Vtables {
        fn offset(&mut self) -> UnitSectionOffset {
            self.next += 1;
            UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(self.next))
        }

        fn add(&mut self, vtable: Vtable) {
            let concrete_id = TypeId(self.offset());
            let concrete_name = vtable.concrete.map(|n| self.reader.strings.intern(n));
            self.reader.types.insert(
                concrete_id,
                RawType::Struct(RawStruct {
                    name: concrete_name,
                    namespace: None,
                    size: 0,
                    members: Box::new([]),
                    template_params: Box::new([]),
                    source_loc: None,
                }),
            );

            // Only the members' offsets are read; their names are not.
            let slot = self.reader.strings.intern("__method");
            let members: Box<[RawMember<_>]> = vtable
                .described
                .iter()
                .map(|s| RawMember {
                    name: Some(slot),
                    offset: u64::from(*s) * 8,
                    type_id: concrete_id,
                    source_loc: None,
                })
                .collect();
            let vtable_id = TypeId(self.offset());
            let vtable_name = self.reader.strings.intern("{vtable_type}");
            self.reader.types.insert(
                vtable_id,
                RawType::Struct(RawStruct {
                    name: Some(vtable_name),
                    namespace: None,
                    size: vtable.size,
                    members,
                    template_params: Box::new([]),
                    source_loc: None,
                }),
            );
            if vtable.containing {
                self.reader.containing_types.insert(vtable_id, concrete_id);
            }

            let var_name = self.reader.strings.intern(vtable.name);
            let var_id = VarId(self.offset());
            self.reader.variables.insert(
                var_id,
                RawStaticVariable {
                    name: Some(var_name),
                    namespace: None,
                    type_id: vtable_id,
                    addr: vtable.addr,
                    linkage_name: None,
                    source_loc: Default::default(),
                },
            );
        }
    }

    fn harvest(vtables: impl IntoIterator<Item = Vtable>) -> (Vec<VtableRecord>, ExtractStats) {
        let mut v = Vtables::default();
        for vtable in vtables {
            v.add(vtable);
        }
        let mut stats = ExtractStats::default();
        let records = harvest_vtables(&v.reader, &mut stats);
        (records, stats)
    }

    /// The header is three words, so `slot_count` counts it and the
    /// first method is slot 3: a five-word vtable naming both methods
    /// has no vacant slot, a four-word one naming none has one, and a
    /// header-only vtable — what a trait with nothing to dispatch gets —
    /// is a whole vtable with no method slots to be vacant.
    #[test]
    fn test_harvest_splits_the_pair_and_reports_vacant_slots() {
        let (records, stats) = harvest([
            Vtable {
                size: 40,
                described: &[3, 4],
                ..vt("app::Eager", "<app::Eager as app::Dyn>::{vtable}", 0x1000)
            },
            Vtable {
                described: &[],
                ..vt("app::Vacant", "<app::Vacant as app::Dyn>::{vtable}", 0x2000)
            },
            Vtable {
                size: 24,
                described: &[],
                ..vt("app::Marker", "<app::Marker as app::Dyn>::{vtable}", 0x3000)
            },
        ]);

        assert_eq!(
            records,
            vec![
                VtableRecord {
                    trait_: "app::Dyn".to_owned(),
                    concrete: "app::Eager".to_owned(),
                    address: 0x1000,
                    slot_count: 5,
                    undescribed_slots: vec![],
                },
                VtableRecord {
                    trait_: "app::Dyn".to_owned(),
                    concrete: "app::Marker".to_owned(),
                    address: 0x3000,
                    slot_count: 3,
                    undescribed_slots: vec![],
                },
                VtableRecord {
                    trait_: "app::Dyn".to_owned(),
                    concrete: "app::Vacant".to_owned(),
                    address: 0x2000,
                    slot_count: 4,
                    undescribed_slots: vec![3],
                },
            ]
        );
        assert_eq!(stats.vtables_harvested, 3);
        assert_eq!(stats.vtables_vacant, 1);
    }

    /// A vtable the linker discarded reads back as address zero, which
    /// is no more an address than a missing location is.
    #[test]
    fn test_harvest_declines_vtables_with_no_address() {
        let (records, stats) = harvest([
            Vtable {
                addr: Some(0),
                ..vt("app::Gone", "<app::Gone as app::Dyn>::{vtable}", 0)
            },
            Vtable {
                addr: None,
                ..vt("app::Never", "<app::Never as app::Dyn>::{vtable}", 0)
            },
        ]);

        assert!(records.is_empty());
        assert_eq!(stats.vtables_no_location, 2);
    }

    /// The concrete type is named twice — by the variable and by the
    /// `{vtable_type}`'s `DW_AT_containing_type` — and the harvest
    /// requires the two spellings to agree. Each way they can fail to is
    /// a decline, never a split made some other way.
    #[test]
    fn test_harvest_declines_a_name_that_does_not_split() {
        let (records, stats) = harvest([
            // No containing-type edge to take the concrete half from.
            Vtable {
                containing: false,
                ..vt("app::Loose", "<app::Loose as app::Dyn>::{vtable}", 0x1000)
            },
            // An edge, to a type with no name.
            Vtable {
                concrete: None,
                ..vt("", "<[u8; 4] as core::fmt::Debug>::{vtable}", 0x2000)
            },
            // A name whose concrete half is some other type.
            vt("app::Other", "<app::Eager as app::Dyn>::{vtable}", 0x3000),
            // The right concrete half, but not followed by ` as `.
            vt("app::Eager", "<app::Eager, app::Dyn>::{vtable}", 0x4000),
            // Not a vtable DIE at all: no suffix, so not a decline
            // either.
            vt("app::Plain", "app::Plain::{vtable_type}", 0x5000),
        ]);

        assert!(records.is_empty());
        assert_eq!(stats.vtables_unsplit, 4);
    }

    /// A `{vtable_type}` that is not whole words, or has no room for the
    /// drop-glue/size/align header, describes no vtable.
    #[test]
    fn test_harvest_declines_a_vtable_type_of_the_wrong_shape() {
        let (records, stats) = harvest([
            Vtable {
                size: 16,
                described: &[],
                ..vt("app::Short", "<app::Short as app::Dyn>::{vtable}", 0x1000)
            },
            Vtable {
                size: 36,
                ..vt("app::Ragged", "<app::Ragged as app::Dyn>::{vtable}", 0x2000)
            },
        ]);

        assert!(records.is_empty());
        assert_eq!(stats.vtables_unshaped, 2);
    }

    /// Two DIEs agreeing on everything are one vtable described twice.
    /// Two names at one address are a fold, and both names are kept:
    /// either may be the one an operator is looking for, and that they
    /// cannot be told apart is the answer.
    #[test]
    fn test_harvest_dedups_repeats_but_keeps_folded_names() {
        let (records, stats) = harvest([
            vt("app::One", "<app::One as app::Dyn>::{vtable}", 0x1000),
            vt("app::One", "<app::One as app::Dyn>::{vtable}", 0x1000),
            vt("app::Two", "<app::Two as app::Dyn>::{vtable}", 0x1000),
            vt("app::Three", "<app::Three as app::Dyn>::{vtable}", 0x2000),
            vt("app::Four", "<app::Four as app::Dyn>::{vtable}", 0x3000),
        ]);

        assert_eq!(
            records
                .iter()
                .map(|r| r.concrete.as_str())
                .collect::<Vec<_>>(),
            ["app::Four", "app::One", "app::Three", "app::Two"]
        );
        assert_eq!(stats.vtables_harvested, 4);
        assert_eq!(stats.vtables_duplicate, 1);
        assert_eq!(stats.vtables_folded, 1);
    }

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

        let hints = discover_vtable_types(&file);
        let hint = |size| VtableTypeHint {
            name: "app::Foo".to_owned(),
            size,
        };
        assert_eq!(hints, vec![hint(24), hint(48)]);
    }
}

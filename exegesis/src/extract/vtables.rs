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
use crate::bundle::VTABLE_HEADER_SLOTS;
use crate::detect::struct_of;
use crate::raw_types::RawType;
use crate::{DwReader, TypeId};

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use tracing::debug;

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

    /// Whether there are any bytes here to check anything against.
    fn is_empty(&self) -> bool {
        self.sections.iter().all(|s| s.bytes.is_empty())
    }

    /// The word at load address `addr`, if a section covers it.
    fn word(&self, addr: u64) -> Option<u64> {
        let index = self.sections.partition_point(|s| s.address <= addr);
        let section = self.sections.get(index.checked_sub(1)?)?;
        let offset = usize::try_from(addr - section.address).ok()?;
        let bytes = section.bytes.get(offset..offset + 8)?;
        Some(read_object_word(bytes, self.little_endian))
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

/// The suffix rustc gives the `DW_TAG_variable` describing an emitted
/// vtable. The whole name is `<{concrete} as {trait}>::{vtable}`.
const VTABLE_SUFFIX: &str = ">::{vtable}";

/// Byte offsets of the two header words the image check reads: the size
/// of the concrete type, and its alignment.
const SIZE_OFFSET: u64 = 8;
const ALIGN_OFFSET: u64 = 16;

/// The largest alignment a Rust type can be given, as the hint scan also
/// screens for.
const MAX_ALIGN: u64 = 1 << 30;

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

/// A harvested vtable and the DWARF type its concrete half resolved to.
///
/// The id is kept out of [`VtableRecord`] because it is not part of a
/// vtable's identity: embedded DWARF describes one vtable once per
/// referencing unit, and the units need not agree on which DIE defines
/// the concrete type. Sorting and deduplicating on the record alone
/// collapses those repeats; a `TypeId` in the key would keep them.
pub(super) struct Harvested {
    pub record: VtableRecord,
    /// Canonical DWARF id of the concrete type, for the bundle-id join
    /// once emission has decided what the bundle describes.
    pub concrete_id: TypeId,
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
///
/// DWARF is the compiler's testimony about the program, not the program
/// — the miscompile this table was built for had debug info that agreed
/// with it — so an entry is kept only if the bytes at the address it
/// names still look like the vtable it claims: see [`image_agrees`].
pub(super) fn harvest_vtables(
    reader: &DwReader<'_>,
    image: &VtableImage<'_>,
    stats: &mut ExtractStats,
) -> Vec<Harvested> {
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
        let Some((concrete_id, concrete, trait_)) = split_pair(reader, var.type_id, pair) else {
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

        if !image.is_empty() && !image_agrees(image, address, declared_size(reader, concrete_id)) {
            debug!("declined, image disagrees at {address:#x}: {name}");
            stats.vtables_contradicted += 1;
            continue;
        }

        let (slot_count, undescribed_slots) = shape;
        records.push(Harvested {
            record: VtableRecord {
                trait_,
                concrete,
                address,
                slot_count,
                undescribed_slots,
            },
            concrete_id,
        });
    }

    // Embedded DWARF repeats a vtable's DIE in every CGU that referenced
    // it, so the same record arrives many times over; those are dropped.
    // Two records that agree on everything but the address are not
    // duplicates — the linker kept two copies of one vtable — and neither
    // are two names at one address, which is a fold and the ambiguity a
    // lookup has to show.
    records.sort_by(|a, b| a.record.cmp(&b.record));
    let before = records.len();
    records.dedup_by(|a, b| a.record == b.record);
    stats.vtables_duplicate = before - records.len();

    let mut by_address: BTreeMap<u64, usize> = BTreeMap::new();
    for h in &records {
        *by_address.entry(h.record.address).or_default() += 1;
    }
    stats.vtables_folded = by_address.values().filter(|&&n| n > 1).count();
    stats.vtables_harvested = records.len();
    stats.vtables_vacant = records
        .iter()
        .filter(|h| !h.record.undescribed_slots.is_empty())
        .count();

    for Harvested { record, .. } in &records {
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

/// Whether the words at `address` are still the vtable the debug info
/// says is there.
///
/// Two of the three header words can be checked without reading anything
/// the linker relocates: the size word must be the concrete type's DWARF
/// size, and the alignment word must be a power of two a Rust type could
/// have. The drop-glue and method slots are addresses filled in at load
/// time on a position-independent image, and read as zero here, so they
/// say nothing.
///
/// `concrete_size` is the size DWARF *states* for the concrete type; see
/// [`declared_size`] for why one that states none leaves that half
/// unchecked rather than failing the entry.
fn image_agrees(image: &VtableImage<'_>, address: u64, concrete_size: Option<u64>) -> bool {
    let (Some(size), Some(align)) = (
        image.word(address + SIZE_OFFSET),
        image.word(address + ALIGN_OFFSET),
    ) else {
        // The debug info placed a vtable where the image has no data at
        // all. Whatever that address is, it is not this vtable.
        return false;
    };
    align != 0
        && align.is_power_of_two()
        && align <= MAX_ALIGN
        && concrete_size.is_none_or(|declared| declared == size)
}

/// The byte size a type's DIE states, for the types that state one.
///
/// [`raw_type_size`] answers for every type, but for a pointer the
/// answer is inferred rather than read — and inferred wrong for a fat
/// one, whose vtable would then be thrown away for disagreeing with a
/// size DWARF never claimed. An array's is computed from its element
/// the same way. Neither records a size of its own, so neither has one
/// to check against.
fn declared_size(reader: &DwReader<'_>, id: TypeId) -> Option<u64> {
    match reader.canonical_type(id)? {
        RawType::Base(base) => Some(base.size),
        RawType::Enum(en) => Some(en.size),
        RawType::Struct(st) => Some(st.size),
        RawType::Union(union) => Some(union.size),
        RawType::Pointer(_) | RawType::Array(_) => None,
    }
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
/// names as the prefix to strip. Returns that type as well: it is what
/// the size check and the bundle-id join are about.
fn split_pair(reader: &DwReader<'_>, id: TypeId, pair: &str) -> Option<(TypeId, String, String)> {
    let concrete_id = reader.canonicalize(*reader.containing_types.get(&id)?);
    let concrete = fq_name(reader, concrete_id)?;
    let trait_ = pair.strip_prefix(&concrete)?.strip_prefix(" as ")?;
    Some((concrete_id, concrete, trait_.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{
        ExtractStats, Placed, VtableImage, VtableRecord, VtableTypeHint, discover_vtable_types,
        harvest_vtables, resolve_vtable_type_hints, scan_vtable_section,
    };
    use crate::raw_types::{RawMember, RawPointer, RawStaticVariable, RawStruct, RawType};
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
        /// The containing type's stated byte size, which the image check
        /// compares the vtable's size word against. `None` builds the
        /// concrete type as a pointer, which states none.
        concrete_size: Option<u64>,
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
            concrete_size: Some(24),
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
            let concrete = match vtable.concrete_size {
                Some(size) => RawType::Struct(RawStruct {
                    name: concrete_name,
                    namespace: None,
                    size,
                    members: Box::new([]),
                    template_params: Box::new([]),
                    source_loc: None,
                }),
                None => RawType::Pointer(RawPointer {
                    name: concrete_name,
                    target_type_id: concrete_id,
                }),
            };
            self.reader.types.insert(concrete_id, concrete);

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

    /// Harvest with nothing to check the DIEs against, which is what an
    /// extraction from a companion debug file alone has.
    fn harvest(vtables: impl IntoIterator<Item = Vtable>) -> (Vec<VtableRecord>, ExtractStats) {
        harvest_against(&VtableImage::default(), vtables)
    }

    fn harvest_against(
        image: &VtableImage<'_>,
        vtables: impl IntoIterator<Item = Vtable>,
    ) -> (Vec<VtableRecord>, ExtractStats) {
        let mut v = Vtables::default();
        for vtable in vtables {
            v.add(vtable);
        }
        let mut stats = ExtractStats::default();
        let harvested = harvest_vtables(&v.reader, image, &mut stats);
        (harvested.into_iter().map(|h| h.record).collect(), stats)
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

    /// An image holding one section based at `address`.
    fn image(address: u64, words: &[u64]) -> VtableImage<'static> {
        let bytes: Vec<u8> = words.iter().copied().flat_map(u64::to_le_bytes).collect();
        VtableImage {
            sections: vec![Placed {
                address,
                bytes: std::borrow::Cow::Owned(bytes),
                scanned: true,
            }],
            little_endian: true,
        }
    }

    /// A vtable whose header words the image confirms is kept; one whose
    /// size word disagrees with the concrete type's DWARF size, whose
    /// alignment word is not one a Rust type could have, or that the
    /// image does not cover at all is not the vtable the debug info
    /// claims, whatever the debug info says.
    #[test]
    fn test_harvest_declines_what_the_image_contradicts() {
        // Four vtables laid out from 0x1000: agreeing, wrong size,
        // impossible alignment, and — past the section's end — absent.
        // Only the drop-glue, size and align words matter; the method
        // slot is relocation-filled and reads as zero.
        let words = [
            0, 24, 8, 0, // 0x1000: as declared
            0, 32, 8, 0, // 0x1020: size 32 against a 24-byte type
            0, 24, 3, 0, // 0x1040: alignment 3
        ];
        let (records, stats) = harvest_against(
            &image(0x1000, &words),
            [
                vt("app::Agrees", "<app::Agrees as app::Dyn>::{vtable}", 0x1000),
                vt("app::Grew", "<app::Grew as app::Dyn>::{vtable}", 0x1020),
                vt("app::Skew", "<app::Skew as app::Dyn>::{vtable}", 0x1040),
                vt("app::Gone", "<app::Gone as app::Dyn>::{vtable}", 0x9000),
            ],
        );

        assert_eq!(
            records
                .iter()
                .map(|r| r.concrete.as_str())
                .collect::<Vec<_>>(),
            ["app::Agrees"]
        );
        assert_eq!(stats.vtables_contradicted, 3);
    }

    /// A concrete type that states no size of its own — a pointer,
    /// whose width the reader infers, and infers as thin — leaves the
    /// size word unchecked rather than failing the entry. The alignment
    /// word is still checked.
    #[test]
    fn test_harvest_checks_alignment_without_a_stated_size() {
        let unstated = |name, addr| Vtable {
            concrete_size: None,
            ..vt("&[u8]", name, addr)
        };
        let (records, stats) = harvest_against(
            &image(0x1000, &[0, 16, 8, 0, 0, 16, 0, 0]),
            [
                unstated("<&[u8] as app::Dyn>::{vtable}", 0x1000),
                unstated("<&[u8] as app::Other>::{vtable}", 0x1020),
            ],
        );

        assert_eq!(
            records
                .iter()
                .map(|r| r.trait_.as_str())
                .collect::<Vec<_>>(),
            ["app::Dyn"]
        );
        assert_eq!(stats.vtables_contradicted, 1);
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

        let hints = discover_vtable_types(&file, &VtableImage::read(&file));
        let hint = |size| VtableTypeHint {
            name: "app::Foo".to_owned(),
            size,
        };
        assert_eq!(hints, vec![hint(24), hint(48)]);
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Input classification and pairing for extraction: what a file offers
//! (full DWARF binary, split companion, dwp, nothing), decided by
//! content, and whether a split file and a binary were really split
//! from the same link.

use object::{Object, ObjectSection};

use std::fmt;

/// What a file offers extraction, decided by its content — never by
/// its name, so a refusal can say what the file *is*.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DebugFlavor {
    /// DWARF plus real program contents: one file can play every role.
    Full,
    /// DWARF whose program sections were emptied when the debug info
    /// was split out (`objcopy --only-keep-debug`, a dSYM).
    Companion,
    /// A DWARF package (`-C split-debuginfo=packed`): dwo units and
    /// their indexes, no symbols, no program contents.
    Dwp,
    /// No DWARF at all.
    NoDebugInfo,
}

impl DebugFlavor {
    /// Whether extraction from this flavor also needs the sibling
    /// binary it was split from.
    pub fn is_split(self) -> bool {
        matches!(self, DebugFlavor::Companion | DebugFlavor::Dwp)
    }
}

impl fmt::Display for DebugFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DebugFlavor::Full => "a full debug binary",
            DebugFlavor::Companion => "split debug info (a companion file)",
            DebugFlavor::Dwp => "a DWARF package (dwp)",
            DebugFlavor::NoDebugInfo => "a binary carrying no debug info",
        })
    }
}

/// Look a section up under both its ELF and Mach-O spellings.
/// `object` translates the `.debug_*` names itself; the program
/// sections it does not.
fn section_by_name<'data, 'file>(
    obj: &'file object::File<'data>,
    elf: &str,
    macho: &str,
) -> Option<object::Section<'data, 'file>> {
    obj.section_by_name(elf)
        .or_else(|| obj.section_by_name(macho))
}

/// Whether a section claims memory but carries no file bytes to back
/// it: an ELF `SHT_NOBITS` section has no file range at all, and a
/// dSYM's program sections keep their sizes with a file offset of 0 —
/// the Mach-O header, not their contents.
fn contentless(section: &object::Section<'_, '_>) -> bool {
    section.size() > 0
        && match section.file_range() {
            None => true,
            Some((offset, _)) => offset == 0,
        }
}

fn has_data(obj: &object::File<'_>, name: &str) -> bool {
    obj.section_by_name(name)
        .is_some_and(|s| s.size() > 0 && !contentless(&s))
}

/// Classify a parsed object by what it carries.
pub(super) fn classify(obj: &object::File<'_>) -> DebugFlavor {
    // A dwp's units live in the `.dwo` sections; a `.debug_info` worth
    // reading is what it does not have.
    if has_data(obj, ".debug_cu_index") || has_data(obj, ".debug_info.dwo") {
        return DebugFlavor::Dwp;
    }
    if !has_data(obj, ".debug_info") {
        return DebugFlavor::NoDebugInfo;
    }
    // DWARF is present; whether the program sections still are decides
    // companion against full. A file with no text section at all never
    // ran and never will — treat it as split.
    match section_by_name(obj, ".text", "__text") {
        Some(text) if !contentless(&text) => DebugFlavor::Full,
        _ => DebugFlavor::Companion,
    }
}

/// The exact-identity note a file carries: an ELF build-id or a Mach-O
/// UUID. illumos binaries carry neither.
pub(super) fn file_id(obj: &object::File<'_>) -> Option<Vec<u8>> {
    if let Ok(Some(id)) = obj.build_id() {
        return Some(id.to_vec());
    }
    if let Ok(Some(uuid)) = obj.mach_uuid() {
        return Some(uuid.to_vec());
    }
    None
}

/// Check that a debug-info file and a binary are two halves of the
/// same link. `None` means they are (as far as can be told); `Some`
/// names the first disagreement found.
///
/// Both files carrying a build-id (or UUID) settles it exactly. When
/// either side has none — every illumos binary — the loaded sections
/// stand in: a split pair keeps every allocated section at the address
/// and size the link gave it, so any section present in both that has
/// moved is proof of two different links. Sections without an address
/// (`.symtab`, the `.debug_*` family) are skipped: splitting and
/// stripping legitimately rewrite those.
pub(super) fn sibling_mismatch(
    binary: &object::File<'_>,
    debug: &object::File<'_>,
) -> Option<String> {
    if let (Some(b), Some(d)) = (file_id(binary), file_id(debug)) {
        return match b == d {
            true => None,
            false => Some("their build ids differ".to_owned()),
        };
    }

    let placed: Vec<(String, u64, u64)> = debug
        .sections()
        .filter(|s| s.address() != 0 && s.size() > 0)
        .filter_map(|s| Some((s.name().ok()?.to_owned(), s.address(), s.size())))
        .collect();
    for (name, address, size) in placed {
        let Some(twin) = binary.section_by_name(&name) else {
            // Stripping the binary removes whole sections (`.debug_*`
            // under `strip -x`); absence is not disagreement.
            continue;
        };
        if twin.address() != address || twin.size() != size {
            return Some(format!(
                "section {name} spans {address:#x}+{size:#x} in one and {:#x}+{:#x} in the other",
                twin.address(),
                twin.size(),
            ));
        }
    }
    None
}

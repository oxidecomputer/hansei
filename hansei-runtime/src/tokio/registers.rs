// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Classifying register values against a target's recorded joins.
//!
//! A register block is only worth printing annotated: the value alone
//! says nothing about whether it points into a task's allocation, a
//! thread's stack, or mapped text. This module is the pure classifier
//! behind those annotations — given the mapping table, every lwp's
//! recorded stack range, and the task extents, it says what one value
//! points into. Classification comes from recorded joins only, never
//! from address neighborhood: on Linux, thread stacks and malloc
//! arenas are interleaved anonymous mappings in the same region, and
//! guessing by adjacency would attribute one to the other. Rendering
//! the answer, and the spelling of each claim, stay with the caller.

use crate::tokio::model::TaskExtents;
use proc::{Mappings, SymbolBuf};

use std::ops::Range;

/// Values below one page are read as plain integers: a flag word, a
/// count, an enum discriminant. Nothing maps there, and annotating
/// every small constant `unmapped` would bury the claims that matter.
const POINTER_FLOOR: u64 = 0x1000;

/// One lwp's recorded stack, as the core states it: the stack range
/// the reader recorded, and the rsp that anchored it. On illumos the
/// range is the thread's own `stack_t`; on Linux it is the whole
/// segment holding rsp, so adjacent stacks merged into one VMA record
/// the same range for several lwps — which is why the rsp rides
/// along (see [`RegClassifier::classify`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LwpStack {
    pub tid: u32,
    pub rsp: u64,
    pub range: Range<u64>,
}

/// What one register value points into — the annotation ladder, most
/// specific claim first. Spelling the claim is the caller's business.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RegClass {
    /// Inside a task's allocation: the task's index in the list the
    /// extents were built from, and the offset within the allocation.
    Task { index: usize, offset: u64 },
    /// Inside the recorded stack of the lwp whose registers these are.
    OwnStack,
    /// Inside another lwp's recorded stack.
    LwpStack(u32),
    /// In a thread-stack region, but attributable to no one lwp: below
    /// every rsp anchored in a merged VMA, or in a stack mapping
    /// outside every recorded range.
    StackRegion,
    /// A file-backed address a symbol covers: the mangled name, and
    /// the offset within the symbol.
    Symbol { name: String, offset: u64 },
    /// A file-backed address no symbol covers: the object's path.
    Object(String),
    /// A mapped anonymous address nothing above claimed.
    Heap,
    /// A pointer-sized value (or null) mapped nowhere.
    Unmapped,
    /// A small non-pointer integer: no claim to make.
    Small,
}

/// The recorded joins one classification reads. Every field is state
/// the session already holds; the classifier owns no discovery.
pub struct RegClassifier<'a> {
    pub mappings: &'a Mappings,
    /// Every lwp's recorded stack, in any order.
    pub stacks: &'a [LwpStack],
    pub extents: &'a TaskExtents,
}

impl RegClassifier<'_> {
    /// Classify `value` as read from `lwp`'s registers. `symbol` is
    /// the target's address-to-symbol lookup, consulted only for
    /// file-backed addresses.
    ///
    /// When several lwps record the same containing range (Linux's
    /// merged-VMA case), the rsp anchors are the joins that remain:
    /// the value is attributed to the sharer with the highest rsp at
    /// or below it. A live stack address always wins its own thread
    /// that way — no other thread's rsp can sit between a thread's
    /// rsp and its own stack top — while a value below every anchored
    /// rsp gets the noncommittal region claim. The one soft spot is a
    /// dead zone above a merged neighbor's live stack, which
    /// attributes to that neighbor; the recorded joins cannot split a
    /// thread's untouched reserve from its live frames.
    pub fn classify(
        &self,
        lwp: u32,
        value: u64,
        symbol: &dyn Fn(u64) -> Option<SymbolBuf>,
    ) -> RegClass {
        if value != 0 && value < POINTER_FLOOR {
            return RegClass::Small;
        }

        if let Some((index, offset)) = self.extents.locate(value) {
            return RegClass::Task { index, offset };
        }

        let holding: Vec<&LwpStack> = self
            .stacks
            .iter()
            .filter(|s| s.range.contains(&value))
            .collect();
        match holding.as_slice() {
            [] => {}
            [only] => return self.attributed(lwp, only.tid),
            shared => {
                return match shared
                    .iter()
                    .filter(|s| s.rsp <= value)
                    .max_by_key(|s| s.rsp)
                {
                    Some(anchor) => self.attributed(lwp, anchor.tid),
                    None => RegClass::StackRegion,
                };
            }
        }

        let Some(mapping) = self.mappings.get(value) else {
            return RegClass::Unmapped;
        };
        // The recorded ranges said nothing, but the mapping holds some
        // lwp's anchor: a thread-stack region the ranges do not cover.
        if self.stacks.iter().any(|s| mapping.range().contains(&s.rsp)) {
            return RegClass::StackRegion;
        }
        match &mapping.path {
            Some(path) => match symbol(value) {
                Some(sym) => RegClass::Symbol {
                    offset: value - sym.st_value,
                    name: sym.name,
                },
                None => RegClass::Object(path.clone()),
            },
            None => RegClass::Heap,
        }
    }

    fn attributed(&self, lwp: u32, tid: u32) -> RegClass {
        if tid == lwp {
            RegClass::OwnStack
        } else {
            RegClass::LwpStack(tid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LwpStack, RegClass, RegClassifier};
    use crate::tokio::model::TaskExtents;
    use proc::{LoadedObjectWithPath, MapFlags, Mappings, SymbolBuf};

    const READ: u32 = 0x04;
    const WRITE: u32 = 0x02;
    const EXEC: u32 = 0x01;
    const ANON: u32 = 0x40;

    fn mapping(vaddr: u64, size: u64, flags: u32, path: Option<&str>) -> LoadedObjectWithPath {
        LoadedObjectWithPath {
            path: path.map(str::to_owned),
            vaddr,
            size,
            flags: MapFlags(flags),
        }
    }

    /// The zoo every test classifies against: text and an anonymous
    /// arena holding one task's extent, plus whatever stacks a test
    /// lays on. No symbol resolves unless a test says so.
    fn fixture() -> (Mappings, TaskExtents) {
        let mappings: Mappings = [
            mapping(0x40_0000, 0x1000, READ | EXEC, Some("/bin/app")),
            mapping(0x50_0000, 0x1000, READ, Some("/lib/libc.so")),
            mapping(0x7000_0000, 0x1_0000, READ | WRITE | ANON, None),
        ]
        .into_iter()
        .collect();
        let extents = TaskExtents {
            spans: vec![(0x7000_2000, 0x7000_2100, 3)],
        };
        (mappings, extents)
    }

    fn no_symbol(_: u64) -> Option<SymbolBuf> {
        None
    }

    fn classify(stacks: &[LwpStack], lwp: u32, value: u64) -> RegClass {
        let (mappings, extents) = fixture();
        RegClassifier {
            mappings: &mappings,
            stacks,
            extents: &extents,
        }
        .classify(lwp, value, &no_symbol)
    }

    /// Rung 5's floor and its edges: a small non-pointer integer makes
    /// no claim, while null and a pointer-sized value mapped nowhere
    /// are both called unmapped.
    #[test]
    fn test_small_integers_make_no_claim() {
        assert_eq!(classify(&[], 1, 0x14), RegClass::Small);
        assert_eq!(classify(&[], 1, 0xfff), RegClass::Small);
        assert_eq!(classify(&[], 1, 0), RegClass::Unmapped);
        assert_eq!(classify(&[], 1, 0xdead_0000), RegClass::Unmapped);
    }

    /// A task allocation claims its addresses even though it sits in a
    /// mapped anonymous region; the rest of that region is heap.
    #[test]
    fn test_a_task_allocation_wins_over_its_mapping() {
        assert_eq!(
            classify(&[], 1, 0x7000_2010),
            RegClass::Task {
                index: 3,
                offset: 0x10
            }
        );
        assert_eq!(classify(&[], 1, 0x7000_0800), RegClass::Heap);
    }

    /// A value inside exactly one recorded stack range attributes to
    /// that lwp — as this lwp's own stack, or by the other's number.
    #[test]
    fn test_stack_ranges_attribute_by_lwp() {
        let stacks = [
            LwpStack {
                tid: 7,
                rsp: 0x9000_0800,
                range: 0x9000_0000..0x9001_0000,
            },
            LwpStack {
                tid: 8,
                rsp: 0x9002_0800,
                range: 0x9002_0000..0x9003_0000,
            },
        ];
        assert_eq!(classify(&stacks, 7, 0x9000_0900), RegClass::OwnStack);
        assert_eq!(classify(&stacks, 7, 0x9002_0900), RegClass::LwpStack(8));
    }

    /// Adjacent stacks merged into one VMA record the same range for
    /// several lwps; the rsp anchors then attribute what they can — a
    /// value at or above an anchor goes to the nearest one below it,
    /// and a value below every anchor gets the noncommittal region.
    #[test]
    fn test_a_merged_vma_attributes_by_rsp_anchor() {
        let merged = 0x9000_0000..0x9400_0000;
        let stacks = [
            LwpStack {
                tid: 7,
                rsp: 0x93f0_0000,
                range: merged.clone(),
            },
            LwpStack {
                tid: 8,
                rsp: 0x9070_0000,
                range: merged.clone(),
            },
        ];
        // At and above the higher anchor: the higher thread's.
        assert_eq!(classify(&stacks, 7, 0x93f0_0000), RegClass::OwnStack);
        assert_eq!(classify(&stacks, 8, 0x93f0_0010), RegClass::LwpStack(7));
        // Between the anchors: the lower thread's run.
        assert_eq!(classify(&stacks, 8, 0x9080_0000), RegClass::OwnStack);
        // Below every anchor: no attribution to make.
        assert_eq!(classify(&stacks, 7, 0x9000_0010), RegClass::StackRegion);
    }

    /// A value in the same mapping as an lwp's anchor but outside
    /// every recorded range — the ranges narrower than the VMA, the
    /// illumos `stack_t` shape — is a thread-stack region, not heap.
    #[test]
    fn test_a_stack_mapping_outside_every_range_is_noncommittal() {
        let stacks = [LwpStack {
            tid: 7,
            rsp: 0x7000_8800,
            range: 0x7000_8000..0x7000_9000,
        }];
        assert_eq!(classify(&stacks, 7, 0x7000_4000), RegClass::StackRegion);
    }

    /// File-backed addresses name the covering symbol with its offset,
    /// or the object when no symbol covers them; anonymous ones are
    /// heap.
    #[test]
    fn test_file_backed_addresses_name_the_symbol_or_object() {
        let (mappings, extents) = fixture();
        let classifier = RegClassifier {
            mappings: &mappings,
            stacks: &[],
            extents: &extents,
        };
        let symbol = |addr: u64| {
            (0x40_0100..0x40_0200).contains(&addr).then(|| SymbolBuf {
                name: "app_main".to_string(),
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0x40_0100,
                st_size: 0x100,
            })
        };
        assert_eq!(
            classifier.classify(1, 0x40_0140, &symbol),
            RegClass::Symbol {
                name: "app_main".to_string(),
                offset: 0x40
            }
        );
        assert_eq!(
            classifier.classify(1, 0x50_0040, &symbol),
            RegClass::Object("/lib/libc.so".to_string())
        );
    }
}

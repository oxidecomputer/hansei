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
/// every small constant would bury the claims that matter. Zero is the
/// exception, and is classified above this: it is the one value down
/// here that a register holds *as a pointer*.
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
    /// The alternate signal stack this lwp registered, where the
    /// target records one. Its own mapping, and anonymous like the
    /// heap — telling the two apart is the whole reason it is here.
    /// Empty where nothing said.
    pub altstack: Range<u64>,
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
    /// A file-backed address no symbol covers: the object's path, and
    /// which of its regions the address is in — which is most of what
    /// is left to say once no symbol will say more.
    Object { path: String, region: &'static str },
    /// Inside the alternate signal stack of the lwp whose registers
    /// these are, or of another lwp — the tid names which.
    AltStack(u32),
    /// Inside the `brk` heap: the one region an allocator grows, and
    /// the only one `pmap` calls `[ heap ]`.
    Heap,
    /// A mapped anonymous address nothing above claimed — `pmap`'s
    /// `[ anon ]`. A process has hundreds: an allocator's mmap-backed
    /// arenas, guard pages, the tables a threading library maps for
    /// itself. Saying "heap" of these would be asserting something
    /// false about all of them, and a target that cannot tell the
    /// break from the rest reports every anonymous mapping this way.
    Anon,
    /// A pointer-sized value mapped nowhere.
    Unmapped,
    /// Zero — the one value below the pointer floor worth a word,
    /// because it is the one that is a pointer, saying so.
    Null,
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
        if value == 0 {
            return RegClass::Null;
        }
        if value < POINTER_FLOOR {
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
        // An alternate signal stack is anonymous like everything below
        // it, so it has to be claimed before the fallbacks or it reads
        // as ordinary heap. A thread only stands on one while handling
        // a signal, which is exactly when saying so matters.
        if let Some(stack) = self
            .stacks
            .iter()
            .find(|s| !s.altstack.is_empty() && s.altstack.contains(&value))
        {
            return RegClass::AltStack(stack.tid);
        }
        match &mapping.path {
            Some(path) => match symbol(value) {
                Some(sym) => RegClass::Symbol {
                    offset: value - sym.st_value,
                    name: sym.name,
                },
                None => RegClass::Object {
                    path: path.clone(),
                    region: mapping.region(),
                },
            },
            // Anonymous, and the break is the only anonymous mapping
            // with a name worth giving.
            None if mapping.is_heap() => RegClass::Heap,
            None => RegClass::Anon,
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
    const BREAK: u32 = 0x10;

    /// One lwp's stack with no alternate signal stack — what most
    /// tests want, and what a target that records none reports.
    fn stack(tid: u32, rsp: u64, range: std::ops::Range<u64>) -> LwpStack {
        LwpStack {
            tid,
            rsp,
            range,
            altstack: 0..0,
        }
    }

    fn mapping(vaddr: u64, size: u64, flags: u32, path: Option<&str>) -> LoadedObjectWithPath {
        LoadedObjectWithPath {
            path: path.map(str::to_owned),
            vaddr,
            size,
            flags: MapFlags(flags),
        }
    }

    /// The zoo every test classifies against: text, an anonymous
    /// arena holding one task's extent, and the break — which is a
    /// separate mapping from the arena on purpose, because telling
    /// those two apart is the thing being tested. Plus whatever
    /// stacks a test lays on. No symbol resolves unless a test says
    /// so.
    fn fixture() -> (Mappings, TaskExtents) {
        let mappings: Mappings = [
            mapping(0x40_0000, 0x1000, READ | EXEC, Some("/bin/app")),
            mapping(0x50_0000, 0x1000, READ, Some("/lib/libc.so")),
            mapping(0x7000_0000, 0x1_0000, READ | WRITE | ANON, None),
            mapping(0x8000_0000, 0x1_0000, READ | WRITE | ANON | BREAK, None),
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
    /// no claim, a pointer-sized value mapped nowhere is unmapped, and
    /// null is neither — it is below the floor but it is a pointer,
    /// and the only one down there.
    #[test]
    fn test_small_integers_make_no_claim() {
        assert_eq!(classify(&[], 1, 0x14), RegClass::Small);
        assert_eq!(classify(&[], 1, 0xfff), RegClass::Small);
        assert_eq!(classify(&[], 1, 0), RegClass::Null);
        assert_eq!(classify(&[], 1, 0xdead_0000), RegClass::Unmapped);
    }

    /// A task allocation claims its addresses even though it sits in a
    /// mapped anonymous region; the rest of that region is anonymous
    /// memory, which is not the heap.
    #[test]
    fn test_a_task_allocation_wins_over_its_mapping() {
        assert_eq!(
            classify(&[], 1, 0x7000_2010),
            RegClass::Task {
                index: 3,
                offset: 0x10
            }
        );
        assert_eq!(classify(&[], 1, 0x7000_0800), RegClass::Anon);
    }

    /// A value inside exactly one recorded stack range attributes to
    /// that lwp — as this lwp's own stack, or by the other's number.
    #[test]
    fn test_stack_ranges_attribute_by_lwp() {
        let stacks = [
            stack(7, 0x9000_0800, 0x9000_0000..0x9001_0000),
            stack(8, 0x9002_0800, 0x9002_0000..0x9003_0000),
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
            stack(7, 0x93f0_0000, merged.clone()),
            stack(8, 0x9070_0000, merged.clone()),
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
        let stacks = [stack(7, 0x7000_8800, 0x7000_8000..0x7000_9000)];
        assert_eq!(classify(&stacks, 7, 0x7000_4000), RegClass::StackRegion);
    }

    /// File-backed addresses name the covering symbol with its offset,
    /// or the object when no symbol covers them.
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
        // No symbol covers it, so what is left to say is the object and
        // the region of it the address is in — read-only here, where
        // the executable's own mapping would say text.
        assert_eq!(
            classifier.classify(1, 0x50_0040, &symbol),
            RegClass::Object {
                path: "/lib/libc.so".to_string(),
                region: "rodata",
            }
        );
        assert_eq!(
            classifier.classify(1, 0x40_0040, &no_symbol),
            RegClass::Object {
                path: "/bin/app".to_string(),
                region: "text",
            }
        );
    }

    /// The break is the heap and every other anonymous mapping is not.
    ///
    /// A process maps hundreds of anonymous regions and exactly one of
    /// them is the break, so the flag is what decides it — calling
    /// them all heap would be a false claim about all but one. A
    /// target that cannot set the flag (a Linux core, which records no
    /// break) therefore reports anon everywhere, which is the weaker
    /// answer rather than a wrong one.
    #[test]
    fn test_only_the_break_is_the_heap() {
        assert_eq!(classify(&[], 1, 0x8000_0800), RegClass::Heap);
        assert_eq!(classify(&[], 1, 0x7000_0800), RegClass::Anon);
    }

    /// An alternate signal stack is claimed as one rather than read as
    /// the anonymous mapping it otherwise looks exactly like — by its
    /// own lwp's number or another's, the way a thread stack is. The
    /// mapping under it is ordinary anonymous memory, so a target that
    /// records no alternate stack still classifies everything else the
    /// same.
    #[test]
    fn test_an_alternate_signal_stack_is_not_anonymous_memory() {
        let mut with_alt = stack(7, 0x9000_0800, 0x9000_0000..0x9001_0000);
        with_alt.altstack = 0x7000_4000..0x7000_6000;
        let stacks = [with_alt, stack(8, 0x9002_0800, 0x9002_0000..0x9003_0000)];

        assert_eq!(classify(&stacks, 7, 0x7000_5000), RegClass::AltStack(7));
        assert_eq!(classify(&stacks, 8, 0x7000_5000), RegClass::AltStack(7));
        // Just outside it, the same mapping is anonymous again.
        assert_eq!(classify(&stacks, 7, 0x7000_6000), RegClass::Anon);
        // And an empty altstack claims nothing at all, however many
        // lwps report one — the empty range must not swallow an
        // address the way `0..0` containing nothing already says.
        let none = [stack(7, 0x9000_0800, 0x9000_0000..0x9001_0000)];
        assert_eq!(classify(&none, 7, 0x7000_5000), RegClass::Anon);
    }
}

//! The `vtables` command: which vtables implement a trait, where they
//! are in the target, and what is in their slots.
//!
//! rustc describes every vtable it instantiates — the `<Concrete as
//! Trait>` pair, the address, and one member per occupied slot — and
//! the bundle carries that table, so this answers from a tokio info and
//! a core with no debug info anywhere near. A vacant slot is part of
//! what it answers: a trait object dispatching through a slot rustc
//! left empty is visible here statically, before anything jumps.
//!
//! The addresses need care. What the debug info records is where the
//! vtable was *linked*, and what a reader wants is where it is *now*,
//! which is that plus the target's executable load bias. Worse, the two
//! only mean the same thing when the tokio info came from the very
//! build that ran: extract from a second, separately-linked compilation
//! of the same sources and every address is a fiction.
//!
//! So the addresses are checked twice, at two scales. Once for the
//! table as a whole ([`Placement`]): a recorded address belongs in some
//! object's mapped image, and a table whose addresses land in anonymous
//! memory instead describes a build this target did not run — then no
//! recorded address is offered at all, because every one of them is
//! wrong. Then once per row, against the words it names — the same
//! believability check `whatis` applies to an arbitrary address — so a
//! single vtable that does not hold up is marked rather than presented
//! as fact.
//!
//! Where the recorded addresses are another build's there is a second
//! route to this target's ([`Scan`]): sweep its data for vtable-shaped
//! runs and name each one by the `<Concrete as Trait>` its first method
//! symbol spells, which is the same pair the recorded table is keyed
//! by. It needs symbols, which the recorded route does not, and it
//! finds a subset — so the two are complementary, and the listing takes
//! the recorded addresses whenever they are this target's.

use crate::Session;
use crate::output::Table;
use crate::summary::counted;

use anyhow::{Context as _, Result};
use hansei_bundle::{BundleView, VTABLE_HEADER_SLOTS, VtableEntry, names};
use proc::{Mappings, Target};

use std::collections::HashMap;
use std::io;

/// How many matches print their slots without being asked for them.
/// One match is the end of a search rather than a listing to scan, and
/// the slots are what the search was for.
const EXPAND: usize = 1;

/// The largest alignment a Rust type can be given — the bound the
/// harvest screens a vtable's own header against, applied again here to
/// the words the target has at that address.
const MAX_ALIGN: u64 = 1 << 30;

pub(crate) fn exec_vtables<T: proc::Target>(
    session: &Session<'_, T>,
    words: &[String],
    verbose: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let image = Image::of(session);
    let pattern = match needle(words) {
        Some(needle) => Some(crate::pattern::Pattern::new(&needle).context("vtables")?),
        None => None,
    };
    report_vtables(
        &session.ctx.view,
        &image,
        &session.impl_fold,
        pattern.as_ref(),
        verbose,
        out,
    )
}

/// The pattern a typed line asked for: the words joined back into the
/// one spelling they were split from, so a name holding spaces pastes in
/// whole — and nothing at all where no word was typed, which is the
/// question "how many are there" rather than a match on everything.
fn needle(words: &[String]) -> Option<String> {
    let needle = words.join(" ");
    (!needle.is_empty()).then_some(needle)
}

/// The target a vtable's words are read from and judged against.
///
/// `whatis` reads a vtable through this too, running the same join
/// backwards: an address it is handed unbiases to the one the table
/// records, rather than a recorded address biasing forward into the
/// target.
pub(crate) struct Image<'a> {
    pub(crate) target: &'a dyn Target,
    pub(crate) mappings: &'a Mappings,
    /// How far the executable landed from where it was linked, which is
    /// what moves a recorded address into this target. `None` where the
    /// target cannot say, and then there is no address in it to offer.
    pub(crate) bias: Option<u64>,
}

impl<'a> Image<'a> {
    /// How this session reads the target.
    pub(crate) fn of<T: proc::Target>(session: &'a Session<'_, T>) -> Self {
        Image {
            target: session.proc,
            mappings: &session.ctx.mappings,
            bias: session.proc.exec_bias(),
        }
    }

    /// Where an entry's vtable is in this target — `None` where the
    /// table's addresses are not this target's to begin with.
    fn at(&self, entry: &VtableEntry) -> Option<u64> {
        Some(entry.address.wrapping_add(self.bias?))
    }

    /// Where an address in this target was linked, which is the address
    /// the recorded table would have it under. `None` where the target
    /// cannot say where its executable landed, or where the address is
    /// below the bias and so belongs to no part of it.
    pub(crate) fn unbias(&self, addr: u64) -> Option<u64> {
        addr.checked_sub(self.bias?)
    }

    /// Every word of a vtable at `addr`, one per slot. A word the
    /// target cannot serve is `None` rather than absent, so the slots
    /// keep the numbers the debug info gave them.
    pub(crate) fn words(&self, addr: u64, slots: u16) -> Vec<Option<u64>> {
        (0..u64::from(slots))
            .map(|i| self.target.read_u64(addr + i * 8).ok())
            .collect()
    }

    /// Whether `addr` is in mapped text, which is where every function
    /// a vtable dispatches through has to be.
    fn is_text(&self, addr: u64) -> bool {
        self.mappings.get(addr).is_some_and(|m| m.flags.is_exec())
    }

    /// Whether `addr` is in some object's mapped image, which is where
    /// static data — a vtable among it — has to be. The test is that a
    /// file is behind the mapping: which object it is does not matter,
    /// since a `dyn` implemented in a library keeps its vtable there.
    fn is_image(&self, addr: u64) -> bool {
        self.mappings.get(addr).is_some_and(|m| m.path.is_some())
    }

    /// The demangled symbol covering `addr`.
    pub(crate) fn symbol(&self, addr: u64) -> Option<String> {
        let symbol = self.target.lookup_symbol_by_addr(addr)?;
        let stripped = hansei_bundle::strip_llvm_suffix(&symbol.name);
        let demangled = rustc_demangle::try_demangle(stripped).ok()?;
        Some(format!("{demangled:#}"))
    }
}

/// Whether the addresses the recorded table carries are this target's
/// addresses at all.
///
/// A vtable is static data in some object's image, so a recorded
/// address, once biased, lands in a mapping that has a file behind it —
/// the executable's, or a library's. Land them in anonymous memory
/// instead and the arithmetic is not off by a little: the tokio info
/// describes a *different build*, whose sections are laid out
/// differently, and every address in the table is a statement about
/// that build rather than this one.
///
/// This is the coarse gate, and the reason it exists is that the
/// per-row check cannot say it. A row whose words deny it is one fact
/// about one vtable; forty-five thousand of them are one fact about the
/// pair of files, and it is the second that a reader has to be told
/// once instead of inferring from a column of marks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Placement {
    /// The recorded addresses land in mapped images, so they are this
    /// target's.
    Placed,
    /// They do not: only `placed` of `checked` land anywhere an image
    /// is mapped, so this tokio info is not from the build that ran.
    OtherBuild { placed: usize, checked: usize },
    /// The target cannot say where its executable landed, so no
    /// recorded address can be moved into it at all.
    Unbiased,
    /// There is no table to place.
    Empty,
}

/// How many recorded addresses have to land in a mapped image for the
/// table to be this target's.
///
/// Not all of them: a core need not dump every mapping, and a vtable in
/// a library the core left out is a miss that says nothing about the
/// build. Not one of them either — on a mismatched pair an address can
/// fall inside some unrelated file-backed mapping by luck. A majority
/// separates "laid out like this target" from "laid out like something
/// else" with room on both sides, and the two real cases are not near
/// the line: a matched pair places essentially all of them and a
/// mismatched one essentially none.
const PLACED_FRACTION: usize = 2;

impl Placement {
    /// Whether this target's mappings bear out the table's addresses.
    ///
    /// Every entry is looked at rather than a sample. The lookup is a
    /// binary search over a few hundred mappings, so the whole of
    /// nexus's forty-five thousand costs well under a millisecond, and
    /// a sample would have to defend its size against a table sorted
    /// by name — whose addresses are in no order at all.
    pub(crate) fn of(image: &Image<'_>, entries: &[VtableEntry]) -> Placement {
        if entries.is_empty() {
            return Placement::Empty;
        }
        if image.bias.is_none() {
            return Placement::Unbiased;
        }
        let placed = entries
            .iter()
            .filter(|entry| image.at(entry).is_some_and(|addr| image.is_image(addr)))
            .count();
        match placed * PLACED_FRACTION >= entries.len() {
            true => Placement::Placed,
            false => Placement::OtherBuild {
                placed,
                checked: entries.len(),
            },
        }
    }

    /// Whether a recorded entry says anything about *this* target — the
    /// gate on using the table at all, as against merely printing its
    /// addresses.
    pub(crate) fn applies(self) -> bool {
        matches!(self, Placement::Placed | Placement::Empty)
    }

    /// What is wrong with the table's addresses, in one clause — the
    /// form an attach summary can print under a heading. `None` where
    /// nothing is wrong, which is the ordinary case and wants no line.
    pub(crate) fn note(self) -> Option<String> {
        match self {
            Placement::Placed | Placement::Empty => None,
            Placement::Unbiased => {
                Some("this target cannot say where its executable landed".to_string())
            }
            Placement::OtherBuild { placed, checked } => Some(format!(
                "the tokio info is from a different build than the core \
                 ({placed} of its {checked} recorded addresses land in a \
                 mapped image)"
            )),
        }
    }

    /// The same fault as the line a listing leads with: what is wrong,
    /// what is missing from the listing because of it, and what to do.
    fn listing_note(self) -> Option<String> {
        let note = self.note()?;
        Some(match self {
            Placement::OtherBuild { .. } => format!(
                "{note}, so no address is shown below. The pairs, slot counts \
                 and vacancies are the debug info's own and hold either way; \
                 extract a tokio info from the binary that ran to place them."
            ),
            _ => format!(
                "{note}, so the addresses below are link-time ones and nothing \
                 was read at them."
            ),
        })
    }
}

/// What the memory at an entry's address says about the entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// A vtable of the shape the debug info describes is there.
    Confirmed,
    /// Something else is: this tokio info describes a build the target
    /// did not run, or those bytes have been overwritten.
    Unverified,
    /// The target holds not one word of it, so it says nothing either
    /// way. An address out of a build this target did not run lands
    /// wherever it lands, and a hole between two of this one's segments
    /// is as likely as the middle of one; a core that dumped the
    /// mapping only in part leaves the same silence.
    Unreadable,
    /// Never asked. The target cannot say where its executable landed,
    /// so the recorded address stays a link-time one and there is no
    /// address in the target to check.
    Unbiased,
}

impl Standing {
    /// What reading `addr` in this target proved about the entry the
    /// table records there.
    pub(crate) fn of(image: &Image<'_>, entry: &VtableEntry, words: &[Option<u64>]) -> Standing {
        match stands(image, entry, words) {
            true => Standing::Confirmed,
            false if words.iter().all(Option::is_none) => Standing::Unreadable,
            false => Standing::Unverified,
        }
    }

    /// How an address is qualified where the words at it do not bear
    /// out what is being said about it — nothing at all where they do.
    pub(crate) fn mark(self) -> &'static str {
        match self {
            Standing::Confirmed => "",
            Standing::Unreadable => " (unreadable)",
            Standing::Unverified | Standing::Unbiased => " (unverified)",
        }
    }
}

/// How far past the header a scan looks for a method whose symbol
/// names the pair.
///
/// Slot 3 is not reliably the one. It is as likely to hold a
/// supertrait's shim or a closure's `call_once`, neither of which is
/// mangled as a `<Concrete as Trait>` method, and the first that is
/// often sits a slot or two further on. Measured against a target whose
/// recorded table is known good: slot 3 alone joined 353 vtables of the
/// 1,194 recorded, and looking on through slot 11 joined 1,138 — with
/// almost all of the gain at slot 4.
const SCAN_SLOTS: u16 = 12;

/// Where the *target* says its vtables are, found by reading it rather
/// than by trusting the recorded addresses.
///
/// Rust lays a vtable out as drop glue, size, align, then one method
/// per slot, and a method is a function with a symbol — `<Concrete as
/// Trait>::method`, which names both halves of the very pair the
/// recorded table is keyed by. So the target can be swept for
/// vtable-shaped runs and each one joined back to its entry by that
/// pair, with no address in common between the build that ran and the
/// build the debug info came from. That is the whole point: it is the
/// answer for a tokio info whose own addresses are another build's.
///
/// It costs what the recorded table does not: symbols. An illumos core
/// carries every mapped object's, so this works there whatever binary
/// the tokio info came from. A Linux core carries none and only the
/// `--binary` executable's are on hand — which is the build that ran,
/// so where this route works there the recorded one usually does too.
/// The two are complementary rather than redundant, which is why
/// neither replaces the other.
///
/// Joining on the pair rather than on the concrete type alone is what
/// makes it trustworthy. A symbol spells a type as the mangler does and
/// the debug info spells it as rustc's type printer does, and the two
/// disagree — `alloc::sync::Arc` against `Arc` — often enough that a
/// concrete-only join was built and thrown out once already. Requiring
/// the trait to agree as well leaves far less room for a wrong answer,
/// and a pair that does not match is dropped rather than guessed at.
pub(crate) struct Scan {
    /// The address each recorded entry's vtable has in this target, by
    /// entry index. `None` where the sweep did not find it — a trait
    /// with no methods has no symbol to be found by, and a core need
    /// not have dumped the data at all.
    found: Vec<Option<u64>>,
    /// Vtable-shaped runs looked at, and how many joined to an entry.
    examined: usize,
    joined: usize,
}

impl Scan {
    /// Sweep the target for vtables and join them to the recorded
    /// table's pairs.
    pub(crate) fn of(image: &Image<'_>, view: &BundleView<'_>) -> Scan {
        let entries = &view.bundle().vtables.entries;
        let wanted = pair_index(view);

        let text = TextRanges::of(image.mappings);
        let mut scan = Scan {
            found: vec![None; entries.len()],
            examined: 0,
            joined: 0,
        };
        let mut addresses: HashMap<String, std::collections::BTreeSet<u64>> = HashMap::default();
        // Only data, and only what has a file behind it: a vtable is a
        // static in some object's image, so the heap and the stacks —
        // which are most of a target — hold none and sweeping them is
        // time spent to find nothing.
        for mapping in image
            .mappings
            .iter()
            .filter(|m| m.path.is_some() && !m.flags.is_exec())
        {
            for (addr, len) in proc::readable_runs(mapping.vaddr, mapping.size, |a, max| {
                image.target.readable_len(a, max)
            }) {
                let Ok(bytes) = image.target.read_bytes(addr, len) else {
                    continue;
                };
                scan.sweep(
                    image,
                    view,
                    entries,
                    &wanted,
                    &mut addresses,
                    addr,
                    bytes,
                    &text,
                );
            }
        }
        // Hand each pair's addresses to its rows. Both sides are in
        // address order, which makes the assignment stable rather than
        // meaningful: the rows of one pair describe the same vtable, so
        // there is nothing to get right beyond how many were found.
        for (pair, indices) in &wanted {
            let Some(found) = addresses.get(pair) else {
                continue;
            };
            for (&index, &addr) in indices.iter().zip(found) {
                scan.found[index] = Some(addr);
                scan.joined += 1;
            }
        }
        scan
    }

    /// Look at every eight-byte-aligned position in one readable run.
    #[allow(clippy::too_many_arguments)]
    fn sweep(
        &mut self,
        image: &Image<'_>,
        view: &BundleView<'_>,
        entries: &[VtableEntry],
        wanted: &HashMap<String, Vec<usize>>,
        addresses: &mut HashMap<String, std::collections::BTreeSet<u64>>,
        base: u64,
        bytes: &[u8],
        text: &TextRanges,
    ) {
        let word = |at: usize| {
            let end = at.checked_add(8)?;
            Some(u64::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
        };
        let first = (base.wrapping_neg() & 7) as usize;
        for at in (first..bytes.len().saturating_sub(24)).step_by(8) {
            // A cheap screen first, on the borrowed slice: an
            // alignment no type is given, a size that is not a
            // multiple of it, or drop glue that is not code, is not a
            // vtable however the rest of it reads. This runs at every
            // aligned word of the target's data, so it must not cost a
            // read; what survives it is rare enough to afford one.
            let (Some(drop_fn), Some(size), Some(align)) = (word(at), word(at + 8), word(at + 16))
            else {
                continue;
            };
            if !plausible_header(drop_fn, size, align, |a| text.contains(a)) {
                continue;
            }
            self.examined += 1;
            let addr = base + at as u64;
            if let Some(index) = identify(image, view, wanted, text, addr) {
                addresses
                    .entry(pair_key_of(view, &entries[index]))
                    .or_default()
                    .insert(addr);
            }
        }
    }

    /// Where this target has the vtable the recorded entry describes.
    fn at(&self, index: usize) -> Option<u64> {
        self.found.get(index).copied().flatten()
    }

    /// What the sweep did, for the line that says the addresses below
    /// were read out of the target rather than recorded — and how far
    /// that is to be trusted.
    ///
    /// Not all the way. The join is by method symbol, and a linker
    /// folds identical functions: where two near-identical types have
    /// the same compiled method, one symbol serves both vtables and a
    /// row can be shown its sibling's. Measured against a target whose
    /// recorded table is known good, 440 of the 493 pairs the sweep
    /// answered for got exactly the addresses the table records and 53
    /// got at least one that belongs to a sibling. So the words at
    /// every address are still read and the row marked where they do
    /// not bear it out, exactly as for a recorded address.
    fn note(&self) -> String {
        format!(
            "the addresses below were read out of the target instead — {} of \
             the {} vtable-shaped runs in it name a pair the tokio info also \
             records. That join is by method symbol, which a linker may have \
             folded with an identical one, so a row can be shown a \
             near-identical sibling's vtable; as ever, the words at each \
             address are read and a row they do not bear out is marked",
            self.joined, self.examined
        )
    }
}

/// Whether three words read as a vtable's header.
///
/// An alignment that is not a power of two, or larger than any Rust
/// type is given, is not one rustc emitted; a null drop slot is what it
/// leaves for a type with no glue to run, and a non-null one has to be
/// code.
///
/// The size is screened against the alignment because that is what
/// rules out the window one slot off from a real vtable — the sweep's
/// whole difficulty, since such a window still holds that vtable's
/// methods a slot along and so joins to the very pair it is not.
/// Shifted, the size word is the neighbour's drop pointer, and a Rust
/// type's size is a multiple of its alignment, which a text address in
/// a real program is not.
fn plausible_header(drop_fn: u64, size: u64, align: u64, is_text: impl Fn(u64) -> bool) -> bool {
    align != 0
        && align.is_power_of_two()
        && align <= MAX_ALIGN
        && size.is_multiple_of(align)
        && (drop_fn == 0 || is_text(drop_fn))
}

/// Which recorded entry the vtable at `addr` is, by the join [`Scan`]
/// describes: the first method slot whose symbol names a pair the table
/// records, with the run held to that entry's shape.
///
/// This is the whole join at one address, which is what a caller that
/// already has an address wants — `whatis`, handed the second word of a
/// trait object on a target whose recorded addresses are another
/// build's. The sweep screens candidates on a borrowed slice first,
/// because it looks at every aligned word of the target's data and
/// cannot afford a read apiece, and then comes here for the rest.
fn identify(
    image: &Image<'_>,
    view: &BundleView<'_>,
    wanted: &HashMap<String, Vec<usize>>,
    text: &TextRanges,
    addr: u64,
) -> Option<usize> {
    let entries = &view.bundle().vtables.entries;
    let words = image.words(addr, SCAN_SLOTS);
    let word = |slot: u16| words.get(usize::from(slot)).copied().flatten();
    if !plausible_header(word(0)?, word(1)?, word(2)?, |a| text.contains(a)) {
        return None;
    }
    for slot in VTABLE_HEADER_SLOTS..SCAN_SLOTS {
        let Some(method) = word(slot) else {
            break;
        };
        if !text.contains(method) {
            continue;
        }
        let Some(symbol) = image.symbol(method) else {
            continue;
        };
        let Some((concrete, trait_)) = hansei_bundle::symbols::trait_object_pair(&symbol) else {
            continue;
        };
        // A method naming a pair the table does not record says
        // nothing about this run; the next slot may still name one.
        let Some(&index) = wanted
            .get(&pair_key(concrete, trait_))
            .and_then(|v| v.first())
        else {
            continue;
        };
        // Past the end of the vtable the entry describes, the words
        // belong to whatever the linker put next — so a pair reached
        // out there is the neighbour's, and this run is not it. This is
        // the bound that makes looking beyond slot 3 safe.
        if slot >= entries[index].slot_count {
            return None;
        }
        // And the same check the listing applies to a recorded address
        // decides whether this really is that vtable's first word.
        let full = image.words(addr, entries[index].slot_count);
        return stands(image, &entries[index], &full).then_some(index);
    }
    None
}

/// The recorded pairs, indexed by the spelling a method symbol gives
/// them; normalizing both halves is what bridges the two formatting
/// paths.
///
/// A pair names a *set* of entries rather than one. rustc emits a
/// vtable per codegen unit that needs it, so one pair is recorded
/// several times over — six, for one of nexus's — and those entries
/// differ in nothing but their address. The target duplicates them the
/// same way, so what a sweep really recovers is a pair's addresses, and
/// which recorded row gets which is a distinction without a difference.
fn pair_index(view: &BundleView<'_>) -> HashMap<String, Vec<usize>> {
    let mut index: HashMap<String, Vec<usize>> = HashMap::default();
    for (position, entry) in view.bundle().vtables.entries.iter().enumerate() {
        if let (Some(concrete), Some(trait_)) = (view.str(entry.concrete), view.str(entry.trait_)) {
            index
                .entry(pair_key(concrete, trait_))
                .or_default()
                .push(position);
        }
    }
    index
}

/// Which recorded entry the vtable at one address is, for a caller
/// with an address and no sweep to hand — `whatis`, on a target whose
/// recorded addresses are another build's. Builds the pair index for
/// the one lookup, which a single address can afford.
pub(crate) fn identify_at(image: &Image<'_>, view: &BundleView<'_>, addr: u64) -> Option<usize> {
    identify(
        image,
        view,
        &pair_index(view),
        &TextRanges::of(image.mappings),
        addr,
    )
}

/// An entry's own pair key.
fn pair_key_of(view: &BundleView<'_>, entry: &VtableEntry) -> String {
    pair_key(
        view.str(entry.concrete).unwrap_or_default(),
        view.str(entry.trait_).unwrap_or_default(),
    )
}

/// The recorded pair as a method symbol would spell it: both halves
/// normalized, since one comes from the mangler and the other from
/// rustc's type printer.
fn pair_key(concrete: &str, trait_: &str) -> String {
    format!(
        "{} as {}",
        hansei_bundle::symbols::normalized_rust_type_name(concrete),
        hansei_bundle::symbols::normalized_rust_type_name(trait_)
    )
}

/// The target's executable mappings, as a structure a sweep can ask
/// millions of times.
///
/// [`Mappings::get`] walks its table, which is right for the handful of
/// lookups every other reader makes and wrong here: a sweep asks of
/// every word it considers, and a few hundred mappings times a few
/// hundred thousand words is the whole cost of the pass.
struct TextRanges(Vec<std::ops::Range<u64>>);

impl TextRanges {
    fn of(mappings: &Mappings) -> TextRanges {
        let mut ranges: Vec<_> = mappings
            .iter()
            .filter(|m| m.flags.is_exec())
            .map(|m| m.range())
            .collect();
        ranges.sort_by_key(|r| r.start);
        TextRanges(ranges)
    }

    fn contains(&self, addr: u64) -> bool {
        let next = self.0.partition_point(|r| r.start <= addr);
        next.checked_sub(1)
            .is_some_and(|i| self.0[i].contains(&addr))
    }
}

/// One entry to print: its two names, where it is, and what reading it
/// there proved.
struct Match<'a> {
    entry: &'a VtableEntry,
    trait_: &'a str,
    concrete: &'a str,
    addr: Option<u64>,
    words: Vec<Option<u64>>,
    standing: Standing,
}

/// Whether the words at an entry's address are the vtable it describes.
///
/// The check is what the words *are*, never what they are called. The
/// header decides most of it: an alignment that is not a power of two
/// is not one rustc emitted. Past it, every slot the debug info names a
/// member for holds a method, and a method is code — a slot pointing
/// anywhere else says these are somebody else's bytes. A slot the debug
/// info names nothing for is exempt: what rustc leaves in a vacant
/// entry is its own business.
///
/// Joining the drop glue's symbol to the entry's own concrete name
/// would be the sharper test and is deliberately not made: a symbol
/// spells a type as the mangler does and the debug info spells it as
/// rustc's type printer does, so the two disagree over `Arc` against
/// `alloc::sync::Arc` on vtables that are provably the right ones. The
/// symbol is worth showing beside the slot, not worth deciding on.
fn stands(image: &Image<'_>, entry: &VtableEntry, words: &[Option<u64>]) -> bool {
    let word = |i: u16| words.get(usize::from(i)).copied().flatten();
    let (Some(drop_fn), Some(align)) = (word(0), word(2)) else {
        return false;
    };
    if !align.is_power_of_two() || align > MAX_ALIGN {
        return false;
    }
    if drop_fn != 0 && !image.is_text(drop_fn) {
        return false;
    }
    (VTABLE_HEADER_SLOTS..entry.slot_count).all(|slot| {
        entry.undescribed_slots.contains(&slot)
            || word(slot).is_some_and(|fn_addr| image.is_text(fn_addr))
    })
}

/// List the vtables whose trait or concrete type matches `needle`,
/// grouped under the trait they implement.
///
/// Apart from the session so the offline tests can drive it.
fn report_vtables(
    view: &BundleView<'_>,
    image: &Image<'_>,
    impls: &names::ImplFold,
    needle: Option<&crate::pattern::Pattern>,
    verbose: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let entries = &view.bundle().vtables.entries;
    let placement = Placement::of(image, entries);
    // The recorded addresses first, since they are complete where they
    // apply; the sweep only where they do not, because it costs a pass
    // over the target's data and finds a subset.
    let scan = match placement {
        Placement::OtherBuild { .. } => Some(Scan::of(image, view)),
        _ => None,
    };
    let note = match &scan {
        Some(scan) if scan.joined > 0 => Some(format!(
            "{}, so {}",
            placement.note().unwrap_or_default(),
            scan.note()
        )),
        _ => placement.listing_note(),
    };
    if let Some(note) = note {
        writeln!(out, "note: {note}\n")?;
    }
    let Some(needle) = needle else {
        // A target instantiates tens of thousands of these; dumping
        // them all is not a listing anyone reads.
        return match entries.len() {
            0 => Ok(writeln!(out, "this tokio info records no vtables")?),
            n => Ok(writeln!(
                out,
                "{}: name a substring of a trait or a concrete type to list them",
                counted(n, "vtable")
            )?),
        };
    };

    // A table whose addresses are another build's has none to offer for
    // any row the sweep did not find, so the column goes only when the
    // sweep found nothing either — rather than filling with a mark that
    // says the same thing forty-five thousand times.
    let placed = !matches!(placement, Placement::OtherBuild { .. })
        || scan.as_ref().is_some_and(|s| s.joined > 0);

    let matches: Vec<Match<'_>> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let trait_ = view.str(entry.trait_)?;
            let concrete = view.str(entry.concrete)?;
            let hit = needle.is_match(trait_) || needle.is_match(concrete);
            hit.then(|| {
                let addr = match &scan {
                    Some(scan) => scan.at(index),
                    None => image.at(entry),
                };
                let words = addr.map_or_else(Vec::new, |a| image.words(a, entry.slot_count));
                let standing = match addr {
                    None => Standing::Unbiased,
                    Some(_) => Standing::of(image, entry, &words),
                };
                Match {
                    entry,
                    trait_,
                    concrete,
                    addr,
                    words,
                    standing,
                }
            })
        })
        .collect();

    // One table over every match rather than one per trait, so the
    // columns line up down the whole listing; the trait headings are
    // written between its rendered rows.
    let mut table = Table::new(2 + usize::from(placed)).align_right(usize::from(placed));
    for m in &matches {
        let slots = format!("{} slots", m.entry.slot_count);
        let concrete = names::fold_type_name(m.concrete, impls).into_owned();
        match placed {
            true => table.row([address(m, scan.is_some()), slots, concrete]),
            false => table.row([slots, concrete]),
        }
    }
    // Nothing was read where no address was offered, so there are no
    // slots to open even when they were asked for.
    let expand = placed && (verbose || matches.len() <= EXPAND);
    let mut heading: Option<&str> = None;
    for (m, row) in matches.iter().zip(table.render()) {
        if heading != Some(m.trait_) {
            if heading.is_some() {
                writeln!(out)?;
            }
            writeln!(out, "{}", names::fold_type_name(m.trait_, impls))?;
            heading = Some(m.trait_);
        }
        writeln!(out, "    {row}")?;
        if expand {
            print_slots(image, m, out)?;
        }
    }

    let traits = matches
        .iter()
        .map(|m| m.trait_)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let across = match traits {
        0 | 1 => String::new(),
        n => format!(", {}", counted(n, "trait")),
    };
    writeln!(out, "\n[{}{across}]", counted(matches.len(), "vtable"))?;
    Ok(())
}

/// The address cell: where the vtable is in the target, marked where
/// the memory there does not bear that out or is not there to read.
///
/// What no address means depends on where the addresses came from. A
/// sweep of the target answers only for a vtable whose slots named a
/// pair, and finding none is an ordinary outcome; the recorded table
/// answers for every entry, so an entry without one is a target that
/// could not say where its executable landed, and the link-time
/// address is what there is to offer.
fn address(m: &Match<'_>, scanned: bool) -> String {
    match (m.addr, scanned) {
        (Some(addr), _) => format!("{addr:#x}{}", m.standing.mark()),
        (None, true) => "(not found)".to_string(),
        (None, false) => format!("{:#x} (link-time)", m.entry.address),
    }
}

/// One vtable's words, under the row that named it: the three header
/// words rustc opens with, then a slot per method.
fn print_slots(image: &Image<'_>, m: &Match<'_>, out: &mut dyn io::Write) -> Result<()> {
    let mut table = Table::new(3);
    for (slot, word) in m.words.iter().enumerate() {
        let Some(word) = *word else {
            table.row([
                format!("slot {slot}"),
                "(unreadable)".to_string(),
                note(m, slot as u16),
            ]);
            continue;
        };
        table.row([
            format!("slot {slot}"),
            format!("{word:#x}"),
            match slot {
                0 => match erased_symbol(image, word) {
                    Some(symbol) => format!("drop glue: {symbol}"),
                    None => "drop glue".to_string(),
                },
                1 => format!("size: {}", counted(word as usize, "byte")),
                2 => format!("align: {word}"),
                _ => match note(m, slot as u16) {
                    note if !note.is_empty() => note,
                    _ => image.symbol(word).unwrap_or_default(),
                },
            },
        ]);
    }
    for line in table.render() {
        writeln!(out, "        {}", line.trim_end())?;
    }
    Ok(())
}

/// What a slot needs saying about it whether or not it could be read:
/// that the debug info describes no entry for it. rustc emits a vacant
/// entry for a method a trait object cannot dispatch — one that takes
/// `Self: Sized` — and that is a fact about the vtable, not a fault in
/// it.
fn note(m: &Match<'_>, slot: u16) -> String {
    match m.entry.undescribed_slots.contains(&slot) {
        true => "no entry recorded in debuginfo".to_string(),
        false => String::new(),
    }
}

/// The drop-glue symbol as a slot line names it: the whole symbol
/// rather than the type inside it, since the whole name is the
/// evidence. A null first slot names nothing, which is what it is.
fn erased_symbol(image: &Image<'_>, drop_fn: u64) -> Option<String> {
    (drop_fn != 0).then(|| image.symbol(drop_fn)).flatten()
}

/// Offline `vtables` tests: what the listing says about a hand-built
/// table read against a target whose memory is arranged to hold, and to
/// fail to hold, the vtables it describes.
#[cfg(test)]
pub(crate) mod vtable_tests {
    use super::{Image, MAX_ALIGN, Placement, report_vtables};

    use hansei_bundle::{
        Bundle, BundleTypeId, BundleView, Encoding, FORMAT_VERSION, InfraTypes, Meta,
        StringInterner, TypeDef, TypeTable, VtableEntry, VtableTable, names,
    };
    use proc::{LoadedObjectWithPath, MapFlags, Mappings, SymbolBuf, Target};

    /// Where the executable landed: every recorded address is a link-
    /// time one and has to be moved by this to be read.
    const BIAS: u64 = 0x40_0000;
    /// The link-time address of the first vtable; the rest follow it.
    const LINKED: u64 = 0x1000;
    /// The target's text, where every function a vtable names lives.
    const TEXT: u64 = 0x50_0000;
    const DROP: u64 = TEXT + 0x100;
    const CALL: u64 = TEXT + 0x200;

    /// Legacy-mangled symbols standing in for the two a vtable's slots
    /// resolve to. Mangled, not plain, because what the listing prints
    /// is what the demangler makes of them.
    const DROP_SYMBOL: &str = "_ZN4core3ptr13drop_in_place17h0f0e0d0c0b0a0908E";
    const CALL_SYMBOL: &str = "_ZN1a3One4call17h0f0e0d0c0b0a0908E";

    /// A target holding one run of vtable words in data, a page of
    /// text, and the two symbols the words point into.
    struct Fake {
        /// The words at `BIAS + LINKED`, laid out little-endian.
        bytes: Vec<u8>,
        bias: Option<u64>,
    }

    fn words(words: &[u64]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn symbol(name: &str, value: u64) -> SymbolBuf {
        SymbolBuf {
            name: name.to_string(),
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: value,
            st_size: 0x10,
        }
    }

    impl Target for Fake {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            let start = addr
                .checked_sub(BIAS + LINKED)
                .filter(|&s| s + len <= self.bytes.len() as u64)
                .ok_or_else(|| proc::Error::unmapped(addr, len))?;
            Ok(&self.bytes[start as usize..(start + len) as usize])
        }

        fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
            [(DROP, DROP_SYMBOL), (CALL, CALL_SYMBOL)]
                .into_iter()
                .find(|&(at, _)| at == addr)
                .map(|(at, name)| symbol(name, at))
        }

        fn lookup_symbol_by_name(&self, _: &str) -> Option<SymbolBuf> {
            None
        }

        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            Ok(Vec::new())
        }

        fn mappings(&self) -> proc::Result<Mappings> {
            Ok(Mappings::from_iter([]))
        }

        fn lwps(&self) -> proc::Result<Vec<proc::LwpInfo>> {
            Ok(Vec::new())
        }

        fn tls_var_addr(&self, _: &proc::Regs, _: &SymbolBuf) -> proc::Result<Option<u64>> {
            Ok(None)
        }

        fn exec_bias(&self) -> Option<u64> {
            self.bias
        }
    }

    /// The two mappings the check reads: the data holding the vtables,
    /// and the text everything they name has to be in.
    fn mappings() -> Mappings {
        let map = |vaddr, size, flags| LoadedObjectWithPath {
            path: Some("/bin/fake".to_string()),
            vaddr,
            size,
            flags: MapFlags(flags),
        };
        Mappings::from_iter([map(BIAS, 0x1_0000, 0x06), map(TEXT, 0x1000, 0x05)])
    }

    /// One vtable table and nothing else, in the sorted order the
    /// format requires — which `validate` is here to hold us to.
    ///
    /// `whatis` reads the same table from the other end, so its tests
    /// build theirs with this rather than a second copy of it.
    pub(crate) fn bundle(entries: &[(&str, &str, u64, u16, &[u16])]) -> Bundle {
        let mut strings = StringInterner::new();
        // One type, because the infrastructure ids have to name
        // something for the bundle to be a legal one at all.
        let types = TypeTable {
            types: vec![TypeDef::Base {
                name: strings.intern("u64"),
                size: 8,
                encoding: Encoding::Unsigned,
            }],
            ..Default::default()
        };
        let vtables = VtableTable {
            entries: entries
                .iter()
                .map(
                    |(trait_, concrete, address, slot_count, vacant)| VtableEntry {
                        trait_: strings.intern(trait_),
                        concrete: strings.intern(concrete),
                        address: *address,
                        slot_count: *slot_count,
                        undescribed_slots: vacant.to_vec(),
                        type_id: None,
                    },
                )
                .collect(),
        };
        let ty = BundleTypeId(0);
        let bundle = Bundle {
            meta: Meta {
                format_version: FORMAT_VERSION,
                ..Default::default()
            },
            strings: strings.finish(),
            types,
            tasks: Default::default(),
            dyn_futures: Default::default(),
            statics: Default::default(),
            walks: Default::default(),
            infra: InfraTypes {
                header: ty,
                vtable: ty,
                trailer: ty,
                context: ty,
                scheduler_handle: ty,
                mt_handle: ty,
                ct_handle: ty,
                location: ty,
                raw_waker_vtable: ty,
            },
            provenance: Default::default(),
            impls: Default::default(),
            vtables,
        };
        bundle.validate().expect("the table is a legal one");
        bundle
    }

    /// The fixture: seven entries against a run of words holding three
    /// vtables the target bears out and four it does not, one per way
    /// the check can refuse.
    ///
    /// Every address is `LINKED` plus the offset of its words, so the
    /// table describes a link-time layout and the target holds it a
    /// `BIAS` further up — the join the command exists to make.
    fn fixture() -> (Bundle, Fake) {
        let table = bundle(&[
            ("a::Dyn", "a::None", LINKED + 0x20, 4, &[]),
            ("a::Dyn", "a::One", LINKED, 4, &[]),
            ("a::Dyn", "a::Two", LINKED + 0x40, 4, &[3]),
            ("b::Other", "a::Cut", LINKED + 0xc0, 4, &[]),
            ("b::Other", "a::Elsewhere", LINKED + 0x80, 4, &[]),
            ("b::Other", "a::Gone", LINKED + 0x1000, 4, &[]),
            ("b::Other", "a::Rubbish", LINKED + 0x60, 4, &[]),
            ("b::Other", "a::Skewed", LINKED + 0xa0, 4, &[]),
        ]);
        let mut layout: Vec<u64> = [
            // a::One: a whole, ordinary vtable.
            [DROP, 48, 8, CALL],
            // a::None: a null drop slot — what rustc leaves for a type
            // with no glue to run — under the largest alignment a type
            // can be given, which is still an alignment. Neither is a
            // fault, and both are believed.
            [0, 8, MAX_ALIGN, CALL],
            // a::Two: its one method slot is vacant.
            [DROP, 16, 8, 0],
            // a::Rubbish: not a vtable at all — the words there belong
            // to whatever else this build put here.
            [0x12_3456, 1, 3, 0x99],
            // a::Elsewhere: a plausible header over a method slot
            // pointing at data rather than at code.
            [DROP, 8, 8, BIAS + LINKED],
            // a::Skewed: an alignment past the largest one a type can
            // be given, which is the header saying these are not its
            // words however round the number looks.
            [DROP, 8, MAX_ALIGN * 2, CALL],
        ]
        .concat();
        // a::Cut: the target's memory runs out inside its header, so
        // the rest of it cannot be read at all. Past that is a::Gone,
        // of which the target holds nothing whatever.
        layout.extend([0, 0]);
        let fake = Fake {
            bytes: words(&layout),
            bias: Some(BIAS),
        };
        (table, fake)
    }

    /// A test needle, compiled the way `exec_vtables` compiles one.
    fn pattern(needle: &str) -> crate::pattern::Pattern {
        crate::pattern::Pattern::new(needle).expect("the test needle compiles")
    }

    fn listing(bundle: &Bundle, fake: &Fake, needle: Option<&str>, verbose: bool) -> String {
        let needle = needle.map(pattern);
        let mappings = mappings();
        let image = Image {
            target: fake,
            mappings: &mappings,
            bias: fake.bias,
        };
        let mut out = Vec::new();
        report_vtables(
            &BundleView::new(bundle),
            &image,
            &names::ImplFold::default(),
            needle.as_ref(),
            verbose,
            &mut out,
        )
        .expect("the listing renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// The listing groups by trait, prints the address the vtable has
    /// in the target rather than the one it was linked at, and counts
    /// what it found. A vtable the memory bears out is printed plainly
    /// — including one whose drop slot is null, which is what rustc
    /// leaves for a type with no glue to run. One the memory does not
    /// bear out is marked, on the row rather than in a footnote,
    /// whichever way it failed: an alignment that is no alignment, one
    /// no Rust type is given, a method slot pointing outside text, or
    /// memory that stops part-way through. A vtable the target holds
    /// not one word of gets a mark of its own — a core need not dump
    /// read-only data, and nothing there is a different answer from
    /// the wrong thing there.
    #[test]
    fn test_the_listing_marks_what_the_target_does_not_bear_out() {
        let (bundle, fake) = fixture();
        assert_eq!(
            listing(&bundle, &fake, Some("a::"), false),
            "a::Dyn\n\
             \x20   0x401020               4 slots  a::None\n\
             \x20   0x401000               4 slots  a::One\n\
             \x20   0x401040               4 slots  a::Two\n\
             \n\
             b::Other\n\
             \x20   0x4010c0 (unverified)  4 slots  a::Cut\n\
             \x20   0x401080 (unverified)  4 slots  a::Elsewhere\n\
             \x20   0x402000 (unreadable)  4 slots  a::Gone\n\
             \x20   0x401060 (unverified)  4 slots  a::Rubbish\n\
             \x20   0x4010a0 (unverified)  4 slots  a::Skewed\n\
             \n\
             [8 vtables, 2 traits]\n"
        );
    }

    /// A needle matches either half of the pair, and one match is the
    /// end of a search: its slots print without `-v` being asked for.
    #[test]
    fn test_one_match_prints_its_slots_unasked() {
        let (bundle, fake) = fixture();
        assert_eq!(
            listing(&bundle, &fake, Some("a::One"), false),
            "a::Dyn\n\
             \x20   0x401000  4 slots  a::One\n\
             \x20       slot 0  0x500100  drop glue: core::ptr::drop_in_place\n\
             \x20       slot 1  0x30      size: 48 bytes\n\
             \x20       slot 2  0x8       align: 8\n\
             \x20       slot 3  0x500200  a::One::call\n\
             \n\
             [1 vtable]\n"
        );
    }

    /// A slot the debug info records no entry for says so — a neutral
    /// fact about the vtable — and it is exempt from the check, so a
    /// vtable carrying one is still confirmed. A slot the target cannot
    /// serve says that instead of printing nothing.
    #[test]
    fn test_vacant_and_unreadable_slots_say_which_they_are() {
        let (bundle, fake) = fixture();
        let vacant = listing(&bundle, &fake, Some("a::Two"), false);
        assert!(
            vacant.contains("slot 3  0x0       no entry recorded in debuginfo\n"),
            "{vacant}"
        );
        assert!(!vacant.contains("unverified"), "{vacant}");

        let short = listing(&bundle, &fake, Some("a::Cut"), false);
        assert!(
            short.contains("slot 0  0x0           drop glue\n"),
            "{short}"
        );
        assert!(
            short.contains("slot 1  0x0           size: 0 bytes\n"),
            "{short}"
        );
        assert!(short.contains("slot 2  (unreadable)\n"), "{short}");
        assert!(short.contains("slot 3  (unreadable)\n"), "{short}");
    }

    /// `-v` opens every match's slots, and without it a listing of
    /// several stays a listing.
    #[test]
    fn test_verbose_opens_every_match() {
        let (bundle, fake) = fixture();
        assert!(!listing(&bundle, &fake, Some("a::Dyn"), false).contains("slot 0"));
        assert_eq!(
            listing(&bundle, &fake, Some("a::Dyn"), true)
                .matches("slot 0")
                .count(),
            3
        );
    }

    /// The words a typed line was split into are joined back into the
    /// one name they came from, and no word at all is no substring —
    /// the question "how many are there", not a match on everything.
    #[test]
    fn test_the_needle_is_the_rest_of_the_line() {
        let words =
            |line: &str| super::needle(&line.split(' ').map(str::to_owned).collect::<Vec<_>>());
        assert_eq!(
            words("DynService<Request, Body>").as_deref(),
            Some("DynService<Request, Body>")
        );
        assert_eq!(super::needle(&[]), None);
        assert_eq!(super::needle(&[String::new()]), None);
    }

    /// A target that cannot say where its executable landed has no
    /// address in it to offer, so the recorded one is printed as what
    /// it is — and nothing is read, so nothing is claimed about it.
    #[test]
    fn test_a_target_without_a_bias_prints_link_time_addresses() {
        let (bundle, _) = fixture();
        let fake = Fake {
            bytes: Vec::new(),
            bias: None,
        };
        let shown = listing(&bundle, &fake, Some("a::One"), false);
        assert!(
            shown.contains("0x1000 (link-time)  4 slots  a::One\n"),
            "{shown}"
        );
        assert!(!shown.contains("slot 0"), "{shown}");
    }

    /// Naming no substring reports the size of the table rather than
    /// printing it: a real target instantiates tens of thousands.
    #[test]
    fn test_no_needle_reports_the_count() {
        let (table, fake) = fixture();
        assert_eq!(
            listing(&table, &fake, None, false),
            "8 vtables: name a substring of a trait or a concrete type to list them\n"
        );
        assert_eq!(
            listing(&bundle(&[]), &fake, None, false),
            "this tokio info records no vtables\n"
        );
    }

    /// A tokio info out of a build the target did not run records
    /// addresses that are statements about that build, so not one of
    /// them is offered: the column goes, nothing is read at them, and
    /// one note at the top says why once instead of a mark saying it on
    /// every row. What the debug info knows without the target — the
    /// pair and the slot count — is what is left, and it is still true.
    #[test]
    fn test_a_table_from_another_build_offers_no_addresses() {
        let (bundle, fake) = fixture();
        // The same table read against a target that maps nothing where
        // the table says its vtables are.
        let elsewhere = Mappings::from_iter([LoadedObjectWithPath {
            path: Some("/bin/fake".to_string()),
            vaddr: TEXT,
            size: 0x1000,
            flags: MapFlags(0x05),
        }]);
        let image = Image {
            target: &fake,
            mappings: &elsewhere,
            bias: fake.bias,
        };
        assert_eq!(
            Placement::of(&image, &bundle.vtables.entries),
            Placement::OtherBuild {
                placed: 0,
                checked: 8
            }
        );

        let mut out = Vec::new();
        // `-v` was asked for and cannot be honoured: there is no
        // address to read slots at.
        report_vtables(
            &BundleView::new(&bundle),
            &image,
            &names::ImplFold::default(),
            Some(&pattern("a::Dyn")),
            true,
            &mut out,
        )
        .expect("the listing renders");
        let shown = String::from_utf8(out).expect("rendered output is UTF-8");
        assert!(
            shown.starts_with(
                "note: the tokio info is from a different build than the core \
                 (0 of its 8 recorded addresses land in a mapped image), so no \
                 address is shown below."
            ),
            "{shown}"
        );
        assert!(
            shown.ends_with(
                "a::Dyn\n\
                 \x20   4 slots  a::None\n\
                 \x20   4 slots  a::One\n\
                 \x20   4 slots  a::Two\n\
                 \n\
                 [3 vtables]\n"
            ),
            "{shown}"
        );
        assert!(!shown.contains("0x"), "{shown}");
        assert!(!shown.contains("slot 0"), "{shown}");
    }

    /// A target whose mappings do bear the table out says nothing about
    /// it: the note is for a reader about to be shown less than they
    /// asked for, and there is no such reader here.
    #[test]
    fn test_a_placed_table_says_nothing_about_its_placement() {
        let (bundle, fake) = fixture();
        let mappings = mappings();
        let image = Image {
            target: &fake,
            mappings: &mappings,
            bias: fake.bias,
        };
        assert_eq!(
            Placement::of(&image, &bundle.vtables.entries),
            Placement::Placed
        );
        assert_eq!(Placement::Placed.note(), None);
        assert!(!listing(&bundle, &fake, Some("a::One"), false).contains("note:"));
    }

    /// Where the swept target keeps its vtables, and the two functions
    /// they dispatch to.
    const DATA: u64 = 0x30_0000;
    const CALL_ONE: u64 = TEXT + 0x40;
    const CALL_TWO: u64 = TEXT + 0x80;

    /// Genuine v0 manglings of `<a::One as a::Dyn>::call` and
    /// `<a::Two as a::Dyn>::call` — the shape the sweep joins on, since
    /// a method symbol is the one place a symbol names a trait.
    const ONE_CALL: &str = "_RNvXCs1dINKnBl13J_1aNtCs1dINKnBl13J_1a3OneNtCs1dINKnBl13J_1a3Dyn4call";
    const TWO_CALL: &str = "_RNvXCs1dINKnBl13J_1aNtCs1dINKnBl13J_1a3TwoNtCs1dINKnBl13J_1a3Dyn4call";

    /// A target the sweep can read: one file-backed data mapping
    /// holding a run of words, a page of text, and a symbol for each
    /// function the words point at.
    struct Swept {
        data: Vec<u8>,
        symbols: Vec<(u64, &'static str)>,
    }

    impl Target for Swept {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            let start = addr
                .checked_sub(DATA)
                .filter(|&s| s + len <= self.data.len() as u64)
                .ok_or_else(|| proc::Error::unmapped(addr, len))?;
            Ok(&self.data[start as usize..(start + len) as usize])
        }
        fn readable_len(&self, addr: u64, max: u64) -> u64 {
            match addr.checked_sub(DATA) {
                Some(off) if off < self.data.len() as u64 => max.min(self.data.len() as u64 - off),
                _ => 0,
            }
        }
        fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
            self.symbols
                .iter()
                .find(|&&(at, _)| at == addr)
                .map(|&(at, name)| symbol(name, at))
        }
        fn lookup_symbol_by_name(&self, _: &str) -> Option<SymbolBuf> {
            None
        }
        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            Ok(Vec::new())
        }
        fn mappings(&self) -> proc::Result<Mappings> {
            Ok(Mappings::from_iter([]))
        }
        fn lwps(&self) -> proc::Result<Vec<proc::LwpInfo>> {
            Ok(Vec::new())
        }
        fn tls_var_addr(&self, _: &proc::Regs, _: &SymbolBuf) -> proc::Result<Option<u64>> {
            Ok(None)
        }
        fn exec_bias(&self) -> Option<u64> {
            Some(0)
        }
    }

    /// The sweep's mappings: the data it reads and the text every
    /// function it believes has to be in. `data_flags` and `path` are
    /// what the filter deciding *which* mappings hold vtables reads.
    fn swept_mappings(data_flags: u32, path: Option<&str>) -> Mappings {
        let map = |vaddr, flags, path: Option<&str>| LoadedObjectWithPath {
            path: path.map(str::to_owned),
            vaddr,
            size: 0x1000,
            flags: MapFlags(flags),
        };
        Mappings::from_iter([
            map(DATA, data_flags, path),
            map(TEXT, 0x05, Some("/bin/fake")),
        ])
    }

    fn swept_in(bundle: &Bundle, data: &[u64], mappings: &Mappings) -> super::Scan {
        let target = Swept {
            data: words(data),
            symbols: vec![(CALL_ONE, ONE_CALL), (CALL_TWO, TWO_CALL)],
        };
        let image = Image {
            target: &target,
            mappings,
            bias: Some(0),
        };
        super::Scan::of(&image, &BundleView::new(bundle))
    }

    fn swept(bundle: &Bundle, data: &[u64]) -> (Vec<Option<u64>>, usize) {
        let scan = swept_in(bundle, data, &swept_mappings(0x06, Some("/bin/fake")));
        (scan.found.clone(), scan.examined)
    }

    /// The sweep finds a vtable by its own words and names it by the
    /// pair its method symbol spells, so a recorded entry gets the
    /// address the *target* has it at — with no address in common
    /// between the build that ran and the build the tokio info came
    /// from, which is the whole point.
    ///
    /// A run whose method names a pair the table does not record is
    /// passed over; so is one that is not vtable-shaped at all.
    #[test]
    fn test_the_sweep_finds_a_vtable_by_the_pair_its_method_names() {
        // Only `a::One` is recorded, so `a::Two`'s vtable — which the
        // sweep sees and names perfectly well — has no row to fill.
        let bundle = bundle(&[("a::Dyn", "a::One", 0, 4, &[])]);
        let (found, examined) = swept(
            &bundle,
            &[
                // Not a vtable: an alignment that is not one.
                0, 8, 3, 0, //
                // a::Two's, recorded nowhere.
                0, 16, 8, CALL_TWO, //
                // a::One's, which is the one asked for.
                0, 24, 8, CALL_ONE,
            ],
        );
        assert_eq!(found, vec![Some(DATA + 0x40)]);
        // Three runs pass the header screen: the two real vtables, and
        // one straddling them whose words happen to read as a header.
        assert_eq!(examined, 3);
    }

    /// A window a slot or two off from a real vtable still holds that
    /// vtable's methods, so it joins to the very pair it is not. Two
    /// things reject it: a size that is not a multiple of the
    /// alignment — which a shifted window's, being the neighbour's
    /// pointer, is not — and the shape check the listing already
    /// applies to a recorded address.
    #[test]
    fn test_a_window_off_a_real_vtable_is_not_mistaken_for_it() {
        let bundle = bundle(&[("a::Dyn", "a::One", 0, 4, &[])]);
        // The vtable is at +0x10. The window one slot early reads as
        // a header too — a null drop, the real vtable's null drop as
        // its size, its size as an alignment — and reaches the real
        // method a slot further on than a four-slot vtable has.
        let (found, _) = swept(&bundle, &[0, 0, 0, 32, 8, CALL_ONE]);
        assert_eq!(
            found,
            vec![Some(DATA + 0x10)],
            "the window at +0x8 reaches the same method and is not it"
        );
    }

    /// rustc emits a vtable per codegen unit that needs one, so a pair
    /// is recorded several times over and the entries differ in nothing
    /// but their address. The target duplicates them the same way, so
    /// what a sweep recovers is a pair's *addresses*; which row gets
    /// which is a distinction without a difference, and the count is
    /// the only thing to get right.
    #[test]
    fn test_a_pair_recorded_twice_takes_both_addresses() {
        let bundle = bundle(&[
            ("a::Dyn", "a::One", 0, 4, &[]),
            ("a::Dyn", "a::One", 0x100, 4, &[]),
        ]);
        let (found, _) = swept(&bundle, &[0, 8, 8, CALL_ONE, 0, 8, 8, CALL_ONE]);
        assert_eq!(found, vec![Some(DATA), Some(DATA + 0x20)]);

        // One address for two rows fills one of them; the other says
        // it was not found rather than repeating an address.
        let (found, _) = swept(&bundle, &[0, 8, 8, CALL_ONE]);
        assert_eq!(found, vec![Some(DATA), None]);
    }

    /// A vtable is static data in some object's image, so only a
    /// mapping with a file behind it and no execute bit is swept. The
    /// heap and the stacks are most of a target and hold none; text
    /// holds code, whose words read as headers often enough to matter.
    #[test]
    fn test_only_an_objects_data_is_swept() {
        let bundle = bundle(&[("a::Dyn", "a::One", 0, 4, &[])]);
        let vtable = &[0, 24, 8, CALL_ONE];
        let found = |flags, path| {
            swept_in(&bundle, vtable, &swept_mappings(flags, path))
                .found
                .clone()
        };
        assert_eq!(found(0x06, Some("/bin/fake")), vec![Some(DATA)]);
        assert_eq!(
            found(0x05, Some("/bin/fake")),
            vec![None],
            "text is not swept"
        );
        assert_eq!(
            found(0x06, None),
            vec![None],
            "anonymous memory is not swept"
        );
    }

    /// Every function a vtable dispatches through is code, and the
    /// drop slot is the one the screen can afford to check: a run whose
    /// drop word points somewhere that is not text is not a vtable,
    /// however well the rest of its header reads and whatever its next
    /// slot names.
    #[test]
    fn test_drop_glue_that_is_not_code_is_not_a_vtable() {
        let bundle = bundle(&[("a::Dyn", "a::One", 0, 4, &[])]);
        let mappings = swept_mappings(0x06, Some("/bin/fake"));

        let scan = swept_in(&bundle, &[0x1234, 24, 8, CALL_ONE], &mappings);
        assert_eq!(scan.found, vec![None]);
        assert_eq!(scan.examined, 0, "not even a candidate");

        // The same run with a null drop slot — what rustc leaves for a
        // type with no glue to run — is one.
        let scan = swept_in(&bundle, &[0, 24, 8, CALL_ONE], &mappings);
        assert_eq!(scan.found, vec![Some(DATA)]);
        assert_eq!(scan.examined, 1);
    }

    /// The whole of it, through the listing: a table whose addresses
    /// are another build's, a target holding the vtable it describes,
    /// and the row given the address the sweep found — with the note
    /// saying that is where it came from and how much of the target it
    /// had to read to say so.
    #[test]
    fn test_a_swept_address_reaches_the_listing() {
        // Recorded a long way from anything this target maps, so the
        // recorded route is closed and only the sweep is left.
        let bundle = bundle(&[("a::Dyn", "a::One", 0x90_0000, 4, &[])]);
        let target = Swept {
            data: words(&[0, 24, 8, CALL_ONE, 0, 24, 8, CALL_ONE]),
            symbols: vec![(CALL_ONE, ONE_CALL), (CALL_TWO, TWO_CALL)],
        };
        let mappings = swept_mappings(0x06, Some("/bin/fake"));
        let image = Image {
            target: &target,
            mappings: &mappings,
            bias: Some(0),
        };
        assert!(!Placement::of(&image, &bundle.vtables.entries).applies());

        let mut out = Vec::new();
        report_vtables(
            &BundleView::new(&bundle),
            &image,
            &names::ImplFold::default(),
            Some(&pattern("a::One")),
            false,
            &mut out,
        )
        .expect("the listing renders");
        let shown = String::from_utf8(out).expect("rendered output is UTF-8");

        // One row, one address — the second vtable in the target has no
        // second row to go in, the table recording the pair only once.
        assert!(
            shown.contains(&format!("{DATA:#x}  4 slots  a::One\n")),
            "{shown}"
        );
        assert!(!shown.contains("(not found)"), "{shown}");
        // The note counts what the sweep did: two runs looked at, one
        // of them placed on a row.
        assert!(
            shown.contains("instead — 1 of the 2 vtable-shaped runs in it name a pair"),
            "{shown}"
        );
        // A single match opens its slots, and they are read at the
        // swept address rather than the recorded one.
        assert!(shown.contains("slot 3  0x500040"), "{shown}");
    }

    /// A needle nothing matches is an empty answer, not an error.
    #[test]
    fn test_a_needle_nothing_matches_counts_nothing() {
        let (bundle, fake) = fixture();
        assert_eq!(
            listing(&bundle, &fake, Some("nothing"), false),
            "\n[0 vtables]\n"
        );
    }
}

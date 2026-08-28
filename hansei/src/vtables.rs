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
//! of the same sources and every address is a fiction. So each address
//! this prints is checked against the words it names — the same
//! believability check `whatis` applies to an arbitrary address — and
//! one that does not hold up is marked rather than presented as fact.

use crate::Session;
use crate::output::Table;
use crate::summary::counted;

use anyhow::Result;
use hansei_bundle::{BundleView, VTABLE_HEADER_SLOTS, VtableEntry, names};
use proc::{Mappings, Target};

use std::io;

/// How many matches print their slots without being asked for them.
/// One match is the end of a search rather than a listing to scan, and
/// the slots are what the search was for.
const EXPAND: usize = 1;

/// The largest alignment a Rust type can be given — the bound the
/// harvest screens a vtable's own header against, applied again here to
/// the words the target has at that address.
const MAX_ALIGN: u64 = 1 << 30;

pub(crate) fn exec_vtables(
    session: &Session<'_>,
    words: &[String],
    verbose: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let image = Image::of(session);
    report_vtables(
        &session.ctx.view,
        &image,
        &session.impl_fold,
        needle(words).as_deref(),
        verbose,
        out,
    )
}

/// The substring a typed line asked for: the words joined back into the
/// one name they were split from, so a spelling holding spaces pastes in
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
    pub(crate) fn of(session: &'a Session<'_>) -> Self {
        Image {
            target: session.proc,
            mappings: &session.ctx.mappings,
            bias: session.proc.exec_bias(),
        }
    }

    /// Where an entry's vtable is in this target.
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

    /// The demangled symbol covering `addr`.
    pub(crate) fn symbol(&self, addr: u64) -> Option<String> {
        let symbol = self.target.lookup_symbol_by_addr(addr)?;
        let stripped = hansei_bundle::strip_llvm_suffix(&symbol.name);
        let demangled = rustc_demangle::try_demangle(stripped).ok()?;
        Some(format!("{demangled:#}"))
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

/// List the vtables whose trait or concrete type contains `needle`,
/// grouped under the trait they implement.
///
/// Apart from the session so the offline tests can drive it.
fn report_vtables(
    view: &BundleView<'_>,
    image: &Image<'_>,
    impls: &names::ImplFold,
    needle: Option<&str>,
    verbose: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let entries = &view.bundle().vtables.entries;
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

    let matches: Vec<Match<'_>> = entries
        .iter()
        .filter_map(|entry| {
            let trait_ = view.str(entry.trait_)?;
            let concrete = view.str(entry.concrete)?;
            let hit = trait_.contains(needle) || concrete.contains(needle);
            hit.then(|| {
                let addr = image.at(entry);
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
    let mut table = Table::new(3).align_right(1);
    for m in &matches {
        table.row([
            address(m),
            format!("{} slots", m.entry.slot_count),
            names::fold_type_name(m.concrete, impls).into_owned(),
        ]);
    }
    let expand = verbose || matches.len() <= EXPAND;
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
    writeln!(out, "\n{}{across}", counted(matches.len(), "vtable"))?;
    Ok(())
}

/// The address cell: where the vtable is in the target, marked where
/// the memory there does not bear that out or is not there to read, and
/// falling back to the link-time address where the target cannot say
/// where anything landed.
fn address(m: &Match<'_>) -> String {
    match m.addr {
        Some(addr) => format!("{addr:#x}{}", m.standing.mark()),
        None => format!("{:#x} (link-time)", m.entry.address),
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
    use super::{Image, MAX_ALIGN, report_vtables};

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

    fn listing(bundle: &Bundle, fake: &Fake, needle: Option<&str>, verbose: bool) -> String {
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
            needle,
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
             8 vtables, 2 traits\n"
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
             1 vtable\n"
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

    /// A needle nothing matches is an empty answer, not an error.
    #[test]
    fn test_a_needle_nothing_matches_counts_nothing() {
        let (bundle, fake) = fixture();
        assert_eq!(
            listing(&bundle, &fake, Some("nothing"), false),
            "\n0 vtables\n"
        );
    }
}

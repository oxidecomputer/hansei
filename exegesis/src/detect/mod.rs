//! The formatter detection layer: recognize known types in DWARF and build
//! the [`DisplayNode`] display programs the bundle carries for them.
//!
//! Dispatch is name-keyed ([`BY_NAME`], [`BY_PREFIX`]) with a short
//! shape-keyed chain ([`STRUCTURAL`]) behind it. This module root holds the
//! dispatch tables and the machinery every detector navigates with — the
//! [`Reach`] vocabulary, the shape walk, the addressing check, the trace
//! sink `--explain-format` reads. The detectors themselves are filed by who
//! owns the layout they describe, since that is who moves it:
//!
//! - [`std`]: std/core/alloc types plus the shape-keyed structural chain,
//!   whose layouts move with the toolchain;
//! - [`crates`]: third-party crates (camino, uuid, parking_lot, …), each
//!   moving on its own release cadence;
//! - [`tokio`]: tokio types whose layout has held across every supported
//!   tokio version;
//! - [`tokio_v1_50`]: a family module — only the detectors a tokio
//!   restructure moved, dispatched per target by the recovered tokio
//!   version (see [`Family`]).

mod crates;
mod std;
mod tokio;
mod tokio_v1_50;

use self::crates::{hex_bytes_node, raw_mutex_node, utf8_path_buf_node, utf8_path_node, uuid_node};
use self::std::{
    atomic_node, btree_map_node, dyn_pointer_node, function_pointer_node, instant_alias_node,
    ip_address_node, non_null_node, nonzero_inner_node, nonzero_node, raw_waker_node,
    raw_waker_vtable_node, scalar_newtype_node, slice_node, str_node, string_node, unique_node,
    unsafe_cell_node, usize_no_high_bit_node, vec_node, waker_node,
};
use self::tokio::{
    batch_semaphore_node, bounded_semaphore_node, cache_padded_node, loom_atomic_node,
    loom_parking_lot_node, loom_unsafe_cell_node, mpsc_block_node, mpsc_chan_node,
    mpsc_handle_node, notify_node, watch_receiver_node, watch_sender_node, watch_shared_node,
    watch_state_node,
};
use self::tokio_v1_50::{sleep_node, timer_entry_node};
use crate::bundle::{
    BitField, Bundle, BundleTypeId, DisplayNode, Field, FieldRender, MemberRef, ScalarDecode,
    Selector, Shape, Step, StringInterner,
};
use crate::extract::{Emitter, fq_name, raw_type_size};
use crate::raw_types::{RawType, VariantShape as RawVariantShape};
use crate::{DwReader, Encoding, TypeId};

use ::std::num::NonZeroU8;

/// How a type reads in a formatter trace: its name, or its shape when it has
/// none (an anonymous struct, a pointer, an array).
fn type_label(reader: &DwReader<'_>, id: TypeId) -> String {
    if let Some(name) = fq_name(reader, id) {
        return name;
    }
    match reader.canonical_type(id) {
        Some(RawType::Struct(_)) => "an unnamed struct".to_string(),
        Some(RawType::Union(_)) => "an unnamed union".to_string(),
        Some(RawType::Pointer(_)) => "a pointer".to_string(),
        Some(RawType::Array(_)) => "an array".to_string(),
        Some(_) => "an unnamed type".to_string(),
        None => "a type the reader did not model".to_string(),
    }
}

/// The member names of an aggregate, for a formatter trace. Truncated, since
/// the point is to show whether the name a detector wanted is among them.
fn member_labels(
    reader: &DwReader<'_>,
    members: &[crate::raw_types::RawMember<crate::StrId>],
) -> String {
    const SHOWN: usize = 12;
    if members.is_empty() {
        return "no members".to_string();
    }
    let names: Vec<&str> = members
        .iter()
        .take(SHOWN)
        .map(|m| m.name.map_or("<anonymous>", |n| reader.strings.get(n)))
        .collect();
    let rest = members.len().saturating_sub(SHOWN);
    if rest > 0 {
        format!("{} (and {rest} more)", names.join(", "))
    } else {
        names.join(", ")
    }
}

/// Reporting why a formatter did or did not attach to a type.
///
/// A detector fails safe: on any mismatch it returns `None` and the type
/// renders structurally. That is the right behavior and a poor diagnostic —
/// the only evidence is a `debug:` line missing from the dump of a binary
/// with tens of thousands of types, which says nothing about *where* the
/// detector gave up. With `ExtractOptions::explain_format` set, the shared
/// navigators record what they saw while the emitter works on a matching
/// type, and [`Emitter::emit`] keeps the trace.
///
/// The sink is thread-local rather than a reporter threaded through every
/// helper: the emit loop is single-threaded, and a parameter no ordinary
/// extraction reads would spread across every navigation signature.
pub(crate) mod trace {
    use ::std::cell::RefCell;

    thread_local! {
        static SINK: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    }

    /// Whether a trace is being collected. Checked before a note is
    /// formatted, so an ordinary extraction pays one thread-local read.
    pub(crate) fn active() -> bool {
        SINK.with_borrow(Option::is_some)
    }

    /// Add one line to the trace being collected, if any.
    pub(crate) fn note(line: String) {
        SINK.with_borrow_mut(|sink| {
            if let Some(lines) = sink {
                lines.push(line);
            }
        });
    }

    /// Run `f` with a trace collected, returning it alongside `f`'s result.
    pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
        SINK.with_borrow_mut(|sink| *sink = Some(Vec::new()));
        let out = f();
        let lines = SINK.with_borrow_mut(Option::take).unwrap_or_default();
        (out, lines)
    }
}

/// Add a line to the formatter trace when one is being collected. The
/// arguments are formatted only then, so this is free in an ordinary run.
macro_rules! explain {
    ($($arg:tt)*) => {
        if crate::detect::trace::active() {
            crate::detect::trace::note(format!($($arg)*));
        }
    };
}

/// Build a [`Reach`]. `reach![Named("a"), Deref]` reads as the path it describes.
macro_rules! reach {
    ($($step:expr),* $(,)?) => { vec![$($step),*] };
}
pub(super) use reach;

/// One type's formatter trace: what the navigators saw while a display program
/// was built for it, and which type it was built for.
///
/// The verdict — the program itself — is deliberately *not* recorded here. It
/// is read back out of the finished bundle by [`FormatExplanation::render`],
/// for two reasons. Rendering a program resolved to member names and byte
/// offsets needs the type table, which is still being built while the trace is
/// collected; and extraction rewrites member lists after programs are attached,
/// so a verdict captured here would describe the program as built rather than
/// as shipped.
#[derive(Debug)]
pub struct FormatExplanation {
    /// The fully-qualified name the type was reported under.
    pub name: String,
    /// The type the trace belongs to, as `exegesis dump` numbers it.
    pub id: BundleTypeId,
    /// What the navigators saw, one line each, in the order they saw it.
    pub trace: Vec<String>,
}

impl FormatExplanation {
    /// The trace as `--explain-format` prints it: the type, what the navigators
    /// saw, then the program `bundle` ended up carrying for it, resolved to the
    /// paths it addresses.
    pub fn render(&self, bundle: &Bundle) -> String {
        use ::std::fmt::Write as _;
        let mut out = format!("{} [type {}]\n", self.name, self.id.0);
        for line in &self.trace {
            let _ = writeln!(out, "{line}");
        }
        let _ = match bundle.types.debug_formats.get(&self.id) {
            Some(node) => writeln!(
                out,
                "  => {}",
                crate::bundle::describe_node(bundle, self.id, node)
            ),
            None => writeln!(out, "  => no formatter; renders structurally"),
        };
        out
    }
}

/// Recognize a type whose source-level Debug representation is simpler than its
/// private storage layout, and return the display program that renders it —
/// or `None` when the type does not have the shape the detector expects, in
/// which case the type renders structurally.
///
/// Every detector has this one signature, whether or not it uses the
/// [`Emitter`]: a detector that interns a string (a record label, a
/// [`ScalarDecode`] table) or reserves a related type that must be emitted
/// alongside (an `element`, a key/value, a list's node type) needs it, and one
/// that only navigates DWARF opens with `let reader = emitter.reader;`. Keeping
/// the signature uniform is what lets [`BY_NAME`], [`BY_PREFIX`] and
/// [`STRUCTURAL`] be one kind of table, so a detector that later grows a label
/// does not have to move.
type Detector = fn(&mut Emitter<'_>, TypeId) -> Option<DisplayNode>;

/// A tokio version family: a contiguous range of tokio releases whose
/// layouts share detector code, named by the floor of the range. Families
/// exist for divergence too large for a structural alternative to absorb —
/// a respelled member is an ordered fallback inside one detector, but a
/// restructure gets a `tokio_v<floor>` module of its own, holding only the
/// detectors that moved.
///
/// Selection is by version, once per target: the tokio version recovered
/// from the target's DWARF (`Meta::tokio_version`) picks the family with
/// the highest floor at or below it, so every versioned row in one bundle
/// answers coherently. Two structural nets stay underneath the version
/// check: the selected detector still validates the layout it describes
/// and declines on any mismatch, and the per-cell matrix goldens pin which
/// family actually attached.
///
/// Declaration order is floor order, oldest first; [`Family::ALL`] and the
/// derived `Ord` both rely on it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    /// tokio 1.50 through 1.52: the timer entry keeps a `registered` flag
    /// and a cached `deadline` instant beside a lazily-registered
    /// `Option<TimerShared>`.
    V1_50,
}

impl Family {
    /// Every family, oldest floor first.
    pub const ALL: &'static [Family] = &[Family::V1_50];

    /// The lowest tokio `(major, minor)` the family covers; its range runs
    /// to the next family's floor.
    fn floor(self) -> (u64, u64) {
        match self {
            Family::V1_50 => (1, 50),
        }
    }

    /// The tag `--explain-format` and the matrix goldens name the family by.
    pub fn name(self) -> &'static str {
        match self {
            Family::V1_50 => "v1_50",
        }
    }

    /// Select the family for a target: the one with the highest floor at or
    /// below the recovered tokio version. A version older than every floor
    /// takes the oldest family, and a version newer than every family — or
    /// none recovered at all, as for a vendored or forked tokio with no
    /// registry path — takes the newest: the latest supported layouts are
    /// the best guess, and the detectors decline structurally wherever the
    /// guess is wrong.
    pub fn select(version: Option<&semver::Version>) -> Family {
        let newest = *Family::ALL.last().expect("at least one family");
        let Some(version) = version else {
            return newest;
        };
        Family::ALL
            .iter()
            .rev()
            .find(|family| (version.major, version.minor) >= family.floor())
            .copied()
            .unwrap_or(Family::ALL[0])
    }

    /// The selection and why, as the per-cell detector catalog pins it:
    /// `v1_50 (tokio 1.50.0)`, or `v1_50 (version unrecovered)` for the
    /// newest-family guess.
    pub fn describe(version: Option<&semver::Version>) -> String {
        let family = Family::select(version);
        match version {
            Some(version) => format!("{} (tokio {version})", family.name()),
            None => format!("{} (version unrecovered)", family.name()),
        }
    }
}

/// One [`BY_NAME`]/[`BY_PREFIX`] row: how a name maps to detector code.
///
/// Nearly every row is [`Row::All`] — one detector for every supported
/// tokio version, which is also the only sensible spelling for the std and
/// third-party detectors that no tokio release can move. A tokio
/// restructure turns its row [`Row::Versioned`]: one detector per
/// [`Family`], oldest first, and the target's selected family takes the
/// entry with the highest floor at or below it — so the newest entry keeps
/// serving every later version until a restructure adds a newer one. A row
/// with no entry old enough for the target declines to the structural
/// chain, the same fail-safe as any other mismatch.
#[derive(Copy, Clone)]
enum Row {
    /// One detector for every version.
    All(Detector),
    /// Family-keyed detectors, oldest first.
    Versioned(&'static [(Family, Detector)]),
}

use Row::{All, Versioned};

/// Detectors keyed by fully-qualified type name with generic arguments
/// stripped. Screening on the name means only the one matching detector runs
/// rather than each in turn, and it is what `--explain-format` reports as the
/// detector it selected — so a detector belongs here whenever a name selects
/// it, and its body then validates only the *structure*. A type named by
/// neither this table nor [`BY_PREFIX`] falls through to [`STRUCTURAL`].
static BY_NAME: &[(&str, Row)] = &[
    ("&camino::Utf8Path", All(utf8_path_node)),
    ("&str", All(str_node)),
    (
        "alloc::collections::btree::map::BTreeMap",
        All(btree_map_node),
    ),
    ("alloc::string::String", All(string_node)),
    ("alloc::vec::Vec", All(vec_node)),
    ("allocator_api2::stable::vec::Vec", All(vec_node)),
    ("camino::Utf8PathBuf", All(utf8_path_buf_node)),
    ("core::cell::UnsafeCell", All(unsafe_cell_node)),
    ("core::net::ip_addr::Ipv4Addr", All(ip_address_node)),
    ("core::net::ip_addr::Ipv6Addr", All(ip_address_node)),
    (
        "core::num::niche_types::UsizeNoHighBit",
        All(usize_no_high_bit_node),
    ),
    ("core::num::nonzero::NonZero", All(nonzero_node)),
    ("core::ptr::non_null::NonNull", All(non_null_node)),
    ("core::ptr::unique::Unique", All(unique_node)),
    ("core::sync::atomic::Atomic", All(atomic_node)),
    ("core::task::wake::RawWaker", All(raw_waker_node)),
    (
        "core::task::wake::RawWakerVTable",
        All(raw_waker_vtable_node),
    ),
    ("core::task::wake::Waker", All(waker_node)),
    ("parking_lot::raw_mutex::RawMutex", All(raw_mutex_node)),
    ("slog::Logger", All(elided_node)),
    ("std::sys::time::unix::Instant", All(instant_alias_node)),
    ("std::time::Instant", All(instant_alias_node)),
    (
        "tokio::loom::std::unsafe_cell::UnsafeCell",
        All(loom_unsafe_cell_node),
    ),
    ("tokio::runtime::handle::Handle", All(elided_node)),
    ("tokio::runtime::runtime::Runtime", All(elided_node)),
    ("tokio::runtime::scheduler::Handle", All(elided_node)),
    (
        "tokio::runtime::time::entry::TimerEntry",
        Versioned(&[(Family::V1_50, timer_entry_node)]),
    ),
    (
        "tokio::sync::batch_semaphore::Semaphore",
        All(batch_semaphore_node),
    ),
    ("tokio::sync::mpsc::block::Block", All(mpsc_block_node)),
    (
        "tokio::sync::mpsc::bounded::Receiver",
        All(mpsc_handle_node),
    ),
    ("tokio::sync::mpsc::bounded::Sender", All(mpsc_handle_node)),
    (
        "tokio::sync::mpsc::bounded::Semaphore",
        All(bounded_semaphore_node),
    ),
    ("tokio::sync::mpsc::chan::Chan", All(mpsc_chan_node)),
    ("tokio::sync::notify::Notify", All(notify_node)),
    ("tokio::sync::watch::Receiver", All(watch_receiver_node)),
    ("tokio::sync::watch::Sender", All(watch_sender_node)),
    ("tokio::sync::watch::Shared", All(watch_shared_node)),
    (
        "tokio::sync::watch::state::AtomicState",
        All(watch_state_node),
    ),
    ("tokio::time::instant::Instant", All(instant_alias_node)),
    (
        "tokio::time::sleep::Sleep",
        Versioned(&[(Family::V1_50, sleep_node)]),
    ),
    (
        "tokio::util::cacheline::CachePadded",
        All(cache_padded_node),
    ),
    (
        "tufaceous_artifact::artifact::ArtifactHash",
        All(hex_bytes_node),
    ),
    ("uuid::Uuid", All(uuid_node)),
];

/// Detectors keyed by a prefix of the *full* name, for a family no single base
/// name spans: a slice carries its element inside the brackets (`&[T]`,
/// `Box<[T]>`, where the `Box<[` prefix is what separates a boxed slice from a
/// thin `Box<T>`), the niche-typed `NonZero` inners are one type per width, and
/// the loom shims live one module per atomic width. A prefix is a looser screen
/// than a name, so these detectors keep the residual check the key cannot
/// express — `NonZeroU32Inner` ends in `Inner`, a loom atomic module has a
/// single segment.
static BY_PREFIX: &[(&str, Row)] = &[
    ("&[", All(slice_node)),
    ("alloc::boxed::Box<[", All(slice_node)),
    ("core::num::niche_types::NonZero", All(nonzero_inner_node)),
    ("tokio::loom::std::atomic_", All(loom_atomic_node)),
    (
        "tokio::loom::std::parking_lot::",
        All(loom_parking_lot_node),
    ),
];

/// Detectors that recognize a type by *shape* alone, tried in order from most
/// to least specific because nothing else separates them. This is the short
/// list on purpose: a detector a name can select belongs in [`BY_NAME`] or
/// [`BY_PREFIX`], where the dispatch is a lookup and `--explain-format` can say
/// which detector ran.
static STRUCTURAL: &[Detector] = &[
    // A `{ pointer, vtable }` pair, then a pointer to a subroutine type.
    dyn_pointer_node,
    function_pointer_node,
    // Least specific: a bare scalar newtype claims a type only if no semantic
    // formatter above it did.
    scalar_newtype_node,
];

/// Try the shape-keyed detectors in order.
fn structural_debug_format(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    STRUCTURAL.iter().find_map(|detector| detector(emitter, id))
}

pub(crate) fn unique_member<'a>(
    reader: &DwReader<'_>,
    members: &'a [crate::raw_types::RawMember<crate::StrId>],
    expected: &str,
) -> Option<(usize, &'a crate::raw_types::RawMember<crate::StrId>)> {
    let mut matches = members
        .iter()
        .enumerate()
        .filter(|(_, member)| member.name.map(|name| reader.strings.get(name)) == Some(expected));
    let found = matches.next()?;
    matches.next().is_none().then_some(found)
}

fn raw_variant<'a>(
    reader: &DwReader<'_>,
    en: &'a crate::raw_types::RawEnum<crate::StrId>,
    expected: &str,
) -> Option<&'a crate::raw_types::RawMember<crate::StrId>> {
    let variants: Vec<_> = match &en.shape {
        RawVariantShape::One(variant) => vec![&variant.member],
        RawVariantShape::Many { variants, .. } => variants
            .iter()
            .map(|(_, variant)| &variant.member)
            .collect(),
        RawVariantShape::Zero | RawVariantShape::CStyle { .. } => return None,
    };
    let mut matches = variants
        .into_iter()
        .filter(|member| member.name.map(|name| reader.strings.get(name)) == Some(expected));
    let found = matches.next()?;
    matches.next().is_none().then_some(found)
}

fn is_unsigned_integer(reader: &DwReader<'_>, id: TypeId, size: u64) -> bool {
    matches!(
        reader.canonical_type(id),
        Some(RawType::Base(base)) if base.size == size && base.encoding == Encoding::Unsigned
    )
}

/// What a member walk is looking for, and what it reports on arrival.
enum Want<'a> {
    /// A type the predicate accepts, reported as itself.
    Type(&'a dyn Fn(TypeId) -> bool),
    /// A pointer whose target the predicate accepts. The walk lands on the
    /// pointer — so the path stops there rather than crossing it — and
    /// reports the *target*, which is what a caller then navigates.
    PointerTo(&'a dyn Fn(TypeId) -> bool),
}

impl Want<'_> {
    /// How this want reads in a formatter trace.
    fn label(&self) -> &'static str {
        match self {
            Want::Type(_) => "a matching type",
            Want::PointerTo(_) => "a pointer to a matching type",
        }
    }

    /// The type to report for a candidate the walk landed on, or `None` when
    /// it is not what this want is looking for.
    fn accepts(&self, reader: &DwReader<'_>, id: TypeId) -> Option<TypeId> {
        match self {
            Want::Type(pred) => pred(id).then_some(id),
            Want::PointerTo(pred) => {
                let RawType::Pointer(pointer) = reader.canonical_type(id)? else {
                    return None;
                };
                let target = reader.canonicalize(pointer.target_type_id);
                pred(target).then_some(target)
            }
        }
    }
}

/// Which members a walk may descend through.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Through {
    /// Members at offset zero only: the transparent-wrapper chain an atomic,
    /// a cell, or a newtype builds around one datum.
    ZeroOffset,
    /// Every member, for a datum a struct keeps past its own bookkeeping —
    /// the value inside a lock, say.
    AnyOffset,
}

/// A wrapper chain deeper than this is not one; the cap also bounds the walk
/// on a type graph that nests without repeating a type.
const MAX_WRAPPER_DEPTH: usize = 8;

/// The one member path from `root` to what `want` accepts, with the type it
/// reports.
///
/// Uniqueness is the point: two candidates mean this is not the layout the
/// caller recognized, and choosing either would be a guess, so both that and
/// "no candidate" return `None` and the type renders structurally. Every
/// detector that reaches a datum by shape rather than by name goes through
/// here.
fn find_unique(
    reader: &DwReader<'_>,
    root: TypeId,
    want: Want<'_>,
    through: Through,
) -> Option<(Selector, TypeId)> {
    fn walk(
        reader: &DwReader<'_>,
        current: TypeId,
        want: &Want<'_>,
        through: Through,
        path: &mut Vec<u32>,
        seen: &mut Vec<TypeId>,
        found: &mut Vec<(Vec<u32>, TypeId)>,
    ) {
        // One hit past the first is enough to know the answer is ambiguous.
        if found.len() > 1 || path.len() >= MAX_WRAPPER_DEPTH || seen.contains(&current) {
            return;
        }
        if let Some(reported) = want.accepts(reader, current) {
            found.push((path.clone(), reported));
            return;
        }
        let members = match reader.canonical_type(current) {
            Some(RawType::Struct(st)) => st.members.as_ref(),
            Some(RawType::Union(union)) => union.members.as_ref(),
            _ => return,
        };
        seen.push(current);
        for (index, member) in members.iter().enumerate() {
            if through == Through::ZeroOffset && member.offset != 0 {
                continue;
            }
            path.push(index as u32);
            walk(
                reader,
                reader.canonicalize(member.type_id),
                want,
                through,
                path,
                seen,
                found,
            );
            path.pop();
        }
        seen.pop();
    }

    let mut found = Vec::new();
    walk(
        reader,
        reader.canonicalize(root),
        &want,
        through,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut found,
    );
    let [(path, reported)] = found.as_slice() else {
        explain!(
            "  find_unique in {}: {} {} through {}",
            type_label(reader, root),
            if found.is_empty() {
                "found nothing matching".to_string()
            } else {
                format!("found {}+ candidates for", found.len())
            },
            want.label(),
            match through {
                Through::ZeroOffset => "zero-offset members",
                Through::AnyOffset => "any member",
            },
        );
        return None;
    };
    Some((Selector::members(path), *reported))
}

/// The DWARF member a [`MemberRef`] addresses.
///
/// A name in a display program is a [`StrRef`] into the bundle's own string
/// table, so matching one against DWARF means reading it back out of the
/// interner the detector put it in and comparing spellings. The uniqueness
/// rule is [`MemberRef::resolve`]'s, the same one validation and reify apply.
fn raw_member_at<'m>(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    members: &'m [crate::raw_types::RawMember<crate::StrId>],
    at: &MemberRef,
) -> Option<&'m crate::raw_types::RawMember<crate::StrId>> {
    let index = at.resolve(members.len(), |index, name| {
        members[index].name.map(|n| reader.strings.get(n)) == strings.get(name)
    })?;
    members.get(index)
}

/// Walk a [`Selector`] through DWARF from `root`, returning the type it lands
/// on. The DWARF counterpart of the bundle's own `selector_target`; where that
/// one validates a finished bundle, this one lets a detector be held to the
/// same addressing contract while the node is still being built.
fn selector_lands(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    root: TypeId,
    sel: &Selector,
) -> Option<TypeId> {
    let mut cur = reader.canonicalize(root);
    for step in sel.steps() {
        cur = match step {
            Step::Member(at) => {
                let members = match reader.canonical_type(cur)? {
                    RawType::Struct(st) => &st.members,
                    RawType::Union(union) => &union.members,
                    _ => return None,
                };
                reader.canonicalize(raw_member_at(reader, strings, members, at)?.type_id)
            }
            Step::Deref => {
                let RawType::Pointer(pointer) = reader.canonical_type(cur)? else {
                    return None;
                };
                reader.canonicalize(pointer.target_type_id)
            }
            Step::Variant(name) => {
                let RawType::Enum(en) = reader.canonical_type(cur)? else {
                    return None;
                };
                let variant = raw_variant(reader, en, strings.get(*name)?)?;
                reader.canonicalize(variant.type_id)
            }
        };
    }
    Some(cur)
}

/// Whether DWARF's `id` meets `shape`. This is the [`DwReader`] half of the
/// shared shape table (`crate::bundle::shape`); the bundle's `shape_matches`
/// is the other.
fn raw_shape_matches(reader: &DwReader<'_>, id: TypeId, shape: Shape) -> bool {
    match shape {
        Shape::Word => matches!(raw_type_size(reader, id), Some(1..=8)),
        Shape::Uint(size) => is_unsigned_integer(reader, id, size),
        Shape::PointerSized => raw_type_size(reader, id) == Some(crate::bundle::POINTER_SIZE),
        Shape::Pointer => matches!(reader.canonical_type(id), Some(RawType::Pointer(_))),
        Shape::Array => matches!(reader.canonical_type(id), Some(RawType::Array(_))),
        Shape::Any => true,
    }
}

/// Whether every datum `node` addresses within a value of type `root` is
/// reachable and has the shape its node kind requires.
///
/// This holds a detector to the schema's addressing contract without the
/// detector having to restate it: a formatter that navigated to the wrong
/// member declines here and the type renders structurally, rather than
/// producing a node that only fails when the finished bundle is validated.
///
/// A child node rooted somewhere else — a list element, the target of a
/// pointer hop — is not walked, since its root is a bundle id the detector
/// reserved rather than a `TypeId`; those are checked against the type table
/// on save. Children rendered against this same value are walked.
fn addressing_holds(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    root: TypeId,
    node: &DisplayNode,
) -> bool {
    for addressed in node.addressed() {
        let what = addressed.what;
        if addressed.sel.is_empty() && !addressed.root_allowed {
            explain!("  {what} addresses the value itself, which its node may not do");
            return false;
        }
        let Some(landed) = selector_lands(reader, strings, root, addressed.sel) else {
            explain!("  {what} does not resolve in {}", type_label(reader, root));
            return false;
        };
        if !raw_shape_matches(reader, landed, addressed.shape) {
            explain!(
                "  {what} lands on {}, which is not {}",
                type_label(reader, landed),
                addressed.shape,
            );
            return false;
        }
    }
    match node {
        DisplayNode::Struct { fields } => fields.iter().all(|field| match field {
            Field::Member { node: None, .. } => true,
            Field::Member {
                node: Some(node), ..
            }
            | Field::Synth { node, .. } => addressing_holds(reader, strings, root, node),
        }),
        DisplayNode::Variant { arms, default, .. } => {
            arms.iter().all(|arm| {
                arm.payload
                    .as_ref()
                    .is_none_or(|node| addressing_holds(reader, strings, root, node))
            }) && default
                .as_ref()
                .is_none_or(|node| addressing_holds(reader, strings, root, node))
        }
        _ => true,
    }
}

/// One step of a [`Reach`]: how a detector says to get somewhere, before
/// anything has looked at DWARF.
#[derive(Clone)]
enum ReachStep<'a> {
    /// The uniquely-named member. What a detector reaches for whenever the
    /// spelling is stable, which is nearly always.
    Named(&'a str),
    /// Follow the pointer reached so far.
    Deref,
    /// Enter the named variant's payload of a Rust enum — landing on the
    /// per-variant struct rustc emits, whose members then address the
    /// variant's fields. The step lowers statically (a payload's offset is
    /// fixed either way); reify guards every read crossing it with the
    /// enum's discriminant, so only a read that travels as a guarded place —
    /// a value-expression `Read`, an `Alias` — may carry one (see
    /// [`Step::Variant`]).
    Variant(&'a str),
    /// Descend the zero-offset wrapper chain to the one value of this shape.
    ///
    /// tokio reaches an atomic's word through a different chain of loom,
    /// `UnsafeCell` and atomic shims depending on how the compiler spelled the
    /// atomic, so a pattern says what it is looking for rather than naming
    /// wrappers it cannot predict. Two candidates decline just as none do.
    PeelTo(Shape),
    /// Descend the zero-offset wrapper chain to the `T` a `Wrapper<T>`
    /// declares. What an atomic peels to is its own parameter rather than any
    /// fixed shape — `AtomicPtr` stores a pointer, `AtomicUsize` a word — so
    /// the type the wrapper names is the only thing that identifies it.
    PeelToParam,
    /// The same search for a declared `T`, but through *any* member rather
    /// than the zero-offset chain.
    ///
    /// Where peeling unwraps transparent layers, this digs past a type's own
    /// bookkeeping: a lock keeps its guarded `T` beside a raw lock word, so no
    /// chain of wrappers leads to it. Which bookkeeping there is varies by
    /// platform and lock implementation, so the `T` is searched for rather
    /// than navigated to. Uniqueness still decides: two candidates decline
    /// exactly as none do.
    FindParam,
    /// Continue along a path something else already resolved — how a shape
    /// helper's selectors are anchored under the member that holds them.
    Resolved(Selector),
}

/// A path from a type to a datum inside it, outermost step first.
type Reach<'a> = Vec<ReachStep<'a>>;

// A path is written far more often than it is matched on, so the steps are
// spelled bare: `reach![Named("head"), Deref]` reads as the path it describes.
use ReachStep::Named;

/// The shape of a `usize`, which most of what a path peels to is.
const WORD: Shape = Shape::Uint(crate::bundle::POINTER_SIZE);

impl Emitter<'_> {
    /// Address the uniquely-named member `name` of `root`, checking it is
    /// there.
    fn member_named(&mut self, root: TypeId, name: &str) -> Option<MemberRef> {
        let members = aggregate_members(self.reader, root)?;
        if unique_member(self.reader, members, name).is_none() {
            explain!(
                "  no unique member `{name}` in {}, which has {}",
                type_label(self.reader, root),
                member_labels(self.reader, members),
            );
            return None;
        }
        Some(MemberRef::Named(self.intern(name)))
    }

    /// Resolve a pattern path against `root`: the selector it lowers to and
    /// the type it lands on.
    fn walk(&mut self, root: TypeId, path: &Reach<'_>) -> Option<(Selector, TypeId)> {
        let mut steps = Vec::new();
        let mut cur = self.reader.canonicalize(root);
        for step in path {
            match step {
                Named(name) => {
                    let members = aggregate_members(self.reader, cur).or_else(|| {
                        explain!(
                            "  path stopped at `{name}`, since {} is not a struct or union",
                            type_label(self.reader, cur),
                        );
                        None
                    })?;
                    let Some((_, member)) = unique_member(self.reader, members, name) else {
                        explain!(
                            "  no unique member `{name}` in {}, which has {}",
                            type_label(self.reader, cur),
                            member_labels(self.reader, members),
                        );
                        return None;
                    };
                    cur = self.reader.canonicalize(member.type_id);
                    steps.push(Step::Member(MemberRef::Named(self.intern(name))));
                }
                ReachStep::Deref => {
                    let Some(RawType::Pointer(pointer)) = self.reader.canonical_type(cur) else {
                        explain!(
                            "  path dereferences {}, which is not a pointer",
                            type_label(self.reader, cur),
                        );
                        return None;
                    };
                    cur = self.reader.canonicalize(pointer.target_type_id);
                    steps.push(Step::Deref);
                }
                ReachStep::Variant(name) => {
                    let Some(RawType::Enum(en)) = self.reader.canonical_type(cur) else {
                        explain!(
                            "  path enters variant `{name}`, but {} is not an enum",
                            type_label(self.reader, cur),
                        );
                        return None;
                    };
                    let Some(variant) = raw_variant(self.reader, en, name) else {
                        explain!(
                            "  no unique variant `{name}` in {}",
                            type_label(self.reader, cur),
                        );
                        return None;
                    };
                    cur = self.reader.canonicalize(variant.type_id);
                    steps.push(Step::Variant(self.intern(name)));
                }
                ReachStep::PeelTo(shape) => {
                    let reader = self.reader;
                    let accepts = |id| raw_shape_matches(reader, id, *shape);
                    let (found, landed) =
                        self.search(cur, &accepts, Through::ZeroOffset, &shape.to_string())?;
                    steps.extend(found.0);
                    cur = landed;
                }
                ReachStep::PeelToParam => {
                    let (found, landed) = self.search_param(cur, Through::ZeroOffset)?;
                    steps.extend(found.0);
                    cur = landed;
                }
                ReachStep::FindParam => {
                    let (found, landed) = self.search_param(cur, Through::AnyOffset)?;
                    steps.extend(found.0);
                    cur = landed;
                }
                ReachStep::Resolved(sel) => {
                    let Some(landed) = selector_lands(self.reader, &self.interner, cur, sel) else {
                        explain!(
                            "  an already-resolved path does not reach into {}",
                            type_label(self.reader, cur),
                        );
                        return None;
                    };
                    steps.extend(self.readdress(cur, sel)?.0);
                    cur = landed;
                }
            }
        }
        Some((Selector(steps), cur))
    }

    /// Descend from `root` to the one value `accepts` takes, name-addressed —
    /// `through` decides whether that is the zero-offset wrapper chain or any
    /// member. `want` names what was looked for, for the trace when nothing or
    /// several were found.
    fn search(
        &mut self,
        root: TypeId,
        accepts: &dyn Fn(TypeId) -> bool,
        through: Through,
        want: &str,
    ) -> Option<(Selector, TypeId)> {
        let Some((found, landed)) = find_unique(self.reader, root, Want::Type(accepts), through)
        else {
            explain!(
                "  no single {want} is stored in {}",
                type_label(self.reader, root),
            );
            return None;
        };
        Some((self.readdress(root, &found)?, landed))
    }

    /// Search for the `T` the type at `root` declares, either way through.
    fn search_param(&mut self, root: TypeId, through: Through) -> Option<(Selector, TypeId)> {
        let reader = self.reader;
        let Some(param) = struct_of(reader, root).and_then(|st| sole_param_target(reader, st))
        else {
            explain!(
                "  {} does not declare a sole parameter `T`",
                type_label(reader, root),
            );
            return None;
        };
        let accepts = |id| id == param;
        self.search(root, &accepts, through, &type_label(reader, param))
    }

    /// Every member structural display would show — those of nonzero size — as
    /// `Field`s in declaration order, with the named ones computed instead of
    /// rendered.
    ///
    /// A zero-sized member carries no value and structural display elides it,
    /// so a record that listed it would differ from the plain view for no
    /// reason. An override naming a member that is not there, or is elided,
    /// declines: it means the detector is describing a layout this type does
    /// not have.
    ///
    /// Synthesized fields are the caller's business — it splices them around
    /// the result — which is why this is a helper and not a kind of field list.
    /// A record that is "the type itself plus one computed field" and one that
    /// is "the type itself plus a synthetic field" then cost the same.
    fn visible_fields(
        &mut self,
        root: TypeId,
        mut overrides: Vec<(&str, DisplayNode)>,
    ) -> Option<Vec<Field>> {
        let reader = self.reader;
        let members = aggregate_members(reader, root)?;
        let mut fields = Vec::with_capacity(members.len());
        for (index, member) in members.iter().enumerate() {
            if raw_type_size(reader, member.type_id).unwrap_or(0) == 0 {
                continue;
            }
            let name = member.name.map(|name| reader.strings.get(name));
            let at = self.address(members, index as u32);
            fields.push(
                match overrides.iter().position(|(want, _)| Some(*want) == name) {
                    Some(position) => Field::computed(at, overrides.remove(position).1),
                    None => Field::member(at),
                },
            );
        }
        overrides.is_empty().then_some(fields)
    }

    /// The type the pointer `ty` targets. Declines, narrating, when it is not
    /// a pointer — the one thing a caller crossing one has to establish before
    /// it can root anything at the far side.
    fn pointee(&self, ty: TypeId) -> Option<TypeId> {
        let Some(RawType::Pointer(pointer)) = self.reader.canonical_type(ty) else {
            explain!(
                "  {} is not a pointer, so nothing is behind it",
                type_label(self.reader, ty),
            );
            return None;
        };
        Some(self.reader.canonicalize(pointer.target_type_id))
    }

    /// [`Emitter::pointee`], reserved, for a node that names the type behind a
    /// pointer rather than rooting a path there.
    fn behind(&mut self, ty: TypeId) -> Option<BundleTypeId> {
        let target = self.pointee(ty)?;
        Some(self.reserve(target))
    }

    /// Re-address a path that was found rather than declared, so it names what
    /// it can.
    ///
    /// A shape walk reports positions, since what it matched on was a type and
    /// not a name. Converting each hop through [`Emitter::address`] here is
    /// what makes a discovered path as durable as a declared one — and it is
    /// the only place that conversion happens, so no walk can forget it.
    fn readdress(&mut self, root: TypeId, found: &Selector) -> Option<Selector> {
        let mut steps = Vec::with_capacity(found.steps().len());
        let mut cur = self.reader.canonicalize(root);
        for step in found.steps() {
            match step {
                Step::Member(at) => {
                    let members = aggregate_members(self.reader, cur)?;
                    let index = at.resolve(members.len(), |index, name| {
                        members[index].name.map(|n| self.reader.strings.get(n))
                            == self.interner.get(name)
                    })?;
                    cur = self.reader.canonicalize(members[index].type_id);
                    steps.push(Step::Member(self.address(members, index as u32)));
                }
                Step::Deref => {
                    let RawType::Pointer(pointer) = self.reader.canonical_type(cur)? else {
                        return None;
                    };
                    cur = self.reader.canonicalize(pointer.target_type_id);
                    steps.push(Step::Deref);
                }
                Step::Variant(name) => {
                    // Already addressed by name; only the type advances.
                    let RawType::Enum(en) = self.reader.canonical_type(cur)? else {
                        return None;
                    };
                    let variant = raw_variant(self.reader, en, self.interner.get(*name)?)?;
                    cur = self.reader.canonicalize(variant.type_id);
                    steps.push(Step::Variant(*name));
                }
            }
        }
        Some(Selector(steps))
    }

    /// The type a pattern path lands on, for a screen tighter than the shape
    /// the node itself requires.
    fn landed(&mut self, root: TypeId, path: &Reach<'_>) -> Option<TypeId> {
        Some(self.walk(root, path)?.1)
    }
}

/// The members of `id`, or `None` when it is not an aggregate.
fn aggregate_members<'r>(
    reader: &'r DwReader<'_>,
    id: TypeId,
) -> Option<&'r [crate::raw_types::RawMember<crate::StrId>]> {
    match reader.canonical_type(id)? {
        RawType::Struct(st) => Some(&st.members),
        RawType::Union(union) => Some(&union.members),
        _ => None,
    }
}

impl Emitter<'_> {
    /// Build a [`DisplayNode::Struct`] field named `label` whose value is the
    /// decoded word at `at` — the shape every curated sync-primitive record is
    /// mostly made of.
    fn named_scalar(&mut self, label: &str, at: Selector, decode: ScalarDecode) -> Field {
        Field::Synth {
            label: self.intern(label),
            node: DisplayNode::Scalar { at, decode },
        }
    }

    /// Build an enumerated [`BitField`], interning its label and value labels.
    fn enum_field(&mut self, name: &str, shift: u8, width: u8, table: &[(u64, &str)]) -> BitField {
        let name = self.interner.intern(name);
        let interner = &mut self.interner;
        let render = FieldRender::Enum(
            table
                .iter()
                .map(|(v, l)| (*v, interner.intern(l)))
                .collect(),
        );
        BitField {
            name,
            shift,
            width: NonZeroU8::new(width),
            render,
        }
    }

    /// Build a single-bit boolean [`BitField`] rendered as `false`/`true`.
    fn bool_field(&mut self, name: &str, shift: u8) -> BitField {
        self.enum_field(name, shift, 1, &[(0, "false"), (1, "true")])
    }

    /// Build an unsigned-integer [`BitField`] covering all bits at and above
    /// `shift` (`width: None`).
    fn uint_tail_field(&mut self, name: &str, shift: u8) -> BitField {
        let name = self.interner.intern(name);
        BitField {
            name,
            shift,
            width: None,
            render: FieldRender::Uint,
        }
    }

    /// A boolean byte rendered bare as `false`/`true` (an empty field name, so
    /// no `name=` prefix) — for a bool shown under a record label of its own.
    fn bool_decode(&mut self) -> ScalarDecode {
        ScalarDecode::Bits(vec![self.bool_field("", 0)])
    }

    /// The display program for one type: its name-keyed detector if it has
    /// one, else the structural chain.
    ///
    /// Whichever produced it, the node is held to the schema's addressing
    /// contract ([`addressing_holds`]) before it is accepted, so a detector
    /// declines the same way whether it noticed the mismatch itself or not.
    pub(crate) fn debug_format_of(
        &mut self,
        tid: TypeId,
        name: Option<&str>,
    ) -> Option<DisplayNode> {
        if let Some(node) = self.specific_debug_format(tid, name)
            && addressing_holds(self.reader, &self.interner, tid, &node)
        {
            return Some(node);
        }
        let node = structural_debug_format(self, tid)?;
        addressing_holds(self.reader, &self.interner, tid, &node).then_some(node)
    }

    /// The name to report this type under, when the caller asked for its
    /// formatter to be explained.
    pub(crate) fn explained(&self, name: Option<&str>) -> Option<String> {
        let wanted = self.explain_format.as_deref()?;
        let name = name?;
        name.contains(wanted).then(|| name.to_string())
    }

    /// Build the display program for a type whose fully-qualified name selects a
    /// specific detector: an exact base-name match in [`BY_NAME`], else a
    /// full-name prefix in [`BY_PREFIX`]. A type named by neither falls through
    /// to [`structural_debug_format`], the short shape-keyed chain.
    fn specific_debug_format(&mut self, tid: TypeId, full: Option<&str>) -> Option<DisplayNode> {
        let full = full?;
        // Strip generic arguments for the exact-keyed detectors; the prefix
        // table keeps the full name, since `&[T]`/`Box<[T]>` are not
        // distinguished by a leading path.
        let base = full.split_once('<').map_or(full, |(head, _)| head);
        let matched = BY_NAME.iter().find(|&&(name, _)| name == base).or_else(|| {
            BY_PREFIX
                .iter()
                .find(|&&(prefix, _)| full.starts_with(prefix))
        });
        let Some(&(key, row)) = matched else {
            explain!("  no name-keyed detector for `{base}`; trying the structural chain");
            return None;
        };
        let detector = match row {
            All(detector) => {
                explain!("  name-keyed detector for `{key}` selected");
                detector
            }
            Versioned(families) => {
                self.versioned_dispatch = true;
                let Some(&(family, detector)) = families
                    .iter()
                    .rev()
                    .find(|&&(family, _)| family <= self.family)
                else {
                    explain!(
                        "  name-keyed detector for `{key}` has no entry as old as \
                         family {}; trying the structural chain",
                        self.family.name(),
                    );
                    return None;
                };
                let why = match &self.tokio_version {
                    Some(version) => format!("tokio {version}"),
                    None => "version unrecovered".to_owned(),
                };
                explain!(
                    "  name-keyed detector for `{key}` selected (family {}: {why})",
                    family.name(),
                );
                detector
            }
        };
        detector(self, tid)
    }
}

/// Whether `at` reaches an inline array of unsigned bytes — exactly `count` of
/// them when a count is given, any nonzero number otherwise.
///
/// A `Bytes` node requires an array and validation requires the length its
/// notation spells, but only at save time — so a detector that would emit the
/// wrong length screens for it here and declines instead.
fn is_byte_array(
    emitter: &mut Emitter<'_>,
    id: TypeId,
    at: &Reach<'_>,
    count: Option<u64>,
) -> bool {
    let Some(landed) = emitter.landed(id, at) else {
        return false;
    };
    let reader = emitter.reader;
    matches!(reader.canonical_type(landed), Some(RawType::Array(array))
        if count.unwrap_or(array.count) == array.count
            && array.count > 0
            && is_unsigned_integer(reader, array.elem_type_id, 1))
}

/// The types worth less than the space their insides take: a runtime handle
/// or an owned runtime drags the whole scheduler graph into every value that
/// stores one, and a logger is an `Arc<dyn Drain>` chain of sinks. Neither is
/// ever what a debugging session is reading a value for, so they render as
/// `<elided>`; `--ugly` shows them structurally like everything else.
///
/// The `scheduler::Handle` enum is here for the same reason as the outer
/// `handle::Handle` it sits inside: tokio's timer entries and io registrations
/// embed one directly, so any future holding a `Sleep` or a registered socket
/// would otherwise render the whole runtime.
///
/// Deliberately *not* here: the handles *inside* the per-scheduler handle
/// (`tokio::runtime::driver::Handle`, `multi_thread::worker::Shared`), which
/// the `drivers` and `shared-state` commands render on purpose. Eliding the
/// wrappers embedded in user futures does not touch them, since hansei reaches
/// them by member navigation, never by rendering a wrapper value.
fn elided_node(_emitter: &mut Emitter<'_>, _id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Elided)
}

/// The index of the unique member at offset zero named `name` — or of whatever
/// name, when that is `None` — whose type `accept`s.
///
/// Zero and several both give `None`: a wrapper with two candidate members is
/// not one this can see through, so an ambiguous layout fails closed the same
/// way a renamed member does.
fn zero_offset_member(
    reader: &DwReader<'_>,
    members: &[crate::raw_types::RawMember<crate::StrId>],
    name: Option<&str>,
    accept: impl Fn(TypeId) -> bool,
) -> Option<u32> {
    let mut matches = members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && name.is_none_or(|want| member.name.map(|n| reader.strings.get(n)) == Some(want))
            && accept(member.type_id)
    });
    let (index, _) = matches.next()?;
    matches.next().is_none().then_some(index as u32)
}

/// The struct `id` canonically names, or `None` if it is not a struct. This is a
/// detector's usual first move: a formatter for a named Rust type is a formatter
/// for an aggregate, and one handed anything else declines.
pub(crate) fn struct_of<'r>(
    reader: &'r DwReader<'_>,
    id: TypeId,
) -> Option<&'r crate::raw_types::RawStruct<crate::StrId>> {
    match reader.canonical_type(id)? {
        RawType::Struct(st) => Some(st),
        _ => None,
    }
}

/// The `T` of a wrapper declared `Wrapper<T>`, canonicalized, or `None` if the
/// type does not have exactly that one parameter. A transparent wrapper's
/// member has to *be* this type: checking it is what stops a detector from
/// aliasing whatever else happens to sit at offset zero.
fn sole_param_target(
    reader: &DwReader<'_>,
    st: &crate::raw_types::RawStruct<crate::StrId>,
) -> Option<TypeId> {
    let [param] = st.template_params.as_ref() else {
        return None;
    };
    (param.name.map(|name| reader.strings.get(name)) == Some("T"))
        .then(|| reader.canonicalize(param.type_id))
}

/// A transparent wrapper displays as the one member that *is* its value, so it
/// renders through that member and chases it if it is a pointer. The ten
/// wrappers std and tokio's loom shims interpose all reduce to this; what
/// differs between them is only which member [`zero_offset_member`] accepts.
/// (An atomic is not one of them: it aliases its value without chasing it, and
/// reaches it through a whole wrapper chain, peeling to its own parameter.)
fn transparent(
    emitter: &mut Emitter<'_>,
    members: &[crate::raw_types::RawMember<crate::StrId>],
    member: u32,
) -> Option<DisplayNode> {
    let at = emitter.address(members, member);
    Some(DisplayNode::Alias {
        at: Selector(vec![Step::Member(at)]),
        follow_pointers: true,
    })
}

#[cfg(test)]
mod tests {
    use super::ReachStep::{Named, PeelTo};
    use super::std::{dyn_tail_offset, has_dyn_tail, scalar_newtype_node, str_node};
    use super::{Detector, Family, trace};
    use crate::bundle::{DisplayNode, MemberRef, Notation, POINTER_SIZE, Shape, Step};
    use crate::extract::Emitter;
    use crate::raw_types::{NsId, RawBase, RawMember, RawPointer, RawStruct, RawType};
    use crate::{DwReader, Encoding, TypeId};

    use gimli::{DebugInfoOffset, UnitSectionOffset};

    use ::std::collections::BTreeMap;

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(offset)))
    }

    /// Version-keyed family selection: highest floor at or below the
    /// version, the newest family for anything newer or unrecovered, and
    /// the oldest for anything below every floor.
    #[test]
    fn test_family_selection() {
        let v = |s: &str| semver::Version::parse(s).unwrap();
        let newest = *Family::ALL.last().unwrap();
        assert_eq!(Family::select(None), newest);
        assert_eq!(Family::select(Some(&v("1.50.0"))), Family::V1_50);
        assert_eq!(Family::select(Some(&v("1.52.4"))), Family::V1_50);
        assert_eq!(Family::select(Some(&v("1.99.0"))), newest);
        assert_eq!(Family::select(Some(&v("1.49.9"))), Family::ALL[0]);
        assert_eq!(Family::describe(Some(&v("1.50.0"))), "v1_50 (tokio 1.50.0)");
        assert_eq!(Family::describe(None), "v1_50 (version unrecovered)");
    }

    /// Run one detector directly. Every detector takes an `Emitter` whether or
    /// not it uses one, so a test that only navigates DWARF still needs one.
    fn detect(reader: &DwReader<'_>, detector: Detector, id: TypeId) -> Option<DisplayNode> {
        detector(&mut Emitter::new(reader, BTreeMap::new(), None, None), id)
    }

    /// Dispatch `id` the way the emitter does, by the name it would carry. This
    /// covers the [`super::BY_NAME`]/[`super::BY_PREFIX`] row as well as the
    /// detector, which is where the name screening now lives.
    fn detect_by_name(reader: &DwReader<'_>, id: TypeId, name: &str) -> Option<DisplayNode> {
        Emitter::new(reader, BTreeMap::new(), None, None).specific_debug_format(id, Some(name))
    }

    /// The member a transparent wrapper aliases, spelled the way the detector
    /// addressed it: a name where it used one, `#index` where it counted.
    ///
    /// A `MemberRef::Named` carries a string-table position, which says nothing
    /// on its own, so a test that means "aliases `__0`" compares against that
    /// rather than against whatever position the emitter happened to intern it
    /// at.
    fn aliased(node: Option<DisplayNode>, emitter: &Emitter<'_>) -> Option<String> {
        let DisplayNode::Alias {
            at,
            follow_pointers: true,
        } = node?
        else {
            return None;
        };
        match at.steps() {
            [Step::Member(MemberRef::Named(name))] => Some(emitter.interner.get(*name)?.to_owned()),
            [Step::Member(MemberRef::Index(index))] => Some(format!("#{index}")),
            _ => None,
        }
    }

    /// [`aliased`] over one detector run directly.
    fn detect_alias(reader: &DwReader<'_>, detector: Detector, id: TypeId) -> Option<String> {
        let mut emitter = Emitter::new(reader, BTreeMap::new(), None, None);
        let node = detector(&mut emitter, id);
        aliased(node, &emitter)
    }

    /// [`aliased`] over one dispatch by name.
    fn detect_alias_by_name(reader: &DwReader<'_>, id: TypeId, name: &str) -> Option<String> {
        let mut emitter = Emitter::new(reader, BTreeMap::new(), None, None);
        let node = emitter.specific_debug_format(id, Some(name));
        aliased(node, &emitter)
    }

    fn empty_struct(name: crate::StrId) -> RawType<crate::StrId> {
        RawStruct {
            name: Some(name),
            namespace: None,
            size: 0,
            members: Box::new([]),
            template_params: Box::new([]),
            source_loc: None,
        }
        .into()
    }

    fn wrapper(name: crate::StrId, tail: TypeId) -> RawType<crate::StrId> {
        RawStruct {
            name: Some(name),
            namespace: None,
            size: 16,
            members: Box::new([RawMember {
                name: None,
                offset: 16,
                type_id: tail,
                source_loc: None,
            }]),
            template_params: Box::new([]),
            source_loc: None,
        }
        .into()
    }

    #[test]
    fn test_has_dyn_tail_through_unsized_wrapper() {
        let mut reader = DwReader::default();
        let dyn_id = type_id(1);
        let inner_id = type_id(2);
        let outer_id = type_id(3);
        let plain_id = type_id(4);
        let dyn_name = reader.strings.intern("dyn app::Trait");
        let inner_name = reader
            .strings
            .intern("alloc::sync::ArcInner<dyn app::Trait>");
        let outer_name = reader
            .strings
            .intern("app::Outer<alloc::sync::ArcInner<dyn app::Trait>>");
        let plain_name = reader.strings.intern("app::Plain");
        reader.types.insert(dyn_id, empty_struct(dyn_name));
        reader.types.insert(inner_id, wrapper(inner_name, dyn_id));
        reader.types.insert(outer_id, wrapper(outer_name, inner_id));
        reader.types.insert(plain_id, empty_struct(plain_name));

        assert!(has_dyn_tail(&reader, dyn_id, &mut Vec::new()));
        assert!(has_dyn_tail(&reader, inner_id, &mut Vec::new()));
        assert!(has_dyn_tail(&reader, outer_id, &mut Vec::new()));
        assert!(!has_dyn_tail(&reader, plain_id, &mut Vec::new()));

        // A bare `dyn` sits at offset zero; each wrapper adds its tail
        // member's offset (16), so the erased value is reached by skipping
        // the accumulated sized headers.
        assert_eq!(dyn_tail_offset(&reader, dyn_id, &mut Vec::new()), Some(0));
        assert_eq!(
            dyn_tail_offset(&reader, inner_id, &mut Vec::new()),
            Some(16)
        );
        assert_eq!(
            dyn_tail_offset(&reader, outer_id, &mut Vec::new()),
            Some(32)
        );
        assert_eq!(dyn_tail_offset(&reader, plain_id, &mut Vec::new()), None);
    }

    /// A failed named walk says which member it wanted and what the type
    /// actually has — the question `--explain-format` exists to answer, since
    /// a detector that returns `None` otherwise leaves no trace at all.
    #[test]
    fn test_a_failed_field_walk_names_the_member_and_the_alternatives() {
        let mut reader = DwReader::default();
        let notify = type_id(1);
        let word = type_id(2);
        let name = reader.strings.intern("Notify");
        let u64_name = reader.strings.intern("u64");
        let waiters = reader.strings.intern("waiters");
        let generation = reader.strings.intern("generation");
        reader.types.insert(
            word,
            crate::raw_types::RawBase {
                name: Some(u64_name),
                namespace: None,
                size: 8,
                alignment: None,
                encoding: crate::Encoding::Unsigned,
            }
            .into(),
        );
        reader.types.insert(
            notify,
            ns_struct(
                None,
                name,
                16,
                vec![
                    RawMember {
                        name: Some(waiters),
                        offset: 0,
                        type_id: word,
                        source_loc: None,
                    },
                    RawMember {
                        name: Some(generation),
                        offset: 8,
                        type_id: word,
                        source_loc: None,
                    },
                ],
            ),
        );

        let walk = |path| {
            trace::capture(|| {
                Emitter::new(&reader, BTreeMap::new(), None, None)
                    .walk(notify, &path)
                    .map(|(at, _)| at)
            })
        };

        // The member is missing: the trace names it and lists what is there.
        let (got, trace) = walk(reach![Named("state")]);
        assert!(got.is_none());
        assert_eq!(trace.len(), 1, "{trace:?}");
        assert!(
            trace[0].contains("no unique member `state`")
                && trace[0].contains("Notify")
                && trace[0].contains("waiters, generation"),
            "{}",
            trace[0]
        );

        // The walk leaves an aggregate: the trace says where it stopped.
        let (got, trace) = walk(reach![Named("waiters"), Named("value")]);
        assert!(got.is_none());
        assert!(
            trace[0].contains("stopped at `value`") && trace[0].contains("u64"),
            "{}",
            trace[0]
        );

        // A walk that fits says nothing — silence is the ordinary case — and
        // addresses what it found by name, the point of describing a layout
        // rather than counting to it.
        let (got, trace) = walk(reach![Named("waiters")]);
        assert!(trace.is_empty(), "{trace:?}");
        let Some(at) = got else {
            panic!("a pattern that fits compiles to its node");
        };
        assert!(
            matches!(at.steps(), [Step::Member(MemberRef::Named(_))]),
            "{at:?}"
        );
    }

    /// A shape-based reach reports both ways it can fail, since "no candidate"
    /// and "more than one" call for opposite fixes.
    #[test]
    fn test_a_failed_shape_walk_separates_absence_from_ambiguity() {
        let mut reader = DwReader::default();
        let holder = type_id(1);
        let word = type_id(2);
        let holder_name = reader.strings.intern("Holder");
        let u64_name = reader.strings.intern("u64");
        let first = reader.strings.intern("first");
        let second = reader.strings.intern("second");
        reader.types.insert(
            word,
            crate::raw_types::RawBase {
                name: Some(u64_name),
                namespace: None,
                size: 8,
                alignment: None,
                encoding: crate::Encoding::Unsigned,
            }
            .into(),
        );
        // Two words, both at offset zero, so a zero-offset walk sees both.
        reader.types.insert(
            holder,
            ns_struct(
                None,
                holder_name,
                8,
                vec![
                    RawMember {
                        name: Some(first),
                        offset: 0,
                        type_id: word,
                        source_loc: None,
                    },
                    RawMember {
                        name: Some(second),
                        offset: 0,
                        type_id: word,
                        source_loc: None,
                    },
                ],
            ),
        );

        let peel = |shape| {
            trace::capture(|| {
                Emitter::new(&reader, BTreeMap::new(), None, None)
                    .walk(holder, &reach![PeelTo(shape)])
            })
        };
        let (got, trace) = peel(Shape::Uint(POINTER_SIZE));
        assert!(got.is_none(), "two candidates must not resolve");
        assert!(
            trace[0].contains("candidates") && trace[0].contains("Holder"),
            "{}",
            trace[0]
        );
        // The walk says what it was after, since "nothing" and "several" read
        // the same without it.
        assert!(
            trace[1].contains("no single a 8-byte unsigned integer"),
            "{}",
            trace[1]
        );

        // Nothing of that width is there at all.
        let (got, trace) = peel(Shape::Uint(2));
        assert!(got.is_none());
        assert!(trace[0].contains("found nothing matching"), "{}", trace[0]);
    }

    /// A base type, for a test that cares what a member's shape is.
    fn base(name: crate::StrId, size: u64, encoding: Encoding) -> RawType<crate::StrId> {
        RawBase {
            name: Some(name),
            namespace: None,
            size,
            encoding,
            alignment: None,
        }
        .into()
    }

    /// A fat pointer laid out like `&str`, with `length` given whatever type
    /// the caller wants to test the addressing contract against.
    fn fat_pointer(
        name: crate::StrId,
        data_ptr: crate::StrId,
        pointer_id: TypeId,
        length: crate::StrId,
        length_id: TypeId,
    ) -> RawType<crate::StrId> {
        let member = |name, type_id, offset| RawMember {
            name: Some(name),
            offset,
            type_id,
            source_loc: None,
        };
        ns_struct(
            None,
            name,
            16,
            vec![
                member(data_ptr, pointer_id, 0),
                member(length, length_id, 8),
            ],
        )
    }

    #[test]
    fn test_a_node_addressing_the_wrong_shape_declines() {
        let mut reader = DwReader::default();
        let (data_ptr, length) = (
            reader.strings.intern("data_ptr"),
            reader.strings.intern("length"),
        );

        let byte_id = type_id(1);
        let pointer_id = type_id(2);
        let usize_id = type_id(3);
        let float_id = type_id(4);
        let good_id = type_id(5);
        let bad_id = type_id(6);
        let byte_name = reader.strings.intern("u8");
        let usize_name = reader.strings.intern("usize");
        let float_name = reader.strings.intern("f64");
        let good_name = reader.strings.intern("&str");
        let bad_name = reader.strings.intern("&str");
        reader
            .types
            .insert(byte_id, base(byte_name, 1, Encoding::Unsigned));
        reader.types.insert(
            pointer_id,
            RawPointer {
                name: None,
                target_type_id: byte_id,
            }
            .into(),
        );
        reader
            .types
            .insert(usize_id, base(usize_name, POINTER_SIZE, Encoding::Unsigned));
        reader
            .types
            .insert(float_id, base(float_name, 8, Encoding::Float));
        reader.types.insert(
            good_id,
            fat_pointer(good_name, data_ptr, pointer_id, length, usize_id),
        );
        // Same layout, but the length is a float rather than a `usize`.
        reader.types.insert(
            bad_id,
            fat_pointer(bad_name, data_ptr, pointer_id, length, float_id),
        );

        let format_of = |reader: &DwReader<'_>, id| {
            Emitter::new(reader, BTreeMap::new(), None, None).debug_format_of(id, Some("&str"))
        };
        assert!(matches!(
            format_of(&reader, good_id),
            Some(DisplayNode::Str { .. })
        ));
        // `str_node` itself no longer looks at the length: the `Str` node
        // requires a `usize` there, and the shared shape table is what holds
        // the detector to it.
        assert!(detect(&reader, str_node, bad_id).is_some());
        assert_eq!(format_of(&reader, bad_id), None);
    }

    /// A `uuid::Uuid`-shaped newtype over `[u8; count]`, so a test can vary the
    /// one thing the notation cares about.
    #[test]
    fn test_a_uuid_is_recognized_only_at_sixteen_bytes() {
        for (count, expected) in [(16, true), (8, false), (4, false)] {
            let mut reader = DwReader::default();
            let m0 = reader.strings.intern("__0");
            let byte_name = reader.strings.intern("u8");
            let uuid_name = reader.strings.intern("Uuid");
            let (byte, array, uuid) = (type_id(1), type_id(2), type_id(3));
            reader
                .types
                .insert(byte, base(byte_name, 1, Encoding::Unsigned));
            reader.types.insert(
                array,
                crate::raw_types::RawArray {
                    elem_type_id: byte,
                    count,
                }
                .into(),
            );
            reader.types.insert(
                uuid,
                ns_struct(
                    None,
                    uuid_name,
                    count,
                    vec![RawMember {
                        name: Some(m0),
                        offset: 0,
                        type_id: array,
                        source_loc: None,
                    }],
                ),
            );

            let got = detect_by_name(&reader, uuid, "uuid::Uuid");
            assert_eq!(
                got.is_some(),
                expected,
                "a {count}-byte newtype should{} be a UUID, got {got:?}",
                if expected { "" } else { " not" },
            );
            // Sixteen bytes is also an `Ipv6Addr`'s layout, so the notation is
            // the whole of what this detector decides.
            if expected {
                assert!(
                    matches!(
                        got,
                        Some(DisplayNode::Bytes {
                            notation: Notation::Uuid,
                            ..
                        })
                    ),
                    "{got:?}"
                );
            }
        }
    }

    /// Hex spells any run of bytes, so unlike a UUID its detector must accept
    /// every length — and still decline an empty array, which spells nothing.
    #[test]
    fn test_a_digest_is_hex_at_any_nonzero_length() {
        for (count, expected) in [(32, true), (20, true), (1, true), (0, false)] {
            let mut reader = DwReader::default();
            let m0 = reader.strings.intern("__0");
            let byte_name = reader.strings.intern("u8");
            let hash_name = reader.strings.intern("ArtifactHash");
            let (byte, array, hash) = (type_id(1), type_id(2), type_id(3));
            reader
                .types
                .insert(byte, base(byte_name, 1, Encoding::Unsigned));
            reader.types.insert(
                array,
                crate::raw_types::RawArray {
                    elem_type_id: byte,
                    count,
                }
                .into(),
            );
            reader.types.insert(
                hash,
                ns_struct(
                    None,
                    hash_name,
                    count,
                    vec![RawMember {
                        name: Some(m0),
                        offset: 0,
                        type_id: array,
                        source_loc: None,
                    }],
                ),
            );

            let got = detect_by_name(&reader, hash, "tufaceous_artifact::artifact::ArtifactHash");
            assert_eq!(
                got.is_some(),
                expected,
                "a {count}-byte digest should{} render as hex, got {got:?}",
                if expected { "" } else { " not" },
            );
        }
    }

    fn ns_struct(
        namespace: Option<NsId>,
        name: crate::StrId,
        size: u64,
        members: Vec<RawMember<crate::StrId>>,
    ) -> RawType<crate::StrId> {
        RawStruct {
            name: Some(name),
            namespace,
            size,
            members: members.into_boxed_slice(),
            template_params: Box::new([]),
            source_loc: None,
        }
        .into()
    }

    #[test]
    fn test_loom_parking_lot_mutex_is_transparent_over_inner_lock() {
        let mut reader = DwReader::default();

        // Namespaces: tokio::loom::std::parking_lot and core::marker.
        let mut ns = None;
        for seg in ["tokio", "loom", "std", "parking_lot"] {
            let name = reader.strings.intern(seg);
            ns = Some(reader.namespaces.insert(ns, name));
        }
        let parking_lot = ns.unwrap();
        let core = {
            let name = reader.strings.intern("core");
            reader.namespaces.insert(None, name)
        };
        let marker = {
            let name = reader.strings.intern("marker");
            reader.namespaces.insert(Some(core), name)
        };

        let (m0, m1) = (reader.strings.intern("__0"), reader.strings.intern("__1"));
        let phantom_name = reader.strings.intern("PhantomData<std::sync::Mutex<T>>");
        let inner_name = reader
            .strings
            .intern("lock_api::mutex::Mutex<parking_lot::raw_mutex::RawMutex, T>");
        let mutex_name = reader.strings.intern("Mutex<T>");
        let member = |name, type_id, offset| RawMember {
            name: Some(name),
            offset,
            type_id,
            source_loc: None,
        };

        let phantom_id = type_id(1);
        let inner_id = type_id(2);
        let mutex_id = type_id(3);
        let phantom = ns_struct(Some(marker), phantom_name, 0, vec![]);
        let inner = ns_struct(None, inner_name, 80, vec![]);
        let mutex = ns_struct(
            Some(parking_lot),
            mutex_name,
            80,
            vec![member(m0, phantom_id, 0), member(m1, inner_id, 0)],
        );
        reader.types.insert(phantom_id, phantom);
        reader.types.insert(inner_id, inner);
        reader.types.insert(mutex_id, mutex);

        // The PhantomData marker is skipped; the shim is transparent over the
        // real lock at member index 1.
        assert_eq!(
            detect_alias_by_name(&reader, mutex_id, "tokio::loom::std::parking_lot::Mutex<T>")
                .as_deref(),
            Some("__1")
        );
        // The namespace is the dispatch table's screen: the same layout under a
        // name outside the loom shims reaches no detector.
        assert_eq!(
            detect_by_name(
                &reader,
                mutex_id,
                "lock_api::mutex::Mutex<parking_lot::raw_mutex::RawMutex, T>"
            ),
            None
        );
    }

    #[test]
    fn test_nonzero_layers_are_transparent_over_the_integer() {
        use crate::raw_types::{Encoding, RawBase};

        let mut reader = DwReader::default();

        let mut core_num = None;
        for seg in ["core", "num"] {
            let name = reader.strings.intern(seg);
            core_num = Some(reader.namespaces.insert(core_num, name));
        }
        let nonzero_ns = {
            let name = reader.strings.intern("nonzero");
            reader.namespaces.insert(core_num, name)
        };
        let niche_ns = {
            let name = reader.strings.intern("niche_types");
            reader.namespaces.insert(core_num, name)
        };

        let m0 = reader.strings.intern("__0");
        let member = |type_id| RawMember {
            name: Some(m0),
            offset: 0,
            type_id,
            source_loc: None,
        };

        // Exercise a signed width too, to confirm the match is not u64-only.
        let int_id = type_id(1);
        let inner_id = type_id(2);
        let nonzero_id = type_id(3);
        let int_name = reader.strings.intern("i32");
        let inner_name = reader.strings.intern("NonZeroI32Inner");
        let nonzero_name = reader.strings.intern("NonZero<i32>");
        reader.types.insert(
            int_id,
            RawBase {
                name: Some(int_name),
                namespace: None,
                encoding: Encoding::Signed,
                size: 4,
                alignment: None,
            }
            .into(),
        );
        reader.types.insert(
            inner_id,
            ns_struct(Some(niche_ns), inner_name, 4, vec![member(int_id)]),
        );
        reader.types.insert(
            nonzero_id,
            ns_struct(Some(nonzero_ns), nonzero_name, 4, vec![member(inner_id)]),
        );

        assert_eq!(
            detect_alias_by_name(&reader, nonzero_id, "core::num::nonzero::NonZero<i32>")
                .as_deref(),
            Some("__0")
        );
        assert_eq!(
            detect_alias_by_name(&reader, inner_id, "core::num::niche_types::NonZeroI32Inner")
                .as_deref(),
            Some("__0")
        );

        // The niche-types row is keyed by prefix, so it is offered every
        // `NonZero*` in that module; only the `*Inner` wrappers are transparent
        // over an integer, and one that is not is left alone.
        let bare_id = type_id(4);
        let bare_name = reader.strings.intern("NonZeroU32");
        reader.types.insert(
            bare_id,
            ns_struct(Some(niche_ns), bare_name, 4, vec![member(int_id)]),
        );
        assert_eq!(
            detect_by_name(&reader, bare_id, "core::num::niche_types::NonZeroU32"),
            None
        );
    }

    #[test]
    fn test_scalar_newtype_is_transparent_over_its_value() {
        use crate::raw_types::{Encoding, RawBase};

        let mut reader = DwReader::default();
        let u64n = reader.strings.intern("u64");
        let u64_id = type_id(1);
        reader.types.insert(
            u64_id,
            RawBase {
                name: Some(u64n),
                namespace: None,
                encoding: Encoding::Unsigned,
                size: 8,
                alignment: None,
            }
            .into(),
        );
        let (m0, m1) = (reader.strings.intern("__0"), reader.strings.intern("__1"));
        let member = |name, type_id, offset| RawMember {
            name: Some(name),
            offset,
            type_id,
            source_loc: None,
        };

        // A tuple newtype over a scalar is transparent over its field.
        let epochn = reader.strings.intern("Epoch");
        let epoch_id = type_id(2);
        reader.types.insert(
            epoch_id,
            ns_struct(None, epochn, 8, vec![member(m0, u64_id, 0)]),
        );
        assert_eq!(
            detect_alias(&reader, scalar_newtype_node, epoch_id).as_deref(),
            Some("__0")
        );

        // A pair is not a wrapper: the scalar does not fill the struct.
        let pairn = reader.strings.intern("Pair");
        let pair_id = type_id(3);
        reader.types.insert(
            pair_id,
            ns_struct(
                None,
                pairn,
                16,
                vec![member(m0, u64_id, 0), member(m1, u64_id, 8)],
            ),
        );
        assert_eq!(detect(&reader, scalar_newtype_node, pair_id), None);

        // Wrapping a non-scalar (a struct) is left alone.
        let wrapn = reader.strings.intern("Wrap");
        let wrap_id = type_id(4);
        reader.types.insert(
            wrap_id,
            ns_struct(None, wrapn, 8, vec![member(m0, epoch_id, 0)]),
        );
        assert_eq!(detect(&reader, scalar_newtype_node, wrap_id), None);
    }
}

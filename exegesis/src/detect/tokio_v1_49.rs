//! The timer detectors for tokio 1.49 through 1.52, where the alternative
//! timer arrived. The entry layout is unchanged from
//! [`super::tokio_v1_47`] — whose record builders this module reuses —
//! but the spellings around it moved: `Sleep`'s `entry` sits behind the
//! `Timer` flavor enum, crossed with a guarded `Traditional` step (an
//! unstable alternative-timer build degrades rather than misreads), and
//! the driver's `time::Inner` becomes an enum over the driver flavor.

use super::ReachStep::{ActiveVariant, Named, Variant};
use super::tokio_v1_47::{sleep_record, timer_entry_record};
use super::{Reach, reach};
use crate::TypeId;
use crate::bundle::DisplayNode;
use crate::extract::Emitter;

/// [`super::tokio_v1_47::timer_entry_node`]'s record over the flavored
/// `time::Inner`.
pub(super) fn timer_entry_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    timer_entry_record(emitter, id, true)
}

/// [`super::tokio_v1_47::sleep_node`]'s record, with the entry reached
/// through the `Timer` flavor enum.
pub(super) fn sleep_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let entry = reach![Named("entry"), Variant("Traditional"), Named("__0")];
    sleep_record(emitter, id, &entry, true)
}

/// The walk contract's `Wheel.levels` spelling from this family on: the
/// shared chain, crossing the `time::Inner` flavor enum the alternative
/// timer added. 1.53 left the driver chain alone, so this spelling serves
/// it too — the dispatch row declares no entry of its own for it.
pub(super) fn wheel_levels_walk() -> Vec<Reach<'static>> {
    super::tokio::wheel_levels_walk(true)
}

/// The walk contract's `Sleep.deadline` spelling for this family: the
/// `Timer` enum over the two timer implementations arrived in 1.49, and
/// the walk takes whichever variant is live — both carry the cached
/// deadline `Instant`, peeled through std's newtype chain to the
/// `Timespec`. (The formatter above enters the `Traditional` variant by
/// name instead: a display selector may not take the active variant.)
pub(super) fn sleep_deadline_walk() -> Vec<Reach<'static>> {
    vec![reach![
        Named("entry"),
        ActiveVariant,
        Named("__0"),
        Named("deadline"),
        Named("std"),
        Named("__0"),
        Named("t"),
    ]]
}

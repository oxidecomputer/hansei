//! The timer detectors for tokio 1.49 through 1.52, where the alternative
//! timer arrived. The entry layout is unchanged from
//! [`super::tokio_v1_47`] — whose record builders this module reuses —
//! but the spellings around it moved: `Sleep`'s `entry` sits behind the
//! `Timer` flavor enum, crossed with a guarded `Traditional` step (an
//! unstable alternative-timer build degrades rather than misreads), and
//! the driver's `time::Inner` becomes an enum over the driver flavor.

use super::ReachStep::{Named, Variant};
use super::reach;
use super::tokio_v1_47::{sleep_record, timer_entry_record};
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

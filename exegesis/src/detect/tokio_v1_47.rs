//! The timer detectors for tokio 1.47 and 1.48: the `TimerEntry` that
//! keeps a `registered` flag and a cached `deadline` `Instant` beside its
//! lazily-registered `TimerShared`, the `Sleep` whose `entry` is that
//! `TimerEntry` bare, and the unflavored `time::Inner` behind the wheel
//! clock. tokio 1.49 kept the entry layout but wrapped `Sleep`'s entry in
//! the `Timer` flavor enum and flavored `time::Inner` — so the record
//! builders here are shared with [`super::tokio_v1_49`], which supplies
//! its own spellings; tokio 1.53 restructured the entry itself, which is
//! why all of this lives apart from the invariant tokio detectors.

use super::ReachStep::{Named, PeelTo, Variant};
use super::tokio::wheel_elapsed;
use super::{Reach, WORD, reach};
use crate::TypeId;
use crate::bundle::{Arm, DisplayNode, Field, ScalarDecode, ValueExpr};
use crate::extract::Emitter;

/// The `{ deadline, state }` pair a timer renders as. `state` names where the
/// entry is in its life — `unregistered` (first poll pending), `registered`
/// (parked in the wheel), or `elapsed` (fired, not yet polled) — and
/// `deadline` is the wait remaining as a duration (`12.721s`) while
/// registered, falling back to the absolute deadline instant in the states
/// where no remaining wait is computable.
///
/// The entry's `StateCell` word holds the deadline as a *tick* (ms since the
/// runtime's `TimeSource` epoch), or `u64::MAX` once the driver has fired
/// it; the driver's wheel keeps its own clock in the same unit (`elapsed`,
/// advanced each time the wheel is processed). Their difference is the
/// remaining wait — computed from two reads of target memory, no host clock
/// involved, so it means the same thing against a live process and a core.
///
/// The wheel is reached through the entry's own scheduler handle
/// ([`wheel_elapsed`]); `flavored_inner` is the calling family's declaration
/// of the `time::Inner` spelling along that reach.
///
/// Every selector is rooted at `root` under `prefix` — empty for the
/// `TimerEntry` itself, the path down to the entry for the `Sleep` that
/// embeds one — so the two formatters share this one builder.
pub(super) fn timer_fields<'a>(
    emitter: &mut Emitter<'_>,
    root: TypeId,
    prefix: &Reach<'a>,
    flavored_inner: bool,
) -> Option<(DisplayNode, DisplayNode)> {
    let under = |tail: Reach<'a>| -> Reach<'a> {
        let mut path = prefix.clone();
        path.extend(tail);
        path
    };
    // The deadline tick, valid while the entry is registered.
    let tick = emitter
        .walk(
            root,
            &under(reach![
                Named("inner"),
                Variant("Some"),
                Named("__0"),
                Named("state"),
                Named("state"),
                PeelTo(WORD),
            ]),
        )?
        .0;
    // The wheel's clock, as of the driver's last tick.
    let now = wheel_elapsed(emitter, root, prefix, flavored_inner)?;
    let registered = emitter.walk(root, &under(reach![Named("registered")]))?.0;
    // The absolute instant, for the states with no computable remaining wait;
    // its own `Instant` alias formatters reduce it to the Timespec inside.
    let instant_at = emitter.walk(root, &under(reach![Named("deadline")]))?.0;
    let instant = || DisplayNode::Alias {
        at: instant_at.clone(),
        follow_pointers: true,
    };

    use ValueExpr::{Const, Read};
    let remaining = DisplayNode::Computed {
        value: Read(tick.clone()) - Read(now),
        decode: ScalarDecode::Millis,
    };
    let registered_read = || Read(registered.clone());
    let fired_test = || Read(tick.clone()).ne(Const(u64::MAX));
    let deadline = DisplayNode::Variant {
        discriminant: registered_read(),
        arms: vec![Arm::payload(0, instant())],
        default: Some(Box::new(DisplayNode::Variant {
            discriminant: fired_test(),
            arms: vec![Arm::payload(0, instant()), Arm::payload(1, remaining)],
            default: None,
        })),
    };
    let unregistered = emitter.label_arm(0, "unregistered");
    let elapsed = emitter.label_arm(0, "elapsed");
    let parked = emitter.label_arm(1, "registered");
    let state = DisplayNode::Variant {
        discriminant: registered_read(),
        arms: vec![unregistered],
        default: Some(Box::new(DisplayNode::Variant {
            discriminant: fired_test(),
            arms: vec![elapsed, parked],
            default: None,
        })),
    };
    Some((deadline, state))
}

/// A `tokio::runtime::time::entry::TimerEntry` renders as `TimerEntry {
/// deadline: 12.721s, state: registered }` — the real `deadline` member under
/// its own name with its value computed by [`timer_fields`], and the state
/// synthesized beside it. Shared by the two families whose entry this is.
pub(super) fn timer_entry_record(
    emitter: &mut Emitter<'_>,
    id: TypeId,
    flavored_inner: bool,
) -> Option<DisplayNode> {
    let (deadline, state) = timer_fields(emitter, id, &reach![], flavored_inner)?;
    Some(DisplayNode::Struct {
        fields: vec![
            Field::computed(emitter.member_named(id, "deadline")?, deadline),
            Field::Synth {
                label: emitter.intern("state"),
                node: state,
            },
        ],
    })
}

pub(super) fn timer_entry_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    timer_entry_record(emitter, id, false)
}

/// A `tokio::time::sleep::Sleep` is a `TimerEntry` and nothing else, so it
/// renders as the same `{ deadline, state }` record with the wrapper levels
/// flattened away. `entry` is the calling family's path down to the entry.
pub(super) fn sleep_record(
    emitter: &mut Emitter<'_>,
    id: TypeId,
    entry: &Reach<'_>,
    flavored_inner: bool,
) -> Option<DisplayNode> {
    let (deadline, state) = timer_fields(emitter, id, entry, flavored_inner)?;
    Some(DisplayNode::Struct {
        fields: vec![
            Field::Synth {
                label: emitter.intern("deadline"),
                node: deadline,
            },
            Field::Synth {
                label: emitter.intern("state"),
                node: state,
            },
        ],
    })
}

pub(super) fn sleep_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    sleep_record(emitter, id, &reach![Named("entry")], false)
}

/// The walk contract's `Wheel.levels` spelling for this family: the
/// shared chain over the unflavored `time::Inner` this family's releases
/// still spell as a plain struct.
pub(super) fn wheel_levels_walk() -> Vec<Reach<'static>> {
    super::tokio::wheel_levels_walk(false)
}

/// The walk contract's `Sleep.deadline` spelling for this family: `Sleep`'s
/// `entry` is the `TimerEntry` bare, and the deadline `Instant` it caches
/// peels through std's newtype chain to the `Timespec` inside. (tokio 1.49
/// put the entry behind the `Timer` flavor enum; 1.53 moved the deadline
/// onto the `Sleep` itself.)
pub(super) fn sleep_deadline_walk() -> Vec<Reach<'static>> {
    vec![reach![
        Named("entry"),
        Named("deadline"),
        Named("std"),
        Named("__0"),
        Named("t"),
    ]]
}

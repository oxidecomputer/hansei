// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `v1_53` timer family. tokio 1.53 restructured the timer: the entry
//! holds its `TimerShared` directly — the `registered` flag and the cached
//! `deadline` `Instant` are gone — and registration collapsed into the
//! state word, with the cached registration tick beside it. `Sleep` keeps
//! the deadline itself and creates its entry on first poll, behind an
//! `Option<runtime::Timer>`.

use super::ReachStep::{Named, PeelTo, Variant};
use super::tokio::wheel_elapsed;
use super::{Reach, WORD, reach};
use crate::TypeId;
use crate::bundle::tokio::timer::{PENDING_FIRE, REGISTERED, STATE_DEREGISTERED, STATE_MIN_VALUE};
use crate::bundle::{Arm, DisplayNode, Field, ScalarDecode, ValueExpr};
use crate::extract::Emitter;

/// The `{ deadline, state }` pair a 1.53 timer renders as — the same record
/// the earlier family produces, decoded from the restructured words.
/// `state` names where the entry is in its life — `unregistered` (first
/// poll pending), `registered` (parked in the wheel), `pending fire` (the
/// driver has marked it to fire and not yet delivered the wakeup) or
/// `elapsed` (fired, not yet polled) — and `deadline` is the wait remaining
/// as a duration (`12.721s`) while registered, falling back to `absolute`
/// where no remaining wait is computable.
///
/// The entry's `StateCell` word *is* the registration state: the deadline
/// tick (ms since the runtime's `TimeSource` epoch) while the entry sits in
/// the wheel, and one of tokio's sentinels at or above `STATE_MIN_VALUE`
/// otherwise — `STATE_PENDING_FIRE` between the driver's `mark_pending` and
/// its `fire`, `STATE_DEREGISTERED` after. The tick test is tokio's own
/// `state < STATE_MIN_VALUE`, not a comparison with one sentinel: a sentinel
/// treated as a tick would print a plausible small negative wait.
/// `registered_when` beside it caches the registration tick — zero from the
/// constructor and kept after firing, so with the state word deregistered
/// it is what separates `unregistered` from `elapsed`. The wheel's own clock ([`wheel_elapsed`]) is in the same
/// unit, and the difference is the remaining wait — two reads of target
/// memory, no host clock, so it means the same thing against a live process
/// and a core.
///
/// Every selector is rooted at `root` under `prefix` — empty for the
/// `TimerEntry` itself, the path down through `Option<Timer>` for the
/// `Sleep` that lazily creates one — so the two formatters share this one
/// builder. `absolute` is the absolute deadline to fall back on: `Sleep`
/// keeps one as its own member, while the bare entry has none and labels
/// the state instead.
fn timer_fields<'a>(
    emitter: &mut Emitter<'_>,
    root: TypeId,
    prefix: &Reach<'a>,
    absolute: Option<DisplayNode>,
) -> Option<(DisplayNode, DisplayNode)> {
    let under = |tail: Reach<'a>| -> Reach<'a> {
        let mut path = prefix.clone();
        path.extend(tail);
        path
    };
    // The state word: the deadline tick while registered, a sentinel not.
    let tick = emitter
        .walk(
            root,
            &under(reach![
                Named("inner"),
                Named("state"),
                Named("state"),
                PeelTo(WORD),
            ]),
        )?
        .0;
    // The cached registration tick, `0` for a never-registered entry.
    let registered_when = emitter
        .walk(
            root,
            &under(reach![
                Named("inner"),
                Named("registered_when"),
                PeelTo(WORD)
            ]),
        )?
        .0;
    // The wheel's clock, as of the driver's last tick; `time::Inner` has
    // been flavored since 1.49.
    let now = wheel_elapsed(emitter, root, prefix, true)?;

    use ValueExpr::{Const, Read};
    // `1` while the word is a deadline tick, `0` for either sentinel.
    let tick_test = || Read(tick.clone()).lt(Const(STATE_MIN_VALUE));
    // Among the sentinels: `1` for pending fire, `0` for deregistered.
    let pending_test = || Read(tick.clone()).ne(Const(STATE_DEREGISTERED));
    let ever_registered = || Read(registered_when.clone()).ne(Const(0));
    let remaining = DisplayNode::Computed {
        value: Read(tick.clone()) - Read(now),
        decode: ScalarDecode::Millis,
    };
    // The state a sentinel word names: pending fire by the word itself,
    // otherwise whether the entry was ever in the wheel.
    let sentinel_state = |emitter: &mut Emitter<'_>| {
        let pending = emitter.label_arm(1, PENDING_FIRE);
        let unregistered = emitter.label_arm(0, "unregistered");
        let elapsed = emitter.label_arm(1, "elapsed");
        DisplayNode::Variant {
            discriminant: pending_test(),
            arms: vec![pending],
            default: Some(Box::new(DisplayNode::Variant {
                discriminant: ever_registered(),
                arms: vec![unregistered, elapsed],
                default: None,
            })),
        }
    };

    // With no tick in the word, fall back to the absolute deadline where
    // the caller has one, and to naming the state where it does not.
    let fallback = match absolute {
        Some(node) => node,
        None => sentinel_state(emitter),
    };
    let deadline = DisplayNode::Variant {
        discriminant: tick_test(),
        arms: vec![Arm::payload(1, remaining)],
        default: Some(Box::new(fallback)),
    };

    let parked = emitter.label_arm(1, REGISTERED);
    let state = DisplayNode::Variant {
        discriminant: tick_test(),
        arms: vec![parked],
        default: Some(Box::new(sentinel_state(emitter))),
    };
    Some((deadline, state))
}

/// A 1.53 `tokio::runtime::time::entry::TimerEntry` renders as `TimerEntry
/// { deadline: 12.721s, state: registered }`. Both fields are synthesized:
/// the entry no longer carries a deadline member of its own, so a
/// deregistered entry's `deadline` names the state (`unregistered`,
/// `elapsed`) instead of an instant.
pub(super) fn timer_entry_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let (deadline, state) = timer_fields(emitter, id, &reach![], None)?;
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

/// A 1.53 `tokio::time::sleep::Sleep` renders as the same `{ deadline,
/// state }` record, rooted across `timer`'s `Some` and `Traditional`
/// variants (guarded — an alternative-timer build degrades rather than
/// misreads). The sleep's own `deadline` member is always valid and is the
/// fallback wherever no remaining wait is computable; `timer` is `None`
/// until first poll, so on a never-polled sleep the entry-word reads — and
/// with them both computed fields — degrade to `<inactive variant>`.
pub(super) fn sleep_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let entry = reach![
        Named("timer"),
        Variant("Some"),
        Named("__0"),
        Variant("Traditional"),
        Named("__0")
    ];
    // The absolute deadline; its own `Instant` alias formatters reduce it
    // to the Timespec inside.
    let absolute = DisplayNode::Alias {
        at: emitter.walk(id, &reach![Named("deadline")])?.0,
        follow_pointers: true,
    };
    let (deadline, state) = timer_fields(emitter, id, &entry, Some(absolute))?;
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

/// The walk contract's `Sleep.deadline` spelling for this family: 1.53
/// moved the deadline out of the timer entry onto the `Sleep` itself, so
/// the walk reads it there — always valid, even before the entry exists —
/// peeled through std's newtype chain to the `Timespec`.
pub(super) fn sleep_deadline_walk() -> Vec<Reach<'static>> {
    vec![reach![
        Named("deadline"),
        Named("std"),
        Named("__0"),
        Named("t"),
    ]]
}

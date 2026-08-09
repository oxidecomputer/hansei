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
use crate::bundle::{Arm, DisplayNode, Field, ScalarDecode, ValueExpr};
use crate::extract::Emitter;

/// The `{ deadline, state }` pair a 1.53 timer renders as — the same record
/// the earlier family produces, decoded from the restructured words.
/// `state` names where the entry is in its life — `unregistered` (first
/// poll pending), `registered` (parked in the wheel), or `elapsed` (fired,
/// not yet polled) — and `deadline` is the wait remaining as a duration
/// (`12.721s`) while registered, falling back to `absolute` where no
/// remaining wait is computable.
///
/// The entry's `StateCell` word *is* the registration state: the deadline
/// tick (ms since the runtime's `TimeSource` epoch) while the entry sits in
/// the wheel, `u64::MAX` otherwise. `registered_when` beside it caches the
/// registration tick — zero from the constructor and kept after firing, so
/// with the state word deregistered it is what separates `unregistered`
/// from `elapsed`. The wheel's own clock ([`wheel_elapsed`]) is in the same
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
    // The state word: the deadline tick while registered, `u64::MAX` not.
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
    // The wheel's clock, as of the driver's last tick.
    let now = wheel_elapsed(emitter, root, prefix)?;

    let registered_test = || {
        ValueExpr::Ne(
            Box::new(ValueExpr::Read(tick.clone())),
            Box::new(ValueExpr::Const(u64::MAX)),
        )
    };
    let ever_registered = || {
        ValueExpr::Ne(
            Box::new(ValueExpr::Read(registered_when.clone())),
            Box::new(ValueExpr::Const(0)),
        )
    };
    let remaining = Box::new(DisplayNode::Computed {
        value: ValueExpr::Sub(
            Box::new(ValueExpr::Read(tick.clone())),
            Box::new(ValueExpr::Read(now)),
        ),
        decode: ScalarDecode::Millis,
    });
    let payload_arm = |value, node: Box<DisplayNode>| Arm {
        value,
        label: None,
        payload: Some(node),
    };
    let label_arm = |emitter: &mut Emitter<'_>, value, label: &str| Arm {
        value,
        label: Some(emitter.intern(label)),
        payload: None,
    };

    // With the entry deregistered, fall back to the absolute deadline where
    // the caller has one, and to naming the state where it does not.
    let fallback = match absolute {
        Some(node) => Box::new(node),
        None => {
            let unregistered = label_arm(emitter, 0, "unregistered");
            let elapsed = label_arm(emitter, 1, "elapsed");
            Box::new(DisplayNode::Variant {
                discriminant: ever_registered(),
                arms: vec![unregistered, elapsed],
                default: None,
            })
        }
    };
    let deadline = DisplayNode::Variant {
        discriminant: registered_test(),
        arms: vec![payload_arm(1, remaining)],
        default: Some(fallback),
    };

    let unregistered = label_arm(emitter, 0, "unregistered");
    let elapsed = label_arm(emitter, 1, "elapsed");
    let parked = label_arm(emitter, 1, "registered");
    let state = DisplayNode::Variant {
        discriminant: registered_test(),
        arms: vec![parked],
        default: Some(Box::new(DisplayNode::Variant {
            discriminant: ever_registered(),
            arms: vec![unregistered, elapsed],
            default: None,
        })),
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

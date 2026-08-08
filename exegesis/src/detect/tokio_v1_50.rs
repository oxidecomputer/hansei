//! The timer detectors for the tokio range this tree supports: the
//! `TimerEntry` that keeps a `registered` flag and a cached `deadline`
//! `Instant` beside its lazily-registered `TimerShared`, and the `Sleep`
//! that wraps one behind the `Timer` enum. tokio 1.53 restructured all of
//! this, which is why these live apart from the invariant tokio
//! detectors.

use super::ReachStep::{Deref, FindParam, Named, PeelTo, Variant};
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
/// The wheel is reached *through the entry's own scheduler handle*: driver →
/// the `MultiThread` variant's `Arc` → the runtime's `driver::Handle` → the
/// time handle → the `Traditional` driver's mutex-guarded `InnerState`. Every
/// enum on that path is crossed with a guarded variant step, so a
/// current-thread runtime (or an alternative timer) degrades the field to
/// `<inactive variant>` rather than misreading; the mutex is not taken, the
/// usual torn-read caveat for a live target.
///
/// Every selector is rooted at `root` under `prefix` — empty for the
/// `TimerEntry` itself, the path down through the `Timer` enum for the
/// `Sleep` that embeds one — so the two formatters share this one builder.
pub(super) fn timer_fields<'a>(
    emitter: &mut Emitter<'_>,
    root: TypeId,
    prefix: &Reach<'a>,
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
    // The wheel's clock, as of the driver's last tick. `time` is an
    // `Option<time::Handle>` (`None` only for a runtime built without a time
    // driver) and the mutex spelling varies by feature set, so the guarded
    // steps and the parameter search do the navigating.
    let now = emitter
        .walk(
            root,
            &under(reach![
                Named("driver"),
                Variant("MultiThread"),
                Named("__0"),
                Named("ptr"),
                Named("pointer"),
                Deref,
                Named("data"),
                Named("driver"),
                Named("time"),
                Variant("Some"),
                Named("__0"),
                Named("inner"),
                Variant("Traditional"),
                Named("state"),
                FindParam,
                Named("wheel"),
                Named("elapsed"),
            ]),
        )?
        .0;
    let registered = emitter.walk(root, &under(reach![Named("registered")]))?.0;
    // The absolute instant, for the states with no computable remaining wait;
    // its own `Instant` alias formatters reduce it to the Timespec inside.
    let instant_at = emitter.walk(root, &under(reach![Named("deadline")]))?.0;
    let instant = || {
        Box::new(DisplayNode::Alias {
            at: instant_at.clone(),
            follow_pointers: true,
        })
    };
    let instant_arm = |value, node: Box<DisplayNode>| Arm {
        value,
        label: None,
        payload: Some(node),
    };

    let remaining = Box::new(DisplayNode::Computed {
        value: ValueExpr::Sub(
            Box::new(ValueExpr::Read(tick.clone())),
            Box::new(ValueExpr::Read(now)),
        ),
        decode: ScalarDecode::Millis,
    });
    let registered_read = || ValueExpr::Read(registered.clone());
    let fired_test = || {
        ValueExpr::Ne(
            Box::new(ValueExpr::Read(tick.clone())),
            Box::new(ValueExpr::Const(u64::MAX)),
        )
    };
    let deadline = DisplayNode::Variant {
        discriminant: registered_read(),
        arms: vec![instant_arm(0, instant())],
        default: Some(Box::new(DisplayNode::Variant {
            discriminant: fired_test(),
            arms: vec![instant_arm(0, instant()), instant_arm(1, remaining)],
            default: None,
        })),
    };
    let label_arm = |emitter: &mut Emitter<'_>, value, label: &str| Arm {
        value,
        label: Some(emitter.intern(label)),
        payload: None,
    };
    let unregistered = label_arm(emitter, 0, "unregistered");
    let elapsed = label_arm(emitter, 0, "elapsed");
    let parked = label_arm(emitter, 1, "registered");
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
/// synthesized beside it.
pub(super) fn timer_entry_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let (deadline, state) = timer_fields(emitter, id, &reach![])?;
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

/// A `tokio::time::sleep::Sleep` is a `Timer` enum around a `TimerEntry` and
/// nothing else, so it renders as the same `{ deadline, state }` record with
/// the wrapper levels flattened away: the selectors are rooted at the `Sleep`
/// and cross the `Timer`'s `Traditional` variant (guarded — an unstable
/// alternative-timer build degrades rather than misreads).
pub(super) fn sleep_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let entry = reach![Named("entry"), Variant("Traditional"), Named("__0")];
    let (deadline, state) = timer_fields(emitter, id, &entry)?;
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

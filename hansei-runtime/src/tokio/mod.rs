// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tokio types loaded from an exegesis bundle.
//!
//! What is modelled here is only what the bundle walk cannot read
//! straight out of the target: a task's state word, whose bit meanings
//! rustc const-folds away and DWARF therefore never records, and the
//! few shapes the walk hands back to its callers. Everything else the
//! runtime holds is read through the bundle's own layouts, so it needs
//! no mirror struct here to be described.

pub mod bundle;
pub mod census;
pub mod contract;
pub mod graph;
mod model;
pub mod stackjoin;

use std::fmt;
use std::mem;
use std::time::Instant;

/// The address of a task's `Header`, which is the identity of a task
/// before its id has been read.
// TODO non-zero? Validate mapping?
#[derive(Copy, Clone, PartialEq, PartialOrd, Ord, Hash, Eq)]
pub struct TaskAddr(pub u64);

impl fmt::Debug for TaskAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// A task's state word: lifecycle flags and a reference count, packed
/// into one atomic. The bit assignments are tokio's own, folded into
/// its code at compile time and so knowable only from its source.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct TaskState(pub u64);

impl TaskState {
    /// The task is currently being run.
    const RUNNING: u64 = 0b0001;
    /// The task is complete. Once set, never unset.
    const COMPLETE: u64 = 0b0010;
    /// The task has been pushed into a run queue.
    const NOTIFIED: u64 = 0b100;
    /// The join handle is still around.
    const JOIN_INTEREST: u64 = 0b1_000;
    /// A join handle waker has been set.
    const JOIN_WAKER: u64 = 0b10_000;
    /// The task has been forcibly cancelled.
    const CANCELLED: u64 = 0b100_000;

    const STATE_MASK: u64 = Self::RUNNING
        | Self::COMPLETE
        | Self::NOTIFIED
        | Self::JOIN_INTEREST
        | Self::JOIN_WAKER
        | Self::CANCELLED;
    const REF_COUNT_MASK: u64 = !Self::STATE_MASK;
    const REF_COUNT_SHIFT: u64 = Self::REF_COUNT_MASK.count_zeros() as u64;

    pub fn is_running(&self) -> bool {
        self.0 & Self::RUNNING != 0
    }

    pub fn is_complete(&self) -> bool {
        self.0 & Self::COMPLETE != 0
    }

    pub fn is_notified(&self) -> bool {
        self.0 & Self::NOTIFIED != 0
    }

    pub fn is_cancelled(&self) -> bool {
        self.0 & Self::CANCELLED != 0
    }

    pub fn is_join_interested(&self) -> bool {
        self.0 & Self::JOIN_INTEREST != 0
    }

    pub fn is_join_waker_set(&self) -> bool {
        self.0 & Self::JOIN_WAKER != 0
    }

    pub fn ref_count(&self) -> u64 {
        (self.0 & Self::REF_COUNT_MASK) >> Self::REF_COUNT_SHIFT
    }

    /// Derived lifecycle classification. `COMPLETE` wins over
    /// `RUNNING` (the final poll sets both until the ref is dropped), and
    /// `NOTIFIED` only matters while the task is idle.
    pub fn lifecycle(&self) -> Lifecycle {
        if self.is_complete() {
            Lifecycle::Complete
        } else if self.is_running() {
            Lifecycle::Running
        } else if self.is_notified() {
            Lifecycle::Queued
        } else {
            Lifecycle::Idle
        }
    }
}

impl fmt::Debug for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskState")
            .field("lifecycle", &self.lifecycle())
            .field("ref_count", &self.ref_count())
            .field("is_cancelled", &self.is_cancelled())
            .field("is_join_interested", &self.is_join_interested())
            .field("is_join_waker_set", &self.is_join_waker_set())
            .field("bits", &format_args!("{:#b}", self.0))
            .finish()
    }
}

/// What a task is doing right now, derived from its state bits.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Lifecycle {
    /// Mid-poll on some worker thread.
    Running,
    /// Notified while idle: sitting in a run queue, not yet picked up.
    Queued,
    /// Suspended, waiting on a waker.
    Idle,
    /// Finished: returned, panicked, or cancelled.
    Complete,
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            Self::Running => "running",
            Self::Queued => "queued",
            Self::Idle => "idle",
            Self::Complete => "complete",
        };
        f.write_str(desc)
    }
}

/// Where a task was spawned, as `core::panic::Location` records it —
/// with the build machine's path prefix already cut off
/// (`hansei_bundle::strip_build_prefix`), so the file is spelled the way
/// a bundle spells the same file.
#[derive(Clone, PartialEq, Debug)]
pub struct Location {
    pub filename: String,
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.filename, self.line, self.col)
    }
}

/// Must match the layout of `tokio::time::Instant`.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct RawInstant {
    pub tv_sec: u64,
    pub tv_nsec: u32,
}

impl TryFrom<proc::Timespec> for RawInstant {
    type Error = anyhow::Error;

    fn try_from(value: proc::Timespec) -> std::result::Result<Self, Self::Error> {
        const NSEC_PER_SEC: i64 = 1_000_000_000;
        if value.tv_nsec < 0 || value.tv_nsec >= NSEC_PER_SEC {
            anyhow::bail!("invalid process timestamp {value:?}");
        }

        Ok(Self {
            tv_sec: value.tv_sec as u64,
            tv_nsec: value.tv_nsec as u32,
        })
    }
}

impl From<RawInstant> for Instant {
    fn from(value: RawInstant) -> Self {
        assert_eq!(size_of::<RawInstant>(), size_of::<Instant>());

        // SAFETY: RawInstant has the same layout as the underlying `Timespec`
        // used by `tokio::time::Instant`, we hope.
        unsafe { mem::transmute(value) }
    }
}

#[cfg(test)]
mod tests {
    use super::bundle::WaitTarget;
    use super::{Lifecycle, RawInstant, TaskState};

    const RUNNING: u64 = 0b0001;
    const COMPLETE: u64 = 0b0010;
    const NOTIFIED: u64 = 0b100;
    const JOIN_INTEREST: u64 = 0b1_000;
    const JOIN_WAKER: u64 = 0b10_000;
    const CANCELLED: u64 = 0b100_000;
    const REF_ONE: u64 = 1 << 6;

    /// Every lifecycle classification, including tokio's
    /// INITIAL_STATE (0xCC: ref count 3, NOTIFIED | JOIN_INTEREST) and
    /// concurrently-set flag combinations.
    #[test]
    fn test_lifecycle_classification() {
        let cases: &[(u64, Lifecycle)] = &[
            // INITIAL_STATE: freshly spawned, queued for its first poll.
            (0xCC, Lifecycle::Queued),
            (2 * REF_ONE, Lifecycle::Idle),
            ((2 * REF_ONE) | JOIN_INTEREST | JOIN_WAKER, Lifecycle::Idle),
            ((2 * REF_ONE) | NOTIFIED, Lifecycle::Queued),
            ((2 * REF_ONE) | RUNNING, Lifecycle::Running),
            // Woken again while mid-poll: still running.
            ((2 * REF_ONE) | RUNNING | NOTIFIED, Lifecycle::Running),
            (REF_ONE | COMPLETE, Lifecycle::Complete),
            // The final poll sets COMPLETE while RUNNING is still set.
            (REF_ONE | COMPLETE | RUNNING, Lifecycle::Complete),
            (REF_ONE | COMPLETE | CANCELLED, Lifecycle::Complete),
            // Cancelled but not yet complete: still waiting to be polled.
            ((2 * REF_ONE) | NOTIFIED | CANCELLED, Lifecycle::Queued),
        ];
        for &(bits, expected) in cases {
            let state = TaskState(bits);
            assert_eq!(state.lifecycle(), expected, "state bits {bits:#b}");
        }
    }

    #[test]
    fn test_state_flags_and_ref_count() {
        let initial = TaskState(0xCC);
        assert_eq!(initial.ref_count(), 3);
        assert!(initial.is_notified());
        assert!(initial.is_join_interested());
        assert!(!initial.is_running());
        assert!(!initial.is_complete());
        assert!(!initial.is_cancelled());
        assert!(!initial.is_join_waker_set());

        let state = TaskState((5 * REF_ONE) | RUNNING | JOIN_WAKER | CANCELLED);
        assert_eq!(state.ref_count(), 5);
        assert!(state.is_running());
        assert!(state.is_join_waker_set());
        assert!(state.is_cancelled());
        assert!(!state.is_notified());
        assert!(!state.is_join_interested());

        // A word that is only the tested bit still answers true — the
        // case that separates a mask test from an xor.
        assert!(TaskState(JOIN_INTEREST).is_join_interested());
    }

    /// The debug form spells out the derived fields — it is what a
    /// value dump of a task's Header shows.
    #[test]
    fn test_task_state_debug_names_the_fields() {
        let dbg = format!("{:?}", TaskState(0xCC));
        for needle in [
            "lifecycle: Queued",
            "ref_count: 3",
            "is_cancelled: false",
            "is_join_interested: true",
            "is_join_waker_set: false",
            "bits: 0b11001100",
        ] {
            assert!(dbg.contains(needle), "{needle} not in {dbg}");
        }
    }

    /// The timespec validation: nanoseconds must lie in [0, 1s), with
    /// both boundaries valid and either side out refused.
    #[test]
    fn test_raw_instant_rejects_invalid_timespecs() {
        let convert = |tv_sec, tv_nsec| RawInstant::try_from(proc::Timespec { tv_sec, tv_nsec });
        assert_eq!(
            convert(1, 0).unwrap(),
            RawInstant {
                tv_sec: 1,
                tv_nsec: 0
            }
        );
        assert_eq!(
            convert(1, 999_999_999).unwrap(),
            RawInstant {
                tv_sec: 1,
                tv_nsec: 999_999_999
            }
        );
        assert!(convert(1, -1).is_err());
        assert!(convert(1, 1_000_000_000).is_err());
    }

    /// Both spellings of a timer deadline. Which one a real target gets
    /// depends on whether its lwps stamp a stop time — illumos does,
    /// a Linux core does not — so the acceptance suite cannot pin
    /// either; this covers both from constructed values instead.
    #[test]
    fn test_timer_deadline_spellings() {
        let at = |tv_sec, tv_nsec| RawInstant { tv_sec, tv_nsec };
        let timer = |deadline, stopped| WaitTarget::Timer { deadline, stopped }.to_string();

        // Relative to the stop: the wait remaining at the moment the
        // target was observed.
        assert_eq!(
            timer(at(1_042, 500_000_000), Some(at(1_030, 0))),
            "the timer: deadline 12.500s"
        );
        // A deadline already passed reads as a small negative duration,
        // never as a wrapped unsigned one.
        assert_eq!(
            timer(at(1_030, 0), Some(at(1_031, 250_000_000))),
            "the timer: deadline -1.250s"
        );
        // A deadline exactly at the stop is zero, not negative zero.
        assert_eq!(
            timer(at(1_030, 0), Some(at(1_030, 0))),
            "the timer: deadline 0.000s"
        );
        // With no stop time there is nothing to be relative to, so the
        // absolute point is reported with its clock spelled out.
        assert_eq!(
            timer(at(42, 7_000_000), None),
            "the timer: deadline 42.007s on the target's monotonic clock"
        );
    }
}

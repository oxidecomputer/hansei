// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! tokio constants that reach a target's memory only as values.
//!
//! These are `const` items in tokio, folded into its code at compile time,
//! so no DWARF names them: a reader knows them from tokio's source alone.
//! Both sides of the bundle decode them — exegesis writes them into
//! display programs, hansei-runtime matches raw words against them — and
//! a spelling that lives in one place is what keeps `print` and `tasks`
//! saying the same thing about one word.

/// The `TimerShared.state` word of a wheel entry
/// (`tokio::runtime::time::entry`). Below [`STATE_MIN_VALUE`] it is the
/// deadline tick; at or above it, one of the two sentinels.
pub mod timer {
    /// Fired or cancelled: not in the wheel.
    pub const STATE_DEREGISTERED: u64 = u64::MAX;
    /// Marked to fire by the driver (`mark_pending`), the wakeup not yet
    /// delivered (`fire`). Both happen under the driver lock inside one
    /// `process_at_time`, so only a capture during that call shows it.
    pub const STATE_PENDING_FIRE: u64 = STATE_DEREGISTERED - 1;
    /// Every word at or above this is a sentinel, not a tick; tokio's own
    /// check is `state < STATE_MIN_VALUE`.
    pub const STATE_MIN_VALUE: u64 = STATE_PENDING_FIRE;

    /// How the two states both layers name are spelled.
    pub const REGISTERED: &str = "registered";
    pub const PENDING_FIRE: &str = "pending fire";
}

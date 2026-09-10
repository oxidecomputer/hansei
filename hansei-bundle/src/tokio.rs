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

/// The `batch_semaphore::Semaphore` permits word, behind tokio's `Mutex`,
/// `RwLock`, `Semaphore` and the bounded mpsc channel.
pub mod semaphore {
    /// The low bit: set once the semaphore is closed.
    pub const CLOSED: u64 = 1;
    /// The available permit count occupies the bits above the closed bit.
    pub const PERMIT_SHIFT: u8 = 1;
}

/// The `sync::task::AtomicWaker` state word, which the bounded mpsc
/// channel keeps its receiver's waker behind.
pub mod atomic_waker {
    /// No registration or wake in progress: the waker cell is at rest.
    pub const WAITING: u64 = 0;
    /// A `register` is writing the cell.
    pub const REGISTERING: u64 = 0b01;
    /// A `wake` is taking the cell.
    pub const WAKING: u64 = 0b10;
}

/// The mpsc block list (`sync::mpsc::block`): a block's `ready_slots`
/// word packs one ready bit per slot below two flags.
pub mod mpsc {
    /// Slots per block.
    pub const BLOCK_CAP: u64 = 32;
    /// The slot at index `i` lives in the block whose `start_index`
    /// is `i` with these bits cleared.
    pub const BLOCK_MASK: u64 = !(BLOCK_CAP - 1);
    /// The offset within a block of slot `i`.
    pub const SLOT_MASK: u64 = BLOCK_CAP - 1;
    /// The block has been released by the sender side.
    pub const RELEASED: u64 = 1 << BLOCK_CAP;
    /// Every sender is gone: `Tx::close` claimed a slot in this block
    /// and set the flag instead of writing it.
    pub const TX_CLOSED: u64 = RELEASED << 1;
    /// The ready bits.
    pub const READY_MASK: u64 = RELEASED - 1;
}

/// `sync::notify::Notify`'s state word and a waiter's notification word.
pub mod notify {
    /// The low two bits of `Notify.state`: no waiters and no pending
    /// `notify_one`, waiters queued, or one `notify_one` stored for
    /// the next waiter.
    pub const EMPTY: u64 = 0;
    pub const WAITING: u64 = 1;
    pub const NOTIFIED: u64 = 2;
    pub const STATE_MASK: u64 = 0b11;
    /// The count of `notify_waiters` calls sits above the state bits.
    pub const CALLS_SHIFT: u8 = 2;

    /// A waiter's `notification` word: nothing yet, or which call
    /// notified it and unlinked its node.
    pub const NOTIFICATION_NONE: u64 = 0b000;
    pub const NOTIFICATION_ONE: u64 = 0b001;
    pub const NOTIFICATION_LAST: u64 = 0b101;
    pub const NOTIFICATION_ALL: u64 = 0b010;
}

/// `sync::watch::state::AtomicState`: the closed flag below the
/// published version.
pub mod watch {
    /// The sender side closed.
    pub const CLOSED: u64 = 1;
    /// The version counter occupies the bits above the closed bit.
    pub const VERSION_SHIFT: u8 = 1;
}

/// `sync::oneshot::Inner`'s state word: four independent bits. A
/// dropped `Sender` sets `VALUE_SENT` like a send does (`complete`),
/// with the value left `None`; a dropped or closed `Receiver` sets
/// `CLOSED`. The two task bits say which waker slots hold a waker.
pub mod oneshot {
    /// The receiver stored its waker in `rx_task`.
    pub const RX_TASK_SET: u64 = 0b0001;
    /// The sender completed: a value was sent, or the sender dropped.
    pub const VALUE_SENT: u64 = 0b0010;
    /// The receiver closed or dropped.
    pub const CLOSED: u64 = 0b0100;
    /// The sender stored its waker in `tx_task` (`poll_closed`).
    pub const TX_TASK_SET: u64 = 0b1000;
}

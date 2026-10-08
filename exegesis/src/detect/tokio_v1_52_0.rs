// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! tokio 1.52.0 alone: [`super::tokio_v1_49`]'s layouts but for the
//! blocking pool. 1.52.0 moved the pool's queue out of its `Shared` into
//! a `ShardedQueue` on its `Inner` — sixteen `Shard`s, each a
//! mutex-guarded `VecDeque` of tasks, which a spawn picks one of at
//! random — and 1.52.1 reverted it. Only the walks to the queue move;
//! each shard's `VecDeque` is the ring every other release keeps, read
//! by the same roles.

use super::ReachStep::{Deref, Named};
use super::{Reach, reach};

/// The walk contract's `blocking::ShardedQueue.shards` route: the
/// spawner's `Arc<Inner>`, then the `ShardedQueue` beside the pool's
/// `shared` mutex rather than inside it, and its inline array of shards.
pub(super) fn blocking_queue_shards_walk() -> Vec<Reach<'static>> {
    vec![reach![
        Named("blocking_spawner"),
        Named("inner"),
        Named("ptr"),
        Named("pointer"),
        Deref,
        Named("data"),
        Named("queue"),
        Named("shards"),
    ]]
}

/// The walk contract's `blocking::Shard.queue` route: a shard's
/// `VecDeque` behind tokio's loom mutex shim, whose member names vary
/// with the parking_lot feature within the release — the parking_lot
/// shim's `__1`, the std shim's `__0`, or a bare std `Mutex` — as the
/// pool's `Shared` mutex does.
pub(super) fn shard_queue_walk() -> Vec<Reach<'static>> {
    vec![
        reach![Named("queue"), Named("__1"), Named("data"), Named("value")],
        reach![Named("queue"), Named("__0"), Named("data"), Named("value")],
        reach![Named("queue"), Named("data"), Named("value")],
    ]
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! tokio 1.54 onward: [`super::tokio_v1_53`]'s layouts but for the
//! blocking pool. 1.54 replaced the pool's `shared` mutex with an
//! `InnerImpl` enum over two queue implementations, chosen per runtime
//! when it is built: `Locked`, one mutex-guarded `LockedInner` holding
//! the queue and the thread state, and `Sharded`, sixteen
//! mutex-guarded `Shard`s, each with a queue of its own, and a
//! `ShardedCoord` mutex holding the thread state. The sharded queue is
//! an unstable option, but `TOKIO_UNSTABLE_SHARDED_BLOCKING_QUEUE`
//! selects it in any build, so both variants are walked: each route
//! names its variant, and the variant a runtime did not choose reads
//! as inactive. Each queue is the `VecDeque` ring every other release
//! keeps, read by the same roles, and the thread state is one
//! `ThreadManagementState` in both.

use super::ReachStep::{Deref, Named, Variant};
use super::{Reach, reach};

/// The pool's `InnerImpl` variant `variant`, from a scheduler `Handle`:
/// the spawner's `Arc<Inner>`, then the enum, then the variant's one
/// payload.
fn pool_impl(variant: &'static str) -> Reach<'static> {
    reach![
        Named("blocking_spawner"),
        Named("inner"),
        Named("ptr"),
        Named("pointer"),
        Deref,
        Named("data"),
        Named("inner_impl"),
        Variant(variant),
        Named("__0"),
    ]
}

/// `prefix`, then the value tokio's loom mutex shim guards, then
/// `tail`. The shim's member names vary with the parking_lot feature
/// within the release — the parking_lot shim's `__1`, the std shim's
/// `__0`, or a bare std `Mutex` — as they do for every pool mutex.
fn guarded(prefix: Reach<'static>, tail: Reach<'static>) -> Vec<Reach<'static>> {
    [
        reach![Named("__1"), Named("data"), Named("value")],
        reach![Named("__0"), Named("data"), Named("value")],
        reach![Named("data"), Named("value")],
    ]
    .into_iter()
    .map(|shim| {
        let mut steps = prefix.clone();
        steps.extend(shim);
        steps.extend(tail.iter().cloned());
        steps
    })
    .collect()
}

/// The `Locked` pool's mutex, then `tail` in the `LockedInner` it guards.
fn locked(tail: Reach<'static>) -> Vec<Reach<'static>> {
    let mut prefix = pool_impl("Locked");
    prefix.push(Named("mutex"));
    guarded(prefix, tail)
}

/// The walk contract's `blocking::Shared.queue` route: the `Locked`
/// pool's one `VecDeque`.
pub(super) fn blocking_queue_walk() -> Vec<Reach<'static>> {
    locked(reach![Named("queue")])
}

/// The walk contract's `blocking::Shared.worker_threads` route: the
/// `Locked` pool's thread map, in the thread state beside its queue.
pub(super) fn worker_threads_walk() -> Vec<Reach<'static>> {
    locked(reach![Named("thread_mgmt_state"), Named("worker_threads")])
}

/// The walk contract's `blocking::ShardedQueue.shards` route: the
/// `Sharded` pool's inline array of mutex-guarded shards.
pub(super) fn blocking_queue_shards_walk() -> Vec<Reach<'static>> {
    let mut steps = pool_impl("Sharded");
    steps.push(Named("shards"));
    vec![steps]
}

/// The walk contract's `blocking::Shard.queue` route: from one element
/// of the shard array, the `Shard` its mutex guards and that shard's
/// `VecDeque`.
pub(super) fn shard_queue_walk() -> Vec<Reach<'static>> {
    guarded(Vec::new(), reach![Named("queue")])
}

/// The walk contract's `blocking::ShardedCoord.worker_threads` route:
/// the `Sharded` pool's thread map, in the thread state its
/// coordinator mutex guards.
pub(super) fn sharded_worker_threads_walk() -> Vec<Reach<'static>> {
    let mut prefix = pool_impl("Sharded");
    prefix.push(Named("coord"));
    guarded(
        prefix,
        reach![Named("thread_mgmt_state"), Named("worker_threads")],
    )
}

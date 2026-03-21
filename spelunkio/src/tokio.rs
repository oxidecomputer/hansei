// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Access to thread local tokio internals
//!
//! It's possible that these types may change in future versions of tokio.
//! Therefore we will need some sort of versioning strategy in the future.

use hansei_types::tokio::{Scheduler, ThreadCtx, TokioRuntime, WorkerState};

use crate::Dbg;
use anyhow::{Context, Result, anyhow, bail};
use debugdb::{load::Load, value::Struct};
use derive_more::Display;
use std::{collections::BTreeMap, fmt, time::Instant};

/// A newtype that always debug prints in hex.
#[derive(Clone, Copy)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:x}", self.0))
    }
}

/// A thread id read via libproc
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadId(u32);

/// Specific, fully qualified type names that we need to work with. We put these
/// in an enum for easy access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokioTypeName {
    // The `pthread_key_t` that is used to index into thread specific data. This
    // type is static and the key is the same for all threads.
    StaticContextPthreadKey,

    /// The tokio runtime context. This is what is pointed to by the thread
    /// specific data for each worker thread, and where all the tokio related
    /// information resides.
    RuntimeContext,
}

impl TokioTypeName {
    /// Return the fully qualified type name
    pub fn name(&self) -> &'static str {
        match self {
            TokioTypeName::StaticContextPthreadKey => {
                "tokio::runtime::context::CONTEXT::{closure#0}::VAL"
            }
            TokioTypeName::RuntimeContext => "tokio::runtime::context::Context",
        }
    }
}

// TODO: This assumes the process only has one tokio runtime and
// that it's a multi-threaded one.
pub fn load_tokio_runtime(dbg: &Dbg) -> Result<TokioRuntime> {
    let tokio_worker_threads = find_tokio_threads(dbg)?;
    let mut stacks = unwind::load_frames(&dbg.core)?;
    let mut workers = BTreeMap::new();
    let mut scheduler = None;

    for (tid, context_addr) in tokio_worker_threads {
        // Load the workers
        let ty = TokioTypeName::RuntimeContext;
        let (_, ty) =
            dbg.db.types_by_name(ty.name()).next().with_context(|| {
                format!("type does not exist: {}", ty.name())
            })?;
        let backtrace = stacks.remove(&tid.0);

        let runtime_context =
            Struct::from_state(dbg.segments(), context_addr.0, &dbg.db, ty)?;
        let thd_ctx = ThreadCtx::load(dbg, &runtime_context)?;
        workers.insert(tid.0, WorkerState { thd_ctx, backtrace });

        if scheduler.is_none() {
            scheduler =
                Some(Scheduler::load_from_context(dbg, &runtime_context)?);
        }
    }
    Ok(TokioRuntime {
        workers,
        scheduler: scheduler.unwrap(),
        // TODO: get the time from thread 1 in the core. I'm not sure this is
        // necessary for debugging. If anything maybe it should live elsewhere.
        now: Instant::now(),
    })
}

/// Look in thread local storage (tls) to find the address of each
/// `tokio::runtime::context::Context` for each light weight process (lwp).
///
/// Return a map of thread-id to pointers to `tokio::runtime::context::Context`.
pub fn find_tokio_threads(dbg: &Dbg) -> Result<BTreeMap<ThreadId, Addr>> {
    // Get the index into thread specific data that stores a
    // `tokio::runtime::context::Context`. This index is the same for each
    // thread.
    let tsd_index = get_pthread_key(dbg)?;

    // TODO: For now, we panic if `tsd_index` isn't in `ul_ftsd`
    //
    // In illumos there are up to 9 pointers stored in a "fast thread
    // specific data" array: `ul_ftsd`, which itself is stored in illumos's
    // userland thread structure `ulwp_t`. In omicron, we don't use much
    // thread specific storage, and so it always seems that tokio worker
    // threads end up with their pointers in ftsd. This is not guaranteed
    // however. In the future we should also check `ul_stsd`, the "slow"
    // TSD, if the pointer is not found in `ftsd`.
    if tsd_index > 8 {
        panic!("TSD index is not in fast array (ul_ftsd)");
    }

    let lwps = dbg.core.lwps().context("Failed to load lwps from core")?;
    let mut contexts = BTreeMap::new();
    for lwp in lwps {
        // Let's see if the thread name matches what tokio uses by default
        let Ok(name) = dbg.core.lwp_name(lwp.tid) else {
            continue;
        };
        let is_tokio_thread = match name.as_str() {
            // up to tokio 1.50
            "tokio-runtime-worker" => true,
            // tokio 1.50
            "tokio-rt-worker" => true,
            _ => false,
        };
        if !is_tokio_thread {
            continue;
        }

        // We know this is a tokio worker thread and that a
        // `tokio::runtime::context::Context` exists in thread local storage.
        // Now we have to find it.
        //
        let Ok(ftsd) = dbg.core.tsd_from_regs(&lwp.regs) else {
            println!(
                "failed to find thread specific data for tid: {}",
                lwp.tid
            );
            continue;
        };
        let context_addr = Addr(ftsd[tsd_index as usize]);
        contexts.insert(ThreadId(lwp.tid), context_addr);
    }
    Ok(contexts)
}

fn get_pthread_key(dbg: &Dbg) -> Result<u64> {
    for (_id, v) in dbg.db.static_variables() {
        if v.name.as_str() == TokioTypeName::StaticContextPthreadKey.name() {
            let ty = dbg
                .db
                .type_by_id(v.type_id)
                .ok_or(anyhow!("No such type for type_id: {:?}", v.type_id))?;

            let s = Struct::from_state(
                &dbg.segments.segments,
                v.location,
                &dbg.db,
                ty,
            )
            .context("tokio context is not a struct")?;
            return read_pthread_key(s)
                .context("failed to read pthread key for tokio context");
        }
    }
    bail!("failed to find pthread key for tokio context")
}

fn read_pthread_key(s: Struct) -> Option<u64> {
    s.unique_member_named("key")?
        .as_struct()?
        .unique_member_named("key")?
        .as_struct()?
        .unique_member_named("v")?
        .as_struct()?
        .unique_member_named("value")?
        .u64_value()
}

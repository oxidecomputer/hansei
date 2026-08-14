//! Test-only helpers over the checked-in fixture pairs in
//! `tests/fixtures/<set>/`: the load-and-attach chain that this crate's
//! offline suites and hansei's unit tests otherwise each re-spell.
//! Nothing on a session's path calls this. See [`FIXTURE_SET`] for why
//! there is more than one set.

use crate::tokio::bundle::{Context, LocalSetRef, RuntimeRef, TaskList};

use hansei_bundle::{Bundle, BundleView};
use proc::Target;
use proc::snapshot::Snapshot;

use std::path::PathBuf;

/// Which set of checked-in pairs this build reads.
///
/// A pair is only as good as the symbol table its capture had to work
/// with: the fingerprint joining bundle to snapshot is built from the
/// tokio `poll` instantiations that survive into the cored binary, and
/// illumos keeps far more of them than Linux does. So each system that
/// can core a process contributes its own set, and neither is asked to
/// stand for the other.
///
/// macOS captures nothing — it has no ELF core to take — so it reads
/// the illumos set, the one fingerprinted against more names. That is
/// also why this names the *set* rather than the host: what a golden
/// has to agree with is the pair that was loaded, and on macOS that is
/// not the host's own.
pub const FIXTURE_SET: &str = match cfg!(target_os = "linux") {
    true => "linux",
    false => "illumos",
};

/// The path of one checked-in fixture file, in the set this build reads.
pub fn fixture(name: &str) -> PathBuf {
    fixture_dir().join(name)
}

/// The directory holding the set this build reads.
pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(FIXTURE_SET)
}

/// Load a program's fixture pair.
pub fn load(program: &str) -> (Bundle, Snapshot) {
    let bundle = Bundle::load(&fixture(&format!("{program}.bundle")))
        .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
    let snapshot = Snapshot::load(&fixture(&format!("{program}.snapshot")))
        .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
    (bundle, snapshot)
}

/// Attach a loaded pair the way a session does.
pub fn context<'a>(bundle: &'a Bundle, snapshot: &'a Snapshot) -> Context<'a, Snapshot> {
    Context::new(snapshot, BundleView::new(bundle)).expect("snapshot has mappings")
}

/// Discovery and enumeration against an arbitrary target — generic so
/// a fault-injecting wrapper over the snapshot can drive it too. The
/// whole of what an attach finds, for the tests that assert on the
/// runtimes and sets rather than only on the tasks.
pub fn discover<'a, T: Target>(
    ctx: &Context<'a, T>,
    snapshot: &Snapshot,
) -> (Vec<RuntimeRef<'a>>, Vec<LocalSetRef<'a>>, TaskList) {
    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let mut runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let mut list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");
    let sets = ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &[], &mut list);
    (runtimes, sets, list)
}

/// Just the task population [`discover`] leaves behind.
pub fn tasks<T: Target>(ctx: &Context<'_, T>, snapshot: &Snapshot) -> TaskList {
    discover(ctx, snapshot).2
}

/// The io registry's discovery candidates, before the identification
/// chain takes them.
///
/// A `ScheduledIo` holds wakers in three places, and every candidate a
/// fixture's set produces dedups to that one set — so discovery's own
/// output cannot tell the three apart, and only counting what the
/// harvest yielded says whether all three were read.
pub fn io_candidates<T: Target>(ctx: &Context<'_, T>, snapshot: &Snapshot) -> Vec<u64> {
    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");
    let (found, errors) = ctx.io_task_pointers(&runtimes, &list);
    assert!(errors.is_empty(), "{errors:?}");
    found.into_iter().map(|(addr, _)| addr).collect()
}

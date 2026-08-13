//! Test-only helpers over the checked-in fixture pairs in
//! `tests/fixtures/`: the load-and-attach chain that this crate's
//! offline suites and hansei's unit tests otherwise each re-spell.
//! Nothing on a session's path calls this.

use crate::tokio::bundle::{Context, TaskList};

use hansei_bundle::{Bundle, BundleView};
use proc::Target;
use proc::snapshot::Snapshot;

use std::path::PathBuf;

/// The path of one checked-in fixture file.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
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
/// a fault-injecting wrapper over the snapshot can drive it too.
pub fn tasks<T: Target>(ctx: &Context<'_, T>, snapshot: &Snapshot) -> TaskList {
    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let mut list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");
    ctx.discover_local_tasks(&lwps, &workers, &mut list, runtimes.len());
    list
}

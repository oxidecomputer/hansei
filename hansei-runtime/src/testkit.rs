// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test-only helpers over the checked-in fixture pairs in
//! `tests/fixtures/<set>/`: the load-and-attach chain that this crate's
//! offline suites and hansei's unit tests otherwise each re-spell.
//! Nothing on a session's path calls this. See [`FIXTURE_SET`] for why
//! there is more than one set.

use crate::heap::umem::UmemHeap;
use crate::heap::view::{GateCounts, HeapView};
use crate::tokio::bundle::{Context, LocalSetRef, Registries, RuntimeRef, TaskList, Worker};
use crate::tokio::census::{self as census_mod, Bounds, FutureCensus};
use crate::tokio::observe::ReadContext;

use anyhow::Context as _;
use hansei_bundle::{Bundle, BundleView};
use proc::snapshot::Snapshot;
use proc::{LwpInfo, Target};

use std::path::PathBuf;
use std::sync::OnceLock;

pub mod canonical;
pub mod cores;
pub mod corrupt;
pub mod delegation;
pub mod fixture;
pub mod heap;

pub use canonical::Canonical;
pub use fixture::Fixture;

/// Record each of `kinds` on `bundle`'s type as the coroutine kind a
/// rule of that kind names — what extraction records for a coroutine
/// a reviewed convention covers — for a test whose names a listing
/// reads the kind word of.
pub fn coroutine_kinds(
    bundle: &mut Bundle,
    kinds: &[(hansei_bundle::BundleTypeId, hansei_bundle::SemanticRuleKind)],
) {
    use hansei_bundle::{SemanticOriginId, SemanticRule, SemanticRuleId, TypeSemantics};
    for &(ty, kind) in kinds {
        let rule = SemanticRuleId(bundle.semantics.rules.len() as u32);
        bundle.semantics.rules.push(SemanticRule {
            kind,
            revision: 1,
            origin: SemanticOriginId(0),
        });
        bundle.semantics.types.push(TypeSemantics {
            ty,
            storage: hansei_bundle::StoragePolicy::DeclaredMembers,
            future: None,
            coroutine: None,
            access: None,
            resource: None,
            container: None,
            select: None,
            http: None,
            request: None,
            table: None,
            pool: None,
            connected: None,
            io_route: None,
            io: None,
            tls_session: None,
            tls_stream: None,
            stream_peer: None,
            far_end: None,
            refcount: None,
            lock: None,
            acquires_for: None,
            coroutine_kind: Some(rule),
            issues: Vec::new(),
        });
    }
    bundle.semantics.types.sort_by_key(|record| record.ty);
}

/// A bundle holding nothing but a type named each of `names`, the
/// `i`th as `BundleTypeId(i)`: what a test that lays records out by
/// hand gives the code naming their types, where no fixture's bundle
/// carries the names it wants to see printed.
pub fn named_types(names: &[&str]) -> Bundle {
    use hansei_bundle::{
        BundleTypeId, DynFutureTable, Encoding, FORMAT_VERSION, ImplTable, InfraTypes, Meta,
        ProvenanceTable, StaticsTable, StringInterner, TaskTable, TypeDef, TypeTable, WalksTable,
    };
    let mut strings = StringInterner::new();
    let types = names
        .iter()
        .map(|name| TypeDef::Base {
            name: strings.intern(name),
            size: 8,
            encoding: Encoding::Unsigned,
        })
        .collect();
    let any = BundleTypeId(0);
    Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.finish(),
        types: TypeTable {
            types,
            ..Default::default()
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: any,
            vtable: any,
            trailer: any,
            context: any,
            scheduler_handle: any,
            mt_handle: any,
            ct_handle: any,
            location: any,
            raw_waker_vtable: any,
        },
        provenance: ProvenanceTable::default(),
        impls: ImplTable::default(),
        semantics: Default::default(),
    }
}

/// Explicit continuation bindings for the `walk-shapes` pair's two
/// hand-written wrappers — `WrapS`, a plain struct whose `inner` is the
/// future it polls, and `WrapE`, a named-variant enum whose `Running`
/// case polls its `inner` — under one rule of a reviewed forwarding
/// kind on the bundle's compiler origin. The production binders decline
/// both (no reviewed implementation covers them); a test that wants the
/// engine to step through them attaches with these through
/// [`Context::with_test_bindings`], which validates them the way the
/// bundle's own records are validated.
pub fn walk_shapes_bindings(
    bundle: &Bundle,
) -> (
    Vec<hansei_bundle::TypeSemantics>,
    Vec<hansei_bundle::SemanticRule>,
) {
    use hansei_bundle::{
        BundleType, BundleTypeId, Continuation, FutureEvidence, FutureFacts, FutureTarget,
        MemberRef, PollAction, PollCase, PollProgram, SemanticIssue, SemanticIssueKind,
        SemanticOrigin, SemanticOriginId, SemanticRule, SemanticRuleId, SemanticRuleKind, Step,
        StoragePolicy, TypeSemantics, TypedPath,
    };
    let view = BundleView::new(bundle);
    let type_by_name = |pred: &dyn Fn(&str) -> bool| -> BundleType<'_> {
        let hits: Vec<BundleType<'_>> = (0..bundle.types.types.len() as u32)
            .filter_map(|i| view.ty(BundleTypeId(i)))
            .filter(|ty| pred(ty.name()))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "one such type: {:?}",
            hits.iter().map(|t| t.name()).collect::<Vec<_>>()
        );
        hits[0]
    };
    let wrap_s = type_by_name(&|n| n.starts_with("walk_shapes::WrapS<") && !n.contains(">::"));
    let wrap_e = type_by_name(&|n| n.starts_with("walk_shapes::WrapE<") && !n.contains(">::"));
    let deep = type_by_name(&|n| n.contains("::deep::") && n.ends_with('}'));
    let chained = type_by_name(&|n| n.contains("::chained::") && n.ends_with('}'));
    let origin = bundle
        .semantics
        .origins
        .iter()
        .position(|o| matches!(o, SemanticOrigin::Rustc { .. }))
        .expect("a compiler origin");
    let rule = SemanticRuleId(bundle.semantics.rules.len() as u32);
    let rules = vec![SemanticRule {
        kind: SemanticRuleKind::StdBoxPoll,
        revision: 1,
        origin: SemanticOriginId(origin as u32),
    }];
    let running = wrap_e.variant_name_ref("Running").expect("WrapE::Running");
    // Every variant of the state needs a case: `Done` polls nothing,
    // which no action spells, so its case is an unknown continuation.
    let done = wrap_e.variant_name_ref("Done").expect("WrapE::Done");
    let running_inner = wrap_e
        .variants()
        .find(|v| v.name == "Running")
        .and_then(|v| v.ty.members().find(|m| m.name() == "inner"))
        .expect("Running declares inner")
        .name_ref();
    let s_inner = wrap_s
        .member("inner")
        .expect("WrapS declares inner")
        .name_ref();
    let record = |ty: BundleType<'_>, parent: BundleType<'_>, program: PollProgram| TypeSemantics {
        ty: ty.id(),
        storage: StoragePolicy::DeclaredMembers,
        future: Some(FutureFacts {
            evidence: vec![FutureEvidence::DelegatedBy {
                parent: parent.id(),
            }],
            continuation: Continuation::Bound { rule, program },
        }),
        coroutine: None,
        access: None,
        resource: None,
        container: None,
        select: None,
        http: None,
        request: None,
        table: None,
        pool: None,
        connected: None,
        io_route: None,
        io: None,
        tls_session: None,
        tls_stream: None,
        stream_peer: None,
        far_end: None,
        refcount: None,
        lock: None,
        acquires_for: None,
        coroutine_kind: None,
        issues: Vec::new(),
    };
    let bindings = vec![
        record(
            wrap_s,
            chained,
            PollProgram::Direct(PollAction::Delegate {
                target: FutureTarget::Value(TypedPath {
                    steps: vec![Step::Member(MemberRef::Named(s_inner))],
                    target: wrap_e.id(),
                }),
                exclusive: false,
            }),
        ),
        record(
            wrap_e,
            wrap_s,
            PollProgram::MatchVariant {
                state: TypedPath {
                    steps: Vec::new(),
                    target: wrap_e.id(),
                },
                cases: vec![
                    PollCase {
                        variant: running,
                        action: PollAction::Delegate {
                            target: FutureTarget::Value(TypedPath {
                                steps: vec![
                                    Step::Variant(running),
                                    Step::Member(MemberRef::Named(running_inner)),
                                ],
                                target: deep.id(),
                            }),
                            exclusive: false,
                        },
                    },
                    PollCase {
                        variant: done,
                        action: PollAction::Unknown(SemanticIssue {
                            kind: SemanticIssueKind::UnsupportedState,
                            detail: None,
                        }),
                    },
                ],
            },
        ),
    ];
    (bindings, rules)
}

/// The bindings that turn `ty`'s record into an access-only one — its
/// future facts dropped, its storage route kept — for a test of how
/// the engine crosses such a record over a real pair. Every record
/// that cited `ty` as the parent that proved it a future loses that
/// citation too, since the validator holds each one to a bound program
/// at the parent; a record that would be left with no evidence at all
/// is a test the pair cannot host, and the assertion says so.
pub fn access_only(
    bundle: &Bundle,
    ty: hansei_bundle::BundleTypeId,
) -> Vec<hansei_bundle::TypeSemantics> {
    use hansei_bundle::FutureEvidence;
    let cites = FutureEvidence::DelegatedBy { parent: ty };
    let mut out = Vec::new();
    for record in &bundle.semantics.types {
        if record.ty == ty {
            let mut stripped = record.clone();
            assert!(stripped.access.is_some(), "{ty:?} has a storage route");
            stripped.future = None;
            out.push(stripped);
        } else if let Some(facts) = &record.future
            && facts.evidence.contains(&cites)
        {
            let mut citing = record.clone();
            let facts = citing.future.as_mut().unwrap();
            facts.evidence.retain(|e| *e != cites);
            assert!(
                !facts.evidence.is_empty(),
                "{:?} was a future by {ty:?} alone",
                record.ty
            );
            out.push(citing);
        }
    }
    assert!(out.iter().any(|r| r.ty == ty), "{ty:?} has a record");
    out
}

/// Every checked-in set of pairs, named for its capture's coordinates.
///
/// The first axis is the capturing system. A pair is only as good as
/// the symbol table its capture had to work with: the fingerprint
/// joining bundle to snapshot is built from the tokio `poll`
/// instantiations that survive into the cored binary, and illumos
/// keeps far more of them than Linux does. So each system that can
/// core a process contributes a set, and neither stands for the other.
///
/// The second axis is the tokio endpoint. The version matrix pins that
/// the walks *bind* per supported tokio version; `linux-floor` — the
/// same fixtures built against `matrix.toml`'s floor lockfile
/// (`capture-snapshots.sh --tokio <floor>`, Linux host only) — is what
/// *executes* them against memory from the oldest supported release.
/// The newest is what the per-system sets already are, or near it; one
/// endpoint set, deliberately not a per-cell cross product.
///
/// Which set a *reader* takes is not a property of where it runs. A
/// pair is two files, and reading one needs nothing from the system
/// that wrote it — which is what an offline suite is for. So the
/// golden suites walk every set wherever they run, macOS included
/// though it can capture neither, and a test that only wants some pair
/// to render names the set it means.
pub const FIXTURE_SETS: &[&str] = &["illumos", "linux", "linux-floor"];

/// The path of one checked-in fixture file in `set`.
pub fn fixture(set: &str, name: &str) -> PathBuf {
    fixture_dir(set).join(name)
}

/// The directory holding `set`.
pub fn fixture_dir(set: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(set)
}

/// Every program `capture-snapshots.sh` captures a fixture pair for —
/// the inventory each set holds, and the program list every suite
/// reading the pairs iterates. `gen-0007` is quarantined generated
/// output (see its header): it is in the offline suites and the
/// capture loop only, not the golden, matrix, or acceptance lists.
pub const PROGRAMS: &[&str] = &[
    "simple-await",
    "nested-await",
    "dyn-future",
    "futurelock",
    "sleep-join",
    "channels",
    "unordered",
    "joinset",
    "ct-runtime",
    "local-set",
    "local-set-timer",
    "local-set-io",
    "foreign-runtime",
    "gen-0007",
    "walk-shapes",
    "blocking-pool",
    "delegation-cases",
    "armed-select",
    "watch-stream",
    "http-conns",
    "two-releases",
    "tls-conns",
];

/// Mask the run-varying values analysis output carries — heap
/// addresses and timer deadlines (relative to the stop instant, so
/// they shift with how long the capture took) — so goldens over the
/// pairs compare exactly. A deadline is masked with the word before it
/// and without: the `connections` column prints it bare, `+29.981s`,
/// under a header that already says what it is.
///
/// Over fresh cores ([`cores::CORES`]) the mask is [`mask_core`]'s
/// instead, which a core needs and a snapshot never did.
pub fn mask(s: &str) -> String {
    match cores::dir() {
        None => mask_times(
            &regex::Regex::new(r"0x[0-9a-f]+")
                .unwrap()
                .replace_all(s, "0xADDR"),
        ),
        Some(_) => mask_core(s),
    }
}

/// [`mask`], for output read from `set`, which over a Linux set's
/// fresh cores also leaves out the waker slots attribution could only
/// call unknown: the `unknown @ 0x…` line of a task's slot list and
/// the `unknown` entry of a slot cell.
///
/// glibc keeps a freed chunk's old bytes past its first two words, so
/// a waker the chunk held before it was freed reads as a hit, and
/// whether one is there depends on what the allocator reused before
/// the core was taken. hansei has no model of glibc's heap to tell
/// such a chunk from a live one (an illumos core's allocator index
/// does exactly that, so the illumos set keeps its unknown slots).
pub fn mask_for(set: &str, s: &str) -> String {
    if cores::dir().is_none() || !set.starts_with("linux") {
        return mask(s);
    }
    let re = |pattern: &str| regex::Regex::new(pattern).unwrap();
    // Before the addresses are numbered, so the ones after a slot
    // present in one capture and absent in the next keep their names.
    let s = re(r"(?m)^[ \t]*unknown @ 0x[0-9a-f]+\n").replace_all(s, "");
    let s = re(r"(?m), unknown([ \t]{2}|,|$)").replace_all(&s, "$1");
    mask_core(&s)
}

/// The timer readings either mask hides: how far the capture sat from
/// each deadline.
fn mask_times(s: &str) -> String {
    let deadlines = regex::Regex::new(r"deadline \+?\d+\.\d{3}s").unwrap();
    let relative = regex::Regex::new(r"\+\d+\.\d{3}s").unwrap();
    let monotonic = regex::Regex::new(r"\d+\.\d{3}s on the target's monotonic clock").unwrap();
    let overdue = regex::Regex::new(r"overdue by \d+\.\d{3}s").unwrap();
    let s = deadlines.replace_all(s, "deadline TS");
    let s = relative.replace_all(&s, "+TS");
    let s = monotonic.replace_all(&s, "TS on the target's monotonic clock");
    overdue.replace_all(&s, "overdue by TS").into_owned()
}

/// Mask what two fresh cores of one program differ in that a
/// [`Canonical`] core cannot rename away, so goldens over cores compare
/// exactly from one capture to the next:
///
/// - every address, numbered by first appearance (`0xA1`, `0xA2`, …),
///   so that two mentions of one address still agree;
/// - the timer readings [`mask`] hides, and elapsed times (`idle
///   (2ms)`);
/// - the process's own facts: its pid and parent, start time, the
///   checkout its binary ran from (truncated at a length that moves
///   with that path, in `psargs`), and the build ids, which follow the
///   path the build was compiled at;
/// - the worker index: which worker held the driver is a race no
///   readiness wait controls, so the state is kept and the number not;
/// - what scheduling and stale stack contents decide: the runtime's
///   metric counters, the waker sweep's extent and hit counts, the
///   allocator's cache and slab counts;
/// - ephemeral ports, and file descriptor numbers, which the kernel
///   hands out in the order threads opening sockets at once reach it;
/// - runs of spaces inside a line, which move with the width of a
///   value beside them.
pub fn mask_core(s: &str) -> String {
    let re = |pattern: &str| regex::Regex::new(pattern).unwrap();
    let s = re(r"\b[0-9a-f]{40}\b").replace_all(s, "BUILDID");
    let s = re(r"(?m)^(psargs:\s+).*$").replace_all(&s, "${1}PSARGS");
    let s = re(r"\S*/test-programs/").replace_all(&s, "<test-programs>/");
    let s = first_seen(&s);
    let s = mask_times(&s);
    let s = re(r"\(\d+(\.\d+)?(ns|µs|ms|s)\)").replace_all(&s, "(T)");
    let s = re(r"(?m)^(pid:\s+)\d+").replace_all(&s, "${1}PID");
    let s = re(r"(?m)^(ppid:\s+)\d+").replace_all(&s, "${1}PID");
    let s = re(r"(?m)^(start:\s+).*$").replace_all(&s, "${1}TIME");
    let s = re(r"\bworker \d+\b").replace_all(&s, "worker N");
    let s = re(r"(MetricAtomic\w+ \{\n\s*value: )\d+").replace_all(&s, "${1}N");
    let s = re(r"\b(busy_duration_total|tick|park_count|park_unpark_count|noop_count): \d+")
        .replace_all(&s, "$1: N");
    let s = re(r"[\d.]+ [KMG]?i?B swept in \d+ chunks").replace_all(&s, "N swept in N chunks");
    let s = re(r"(?m)^(\s*(hits|by class|attributed):).*$").replace_all(&s, "$1 N");
    let s = re(r"\(\d+ caches, \d+ slabs\)").replace_all(&s, "(N caches, N slabs)");
    let s = re(r"\b(\d{1,3}(\.\d{1,3}){3}):\d+\b").replace_all(&s, "$1:PORT");
    let s = re(r"\bfd(:?) \d+\b").replace_all(&s, "fd$1 N");
    re(r"(\S) {2,}").replace_all(&s, "$1  ").into_owned()
}

/// Every `0x` address in `s`, numbered by first appearance.
fn first_seen(s: &str) -> String {
    let mut seen: Vec<String> = Vec::new();
    regex::Regex::new(r"0x[0-9a-f]+")
        .unwrap()
        .replace_all(s, |caps: &regex::Captures<'_>| {
            let addr = &caps[0];
            let n = match seen.iter().position(|a| a == addr) {
                Some(i) => i + 1,
                None => {
                    seen.push(addr.to_owned());
                    seen.len()
                }
            };
            format!("0xA{n}")
        })
        .into_owned()
}

/// The sets this run reads, in [`FIXTURE_SETS`] order: every one over
/// the checked-in snapshots, and over fresh cores ([`cores::CORES`]) the
/// ones this system captures plus any other copied in beside them — on
/// a system that captures none, all of them, each of which must be
/// there. A test walking the sets walks these.
pub fn fixture_sets() -> &'static [&'static str] {
    static SETS: OnceLock<Vec<&'static str>> = OnceLock::new();
    SETS.get_or_init(|| match cores::dir() {
        None => FIXTURE_SETS.to_vec(),
        Some(dir) => cores::sets(&dir),
    })
}

/// Whether this run reads `set`: always over the snapshots and on a
/// system that captures none, and over fresh cores elsewhere only for
/// the host's own sets and copies beside them. A test whose subject is
/// one system's capture — the illumos allocator, say — runs only where
/// the run reads that set, which every system that cannot core does.
pub fn reads(set: &str) -> bool {
    fixture_sets().contains(&set)
}

/// `set` where this run reads it, and otherwise the first set it does:
/// for a test written against one set whose choice of it is arbitrary,
/// so that the run over the snapshots reads exactly what it always did
/// and a capturing host still runs it over a set of its own.
pub fn set_or_any(set: &'static str) -> &'static str {
    match reads(set) {
        true => set,
        false => fixture_sets()[0],
    }
}

/// Load a program's pair from whichever set, for a test that wants
/// some real capture to work with rather than every capture there is.
///
/// The choice is arbitrary and fixed for a given run: the first set
/// the run reads ([`fixture_sets`]), so illumos's over the snapshots
/// and on a Mac, the host's own on a capturing host. A test reading
/// this is testing what it does with a pair, and two sets would only
/// run it twice. A test whose subject *is* the capture walks
/// [`fixture_sets`] instead.
pub fn load_any(program: &str) -> (Bundle, Fixture) {
    load(fixture_sets()[0], program)
}

/// Load a program's fixture pair from `set`: its snapshot, or under
/// [`cores::CORES`] a fresh core opened through the production reader
/// with the bundle extracted from its build B.
pub fn load(set: &str, program: &str) -> (Bundle, Fixture) {
    if let Some(dir) = cores::dir() {
        let (bundle, proc) = cores::load(&dir, set, program);
        let core = Canonical::new(proc, &bundle);
        return (bundle, Fixture::Core(Box::new(core)));
    }
    let bundle = Bundle::load(&fixture(set, &format!("{program}.tinfo")))
        .expect("fixture tokio info loads; regenerate with capture-snapshots.sh");
    let snapshot = Snapshot::load(&fixture(set, &format!("{program}.snapshot")))
        .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
    (bundle, Fixture::from(snapshot))
}

/// `program`'s bundle, for a test that reads nothing of a target: the
/// checked-in one from the set [`load_any`] reads, or under
/// [`cores::CORES`] the one extracted from this system's own build B
/// ([`bundle_path`]), so the test runs where no core is.
///
/// Only for a test that reads the bundle alone. A type id joined
/// against a target's memory must come from that target's own bundle,
/// which [`load`] returns beside it. And the build is native, Mach-O on
/// a Mac, so a test asserting on a type only one system's std defines,
/// or a monomorphization one object format keeps and another folds
/// away, reads [`load`]'s bundle instead.
pub fn bundle(program: &str) -> Bundle {
    let path = match cores::dir() {
        Some(_) => bundle_path(program),
        None => fixture(fixture_sets()[0], &format!("{program}.tinfo")),
    };
    Bundle::load(&path)
        .unwrap_or_else(|e| panic!("the {program} bundle loads from {}: {e}", path.display()))
}

/// The bundle the exegesis under test extracts from this system's own
/// build B of `program` in the primary cell, once per run, written to a
/// file whose path is returned. The build is the one the extraction
/// goldens read, so on a Mac it is the Mach-O binary with its dSYM.
pub fn bundle_path(program: &str) -> PathBuf {
    assert!(
        PROGRAMS.contains(&program),
        "{program} is not a fixture program"
    );
    let recipe = matrix::Matrix::load().primary_recipe();
    let binary = matrix::build_b(&recipe, &[program]).join(program);
    let dsym = binary
        .with_extension("dSYM")
        .join("Contents/Resources/DWARF")
        .join(program);
    let dsym = dsym.exists().then_some(dsym);
    let bundles = matrix::test_programs_dir().join("fixtures/bundles");
    let path = bundles.join(format!("{program}.tinfo"));
    testrun::once_per_run_each(
        &bundles.join(".stamps"),
        &[program],
        |_| {
            let root = matrix::test_programs_dir().join("..");
            let mut inputs = testrun::Inputs::new();
            inputs.file(&binary);
            if let Some(dsym) = &dsym {
                inputs.file(dsym);
            }
            inputs
                .tree(&root.join("exegesis/src"), ".rs")
                .tree(&root.join("hansei-bundle/src"), ".rs")
                .file(&root.join("Cargo.lock"));
            inputs.finish()
        },
        |_| {
            let sources = exegesis::extract::DebugSources {
                binary: &binary,
                debug_info: dsym.as_deref(),
            };
            let opts = exegesis::extract::ExtractOptions {
                extract_args: format!("testkit extraction of {program}"),
                ..Default::default()
            };
            let (bundle, _stats) = exegesis::extract::extract_sources(&sources, &opts)
                .unwrap_or_else(|e| panic!("extraction of {program} failed: {e}"));
            std::fs::create_dir_all(&bundles).expect("failed to create the bundle dir");
            let tmp = path.with_extension(format!("tmp{}", std::process::id()));
            bundle.save(&tmp).expect("failed to write the bundle");
            std::fs::rename(&tmp, &path).expect("failed to install the bundle");
        },
    );
    path
}

/// The files a session over a program's pair in `set` is opened from,
/// as a command line names them.
pub struct Paths {
    /// The snapshot, or the core.
    pub core: PathBuf,
    /// The tokio-info file.
    pub tokio_info: PathBuf,
    /// The executable a Linux core is read with.
    pub binary: Option<PathBuf>,
    /// Where a Linux core's libraries are.
    pub sysroot: Option<PathBuf>,
}

/// The files [`load`] reads `program`'s pair in `set` from.
pub fn paths(set: &str, program: &str) -> Paths {
    if let Some(dir) = cores::dir() {
        let capture = cores::capture(&dir, set, program);
        let tokio_info = cores::bundle_path(&dir, set, program, &capture);
        return Paths {
            core: capture.core,
            tokio_info,
            binary: capture.sysroot.is_some().then_some(capture.binary),
            sysroot: capture.sysroot,
        };
    }
    Paths {
        core: fixture(set, &format!("{program}.snapshot")),
        tokio_info: fixture(set, &format!("{program}.tinfo")),
        binary: None,
        sysroot: None,
    }
}

/// Attach a loaded pair the way a session does.
pub fn context<'a>(bundle: &'a Bundle, fixture: &'a Fixture) -> Context<'a, Fixture> {
    Context::new(fixture, BundleView::new(bundle)).expect("the fixture has mappings")
}

/// The state a session is in after enumerating what the runtimes own,
/// stopped *before* hidden-task discovery — which is what the
/// discovery tests assert against before letting the sweep run.
pub struct Enumeration<'b> {
    pub lwps: Vec<LwpInfo>,
    pub workers: Vec<Worker>,
    pub runtimes: Vec<RuntimeRef<'b>>,
    pub list: TaskList,
    /// What the registry harvests retained; empty until [`discover`]
    /// runs them.
    ///
    /// [`discover`]: Enumeration::discover
    pub registries: Registries,
    /// The allocator evidence the pair reads under, prepared the way a
    /// session prepares it ([`crate::heap::prepare`]): the recorded
    /// policy of a snapshot, honored before anything is gated by it.
    pub heap: Option<UmemHeap>,
    /// What the gates refused through [`with_read`] and [`discover`],
    /// for as long as this enumeration is read.
    ///
    /// [`with_read`]: Enumeration::with_read
    /// [`discover`]: Enumeration::discover
    pub gates: GateCounts,
}

/// Enumerate, stopping before discovery. Panics on a stage failure
/// (a healthy pair enumerates); pipelines run over damaged targets
/// use [`try_enumerate`].
pub fn enumerate<'b, T: Target>(ctx: &Context<'b, T>, target: &T) -> Enumeration<'b> {
    try_enumerate(ctx, target).expect("a healthy pair enumerates")
}

/// The fallible twin, for pipelines run over damaged targets: any
/// stage failing is an `Err`, and which stage is in the error text —
/// a caller that only cares that containment happened can drop it,
/// but a triage log should still say where.
pub fn try_enumerate<'b, T: Target>(
    ctx: &Context<'b, T>,
    target: &T,
) -> anyhow::Result<Enumeration<'b>> {
    let lwps = target.lwps().context("LWP enumeration failed")?;
    let workers = ctx
        .find_workers(&lwps)
        .context("TLS-key worker discovery failed")?;
    let runtimes = ctx
        .find_runtimes(&workers)
        .context("runtime discovery failed")?;
    let list = ctx
        .enumerate_all_tasks(&runtimes)
        .context("the owned-task walk failed")?;
    let heap = crate::heap::prepare(target).context("allocator evidence preparation failed")?;
    Ok(Enumeration {
        lwps,
        workers,
        runtimes,
        list,
        registries: Registries::default(),
        heap,
        gates: GateCounts::default(),
    })
}

impl<'b> Enumeration<'b> {
    /// Run `f` under the read context a session would read this pair
    /// under: the prepared allocator evidence bridged through
    /// [`HeapView`] over `target`, or no heap at all where none was
    /// prepared.
    pub fn with_read<T: Target, R>(&self, target: &T, f: impl FnOnce(&ReadContext<'_>) -> R) -> R {
        let view = self
            .heap
            .as_ref()
            .map(|heap| HeapView::new(heap, target, &self.gates));
        let read = ReadContext {
            heap: view.as_ref().map(|view| view as &dyn reify::Heap),
        };
        f(&read)
    }

    /// Run hidden-task discovery — the sweep `discover_hidden_tasks`
    /// performs — mutating the runtimes and list the way a session
    /// does, under the prepared allocator evidence the way a session
    /// reads, and returning the local sets it admitted.
    pub fn discover<T: Target>(
        &mut self,
        ctx: &Context<'b, T>,
        exclude: &[u64],
    ) -> Vec<LocalSetRef<'b>> {
        let view = self
            .heap
            .as_ref()
            .map(|heap| HeapView::new(heap, ctx.proc, &self.gates));
        let read = ReadContext {
            heap: view.as_ref().map(|view| view as &dyn reify::Heap),
        };
        let (sets, registries) = ctx.discover_hidden_tasks(
            &self.lwps,
            &self.workers,
            &mut self.runtimes,
            exclude,
            &mut self.list,
            &read,
        );
        self.registries = registries;
        sets
    }
}

/// The full pipeline over a loaded pair: attach, enumerate, discover,
/// census, total audit (which panics on violation, in [`census`]).
/// What every census-judging suite starts from; what a *healthy*
/// capture must satisfy beyond that is [`Run::healthy_problems`] and
/// [`Run::registry_problems`], which a suite calls or does not — its
/// strictness is visible at its call site.
///
/// Over a [`Fixture`] unless a suite brings its own target: the
/// generated-fixture loops hold a core of a program no fixture set
/// has, and read it as it is.
pub struct Run<'a, T: Target = Fixture> {
    pub ctx: Context<'a, T>,
    pub list: TaskList,
    pub census: FutureCensus,
    /// The allocator evidence the census was gated by, prepared under
    /// the snapshot's recorded policy: `Some` on a pair whose capture
    /// built an index, `None` on one that recorded none.
    pub heap: Option<UmemHeap>,
}

/// Run the pipeline over a loaded pair, gated the way a session gates
/// it: discovery and the census read under the pair's prepared
/// allocator evidence.
pub fn run<'a, T: Target>(bundle: &'a Bundle, target: &'a T) -> Run<'a, T> {
    let ctx = Context::new(target, BundleView::new(bundle)).expect("the target has mappings");
    let mut e = enumerate(&ctx, target);
    e.discover(&ctx, &[]);
    let census = e.with_read(target, |read| census_with(&ctx, &e.list, read));
    Run {
        ctx,
        list: e.list,
        census,
        heap: e.heap,
    }
}

/// What [`run`] reads of `fixture`, recorded as a snapshot through the
/// production [`Recorder`](proc::snapshot::Recorder): for a test whose
/// subject is a snapshot, whichever kind of target the run reads.
pub fn record(bundle: &Bundle, fixture: &Fixture) -> Snapshot {
    use proc::snapshot::{RecordedHeapEvidence, Recorder};
    let recorder = Recorder::new(fixture);
    let ctx = Context::new(&recorder, BundleView::new(bundle)).expect("the fixture has mappings");
    let mut e = enumerate(&ctx, &recorder);
    e.discover(&ctx, &[]);
    let _ = e.with_read(&recorder, |read| census_with(&ctx, &e.list, read));
    let evidence = match e.heap {
        Some(_) => RecordedHeapEvidence::Available,
        None => RecordedHeapEvidence::Unavailable,
    };
    recorder
        .snapshot(evidence)
        .expect("the recorder assembles a snapshot")
}

impl<T: Target> Run<'_, T> {
    /// [`healthy_problems`] over this run.
    #[must_use]
    pub fn healthy_problems(&self) -> Vec<String> {
        healthy_problems(&self.census, &self.list)
    }

    /// [`expect::problems`] over this run.
    #[must_use]
    pub fn registry_problems(&self) -> Vec<String> {
        expect::problems(self.ctx.proc, self.ctx.view, &self.census, &self.list)
    }
}

/// Everything a *healthy* capture is entitled to beyond the total
/// audit, reported as problems rather than asserted, so the
/// assert-each suites (`assert!(empty)`) and the collect-everything
/// suites (extend a problem list) share one implementation: no census
/// errors, no caps, and the healthy-only audit invariants.
#[must_use]
pub fn healthy_problems(census: &FutureCensus, list: &TaskList) -> Vec<String> {
    let mut problems: Vec<String> = census
        .errors
        .iter()
        .map(|e| format!("census error: {e:#}"))
        .collect();
    if census.capped.any() {
        problems.push(format!("the walk hit a hard limit: {:?}", census.capped));
    }
    problems.extend(
        census
            .audit(list)
            .into_iter()
            .map(|v| format!("healthy-only audit: {v}")),
    );
    problems
}

/// Just the task population [`enumerate`] and a full discovery sweep
/// leave behind — generic so a fault-injecting wrapper over the
/// snapshot can drive it too.
pub fn tasks<T: Target>(ctx: &Context<'_, T>, target: &T) -> TaskList {
    let mut e = enumerate(ctx, target);
    e.discover(ctx, &[]);
    e.list
}

/// The local `local` of the frame on `task`'s chain whose future's
/// name contains `frame`, as the census scans it — a test's way to
/// hand a walk the very value a fixture built, without a marker.
pub fn frame_local<'b, T: Target>(
    ctx: &Context<'b, T>,
    task: &crate::tokio::bundle::Task,
    frame: &str,
    local: &str,
) -> reify::Value<'b> {
    let inspection = ctx
        .inspect_task(task, &ReadContext::none())
        .expect("the task's root reads")
        .expect("the task holds a resident future");
    let found = inspection
        .chain
        .frames
        .iter()
        .find(|f| f.future.ty.name().contains(frame))
        .unwrap_or_else(|| panic!("no frame named {frame} on the chain"));
    census_mod::frame_locals(ctx, found)
        .locals
        .into_iter()
        .find(|(name, _)| *name == local)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("no local {local} in {frame}"))
}

/// The future census over an enumerated list, held to its construction
/// rules: the total audit invariants hold over any input whatsoever, so
/// every test census — healthy pair and fault campaign alike — runs
/// through here. Errors and caps come back intact; a test over a
/// healthy pair asserts on those (and the healthy-only audit) itself.
pub fn census<T: Target>(ctx: &Context<'_, T>, list: &TaskList) -> FutureCensus {
    census_with(ctx, list, &ReadContext::none())
}

/// [`census`] under an explicit read context — the gated form, for a
/// pipeline reading under prepared allocator evidence.
pub fn census_with<T: Target>(
    ctx: &Context<'_, T>,
    list: &TaskList,
    read: &ReadContext<'_>,
) -> FutureCensus {
    let census = census_mod::census_bounded(ctx, list, Bounds::default(), read);
    let violations = census.audit_total(list);
    assert!(violations.is_empty(), "census audit: {violations:#?}");
    census
}

/// Every outcome the census can produce *from a healthy capture*, as
/// one census did or did not produce it. The names are what the
/// corpus coverage test prints, so each says what a reader would go
/// looking for.
///
/// Deliberately absent, so their loss is not mistaken for an
/// oversight: a reaped set slot and the `<undecoded>` /
/// `<unresolved: …>` summaries are producible only by damage, and
/// `degraded.rs` pins each by patching a healthy snapshot. The
/// hand-written corpus also shows no Timer or Task wait — every held
/// fixture future there is unresumed (an unpolled future waits on
/// nothing) — but a generated fixture that parks a polled body on a
/// timer can produce the Timer entry, which is why the timer wait is
/// listed for the generated corpus's accumulator and not asserted by
/// the checked-in corpus's.
pub fn outcomes(census: &crate::tokio::census::FutureCensus) -> Vec<(&'static str, bool)> {
    use crate::tokio::bundle::WaitKind;
    use crate::tokio::census::Via;
    let vias: Vec<Via> = census
        .held
        .iter()
        .map(|h| h.via)
        .chain(census.sets.iter().map(|s| s.via))
        .chain(census.join_sets.iter().map(|s| s.via))
        .flatten()
        .collect();
    let waits: Vec<&WaitKind> = census
        .held
        .iter()
        .filter_map(|h| h.wait.as_ref())
        .chain(
            census
                .sets
                .iter()
                .flat_map(|s| s.children.iter().filter_map(|c| c.wait.as_ref())),
        )
        .collect();
    vec![
        (
            "a find reached through a struct descent",
            census.stats.descend_finds > 0,
        ),
        (
            "a find reached through an active enum variant",
            census.stats.enum_finds > 0,
        ),
        (
            "a find attributed to a held future's chain",
            vias.iter().any(|v| matches!(v, Via::Held(_))),
        ),
        (
            "a find attributed to a set child's chain",
            vias.iter().any(|v| matches!(v, Via::SetChild { .. })),
        ),
        (
            "a dyn find re-rooted at its heap referent",
            census.held.iter().any(|h| h.slot != h.addr),
        ),
        (
            "an unlisted join-set member",
            census
                .join_sets
                .iter()
                .any(|s| s.children.iter().any(|c| !c.listed)),
        ),
        (
            "a semaphore wait",
            waits
                .iter()
                .any(|w| matches!(w, WaitKind::Semaphore { .. })),
        ),
        (
            "a timer wait",
            waits.iter().any(|w| matches!(w, WaitKind::Timer { .. })),
        ),
        (
            "a notify wait",
            waits.iter().any(|w| matches!(w, WaitKind::Notify { .. })),
        ),
    ]
}

/// Print the outcome list in the one-line-per-outcome format the
/// soak scripts' `note_outcomes` parses: `outcome: <name> = <bool>`.
/// The format is an interface — soak.sh and churn.sh parse it through
/// their shared lib.sh — so it changes only with that parser.
pub fn print_outcomes(census: &FutureCensus) {
    for (name, hit) in outcomes(census) {
        println!("outcome: {name} = {hit}");
    }
}

/// The fixture programs' ground-truth registry: reading back what a
/// fixture registered about the state it built (`test-programs`'
/// `census_expect` module — the write side, whose plain-old-data layout
/// this module re-spells by hand; the two must move together), and
/// diffing a census against it in both directions.
///
/// The registry is one `#[no_mangle]` static found by symbol name, so
/// no DWARF is involved; the snapshot command reads it through its
/// recording target at capture time, which is what makes the same
/// bytes replayable from the offline pairs.
pub mod expect {
    use crate::tokio::bundle::{FutureInfo, TaskList};
    use crate::tokio::census::{FutureCensus, Via};

    use anyhow::{Context as _, Result, bail, ensure};
    use hansei_bundle::BundleView;
    use proc::Target;

    use std::collections::BTreeMap;

    /// The write side's `HANSEI_CENSUS_EXPECT` static.
    pub const SYMBOL: &str = "HANSEI_CENSUS_EXPECT";

    /// `committed: u64` then `reserved: u64`, then the entries.
    const HEADER: u64 = 16;
    /// `kind: u32, flags: u32, addr: u64, count: u64, name: [u8; 64]`.
    const ENTRY: u64 = 88;
    const NAME_AT: usize = 24;

    /// One registered expectation, as the write side's API spells them.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Expectation {
        /// A held find at exactly this slot, named `name`.
        Held { slot: u64, name: String },
        /// A find reached via the held find at `parent` — a future
        /// carried inside another, which has no slot of its own the
        /// fixture could name.
        HeldIn { parent: u64, name: String },
        /// A `FuturesUnordered` at `addr` with this many children.
        Set { addr: u64, children: u64 },
        /// A `JoinSet` at `addr` with this many members.
        JoinSet { addr: u64, members: u64 },
        /// A listed task whose future name contains `name`.
        Task { name: String },
        /// A held find somewhere in the frames of a task whose future
        /// name contains `task`, itself named `name` — a future inside a
        /// library's own, whose slot the fixture cannot name and whose
        /// carrier is a chain frame rather than a held find.
        HeldByTask { task: String, name: String },
    }

    /// Read the registry through any target: `None` where the target
    /// carries no registry symbol at all (any real, non-fixture
    /// target), the parsed entries otherwise. The snapshot command
    /// calls this through its `Recorder` purely for the reads it
    /// makes, which is what puts the bytes into the capture.
    pub fn read_from<T: Target>(target: &T) -> Option<Result<Vec<Expectation>>> {
        let sym = target.lookup_symbol_by_name(SYMBOL)?;
        Some(parse(target, sym.st_value))
    }

    /// Read `len` bytes at `addr` in as many pieces as the target
    /// serves them in. The registry sits at the tail of `.data`/`.bss`,
    /// so its bytes routinely straddle the boundary between the last
    /// file-backed page and the anonymous pages after it — two segments
    /// in a core, and a single `read_bytes` spanning two segments is
    /// refused whole. Chunking at `readable_len` reads what one
    /// straight read cannot, from a core and a snapshot alike.
    pub(super) fn read_run<T: Target>(target: &T, addr: u64, len: u64) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(len as usize);
        let mut cur = addr;
        while cur < addr + len {
            let n = target.readable_len(cur, addr + len - cur);
            ensure!(
                n > 0,
                "the range {cur:#x}..+{} is not mapped",
                addr + len - cur
            );
            bytes.extend_from_slice(target.read_bytes(cur, n)?);
            cur += n;
        }
        Ok(bytes)
    }

    fn parse<T: Target>(target: &T, base: u64) -> Result<Vec<Expectation>> {
        let header =
            read_run(target, base, HEADER).context("failed to read the census registry header")?;
        let committed = u64::from_le_bytes(header[..8].try_into().unwrap());
        // The write side caps at 64; anything past that is a misread.
        ensure!(
            committed <= 4096,
            "the census registry claims {committed} entries"
        );
        if committed == 0 {
            return Ok(Vec::new());
        }
        let bytes = read_run(target, base + HEADER, committed * ENTRY)
            .context("failed to read the census registry entries")?;
        let mut expectations = Vec::new();
        for entry in bytes.as_chunks::<{ ENTRY as usize }>().0 {
            let word = |at: usize| u64::from_le_bytes(entry[at..at + 8].try_into().unwrap());
            let kind = u32::from_le_bytes(entry[..4].try_into().unwrap());
            let (addr, count) = (word(8), word(16));
            let raw = &entry[NAME_AT..];
            let raw = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
            let name = std::str::from_utf8(raw)
                .context("a census registry entry's name is not UTF-8")?
                .to_string();
            expectations.push(match kind {
                1 => Expectation::Held { slot: addr, name },
                2 => Expectation::HeldIn { parent: addr, name },
                3 => Expectation::Set {
                    addr,
                    children: count,
                },
                4 => Expectation::JoinSet {
                    addr,
                    members: count,
                },
                5 => Expectation::Task { name },
                // The write side packs both names into the one name
                // field, tab-separated; no type name carries a tab.
                6 => match name.split_once('\t') {
                    Some((task, name)) => Expectation::HeldByTask {
                        task: task.to_string(),
                        name: name.to_string(),
                    },
                    None => bail!("a held-by-task registry entry names no task: {name:?}"),
                },
                other => bail!("unknown census registry entry kind {other}"),
            });
        }
        Ok(expectations)
    }

    /// The registry ladder — present, parses, non-empty — plus the
    /// both-direction [`diff`], as problems. Callers are fixtures that
    /// register by contract, so a missing or empty registry is a
    /// problem, not a skip; a target legitimately without a registry
    /// (a real core) simply never asks.
    #[must_use]
    pub fn problems<T: Target>(
        target: &T,
        view: BundleView<'_>,
        census: &FutureCensus,
        list: &TaskList,
    ) -> Vec<String> {
        match read_from(target) {
            None => vec!["the capture carries no census registry symbol".into()],
            Some(Err(e)) => vec![format!("the registry does not parse: {e:#}")],
            Some(Ok(expected)) if expected.is_empty() => {
                vec!["the registry is empty; every registering fixture registers".into()]
            }
            Some(Ok(expected)) => diff(&expected, view, census, list),
        }
    }

    /// Diff a census (and the task listing it was built from) against
    /// what the fixture registered, both directions: a registered item
    /// with no matching row is an omission unless an error names its
    /// address, and a held/set/join-set row nothing registered is a
    /// fabrication — the fixtures register exhaustively, so the
    /// per-kind populations must match one for one. Task expectations
    /// are one-directional: each registered name must be a listed
    /// task, but unregistered tasks (the runtime's own machinery) are
    /// nobody's business. One line per problem; empty is clean.
    pub fn diff(
        expected: &[Expectation],
        view: BundleView<'_>,
        census: &FutureCensus,
        list: &TaskList,
    ) -> Vec<String> {
        let name_of = |id| view.ty(id).map_or("<unknown>", |ty| ty.name());
        let mut v = Vec::new();
        let errors: Vec<String> = census.errors.iter().map(|e| format!("{e:#}")).collect();
        let excused = |addr: u64| {
            errors
                .iter()
                .any(|text| crate::tokio::census::names_address(text, addr))
        };

        let mut held_claimed = vec![false; census.held.len()];
        let mut set_claimed = vec![false; census.sets.len()];
        let mut join_claimed = vec![false; census.join_sets.len()];
        let mut tasks_wanted: BTreeMap<&str, usize> = BTreeMap::new();

        for expectation in expected {
            match expectation {
                Expectation::Held { slot, name } => {
                    let row = census
                        .held
                        .iter()
                        .enumerate()
                        .find(|(i, h)| !held_claimed[*i] && h.slot == *slot);
                    match row {
                        Some((i, h)) => {
                            held_claimed[i] = true;
                            if !name_of(h.future).contains(name) {
                                v.push(format!(
                                    "the held find at {slot:#x} is `{}`, \
                                     not the registered `{name}`",
                                    name_of(h.future)
                                ));
                            }
                        }
                        None if excused(*slot) => {}
                        None => v.push(format!(
                            "registered held future `{name}` at {slot:#x} \
                             has no census row and no error names it"
                        )),
                    }
                }
                Expectation::HeldIn { parent, name } => {
                    let Some(p) = census.held.iter().position(|h| h.slot == *parent) else {
                        if !excused(*parent) {
                            v.push(format!(
                                "registered carried future `{name}`: no held \
                                 find at its carrier's slot {parent:#x}"
                            ));
                        }
                        continue;
                    };
                    let row = census.held.iter().enumerate().find(|(i, h)| {
                        !held_claimed[*i]
                            && h.via == Some(Via::Held(p))
                            && name_of(h.future).contains(name)
                    });
                    match row {
                        Some((i, _)) => held_claimed[i] = true,
                        None => v.push(format!(
                            "registered carried future `{name}` was not found \
                             via the held find at {parent:#x}"
                        )),
                    }
                }
                Expectation::HeldByTask { task, name } => {
                    let owned_by = |h: &crate::tokio::census::HeldFuture| {
                        matches!(&list.tasks[h.owner].future,
                            FutureInfo::Known(k) if k.name(view).contains(task))
                    };
                    let row = census.held.iter().enumerate().find(|(i, h)| {
                        !held_claimed[*i] && owned_by(h) && name_of(h.future).contains(name)
                    });
                    match row {
                        Some((i, _)) => held_claimed[i] = true,
                        None => v.push(format!(
                            "registered future `{name}` was not found held by a \
                             task named `{task}`"
                        )),
                    }
                }
                Expectation::Set { addr, children } => {
                    let row = census
                        .sets
                        .iter()
                        .enumerate()
                        .find(|(i, s)| !set_claimed[*i] && s.addr == *addr);
                    match row {
                        Some((i, s)) => {
                            set_claimed[i] = true;
                            if s.children.len() as u64 != *children && !excused(*addr) {
                                v.push(format!(
                                    "the set at {addr:#x} lists {} children \
                                     against the registered {children}",
                                    s.children.len()
                                ));
                            }
                        }
                        None if excused(*addr) => {}
                        None => v.push(format!(
                            "registered set at {addr:#x} has no census row \
                             and no error names it"
                        )),
                    }
                }
                Expectation::JoinSet { addr, members } => {
                    let row = census
                        .join_sets
                        .iter()
                        .enumerate()
                        .find(|(i, s)| !join_claimed[*i] && s.addr == *addr);
                    match row {
                        Some((i, s)) => {
                            join_claimed[i] = true;
                            if s.children.len() as u64 != *members && !excused(*addr) {
                                v.push(format!(
                                    "the join set at {addr:#x} lists {} members \
                                     against the registered {members}",
                                    s.children.len()
                                ));
                            }
                        }
                        None if excused(*addr) => {}
                        None => v.push(format!(
                            "registered join set at {addr:#x} has no census \
                             row and no error names it"
                        )),
                    }
                }
                Expectation::Task { name } => *tasks_wanted.entry(name).or_default() += 1,
            }
        }

        for (name, wanted) in tasks_wanted {
            let listed = list
                .tasks
                .iter()
                .filter(
                    |t| matches!(&t.future, FutureInfo::Known(k) if k.name(view).contains(name)),
                )
                .count();
            if listed < wanted {
                v.push(format!(
                    "{wanted} task(s) registered as `{name}`, but the listing shows {listed}"
                ));
            }
        }

        for (i, h) in census.held.iter().enumerate() {
            if !held_claimed[i] {
                v.push(format!(
                    "unregistered held find `{}` (local `{}`) at slot {:#x}",
                    name_of(h.future),
                    h.local,
                    h.slot
                ));
            }
        }
        for (i, s) in census.sets.iter().enumerate() {
            if !set_claimed[i] {
                v.push(format!(
                    "unregistered set `{}` (local `{}`) at {:#x}",
                    name_of(s.ty),
                    s.local,
                    s.addr
                ));
            }
        }
        for (i, s) in census.join_sets.iter().enumerate() {
            if !join_claimed[i] {
                v.push(format!(
                    "unregistered join set `{}` (local `{}`) at {:#x}",
                    name_of(s.ty),
                    s.local,
                    s.addr
                ));
            }
        }
        v
    }
}

/// The io registry's discovery candidates, before the identification
/// chain takes them.
///
/// A `ScheduledIo` holds wakers in three places, and every candidate a
/// fixture's set produces dedups to that one set — so discovery's own
/// output cannot tell the three apart, and only counting what the
/// harvest yielded says whether all three were read.
pub fn io_candidates<T: Target>(ctx: &Context<'_, T>, target: &T) -> Vec<u64> {
    let lwps = target.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");
    let (found, errors) = ctx.io_task_pointers(
        &runtimes,
        &mut foldhash::HashSet::default(),
        &mut Registries::default(),
    );
    assert!(errors.is_empty(), "{errors:?}");
    found
        .iter()
        .map(|candidate| candidate.addr())
        .filter(|addr| !list.contains(*addr))
        .collect()
}

/// The `test-programs/matrix.toml` manifest: the supported-versions
/// statement the version matrix enumerates cells from, and where the
/// fixture suites read the tokio floor. (`matrix.sh` keeps its own awk
/// parse of the same file — bash cannot link this one.)
pub use testrun::fixture as matrix;

/// Test doubles for the registry reader, shared with the census's own
/// test module (which pins the problem lists over hand-built censuses
/// and needs a target to point them at).
#[cfg(test)]
pub(crate) mod fake {
    use super::expect::SYMBOL;

    use proc::{Regs, SymbolBuf, Target};

    /// A target serving one run of bytes at `base`, with the registry
    /// symbol pointing at it (or absent). A `seam` splits the run in
    /// two the way a core's segment boundary does: a read crossing it
    /// is refused whole, and `readable_len` stops at it — which is
    /// what forces the reader through its chunking path.
    pub(crate) struct FakeTarget {
        pub(crate) base: u64,
        pub(crate) bytes: Vec<u8>,
        pub(crate) has_symbol: bool,
        pub(crate) seam: Option<u64>,
    }

    impl Target for FakeTarget {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            if let Some(seam) = self.seam
                && addr < seam
                && addr + len > seam
            {
                return Err(proc::Error::unmapped(addr, len));
            }
            let start = addr
                .checked_sub(self.base)
                .filter(|&s| s + len <= self.bytes.len() as u64)
                .ok_or_else(|| proc::Error::unmapped(addr, len))?;
            Ok(&self.bytes[start as usize..(start + len) as usize])
        }

        fn readable_len(&self, addr: u64, max: u64) -> u64 {
            match self.seam {
                Some(seam) if addr < seam => (seam - addr).min(max),
                _ => max,
            }
        }

        fn lookup_symbol_by_addr(&self, _: u64) -> Option<SymbolBuf> {
            None
        }

        fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
            (self.has_symbol && (name == SYMBOL || name == super::delegation::SYMBOL)).then(|| {
                SymbolBuf {
                    name: name.to_string(),
                    st_name: 0,
                    st_info: 0,
                    st_other: 0,
                    st_shndx: 0,
                    st_value: self.base,
                    st_size: self.bytes.len() as u64,
                }
            })
        }

        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            Ok(Vec::new())
        }

        fn mappings(&self) -> proc::Result<proc::Mappings> {
            unimplemented!("the registry reader never asks")
        }

        fn lwps(&self) -> proc::Result<Vec<proc::LwpInfo>> {
            unimplemented!("the registry reader never asks")
        }

        fn tls_var_addr(&self, _: &Regs, _: &SymbolBuf) -> proc::Result<Option<u64>> {
            unimplemented!("the registry reader never asks")
        }
    }

    /// The write side's layout, laid by hand: `committed`/`reserved`
    /// words, then 88-byte entries of `kind, flags, addr, count,
    /// name[64]`.
    pub(crate) fn registry(entries: &[(u32, u64, u64, &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend((entries.len() as u64).to_le_bytes());
        bytes.extend((entries.len() as u64).to_le_bytes());
        for &(kind, addr, count, name) in entries {
            bytes.extend(kind.to_le_bytes());
            bytes.extend(0u32.to_le_bytes());
            bytes.extend(addr.to_le_bytes());
            bytes.extend(count.to_le_bytes());
            let mut padded = [0u8; 64];
            padded[..name.len()].copy_from_slice(name.as_bytes());
            bytes.extend(padded);
        }
        bytes
    }
}

// The registry *parser* is pinned here, over hand-laid bytes spelling
// the write side's layout; the diff and the problem lists are pinned
// in the census's own tests, which can build a `FutureCensus` by
// hand. The offline registry test only ever shows both passing.
#[cfg(test)]
mod tests {
    use super::expect::{Expectation, read_from};
    use super::fake::{FakeTarget, registry};

    #[test]
    fn test_a_target_without_the_symbol_has_no_registry() {
        let target = FakeTarget {
            base: 0x1000,
            bytes: registry(&[]),
            has_symbol: false,
            seam: None,
        };
        assert!(read_from(&target).is_none());
    }

    #[test]
    fn test_an_empty_registry_parses_to_nothing() {
        let target = FakeTarget {
            base: 0x1000,
            bytes: registry(&[]),
            has_symbol: true,
            seam: None,
        };
        let parsed = read_from(&target).expect("the symbol resolves").unwrap();
        assert_eq!(parsed, Vec::new());
    }

    #[test]
    fn test_every_entry_kind_parses() {
        let target = FakeTarget {
            base: 0x1000,
            bytes: registry(&[
                (1, 0x100, 0, "held_name"),
                (2, 0x200, 0, "carried"),
                (3, 0x300, 4, ""),
                (4, 0x400, 2, ""),
                (5, 0, 0, "task_name"),
            ]),
            has_symbol: true,
            seam: None,
        };
        let parsed = read_from(&target).expect("the symbol resolves").unwrap();
        assert_eq!(
            parsed,
            [
                Expectation::Held {
                    slot: 0x100,
                    name: "held_name".to_string(),
                },
                Expectation::HeldIn {
                    parent: 0x200,
                    name: "carried".to_string(),
                },
                Expectation::Set {
                    addr: 0x300,
                    children: 4,
                },
                Expectation::JoinSet {
                    addr: 0x400,
                    members: 2,
                },
                Expectation::Task {
                    name: "task_name".to_string(),
                },
            ]
        );
    }

    /// The registry read straddling a segment boundary — the `.bss`
    /// tail of a real core, where the entries run past the last
    /// file-backed page into anonymous memory. A whole-run read is
    /// refused there, so the reader has to chunk at `readable_len`
    /// and reassemble the pieces in order.
    #[test]
    fn test_a_registry_straddling_a_segment_seam_reads_whole() {
        let bytes = registry(&[(1, 0x100, 0, "held_name"), (5, 0, 0, "task_name")]);
        // Down the middle of the first entry, nowhere near a chunk
        // edge of the reader's own making.
        let seam: u64 = 0x1000 + 16 + 40;
        assert!(seam - 0x1000 < bytes.len() as u64);
        let target = FakeTarget {
            base: 0x1000,
            bytes,
            has_symbol: true,
            seam: Some(seam),
        };
        let parsed = read_from(&target).expect("the symbol resolves").unwrap();
        assert_eq!(
            parsed,
            [
                Expectation::Held {
                    slot: 0x100,
                    name: "held_name".to_string(),
                },
                Expectation::Task {
                    name: "task_name".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_a_corrupt_registry_is_an_error_not_a_guess() {
        let unknown_kind = FakeTarget {
            base: 0x1000,
            bytes: registry(&[(9, 0, 0, "")]),
            has_symbol: true,
            seam: None,
        };
        let err = read_from(&unknown_kind)
            .expect("the symbol resolves")
            .unwrap_err();
        assert!(err.to_string().contains("kind 9"), "{err:#}");

        // A committed count pointing past the readable bytes fails the
        // read rather than serving garbage.
        let mut bytes = registry(&[]);
        bytes[..8].copy_from_slice(&3u64.to_le_bytes());
        let truncated = FakeTarget {
            base: 0x1000,
            bytes,
            has_symbol: true,
            seam: None,
        };
        assert!(read_from(&truncated).expect("the symbol resolves").is_err());
    }

    /// The manifest parse, over the real manifest. The exact versions
    /// are the manifest's to choose, so this pins consistency rather
    /// than values: every version another field's role can resolve to
    /// must be in the axis that is actually there, and the `[cells]`
    /// role lists must survive the parse non-empty (the matrix suite,
    /// which would notice them dropped, is opt-in).
    #[test]
    fn test_the_matrix_manifest_parses_consistently() {
        let m = super::matrix::Matrix::load();
        assert!(
            m.tokio.versions.contains(&m.tokio.floor),
            "the floor {} is not in the tokio versions",
            m.tokio.floor
        );
        assert!(
            m.tokio.versions.contains(&m.primary.tokio),
            "the primary tokio {} is not in the tokio versions",
            m.primary.tokio
        );
        assert!(
            m.toolchain.versions.contains(&m.primary.toolchain),
            "the primary toolchain {} is not in the toolchain versions",
            m.primary.toolchain
        );
        for (name, list) in [
            ("no_unstable_tokio", &m.cells.no_unstable_tokio),
            (
                "secondary_toolchain_tokio",
                &m.cells.secondary_toolchain_tokio,
            ),
            ("ct_only_tokio", &m.cells.ct_only_tokio),
        ] {
            assert!(!list.is_empty(), "[cells] {name} parsed to nothing");
        }
        assert_eq!(super::matrix::floor(), m.tokio.floor);
    }
}

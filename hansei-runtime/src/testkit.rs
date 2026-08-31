//! Test-only helpers over the checked-in fixture pairs in
//! `tests/fixtures/<set>/`: the load-and-attach chain that this crate's
//! offline suites and hansei's unit tests otherwise each re-spell.
//! Nothing on a session's path calls this. See [`FIXTURE_SET`] for why
//! there is more than one set.

use crate::tokio::bundle::{Context, LocalSetRef, Registries, RuntimeRef, TaskList, Worker};
use crate::tokio::census::FutureCensus;

use anyhow::Context as _;
use hansei_bundle::{Bundle, BundleView};
use proc::snapshot::Snapshot;
use proc::{LwpInfo, Target};

use std::path::PathBuf;

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
];

/// Mask the run-varying values analysis output carries — heap
/// addresses and timer deadlines (relative to the stop instant, so
/// they shift with how long the capture took) — so goldens over the
/// pairs compare exactly.
pub fn mask(s: &str) -> String {
    let addrs = regex::Regex::new(r"0x[0-9a-f]+").unwrap();
    let deadlines = regex::Regex::new(r"deadline \+?\d+\.\d{3}s").unwrap();
    let overdue = regex::Regex::new(r"overdue by \d+\.\d{3}s").unwrap();
    overdue
        .replace_all(
            &deadlines.replace_all(&addrs.replace_all(s, "0xADDR"), "deadline TS"),
            "overdue by TS",
        )
        .into_owned()
}

/// Load a program's pair from whichever set, for a test that wants
/// some real capture to work with rather than every capture there is.
///
/// The choice is arbitrary and fixed — not the host's, which is the
/// point: a test reading this is testing what it does with a pair, and
/// two sets would only run it twice. A test whose subject *is* the
/// capture walks [`FIXTURE_SETS`] instead.
pub fn load_any(program: &str) -> (Bundle, Snapshot) {
    load(FIXTURE_SETS[0], program)
}

/// Load a program's fixture pair from `set`.
pub fn load(set: &str, program: &str) -> (Bundle, Snapshot) {
    let bundle = Bundle::load(&fixture(set, &format!("{program}.tinfo")))
        .expect("fixture tokio info loads; regenerate with capture-snapshots.sh");
    let snapshot = Snapshot::load(&fixture(set, &format!("{program}.snapshot")))
        .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
    (bundle, snapshot)
}

/// Attach a loaded pair the way a session does.
pub fn context<'a>(bundle: &'a Bundle, snapshot: &'a Snapshot) -> Context<'a, Snapshot> {
    Context::new(snapshot, BundleView::new(bundle)).expect("snapshot has mappings")
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
    Ok(Enumeration {
        lwps,
        workers,
        runtimes,
        list,
        registries: Registries::default(),
    })
}

impl<'b> Enumeration<'b> {
    /// Run hidden-task discovery — the sweep `discover_hidden_tasks`
    /// performs — mutating the runtimes and list the way a session
    /// does, and returning the local sets it admitted.
    pub fn discover<T: Target>(
        &mut self,
        ctx: &Context<'b, T>,
        exclude: &[u64],
    ) -> Vec<LocalSetRef<'b>> {
        let (sets, registries) = ctx.discover_hidden_tasks(
            &self.lwps,
            &self.workers,
            &mut self.runtimes,
            exclude,
            &mut self.list,
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
pub struct Run<'a> {
    pub ctx: Context<'a, Snapshot>,
    pub list: TaskList,
    pub census: FutureCensus,
}

/// Run the pipeline over a loaded pair.
pub fn run<'a>(bundle: &'a Bundle, snapshot: &'a Snapshot) -> Run<'a> {
    let ctx = context(bundle, snapshot);
    let list = tasks(&ctx, snapshot);
    let census = census(&ctx, &list);
    Run { ctx, list, census }
}

impl Run<'_> {
    /// [`healthy_problems`] over this run.
    #[must_use]
    pub fn healthy_problems(&self) -> Vec<String> {
        healthy_problems(&self.census, &self.list)
    }

    /// [`expect::problems`] over this run.
    #[must_use]
    pub fn registry_problems(&self) -> Vec<String> {
        expect::problems(self.ctx.proc, &self.census, &self.list)
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

/// The future census over an enumerated list, held to its construction
/// rules: the total audit invariants hold over any input whatsoever, so
/// every test census — healthy pair and fault campaign alike — runs
/// through here. Errors and caps come back intact; a test over a
/// healthy pair asserts on those (and the healthy-only audit) itself.
pub fn census<T: Target>(
    ctx: &Context<'_, T>,
    list: &TaskList,
) -> crate::tokio::census::FutureCensus {
    let census = crate::tokio::census::census(ctx, list);
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
    fn read_run<T: Target>(target: &T, addr: u64, len: u64) -> Result<Vec<u8>> {
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
        for entry in bytes.chunks_exact(ENTRY as usize) {
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
    pub fn problems<T: Target>(target: &T, census: &FutureCensus, list: &TaskList) -> Vec<String> {
        match read_from(target) {
            None => vec!["the capture carries no census registry symbol".into()],
            Some(Err(e)) => vec![format!("the registry does not parse: {e:#}")],
            Some(Ok(expected)) if expected.is_empty() => {
                vec!["the registry is empty; every registering fixture registers".into()]
            }
            Some(Ok(expected)) => diff(&expected, census, list),
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
    pub fn diff(expected: &[Expectation], census: &FutureCensus, list: &TaskList) -> Vec<String> {
        let mut v = Vec::new();
        let errors: Vec<String> = census.errors.iter().map(|e| format!("{e:#}")).collect();
        let excused = |addr: u64| {
            errors
                .iter()
                .any(|text| text.contains(&format!("{addr:#x}")))
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
                            if !h.future.contains(name) {
                                v.push(format!(
                                    "the held find at {slot:#x} is `{}`, \
                                     not the registered `{name}`",
                                    h.future
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
                        !held_claimed[*i] && h.via == Some(Via::Held(p)) && h.future.contains(name)
                    });
                    match row {
                        Some((i, _)) => held_claimed[i] = true,
                        None => v.push(format!(
                            "registered carried future `{name}` was not found \
                             via the held find at {parent:#x}"
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
                    |t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)),
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
                    h.future, h.local, h.slot
                ));
            }
        }
        for (i, s) in census.sets.iter().enumerate() {
            if !set_claimed[i] {
                v.push(format!(
                    "unregistered set `{}` (local `{}`) at {:#x}",
                    s.ty, s.local, s.addr
                ));
            }
        }
        for (i, s) in census.join_sets.iter().enumerate() {
            if !join_claimed[i] {
                v.push(format!(
                    "unregistered join set `{}` (local `{}`) at {:#x}",
                    s.ty, s.local, s.addr
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
pub fn io_candidates<T: Target>(ctx: &Context<'_, T>, snapshot: &Snapshot) -> Vec<u64> {
    let lwps = snapshot.lwps().unwrap();
    let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
    let runtimes = ctx.find_runtimes(&workers).expect("a tokio runtime");
    let list = ctx
        .enumerate_all_tasks(&runtimes)
        .expect("the owned-task walk");
    let (found, errors) = ctx.io_task_pointers(&runtimes, &list, &mut Registries::default());
    assert!(errors.is_empty(), "{errors:?}");
    found.into_iter().map(|(addr, _)| addr).collect()
}

/// The `test-programs/matrix.toml` manifest: the supported-versions
/// statement the version matrix enumerates cells from, and where the
/// fixture suites read the tokio floor. (`matrix.sh` keeps its own awk
/// parse of the same file — bash cannot link this one.)
pub mod matrix {
    use serde::Deserialize;

    use std::path::PathBuf;

    /// What `matrix.toml` declares, in the file's own shape. Unknown
    /// keys are refused everywhere: the manifest is the contract
    /// tooling enumerates cells from, and a key only some of its
    /// readers know about is drift.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Matrix {
        pub primary: Primary,
        pub tokio: Axis,
        pub toolchain: Axis,
        pub cells: Cells,
    }

    /// The `primary` cell: what `test-programs/Cargo.lock` resolves,
    /// on the default toolchain.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Primary {
        pub tokio: String,
        pub toolchain: String,
    }

    /// One version axis: its floor and every version it supports.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Axis {
        pub floor: String,
        pub versions: Vec<String>,
    }

    /// The `[cells]` trim policy: which tokio versions (or roles —
    /// `floor`, `primary`, `latest`) each secondary axis covers.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Cells {
        pub no_unstable_tokio: Vec<String>,
        pub secondary_toolchain_tokio: Vec<String>,
        pub ct_only_tokio: Vec<String>,
    }

    impl Matrix {
        pub fn load() -> Matrix {
            let path =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-programs/matrix.toml");
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            toml::from_str(&text)
                .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
        }
    }

    /// `matrix.toml`'s `[tokio]` floor, the version the endpoint
    /// fixture sets pin.
    pub fn floor() -> String {
        Matrix::load().tokio.floor
    }
}

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
            (self.has_symbol && name == SYMBOL).then(|| SymbolBuf {
                name: name.to_string(),
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: self.base,
                st_size: self.bytes.len() as u64,
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

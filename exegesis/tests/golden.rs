//! Extraction golden tests: run `extract` on the
//! test-programs fixtures and compare a textual summary against checked-in
//! expectations.
//!
//! Fixtures are never checked in: missing ones are built on demand by
//! `test-programs/regen.sh` with the pinned bundle-compatible toolchain;
//! when that toolchain is unavailable the tests skip with a message.
//! Because fixtures are always freshly built, these tests double as the
//! canary for DWARF-shape and mangling drift across toolchain bumps.
//!
//! The summaries contain only platform-portable facts — demangled type
//! names, variant shapes, await-point lines, presence of infra/statics —
//! and are filtered to the fixture crate's own types, so one golden file
//! serves macOS and illumos. Regenerate with `EXEGESIS_BLESS=1 cargo test
//! -p exegesis --test golden`.

use exegesis::bundle::{Bundle, DisplayNode, MemberRef, Step, TypeDef, WalkOutcome, WalkRole};
use exegesis::describe::describe_debug_format;
use exegesis::extract::{ExtractOptions, ExtractStats, extract_file};
use exegesis::summary::{portable_summary, walk_entry_line};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const TOOLCHAIN: &str = "1.97.1";

fn test_programs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-programs")
}

/// The file `extract` should read for a fixture: the binary itself on
/// ELF platforms, the dSYM DWARF on macOS.
fn dwarf_path(program: &str) -> PathBuf {
    let bin = test_programs_dir().join("fixtures/bin").join(program);
    let dsym = bin
        .with_extension("dSYM")
        .join("Contents/Resources/DWARF")
        .join(program);
    if dsym.exists() { dsym } else { bin }
}

/// Put the fixture in the state its sources describe. Returns `false`
/// (skip) when the pinned toolchain is not installed; panics on real
/// build failures.
///
/// The fixture is rebuilt every run rather than kept if it happens to
/// exist. `test-programs/fixtures/` is gitignored, so a checkout that
/// changes a fixture's source leaves the previous build sitting there,
/// and a golden then describes a program that no longer exists — a
/// stale binary reads as line-number drift and has twice been blessed
/// into a golden as if it were the truth. `regen.sh` is a `cargo build`,
/// which decides for itself whether anything has to be compiled, so
/// asking every time costs nothing when nothing changed.
///
/// Once per run, though, not once per test: several tests share a fixture
/// (`test_extraction_is_reproducible` and `test_golden_select_combinator`
/// both read `select-combinator`), extraction *mmaps* the DWARF, and
/// `regen.sh` reinstalls it. Rebuilding on every call let one test's
/// rebuild land in the middle of another test's parse. Building each
/// program at most once keeps the anti-staleness property — a run still
/// rebuilds everything it reads — without rewriting a file some other
/// test is holding open.
fn ensure_fixture(program: &str) -> bool {
    // Also serializes the builds themselves, which would otherwise
    // contend on the fixture target dir.
    static BUILT: Mutex<BTreeMap<String, bool>> = Mutex::new(BTreeMap::new());
    let mut built = BUILT.lock().unwrap();
    if let Some(&usable) = built.get(program) {
        return usable;
    }
    let usable = build_fixture(program);
    built.insert(program.to_string(), usable);
    usable
}

/// Build one fixture, reporting whether it can be tested against. Call
/// [`ensure_fixture`] instead, which does this once per program.
fn build_fixture(program: &str) -> bool {
    if !toolchain_installed() {
        // Nothing can be built, so whatever is on disk is all there is.
        // It may be stale, which is still better than no coverage — the
        // failure it can cause is a loud golden diff, not a wrong pass.
        if dwarf_path(program).exists() {
            eprintln!(
                "warning: toolchain {TOOLCHAIN} not installed; testing against \
                 the {program} fixture already built"
            );
            return true;
        }
        eprintln!(
            "SKIP: fixture {program} missing and toolchain {TOOLCHAIN} not installed \
             (rustup toolchain install {TOOLCHAIN})"
        );
        return false;
    }

    let status = Command::new(test_programs_dir().join("regen.sh"))
        .arg(program)
        .status()
        .expect("failed to run regen.sh");
    assert!(status.success(), "regen.sh failed for {program}");
    assert!(
        dwarf_path(program).exists(),
        "regen.sh succeeded but {program} fixture is still missing"
    );
    true
}

fn toolchain_installed() -> bool {
    Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
        .lines()
        .any(|l| l.starts_with(TOOLCHAIN))
}

/// Assert no display program reaches a member by its position.
///
/// A name survives the member-list rewriting extraction does after programs are
/// attached; a position does not. Only a member no name can select may be
/// addressed positionally — an unnamed one, or one of several sharing a name —
/// and no fixture has either, so any positional address here is a detector that
/// recorded where it found something instead of what it found.
///
/// This reuses `describe_debug_format` rather than walking the tree again, so a
/// new node kind is covered as soon as the summary learns to print it.
fn assert_addresses_by_name(program: &str, bundle: &Bundle) {
    let positional: Vec<String> = bundle
        .types
        .debug_formats
        .iter()
        .map(|(id, node)| describe_debug_format(bundle, *id, node))
        .filter(|rendered| rendered.contains('%'))
        .collect();
    assert!(
        positional.is_empty(),
        "{program}: {} display program(s) address a member by position:\n{}",
        positional.len(),
        positional.join("\n"),
    );

    // The same doctrine for walk bindings: a recorded step may address a
    // member by position only when no name can select it, and no walked
    // tokio layout has such a member.
    use exegesis::bundle::{MemberRef, Step};
    let positional_walks: Vec<&str> = bundle
        .walks
        .entries
        .iter()
        .filter(|(_, binding)| {
            binding
                .steps
                .iter()
                .any(|step| matches!(step, Step::Member(MemberRef::Index(_))))
        })
        .map(|(role, _)| role.name())
        .collect();
    assert!(
        positional_walks.is_empty(),
        "{program}: walk binding(s) address a member by position: {}",
        positional_walks.join(", "),
    );
}

/// Assert that the debug format on the type named exactly `type_name` resolves
/// to `expected` (as rendered by [`describe_debug_format`]). This is the
/// resolved-path check: it fails not only when a detector never fires but when
/// it fires and navigates to the wrong member — a valid-but-wrong path after a
/// toolchain or tokio/std layout shift, which a presence-only assertion
/// misses.
///
/// Asserting on a *named* type (rather than dumping every format present) is
/// what keeps this portable: the set of types a build instantiates differs by
/// platform, but a specific named type resolves identically on every LP64
/// target, so one assertion serves macOS and illumos. On a mismatch the panic
/// prints the actual render, so re-blessing after an intended layout change is
/// a copy-paste.
fn assert_format(program: &str, bundle: &Bundle, type_name: &str, expected: &str) {
    let rendered = bundle
        .types
        .find_by_name(&bundle.strings, type_name)
        .find_map(|id| {
            bundle
                .types
                .debug_formats
                .get(&id)
                .map(|node| describe_debug_format(bundle, id, node))
        });
    match rendered {
        Some(rendered) => assert_eq!(
            rendered, expected,
            "{program}: debug format for {type_name} resolved to an unexpected path"
        ),
        None => panic!("{program}: no `Known` debug format was extracted for {type_name}"),
    }
}

/// The member-name chain a walk row bound to, in `--explain-walk`'s
/// spelling.
///
/// This is [`assert_format`]'s sibling for the walk contract: the
/// portable summary and the matrix goldens say only that a row bound,
/// which a row navigating to the wrong member satisfies just as well.
/// Names rather than offsets because names are what the contract pins —
/// offsets move between tokio versions and between platforms, the chain
/// does not.
fn walk_path(program: &str, bundle: &Bundle, role: WalkRole) -> String {
    let binding = &bundle.walks.entries[&role];
    assert!(
        matches!(binding.outcome, WalkOutcome::Bound { .. }),
        "{program}: {} did not bind: {:?}",
        role.name(),
        binding.outcome
    );
    let s = |name| bundle.strings.get(name).unwrap_or("<bad strref>");
    binding
        .steps
        .iter()
        .map(|step| match step {
            Step::Member(MemberRef::Named(name)) => s(*name).to_owned(),
            Step::Member(MemberRef::Index(index)) => format!("#{index}"),
            Step::Variant(name) => format!("<{}>", s(*name)),
            Step::ActiveVariant => "<active variant>".to_owned(),
            Step::Deref => "*".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn assert_walk(program: &str, bundle: &Bundle, role: WalkRole, expected: &str) {
    assert_eq!(
        walk_path(program, bundle, role),
        expected,
        "{program}: {} bound to an unexpected path",
        role.name()
    );
}

/// Structural assertions that hold for every fixture — the "zero silent
/// drops" checks plus metadata sanity.
fn assert_clean(program: &str, bundle: &Bundle, stats: &ExtractStats) {
    assert_addresses_by_name(program, bundle);
    // Every tokio target has a scheduler owned list, so its id binds
    // everywhere. The summary says only that it did; this says it
    // landed beside `owned.list` rather than on some other counter.
    // The tail is the `NonZeroU64` the peel to a word crosses.
    assert_walk(
        program,
        bundle,
        WalkRole::SchedulerOwnedId,
        "owned.id.__0.__0",
    );
    assert_eq!(stats.cells_missing, 0, "{program}: cells missing");
    assert_eq!(stats.stages_missing, 0, "{program}: stages missing");
    assert_eq!(
        stats.vtable_missing_linkage, 0,
        "{program}: vtable fns without linkage names"
    );
    assert_eq!(
        stats.dyn_unresolved_self, 0,
        "{program}: Future::poll impls with unresolvable self"
    );
    assert!(
        stats.infra_missing.is_empty(),
        "{program}: {:?}",
        stats.infra_missing
    );
    assert!(
        stats.statics_missing.is_empty(),
        "{program}: {:?}",
        stats.statics_missing
    );

    assert!(
        bundle.meta.rustc_version.contains(TOOLCHAIN),
        "{program}: unexpected rustc version {:?}",
        bundle.meta.rustc_version
    );
    assert!(
        bundle.meta.tokio_version.is_some(),
        "{program}: tokio version not recovered"
    );
    assert!(
        !bundle.meta.symbol_fingerprint.is_empty(),
        "{program}: empty symbol fingerprint"
    );
    // Fingerprint symbols are poll instantiations, stored unsuffixed.
    for sym in &bundle.meta.symbol_fingerprint {
        assert!(
            sym.starts_with("_R"),
            "{program}: non-v0 fingerprint {sym:?}"
        );
    }
    assert!(
        bundle.types.debug_formats.values().any(|node| matches!(
            node,
            DisplayNode::Alias {
                follow_pointers: true,
                ..
            }
        )),
        "{program}: no following alias formats were extracted"
    );
    assert!(
        bundle.types.debug_formats.iter().any(|(id, format)| {
            matches!(
                format,
                DisplayNode::Alias {
                    follow_pointers: true,
                    ..
                }
            ) && match &bundle.types.types[id.0 as usize] {
                TypeDef::Struct { name, .. } => bundle
                    .strings
                    .get(*name)
                    .is_some_and(|name| name.starts_with("core::ptr::non_null::NonNull<")),
                _ => false,
            }
        }),
        "{program}: no transparent NonNull format was extracted"
    );
    for prefix in [
        "tokio::loom::std::unsafe_cell::UnsafeCell<",
        "tokio::loom::std::atomic_",
    ] {
        assert!(
            bundle.types.debug_formats.iter().any(|(id, format)| {
                matches!(
                    format,
                    DisplayNode::Alias {
                        follow_pointers: true,
                        ..
                    }
                ) && match &bundle.types.types[id.0 as usize] {
                    TypeDef::Struct { name, .. } => bundle
                        .strings
                        .get(*name)
                        .is_some_and(|name| name.starts_with(prefix)),
                    _ => false,
                }
            }),
            "{program}: no transparent {prefix} format was extracted"
        );
    }
    assert!(
        bundle.types.debug_formats.values().any(|format| matches!(
            format,
            DisplayNode::Alias {
                follow_pointers: false,
                ..
            }
        )),
        "{program}: no atomic alias-node formats were extracted"
    );
    assert!(
        bundle
            .types
            .debug_formats
            .values()
            .any(|format| matches!(format, DisplayNode::Symbol { .. })),
        "{program}: no function-pointer symbol-node formats were extracted"
    );
    assert!(
        bundle
            .types
            .debug_formats
            .values()
            .any(|format| matches!(format, DisplayNode::DynPointer { .. })),
        "{program}: no dyn-pointer nodes were extracted"
    );
    assert_format(
        program,
        bundle,
        "core::task::wake::RawWakerVTable",
        "core::task::wake::RawWakerVTable :: Node Struct \
         { clone: Symbol { clone@+0 }, wake: Symbol { wake@+8 }, \
         wake_by_ref: Symbol { wake_by_ref@+16 }, drop: Symbol { drop@+24 } }",
    );
    // Every tokio fixture reaches the runtime handle, and its insides are
    // never what a session is after, so the bundle hides them.
    assert_format(
        program,
        bundle,
        "tokio::runtime::handle::Handle",
        "tokio::runtime::handle::Handle :: Node Elided",
    );
    // The scheduler::Handle enum is embedded directly in timer entries and
    // io registrations, so it hides its insides the same way.
    assert_format(
        program,
        bundle,
        "tokio::runtime::scheduler::Handle",
        "tokio::runtime::scheduler::Handle :: Node Elided",
    );
    if program == "simple-await" {
        for prefix in [
            "core::ptr::unique::Unique<",
            "core::num::niche_types::UsizeNoHighBit",
        ] {
            assert!(
                bundle.types.debug_formats.iter().any(|(id, format)| {
                    matches!(
                        format,
                        DisplayNode::Alias {
                            follow_pointers: true,
                            ..
                        }
                    ) && match &bundle.types.types[id.0 as usize] {
                        TypeDef::Struct { name, .. } => bundle
                            .strings
                            .get(*name)
                            .is_some_and(|name| name.starts_with(prefix)),
                        _ => false,
                    }
                }),
                "{program}: no transparent {prefix} format was extracted"
            );
        }
        // The container/scalar std formatters, resolved to their member
        // paths. simple-await deterministically instantiates each of these,
        // and a given named type has identical layout on every LP64 target,
        // so these renders are the same on macOS and illumos.
        assert_format(
            program,
            bundle,
            "core::net::ip_addr::Ipv4Addr",
            "core::net::ip_addr::Ipv4Addr :: Node Bytes IpAddr { octets@+0 }",
        );
        assert_format(
            program,
            bundle,
            "core::net::ip_addr::Ipv6Addr",
            "core::net::ip_addr::Ipv6Addr :: Node Bytes IpAddr { octets@+0 }",
        );
        assert_format(
            program,
            bundle,
            "alloc::vec::Vec<u32, alloc::alloc::Global>",
            "alloc::vec::Vec<u32, alloc::alloc::Global> :: Node Slice \
             { pointer=buf.inner.ptr.pointer.pointer@+8, length=len@+16, \
             capacity=buf.inner.cap.__0@+0, element=u32 }",
        );
        // A borrowed `&[T]` and a boxed `Box<[T]>` are `(ptr, len)` fat
        // pointers with no capacity — the same `Slice` node as `Vec`, minus
        // the capacity field.
        assert_format(
            program,
            bundle,
            "&[u32]",
            "&[u32] :: Node Slice { pointer=data_ptr@+0, length=length@+8, element=u32 }",
        );
        assert_format(
            program,
            bundle,
            "alloc::boxed::Box<[u32], alloc::alloc::Global>",
            "alloc::boxed::Box<[u32], alloc::alloc::Global> :: Node Slice \
             { pointer=data_ptr@+0, length=length@+8, element=u32 }",
        );
        assert_format(
            program,
            bundle,
            "&str",
            "&str :: Node Str { pointer=data_ptr@+0, length=length@+8 }",
        );
        assert_format(
            program,
            bundle,
            "alloc::string::String",
            "alloc::string::String :: Node Str \
             { pointer=vec.buf.inner.ptr.pointer.pointer@+8, length=vec.len@+16, \
             capacity=vec.buf.inner.cap.__0@+0 }",
        );
        assert_format(
            program,
            bundle,
            "alloc::collections::btree::map::BTreeMap<u64, u32, alloc::alloc::Global>",
            "alloc::collections::btree::map::BTreeMap<u64, u32, alloc::alloc::Global> :: Node Map \
             { length=length@+16, key=u64, value=u32, entries=BTree { root=root@+0, \
             root_node=__0@+0, height=height@+8, node=node.pointer@+0, \
             leaf=alloc::collections::btree::node::LeafNode<u64, u32>, leaf_len=len@+142, \
             leaf_keys=keys@+8, leaf_values=vals@+96, \
             internal=alloc::collections::btree::node::InternalNode<u64, u32>, \
             internal_data=data@+0, internal_edges=edges@+144, \
             edge=value.value.__0.pointer@+0 } }",
        );
    }
    if program == "futurelock" {
        // The timer formatter behind `sleep`/`timeout`, resolved end to end:
        // the deadline tick out of the entry's `StateCell` (crossing the
        // `Option<TimerShared>` variant), and the wheel clock reached through
        // the entry's own scheduler handle — crossing the handle enum with an
        // active-variant step, so the read carries one guarded candidate per
        // scheduler flavor and the description spells both chains. A wrong
        // member anywhere on any path changes this string.
        //
        // The wheel paths cross the runtime's `driver::Handle`, whose io and
        // signal members embed OS-specific types, so — unlike every other
        // offset these asserts pin — their terminal offsets are per-platform:
        // one arm per system the suite runs on, since no two agree.
        let (ct_wheel, mt_wheel) = if cfg!(target_os = "macos") {
            (1056, 672)
        } else if cfg!(target_os = "linux") {
            (1056, 648)
        } else {
            (1040, 656)
        };
        assert_format(
            program,
            bundle,
            "tokio::runtime::time::entry::TimerEntry",
            &format!(
                "tokio::runtime::time::entry::TimerEntry :: Node Struct \
                 {{ deadline: Variant {{ discr=Read(registered@+104), \
                 arms=[0=>(Alias {{ deadline@+88, follow }})], default=Variant {{ \
                 discr=(Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) != 0xffffffffffffffff), \
                 arms=[0=>(Alias {{ deadline@+88, follow }}), 1=>(Computed(\
                 (Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) - \
                 Read(driver.{{CurrentThread}}.__0.ptr.pointer.*.data.driver.time.{{Some}}.__0.inner.\
                 {{Traditional}}.state.__1.data.value.wheel.elapsed@+{ct_wheel} | \
                 driver.{{MultiThread}}.__0.ptr.pointer.*.data.driver.time.{{Some}}.__0.inner.\
                 {{Traditional}}.state.__1.data.value.wheel.elapsed@+{mt_wheel}))))] }} }}, \
                 state: Variant {{ discr=Read(registered@+104), arms=[0=>unregistered], \
                 default=Variant {{ \
                 discr=(Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) != 0xffffffffffffffff), \
                 arms=[0=>elapsed, 1=>registered] }} }} }}"
            ),
        );
        // The `Sleep` around the entry: the same program re-rooted across the
        // `Timer` enum's `Traditional` variant.
        assert_format(
            program,
            bundle,
            "tokio::time::sleep::Sleep",
            &format!(
                "tokio::time::sleep::Sleep :: Node Struct \
                 {{ deadline: Variant {{ discr=Read(entry.{{Traditional}}.__0.registered@+104), \
                 arms=[0=>(Alias {{ entry.{{Traditional}}.__0.deadline@+88, follow }})], \
                 default=Variant {{ \
                 discr=(Read(entry.{{Traditional}}.__0.inner.{{Some}}.__0.state.state.v.value.__0@+48) \
                 != 0xffffffffffffffff), \
                 arms=[0=>(Alias {{ entry.{{Traditional}}.__0.deadline@+88, follow }}), \
                 1=>(Computed(\
                 (Read(entry.{{Traditional}}.__0.inner.{{Some}}.__0.state.state.v.value.__0@+48) - \
                 Read(entry.{{Traditional}}.__0.driver.{{CurrentThread}}.__0.ptr.pointer.*.data.\
                 driver.time.{{Some}}.__0.inner.{{Traditional}}.state.__1.data.value.wheel.elapsed\
                 @+{ct_wheel} | \
                 entry.{{Traditional}}.__0.driver.{{MultiThread}}.__0.ptr.pointer.*.data.driver.\
                 time.{{Some}}.__0.inner.{{Traditional}}.state.__1.data.value.wheel.elapsed\
                 @+{mt_wheel}))))] }} }}, \
                 state: Variant {{ discr=Read(entry.{{Traditional}}.__0.registered@+104), \
                 arms=[0=>unregistered], default=Variant {{ \
                 discr=(Read(entry.{{Traditional}}.__0.inner.{{Some}}.__0.state.state.v.value.__0@+48) \
                 != 0xffffffffffffffff), arms=[0=>elapsed, 1=>registered] }} }} }}"
            ),
        );
        // The `Instant` chain each deadline sits behind: three transparent
        // newtypes, each aliasing its sole member down to the `Timespec`.
        assert_format(
            program,
            bundle,
            "tokio::time::instant::Instant",
            "tokio::time::instant::Instant :: Node Alias { std@+0, follow }",
        );
        assert_format(
            program,
            bundle,
            "std::time::Instant",
            "std::time::Instant :: Node Alias { __0@+0, follow }",
        );
        assert_format(
            program,
            bundle,
            "std::sys::time::unix::Instant",
            "std::sys::time::unix::Instant :: Node Alias { t@+0, follow }",
        );
    }
    if program == "local-set-timer" {
        // The wheel rows root at the scheduler handles, so the portable
        // summary above already carries them; what it cannot say is
        // *where* they land, which is what a harvest walking the wrong
        // member would get wrong while still binding.
        // The middle of the wheel chain crosses whichever loom mutex the
        // build linked, whose payload member no two flavors spell alike,
        // so only the ends are pinned: from the runtime handle into the
        // time driver, and out of the guarded state onto the level
        // array. Everything below is spelled exactly.
        let levels = walk_path(program, bundle, WalkRole::WheelLevels);
        assert!(
            levels.starts_with("driver.time.<Some>.__0.inner.<Traditional>.state.")
                && levels.ends_with(".wheel.levels.*"),
            "{program}: Wheel.levels bound to an unexpected path: {levels}"
        );
        assert_walk(program, bundle, WalkRole::LevelSlots, "slot");
        assert_walk(
            program,
            bundle,
            WalkRole::SlotHead,
            "head.<Some>.__0.pointer",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::TimerSharedNext,
            "pointers.inner.value.next.<Some>.__0.pointer",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::TimerSharedWaker,
            "state.waker.waker.__0.value.<Some>.__0.waker",
        );
    }
    if program == "local-set-io" {
        // The io rows root at the scheduler handles too, so the same
        // gap applies: the summary says they bound, not where. Two
        // mutexes are crossed on the way — the driver's around the
        // registration list, and each resource's around its waiters —
        // so those two chains pin their ends and leave the loom
        // flavor's payload member unspelled.
        let registrations = walk_path(program, bundle, WalkRole::IoRegistrations);
        assert!(
            registrations.starts_with("driver.io.<Enabled>.__0.synced.")
                && registrations.ends_with(".registrations.head.<Some>.__0.pointer"),
            "{program}: io registrations bound to an unexpected path: {registrations}"
        );
        let waiters = walk_path(program, bundle, WalkRole::ScheduledIoWaiters);
        assert!(
            waiters.starts_with("waiters."),
            "{program}: ScheduledIo.waiters bound to an unexpected path: {waiters}"
        );
        assert_walk(
            program,
            bundle,
            WalkRole::ScheduledIoNext,
            "linked_list_pointers.value.inner.value.next.<Some>.__0.pointer",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::IoWaiterHead,
            "list.head.<Some>.__0.pointer",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::IoReaderWaker,
            "reader.<Some>.__0.waker",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::IoWriterWaker,
            "writer.<Some>.__0.waker",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::IoWaiterNext,
            "pointers.inner.value.next.<Some>.__0.pointer",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::IoWaiterWaker,
            "waker.<Some>.__0.waker",
        );
    }
    if program == "local-set" {
        // The local-set rows root at leaf types, so the portable summary
        // filters them; that they bound on the one fixture that
        // instantiates a LocalSet is asserted here instead — the loud
        // version of the plan's "does the sweep emit local::Shared".
        use exegesis::bundle::{StaticRole, WalkOutcome, WalkRole};
        for role in [
            WalkRole::CellScheduler,
            WalkRole::LocalOwnedId,
            WalkRole::LocalOwnedHead,
            WalkRole::LocalSetOwner,
            WalkRole::LocalTlsCtx,
            WalkRole::LocalCtxShared,
        ] {
            let binding = &bundle.walks.entries[&role];
            assert!(
                matches!(binding.outcome, WalkOutcome::Bound { .. }),
                "{program}: {} did not bind: {:?}",
                role.name(),
                binding.outcome
            );
        }
        assert!(
            bundle
                .statics
                .entries
                .contains_key(&StaticRole::TlsLocalSetKey),
            "{program}: the task::local::CURRENT static was not recorded"
        );
    }
    if program == "channels" {
        // The tokio-sync formatters have no fixture elsewhere, and are the
        // most intricate detectors (multi-path, cross-pointer, waiter queues).
        // Assert their fully-resolved paths so a wrong-member navigation trips
        // the test; each named type resolves identically on macOS and illumos.
        assert_format(
            program,
            bundle,
            "tokio::sync::notify::Notify",
            "tokio::sync::notify::Notify :: Node Struct \
             { state: state.inner.value.v.value.__0@+0, \
             mutex: waiters.__1.raw.state.v.value.__0@+8, \
             queue: List { head=waiters.__1.data.value.head@+16, \
             node_ty=tokio::sync::notify::Waiter, \
             next=pointers.inner.value.next@+8, \
             Struct { notification: notification.__0.inner.value.v.value.__0@+32, \
             waker: <structural> } } }",
        );
        assert_format(
            program,
            bundle,
            "core::task::wake::Waker",
            "core::task::wake::Waker :: Node Alias { waker.data@+8 }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::batch_semaphore::Semaphore",
            "tokio::sync::batch_semaphore::Semaphore :: Node Struct \
             { waiters: <structural>, permits: permits.inner.value.v.value.__0@+32 }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::watch::state::AtomicState",
            "tokio::sync::watch::state::AtomicState :: Node __0.inner.value.v.value.__0@+0",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::mpsc::bounded::Sender<u32>",
            "tokio::sync::mpsc::bounded::Sender<u32> :: Node Pointer \
             { at=chan.inner.ptr.pointer@+0, \
             pointee=alloc::sync::ArcInner<tokio::sync::mpsc::chan::Chan<u32, \
             tokio::sync::mpsc::bounded::Semaphore>>, via=data@+128, \
             then=Struct { capacity: semaphore.bound@+360, \
             free: semaphore.semaphore.permits.inner.value.v.value.__0@+352, \
             queued: CustomList { vars=[Read(rx_fields.__0.value.list.index@+304), \
             Read(tx.value.tail_position.inner.value.v.value.__0@+8), \
             Read(rx_fields.__0.value.list.head.pointer@+288)], \
             condition=((Var(0) < Var(1)) & (Var(2) != 0x0)), \
             body=[break if (Var(0) < Load((Var(2) + 0x80), 8)); \
             if ((Var(0) - Load((Var(2) + 0x80), 8)) < 0x20) \
             { emit((Var(2) + (0x0 + ((Var(0) - Load((Var(2) + 0x80), 8)) * 0x4)))); \
             Var(0) = (Var(0) + 0x1) } else { Var(2) = Load((Var(2) + 0x88), 8) }], \
             element=u32 }, \
             tx: <structural>, rx_waker: <structural>, notify_rx_closed: <structural>, \
             semaphore: <structural>, tx_count: <structural>, tx_weak_count: <structural>, \
             rx_fields: <structural> } }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::watch::Sender<u32>",
            "tokio::sync::watch::Sender<u32> :: Node Pointer { at=shared.ptr.pointer@+0, \
             pointee=alloc::sync::ArcInner<tokio::sync::watch::Shared<u32>>, via=data@+16, \
             then=Struct { value: Alias { value.__1.data.value@+296, follow }, \
             state: <structural>, ref_count_rx: <structural>, ref_count_tx: <structural> } }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::watch::Shared<u32>",
            "tokio::sync::watch::Shared<u32> :: Node Struct \
             { value: Alias { value.__1.data.value@+296, follow }, state: <structural>, \
             ref_count_rx: <structural>, ref_count_tx: <structural> }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::watch::Receiver<u32>",
            "tokio::sync::watch::Receiver<u32> :: Node Struct { unseen: Variant { \
             discr=(Read(version.__0@+8) != \
             (Read(shared.ptr.pointer.*.data.state.__0.inner.value.v.value.__0@+320) & ~0x1)), \
             arms=[0=>None, 1=>Some(Alias \
             { shared.ptr.pointer.*.data.value.__1.data.value@+312, follow })] }, \
             closed: Variant { \
             discr=(Read(shared.ptr.pointer.*.data.state.__0.inner.value.v.value.__0@+320) & 0x1), \
             arms=[0=>false, 1=>true] } }",
        );
        // A cache-line pad is one member holding the value; it aliases that
        // member so the padding does not read as a level of structure.
        assert_format(
            program,
            bundle,
            "tokio::util::cacheline::CachePadded<tokio::sync::mpsc::list::Tx<u32>>",
            "tokio::util::cacheline::CachePadded<tokio::sync::mpsc::list::Tx<u32>> \
             :: Node Alias { value@+0, follow }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::mpsc::chan::Chan<u32, tokio::sync::mpsc::bounded::Semaphore>",
            "tokio::sync::mpsc::chan::Chan<u32, tokio::sync::mpsc::bounded::Semaphore> :: Node Struct \
             { queued: CustomList \
             { vars=[Read(rx_fields.__0.value.list.index@+304), \
             Read(tx.value.tail_position.inner.value.v.value.__0@+8), \
             Read(rx_fields.__0.value.list.head.pointer@+288)], \
             condition=((Var(0) < Var(1)) & (Var(2) != 0x0)), \
             body=[break if (Var(0) < Load((Var(2) + 0x80), 8)); \
             if ((Var(0) - Load((Var(2) + 0x80), 8)) < 0x20) \
             { emit((Var(2) + (0x0 + ((Var(0) - Load((Var(2) + 0x80), 8)) * 0x4)))); \
             Var(0) = (Var(0) + 0x1) } else { Var(2) = Load((Var(2) + 0x88), 8) }], \
             element=u32 }, \
             tx: <structural>, rx_waker: <structural>, notify_rx_closed: <structural>, \
             semaphore: <structural>, tx_count: <structural>, tx_weak_count: <structural>, \
             rx_fields: <structural> }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::mpsc::block::Block<u32>",
            "tokio::sync::mpsc::block::Block<u32> :: Node Struct \
             { header: <structural>, \
             values: SlotCount { bitmap=header.ready_slots.inner.value.v.value.__0@+144, \
             slots=values.__0@+0 } }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::mpsc::bounded::Receiver<u32>",
            "tokio::sync::mpsc::bounded::Receiver<u32> :: Node Pointer \
             { at=chan.inner.ptr.pointer@+0, \
             pointee=alloc::sync::ArcInner<tokio::sync::mpsc::chan::Chan<u32, \
             tokio::sync::mpsc::bounded::Semaphore>>, via=data@+128, \
             then=Struct { capacity: semaphore.bound@+360, \
             free: semaphore.semaphore.permits.inner.value.v.value.__0@+352, \
             queued: CustomList { vars=[Read(rx_fields.__0.value.list.index@+304), \
             Read(tx.value.tail_position.inner.value.v.value.__0@+8), \
             Read(rx_fields.__0.value.list.head.pointer@+288)], \
             condition=((Var(0) < Var(1)) & (Var(2) != 0x0)), \
             body=[break if (Var(0) < Load((Var(2) + 0x80), 8)); \
             if ((Var(0) - Load((Var(2) + 0x80), 8)) < 0x20) \
             { emit((Var(2) + (0x0 + ((Var(0) - Load((Var(2) + 0x80), 8)) * 0x4)))); \
             Var(0) = (Var(0) + 0x1) } else { Var(2) = Load((Var(2) + 0x88), 8) }], \
             element=u32 }, \
             tx: <structural>, rx_waker: <structural>, notify_rx_closed: <structural>, \
             semaphore: <structural>, tx_count: <structural>, tx_weak_count: <structural>, \
             rx_fields: <structural> } }",
        );
        assert_format(
            program,
            bundle,
            "tokio::sync::mpsc::bounded::Semaphore",
            "tokio::sync::mpsc::bounded::Semaphore :: Node Struct \
             { mutex: semaphore.waiters.__1.raw.state.v.value.__0@+0, \
             closed: semaphore.waiters.__1.data.value.closed@+24, \
             permits: semaphore.permits.inner.value.v.value.__0@+32, bound: bound@+40, \
             queue: List { head=semaphore.waiters.__1.data.value.queue.head@+8, \
             node_ty=tokio::sync::batch_semaphore::Waiter, \
             next=pointers.inner.value.next@+24, \
             Struct { permits_needed: state.inner.value.v.value.__0@+32, \
             waker: <structural> } } }",
        );
        assert_format(
            program,
            bundle,
            "parking_lot::raw_mutex::RawMutex",
            "parking_lot::raw_mutex::RawMutex :: Node state.v.value.__0@+0",
        );
    }
}

fn run_golden(program: &str) {
    if !ensure_fixture(program) {
        return;
    }

    let opts = ExtractOptions {
        extract_args: format!("golden-test {program}"),
        ..Default::default()
    };
    let (bundle, stats) = extract_file(&dwarf_path(program), &opts)
        .unwrap_or_else(|e| panic!("extract failed for {program}: {e}"));

    // The bundle must survive its own validation and a save/load round
    // trip (save validates; load re-validates).
    let tmp = tempfile::NamedTempFile::new().unwrap();
    bundle
        .save(tmp.path())
        .expect("bundle failed validation on save");
    let reloaded = Bundle::load(tmp.path()).expect("bundle failed to reload");
    assert_eq!(
        reloaded, bundle,
        "{program}: save/load round trip changed the bundle"
    );

    assert_clean(program, &bundle, &stats);

    let crate_str = program.replace('-', "_");
    let summary = portable_summary(&bundle, program, &crate_str);

    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{program}.golden"));
    if std::env::var_os("EXEGESIS_BLESS").is_some() {
        std::fs::write(&golden_path, &summary).unwrap();
        eprintln!("blessed {}", golden_path.display());
        return;
    }

    let expected = std::fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "no golden file {} — run with EXEGESIS_BLESS=1 to create it",
            golden_path.display()
        )
    });
    assert_eq!(
        summary,
        expected,
        "{program}: extraction summary diverged from {} \
         (EXEGESIS_BLESS=1 to re-bless)\n--- actual ---\n{summary}",
        golden_path.display()
    );
}

#[test]
fn test_golden_simple_await() {
    run_golden("simple-await");
}

#[test]
fn test_golden_nested_await() {
    run_golden("nested-await");
}

#[test]
fn test_golden_dyn_future() {
    run_golden("dyn-future");
}

#[test]
fn test_golden_select_combinator() {
    run_golden("select-combinator");
}

#[test]
fn test_golden_futurelock() {
    run_golden("futurelock");
}

#[test]
fn test_golden_channels() {
    run_golden("channels");
}

#[test]
fn test_golden_unordered() {
    run_golden("unordered");
}

#[test]
fn test_golden_joinset() {
    run_golden("joinset");
}

#[test]
fn test_golden_ct_runtime() {
    run_golden("ct-runtime");
}

#[test]
fn test_golden_local_set() {
    run_golden("local-set");
}

#[test]
fn test_golden_local_set_timer() {
    run_golden("local-set-timer");
}

#[test]
fn test_golden_local_set_io() {
    run_golden("local-set-io");
}

#[test]
fn test_golden_foreign_runtime() {
    run_golden("foreign-runtime");
}

/// Two extractions of one binary agree byte for byte.
///
/// The sweep resolves several fields first-wins, so whichever function
/// it reaches first decides an await's reported site, a coroutine's
/// resume location, and a task's `poll` declaration. The reader hands
/// functions out of a randomly seeded hash map, which made that choice
/// vary from run to run — and a golden can only catch it by flaking, so
/// the property is asserted directly. Both bundles come from one
/// process, where each map still gets its own seed.
#[test]
fn test_extraction_is_reproducible() {
    let program = "select-combinator";
    if !ensure_fixture(program) {
        return;
    }

    let opts = ExtractOptions {
        extract_args: format!("golden-test {program}"),
        ..Default::default()
    };
    let extract = || {
        let (bundle, _) = extract_file(&dwarf_path(program), &opts)
            .unwrap_or_else(|e| panic!("extract failed for {program}: {e}"));
        let mut bytes = Vec::new();
        bundle.write_to(&mut bytes).expect("bundle failed to write");
        (bundle, bytes)
    };

    let (first, first_bytes) = extract();
    let (second, second_bytes) = extract();

    // Compared decoded as well as encoded: the bytes say *whether* two
    // extractions agree, the values say *where* they do not.
    assert_eq!(first.meta, second.meta, "{program}: meta differs");
    assert_eq!(first.tasks, second.tasks, "{program}: task table differs");
    assert_eq!(first.types, second.types, "{program}: type table differs");
    assert_eq!(first, second, "{program}: bundles differ");
    assert!(
        first_bytes == second_bytes,
        "{program}: serialized bundles differ ({} vs {} bytes)",
        first_bytes.len(),
        second_bytes.len()
    );
}

/// The `--explain-format` / `--explain-walk` traces: the one diagnostic
/// for a silently-declining detector, collected only on request, so no
/// other test ever turns the trace sink on.
#[test]
fn test_explain_traces_report_the_verdict() {
    let program = "simple-await";
    if !ensure_fixture(program) {
        return;
    }

    let opts = ExtractOptions {
        extract_args: format!("golden-test {program} --explain"),
        explain_format: Some("alloc::string::String".into()),
        explain_walk: Some("Header.".into()),
        ..Default::default()
    };
    let (bundle, stats) = extract_file(&dwarf_path(program), &opts)
        .unwrap_or_else(|e| panic!("extract failed for {program}: {e}"));

    // A type a formatter claims: the navigators left a trace, and the
    // render ends with the program the bundle actually ships rather
    // than the one the detector built.
    let expl = stats
        .format_explanations
        .iter()
        .find(|e| e.name == "alloc::string::String")
        .unwrap_or_else(|| {
            panic!(
                "no explanation for String; traced: {:?}",
                stats
                    .format_explanations
                    .iter()
                    .map(|e| &e.name)
                    .collect::<Vec<_>>()
            )
        });
    assert!(!expl.trace.is_empty(), "the navigators left no trace");
    let rendered = expl.render(&bundle);
    assert!(
        rendered.starts_with("alloc::string::String [type "),
        "{rendered}"
    );
    assert!(rendered.contains("=>"), "{rendered}");
    assert!(!rendered.contains("no formatter"), "{rendered}");

    // Roles are selected by substring, each carries its binder trace,
    // and a bound one reads its verdict back out of the bundle.
    assert!(!stats.walk_explanations.is_empty());
    for expl in &stats.walk_explanations {
        assert!(expl.role.name().contains("Header."), "{:?}", expl.role);
        assert!(!expl.trace.is_empty(), "{:?} left no trace", expl.role);
    }
    let bound = stats
        .walk_explanations
        .iter()
        .find(|e| bundle.walks.entries.contains_key(&e.role))
        .expect("a Header role binds on the fixture");
    let line = walk_entry_line(bound.role, &bundle.walks.entries[&bound.role]);
    assert!(line.contains(bound.role.name()), "{line}");

    // A type nothing claims says so, instead of silence.
    let opts = ExtractOptions {
        extract_args: format!("golden-test {program} --explain-structural"),
        explain_format: Some("::work::{async_fn_env".into()),
        ..Default::default()
    };
    let (bundle, stats) = extract_file(&dwarf_path(program), &opts)
        .unwrap_or_else(|e| panic!("extract failed for {program}: {e}"));
    let expl = stats
        .format_explanations
        .iter()
        .find(|e| e.name.contains("work::{async_fn_env"))
        .expect("the fixture's own future is emitted");
    let rendered = expl.render(&bundle);
    assert!(
        rendered.contains("no formatter; renders structurally"),
        "{rendered}"
    );
}

/// `--include-type` pulls extra roots into the closure by
/// fully-qualified name, and records the names that resolved to
/// nothing rather than dropping them silently.
#[test]
fn test_include_types_resolve_or_are_reported_missing() {
    let program = "simple-await";
    if !ensure_fixture(program) {
        return;
    }

    let opts = ExtractOptions {
        extract_args: format!("golden-test {program} --include-type"),
        include_types: vec![
            "alloc::string::String".into(),
            "no_such_crate::NoSuchType".into(),
        ],
        ..Default::default()
    };
    let (bundle, stats) = extract_file(&dwarf_path(program), &opts)
        .unwrap_or_else(|e| panic!("extract failed for {program}: {e}"));

    assert!(stats.include_roots >= 1, "String did not resolve as a root");
    assert_eq!(stats.include_missing, ["no_such_crate::NoSuchType"]);
    assert!(
        bundle
            .types
            .find_by_name(&bundle.strings, "alloc::string::String")
            .next()
            .is_some(),
        "the included root is not in the bundle"
    );
}

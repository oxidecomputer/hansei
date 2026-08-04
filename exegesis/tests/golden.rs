//! Extraction golden tests (plan §11.2): run `extract` on the
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

use exegesis::bundle::{Bundle, DisplayNode, StaticRole, TypeDef, describe_debug_format};
use exegesis::extract::{ExtractOptions, ExtractStats, extract_file};

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const TOOLCHAIN: &str = "1.97.0";

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

fn leaf_of(name: &str) -> &str {
    // The generic suffix may itself contain `::`; strip it first.
    let base = name.split('<').next().unwrap_or(name);
    let leaf_start = base.rfind("::").map(|i| i + 2).unwrap_or(0);
    &name[leaf_start..]
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
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

/// Render the platform-portable summary of an extraction, filtered to
/// types mentioning `crate_str` (the fixture crate's name).
fn summarize(program: &str, crate_str: &str, bundle: &Bundle) -> String {
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>");
    let type_name = |id: exegesis::bundle::BundleTypeId| -> String {
        match &bundle.types.types[id.0 as usize] {
            TypeDef::Base { name, .. }
            | TypeDef::Struct { name, .. }
            | TypeDef::Union { name, .. }
            | TypeDef::Enum { name, .. }
            | TypeDef::CEnum { name, .. }
            | TypeDef::Opaque { name, .. } => s(*name).to_owned(),
            TypeDef::Pointer { .. } => "<pointer>".to_owned(),
            TypeDef::Array { .. } => "<array>".to_owned(),
        }
    };

    let mut out = String::new();
    writeln!(out, "program: {program}").unwrap();

    // Task entries for the fixture's own futures, grouped by future type.
    writeln!(out, "\n[tasks]").unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for (i, entry) in bundle.tasks.entries.iter().enumerate() {
        let display = s(entry.display_name);
        if !display.contains(crate_str) || !seen.insert(display.to_owned()) {
            continue;
        }

        let entries_for_future = bundle
            .tasks
            .entries
            .iter()
            .filter(|e| e.display_name == entry.display_name)
            .count();
        let symbols: Vec<usize> = bundle
            .tasks
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.display_name == entry.display_name)
            .map(|(j, _)| {
                bundle
                    .tasks
                    .by_symbol
                    .values()
                    .filter(|id| id.0 as usize == j)
                    .count()
            })
            .collect();

        writeln!(out, "task: {display}").unwrap();
        let p = &bundle.provenance.entries[i];
        writeln!(out, "  kind: {:?}", p.kind).unwrap();
        match &p.decl {
            Some(loc) => writeln!(out, "  decl: {}:{}", basename(s(loc.file)), loc.line).unwrap(),
            None => writeln!(out, "  decl: <none>").unwrap(),
        }
        writeln!(out, "  entries: {entries_for_future}").unwrap();
        writeln!(
            out,
            "  symbols-per-entry: {}",
            symbols
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
        .unwrap();

        writeln!(out, "  stage: {}", leaf_of(&type_name(entry.stage))).unwrap();

        if let TypeDef::Enum { shape, .. } = &bundle.types.types[entry.future.0 as usize] {
            writeln!(out, "  variants:").unwrap();
            for v in &shape.variants {
                let payload = type_name(v.payload.ty);
                // The await site only when it says something the variant's
                // own coordinates do not — i.e. where the await came from a
                // macro and `decl` names the macro's own line.
                let awaited = v
                    .await_site
                    .filter(|loc| v.decl != Some(*loc))
                    .map(|loc| format!(" (awaited at {}:{})", basename(s(loc.file)), loc.line))
                    .unwrap_or_default();
                match &v.decl {
                    Some(loc) => writeln!(
                        out,
                        "    {} @ {}:{}{awaited}",
                        leaf_of(&payload),
                        basename(s(loc.file)),
                        loc.line
                    )
                    .unwrap(),
                    None => writeln!(out, "    {}{awaited}", leaf_of(&payload)).unwrap(),
                }
            }
        }
    }

    // Dyn-future entries for the fixture's own types: which symbol kinds
    // key each type.
    writeln!(out, "\n[dyn-futures]").unwrap();
    let mut dyn_types: std::collections::BTreeMap<String, (bool, bool)> = Default::default();
    for (sym, id) in &bundle.dyn_futures.by_symbol {
        let name = type_name(*id);
        if !name.contains(crate_str) {
            continue;
        }
        let e = dyn_types.entry(name).or_default();
        // drop_glue instantiations are recognizable in the v0 mangling.
        if sym.contains("9drop_glue") {
            e.1 = true;
        } else {
            e.0 = true;
        }
    }
    for (name, (poll, glue)) in &dyn_types {
        let mut kinds = Vec::new();
        if *poll {
            kinds.push("poll");
        }
        if *glue {
            kinds.push("drop_glue");
        }
        writeln!(out, "dyn: {name} ({})", kinds.join(", ")).unwrap();
    }

    writeln!(out, "\n[infra]").unwrap();
    let infra = &bundle.infra;
    for (what, id) in [
        ("header", infra.header),
        ("vtable", infra.vtable),
        ("trailer", infra.trailer),
        ("context", infra.context),
        ("scheduler_handle", infra.scheduler_handle),
        ("mt_handle", infra.mt_handle),
        ("location", infra.location),
        ("raw_waker_vtable", infra.raw_waker_vtable),
    ] {
        let name = type_name(id);
        let ok = if name.starts_with("<missing") {
            "MISSING"
        } else {
            "ok"
        };
        writeln!(out, "{what}: {ok}").unwrap();
    }

    writeln!(out, "\n[statics]").unwrap();
    for (role, label) in [
        (StaticRole::TlsContextKey, "tls-context-key"),
        (StaticRole::TaskWakerVtable, "task-waker-vtable"),
    ] {
        let ok = if bundle.statics.entries.contains_key(&role) {
            "ok"
        } else {
            "MISSING"
        };
        writeln!(out, "{label}: {ok}").unwrap();
    }

    out
}

/// Structural assertions that hold for every fixture — the "zero silent
/// drops" checks (§11.2) plus metadata sanity.
fn assert_clean(program: &str, bundle: &Bundle, stats: &ExtractStats) {
    assert_addresses_by_name(program, bundle);
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
        // the entry's own scheduler handle (crossing the handle enum, the
        // `Option` time handle, and the `Traditional` driver variant). A
        // wrong member anywhere on either path changes this string.
        //
        // The wheel path crosses the runtime's `driver::Handle`, whose io and
        // signal members embed OS-specific types, so — unlike every other
        // offset these asserts pin — its terminal offset is per-platform.
        let wheel_offset = if cfg!(target_os = "macos") { 648 } else { 632 };
        assert_format(
            program,
            bundle,
            "tokio::runtime::time::entry::TimerEntry",
            &format!(
                "tokio::runtime::time::entry::TimerEntry :: Node Struct \
                 {{ deadline: <structural>, state: Variant {{ discr=Read(registered@+104), \
                 arms=[0=>unregistered], default=Variant {{ \
                 discr=(Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) != 0xffffffffffffffff), \
                 arms=[0=>elapsed, 1=>fires_in_ms(Computed(\
                 (Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) - \
                 Read(driver.{{MultiThread}}.__0.ptr.pointer.*.data.driver.time.{{Some}}.__0.inner.\
                 {{Traditional}}.state.__1.data.value.wheel.elapsed@+{wheel_offset}))))] }} }} }}"
            ),
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
    let summary = summarize(program, &crate_str, &bundle);

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

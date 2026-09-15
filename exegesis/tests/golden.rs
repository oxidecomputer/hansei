// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
//! serves macOS and illumos. Regenerate with `INSTA_UPDATE=always cargo
//! test -p exegesis --test golden`; a plain run leaves each rejected
//! golden beside its file as `<program>.snap.new`.

use exegesis::bundle::{
    Bundle, DiscrValue, DiscrValues, DisplayNode, Encoding, MemberRef, Step, TypeDef, WalkOutcome,
    WalkRole,
};
use exegesis::describe::describe_debug_format;
use exegesis::extract::{DebugSources, ExtractOptions, ExtractStats, extract_sources};
use exegesis::summary::{portable_summary, walk_entry_line};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const TOOLCHAIN: &str = "1.98.0";

fn test_programs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-programs")
}

/// The file `extract` should read for a fixture: the binary itself on
/// ELF platforms, the dSYM DWARF on macOS.
fn dwarf_path(program: &str) -> PathBuf {
    let bin = fixture_binary(program);
    let dsym = fixture_dsym(program);
    if dsym.exists() { dsym } else { bin }
}

fn fixture_binary(program: &str) -> PathBuf {
    test_programs_dir().join("fixtures/bin").join(program)
}

fn fixture_dsym(program: &str) -> PathBuf {
    fixture_binary(program)
        .with_extension("dSYM")
        .join("Contents/Resources/DWARF")
        .join(program)
}

/// The packed-split build of a fixture: the skeleton-DWARF binary, with
/// its `.dwp` sitting beside it (`regen.sh --dwp`).
#[cfg(target_os = "linux")]
fn dwp_binary(program: &str) -> PathBuf {
    test_programs_dir().join("fixtures/bin/dwp").join(program)
}

/// [`ensure_fixture`], for the packed-split build of a program: built
/// once per run by `regen.sh --dwp` into its own bin dir, stamped and
/// digested separately from the unsplit build of the same sources.
#[cfg(target_os = "linux")]
fn ensure_dwp_fixture(program: &str) -> bool {
    static BUILT: Mutex<BTreeMap<String, bool>> = Mutex::new(BTreeMap::new());
    let mut built = BUILT.lock().unwrap();
    if let Some(&usable) = built.get(program) {
        return usable;
    }
    let usable = if !toolchain_installed() {
        if dwp_binary(program).exists() {
            eprintln!(
                "warning: toolchain {TOOLCHAIN} not installed; testing against \
                 the {program} dwp fixture already built"
            );
            true
        } else {
            eprintln!(
                "SKIP: dwp fixture {program} missing and toolchain {TOOLCHAIN} \
                 not installed (rustup toolchain install {TOOLCHAIN})"
            );
            false
        }
    } else {
        testrun::once_per_run(
            &built_stamp(&format!("dwp-{program}")),
            || format!("dwp-{}", built_from(program)),
            || {
                let status = Command::new(test_programs_dir().join("regen.sh"))
                    .arg("--dwp")
                    .arg(program)
                    .status()
                    .expect("failed to run regen.sh");
                assert!(status.success(), "regen.sh --dwp failed for {program}");
            },
        );
        assert!(
            dwp_binary(program).exists(),
            "regen.sh --dwp succeeded but the {program} binary is still missing"
        );
        true
    };
    built.insert(program.to_string(), usable);
    usable
}

/// Extract a fixture the way an operator would: the binary as the
/// input, and — where the platform split the DWARF out into a dSYM —
/// that companion as the debug-info file. Every macOS run therefore
/// exercises the two-file path under the full input contract; ELF
/// fixtures carry their DWARF embedded and take the one-file form.
fn extract_fixture(program: &str, opts: &ExtractOptions) -> (Bundle, ExtractStats) {
    let bin = fixture_binary(program);
    let dsym = fixture_dsym(program);
    let sources = DebugSources {
        binary: &bin,
        debug_info: dsym.exists().then_some(dsym.as_path()),
    };
    extract_sources(&sources, opts).unwrap_or_else(|e| panic!("extract failed for {program}: {e}"))
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

    // Once per run rather than once per process: under nextest each test
    // is its own process, and a rebuild landing in the middle of another
    // test's parse is exactly what the `Mutex` above was for.
    testrun::once_per_run(
        &built_stamp(program),
        || built_from(program),
        || {
            let status = Command::new(test_programs_dir().join("regen.sh"))
                .arg(program)
                .status()
                .expect("failed to run regen.sh");
            assert!(status.success(), "regen.sh failed for {program}");
        },
    );
    assert!(
        dwarf_path(program).exists(),
        "regen.sh succeeded but {program} fixture is still missing"
    );
    true
}

/// Where a run records that it has built `program` already.
fn built_stamp(program: &str) -> PathBuf {
    test_programs_dir().join("fixtures/.built").join(program)
}

/// What one fixture binary is built from, for a run reusing what an
/// earlier one left behind (`testrun::REUSE`): the program's own source
/// and the crate it calls into, the manifest and lock that pin what it
/// links, the script that drives the build, and the toolchain that
/// script pins.
fn built_from(program: &str) -> String {
    let dir = test_programs_dir();
    let matrix = testrun::fixture::Matrix::read(&dir);
    matrix.primary_recipe().inputs(&dir, &matrix, program)
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

/// The members a coroutine state lists, by name, in the bundle's order.
///
/// The `.snap` summaries name a coroutine's states and where each
/// suspends, not what each holds, and the state-stripping pass
/// (`drop_members_of_other_states`) decides the latter from the env
/// kind in the type's name. Pinning a state's members here is what
/// catches that pass stripping a capture the state still owns, or
/// keeping an argument it does not — the acceptance suite's `locals:`
/// expectations are blessed from the tool's own output, so they cannot.
fn assert_state_members(program: &str, bundle: &Bundle, type_name: &str, expected: &[&str]) {
    let mut ids = bundle.types.find_by_name(&bundle.strings, type_name);
    let Some(id) = ids.next() else {
        panic!("{program}: no type named {type_name}");
    };
    assert!(
        ids.next().is_none(),
        "{program}: {type_name} names more than one type"
    );
    let members: Vec<&str> = match bundle.types.get(id) {
        Some(TypeDef::Struct { members, .. }) => members
            .iter()
            .map(|m| bundle.strings.get(m.name).unwrap())
            .collect(),
        other => panic!("{program}: {type_name} is {other:?}, not a struct"),
    };
    assert_eq!(
        members, expected,
        "{program}: {type_name} lists unexpected members"
    );
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
/// The bits each variant of the enum named `type_name` is selected by,
/// as `(variant, bits)` in the bundle's order, with `None` for a niche
/// default — after checking the tag is the base type `tag` names.
///
/// The bundle's contract is that these are the tag's raw bits as a
/// little-endian read of it produces them, which is *not* what DWARF
/// carries: LLVM spells a constant in the narrowest form that holds it
/// with the repr's signedness, so a negative constant on a wide signed
/// tag arrives narrower than the tag and extraction must widen it. The
/// portable summary lists variants without their values, so only this
/// notices a constant stored at the form's width instead of the tag's.
fn assert_discr_values(
    program: &str,
    bundle: &Bundle,
    type_name: &str,
    tag: &str,
    expected: &[(&str, Option<u128>)],
) {
    let mut ids = bundle.types.find_by_name(&bundle.strings, type_name);
    let Some(id) = ids.next() else {
        panic!("{program}: no type named {type_name}");
    };
    assert!(
        ids.next().is_none(),
        "{program}: {type_name} names more than one type"
    );
    let Some(TypeDef::Enum { shape, .. }) = bundle.types.get(id) else {
        panic!("{program}: {type_name} is not a variant enum");
    };
    let discr = shape
        .discr
        .as_ref()
        .unwrap_or_else(|| panic!("{program}: {type_name} has no discriminant"));
    match bundle.types.get(discr.ty) {
        Some(TypeDef::Base { name, .. }) => assert_eq!(
            bundle.strings.get(*name).unwrap(),
            tag,
            "{program}: {type_name}'s tag is not {tag}"
        ),
        other => panic!("{program}: {type_name}'s tag is {other:?}, not a base type"),
    }
    let values: Vec<(&str, Option<u128>)> = shape
        .variants
        .iter()
        .map(|v| {
            let bits = v.discr_values.as_ref().map(|dv| match dv {
                DiscrValues(values) => match values[..] {
                    [DiscrValue::Value(x)] => x,
                    _ => panic!("{program}: {type_name} carries a value list: {values:?}"),
                },
            });
            (bundle.strings.get(v.name).unwrap(), bits)
        })
        .collect();
    assert_eq!(
        values, expected,
        "{program}: {type_name}'s variants select on unexpected bits"
    );
}

/// The enumerators of the C-style enum named `type_name`, as
/// `(name, value)` in the bundle's order: the value each constant
/// names, so a negative one is negative whatever form spelled it.
fn assert_enumerators(program: &str, bundle: &Bundle, type_name: &str, expected: &[(&str, i128)]) {
    let mut ids = bundle.types.find_by_name(&bundle.strings, type_name);
    let Some(id) = ids.next() else {
        panic!("{program}: no type named {type_name}");
    };
    assert!(
        ids.next().is_none(),
        "{program}: {type_name} names more than one type"
    );
    let Some(TypeDef::CEnum { enumerators, .. }) = bundle.types.get(id) else {
        panic!("{program}: {type_name} is not a C-style enum");
    };
    let values: Vec<(&str, i128)> = enumerators
        .iter()
        .map(|(name, value)| (bundle.strings.get(*name).unwrap(), *value))
        .collect();
    assert_eq!(
        values, expected,
        "{program}: {type_name} lists unexpected enumerators"
    );
}

/// The env-decl table's entry for the environment type named
/// `type_name`, as (file, line).
fn env_decl<'b>(program: &str, bundle: &'b Bundle, type_name: &str) -> (&'b str, u32) {
    let loc = bundle
        .types
        .env_decls
        .iter()
        .find_map(|(id, loc)| {
            let name = match &bundle.types.types[id.0 as usize] {
                TypeDef::Enum { name, .. } | TypeDef::Struct { name, .. } => *name,
                _ => return None,
            };
            (bundle.strings.get(name)? == type_name).then_some(loc)
        })
        .unwrap_or_else(|| panic!("{program}: {type_name} records no declaration"));
    let file = bundle.strings.get(loc.file).expect("interned file");
    (file, loc.line)
}

/// `type_name`'s environment is declared in the fixture's own source
/// at line `expected`.
fn assert_env_decl(program: &str, bundle: &Bundle, type_name: &str, expected: u32) {
    let (file, line) = env_decl(program, bundle, type_name);
    assert!(
        file.ends_with(&format!("src/bin/{program}.rs")),
        "{program}: {type_name} declared in {file}"
    );
    assert_eq!(line, expected, "{program}: {type_name}'s line");
}

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

/// Every emitted type whose name starts with `prefix` (a generic leaf
/// key ending in `<`) or equals it, with its semantic record if any.
fn types_named<'a>(
    bundle: &'a Bundle,
    prefix: &'a str,
) -> impl Iterator<
    Item = (
        &'a str,
        hansei_bundle::BundleTypeId,
        Option<&'a hansei_bundle::TypeSemantics>,
    ),
> + 'a {
    bundle
        .types
        .name_index
        .iter()
        .filter_map(move |&(name, id)| {
            let name = bundle.strings.get(name)?;
            // A key cut inside a generic list or an impl index is a
            // prefix; anything else is the whole name.
            let matches = if prefix.ends_with('<') || prefix.ends_with('#') {
                name.starts_with(prefix)
            } else {
                name == prefix
            };
            matches.then(|| {
                let record = bundle.semantics.types.iter().find(|r| r.ty == id);
                (name, id, record)
            })
        })
}

/// The resource a leaf type binds: every instantiation the key names
/// carries exactly this kind, under a tokio layout rule, and its
/// continuation — when it is positively a future — is the primitive
/// boundary and nothing more.
fn assert_resource(program: &str, bundle: &Bundle, key: &str, kind: hansei_bundle::ResourceKind) {
    use hansei_bundle::{Continuation, PollAction, PollProgram};
    let mut seen = 0;
    for (name, _, record) in types_named(bundle, key) {
        let record = record.unwrap_or_else(|| panic!("{program}: {name} has no semantic record"));
        let resource = record
            .resource
            .as_ref()
            .unwrap_or_else(|| panic!("{program}: {name} has no resource binding"));
        assert_eq!(resource.kind, kind, "{program}: {name}");
        let rule = &bundle.semantics.rules[resource.rule.0 as usize];
        assert!(
            matches!(
                bundle.semantics.origins[rule.origin.0 as usize],
                hansei_bundle::SemanticOrigin::LibraryLayout { .. }
            ),
            "{program}: {name}"
        );
        // The fixtures build against a tokio inside every protocol's
        // reviewed range, so each resource carries its state protocol —
        // a distinct rule of the state kind, under the same tokio
        // origin, recording a reviewed selection — and the
        // exclusive-pending guarantee that protocol reviews.
        let state_rule = resource
            .state_rule
            .unwrap_or_else(|| panic!("{program}: {name} has no state protocol"));
        assert_ne!(state_rule, resource.rule, "{program}: {name}");
        let state = &bundle.semantics.rules[state_rule.0 as usize];
        use hansei_bundle::{ResourceKind, SemanticRuleKind};
        let expected = match kind {
            ResourceKind::Sleep => SemanticRuleKind::TokioSleepState,
            ResourceKind::JoinHandle => SemanticRuleKind::TokioJoinHandleState,
            ResourceKind::SemaphoreAcquire => SemanticRuleKind::TokioAcquireState,
            ResourceKind::IoOperation(_) => SemanticRuleKind::TokioIoState,
            ResourceKind::MpscRecv => SemanticRuleKind::TokioMpscRecvState,
            ResourceKind::Notified => SemanticRuleKind::TokioNotifiedState,
            ResourceKind::OneshotRecv => SemanticRuleKind::TokioOneshotRecvState,
        };
        assert_eq!(state.kind, expected, "{program}: {name}");
        assert_eq!(state.origin, rule.origin, "{program}: {name}");
        assert!(
            matches!(
                bundle.semantics.origins[state.origin.0 as usize],
                hansei_bundle::SemanticOrigin::LibraryLayout {
                    selection: hansei_bundle::LayoutSelection::ReviewedRange,
                    ..
                }
            ),
            "{program}: {name}"
        );
        assert!(resource.exclusive_pending, "{program}: {name}");
        if let Some(facts) = &record.future {
            assert!(
                matches!(
                    &facts.continuation,
                    Continuation::Bound { rule, program: PollProgram::Direct(PollAction::Primitive) }
                        if *rule == resource.rule
                ),
                "{program}: {name}: {:?}",
                facts.continuation
            );
        }
        seen += 1;
    }
    assert!(seen > 0, "{program}: no type named {key}");
}

/// A type that must carry no resource binding: an operation over a
/// custom reader, however much of a socket it holds.
fn assert_no_resource(program: &str, bundle: &Bundle, key: &str) {
    let mut seen = 0;
    for (name, _, record) in types_named(bundle, key) {
        assert!(
            record.is_none_or(|r| r.resource.is_none()),
            "{program}: {name} acquired a resource binding"
        );
        assert!(
            record.is_none_or(|r| r.future.as_ref().is_none_or(|facts| matches!(
                facts.continuation,
                hansei_bundle::Continuation::Unknown(_)
            ))),
            "{program}: {name} acquired a continuation"
        );
        seen += 1;
    }
    assert!(seen > 0, "{program}: no type named {key}");
}

/// One coroutine's bound states, rendered as `key:Stage[locals](uncertain)`
/// lines with the member names sorted, so an expectation reads as the
/// convention says it should and a state whose members moved fails
/// naming them.
fn assert_coroutine(program: &str, bundle: &Bundle, type_name: &str, expected: &[&str]) {
    let s = |id| bundle.strings.get(id).unwrap();
    let mut ids = bundle.types.find_by_name(&bundle.strings, type_name);
    let id = ids
        .next()
        .unwrap_or_else(|| panic!("{program}: no type named {type_name}"));
    assert!(
        ids.next().is_none(),
        "{program}: {type_name} names more than one type"
    );
    let record = bundle
        .semantics
        .types
        .iter()
        .find(|r| r.ty == id)
        .unwrap_or_else(|| panic!("{program}: {type_name} has no semantic record"));
    let layout = record
        .coroutine
        .as_ref()
        .unwrap_or_else(|| panic!("{program}: {type_name} has no coroutine layout"));
    let rendered: Vec<String> = layout
        .states
        .iter()
        .map(|state| {
            let mut locals: Vec<&str> = state.locals.iter().map(|&n| s(n)).collect();
            locals.sort_unstable();
            let mut uncertain: Vec<&str> = state.uncertain_locals.iter().map(|&n| s(n)).collect();
            uncertain.sort_unstable();
            format!(
                "{}:{:?}[{}]({})",
                s(state.variant),
                state.stage,
                locals.join(","),
                uncertain.join(",")
            )
        })
        .collect();
    assert_eq!(rendered, expected, "{program}: {type_name}");
}

fn assert_container(program: &str, bundle: &Bundle, key: &str, kind: hansei_bundle::ContainerKind) {
    let mut seen = 0;
    for (name, _, record) in types_named(bundle, key) {
        let record = record.unwrap_or_else(|| panic!("{program}: {name} has no semantic record"));
        let container = record
            .container
            .as_ref()
            .unwrap_or_else(|| panic!("{program}: {name} has no container binding"));
        assert_eq!(container.kind, kind, "{program}: {name}");
        // A container is not thereby a future.
        assert!(
            record.future.is_none() || record.resource.is_none(),
            "{program}: {name}"
        );
        seen += 1;
    }
    assert!(seen > 0, "{program}: no type named {key}");
}

/// The semantic table's line for the type `prefix` names, with every
/// rule and task index masked to `#`: ids are assigned in record order,
/// which the platform's type set decides, and the assertions here are
/// about routes and evidence, not numbering.
fn semantic_line(table: &str, prefix: &str) -> String {
    let line = table
        .lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no semantic line for {prefix}"));
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find(|c: char| c.is_ascii_digit()) {
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        let end = tail
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(tail.len());
        let masked = head.ends_with("rule ") || head.ends_with("task ");
        out.push_str(if masked { "#" } else { &tail[..end] });
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// The combinator fixture's reviewed adapter closure, as the semantic
/// table records it: `map` crossing its public newtype and the enum
/// behind it, `map_err` crossing the `Map` over an `IntoFuture` its own
/// constructor builds, and a `Pin<Box<dyn Trait>>` whose trait is not
/// `Future`. Each ends at a hand-written future no rule covers, which
/// is where the chain is meant to stop.
fn assert_adapter_programs(program: &str, bundle: &Bundle) {
    use hansei_bundle::{
        Continuation, FutureTarget, PollAction, PollProgram, SemanticOrigin, SemanticRuleKind,
    };
    let table = exegesis::describe::describe_semantics(bundle);
    let line = |prefix: &str| semantic_line(&table, prefix);
    const PARK: &str = "futures_util::future::future::Map<select_combinator::Park, fn(u32) -> u32>";
    const PARK_ENUM: &str =
        "futures_util::future::future::map::Map<select_combinator::Park, fn(u32) -> u32>";
    // `map`: the public newtype forwards through `inner`, and the enum
    // it holds polls `future` in its incomplete state — the one that
    // has not produced an output — and is done in the other.
    assert_eq!(
        line(&format!("{PARK} ::")),
        format!(
            "{PARK} :: members future[poll, delegated by \
             select_combinator::mapper::{{async_fn_env#0}}] continuation rule # delegate \
             (exclusive) inner@+0 -> {PARK_ENUM}"
        ),
        "{program}"
    );
    assert_eq!(
        line(&format!("{PARK_ENUM} ::")),
        format!(
            "{PARK_ENUM} :: members future[poll, delegated by {PARK}] continuation rule # match \
             <self>@+0 -> {PARK_ENUM} {{Incomplete: delegate (exclusive) {{Incomplete}}.future@+8 \
             -> select_combinator::Park}} {{Complete: returned}}"
        ),
        "{program}"
    );
    // `map_err` is a newtype over a `Map` over an `IntoFuture`: three
    // reviewed rules in a row, ending at the fallible future itself.
    const ERR: &str =
        "futures_util::future::try_future::MapErr<select_combinator::Fallible, fn(u32) -> u32>";
    const ERR_MAP: &str = "futures_util::future::future::Map<futures_util::future::try_future::\
                           into_future::IntoFuture<select_combinator::Fallible>, \
                           futures_util::fns::MapErrFn<fn(u32) -> u32>>";
    const ERR_MAP_ENUM: &str = "futures_util::future::future::map::Map<futures_util::future::\
                                try_future::into_future::IntoFuture<select_combinator::Fallible>, \
                                futures_util::fns::MapErrFn<fn(u32) -> u32>>";
    const INTO: &str =
        "futures_util::future::try_future::into_future::IntoFuture<select_combinator::Fallible>";
    assert_eq!(
        line(&format!("{ERR} ::")),
        format!(
            "{ERR} :: members future[poll, delegated by \
             select_combinator::remapper::{{async_fn_env#0}}] continuation rule # delegate \
             (exclusive) inner@+0 -> {ERR_MAP}"
        ),
        "{program}"
    );
    assert_eq!(
        line(&format!("{INTO} ::")),
        format!(
            "{INTO} :: members future[poll, delegated by {ERR_MAP_ENUM}] continuation rule # \
             delegate (exclusive) future@+0 -> select_combinator::Fallible"
        ),
        "{program}"
    );
    // Where each chain stops: a hand-written future of the fixture's,
    // proved a future by the reviewed delegation above it.
    for (stop, parent) in [
        ("select_combinator::Park", PARK_ENUM.to_owned()),
        ("select_combinator::Fallible", INTO.to_owned()),
    ] {
        assert_eq!(
            line(&format!("{stop} ::")),
            format!(
                "{stop} :: members future[poll, delegated by {parent}] continuation unknown (NoRule)"
            ),
            "{program}"
        );
    }
    // The dyn hop over a trait that merely requires `Future`: the box
    // is an owned adapter like any other, and the concrete pointee is
    // the vtable join's to name at read time.
    const DYN_PARKED: &str = "core::pin::Pin<alloc::boxed::Box<dyn \
                              select_combinator::Parked<Output=u32>, alloc::alloc::Global>>";
    assert_eq!(
        line(&format!("{DYN_PARKED} ::")),
        format!(
            "{DYN_PARKED} :: members future[poll, delegated by \
             select_combinator::dynamic::{{async_fn_env#0}}] continuation rule # delegate \
             (exclusive) dyn pointer@+0 -> alloc::boxed::Box<dyn \
             select_combinator::Parked<Output=u32>, alloc::alloc::Global> access Owned rule # dyn \
             pointer@+0 -> alloc::boxed::Box<dyn select_combinator::Parked<Output=u32>, \
             alloc::alloc::Global>"
        ),
        "{program}"
    );
    let dyn_parked =
        bundle
            .semantics
            .types
            .iter()
            .find(|record| {
                bundle.types.name_index.iter().any(|&(name, ty)| {
                    ty == record.ty && bundle.strings.get(name) == Some(DYN_PARKED)
                })
            })
            .unwrap_or_else(|| panic!("{program}: no record for {DYN_PARKED}"));
    let Some(Continuation::Bound {
        program:
            PollProgram::Direct(PollAction::Delegate {
                target: FutureTarget::Dynamic { layout, .. },
                ..
            }),
        ..
    }) = dyn_parked.future.as_ref().map(|f| &f.continuation)
    else {
        panic!("{program}: {DYN_PARKED} is not a dynamic delegation");
    };
    assert_eq!(layout.poll_slot, None, "{program}");
    // The `map` enum's rule is under a futures-util delegation origin
    // at the version the fixture's lockfile pins, read off the registry
    // path its `poll` was declared on; the two newtypes forward on
    // their layout, under futures-util's layout origin.
    let mut kinds: Vec<SemanticRuleKind> = Vec::new();
    let mut layout_kinds: Vec<SemanticRuleKind> = Vec::new();
    for rule in &bundle.semantics.rules {
        // The selector's `select!` binds tokio's rule under tokio's own
        // origin; `assert_select` holds that one. The coop rule is
        // tokio's as well, bound wherever the target keeps the
        // runtime's own `Coop<changed_impl<()>>`, and the family check
        // above holds it — as it does the tick's, bound wherever a
        // `tick` is in flight.
        if matches!(
            rule.kind,
            SemanticRuleKind::TokioSelect
                | SemanticRuleKind::TokioCoop
                | SemanticRuleKind::TokioIntervalTick
        ) {
            continue;
        }
        if let SemanticOrigin::LibraryLayout { package, .. } =
            &bundle.semantics.origins[rule.origin.0 as usize]
            && bundle.strings.get(*package) == Some("futures-util")
        {
            layout_kinds.push(rule.kind);
            continue;
        }
        let SemanticOrigin::LibraryDelegation {
            package,
            version,
            family,
            source,
            ..
        } = &bundle.semantics.origins[rule.origin.0 as usize]
        else {
            continue;
        };
        let s = |id| bundle.strings.get(id).unwrap();
        assert_eq!(s(*package), "futures-util", "{program}");
        assert_eq!(
            s(*family),
            exegesis::detect::semantics::FUTURES_UTIL_ADAPTERS_V0_3_30.family
        );
        let parsed = hansei_bundle::origin::registry_origin(s(*source))
            .unwrap_or_else(|| panic!("{program}: {} is not a registry path", s(*source)));
        assert_eq!(parsed.package, "futures-util", "{program}");
        assert_eq!(parsed.version.to_string(), s(*version), "{program}");
        kinds.push(rule.kind);
    }
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds, [SemanticRuleKind::FuturesUtilMap], "{program}");
    layout_kinds.sort();
    layout_kinds.dedup();
    assert_eq!(
        layout_kinds,
        [
            SemanticRuleKind::FuturesUtilMap,
            SemanticRuleKind::FuturesUtilMapErr,
            SemanticRuleKind::FuturesUtilIntoFuture,
        ]
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>(),
        "{program}"
    );
}

/// The fixtures that expand a `tokio::select!`, and so carry the
/// select rule: each program's one stop and its branch count.
const SELECT_PROGRAMS: [&str; 5] = [
    "armed-select",
    "channels",
    "futurelock",
    "select-combinator",
    "watch-stream",
];

/// The `select!` binding of the one `PollFn` `key` names: the tuple
/// has `branches` members in `__i` order, the mask is a `u8` (no
/// fixture has more than eight branches), both captures are reached
/// through the closure's references, and the rule is tokio's select
/// kind under a tokio delegation origin. Every `PollFn` from outside
/// the fixture crate — the mpsc receiver's, the scheduler's `block_on`
/// — carries none.
fn assert_select(program: &str, bundle: &Bundle, key: &str, branches: usize) {
    use hansei_bundle::{MemberRef, SemanticOrigin, SemanticRuleKind, Step, TypeDef};
    let s = |id| bundle.strings.get(id).unwrap();
    let mut seen = 0;
    for (name, _, record) in types_named(bundle, key) {
        let record = record.unwrap_or_else(|| panic!("{program}: {name} has no semantic record"));
        let select = record
            .select
            .as_ref()
            .unwrap_or_else(|| panic!("{program}: {name} has no select binding: {record:#?}"));
        let rule = &bundle.semantics.rules[select.rule.0 as usize];
        assert_eq!(
            rule.kind,
            SemanticRuleKind::TokioSelect,
            "{program}: {name}"
        );
        assert!(
            matches!(
                &bundle.semantics.origins[rule.origin.0 as usize],
                SemanticOrigin::LibraryDelegation { package, source, .. }
                    if s(*package) == "tokio" && s(*source).ends_with("/src/macros/select.rs")
            ),
            "{program}: {name}: {:?}",
            bundle.semantics.origins[rule.origin.0 as usize]
        );
        let route = |path: &hansei_bundle::TypedPath| {
            path.steps
                .iter()
                .map(|step| match step {
                    Step::Member(MemberRef::Named(n)) => s(*n).to_owned(),
                    Step::Deref => "*".to_owned(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(".")
        };
        assert_eq!(
            route(&select.mask),
            "f._ref__disabled.*",
            "{program}: {name}"
        );
        assert!(
            matches!(
                bundle.types.get(select.mask.target),
                Some(TypeDef::Base {
                    size: 1,
                    encoding: hansei_bundle::Encoding::Unsigned,
                    ..
                })
            ),
            "{program}: {name}'s mask is not a u8"
        );
        assert_eq!(
            route(&select.futures),
            "f._ref__futures.*",
            "{program}: {name}"
        );
        let members: Vec<String> = select.branches.iter().map(route).collect();
        let expected: Vec<String> = (0..branches).map(|i| format!("__{i}")).collect();
        assert_eq!(members, expected, "{program}: {name}");
        for branch in &select.branches {
            assert!(
                bundle.types.get(branch.target).is_some(),
                "{program}: {name}: a branch names a type the table lacks"
            );
        }
        seen += 1;
    }
    assert_eq!(seen, 1, "{program}: one PollFn named {key}");
    // A fixture with two selects asserts each by its own call, so its
    // own other `PollFn`s are not this call's negatives.
    let own = format!(
        "core::future::poll_fn::PollFn<{}::",
        program.replace('-', "_")
    );
    for (name, _, record) in types_named(bundle, "core::future::poll_fn::PollFn<") {
        if !name.starts_with(key) && !name.starts_with(&own) {
            assert!(
                record.is_none_or(|r| r.select.is_none()),
                "{program}: {name} acquired a select binding"
            );
        }
    }
}

/// The delegation fixture's programs, one per reviewed rule, and its
/// negatives, as the semantic table spells them. Each case's task root
/// is a `Pin<Box<F>>`, so every case exercises the pin rule; what `F`
/// then does is the case. Ordinary forwarding and exclusive forwarding
/// are asserted apart: the std adapters carry the bit, `Instrumented`
/// forwards without it.
fn assert_delegation_programs(program: &str, bundle: &Bundle) {
    use hansei_bundle::{Continuation, PollAction, PollProgram, SemanticRuleKind};
    let table = exegesis::describe::describe_semantics(bundle);
    let line = |prefix: &str| semantic_line(&table, prefix);
    const DYN: &str =
        "(dyn core::future::future::Future<Output=()> + core::marker::Send), alloc::alloc::Global>";
    // A pin over a box over a sized `F` delegates straight to `F`, and
    // the same route is its owned storage access.
    let pin_box = |inner: &str| {
        format!(
            "core::pin::Pin<alloc::boxed::Box<{inner}, alloc::alloc::Global>> :: members \
             future[task #, task #, poll] continuation rule # delegate (exclusive) \
             pointer.*@+0 -> {inner} access Owned rule # pointer.*@+0 -> {inner}"
        )
    };
    for inner in [
        "delegation_cases::Gated<1>",
        "delegation_cases::Gated<2>",
        "delegation_cases::Retained",
        "delegation_cases::RawHolder",
        "&mut delegation_cases::Probe<5>",
        "alloc::boxed::Box<delegation_cases::Probe<6>, alloc::alloc::Global>",
        "tracing::instrument::Instrumented<delegation_cases::Probe<8>>",
    ] {
        assert_eq!(
            line(&format!(
                "core::pin::Pin<alloc::boxed::Box<{inner}, alloc::alloc::Global>> ::"
            )),
            pin_box(inner),
            "{program}: {inner}"
        );
    }
    // The dynamic case: the outer pin delegates to the inner
    // `Pin<Box<dyn Future>>`, which delegates through the box's two
    // words under the vtable ABI rule.
    assert_eq!(
        line(&format!(
            "core::pin::Pin<alloc::boxed::Box<core::pin::Pin<alloc::boxed::Box<{DYN}>, alloc::alloc::Global>> ::"
        )),
        pin_box(&format!("core::pin::Pin<alloc::boxed::Box<{DYN}>")),
        "{program}"
    );
    assert_eq!(
        line(&format!("core::pin::Pin<alloc::boxed::Box<{DYN}> ::")),
        format!(
            "core::pin::Pin<alloc::boxed::Box<{DYN}> :: members future[poll, delegated by \
             core::pin::Pin<alloc::boxed::Box<core::pin::Pin<alloc::boxed::Box<{DYN}>, \
             alloc::alloc::Global>>] continuation rule # delegate (exclusive) dyn pointer@+0 -> \
             alloc::boxed::Box<{DYN} access Owned rule # dyn pointer@+0 -> alloc::boxed::Box<{DYN}"
        ),
        "{program}"
    );
    // The concrete future behind the dyn pointer is the vtable join's to
    // name: no static evidence reaches it.
    assert_eq!(
        line("delegation_cases::Probe<7> ::"),
        "delegation_cases::Probe<7> :: members future[poll] continuation unknown (NoRule)",
        "{program}"
    );
    // A block behind a dyn hop awaits a pinned box of `dyn` of its own.
    // Nothing delegates to the block statically, so the block's storage
    // is what proves the box a future: a bound coroutine seeds the
    // delegation fixed point whether or not anything has proved *it* a
    // future yet. Whether the box's own poll survives as a symbol is the
    // target's call — the Mach-O build inlines it away, ELF keeps it —
    // so the assertion masks that one word: on a build without it the
    // delegation is the box's whole evidence, and without the seed the
    // box has no record at all, with every chain and scan stopping at it.
    const DYN_SYNC: &str = "(dyn core::future::future::Future<Output=()> + core::marker::Send + \
                            core::marker::Sync), alloc::alloc::Global>";
    assert_eq!(
        line(&format!("core::pin::Pin<alloc::boxed::Box<{DYN_SYNC}> ::")).replacen(
            "future[poll, delegated by",
            "future[delegated by",
            1
        ),
        format!(
            "core::pin::Pin<alloc::boxed::Box<{DYN_SYNC}> :: members future[delegated by \
             delegation_cases::main::{{async_block_env#1}}] continuation rule # delegate \
             (exclusive) dyn pointer@+0 -> alloc::boxed::Box<{DYN_SYNC} access Owned rule # \
             dyn pointer@+0 -> alloc::boxed::Box<{DYN_SYNC}"
        ),
        "{program}"
    );
    // The reference and the box forward one poll each, exclusively, to
    // the probe they point at, which then has no rule of its own.
    assert_eq!(
        line("&mut delegation_cases::Probe<5> ::"),
        "&mut delegation_cases::Probe<5> :: members future[poll, delegated by \
         core::pin::Pin<alloc::boxed::Box<&mut delegation_cases::Probe<5>, alloc::alloc::Global>>] \
         continuation rule # delegate (exclusive) *@+0 -> delegation_cases::Probe<5> access \
         Borrowed rule # *@+0 -> delegation_cases::Probe<5>",
        "{program}"
    );
    assert_eq!(
        line("alloc::boxed::Box<delegation_cases::Probe<6>, alloc::alloc::Global> ::"),
        "alloc::boxed::Box<delegation_cases::Probe<6>, alloc::alloc::Global> :: members \
         future[poll, delegated by core::pin::Pin<alloc::boxed::Box<alloc::boxed::Box<\
         delegation_cases::Probe<6>, alloc::alloc::Global>, alloc::alloc::Global>>] \
         continuation rule # delegate (exclusive) *@+0 -> delegation_cases::Probe<6> access \
         Owned rule # *@+0 -> delegation_cases::Probe<6>",
        "{program}"
    );
    for (probe, parent) in [
        ("5", "&mut delegation_cases::Probe<5>"),
        (
            "6",
            "alloc::boxed::Box<delegation_cases::Probe<6>, alloc::alloc::Global>",
        ),
        (
            "8",
            "tracing::instrument::Instrumented<delegation_cases::Probe<8>>",
        ),
    ] {
        assert_eq!(
            line(&format!("delegation_cases::Probe<{probe}> ::")),
            format!(
                "delegation_cases::Probe<{probe}> :: members future[poll, delegated by {parent}] \
                 continuation unknown (NoRule)"
            ),
            "{program}"
        );
    }
    // `Instrumented` forwards through std's `ManuallyDrop` to the probe
    // it holds — ordinary forwarding, without the exclusive bit, under
    // the delegation origin read off its registry path.
    assert_eq!(
        line("tracing::instrument::Instrumented<delegation_cases::Probe<8>> ::"),
        "tracing::instrument::Instrumented<delegation_cases::Probe<8>> :: members future[poll, \
         delegated by core::pin::Pin<alloc::boxed::Box<tracing::instrument::Instrumented<\
         delegation_cases::Probe<8>>, alloc::alloc::Global>>] continuation rule # delegate \
         inner.value.__0@+40 -> delegation_cases::Probe<8>",
        "{program}"
    );
    let source = exegesis::testkit::assert_instrumented_origin(bundle);
    assert!(
        table.contains(&format!(
            "delegation tracing 0.1.40 family tracing-instrumented-0.1.40 from {source} \
             (0 checksummed files)"
        )),
        "{program}: {table}"
    );
    // The hand-written wrappers have no rule: a gate that is not a
    // future, a retained enum, a raw pointer. Their probes are proved
    // futures by their own polls only, never by delegation.
    for (wrapper, probe) in [
        (
            "delegation_cases::Gated<1>",
            Some("delegation_cases::Probe<1>"),
        ),
        (
            "delegation_cases::Gated<2>",
            Some("delegation_cases::Probe<2>"),
        ),
        ("delegation_cases::Retained", None),
        ("delegation_cases::RawHolder", None),
    ] {
        assert_eq!(
            line(&format!("{wrapper} ::")),
            format!(
                "{wrapper} :: members future[poll, delegated by core::pin::Pin<alloc::boxed::Box<\
                 {wrapper}, alloc::alloc::Global>>] continuation unknown (NoRule)"
            ),
            "{program}"
        );
        if let Some(probe) = probe {
            assert_eq!(
                line(&format!("{probe} ::")),
                format!("{probe} :: members future[poll] continuation unknown (NoRule)"),
                "{program}"
            );
        }
    }
    // Structurally: every exclusive delegation is under a std or
    // compiler rule, every `Instrumented` delegation is not exclusive,
    // and both kinds of forwarding are present.
    let mut exclusive = 0;
    let mut ordinary = 0;
    for record in &bundle.semantics.types {
        let Some(facts) = &record.future else {
            continue;
        };
        let Continuation::Bound { rule, program: p } = &facts.continuation else {
            continue;
        };
        let kind = bundle.semantics.rules[rule.0 as usize].kind;
        let actions: Vec<&PollAction> = match p {
            PollProgram::Direct(a) => vec![a],
            PollProgram::MatchVariant { cases, .. } => cases.iter().map(|c| &c.action).collect(),
        };
        for action in actions {
            if let PollAction::Delegate { exclusive: e, .. } = action {
                if *e {
                    exclusive += 1;
                    assert_ne!(kind, SemanticRuleKind::TracingInstrumented, "{program}");
                } else {
                    ordinary += 1;
                    assert_eq!(kind, SemanticRuleKind::TracingInstrumented, "{program}");
                }
            }
        }
    }
    assert!(
        exclusive > 0 && ordinary == 1,
        "{program}: {exclusive} / {ordinary}"
    );
}

/// What every fixture's semantic bindings must satisfy: a layout rule
/// per kind actually bound, every rule under a versioned tokio origin
/// inside the reviewed range (or futures-util's unversioned one), every
/// compiler rule under one of the reviewed rustc families for the
/// target's own producer, a delegation origin only for the pinned
/// tracing, every bound program of the shape its rule kind allows —
/// primitive on a resource, a match on a coroutine, a single delegation
/// on an adapter or wrapper, exclusive only under a rule reviewed for
/// it — and every task entry's scheduler class bound and agreeing with
/// the name of its `S` — the cross-check that keeps the route-based
/// binding honest against the spelling the runtime still classifies by.
fn assert_library_bindings(program: &str, bundle: &Bundle) {
    use exegesis::detect::semantics::FUTURES_UTIL_ADAPTERS_V0_3_30;
    use hansei_bundle::{
        Continuation, FutureTarget, LayoutSelection, PollAction, PollProgram, SchedulerClass,
        SemanticOrigin, SemanticRuleKind,
    };
    let s = |id| bundle.strings.get(id).unwrap();
    for origin in &bundle.semantics.origins {
        match origin {
            SemanticOrigin::Rustc { producer, family } => {
                assert!(
                    s(*producer).contains(&format!("rustc version {}", bundle.meta.rustc_version)),
                    "{program}: compiler origin {:?} is not the target's producer {:?}",
                    s(*producer),
                    bundle.meta.rustc_version
                );
                use exegesis::detect::semantics::{
                    RUSTC_CORE_PENDING_V1_97, RUSTC_COROUTINE_V1_97, RUSTC_DYN_FUTURE_ABI_V1_97,
                    RUSTC_STD_ADAPTERS_V1_97,
                };
                assert!(
                    [
                        RUSTC_COROUTINE_V1_97.family,
                        RUSTC_STD_ADAPTERS_V1_97.family,
                        RUSTC_DYN_FUTURE_ABI_V1_97.family,
                        RUSTC_CORE_PENDING_V1_97.family,
                    ]
                    .contains(&s(*family)),
                    "{program}: unexpected compiler family {:?}",
                    s(*family)
                );
            }
            SemanticOrigin::LibraryDelegation {
                package, version, ..
            } => match s(*package) {
                "tracing" => {
                    assert_eq!(s(*version), "0.1.40", "{program}");
                    assert_eq!(
                        program, "delegation-cases",
                        "{program}: only the delegation fixture instruments a future"
                    );
                }
                "futures-util" => {
                    assert!(
                        FUTURES_UTIL_ADAPTERS_V0_3_30.select(&s(*version).parse().unwrap())
                            == LayoutSelection::ReviewedRange,
                        "{program}: futures-util {} is outside the reviewed range",
                        s(*version)
                    );
                    // Only the combinator fixture maps a future; every
                    // other program binding this origin does so for a
                    // `Next` — and which programs keep a `Next::poll`
                    // out of line is the target's call, so no list.
                    if program != "select-combinator" {
                        let origin_id = bundle
                            .semantics
                            .origins
                            .iter()
                            .position(|o| std::ptr::eq(o, origin))
                            .unwrap();
                        for rule in &bundle.semantics.rules {
                            if rule.origin.0 as usize == origin_id {
                                assert_eq!(
                                    rule.kind,
                                    SemanticRuleKind::FuturesUtilNext,
                                    "{program}: only `Next` binds futures-util here"
                                );
                            }
                        }
                    }
                }
                // The stream route and the map container: only the one
                // fixture that depends on tokio-stream can hold either
                // type, and each binds under its own family.
                "tokio-stream" => {
                    use exegesis::detect::semantics::{
                        TOKIO_STREAM_MAP_V0_1_14, TOKIO_STREAM_WATCH_V0_1_14,
                    };
                    let SemanticOrigin::LibraryDelegation { family, .. } = origin else {
                        unreachable!()
                    };
                    let convention = if s(*family) == TOKIO_STREAM_MAP_V0_1_14.family {
                        &TOKIO_STREAM_MAP_V0_1_14
                    } else {
                        assert_eq!(s(*family), TOKIO_STREAM_WATCH_V0_1_14.family, "{program}");
                        &TOKIO_STREAM_WATCH_V0_1_14
                    };
                    assert_eq!(
                        convention.select(&s(*version).parse().unwrap()),
                        LayoutSelection::ReviewedRange,
                        "{program}: tokio-stream {} is outside the reviewed range",
                        s(*version)
                    );
                    assert_eq!(program, "watch-stream", "{program}");
                }
                "tokio-util" => {
                    use exegesis::detect::semantics::TOKIO_UTIL_REUSABLE_BOX_V0_7_11;
                    let SemanticOrigin::LibraryDelegation { family, .. } = origin else {
                        unreachable!()
                    };
                    assert_eq!(
                        s(*family),
                        TOKIO_UTIL_REUSABLE_BOX_V0_7_11.family,
                        "{program}"
                    );
                    assert_eq!(
                        TOKIO_UTIL_REUSABLE_BOX_V0_7_11.select(&s(*version).parse().unwrap()),
                        LayoutSelection::ReviewedRange,
                        "{program}: tokio-util {} is outside the reviewed range",
                        s(*version)
                    );
                    assert_eq!(program, "watch-stream", "{program}");
                }
                // The `select!` rule is the one tokio delegation read
                // off a declaration file (`Coop` binds on its layout,
                // under tokio's layout origin): it reads tokio's version
                // off the closure's, and it is the version the fixture's
                // lockfile pinned — the one the layout family was
                // selected by.
                "tokio" => {
                    assert_eq!(
                        s(*version),
                        bundle.meta.tokio_version.as_ref().unwrap().to_string(),
                        "{program}"
                    );
                    let SemanticOrigin::LibraryDelegation { family, source, .. } = origin else {
                        unreachable!()
                    };
                    use exegesis::detect::semantics::{
                        TOKIO_INTERVAL_TICK_V1_47, TOKIO_SELECT_V1_47,
                    };
                    let family = s(*family);
                    if family == TOKIO_SELECT_V1_47.family {
                        assert!(
                            SELECT_PROGRAMS.contains(&program),
                            "{program}: only the fixtures with a select! bind its rule"
                        );
                    } else if family == TOKIO_INTERVAL_TICK_V1_47.family {
                        // Which programs keep a `tick` closure's
                        // declaration out of line is the target's
                        // call, so no program list; the file is.
                        assert!(
                            s(*source).ends_with("/src/time/interval.rs"),
                            "{program}: {}",
                            s(*source)
                        );
                    } else {
                        panic!("{program}: unexpected tokio delegation family {family}");
                    }
                }
                other => panic!("{program}: unexpected delegation origin {other:?}"),
            },
            SemanticOrigin::LibraryLayout {
                package,
                version,
                family,
                selection,
            } if s(*package) == "tokio" => {
                let version = version.expect("the fixtures' tokio version is recovered");
                assert_eq!(
                    s(version),
                    bundle.meta.tokio_version.as_ref().unwrap().to_string(),
                    "{program}"
                );
                assert_eq!(
                    s(*family),
                    exegesis::detect::Family::select(bundle.meta.tokio_version.as_ref()).name(),
                    "{program}"
                );
                assert_eq!(*selection, LayoutSelection::ReviewedRange, "{program}");
            }
            SemanticOrigin::LibraryLayout {
                package, selection, ..
            } if s(*package) == "futures-util" => {
                assert_eq!(*selection, LayoutSelection::VersionUnknown, "{program}");
            }
            other => panic!("{program}: unexpected semantic origin {other:?}"),
        }
    }
    // A state protocol binds only under the reviewed tokio origin — the
    // one origin whose selection the assertion above pinned.
    for rule in &bundle.semantics.rules {
        if matches!(
            rule.kind,
            SemanticRuleKind::TokioSleepState
                | SemanticRuleKind::TokioJoinHandleState
                | SemanticRuleKind::TokioAcquireState
                | SemanticRuleKind::TokioIoState
        ) {
            assert!(
                matches!(
                    &bundle.semantics.origins[rule.origin.0 as usize],
                    SemanticOrigin::LibraryLayout {
                        package,
                        selection: LayoutSelection::ReviewedRange,
                        ..
                    } if s(*package) == "tokio"
                ),
                "{program}: {:?} under an unreviewed origin",
                rule.kind
            );
        }
    }
    let rule_kind = |id: hansei_bundle::SemanticRuleId| bundle.semantics.rules[id.0 as usize].kind;
    // The reviewed control-flow guarantee, by rule kind: what a
    // coroutine's resumption and the std adapters' forwarding were
    // reviewed to be, and what a span-entering wrapper was not.
    let exclusive_kinds = [
        SemanticRuleKind::RustcAsyncFn,
        SemanticRuleKind::RustcAsyncBlock,
        SemanticRuleKind::StdBoxPoll,
        SemanticRuleKind::StdMutRefPoll,
        SemanticRuleKind::StdPinBoxPoll,
        SemanticRuleKind::StdPinMutRefPoll,
        SemanticRuleKind::FuturesUtilMap,
        SemanticRuleKind::FuturesUtilMapErr,
        SemanticRuleKind::FuturesUtilIntoFuture,
        SemanticRuleKind::HyperUtilTokioSleep,
        SemanticRuleKind::TokioCoop,
        SemanticRuleKind::FuturesUtilNext,
        SemanticRuleKind::TokioIntervalTick,
    ];
    let delegate_kinds = [
        SemanticRuleKind::StdBoxPoll,
        SemanticRuleKind::StdMutRefPoll,
        SemanticRuleKind::StdPinBoxPoll,
        SemanticRuleKind::StdPinMutRefPoll,
        SemanticRuleKind::TracingInstrumented,
        SemanticRuleKind::FuturesUtilMap,
        SemanticRuleKind::FuturesUtilMapErr,
        SemanticRuleKind::FuturesUtilIntoFuture,
        SemanticRuleKind::HyperUtilTokioSleep,
        SemanticRuleKind::TokioCoop,
        SemanticRuleKind::FuturesUtilNext,
        SemanticRuleKind::TokioIntervalTick,
    ];
    // A wrapper's program is not a storage access: only the std
    // adapters, which are pointers, carry one. `Next` holds a `&mut`
    // but is a future of its own, and the dereference is its program's;
    // so is the tick's, through its closure's capture.
    let wrapper_kinds = [
        SemanticRuleKind::TracingInstrumented,
        SemanticRuleKind::FuturesUtilMap,
        SemanticRuleKind::FuturesUtilMapErr,
        SemanticRuleKind::FuturesUtilIntoFuture,
        SemanticRuleKind::HyperUtilTokioSleep,
        SemanticRuleKind::TokioCoop,
        SemanticRuleKind::FuturesUtilNext,
        SemanticRuleKind::TokioIntervalTick,
    ];
    // Compiler storage: every async fn or async block environment binds
    // its states under the reviewed convention (the fixtures' toolchains
    // are all inside it), carries the matching evidence, and every other
    // compiler candidate stays unavailable with its reason.
    for record in &bundle.semantics.types {
        let name = bundle
            .types
            .name_index
            .iter()
            .find(|&&(_, id)| id == record.ty)
            .map(|&(name, _)| s(name))
            .unwrap_or_default();
        if !hansei_bundle::names::is_coroutine_candidate(name) {
            assert!(record.coroutine.is_none(), "{program}: {name}");
            continue;
        }
        match hansei_bundle::names::coroutine_kind(name) {
            Some(kind @ ("async fn" | "async block")) => {
                let layout = record.coroutine.as_ref().unwrap_or_else(|| {
                    let issues: Vec<String> = record
                        .issues
                        .iter()
                        .map(|i| format!("{:?}: {}", i.kind, i.detail.map(s).unwrap_or("")))
                        .collect();
                    panic!("{program}: {name} has no coroutine layout: {issues:?}")
                });
                assert_eq!(
                    record.storage,
                    hansei_bundle::StoragePolicy::CoroutineStates,
                    "{program}: {name}"
                );
                assert!(
                    record.future.as_ref().is_some_and(|facts| facts
                        .evidence
                        .contains(&hansei_bundle::FutureEvidence::Coroutine(layout.rule))),
                    "{program}: {name} lacks coroutine evidence"
                );
                assert!(layout.states.len() >= 3, "{program}: {name}");
                // Each kind under its own rule: a block is not an fn's
                // rule with different states.
                let expected = if kind == "async fn" {
                    SemanticRuleKind::RustcAsyncFn
                } else {
                    SemanticRuleKind::RustcAsyncBlock
                };
                assert_eq!(
                    bundle.semantics.rules[layout.rule.0 as usize].kind, expected,
                    "{program}: {name}"
                );
            }
            _ => {
                assert!(
                    matches!(record.storage, hansei_bundle::StoragePolicy::Unavailable(_)),
                    "{program}: {name}"
                );
                assert!(!record.issues.is_empty(), "{program}: {name}");
            }
        }
    }
    for record in &bundle.semantics.types {
        if let Some(access) = &record.access {
            let kind = rule_kind(access.rule);
            assert!(
                matches!(
                    kind,
                    SemanticRuleKind::StdBoxAccess
                        | SemanticRuleKind::StdMutRefAccess
                        | SemanticRuleKind::StdPinBoxAccess
                        | SemanticRuleKind::StdPinMutRefAccess
                        | SemanticRuleKind::TokioStreamWatchStream
                        | SemanticRuleKind::TokioUtilReusableBox
                ),
                "{program}: access under {kind:?}"
            );
            // The two library routes are owned storage on a type that
            // is no future: polled through, never polled.
            if matches!(
                kind,
                SemanticRuleKind::TokioStreamWatchStream | SemanticRuleKind::TokioUtilReusableBox
            ) {
                assert_eq!(access.kind, hansei_bundle::AccessKind::Owned, "{program}");
                assert!(
                    record.future.is_none(),
                    "{program}: a stream route with future facts"
                );
            }
        }
        let Some(facts) = &record.future else {
            continue;
        };
        match &facts.continuation {
            Continuation::Unknown(_) => assert!(record.resource.is_none()),
            Continuation::Bound {
                rule,
                program: PollProgram::Direct(PollAction::Primitive),
            } => assert!(
                record.resource.as_ref().is_some_and(|r| r.rule == *rule),
                "{program}: {:?}",
                facts.continuation
            ),
            // The one terminal program: core's `Pending`, under its
            // compiler rule, on a record with nothing to read.
            Continuation::Bound {
                rule,
                program: PollProgram::Direct(PollAction::NeverReady),
            } => {
                assert_eq!(rule_kind(*rule), SemanticRuleKind::CorePending, "{program}");
                assert!(
                    record.resource.is_none() && record.coroutine.is_none(),
                    "{program}: never ready beside state"
                );
            }
            Continuation::Bound {
                rule,
                program: PollProgram::Direct(PollAction::Delegate { target, exclusive }),
            } => {
                let kind = rule_kind(*rule);
                assert!(
                    delegate_kinds.contains(&kind),
                    "{program}: a direct delegation under {kind:?}"
                );
                assert_eq!(
                    *exclusive,
                    exclusive_kinds.contains(&kind),
                    "{program}: exclusivity under {kind:?}"
                );
                assert_eq!(
                    wrapper_kinds.contains(&kind),
                    record.access.is_none(),
                    "{program}: an adapter's program is also its storage access"
                );
                if let Some(access) = &record.access {
                    assert_eq!(&access.target, target, "{program}");
                }
                if let FutureTarget::Dynamic { layout, .. } = target {
                    assert_eq!(rule_kind(layout.abi), SemanticRuleKind::DynFutureAbi);
                    // A poll slot is claimed for a bare `dyn Future`
                    // and for nothing else: another trait puts its
                    // supertrait's methods where its own declaration
                    // says, which no reviewed ABI covers.
                    let pointee = bundle
                        .types
                        .name_index
                        .iter()
                        .find(|&&(_, ty)| ty == layout.trait_ty)
                        .map(|&(name, _)| s(name))
                        .unwrap_or_default();
                    assert_eq!(
                        layout.poll_slot.is_some(),
                        hansei_bundle::names::is_future_trait_object(pointee),
                        "{program}: poll slot over {pointee}"
                    );
                }
            }
            Continuation::Bound {
                rule,
                program: PollProgram::MatchVariant { state, cases },
            } => {
                // A coroutine's states, or futures-util's `Map`, whose
                // two states are the only other reviewed match.
                let states = match &record.coroutine {
                    Some(layout) => {
                        assert_eq!(layout.rule, *rule, "{program}");
                        layout.states.len()
                    }
                    None => {
                        assert_eq!(
                            rule_kind(*rule),
                            SemanticRuleKind::FuturesUtilMap,
                            "{program}: a match program on a non-coroutine"
                        );
                        2
                    }
                };
                assert!(
                    state.steps.is_empty() && state.target == record.ty,
                    "{program}"
                );
                assert_eq!(cases.len(), states, "{program}");
                for case in cases {
                    if let PollAction::Delegate { exclusive, .. } = &case.action {
                        assert!(*exclusive, "{program}: a reviewed resumption is exclusive");
                    }
                }
            }
            other => panic!("{program}: unexpected continuation {other:?}"),
        }
        if let Some(layout) = &record.coroutine {
            assert!(
                matches!(
                    &facts.continuation,
                    Continuation::Bound { rule, program: PollProgram::MatchVariant { .. } }
                        if *rule == layout.rule
                ),
                "{program}: a bound coroutine has its match program"
            );
        }
    }
    for (index, entry) in bundle.tasks.entries.iter().enumerate() {
        let scheduler = bundle
            .types
            .name_index
            .iter()
            .find(|&&(_, id)| id == entry.scheduler)
            .map(|&(name, _)| s(name))
            .unwrap_or_else(|| panic!("{program}: task {index} has an unnamed scheduler"));
        let arc_of = |inner: &str| {
            scheduler
                .strip_prefix("alloc::sync::Arc<")
                .and_then(|rest| rest.strip_prefix(inner))
                .is_some_and(|rest| rest == ">" || rest.starts_with(','))
        };
        let expected = if arc_of("tokio::runtime::scheduler::multi_thread::handle::Handle") {
            SchedulerClass::MultiThread
        } else if arc_of("tokio::runtime::scheduler::current_thread::Handle") {
            SchedulerClass::CurrentThread
        } else if arc_of("tokio::task::local::Shared") {
            SchedulerClass::LocalSet
        } else if scheduler == "tokio::runtime::blocking::schedule::BlockingSchedule" {
            SchedulerClass::Blocking
        } else {
            panic!("{program}: task {index} has an unexpected scheduler {scheduler}");
        };
        let binding = entry.scheduler_binding.as_ref().unwrap_or_else(|| {
            panic!("{program}: task {index} ({scheduler}) has no scheduler binding")
        });
        assert_eq!(
            binding.class, expected,
            "{program}: task {index} ({scheduler})"
        );
    }
    // The class routes' spellings: an `Arc`'s data past its counts, or
    // the blocking schedule's hooks, never an empty path that would bind
    // at the `S` type itself.
    for (role, path) in [
        (WalkRole::MtSchedulerHandle, "ptr.pointer.*.data"),
        (WalkRole::CtSchedulerHandle, "ptr.pointer.*.data"),
        (WalkRole::LocalSchedulerShared, "ptr.pointer.*.data"),
        (WalkRole::BlockingScheduleHooks, "hooks"),
    ] {
        if matches!(
            bundle.walks.entries[&role].outcome,
            WalkOutcome::Bound { .. }
        ) {
            assert_walk(program, bundle, role, path);
        }
    }
}

/// Structural assertions that hold for every fixture — the "zero silent
/// drops" checks plus metadata sanity.
/// Every `core::future::pending::Pending<T>` the program proves a
/// future — by awaiting it, by spawning it — binds the never-ready
/// terminal under the compiler rule, with its origin the target's own
/// producer under the reviewed family; a record the evidence does not
/// reach binds nothing. The two fixtures whose task-level wait is the
/// terminal must hold at least one such binding, as must every
/// program whose `main` parks on `pending()` — which is nearly all of
/// them, but which programs keep that root out of line is the target's
/// call, so no list.
fn assert_never_ready(program: &str, bundle: &Bundle) {
    use hansei_bundle::{Continuation, PollAction, PollProgram, SemanticOrigin, SemanticRuleKind};
    let s = |id| bundle.strings.get(id).unwrap();
    let mut bound = 0;
    for record in &bundle.semantics.types {
        let Some(name) = bundle
            .types
            .name_index
            .iter()
            .find(|&&(_, ty)| ty == record.ty)
            .map(|&(name, _)| s(name))
        else {
            continue;
        };
        if !name.starts_with("core::future::pending::Pending<") {
            continue;
        }
        let Some(facts) = &record.future else {
            panic!("{program}: {name} has a record but is no future");
        };
        assert!(
            !facts.evidence.is_empty(),
            "{program}: {name} is a future on no evidence"
        );
        let Continuation::Bound { rule, program: p } = &facts.continuation else {
            panic!(
                "{program}: {name} is a proven future with no program: {:?}",
                facts.continuation
            );
        };
        assert!(
            matches!(p, PollProgram::Direct(PollAction::NeverReady)),
            "{program}: {name}: {p:?}"
        );
        let rule = &bundle.semantics.rules[rule.0 as usize];
        assert_eq!(
            rule.kind,
            SemanticRuleKind::CorePending,
            "{program}: {name}"
        );
        let SemanticOrigin::Rustc { producer, family } =
            &bundle.semantics.origins[rule.origin.0 as usize]
        else {
            panic!("{program}: {name} under a library origin");
        };
        assert_eq!(
            s(*family),
            exegesis::detect::semantics::RUSTC_CORE_PENDING_V1_97.family,
            "{program}: {name}"
        );
        assert!(
            s(*producer).contains(&format!("rustc version {}", bundle.meta.rustc_version)),
            "{program}: {name} under {:?}",
            s(*producer)
        );
        assert!(
            record.resource.is_none() && record.coroutine.is_none() && record.access.is_none(),
            "{program}: {name} carries another capability"
        );
        bound += 1;
    }
    if matches!(program, "foreign-runtime" | "delegation-cases") {
        assert!(bound > 0, "{program}: no never-ready binding");
    }
}

fn assert_clean(program: &str, bundle: &Bundle, stats: &ExtractStats) {
    assert_addresses_by_name(program, bundle);
    // The impl table records only what the bundle's strings mention —
    // an entry nothing names is dead weight the emit filter should have
    // dropped. (Sortedness and the plain-path value rules are the
    // validator's, which the save above already ran.)
    for &(path, _) in &bundle.impls.entries {
        let path = bundle.strings.get(path).unwrap();
        // Strictly longer: the key itself was interned for the table,
        // so its own row must not count as a mention.
        assert!(
            bundle
                .strings
                .iter()
                .any(|s| s.len() > path.len() && s.contains(path)),
            "{program}: impl table entry {path:?} is mentioned by no string"
        );
    }
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
    // Every task Trailer parks the join waker in the same loom cell
    // chain; the walk lands on the RawWaker inside the armed Waker.
    assert_walk(
        program,
        bundle,
        WalkRole::TrailerWaker,
        "waker.__0.value.<Some>.__0.waker",
    );
    // Every fixture links the io driver, and its registrations' guard
    // is the parking_lot raw mutex behind the loom wrapper's second
    // field — the same spelling the semaphore's guard binds.
    assert_walk(
        program,
        bundle,
        WalkRole::ScheduledIoLock,
        "waiters.__1.raw",
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
    // A bare dyn pointee has no header, so no prefix; an `Arc<dyn>`'s data
    // pointer targets `ArcInner`, whose two refcount words are the one
    // prefix the reader rounds to the concrete type's alignment. Every
    // runtime carries both: the boxed `Any` is a `JoinError`'s panic
    // payload, the `Arc<dyn Fn>` a task hook.
    assert_format(
        program,
        bundle,
        "alloc::boxed::Box<(dyn core::any::Any + core::marker::Send), alloc::alloc::Global>",
        "alloc::boxed::Box<(dyn core::any::Any + core::marker::Send), alloc::alloc::Global> \
         :: Node DynPointer { pointer=pointer@+0, vtable=vtable@+8, \
         slots=[drop_in_place:0, size:1, align:2], tail_prefixes=[] }",
    );
    assert_format(
        program,
        bundle,
        "*const alloc::sync::ArcInner<(dyn core::ops::function::Fn<(), Output=()> \
         + core::marker::Send + core::marker::Sync)>",
        "*const alloc::sync::ArcInner<(dyn core::ops::function::Fn<(), Output=()> \
         + core::marker::Send + core::marker::Sync)> \
         :: Node DynPointer { pointer=pointer@+0, vtable=vtable@+8, \
         slots=[drop_in_place:0, size:1, align:2], tail_prefixes=[16] }",
    );
    assert_format(
        program,
        bundle,
        "core::task::wake::RawWakerVTable",
        "core::task::wake::RawWakerVTable :: Node Struct \
         { clone: Symbol { clone@+0 }, wake: Symbol { wake@+8 }, \
         wake_by_ref: Symbol { wake_by_ref@+16 }, drop: Symbol { drop@+24 } }",
    );
    if program == "simple-await" {
        // The env-decl table, from both of an async fn's sources: `work`
        // is declared at its `fn` line, and `ready_value` — whose outer
        // fn is inlined away, leaving only the resume fn — at its body's
        // `{`, which for a one-line signature is the same line.
        assert_env_decl(program, bundle, "simple_await::work::{async_fn_env#0}", 21);
        assert_env_decl(
            program,
            bundle,
            "simple_await::ready_value::{async_fn_env#0}",
            17,
        );
    }
    if program == "enum-reprs" {
        // Each variant selects on the bits its tag holds. `Below` is the
        // case: a `-1` LLVM spells as one `0xff` byte has to become the
        // four-byte tag's `0xffff_ffff`, and `-2` on the eight-byte tag
        // its `0xffff_ffff_ffff_fffe`; the unsigned control's `0xff`
        // byte stays `0xff`. Everything spelled at the tag's width
        // passes through.
        assert_discr_values(
            program,
            bundle,
            "enum_reprs::Signed32",
            "i32",
            &[
                ("Below", Some(0xffff_ffff)),
                ("Zero", Some(0)),
                ("Wide", Some(1000)),
            ],
        );
        assert_discr_values(
            program,
            bundle,
            "enum_reprs::Signed64",
            "i64",
            &[
                ("Below", Some(0xffff_ffff_ffff_fffe)),
                ("Zero", Some(0)),
                ("Floor", Some(0x8000_0000_0000_0000)),
            ],
        );
        assert_discr_values(
            program,
            bundle,
            "enum_reprs::Unsigned32",
            "u32",
            &[
                ("Byte", Some(0xff)),
                ("Zero", Some(0)),
                ("Top", Some(0xffff_ffff)),
            ],
        );
        // A C-style enum stores the value each constant names.
        assert_enumerators(
            program,
            bundle,
            "enum_reprs::Level",
            &[("Below", -1), ("Base", 0), ("Above", 7)],
        );
    }
    if program == "select-combinator" {
        assert_select(
            program,
            bundle,
            "core::future::poll_fn::PollFn<select_combinator::selector::{async_fn#0}::{closure_env#",
            2,
        );
        // A multi-line signature is where the two sources disagree: the
        // fn at 26, its resume fn at the `{` on 30. The fn wins.
        assert_env_decl(
            program,
            bundle,
            "select_combinator::selector::{async_fn_env#0}",
            26,
        );
    }
    if program == "blocking-pool" {
        // A closure declares at its own line, which is its body fn's —
        // a sibling of the env, never the enclosing block the env's
        // namespace names: the `spawn_blocking` closure is written at
        // 39 inside a block declared at 36.
        assert_env_decl(
            program,
            bundle,
            "blocking_pool::main::{async_block#0}::{closure_env#0}",
            39,
        );
    }
    if program == "futurelock" {
        // Blocks declare at their own line the same way: the background
        // task's block is written at 48 inside a fn declared at 42, and
        // main's spawned block at 20 inside a block at 19. The closure
        // `select!` expands inside `do_stuff` is written by the macro,
        // and declares where the macro's own source writes it.
        assert_env_decl(
            program,
            bundle,
            "futurelock::start_background_task::{async_fn#0}::{async_block_env#0}",
            48,
        );
        assert_env_decl(
            program,
            bundle,
            "futurelock::main::{async_block#0}::{async_block_env#0}",
            20,
        );
        assert_env_decl(program, bundle, "futurelock::main::{async_block_env#0}", 19);
        let (file, _) = env_decl(
            program,
            bundle,
            "futurelock::do_stuff::{async_fn#0}::{closure_env#0}",
        );
        assert!(file.ends_with("/macros/select.rs"), "{program}: {file}");
        // And that closure is the select rule's: two branches, the
        // boxed future and the sleep.
        assert_select(
            program,
            bundle,
            "core::future::poll_fn::PollFn<futurelock::do_stuff::{async_fn#0}::{closure_env#",
            2,
        );
    }
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
        // The C strings are `Str` with `nul_terminated`: the length counts
        // the trailing NUL, which the render trims and verifies. A `&CStr`
        // is a fat pointer like `&str`; a `CString` keeps the box's words
        // behind its `inner` member.
        assert_format(
            program,
            bundle,
            "&core::ffi::c_str::CStr",
            "&core::ffi::c_str::CStr :: Node Str \
             { pointer=data_ptr@+0, length=length@+8, nul_terminated }",
        );
        assert_format(
            program,
            bundle,
            "alloc::ffi::c_str::CString",
            "alloc::ffi::c_str::CString :: Node Str \
             { pointer=inner.data_ptr@+0, length=inner.length@+8, nul_terminated }",
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
        // A `char` is a 4-byte `DW_ATE_UTF` base type, which is what
        // reify's code-point reading of it rests on: a 1-byte char is C's
        // and stays a byte.
        let char_defs: Vec<_> = bundle
            .types
            .find_by_name(&bundle.strings, "char")
            .filter_map(|id| match bundle.types.get(id) {
                Some(TypeDef::Base { size, encoding, .. }) => Some((*size, *encoding)),
                _ => None,
            })
            .collect();
        assert_eq!(
            char_defs,
            [(4, Encoding::UtfChar)],
            "{program}: `char` is not one 4-byte UTF base type"
        );
    }
    if program == "futurelock" {
        // What the state-stripping pass leaves of three coroutines, from
        // the raw DWARF's listing of every capture in every state. The
        // background task's block captures `lock` and `tx`, and both are
        // its live storage while it waits on the lock, so its suspended
        // state keeps them. `do_stuff`'s `lock` is an argument still live
        // at its first suspend: rustc relocates it to a saved slot and
        // lists it twice, and one copy survives. `start_background_task`
        // moves its `lock` into the block before ever suspending, so the
        // stale copy at its `Unresumed` slot goes.
        assert_state_members(
            program,
            bundle,
            "futurelock::start_background_task::{async_fn#0}::{async_block_env#0}::Suspend0",
            &["__awaitee", "__1", "lock", "tx"],
        );
        assert_state_members(
            program,
            bundle,
            "futurelock::do_stuff::{async_fn_env#0}::Suspend0",
            &["lock", "future1", "disabled", "futures", "__awaitee"],
        );
        assert_state_members(
            program,
            bundle,
            "futurelock::start_background_task::{async_fn_env#0}::Suspend0",
            &["__awaitee", "__1", "__2", "__3"],
        );
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
                 discr=(Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) < 0xfffffffffffffffe), \
                 arms=[1=>(Computed(\
                 (Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) - \
                 Read(driver.{{CurrentThread}}.__0.ptr.pointer.*.data.driver.time.{{Some}}.__0.inner.\
                 {{Traditional}}.state.__1.data.value.wheel.elapsed@+{ct_wheel} | \
                 driver.{{MultiThread}}.__0.ptr.pointer.*.data.driver.time.{{Some}}.__0.inner.\
                 {{Traditional}}.state.__1.data.value.wheel.elapsed@+{mt_wheel}))))], \
                 default=Alias {{ deadline@+88, follow }} }} }}, \
                 state: Variant {{ discr=Read(registered@+104), arms=[0=>unregistered], \
                 default=Variant {{ \
                 discr=(Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) < 0xfffffffffffffffe), \
                 arms=[1=>registered], default=Variant {{ \
                 discr=(Read(inner.{{Some}}.__0.state.state.v.value.__0@+48) != 0xffffffffffffffff), \
                 arms=[0=>elapsed, 1=>pending fire] }} }} }} }}"
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
                 < 0xfffffffffffffffe), \
                 arms=[1=>(Computed(\
                 (Read(entry.{{Traditional}}.__0.inner.{{Some}}.__0.state.state.v.value.__0@+48) - \
                 Read(entry.{{Traditional}}.__0.driver.{{CurrentThread}}.__0.ptr.pointer.*.data.\
                 driver.time.{{Some}}.__0.inner.{{Traditional}}.state.__1.data.value.wheel.elapsed\
                 @+{ct_wheel} | \
                 entry.{{Traditional}}.__0.driver.{{MultiThread}}.__0.ptr.pointer.*.data.driver.\
                 time.{{Some}}.__0.inner.{{Traditional}}.state.__1.data.value.wheel.elapsed\
                 @+{mt_wheel}))))], \
                 default=Alias {{ entry.{{Traditional}}.__0.deadline@+88, follow }} }} }}, \
                 state: Variant {{ discr=Read(entry.{{Traditional}}.__0.registered@+104), \
                 arms=[0=>unregistered], default=Variant {{ \
                 discr=(Read(entry.{{Traditional}}.__0.inner.{{Some}}.__0.state.state.v.value.__0@+48) \
                 < 0xfffffffffffffffe), arms=[1=>registered], default=Variant {{ \
                 discr=(Read(entry.{{Traditional}}.__0.inner.{{Some}}.__0.state.state.v.value.__0@+48) \
                 != 0xffffffffffffffff), arms=[0=>elapsed, 1=>pending fire] }} }} }} }}"
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
    if program == "armed-select" {
        // The selector's four branches, each a `&mut` to one of the
        // frame's own locals: the binding names the tuple members,
        // and what they borrow is the inspection's to follow.
        assert_select(
            program,
            bundle,
            "core::future::poll_fn::PollFn<armed_select::selector::{async_fn#0}::{closure_env#",
            4,
        );
        // The ticker's two branches: the oneshot and the pinned tick.
        assert_select(
            program,
            bundle,
            "core::future::poll_fn::PollFn<armed_select::ticker::{async_fn#0}::{closure_env#",
            2,
        );
        let table = exegesis::describe::describe_semantics(bundle);
        // The forever task's three: the pinned `Pending`, the pinned
        // block and the pinned `Ready` its mask disables, each
        // borrowed. The terminal binds by the block's delegation on
        // every target; whether the bare `Pending`'s own pin keeps a
        // poll symbol and delegates too is the target's call (ELF
        // keeps it, Mach-O inlines it away), so only the block's
        // delegation and the verdict are pinned. The borrow of that
        // pin is crossed by its access route either way, and that
        // route is pinned rather than whether a poll stands beside it.
        assert_select(
            program,
            bundle,
            "core::future::poll_fn::PollFn<armed_select::forever::{async_fn#0}::{closure_env#",
            3,
        );
        let pending = semantic_line(&table, "core::future::pending::Pending<u32> :: ");
        assert!(
            pending
                .contains("delegated by armed_select::forever::{async_fn#0}::{async_block_env#0}")
                && pending.ends_with("continuation rule # never ready"),
            "{program}: {pending}"
        );
        let borrow = semantic_line(
            &table,
            "&mut core::pin::Pin<&mut core::future::pending::Pending<u32>> :: ",
        );
        assert!(
            borrow.contains("access Borrowed rule # *@+0 -> core::pin::Pin<&mut core::future::pending::Pending<u32>>"),
            "{program}: {borrow}"
        );
        // The tick's `PollFn` forwards through its closure's capture to
        // the interval's pinned box, exclusively, under tokio's tick
        // rule; the box, proved a future by that delegation, crosses to
        // the `Sleep` by its own std record.
        let tick_prefix = table
            .lines()
            .find(|line| {
                line.starts_with("core::future::poll_fn::PollFn<tokio::time::interval::{impl#")
                    && line.contains("}::tick::{async_fn#0}::{closure_env#0}> :: members")
            })
            .and_then(|line| line.split(" :: members").next())
            .unwrap_or_else(|| panic!("{program}: no record for the tick's PollFn"))
            .to_owned();
        let tick = semantic_line(&table, &tick_prefix);
        assert!(
            tick.contains(
                "continuation rule # delegate (exclusive) f._ref__self.*.delay@+16 -> \
                 core::pin::Pin<alloc::boxed::Box<tokio::time::sleep::Sleep, alloc::alloc::Global>>"
            ) && !tick.contains(" access "),
            "{program}: {tick}"
        );
        let tick_rule = bundle
            .semantics
            .rules
            .iter()
            .find(|rule| rule.kind == hansei_bundle::SemanticRuleKind::TokioIntervalTick)
            .unwrap_or_else(|| panic!("{program}: no tick rule bound"));
        let s = |id| bundle.strings.get(id).unwrap();
        assert!(
            matches!(
                &bundle.semantics.origins[tick_rule.origin.0 as usize],
                hansei_bundle::SemanticOrigin::LibraryDelegation { package, source, .. }
                    if s(*package) == "tokio" && s(*source).ends_with("/src/time/interval.rs")
            ),
            "{program}: {:?}",
            bundle.semantics.origins[tick_rule.origin.0 as usize]
        );
        let boxed = semantic_line(
            &table,
            "core::pin::Pin<alloc::boxed::Box<tokio::time::sleep::Sleep, alloc::alloc::Global>> :: members",
        );
        assert!(
            boxed.contains("delegated by core::future::poll_fn::PollFn<tokio::time::interval::")
                && boxed.contains(
                    "continuation rule # delegate (exclusive) pointer.*@+0 -> tokio::time::sleep::Sleep"
                ),
            "{program}: {boxed}"
        );
        // The oneshot's shared state renders with its flags by name.
        assert_format(
            program,
            bundle,
            "tokio::sync::oneshot::Inner<u32>",
            "tokio::sync::oneshot::Inner<u32> :: Node Struct \
             { state: state.inner.value.v.value.__0@+32, value: <structural>, \
             tx_task: <structural>, rx_task: <structural> }",
        );
        // The receivers a waker slot is read against: the oneshot's
        // `Arc` and the state word and two task slots behind it, the
        // channel's `Arc`, and the watch's `Arc` and the `Notify` array
        // its receivers queue on.
        assert_walk(
            program,
            bundle,
            WalkRole::OneshotInner,
            "inner.<Some>.__0.ptr.pointer",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::OneshotRxTask,
            "data.rx_task.__0.__0.value.value.value.__0.waker",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::OneshotTxTask,
            "data.tx_task.__0.__0.value.value.value.__0.waker",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::OneshotValue,
            "data.value.__0.value",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::MpscReceiverChan,
            "chan.inner.ptr.pointer",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::WatchReceiverShared,
            "shared.ptr.pointer",
        );
        assert_walk(
            program,
            bundle,
            WalkRole::WatchSharedNotifyRx,
            "data.notify_rx",
        );
    }
    if program == "watch-stream" {
        // Two selects, each over a oneshot and a stream's `next()`,
        // both pinned locals the select borrows: the resolver's over
        // a `WatchStream`, the mapper's over a `StreamMap` of them.
        assert_select(
            program,
            bundle,
            "core::future::poll_fn::PollFn<watch_stream::resolver::{async_fn#0}::{closure_env#",
            2,
        );
        assert_select(
            program,
            bundle,
            "core::future::poll_fn::PollFn<watch_stream::mapper::{async_fn#0}::{closure_env#",
            2,
        );
        // The linear route, record by record: `Next` forwards through
        // its `&mut` to the nominal stream, exclusively, and proves it
        // nothing; the stream is an owned access into tokio-util's box
        // with no future facts of its own; the box is an owned access
        // through `boxed` and the `Pin`'s member to the trait object,
        // resolved by the dyn join.
        let table = exegesis::describe::describe_semantics(bundle);
        let next = semantic_line(
            &table,
            "futures_util::stream::stream::next::Next<tokio_stream::wrappers::watch::WatchStream<u32>> :: members",
        );
        assert!(
            next.contains(
                "continuation rule # delegate (exclusive) stream.*@+0 -> \
                 tokio_stream::wrappers::watch::WatchStream<u32>"
            ) && !next.contains(" access "),
            "{program}: {next}"
        );
        let map = semantic_line(
            &table,
            "futures_util::stream::stream::next::Next<tokio_stream::stream_map::StreamMap<&str, \
             tokio_stream::wrappers::watch::WatchStream<u32>>> :: members",
        );
        assert!(
            map.contains(
                "continuation rule # delegate (exclusive) stream.*@+0 -> \
                 tokio_stream::stream_map::StreamMap<&str, tokio_stream::wrappers::watch::WatchStream<u32>>"
            ),
            "{program}: {map}"
        );
        let stream = semantic_line(
            &table,
            "tokio_stream::wrappers::watch::WatchStream<u32> :: members",
        );
        assert!(
            stream.contains(
                " access Owned rule # inner@+0 -> tokio_util::sync::reusable_box::ReusableBoxFuture<"
            ) && !stream.contains("future["),
            "{program}: {stream}"
        );
        let boxed = semantic_line(
            &table,
            "tokio_util::sync::reusable_box::ReusableBoxFuture<(core::result::Result<(), \
             tokio::sync::watch::error::RecvError>, tokio::sync::watch::Receiver<u32>)> :: members",
        );
        assert!(
            boxed.contains(
                " access Owned rule # dyn boxed.pointer@+0 -> alloc::boxed::Box<(dyn \
                 core::future::future::Future<Output="
            ) && !boxed.contains("future["),
            "{program}: {boxed}"
        );
        // The stream has no future facts, so nothing proves it one: no
        // record names it as a delegate's child.
        assert!(
            !table.contains("delegated by futures_util::stream::stream::next::Next<"),
            "{program}: a stream was proved a future by its `Next`"
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
        // The sender's `select!`: three branches behind the one
        // `PollFn` the macro expands to, whatever the two disabled
        // ones are — the binding lists the tuple, the mask is read at
        // runtime.
        assert_select(
            program,
            bundle,
            "core::future::poll_fn::PollFn<channels::send_waiter::{async_fn#0}::{closure_env#",
            3,
        );
        // The impl table resolved mpsc's Sender impl from a member
        // symbol: the `{impl#N}` index is a source-order accident a
        // tokio bump may shift, so the key pins everything but N.
        let sender_impl = bundle.impls.entries.iter().find_map(|&(path, self_type)| {
            (bundle.strings.get(self_type) == Some("tokio::sync::mpsc::bounded::Sender"))
                .then(|| bundle.strings.get(path).unwrap())
        });
        let sender_impl = sender_impl.unwrap_or_else(|| {
            panic!("{program}: no impl table entry resolves to the mpsc Sender")
        });
        assert!(
            sender_impl
                .strip_prefix("tokio::sync::mpsc::bounded::{impl#")
                .is_some_and(|rest| rest
                    .strip_suffix('}')
                    .is_some_and(|n| { !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) })),
            "{program}: unexpected impl path {sender_impl:?} for the mpsc Sender"
        );
        // The channel protocols bind at the receiver's `recv` future —
        // the `PollFn` over its closure, under whatever impl index the
        // compiler gave the block — and at the borrowed `Notified`;
        // the receiver itself is a handle, not an operation.
        assert_resource(
            program,
            bundle,
            "core::future::poll_fn::PollFn<tokio::sync::mpsc::bounded::{impl#",
            hansei_bundle::ResourceKind::MpscRecv,
        );
        assert_resource(
            program,
            bundle,
            "tokio::sync::notify::Notified",
            hansei_bundle::ResourceKind::Notified,
        );
        assert_no_resource(program, bundle, "tokio::sync::mpsc::bounded::Receiver<u32>");
        // A oneshot receiver is its own future, so the binding is on
        // the receiver itself.
        assert_resource(
            program,
            bundle,
            "tokio::sync::oneshot::Receiver<u32>",
            hansei_bundle::ResourceKind::OneshotRecv,
        );
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
             { break if ((Load((Var(2) + 0x90), 8) & (0x1 << (Var(0) - Load((Var(2) + 0x80), 8)))) \
             != (0x1 << (Var(0) - Load((Var(2) + 0x80), 8)))); \
             emit((Var(2) + (0x0 + ((Var(0) - Load((Var(2) + 0x80), 8)) * 0x4)))); \
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
             { break if ((Load((Var(2) + 0x90), 8) & (0x1 << (Var(0) - Load((Var(2) + 0x80), 8)))) \
             != (0x1 << (Var(0) - Load((Var(2) + 0x80), 8)))); \
             emit((Var(2) + (0x0 + ((Var(0) - Load((Var(2) + 0x80), 8)) * 0x4)))); \
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
             { break if ((Load((Var(2) + 0x90), 8) & (0x1 << (Var(0) - Load((Var(2) + 0x80), 8)))) \
             != (0x1 << (Var(0) - Load((Var(2) + 0x80), 8)))); \
             emit((Var(2) + (0x0 + ((Var(0) - Load((Var(2) + 0x80), 8)) * 0x4)))); \
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
    let (bundle, stats) = extract_fixture(program, &opts);

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

    // What the bundle says it was made from: the vtable scan read the
    // binary — beside a recorded dSYM on macOS, where the pair form
    // supplied the DWARF, and alone on ELF hosts.
    match &bundle.meta.vtable_data {
        exegesis::bundle::VtableDataSource::File(file) => assert_eq!(file, program),
        exegesis::bundle::VtableDataSource::None => {
            panic!("{program}: the vtable scan should have had the binary to read")
        }
    }
    assert_eq!(
        bundle.meta.debug_info.is_some(),
        fixture_dsym(program).exists(),
        "{program}: a pair extraction records its debug source, a single-file one does not"
    );

    assert_clean(program, &bundle, &stats);

    // Real DWARF must retain positive task identity without turning the
    // dormant semantic programs into production continuation claims.
    for (index, task) in bundle.tasks.entries.iter().enumerate() {
        let record = bundle
            .semantics
            .types
            .iter()
            .find(|record| record.ty == task.future)
            .expect("task future has semantic identity");
        assert!(record.future.as_ref().unwrap().evidence.contains(
            &hansei_bundle::FutureEvidence::TaskEntry(hansei_bundle::TaskEntryId(index as u32)),
        ));
    }
    assert!(
        !bundle.semantics.types.is_empty(),
        "{program}: no semantic records"
    );
    assert_library_bindings(program, &bundle);
    assert_never_ready(program, &bundle);
    {
        use hansei_bundle::{ContainerKind, IoOperationKind, ResourceKind};
        match program {
            "sleep-join" => {
                assert_resource(
                    program,
                    &bundle,
                    "tokio::time::sleep::Sleep",
                    ResourceKind::Sleep,
                );
                assert_resource(
                    program,
                    &bundle,
                    "tokio::runtime::task::join::JoinHandle<",
                    ResourceKind::JoinHandle,
                );
                // The sleep's entry state on the primary cell: the
                // 1.49 family's route through the `Timer` flavor enum
                // and the entry's `Option<TimerShared>`, landing on the
                // `StateCell` word — the same word the wheel harvest
                // reads off a `TimerShared` (`TimerShared.state`).
                assert_walk(
                    program,
                    &bundle,
                    WalkRole::SleepTimerState,
                    "entry.<Traditional>.__0.inner.<Some>.__0.state.state.v.value.__0",
                );
            }
            "futurelock" => assert_resource(
                program,
                &bundle,
                "tokio::sync::batch_semaphore::Acquire",
                ResourceKind::SemaphoreAcquire,
            ),
            "local-set-io" => {
                // The rendered table is what `tokio-info dump` prints and
                // the matrix catalogs: pin its origin lines and one record
                // line, and the diagnostic a reader asks for by name.
                let table = exegesis::describe::describe_semantics(&bundle);
                let tokio = bundle.meta.tokio_version.as_ref().unwrap();
                assert!(
                    table.contains(&format!(
                        "origin 0: rustc rustc-coroutine-1.97 (clang LLVM (rustc version {}))\n",
                        bundle.meta.rustc_version
                    )),
                    "{program}: {table}"
                );
                assert!(
                    table.lines().any(|line| line.starts_with("origin ")
                        && line.ends_with(&format!(
                            ": layout tokio {tokio} family {} (ReviewedRange)",
                            exegesis::detect::Family::select(Some(tokio)).name()
                        ))),
                    "{program}: {table}"
                );
                // The reader's coroutine: its states under the compiler
                // rule, and a program that resumes into the one awaitee
                // of its one suspended state — the `Read` over the
                // stream — and nothing else.
                let reader = semantic_line(
                    &table,
                    "local_set_io::local_reader::{async_fn_env#0} :: states",
                );
                assert!(
                    reader.contains(
                        "future[task #, coroutine rule #] continuation rule # match <self>@+0 \
                         -> local_set_io::local_reader::{async_fn_env#0} {0: unresumed} \
                         {1: returned} {2: panicked} {3: delegate (exclusive) {3}.__awaitee@+"
                    ) && reader.contains(
                        " -> tokio::io::util::read::Read<tokio::net::unix::stream::UnixStream>} \
                         coroutine rule # {0:Unresumed[ready,stream]() 1:Returned[]() \
                         2:Panicked[]() 3:Suspended[stream,buf,__awaitee,__3]()}"
                    ),
                    "{program}: {reader}"
                );
                // The readiness primitive: its own poll, and — where a
                // coroutine's await lands on it, as the stream's
                // `writable` does — that delegation too.
                let readiness =
                    semantic_line(&table, "tokio::runtime::io::scheduled_io::Readiness ::");
                assert!(
                    readiness.starts_with(
                        "tokio::runtime::io::scheduled_io::Readiness :: members future[poll"
                    ) && readiness.ends_with(
                        "] continuation rule # primitive resource IoOperation(Readiness) rule # \
                         state rule # exclusive-pending"
                    ),
                    "{program}: {readiness}"
                );
                assert!(
                    table.contains(
                        "task 0: scheduler alloc::sync::Arc<tokio::task::local::Shared, \
                         alloc::alloc::Global> :: LocalSet rule "
                    ),
                    "{program}: {table}"
                );
                let none = "no semantic record — no task entry, poll symbol or delegation \
                            names it, it is not a compiler-storage candidate, and no \
                            reviewed resource, container or scheduler route bound at it";
                // The reader and its reference have no record on any
                // platform. `Read<Gated>` is a future on every platform —
                // the gated reader's coroutine awaits it, and that
                // delegation proves it one whether or not its own `poll`
                // survived as a symbol (ELF keeps it, Mach-O inlines it)
                // — and never a resource, never a continuation.
                let gated = exegesis::describe::explain_future(&bundle, "Gated");
                let lines: Vec<&str> = gated.lines().collect();
                assert_eq!(lines.len(), 3, "{program}: {gated}");
                assert_eq!(
                    lines[0],
                    format!("&mut local_set_io::Gated :: {none}"),
                    "{program}"
                );
                assert_eq!(
                    lines[1],
                    format!("local_set_io::Gated :: {none}"),
                    "{program}"
                );
                let delegated = |evidence: &str| {
                    format!(
                        "tokio::io::util::read::Read<local_set_io::Gated> :: members \
                         future[{evidence}delegated by \
                         local_set_io::local_gated_reader::{{async_fn_env#0}}] \
                         continuation unknown (NoRule)"
                    )
                };
                assert!(
                    lines[2] == delegated("") || lines[2] == delegated("poll, "),
                    "{program}: {}",
                    lines[2]
                );
                // A substring covers the environment and everything named
                // after it — its states, the cell around it — and each
                // gets its own line: one record, the rest explained absent.
                let explained =
                    exegesis::describe::explain_future(&bundle, "local_reader::{async_fn_env#0}");
                let lines: Vec<&str> = explained.lines().collect();
                assert!(lines.len() > 1, "{program}: {explained}");
                assert_eq!(
                    lines
                        .iter()
                        .filter(|l| l
                            .starts_with("local_set_io::local_reader::{async_fn_env#0} :: states"))
                        .count(),
                    1,
                    "{program}: {explained}"
                );
                assert!(
                    lines
                        .iter()
                        .filter(|l| !l.contains(":: states"))
                        .all(|l| l.ends_with(none)),
                    "{program}: {explained}"
                );
                assert_eq!(
                    exegesis::describe::explain_future(&bundle, "no::such::type"),
                    "no emitted type's name contains \"no::such::type\"; --include-type pulls \
                     in one nothing else reaches\n",
                    "{program}"
                );
                // An async fn: arguments in `Unresumed`, the locals live
                // across the one await in `Suspend0` — the awaitee, the
                // buffer, the stream moved off its argument slot, and
                // rustc's own state byte — and nothing uncertain.
                assert_coroutine(
                    program,
                    &bundle,
                    "local_set_io::local_reader::{async_fn_env#0}",
                    &[
                        "0:Unresumed[ready,stream]()",
                        "1:Returned[]()",
                        "2:Panicked[]()",
                        "3:Suspended[__3,__awaitee,buf,stream]()",
                    ],
                );
                // An async block: no arguments, so `Unresumed` lists only
                // its captures, and every suspended state lists them again
                // as uncertain — kept for inspection, moved or not — beside
                // the awaitee and rustc's own state bytes.
                assert_coroutine(
                    program,
                    &bundle,
                    "local_set_io::main::{async_block#0}::{async_block_env#0}",
                    &[
                        "0:Unresumed[ready_a_rx,ready_b_rx,ready_c_rx,ready_d_rx,ready_e_rx]()",
                        "1:Returned[]()",
                        "2:Panicked[]()",
                        "3:Suspended[__1,__2,__3,__4,__awaitee](ready_a_rx,ready_b_rx,ready_c_rx,ready_d_rx,ready_e_rx)",
                        "4:Suspended[__1,__2,__3,__4,__awaitee](ready_a_rx,ready_b_rx,ready_c_rx,ready_d_rx,ready_e_rx)",
                        "5:Suspended[__1,__2,__3,__4,__awaitee](ready_a_rx,ready_b_rx,ready_c_rx,ready_d_rx,ready_e_rx)",
                        "6:Suspended[__1,__2,__3,__4,__awaitee](ready_a_rx,ready_b_rx,ready_c_rx,ready_d_rx,ready_e_rx)",
                        "7:Suspended[__1,__2,__3,__4,__awaitee](ready_a_rx,ready_b_rx,ready_c_rx,ready_d_rx,ready_e_rx)",
                        "8:Suspended[__1,__2,__3,__4,__awaitee](ready_a_rx,ready_b_rx,ready_c_rx,ready_d_rx,ready_e_rx)",
                    ],
                );
                // The reviewed socket operations bind; the fixture's own
                // `AsyncRead` over the same socket does not, however
                // much of a socket it holds.
                assert_resource(
                    program,
                    &bundle,
                    "tokio::io::util::read::Read<tokio::net::unix::stream::UnixStream>",
                    ResourceKind::IoOperation(IoOperationKind::Read),
                );
                assert_resource(
                    program,
                    &bundle,
                    "tokio::io::util::write_all::WriteAll<tokio::net::unix::stream::UnixStream>",
                    ResourceKind::IoOperation(IoOperationKind::WriteAll),
                );
                assert_resource(
                    program,
                    &bundle,
                    "tokio::runtime::io::scheduled_io::Readiness",
                    ResourceKind::IoOperation(IoOperationKind::Readiness),
                );
                assert_no_resource(
                    program,
                    &bundle,
                    "tokio::io::util::read::Read<local_set_io::Gated>",
                );
                assert_no_resource(program, &bundle, "tokio::net::unix::stream::UnixStream");
            }
            "delegation-cases" => assert_delegation_programs(program, &bundle),
            "select-combinator" => assert_adapter_programs(program, &bundle),
            "joinset" => assert_container(
                program,
                &bundle,
                "tokio::task::join_set::JoinSet<",
                ContainerKind::JoinSet,
            ),
            // The map is a container whose children are polled with
            // the task's own context; its entries are a `Vec<(K, V)>`
            // walked element by element, each element's `__1` the
            // stream.
            "watch-stream" => {
                assert_container(
                    program,
                    &bundle,
                    "tokio_stream::stream_map::StreamMap<",
                    ContainerKind::StreamMap,
                );
                assert_walk(program, &bundle, WalkRole::StreamMapEntries, "entries");
                assert_walk(program, &bundle, WalkRole::StreamMapEntryStream, "__1");
            }
            "unordered" => assert_container(
                program,
                &bundle,
                "futures_util::stream::futures_unordered::FuturesUnordered<",
                ContainerKind::FuturesUnordered,
            ),
            _ => {}
        }
    }

    // The type-rooted walks are deliberately absent from the portable
    // summary — which resources a build links is the target's call —
    // so their binding is pinned here, on the fixtures that provably
    // link them on every platform. A spelling regression (the peel
    // shape, the Arc route, the queue-element path) breaks these
    // without moving any golden.
    {
        use exegesis::bundle::{WalkOutcome, WalkRole};
        let bound = |role: WalkRole| {
            matches!(
                bundle.walks.entries[&role].outcome,
                WalkOutcome::Bound { .. }
            )
        };
        if program == "local-set-io" {
            assert!(bound(WalkRole::UnixStreamShared), "{program}");
            assert!(bound(WalkRole::UnixStreamFd), "{program}");
        }
        if program == "blocking-pool" {
            assert!(bound(WalkRole::BlockingTaskHeader), "{program}");
        }
    }

    let crate_str = program.replace('-', "_");
    let summary = portable_summary(&bundle, program, &crate_str);

    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path("golden");
    settings.set_prepend_module_to_snapshot(false);
    // A generated report: naming the expression that built one says
    // nothing a reader of the diff wants.
    settings.set_omit_expression(true);
    settings.bind(|| insta::assert_snapshot!(program, summary));
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
fn test_golden_armed_select() {
    run_golden("armed-select");
}

#[test]
fn test_golden_watch_stream() {
    run_golden("watch-stream");
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

#[test]
fn test_golden_blocking_pool() {
    run_golden("blocking-pool");
}

/// The one `Instrumented` future the fixture holds wraps `Probe<8>`, so
/// the source inventory covers exactly that `poll` and nothing else in
/// tracing's `instrument.rs` — the declaration-to-source association a
/// third-party delegation rule's origin evidence is read from.
#[test]
fn test_golden_delegation_cases() {
    run_golden("delegation-cases");
    let dwarf = dwarf_path("delegation-cases");
    let found = exegesis::testkit::assert_instrumented_sources(&dwarf);
    assert_eq!(
        found,
        std::collections::BTreeSet::from(["poll<delegation_cases::Probe<8>>".to_owned()]),
        "{}: Instrumented inventory covered the wrong functions",
        dwarf.display()
    );
}

#[test]
fn test_golden_enum_reprs() {
    run_golden("enum-reprs");
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
        let (bundle, _) = extract_fixture(program, &opts);
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

/// The library's single-file form still reads a dSYM alone — the
/// tests' own door, refused at every user-facing entry — and the
/// bundle records that the vtable scan had nothing to read, which is
/// what the read side's incomplete-dyn-coverage warning keys on.
#[cfg(target_os = "macos")]
#[test]
fn test_a_companion_alone_records_no_vtable_source() {
    let program = "select-combinator";
    if !ensure_fixture(program) {
        return;
    }
    let (bundle, _) =
        exegesis::extract::extract_file(&fixture_dsym(program), &ExtractOptions::default())
            .expect("companion-alone library extraction");
    assert!(matches!(
        bundle.meta.vtable_data,
        exegesis::bundle::VtableDataSource::None
    ));
    assert!(bundle.meta.debug_info.is_none());
}

/// A fixture split after the fact — `objcopy --only-keep-debug` for the
/// companion, `--strip-debug` on the sibling — extracts to the same
/// bundle the unsplit binary does, identity fields aside (they name
/// the inputs and are supposed to differ). Bundle equality is the
/// strong check: every table, format, and walk came out the same
/// whichever way the DWARF arrived. macOS gets the equivalent coverage
/// from every golden running against the binary + dSYM pair.
#[cfg(not(target_os = "macos"))]
#[test]
fn test_a_split_pair_extracts_the_same_bundle() {
    let program = "select-combinator";
    if !ensure_fixture(program) {
        return;
    }
    // GNU spelling on Linux, the g-prefixed binutils elsewhere.
    let Some(objcopy) = ["objcopy", "gobjcopy"].iter().find(|cmd| {
        Command::new(cmd)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }) else {
        eprintln!("SKIP: neither objcopy nor gobjcopy is on this host");
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    // The sibling keeps the fixture's basename so the recorded vtable
    // data source — a basename — matches the unsplit extraction's.
    let bin = dir.path().join(program);
    std::fs::copy(fixture_binary(program), &bin).expect("copy fixture");
    let dbg = dir.path().join(format!("{program}.dbg"));
    let objcopy_ok = |cmd: &mut Command| {
        let status = cmd.status().expect("failed to run objcopy");
        assert!(status.success(), "{cmd:?} failed");
    };
    objcopy_ok(
        Command::new(objcopy)
            .arg("--only-keep-debug")
            .arg(&bin)
            .arg(&dbg),
    );
    objcopy_ok(Command::new(objcopy).arg("--strip-debug").arg(&bin));

    let opts = ExtractOptions::default();
    let (unsplit, _) = extract_sources(
        &DebugSources {
            binary: &fixture_binary(program),
            debug_info: None,
        },
        &opts,
    )
    .expect("unsplit extraction");
    let (mut split, _) = extract_sources(
        &DebugSources {
            binary: &bin,
            debug_info: Some(&dbg),
        },
        &opts,
    )
    .expect("pair extraction");

    assert_eq!(split.meta.binary.basename, program);
    let debug_info = split
        .meta
        .debug_info
        .take()
        .expect("pair records its debug source");
    assert_eq!(debug_info.basename, format!("{program}.dbg"));
    split.meta.binary = unsplit.meta.binary.clone();
    assert_eq!(split, unsplit, "{program}: split pair changed the bundle");

    // The companion alone is refused, saying what it is and what is
    // missing rather than extracting a bundle with no program behind it.
    let err = extract_sources(
        &DebugSources {
            binary: &dbg,
            debug_info: None,
        },
        &opts,
    )
    .expect_err("a companion alone is refused");
    let msg = err.to_string();
    assert!(msg.contains("split debug info"), "{msg}");
    assert!(msg.contains("binary it was split from"), "{msg}");

    // A sibling from a different link is refused as a mismatched pair:
    // by build id where the platform stamps one, by the allocated
    // sections having moved where it does not.
    let other = "simple-await";
    if ensure_fixture(other) {
        let err = extract_sources(
            &DebugSources {
                binary: &fixture_binary(other),
                debug_info: Some(&dbg),
            },
            &opts,
        )
        .expect_err("a sibling from another link is refused");
        assert!(
            matches!(err, exegesis::extract::Error::SiblingMismatch { .. }),
            "{err}"
        );
    }
}

/// The packed Linux split — skeleton DWARF in the binary, every unit's
/// DIEs in the dwp rustc packs at link time — extracts to the same
/// bundle the unsplit build of the same sources does, identity fields
/// aside. This is the one place the real toolchain's DebugFission
/// spellings are exercised end to end: GNU forms, the header-less v4
/// str-offsets, `.debug_addr`-indexed locations, and the
/// `.debug_line.dwo` file tables — which tokio version recovery reads,
/// so equality here is what says family selection still works against
/// a dwp.
#[cfg(target_os = "linux")]
#[test]
fn test_a_packed_dwp_pair_extracts_the_same_bundle() {
    let program = "select-combinator";
    if !ensure_fixture(program) || !ensure_dwp_fixture(program) {
        return;
    }

    let opts = ExtractOptions::default();
    let (mut unsplit, _) = extract_sources(
        &DebugSources {
            binary: &fixture_binary(program),
            debug_info: None,
        },
        &opts,
    )
    .expect("unsplit extraction");
    let bin = dwp_binary(program);
    let dwp = bin.with_extension("dwp");
    let (mut split, _) = extract_sources(
        &DebugSources {
            binary: &bin,
            debug_info: Some(&dwp),
        },
        &opts,
    )
    .expect("packed pair extraction");

    let debug_info = split
        .meta
        .debug_info
        .take()
        .expect("the pair records its debug source");
    assert_eq!(debug_info.basename, format!("{program}.dwp"));
    assert_eq!(split.meta.binary.basename, program);
    // Two separate compilations, so the identity fields differ by
    // construction.
    split.meta.binary = unsplit.meta.binary.clone();
    // So do the raw mangled symbols: the split-debuginfo profile
    // setting feeds -Cmetadata, so every crate disambiguator — and
    // with it every symbol key — differs between the two builds. The
    // *normalized* symbol indexes must still agree (matching symbols
    // across builds is what they exist for), so only the raw keys are
    // cleared on both sides.
    // One more consequence of the metadata drift: rustc duplicates a
    // coroutine's resume fn across CGUs and does not give every copy
    // its awaitees' declaration coordinates, and *which* copy carries
    // them shifts between the two compilations — so one build confirms
    // an await site the other leaves unconfirmed. A confirmed site
    // equal to the variant's decl adds nothing (rendering already
    // suppresses it), so that redundant spelling is normalized away on
    // both sides; a site that disagrees with its decl still has to
    // match exactly.
    for bundle in [&mut split, &mut unsplit] {
        bundle.meta.symbol_fingerprint.clear();
        bundle.tasks.by_symbol.clear();
        bundle.dyn_futures.by_symbol.clear();
        for def in bundle.statics.entries.values_mut() {
            def.symbol.clear();
        }
        for def in &mut bundle.types.types {
            if let TypeDef::Enum { shape, .. } = def {
                for variant in &mut shape.variants {
                    if variant.await_site == variant.decl {
                        variant.await_site = None;
                    }
                }
            }
        }
    }

    // Field by field before the whole, so a mismatch names its table
    // rather than dumping two bundles.
    assert_eq!(split.meta, unsplit.meta, "{program}: meta differs");
    assert_eq!(split.types, unsplit.types, "{program}: type table differs");
    assert_eq!(split.tasks, unsplit.tasks, "{program}: task table differs");
    assert_eq!(split.walks, unsplit.walks, "{program}: walk table differs");
    assert_eq!(
        split.semantics, unsplit.semantics,
        "{program}: semantic table differs"
    );
    // Poll evidence interns raw symbols, which carry the same build-specific
    // crate disambiguators as the indexes cleared above. Normalize only those
    // strings; every other interned value must still agree literally.
    let normalized_strings = |bundle: &Bundle| {
        use exegesis::bundle::{FutureEvidence, StrRef};
        use exegesis::symbols::normalized_v0_key;
        let polls: std::collections::BTreeSet<_> = bundle
            .semantics
            .types
            .iter()
            .filter_map(|record| record.future.as_ref())
            .flat_map(|future| &future.evidence)
            .filter_map(|evidence| match evidence {
                FutureEvidence::PollSymbol(symbol) => Some(*symbol),
                _ => None,
            })
            .collect();
        bundle
            .strings
            .iter()
            .enumerate()
            .map(|(i, value)| {
                if polls.contains(&StrRef(i as u32)) {
                    normalized_v0_key(value).expect("poll evidence has a v0 symbol")
                } else {
                    value.to_owned()
                }
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        normalized_strings(&split),
        normalized_strings(&unsplit),
        "{program}: normalized strings differ"
    );
    split.strings = unsplit.strings.clone();
    assert_eq!(
        split, unsplit,
        "{program}: the packed split changed the bundle"
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
    let (bundle, stats) = extract_fixture(program, &opts);

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
    let (bundle, stats) = extract_fixture(program, &opts);
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
    let (bundle, stats) = extract_fixture(program, &opts);

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

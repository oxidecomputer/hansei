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

use exegesis::bundle::{
    Bundle, BundleTypeId, DisplayNode, Field, MapEntries, Selector, StaticRole, Step, TypeDef,
    ValueExpr,
};
use exegesis::extract::{ExtractOptions, ExtractStats, extract_file};

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

/// Build a fixture if it is missing. Returns `false` (skip) when the
/// pinned toolchain is not installed; panics on real build failures.
fn ensure_fixture(program: &str) -> bool {
    // Serialize builds: parallel test threads would contend on the
    // fixture target dir.
    static BUILD_LOCK: Mutex<()> = Mutex::new(());
    let _guard = BUILD_LOCK.lock().unwrap();

    if dwarf_path(program).exists() {
        return true;
    }

    let toolchains = Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if !toolchains.lines().any(|l| l.starts_with(TOOLCHAIN)) {
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

fn leaf_of(name: &str) -> &str {
    // The generic suffix may itself contain `::`; strip it first.
    let base = name.split('<').next().unwrap_or(name);
    let leaf_start = base.rfind("::").map(|i| i + 2).unwrap_or(0);
    &name[leaf_start..]
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// The fully-qualified name of a type, or a placeholder for the anonymous
/// pointer/array kinds. Type *ids* are not portable across platforms, so the
/// debug-format summary keys everything on these names instead.
fn fq_name(bundle: &Bundle, id: BundleTypeId) -> String {
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>").to_owned();
    match &bundle.types.types[id.0 as usize] {
        TypeDef::Base { name, .. }
        | TypeDef::Struct { name, .. }
        | TypeDef::Union { name, .. }
        | TypeDef::Enum { name, .. }
        | TypeDef::CEnum { name, .. }
        | TypeDef::Opaque { name, .. } => s(*name),
        TypeDef::Pointer { .. } => "<pointer>".to_owned(),
        TypeDef::Array { .. } => "<array>".to_owned(),
    }
}

/// Walk a member-index path from `root`, returning the dotted field-name
/// chain, the terminal byte offset, and the type the path lands on. This is
/// the portable, layout-sensitive rendering of a debug-format path: a wrong
/// member (the failure mode this coverage targets) changes the name or the
/// offset even when the path still validates.
fn walk(bundle: &Bundle, root: BundleTypeId, sel: &Selector) -> (String, u64, BundleTypeId) {
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>").to_owned();
    let mut names = Vec::new();
    let mut offset = 0u64;
    let mut cur = root;
    for step in sel.steps() {
        match step {
            Step::Member(mi) => {
                let members = match &bundle.types.types[cur.0 as usize] {
                    TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
                    _ => {
                        names.push("<non-aggregate>".to_owned());
                        return (names.join("."), offset, cur);
                    }
                };
                match members.get(*mi as usize) {
                    Some(m) => {
                        names.push(s(m.name));
                        offset += m.offset;
                        cur = m.ty;
                    }
                    None => {
                        names.push(format!("<oob:{mi}>"));
                        return (names.join("."), offset, cur);
                    }
                }
            }
            Step::Deref => match &bundle.types.types[cur.0 as usize] {
                TypeDef::Pointer { target, .. } => {
                    names.push("*".to_owned());
                    offset = 0;
                    cur = *target;
                }
                _ => {
                    names.push("<non-pointer-deref>".to_owned());
                    return (names.join("."), offset, cur);
                }
            },
        }
    }
    (names.join("."), offset, cur)
}

/// Render one path as `chain@+offset` (rooted at `root`).
fn field(bundle: &Bundle, root: BundleTypeId, sel: &Selector) -> String {
    let (chain, offset, _) = walk(bundle, root, sel);
    let chain = if chain.is_empty() {
        "<self>".to_owned()
    } else {
        chain
    };
    format!("{chain}@+{offset}")
}

fn ptr_target(bundle: &Bundle, id: BundleTypeId) -> Option<BundleTypeId> {
    match &bundle.types.types[id.0 as usize] {
        TypeDef::Pointer { target, .. } => Some(*target),
        _ => None,
    }
}

/// The payload type of an enum's `Some` variant (BTreeMap's `root` is an
/// `Option<Box<…>>`).
fn some_payload(bundle: &Bundle, id: BundleTypeId) -> Option<BundleTypeId> {
    match &bundle.types.types[id.0 as usize] {
        TypeDef::Enum { shape, .. } => shape
            .variants
            .iter()
            .find(|v| bundle.strings.get(v.name) == Some("Some"))
            .map(|v| v.payload.ty),
        _ => None,
    }
}

fn array_elem(bundle: &Bundle, id: BundleTypeId) -> Option<BundleTypeId> {
    match &bundle.types.types[id.0 as usize] {
        TypeDef::Array { elem, .. } => Some(*elem),
        _ => None,
    }
}

/// Render a debug format as a portable, layout-sensitive summary.
fn describe_debug_format(bundle: &Bundle, id: BundleTypeId, node: &DisplayNode) -> String {
    format!(
        "{} :: Node {}",
        fq_name(bundle, id),
        describe_node(bundle, id, node)
    )
}

/// Render a [`DisplayNode`] tree as a portable, layout-sensitive summary: every
/// selector resolved to its field-name chain and byte offset (rooted at the
/// type the node is rendered against, following the same rooting as resolution),
/// so a wrong-member regression after a toolchain/layout shift trips the test.
fn describe_node(bundle: &Bundle, root: BundleTypeId, node: &DisplayNode) -> String {
    match node {
        DisplayNode::Scalar { at, .. } => field(bundle, root, at),
        DisplayNode::Symbol { at } => format!("Symbol {{ {} }}", field(bundle, root, at)),
        DisplayNode::Struct { fields } => {
            let parts: Vec<String> = fields
                .iter()
                .map(|fld| describe_field(bundle, root, fld))
                .collect();
            format!("Struct {{ {} }}", parts.join(", "))
        }
        DisplayNode::List {
            head,
            next,
            node,
            node_ty,
        } => format!(
            "List {{ head={}, node_ty={}, next={}, {} }}",
            field(bundle, root, head),
            fq_name(bundle, *node_ty),
            field(bundle, *node_ty, next),
            describe_node(bundle, *node_ty, node),
        ),
        DisplayNode::Str {
            pointer,
            length,
            capacity,
        } => {
            let capacity = match capacity {
                Some(capacity) => format!(", capacity={}", field(bundle, root, capacity)),
                None => String::new(),
            };
            format!(
                "Str {{ pointer={}, length={}{} }}",
                field(bundle, root, pointer),
                field(bundle, root, length),
                capacity,
            )
        }
        DisplayNode::Slice {
            pointer,
            length,
            capacity,
            element,
        } => {
            let capacity = match capacity {
                Some(capacity) => format!(", capacity={}", field(bundle, root, capacity)),
                None => String::new(),
            };
            format!(
                "Slice {{ pointer={}, length={}{}, element={} }}",
                field(bundle, root, pointer),
                field(bundle, root, length),
                capacity,
                fq_name(bundle, *element),
            )
        }
        DisplayNode::IpAddr { octets } => {
            format!("IpAddr {{ octets={} }}", field(bundle, root, octets))
        }
        DisplayNode::Alias {
            at,
            follow_pointers,
        } => {
            let follow = if *follow_pointers { ", follow" } else { "" };
            format!("Alias {{ {}{} }}", field(bundle, root, at), follow)
        }
        DisplayNode::SlotCount { bitmap, slots } => format!(
            "SlotCount {{ bitmap={}, slots={} }}",
            field(bundle, root, bitmap),
            field(bundle, root, slots),
        ),
        DisplayNode::Pointer { at, via, then } => {
            let (_, _, ptr_land) = walk(bundle, root, at);
            let pointee = ptr_target(bundle, ptr_land).unwrap_or(root);
            let (_, _, target) = walk(bundle, pointee, via);
            format!(
                "Pointer {{ at={}, pointee={}, via={}, then={} }}",
                field(bundle, root, at),
                fq_name(bundle, pointee),
                field(bundle, pointee, via),
                describe_node(bundle, target, then),
            )
        }
        DisplayNode::DynPointer {
            pointer,
            vtable,
            drop_in_place,
            size,
            align,
            tail_offset,
        } => format!(
            "DynPointer {{ pointer={}, vtable={}, slots=[drop_in_place:{drop_in_place}, size:{size}, align:{align}], tail_offset={tail_offset} }}",
            field(bundle, root, pointer),
            field(bundle, root, vtable),
        ),
        DisplayNode::MpscChan {
            tail,
            index,
            head,
            start_index,
            next,
            values,
            element,
        } => {
            let (_, _, head_land) = walk(bundle, root, head);
            let block = ptr_target(bundle, head_land).unwrap_or(root);
            format!(
                "MpscChan {{ tail={}, index={}, head={}, block={}, start_index={}, next={}, values={}, element={} }}",
                field(bundle, root, tail),
                field(bundle, root, index),
                field(bundle, root, head),
                fq_name(bundle, block),
                field(bundle, block, start_index),
                field(bundle, block, next),
                field(bundle, block, values),
                fq_name(bundle, *element),
            )
        }
        DisplayNode::Map {
            length,
            key,
            value,
            entries,
        } => {
            let MapEntries::BTree {
                root: map_root,
                root_node,
                height,
                node,
                leaf,
                leaf_len,
                leaf_keys,
                leaf_values,
                internal,
                internal_data,
                internal_edges,
                edge,
            } = entries.as_ref();
            let (_, _, root_ty) = walk(bundle, root, map_root);
            let some = some_payload(bundle, root_ty).unwrap_or(root_ty);
            let (_, _, node_ref) = walk(bundle, some, root_node);
            let (_, _, edges_ty) = walk(bundle, *internal, internal_edges);
            let edge_elem = array_elem(bundle, edges_ty).unwrap_or(*internal);
            format!(
                "Map {{ length={}, key={}, value={}, entries=BTree {{ root={}, root_node={}, \
                 height={}, node={}, leaf={}, leaf_len={}, leaf_keys={}, leaf_values={}, \
                 internal={}, internal_data={}, internal_edges={}, edge={} }} }}",
                field(bundle, root, length),
                fq_name(bundle, *key),
                fq_name(bundle, *value),
                field(bundle, root, map_root),
                field(bundle, some, root_node),
                field(bundle, node_ref, height),
                field(bundle, node_ref, node),
                fq_name(bundle, *leaf),
                field(bundle, *leaf, leaf_len),
                field(bundle, *leaf, leaf_keys),
                field(bundle, *leaf, leaf_values),
                fq_name(bundle, *internal),
                field(bundle, *internal, internal_data),
                field(bundle, *internal, internal_edges),
                field(bundle, edge_elem, edge),
            )
        }
        DisplayNode::Variant {
            discriminant,
            arms,
            default,
        } => {
            let arms = arms
                .iter()
                .map(|arm| {
                    let label = arm
                        .label
                        .map_or("", |l| bundle.strings.get(l).unwrap_or("?"));
                    match &arm.payload {
                        Some(payload) => format!(
                            "{}=>{label}({})",
                            arm.value,
                            describe_node(bundle, root, payload)
                        ),
                        None => format!("{}=>{label}", arm.value),
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            let default = match default {
                Some(node) => format!(", default={}", describe_node(bundle, root, node)),
                None => String::new(),
            };
            format!(
                "Variant {{ discr={}, arms=[{arms}]{default} }}",
                describe_value_expr(bundle, root, discriminant),
            )
        }
    }
}

/// Render a [`ValueExpr`] for [`describe_node`], resolving each `Read` selector
/// to its member path (crossing any `Deref` via [`walk`]).
fn describe_value_expr(bundle: &Bundle, root: BundleTypeId, expr: &ValueExpr) -> String {
    match expr {
        ValueExpr::Read(sel) => format!("Read({})", field(bundle, root, sel)),
        ValueExpr::Const(value) => format!("{value:#x}"),
        ValueExpr::And(a, b) => format!(
            "({} & {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
        ValueExpr::Not(inner) => format!("~{}", describe_value_expr(bundle, root, inner)),
        ValueExpr::Ne(a, b) => format!(
            "({} != {})",
            describe_value_expr(bundle, root, a),
            describe_value_expr(bundle, root, b)
        ),
    }
}

/// Render one [`Field`] of a [`DisplayNode::Struct`] for [`describe_node`].
fn describe_field(bundle: &Bundle, root: BundleTypeId, fld: &Field) -> String {
    let member_name = |index: u32| match &bundle.types.types[root.0 as usize] {
        TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members
            .get(index as usize)
            .map_or("?", |m| bundle.strings.get(m.name).unwrap_or("?")),
        _ => "?",
    };
    match fld {
        Field::Member(index) => format!("{}: <structural>", member_name(*index)),
        Field::Named { label, node } => {
            format!(
                "{}: {}",
                bundle.strings.get(*label).unwrap_or("?"),
                describe_node(bundle, root, node)
            )
        }
        Field::Override { index, node } => {
            format!(
                "{}: {}",
                member_name(*index),
                describe_node(bundle, root, node)
            )
        }
    }
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
                match &v.decl {
                    Some(loc) => writeln!(
                        out,
                        "    {} @ {}:{}",
                        leaf_of(&payload),
                        basename(s(loc.file)),
                        loc.line
                    )
                    .unwrap(),
                    None => writeln!(out, "    {}", leaf_of(&payload)).unwrap(),
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
            "core::net::ip_addr::Ipv4Addr :: Node IpAddr { octets=octets@+0 }",
        );
        assert_format(
            program,
            bundle,
            "core::net::ip_addr::Ipv6Addr",
            "core::net::ip_addr::Ipv6Addr :: Node IpAddr { octets=octets@+0 }",
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
             Struct { notification: notification.__0.inner.value.v.value.__0@+32 } } }",
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
        assert_format(
            program,
            bundle,
            "tokio::sync::mpsc::chan::Chan<u32, tokio::sync::mpsc::bounded::Semaphore>",
            "tokio::sync::mpsc::chan::Chan<u32, tokio::sync::mpsc::bounded::Semaphore> :: Node Struct \
             { queued: MpscChan \
             { tail=tx.value.tail_position.inner.value.v.value.__0@+8, \
             index=rx_fields.__0.value.list.index@+304, \
             head=rx_fields.__0.value.list.head.pointer@+288, \
             block=tokio::sync::mpsc::block::Block<u32>, \
             start_index=header.start_index@+128, next=header.next.v.value.__0@+136, \
             values=values.__0@+0, element=u32 }, \
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
             queued: MpscChan { tail=tx.value.tail_position.inner.value.v.value.__0@+8, \
             index=rx_fields.__0.value.list.index@+304, \
             head=rx_fields.__0.value.list.head.pointer@+288, \
             block=tokio::sync::mpsc::block::Block<u32>, \
             start_index=header.start_index@+128, next=header.next.v.value.__0@+136, \
             values=values.__0@+0, element=u32 }, \
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
             Struct { permits_needed: state.inner.value.v.value.__0@+32 } } }",
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

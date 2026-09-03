// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The portable extraction summary: the task shapes, await-point lines,
//! dyn-future keys, and infra/statics presence of a bundle, rendered as
//! text a golden file can pin.
//!
//! Everything printed is platform-portable — demangled type names,
//! variant shapes, await lines, presence — and filtered to the fixture
//! crate's own types, so one golden serves every target the fixture
//! builds on. Both golden suites diff it (the extraction goldens for the
//! primary fixtures, the matrix suite per cell); keeping one renderer is
//! what keeps their review surfaces the same.
//!
//! It reads a bundle but does not belong to one: deciding which walk roles
//! to print is [`crate::detect::walk::leaf_rooted`]'s call, a builder-side
//! judgment about what a role means that the wire format itself never makes.

use crate::bundle::{Bundle, StaticRole, TypeDef, WalkBinding, WalkOutcome, WalkRole};

use std::fmt::Write as _;

fn leaf_of(name: &str) -> &str {
    // The generic suffix may itself contain `::`; strip it first.
    let base = name.split('<').next().unwrap_or(name);
    let leaf_start = base.rfind("::").map(|i| i + 2).unwrap_or(0);
    &name[leaf_start..]
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Render the summary of `bundle`, filtered to types mentioning
/// `crate_str` (the fixture crate's name).
pub fn portable_summary(bundle: &Bundle, program: &str, crate_str: &str) -> String {
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>");
    let type_name = |id: crate::bundle::BundleTypeId| -> String {
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
        // futures_util's own stream adapters are skipped: whether one
        // survives as a standalone monomorphization or is inlined away
        // is the target's call, not extraction's — `unordered`'s
        // `Next<FuturesUnordered<…>>` is emitted on ELF and absent from
        // the Mach-O build — and a summary that varies by platform
        // cannot be one golden file. The fixture's own futures and their
        // tokio/core plumbing, which is what this canary is for, are
        // unaffected.
        // `LocalSet::run_until`'s own wrappers — the `RunUntil` future
        // and the async fn env around it — are skipped for the same
        // reason: which of them survives as its own monomorphization is
        // the target's call. Two fixtures differing only in what their
        // spawned task captures already disagree about `RunUntil` across
        // Mach-O and ELF, so a row for it could not be one golden file.
        if name.starts_with("futures_util::")
            || name.starts_with("futures_core::")
            || name.starts_with("tokio::task::local::")
        {
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
        ("ct_handle", infra.ct_handle),
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

    // Only the statics every tokio target has. `TlsLocalSetKey` is
    // deliberately absent: whether a program that constructs no
    // `LocalSet` still carries `task::local::CURRENT` in its symbol
    // table is the linker's call — illumos keeps it where macOS and
    // Linux drop it — so a row for it could not be one golden. It is
    // the same judgment that skips the leaf-rooted walk rows below and
    // the `futures_util` adapters above; that the matcher finds the
    // symbol where a program really does use a set is asserted against
    // the local-set fixture instead.
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

    // The walk bindings the binder recorded, offsets stripped: which
    // spelling bound (and under which family), what is absent and why,
    // what broke. The map's order is `WalkRole`'s declaration order —
    // the report's order. Two target-dependent facts are left out so one
    // golden serves every platform: rows rooted at leaf types (whether a
    // `Sleep` or `Acquire` monomorphization exists in the image is the
    // linker's call — the same reason the dyn-future list above skips
    // `futures_util` adapters), and the cell/type counts a binding's
    // note carries (an ELF build keeps task instantiations the Mach-O
    // build inlines away). The single-target matrix goldens report both.
    writeln!(out, "\n[walks]").unwrap();
    for (role, binding) in &bundle.walks.entries {
        if crate::detect::walk::leaf_rooted(*role) {
            continue;
        }
        writeln!(out, "{}", walk_entry_line_portable(*role, binding)).unwrap();
    }

    out
}

/// [`walk_entry_line`] with the target-dependent note segments (counts)
/// removed; only the family annotation survives.
fn walk_entry_line_portable(role: WalkRole, binding: &WalkBinding) -> String {
    let portable = |note: &Option<String>| -> Option<String> {
        let kept: Vec<&str> = note
            .as_deref()?
            .split("; ")
            .filter(|segment| segment.starts_with("family "))
            .collect();
        (!kept.is_empty()).then(|| kept.join("; "))
    };
    match &binding.outcome {
        WalkOutcome::Bound {
            spelling,
            spellings,
            note,
        } => walk_entry_line(
            role,
            &WalkBinding {
                roots: binding.roots.clone(),
                steps: binding.steps.clone(),
                outcome: WalkOutcome::Bound {
                    spelling: *spelling,
                    spellings: *spellings,
                    note: portable(note),
                },
            },
        ),
        _ => walk_entry_line(role, binding),
    }
}

/// One walk binding as the golden summary prints it — also what
/// `--explain-walk` reports as the recorded verdict.
pub fn walk_entry_line(role: WalkRole, binding: &WalkBinding) -> String {
    match &binding.outcome {
        WalkOutcome::Bound {
            spelling,
            spellings,
            note,
        } => {
            let mut extras = Vec::new();
            if *spellings > 1 {
                extras.push(format!("spelling {} of {spellings}", spelling + 1));
            }
            if let Some(note) = note {
                extras.push(note.clone());
            }
            if extras.is_empty() {
                format!("ok      {}", role.name())
            } else {
                format!("ok      {} ({})", role.name(), extras.join("; "))
            }
        }
        WalkOutcome::Absent { reason } => format!("absent  {} — {reason}", role.name()),
        WalkOutcome::Broken { errors } => {
            format!("BROKEN  {} — {}", role.name(), errors.join("; "))
        }
    }
}

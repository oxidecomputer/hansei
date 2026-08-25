// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Offline reachability-index tests: build the index over a real
//! extracted bundle joined against a real captured snapshot, and pin what
//! it finds — every recorded extent's kind, size, type and path, plus the
//! walk's honesty counters — as a golden.
//!
//! The unit tests beside the walk prove each edge kind over synthetic
//! bundles; this is the census-golden-adjacent layer that makes a drift
//! in what the walk reaches over *real* extraction output a loud diff.
//! Addresses are masked (they vary per capture); everything else — how
//! many extents, through which paths, of which types — is pinned.
//!
//! Regenerate after an intended change with `INSTA_UPDATE=always cargo
//! nextest run -p hansei-runtime --test reach` and review the diff.

use hansei_bundle::Bundle;
use hansei_runtime::testkit::load;
use hansei_runtime::tokio::reach::{ExtentKind, ReachBounds, reach_index};
use proc::snapshot::Snapshot;

use std::fmt::Write as _;

fn summarize(bundle: &Bundle, snapshot: &Snapshot) -> String {
    let ctx = hansei_runtime::testkit::context(bundle, snapshot);
    let list = hansei_runtime::testkit::tasks(&ctx, snapshot);
    let extents = ctx.task_extents(&list);
    let census = hansei_runtime::testkit::census(&ctx, &list);
    let index = reach_index(&ctx, &list, &census, &extents, ReachBounds::default());

    let mut out = String::new();
    writeln!(out, "roots: {} records: {}", index.stats.roots, index.len()).unwrap();
    writeln!(
        out,
        "capped: deep={} elements={} records={}",
        index.capped.deep, index.capped.elements, index.capped.records
    )
    .unwrap();
    writeln!(
        out,
        "stats: dedup={} task_hits={} degraded={}",
        index.stats.dedup_hits, index.stats.task_hits, index.stats.degraded
    )
    .unwrap();
    writeln!(out).unwrap();
    for record in index.records() {
        // Re-locate the record's own start so the row also exercises the
        // query path end-to-end: kind, size, type, root, and full path.
        let hit = index
            .locate(record.start)
            .expect("every record's start locates");
        let kind = match record.kind {
            ExtentKind::Value => "value".to_string(),
            ExtentKind::Buffer { stride } => format!("buffer/{stride}"),
            ExtentKind::Bytes => "bytes".to_string(),
        };
        let ty = ctx
            .view
            .ty(record.ty)
            .map(|t| t.name().to_string())
            .unwrap_or_else(|| format!("<type {:?}>", record.ty));
        let via = match hit.root.via.as_str() {
            "" => String::new(),
            via => format!(" ({via})"),
        };
        writeln!(
            out,
            "{kind} {}B {ty}\n    task {}{via}: {}",
            record.end - record.start,
            hit.root.owner,
            hit.path.join(" -> "),
        )
        .unwrap();
    }
    out
}

#[track_caller]
fn assert_golden(program: &str) {
    for set in hansei_runtime::testkit::FIXTURE_SETS {
        let (bundle, snapshot) = load(set, program);
        let actual = summarize(&bundle, &snapshot);
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path("reach");
        settings.set_snapshot_suffix(*set);
        settings.set_prepend_module_to_snapshot(false);
        settings.set_omit_expression(true);
        settings.bind(|| insta::assert_snapshot!(program, actual.trim()));
    }
}

/// The sync-primitive fixture: `Arc`-shared channel state — the mpsc
/// chan, semaphores, `Notify`, watch — reached through the holder task's
/// locals, plus every `String`/`Vec` buffer along the way.
#[test]
fn test_channels_reach_index() {
    assert_golden("channels");
}

/// The set fixture: `FuturesUnordered` children rooted through the
/// census's set-child enumeration, held futures through their own
/// chains.
#[test]
fn test_unordered_reach_index() {
    assert_golden("unordered");
}

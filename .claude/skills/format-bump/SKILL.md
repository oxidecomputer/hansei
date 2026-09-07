---
name: format-bump
description: The FORMAT_VERSION bump loop — regenerate the checked-in binary bundle fixtures on a capture host and fold them into the schema commit so main is never red. Use when bumping FORMAT_VERSION (new DisplayNode kind, Bytes notation, any bundle schema/io change) or when hansei-runtime fixture tests fail to load bundles after a schema change.
---

# Format bumps

A `FORMAT_VERSION` bump (in `hansei-bundle/src/io.rs`) invalidates the
checked-in binary fixtures in `hansei-runtime/tests/fixtures/*.tinfo` —
`cargo nextest run -p hansei-runtime` fails to *load* them until they are
regenerated with `test-programs/capture-snapshots.sh`. That script needs
`gcore`, so it runs on an illumos or Linux host, **not macOS**.

Never weigh the bump itself in a design trade-off — bumping is routine and
free; this loop is its only cost.

The snapshot side has a version of its own, `proc::snapshot::FORMAT_VERSION`
(in `proc/src/snapshot.rs`), covering the `*.snapshot` half of each fixture
pair. It advances independently of the bundle's, and a bump to it runs the
same loop: the fixture-backed tests fail to load (`VersionMismatch`) until
`capture-snapshots.sh` recaptures every set. Snapshots are stored as raw
payloads so git can delta consecutive recaptures (see the module docs);
a change to the file container alone, not the payload, can convert the
checked-in files in place instead of recapturing.

A recapture can also be forced from outside the fixtures: the DWARF-5
`delegation-cases` bundle recipe hashes the workspace `Cargo.lock` among
its inputs (`testrun/src/fixture.rs`), so a workspace dependency change
stales that program's `.capture` receipt on every set, and
`test_fixtures_record_the_current_programs` refuses to bless SOURCES
until `capture-snapshots.sh <set dir> delegation-cases` reruns there.

## The loop

Ordering matters: the capture host builds the commit at `HEAD`, and
`main` must never be left with a red `hansei-runtime`.

1. Land the schema change locally: everything green
   (`cargo nextest run --no-fail-fast` — the fixture-loading tests in
   `hansei-runtime` are the expected reds until step 3), commit.
2. Push, and sync the capture host to that commit.
3. Regenerate on the capture host: run `test-programs/capture-snapshots.sh`,
   then copy the regenerated `hansei-runtime/tests/fixtures/*.tinfo` back.
4. Fold the fixtures into the *same* commit: `git commit --amend`, then
   force-push — the standing convention for fixture fixes verified on
   another host.
5. Prove it: `cargo nextest run -p hansei-runtime` locally, then the full
   suite on every platform (which tests what is pushed, so re-push first
   after amending).

Which host captures, how to reach it, and where to push are per-checkout
facts — see the untracked `CLAUDE.local.md`.

## Notes

- The fixtures' recorded line numbers go quietly stale if the fixture
  *programs* changed too (they are not rebuilt from source by any test) —
  this loop is also how they are refreshed after a `test-programs` reflow.

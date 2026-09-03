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

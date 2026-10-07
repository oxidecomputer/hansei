---
name: onboard-tokio-release
description: Onboard a new tokio or Rust toolchain release into the version matrix — matrix.sh mechanics, classifying the divergence, adding a Family when one is needed, and the golden-blessing gates. Use when matrix.sh update reports the matrix is behind, when asked to add tokio/rust version support, or when a new tokio release needs a family decision.
---

# Onboard a tokio (or toolchain) release

The mechanical half is scripted; the human half is *classifying* what the
release moved and never blessing a golden diff you have not read. Doctrine
(also in CLAUDE.md *tokio version families*): **any tokio-version-determined
divergence in a layout the detectors navigate — a respelled member, an added
wrapper, a full restructure — is a `Family` boundary, never an ordered
fallback that could bind on a version it was not written for.** Ordered
alternatives inside a detector are only for divergence a version cannot
select: feature/cfg variance within one release, or rustc-driven drift.

## 1. Notice, review, and run the mechanical half

```
test-programs/matrix.sh update            # exit 1 + report when behind
test-programs/matrix.sh add tokio-<ver>   # or add rust-<ver>
```

`update` reports every release no review has read: a new minor or patch
of tokio (the floor's and primary's minors too), a new stable Rust, and
a point release of a Rust minor the matrix lists.

**Review before `add`.** Every review in `exegesis/src/detect/semantics.rs`
reads tokio and rustc release by release — `TOKIO_RELEASES` and
`RUSTC_RELEASES`, one span per minor through the matrix's newest pin —
so a release outside them gets no rule and extraction refuses it. For
the new release:

1. Hash every file each review names (its `checksums` paths) at the
   release — the crate's registry sources for tokio, the toolchain's
   `rust-src` for rustc — and diff each file that hashes to no listed
   revision against the neighbouring reviewed one. A rustc convention
   with no checksums read compiler sources, which no toolchain ships:
   diff the files its doc names at the two git tags.
2. Where the change leaves a review's claims true, list the new
   revision's checksum (generate the bytes; never type them) and amend
   the doc's account of how its files vary across the range. Where it
   does not, that is a layout or protocol change: stop and treat it as
   §2's classification does.
3. Raise the minor's span in `TOKIO_RELEASES`/`RUSTC_RELEASES` to the
   release, or add one for a new minor.

Then run `add`. The matrix suite holds each span's top to the matrix's
pin for that minor and every listed checksum to the sources each cell
builds, so `add`'s runs fail on a span left behind or a file nobody
read.

`add` derives the lockfile, edits `matrix.toml`, deletes golden dirs the
edit orphans (the "latest" role slides), blesses the new cells, then runs
the whole matrix un-blessed to prove no existing cell moved. It refuses to
touch the floor and primary pins — those advance by hand, deliberately.
Advancing the primary toolchain edits `rust-toolchain.toml` at the
repository root in the same commit, since the workspace builds on the
primary too; a `testrun` test fails while the two differ.
`add` installs the toolchains, with the `rust-src` the matrix suite's
source check reads, blesses and runs the full matrix in the Linux test
image, so onboard on an x86_64 Linux host with podman; it refuses
anywhere else. A cell whose toolchain is missing fails.

## 2. Classify the release

Read the new cells' three goldens under `hansei-runtime/tests/matrix/<cell>/`
(and any failure in the blessing run):

- **`formats.snap`** — the detector catalog. A detector that stopped
  attaching, or attached with different member chains, is detect-side
  divergence.
- **`walk.snap`** — the walk-contract report. A path newly `BROKEN`, or
  newly binding a different alternative, is walk-side divergence.
- **`summary.snap`** — extraction shape drift (tasks, awaits).

Then pick exactly one treatment per moved layout:

| What the goldens show | Treatment |
| --- | --- |
| Nothing moved | No code. Review, commit the matrix.sh output. |
| A respelling/wrapper; the underlying layout is an existing family's | New family whose module declares its own spellings and **reuses the prior module's builders** (`tokio_v1_49.rs` is the template: two thin detectors over `tokio_v1_47`'s `*_record` builders, plus a declaration parameter like `flavored_inner` where shared machinery in `detect/tokio.rs` needs to know) |
| A restructure (layout/semantics moved together) | New family with its own builders (`tokio_v1_53.rs` is the template) |
| Divergence *within* one release (cfg/feature-dependent spelling) | Ordered alternative or guarded variant step inside the owning family — the only case that is not a family |

Walk-contract divergence is an ordered alt in the affected `WalkPath`
(`hansei-runtime/src/tokio/contract.rs`).

## 3. Adding a Family — the checklist

All in `exegesis/src/detect/`:

1. `mod.rs`: variant in `Family` (declaration order is first-floor order —
   `ALL` relies on it), its range in `Family::RANGES` (patch-level floors;
   a release a later patch reverts is a family between two of its
   parent's ranges, as `V1_52_0` is), and arms in `parent()` and `name()`.
   `parent()` is the family whose layouts this one departs from — the
   lineage a row falls back along — so a branch family is nobody's parent.
2. Doc comments: the new variant's range and what moved; **tighten the
   prior family's doc to its new ceiling**; the module-doc file list at the
   top of `mod.rs` if it names the family modules.
3. `tokio_v<floor>.rs`: only the detectors and walk routes that moved.
   Same fn names as the sibling modules (`timer_entry_node`, `sleep_node`,
   …).
4. `mod tokio_v<floor>;` declaration, and one `(Family::V<floor>, …)`
   entry in each affected `Versioned` row — never touching other families'
   entries. A row may skip a family (lookup falls back along the lineage),
   so only list the family where the layout actually differs. A walk the
   family's layout lacks altogether takes `absent_here` (recorded absent
   by the version, not broken); a value two families reach by different
   routes roots its rows at `WalkRoot::EndOfAny`.
5. `test_family_selection` in `mod.rs`: asserts on both sides of every
   new floor, and the `describe` string if the example version's family
   moved. A family inside a minor also splits that minor's span in
   `TOKIO_RELEASES` and is pinned in `matrix.toml` beside the minor's
   newest patch.

## 4. Verification gates, in order

Never bless first. The un-blessed diff is the review surface.

1. `cargo nextest run -p exegesis --no-fail-fast` — unit + extraction goldens
   (primary cell). A new family serving the primary pin must leave these
   goldens unchanged unless the render intentionally changed.
2. `.github/scripts/in-image.sh env HANSEI_MATRIX=1 cargo nextest run -p
   hansei-runtime --test matrix` (alone, not under a workspace-wide run;
   x86_64 Linux) — **read every diverged cell** and
   confirm the diff is exactly what step 2's classification predicts (a
   family split with unchanged rendering diffs only the `family:` header
   line in the affected cells' `formats.snap`).
3. `test-programs/matrix.sh bless`, then a plain re-run proving clean,
   then `git diff` on the golden dirs as a second look.
4. `cargo clippy -p exegesis -p reify`; `cargo fmt --all` **and**
   `cargo fmt --manifest-path test-programs/Cargo.toml`.
5. Commit (repo conventions: `exegesis:` / `test-programs:` prefix, why
   before what), then push and run the full suite on every platform —
   green means green on all three, and the other hosts only test what is
   pushed.

## 5. Retiring a version

Deleting a supported version removes its lockfile under
`test-programs/locks/` and its golden dirs in the same change that edits
`matrix.toml`. Advancing the floor past a family's whole range is when
that family's module and enum variant are deleted — a mechanical sweep,
since every version-specific spelling is family-keyed, not buried in
fallbacks.

**Advancing the floor also moves the `linux-floor` fixture set** — the
cores that *execute* the walks at the floor (`testkit::FIXTURE_SETS`).
They are captured fresh on every Linux run from the floor named in
`matrix.toml`, so the first run after the manifest edit reads cores of
the new floor. Re-bless the `@linux-floor` goldens on a Linux host in
the same change and review that the diff is only what the
classification predicts.

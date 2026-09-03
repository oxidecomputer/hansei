---
name: profile-hansei
description: Profile and optimize hansei's render/startup path — the A/B measurement bar a perf change must clear, the profiler traps, and the size-vs-speed policy for bundle changes. Use when investigating hansei performance, proposing a perf optimization, or judging whether a measured win justifies landing.
---

# Profiling hansei

hansei, extraction and the whole render path build and run on macOS and
Linux, so profile locally against a real core: a cored tokio program,
its full debug build, and a current-format tokio-info file extracted
from it. Which cores, binaries and profiler a particular checkout has —
and the measured baselines and the ledger of parked ideas and negative
results — are per-machine and live in the untracked `CLAUDE.local.md`
and the perf ledger it names. **Read that ledger before proposing an
optimization** so a parked idea is not re-proposed.

## The workload

- Pick a task id out of the core rather than reusing one: a `trace <id>`
  for an id the core does not own *errors* while the run still exits with
  output, so a workload built around a stale id silently measures only
  the commands before it. Prefer the deepest task the core owns.
- A good render A/B workload exercises enumeration and the deep value
  render together: `tasks;graph;census;trace <id> -v -d 50`. Timing a
  *second* identical `-e "trace …"` in the same process isolates warm
  render cost from startup.
- The extraction A/B is `hansei tokio-info extract` on a full debug build
  and on a production-scale one: run both, `cmp` bundles against a
  pre-change build (byte-identical unless the change means to alter
  output — and mind that `extract_args` is recorded in `Meta`, so the
  command lines must match exactly), and read peak RSS from
  `/usr/bin/time -l` (macOS) or `/usr/bin/time -v` (Linux).
- Re-extract the tokio-info file after any `FORMAT_VERSION` bump.

## Measurement discipline (the bar a change must clear)

- **A/B on the real workload before landing**: `time` both builds against
  the core, `cmp` the outputs byte-for-byte. Not measurable → revert,
  and record the negative result in the perf ledger so it is not
  re-proposed. Parity does not justify a change either — not even a
  "consistency" refactor.
- **Verify a perf plan's premise first** (count the occurrences!) — a
  projected win is often mooted by an earlier fix.
- Profiler traps, all confirmed the hard way: on-CPU sample profiles hide
  a main thread blocked on a join (parallel work's wall cost gets
  overestimated from its sample share); lazily-built shared state makes
  the first caller look expensive while later callers reuse it — removing
  the "waste" just moves the cost. For attach/startup phases, instrument
  wall timestamps at phase boundaries instead of attributing samples by
  frame-name substrings.

## Bundle size vs speed policy

Bundles are shipped/stored artifacts: size is an ongoing cost, load time
is per-session. Prioritize minimizing runtime work via bundle precompute,
judged by *proportion*: ~1% size for ~5% perf is acceptable; ~20% size for
~1% perf is not. For load-speed-only changes, growth needs roughly ≥20% of
startup saved; prefer levers that keep compression. Format bumps are never
part of the cost calculus. Decided and not to be re-proposed: the
zero-copy/uncompressed mmap layout (17.8× size for ≤0.6 s), and parallel
chunked zstd frames (the zstd time is buffer work, not decompression —
don't revisit without wall-clock phase instrumentation inside
`Bundle::load`).

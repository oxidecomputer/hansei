# Milestone 1 spike findings: v0 symbol matching across separate builds

Status: COMPLETE (2026-07-13). This is the Phase-0 risk-retirement spike from
`HANSEI_V0_MANGLING_PLAN.md` §6. All acceptance criteria met; two plan
amendments identified (see "Consequences for the plan" below).

Environment: illumos box (`ssh illumos`), helios-3.0.24008, rustc 1.97.0
(2d8144b78 2026-07-07), cargo 1.97.0 — v0 mangling is the default, no
`-Csymbol-mangling-version` flag needed. Spike artifacts live in
`/data/spike-v0` on the box (build dirs `a`/`b`, symbol lists, `fl.core.*`);
the one-off verifier is `/data/durin/proc/examples/tls_spike.rs` (untracked).

## 1. Double-build symbol match — PASS

`test-programs/futurelock` built twice as standalone crates at **different
absolute paths** (`/data/spike-v0/a` vs `/data/spike-v0/b`), same toolchain,
same `Cargo.lock` (tokio 1.52.3, oxide-tokio-rt 0.1.6), same flags
(`--cfg tokio_unstable`, release profile with `debug = true`):

- **All 17 `tokio::runtime::task::raw::poll::<T,S>` instantiations: identical
  mangled names.** Crate disambiguators (`Cs…` hashes) are path-independent.
- Of ~14,000 defined v0 symbols, only 148 lines differed — every one an
  internalized symbol carrying a `.llvm.<hash>` suffix (LLVM local-symbol
  promotion; the numeric hash is derived from the module path). After
  stripping `\.llvm\.[0-9]+$`, the two builds' symbol sets are **100%
  identical**.
- A fresh rebuild at the **same** path is bit-for-bit identical in symbol
  names, *including* the `.llvm.` hashes.

Conclusion: the join key is sound. Names of all join-relevant symbols
(task-vtable fns, `<T as Future>::poll` impls, drop glue) match across
separate compilations even at different paths, provided toolchain, lockfile,
features, RUSTFLAGS, and profile match. The only path-sensitive artifact is
the `.llvm.` suffix on internalized *copies*, which the join must strip
(§4 below).

## 2. Symtab audit of production artifacts — PASS (v0 pair still pending)

Real artifacts on hand (`dwarf2ctf/crucible-downstairs.14rc1`,
`dwarf2ctf/propolis-server.16rc1`) predate rustc 1.97 and are legacy-mangled,
so a real-artifact v0 match test is **deferred until omicron ships 1.97
builds**. What they do confirm:

- Production binaries retain a full `.symtab` with local symbols (42k–54k
  local text syms) including all `task::raw::poll` instantiations
  (107 in crucible-downstairs, 131 in propolis-server).
- No address folding: every poll instantiation has a distinct address in
  both artifacts (107/107 and 131/131 unique). Same in the spike build
  (17/17). No ICF/LTO folding observed anywhere — consistent with omicron
  not using LTO (plan §13.6).

## 3. Symtab-only runtime discovery on live process and core — PASS

One-off verifier (`proc/examples/tls_spike.rs` on the box) run against a
deadlocked futurelock, live (`Pgrab`) and against its `gcore`:

- The TLS-key static resolves **by name in the symtab, no DWARF**:
  `_RNvNCNvNtNtCscIwcofkaqOM_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL`
  — a *global* data symbol (`st_info 0x11`, size 16, i.e. std's
  `LazyKey { key, dtor }`).
- The u64 at that address (5) **is** the pthread key, used directly as the
  fast-TSD index — no sentinel adjustment, matching spelunkio's flow.
- Every worker LWP (`tokio-rt-worker`) *and the unnamed main thread* yielded
  a mapped, readable `Context` pointer at `ftsd[key]` — 5/5 LWPs. This
  vindicates the §13.3 decision to probe all LWPs rather than filter by
  thread name.
- Local-symbol lookup round-trips: a `task::raw::poll` instantiation
  (STB_LOCAL, `st_info 0x2`) resolves via `Plookup_by_name` and back via
  `Plookup_by_addr`, identically on the live process and the core.

Caveats worth recording:

- The `__RUST_STD_INTERNAL_VAL` spelling is a std-internal detail of the
  1.97-era `thread_local!` implementation. The bundle must record the exact
  mangled name discovered from DWARF at extraction time (as planned, §5.4),
  never a hardcoded string.
- There is a second, unrelated `…CONTEXT…__RUST_STD_INTERNAL_VAL` static in
  the binary (from `std::sync::mpmc::context::Context::with`). Matching must
  always be on the full mangled name.
- spelunkio's fast-TSD-only caveat stands: key 5 ≤ 8 here, but the slow-TSD
  fallback (`ul_stsd`) remains future work if a target ever exceeds the fast
  array.

## 4. Consequences for the plan (amendments to HANSEI_V0_MANGLING_PLAN.md)

1. **`drop_in_place` is now `drop_glue`.** rustc 1.97 emits drop glue as
   `core::ptr::drop_glue::<T>` — the spike binary has 2,426 `drop_glue`
   symbols and **zero** `drop_in_place`. The dyn-future table (§5.3) and the
   vtable-slot-0 fallback (§3.5) must key on `drop_glue`.
2. **Strip `.llvm.<hash>` suffixes before joining.** 699 of the 2,426
   `drop_glue` symbols (and ~1,000 symbols overall) are internalized copies
   with a path-sensitive `.llvm.<decimal>` suffix. A vtable drop slot may
   point at such a copy, and `Plookup_by_addr` will return the suffixed
   name, while the bundle records the unsuffixed `DW_AT_linkage_name`. Both
   sides of every join must canonicalize by stripping `\.llvm\.[0-9]+$`
   (rustc-demangle does the same). The primary keys — `task::raw::poll`
   instantiations and `<T as Future>::poll` impls (39 in the spike binary) —
   were never suffixed in practice, but the strip is cheap insurance.

## 5. Pinned "bundle-compatible build" recipe

Two builds are join-compatible when **all** of the following match; the
absolute build path does *not* need to:

| Ingredient | Spike value | Rule |
|---|---|---|
| toolchain | rustc 1.97.0 (2d8144b78) | identical rustc (mangling & std internals) |
| mangling | v0 (1.97 default) | ≥1.97, or `-Csymbol-mangling-version=v0` |
| lockfile | same `Cargo.lock` | byte-identical (dep versions feed `-Cmetadata`) |
| features | tokio `full`,`test-util` | identical feature sets |
| RUSTFLAGS | `--cfg tokio_unstable` | identical (feeds `-Cmetadata`) |
| profile | `release` + `debug = true` | identical profile incl. debug level |
| LTO | off (cargo default thin-local) | keep off; ICF unobserved on illumos ld |

Symbol-set comparison procedure (reusable as the §11.2/§11.4 canary):

```sh
/usr/gnu/bin/nm --defined-only BIN | awk '{print $3}' | grep '^_R' \
    | sed 's/\.llvm\.[0-9]*$//' | sort -u
# diff the two outputs; join-critical subset:
#   grep 5tokio7runtime4task3raw4poll
```

Remaining risk (tracked, not blocking): validate on a real omicron artifact
pair once 1.97-built debug/production binaries exist (§2 above); re-run the
double-build against the actual omicron build environment (CI path layout,
`--remap-path-prefix` if introduced) at that time.

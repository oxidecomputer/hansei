# hansei

`hansei` reifies the runtime state of a cored (or snapshotted) Rust/tokio
process:
`exegesis` reads DWARF and emits a self-contained *bundle* describing types;
`hansei-bundle` is that bundle's wire format, and the only thing the read
side depends on; `reify` reads a target process's memory and renders values
of those types for humans. `hansei`/`proc` do the target reading; their
illumos-only parts
are cfg-gated at module level, so both crates **build and compile-check on
macOS** (`cargo check -p hansei` works there) — but *running* against a real
core, and hansei's acceptance suite
(`#![cfg(any(linux, illumos))]`, zero tests on macOS), need an illumos or
Linux host. Type/bundle/render work lives in `exegesis`, `hansei-bundle`
and `reify`, which are fully portable, tests included.

Host names, paths, remotes and the per-host loops for a particular
checkout live in an untracked `CLAUDE.local.md` beside this file; nothing
machine-specific belongs here.

Only exegesis reads DWARF, so only exegesis depends on the DWARF stack
(gimli, object, memmap2, regex). **hansei-runtime and reify never depend on
exegesis** — reify not at all, hansei-runtime as a **dev**-dependency only,
because its matrix goldens build bundles from fixture binaries. The `hansei`
bin crate does depend on it, because `hansei tokio-info` produces and inspects
tokio-info files, but the DWARF stack reaches no further than the entry points
arg handling calls (`hansei/src/bundle_cmd.rs`). exegesis builds no
binary of its own: `hansei` is the only one the workspace produces. No
session, runtime or render code imports exegesis types; if read-side code
seems to need something from it, it wants `hansei-bundle`.

**Naming:** the tool as a whole, and the repository, are **`hansei`**.
`durin` was the repository's earlier name and survives only in old history
and in some local checkout paths; it names nothing. In prose — commit
messages, comments, docs — say "what hansei does", never "what durin
does". The other crate names (`exegesis`, `hansei-bundle`, `reify`,
`proc`) name their specific layers as usual.

## Before every commit

Run `cargo fmt --all` **and** `cargo fmt --manifest-path
test-programs/Cargo.toml`. The tree is meant to be rustfmt-clean; letting it
drift means the next person's `cargo fmt` sweeps unrelated reflow into their
diff. The second command exists because `test-programs` is deliberately not a
workspace member: it is a fixture crate with its own checked-in `Cargo.lock`
(so the version matrix can pin tokio per cell — see
`test-programs/matrix.toml`), and `cargo fmt --all` does not reach it.

One consequence is not cosmetic. A fixture under `test-programs/src/bin/` has
its line numbers pinned by `exegesis/tests/golden/*.golden` — task decls and
await sites — so reflowing a single statement shifts every line below it and
fails that program's golden. Re-bless it
(`INSTA_UPDATE=always cargo nextest run -p exegesis --test golden`) and confirm
the diff
is *only* the shift. The checked-in `hansei-runtime/tests/fixtures/*.tinfo`
pairs record those line numbers too, but are not rebuilt from source, so they
will not fail — they go quietly stale against the fixture they came from.
Regenerating them is the *Format bumps* loop below.

## Adding a new type formatter

A "formatter" teaches reify to render a specific known type (a tokio channel, a
`Notify`, an `Arc<dyn>`, an IP address, …) as decoded semantics instead of raw
bytes.

A formatter is **not** per-type code. It is a `DisplayNode`
(`hansei-bundle/src/schema.rs`) — a small recursive display *program* carried
in the bundle as data — which reify executes with one generic interpreter
(`eval_node` in `reify/src/render/node.rs`). Detection happens in exegesis while
structured DWARF (generic params, field names) is still available; the bundle
records `Selector` paths, and reify reduces those to byte offsets once, when it
resolves the type (`DisplayNode::resolve` in `reify/src/debug_type.rs`).

So the normal cost of a new formatter is **one edit site**: a detector under
`exegesis/src/detect/` that builds the node it wants and reaches for each
datum it addresses. `utf8_path_node` and `slice_node` are the shape to aim for —
a node literal and nothing else. Everything downstream (navigation, name addressing,
the shape check, the `--explain-format` trace, validation, resolution,
rendering, pretty-vs-inline, the cycle guard, the degradation strings) is
already written and generic.

### 1. Pick the node shape · 2. Write the detector

The full recipe — the node vocabulary table, the `reach!` and emitter
vocabulary, the transparent-wrapper helpers, the coverage steps, and the
`--explain-format` / real-DWARF debugging loops — is the `add-formatter`
skill (`.claude/skills/add-formatter/`); follow it rather than re-deriving
the steps. The doctrine that must survive any diff, formatter or not:

- Compose the existing `DisplayNode` vocabulary; a new node kind is the
  exceptional path (see below). A fixed-size byte array with a canonical
  text form is a `Notation` on `Bytes`, not a kind of its own.
- Detectors are **name-keyed and fail safe**: the dispatch tables
  (`BY_NAME` / `BY_PREFIX` / `STRUCTURAL` in `detect/mod.rs`) screen on
  the name, the body describes the layout and returns `None` on any
  mismatch, and whatever it returns is checked against the shape table
  (`hansei-bundle/src/shape.rs`, `DisplayNode::addressed()`) before it is accepted —
  the type then renders structurally, no crash.
- **Address members by name, never by position**: fill selectors through
  `Emitter::walk` / `Emitter::address` (never `Selector::member(index)`),
  and a member *found* by shape must still become a name-addressed path
  where a name exists. `assert_addresses_by_name` in
  `exegesis/tests/golden.rs` enforces it.
- File detectors by who owns the layout, which is who moves it:
  std/core/alloc in `detect/std.rs`, third-party crates in
  `detect/crates.rs`, version-invariant tokio in `detect/tokio.rs`, and
  per-family `detect/tokio_v<floor>.rs` for the tokio types a release
  moved (see *tokio version families* below).


### tokio version families

Any divergence a tokio release ships in a layout the detectors navigate —
a respelled member, an added wrapper, a full restructure — gets **distinct
code covering a version range**, never an ordered fallback that would let
one spelling bind on a version it was not written for: a `Family`
(`detect/mod.rs`) names the range by its floor (`v1_47` covers 1.47–1.48,
`v1_49` covers 1.49–1.52, `v1_53` from 1.53), a `tokio_v<floor>.rs` module
holds *only* the detectors that moved (a family whose layouts are an older
family's plus a respelling declares its own spellings and reuses the older
module's builders, as `tokio_v1_49.rs` does), and the dispatch row lists
one detector per family. The tokio version recovered from the target's
DWARF selects the family once per target: the highest floor at or below
it, the oldest family for anything below every floor, and the newest for
anything newer or unrecovered (with a warning when unrecovered and a
versioned row actually ran). Ordered alternatives inside a detector are
reserved for divergence a version cannot select — a spelling that varies
with build features or cfg within one release. Selection is versioned, but
safety stays structural: the selected
detector still validates the layout and declines on mismatch,
`--explain-format` names the family and why, and each matrix cell's
`formats.snap` header pins which family attached.

A new release is onboarded with `test-programs/matrix.sh` (`update` to
notice one, `add tokio-<ver>` / `add rust-<ver>` for the mechanical
half); the human half is classifying what the new cells' goldens say
moved and giving any version-determined divergence its own family per
the rule above. The full procedure — the classification rubric, the
family-add checklist, and the blessing gates in order — is the
`onboard-tokio-release` skill (`.claude/skills/onboard-tokio-release/`);
follow it rather than re-deriving the steps. Two facts worth knowing
even outside that flow: the floor and primary pins advance deliberately,
by hand — `add` refuses to touch them — and retiring a version deletes
its lockfile and golden dirs in the same change that edits the manifest.
Advancing the floor also means recapturing the `linux-floor` fixture
set at the new floor (`capture-snapshots.sh --tokio <floor>`, Linux
capture host); its SOURCES check fails loudly until that happens.

### 3. Only if no node can express it: add a node kind

The exceptional path: six sites, three of them in `hansei-bundle/src/`
(schema variant, `addressed()` arm, `check_node` arm + **`FORMAT_VERSION`
bump**), a `describe_node` arm in `exegesis/src/describe.rs`, and two in
reify (the resolved variant, an `eval_node` arm that degrades rather than
errors) — the checklist is §5
of the `add-formatter` skill. A missing arm won't compile; a missing
version bump breaks compatibility silently.

### Format bumps

Bumping `FORMAT_VERSION` invalidates the checked-in binary fixtures in
`hansei-runtime/tests/fixtures/`, so a `-p hansei-runtime` run fails to
load them until they are regenerated — which needs an illumos or Linux
host, not macOS. The regeneration loop (land, push, regenerate, `--amend` +
force-push so `main` is never red) is the `format-bump` skill. Never
weigh the bump itself in a design trade-off; the loop is its only cost.

### Testing

**Run tests with `cargo nextest run --no-fail-fast`.** nextest stops at the
first failure by default, so that flag is not optional — the point of a sweep
is every failure at once. It cannot run doctests (the tree has none —
`cargo test --doc` if that changes). Every invocation this file spells
translates directly to `cargo test` where nextest is unavailable.

Green means green on **all three platforms**: macOS, illumos and Linux.
Each has caught a failure the other two could not, so a suite run on one
proves little about the others. Detection is covered portably by the golden
tests below; a real cored target on an illumos or Linux host is where the
render side and the acceptance suite are exercised.

**A test that builds a fixture must go through `testrun::once_per_run`.**
nextest runs each test in its own process, so anything a suite arranged once
per process — the acceptance suite's two compilations and per-program bundle
extraction, the goldens' per-program `regen.sh` — otherwise happens once per
*test*, with every process writing over files the others are reading. That
cost is not small: acceptance took ~200 s per test that way, against 57 s for
the whole suite now. `once_per_run` does the work under a lock and stamps it
with `NEXTEST_RUN_ID`, so a run does it once whether it is one process or
thirty-two, and the next run — named differently — still rebuilds everything
it reads. `testrun` is a dev-dependency-only crate, which is also why the
helper is not `#[cfg(test)]`: that cfg is set only while a crate compiles its
own unit tests, and an integration test links the library built without it.

Each caller also passes a digest of what its fixtures are built *from*, and
setting **`HANSEI_REUSE_FIXTURES`** stamps with that digest instead of the run
id — so a run reuses what an earlier one left behind when no input moved, and
rebuilds when one did. Nothing sets it by default; a human's run rebuilds as
before. It exists for `cargo mutants`, which is one nextest run per mutant
over one scratch copy of the tree per job: with it, the acceptance suite on
Linux is 5 s a run instead of 20 s, which is what makes a sweep on a host
where that suite actually runs affordable at all. If you add fixture work,
add its inputs to the digest (`compiled_from`/`extracted_from` in
`acceptance.rs`, `built_from` in `golden.rs`) — an input left out is a stale
fixture reused under reuse, which is exactly the failure the run stamp exists
to prevent.

Two automated layers run in a plain test run on macOS, plus a manual real-DWARF
check:

- **Golden extraction tests** (`exegesis/tests/golden.rs`) run the real `extract`
  on the `test-programs` fixtures and diff a portable summary (tasks, awaits,
  dyn-futures, infra/statics) against the checked-in
  `exegesis/tests/golden/*.golden`. They read the dSYM DWARF on macOS, so the
  **detection layer is covered on macOS**. Formatters are checked by
  inline `assert_format` calls rather than by the `.golden` files: each names a
  type and its whole expected node tree, with every selector resolved to its
  field-name chain *and* byte offset by `describe_node`, so a detector that
  navigates to the wrong member fails even though it still fires. Covered that
  way today: `&str`, `String`, `Vec`, `&[T]`, `Box<[T]>`, `BTreeMap`, both
  `IpAddr`s, `RawWakerVTable`, `RawMutex`, `Notify`, both semaphores, watch's
  `Receiver`/`AtomicState`, and mpsc's `Block`/`Chan`/`Receiver`; `NonNull`,
  `Unique`, `UsizeNoHighBit`, the loom `UnsafeCell`/`atomic_*` shims, atomics,
  symbols and dyn-pointers have presence-only assertions. **Not** covered by any
  fixture: camino's `Utf8Path`/`Utf8PathBuf`, the loom `parking_lot` shims, and
  `NonZero`. See *Golden tests* below for adding a fixture.
- **Synthetic rendering tests** — reify's rendering. Tests live beside the code
  they cover (`reify/src/render/*.rs`, `reify/src/debug_type.rs`), over the
  hand-built bundles in `reify/src/testhelper.rs` (`node_bundle()` for
  node-formatter tests, `test_bundle()` for the type-kind zoo). Both call
  `b.validate()`, so a test also exercises your io.rs validation for free.
  - Add a name to the fixture's `fixture_ids!` list and a matching
    `types.add(NAME, TypeDef::…)` in the same position. Ids are positions in
    the type table, but you never write a number: the macro numbers the list
    and `add` checks each definition against the id it claims, so a name and
    a definition that fall out of step fail immediately.
  - Build a *separate* type for your feature rather than growing a shared one
    (e.g. `CHAN`): growing it changes its size and truncates other tests'
    fixtures. This the ids cannot catch — the bytes a test lays down are
    matched to a size by hand.
  - Drive it with `FakeMem` (`.at(addr, bytes)`, `.symbol(addr, name)`,
    `.unreadable()`), then assert on
    `format!("{}", value.display_from_target(&mem, depth))`. Byte helpers:
    `u32s`, `u64s`, `node_bytes`, `sync_waiter`, `btree_leaf`, `mpsc_block`;
    selector/expr helpers: `sel`, `ebf`/`ubf`, `vread`/`vconst`/`vadd`/….
- **Offline two-binary fixtures** (`hansei-runtime/tests/fixtures/*.tinfo`) are
  checked-in *binary* bundles with a version header, so **any `FORMAT_VERSION`
  bump makes a `-p hansei-runtime` run fail to load them** — see *Format
  bumps* above for the regeneration loop, which needs an illumos or Linux
  host.
- **Version-matrix goldens** (`hansei-runtime/tests/matrix.rs`, opt-in) build
  every cell `test-programs/matrix.toml` declares (tokio × toolchain ×
  tokio_unstable) via `regen.sh`, extract every tokio fixture per cell, and
  diff three goldens under `hansei-runtime/tests/matrix/<cell>/`: the
  walk-contract report (which alternative spelling bound, what is absent and
  why), the detector catalog (every attached format's member-name chains,
  offsets stripped), and the portable extraction summary. This is what turns
  a fail-safe layer's silent declines into loud diffs when a tokio or
  toolchain release moves a layout. Run with `HANSEI_MATRIX=1 cargo nextest
  run -p hansei-runtime --test matrix` (any other value filters cells by substring;
  `INSTA_UPDATE=always` re-blesses), **alone, not under a workspace-wide
  workspace-wide run** — the primary cell shares fixture dirs with the extraction
  goldens. Cells whose toolchain is not installed skip with a message. A
  full sweep is ~2 minutes cold, ~40 s warm, ~2 GB of gitignored build dirs.
  Onboarding or retiring a version is the `onboard-tokio-release` skill
  (mechanized by `test-programs/matrix.sh`; see *tokio version families*
  above for what a red diff means).

**Mutation testing** (`cargo mutants`, configured in `.cargo/mutants.toml`)
is what tells a test that *pins* behavior from one that merely runs the
code. Nearly every suite here asserts over a frozen capture, so nearly
every test executes the same lines and line coverage says almost
nothing. The per-change loop is the diff — `git diff origin/main >
/tmp/change.diff && cargo mutants --in-diff /tmp/change.diff` — and it
replaces hand-writing mutations to check a new test actually bites. A
whole-crate sweep (`cargo mutants -p hansei-runtime -j 4`) is ~25
minutes; triage its `missed.txt` into tests, or into an `exclude_re`
entry with a comment where the mutant is equivalent.

Every `cargo mutants` run, `--in-diff` included, goes on Linux under a
memory cap. A mutant that breaks a write loop's exit appends output
without bound, and macOS has no enforceable per-process memory cap: such
a run has crashed a machine before the test timeout could reap it.

```
ulimit -v 16777216 && systemd-run --user --scope -p MemoryMax=48G \
  -p OOMPolicy=continue env HANSEI_REUSE_FIXTURES=1 cargo mutants -p <crate> -j 4
```

`ulimit -v` is the limit doing the work (a bomb's own allocation fails,
so the mutant is caught with no cross-fire on sibling jobs);
`OOMPolicy=continue` keeps one OOM kill from tearing down the sweep.
`test_package` in the config widens the judging suite past the mutated
crate, because hansei-runtime is a library its consumers assert, and it
includes exegesis, the only thing that writes a bundle. A survivor worth
chasing is confirmed with a rerun before triage.

Then: `cargo nextest run -p reify -p exegesis -p hansei-bundle`, `cargo clippy -p
exegesis -p reify -p hansei-bundle`, and `cargo fmt --all` (see *Before every
commit*). Do not drop `-p hansei-bundle` from that loop: the bundle
round-trip and validation tests live in the wire crate, and a
`-p exegesis` run alone does not reach them.

### Golden tests

`exegesis/tests/golden.rs` extracts a bundle from each
`test-programs/src/bin/*.rs` fixture and diffs a portable textual summary (task
shapes, await-point lines, dyn-futures, infra/statics presence, and — via inline
`assert!`s in the test — which debug formats were detected) against a checked-in
`exegesis/tests/golden/<program>.golden`. They are the only *automated* coverage
of the real detection path, and they double as a toolchain/DWARF-drift
canary because every fixture is rebuilt from source.

- **Running:** `cargo nextest run -p exegesis --test golden`. Fixtures are built on
  demand by `test-programs/regen.sh` with the pinned toolchain (`1.98.0`).
  That default invocation builds the *primary* matrix cell — the tokio
  version pinned by `test-programs/Cargo.lock`; `regen.sh` can also build
  other cells (`--tokio`/`--toolchain`/`--no-unstable`, `--ct-only` for
  the tokio-without-`rt-multi-thread` cell, plus
  `--no-debug-info` for a production-shaped core target), with the
  supported versions listed in `test-programs/matrix.toml` and per-version
  lockfiles under `test-programs/locks/`. If
  that toolchain is not installed the affected cases **skip with a message**
  rather than fail — so a green run can mean "verified" *or* "skipped
  everything." Install it (`rustup toolchain install 1.98.0`) before trusting a
  pass.
- **Regenerating expectations:** after an intended change to extraction output,
  re-bless with `INSTA_UPDATE=always cargo nextest run -p exegesis --test golden`,
  then
  review the diff to the `.golden` files before committing — that diff is the
  review surface for "did I change only what I meant to."
- **Adding coverage for a new formatter** — and debugging a detector that
  does not fire (`--explain-format`), and discovering a layout from real
  DWARF (`--include-type` + `dump` against a real production binary) — are §§3–4
  of the `add-formatter` skill. The one fact worth repeating here: **debug
  formats are not in the `.golden` files at all**, so a new formatter
  changes no golden and re-blessing tells you nothing about it — its
  coverage is an inline `assert_format` (or presence-only `assert!`) in
  `exegesis/tests/golden.rs`.

`config ugly on` disables every custom formatter for the session and prints
the raw structural view — the way to see what a formatter is hiding, and to
check that it hides only what you meant.

What varies by target, and so must never be pinned in a portable test:

- **Whether a core needs the binary alongside it.** An illumos core carries
  each mapped object's symbol table in its own section headers; a Linux one
  carries no symbols at all (`.symtab` is not `SHF_ALLOC`, so it is never in
  the address space there is to dump), and names a path that is rarely still
  right on the machine reading it. So hansei requires `--binary` — the
  executable that *ran*, not a separate debug build — for a Linux
  core, checks it against the core's `NT_GNU_BUILD_ID`, and warns that it is
  ignored for an illumos one. The acceptance suite fills the flag in from the
  core itself (`binary_args`), so its call sites do not carry it.
- **How much of a stack unwinds exactly.** An illumos core carries every
  mapped object's text, so library CFI is always on hand; a Linux core
  carries none, and the backing files its `NT_FILE` names exist only on
  the capture host. Read elsewhere, a walk is exact through the
  `--binary` executable, then cuts silently at the first library frame
  (the walk's truncation note says why); the frames the frame-pointer
  fallback
  bridges print like any other. Only supplying the named libraries
  makes those frames exact.
- **A timer's deadline spelling.** illumos lwps stamp a stop time and the
  deadline is reported relative to it; a Linux core records none, so the
  absolute point on the monotonic clock is printed instead. Both spellings are
  covered from constructed values in `hansei-runtime`; the acceptance suite masks
  the deadline whole.
- **Which wrapper futures exist.** Whether an adapter survives as its own
  monomorphization or is inlined away is the target's call
  (`Next<FuturesUnordered<…>>` is emitted on ELF, absent from the Mach-O
  build; `LocalSet::run_until`'s `RunUntil<…>` differs the same way between
  two near-identical fixtures), so the golden dyn-future list skips
  `futures_util`/`futures_core` and `tokio::task::local::` types. Expect the
  next wrapper future added to a fixture to need the same treatment.
- **Whether two identically-shaped futures both keep their drop glue.**
  Identical code is foldable and Mach-O folds it, so only one of them is
  named in the golden dyn-future list while ELF names both. Give a fixture's
  futures distinct shapes — capture something different — rather than
  discovering this a cross-platform round trip later.
- **Offsets reached through tokio's `driver::Handle`,** whose io and signal
  members embed OS-specific types. The `TimerEntry` `assert_format` carries one
  arm per system because no two agree. Every other offset these asserts pin is
  portable.

### tokio/std layout facts worth remembering

- A **sized** `Arc<T>`'s pointer targets `ArcInner<T> { strong, weak, data: T }`,
  so plain recursion already reaches `data` — a dedicated formatter is about
  *presentation* (flattening, surfacing one field), not reachability. An
  **unsized** `Arc<dyn>` needs the `tail_offset` trick (see `DynPointer`) to skip
  the header.
- `NonNull<T>`'s field is `pointer`. tokio wraps shared state in
  loom/`UnsafeCell` shims navigated by the literal member names `__0` / `value`.
- mpsc: `bounded::Receiver<T>` → `chan::Rx` (`inner`) → `Arc<Chan<T, S>>`;
  capacity is the bounded `Semaphore`'s `bound`, free slots are the inner
  `batch_semaphore::Semaphore`'s `permits` word (bit 0 = closed, rest = count).
- Reach an atomic's stored word with `PeelTo(WORD)` (or `Shape::Uint(1)`,
  `Shape::Pointer`), **not** by naming the atomic type on the way. Only the
  generic `core::sync::atomic::Atomic<T>` spelling has a `T` to navigate; real
  binaries also emit concrete `AtomicU8` / `AtomicUsize` types, and a walk that
  expects the generic one silently declines on those. Peeling to a shape has no
  such blind spot. `PeelToParam` is for the one case that genuinely wants the
  declared `T` — the `Atomic<T>` detector itself.
- tokio's loom shim `tokio::loom::std::parking_lot::Mutex<T>` is a tuple struct:
  `__0` is a zero-sized `PhantomData`, `__1` is the real
  `lock_api::Mutex<RawMutex, T>` (`{ raw: RawMutex, data: UnsafeCell<T> }`).
  Navigate `__1` (its `Alias` node names that member), then `data` → `value` for
  the guarded value.
- `Option<NonNull<T>>` (linked-list `head`/`tail`, intrusive `next`) is
  niche-optimized to a pointer-sized **enum** TypeDef, not a `Pointer`: a null
  word is `None`. Read it as a `u64` (0 = empty) and address such a path with
  `Shape::PointerSized` rather than `Shape::Pointer` (`selector_target` /
  `resolve_selector` land on the enum fine, since the last step does not traverse
  into it). An intrusive `tokio::util::linked_list` node reaches
  its successor via `pointers.inner.value.next` (`Pointers` → `UnsafeCell` →
  `PointersInner`); the `LinkedList<L, T>` node type is its last template param.
- An **unresumed** coroutine's frame carries only its *arguments* — a body
  local of an `async fn` that has never been polled exists in no variant
  anything can read. This decides fixture design wherever a test needs a
  find *inside* a future that is merely held: every held future in the
  fixtures is `Unresumed`, so the inner future has to arrive as an
  argument (`unordered.rs`'s `holder`), not as a `let` in the body. A
  future that has been polled and suspended does carry its locals, which
  is why the same shape works unaided for a set's children.

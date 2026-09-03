---
name: add-formatter
description: Add or fix a reify type formatter — pick the DisplayNode shape, write the exegesis detector, add golden coverage, and debug a detector that does not fire. Use when teaching hansei to render a new known type (a tokio primitive, a std/crate container, a byte-array notation) or when a formatter stopped attaching or renders the wrong member.
---

# Add (or fix) a type formatter

Doctrine (also in CLAUDE.md): a formatter is **not** per-type code. It is a
`DisplayNode` (`hansei-bundle/src/schema.rs`) — a display *program*
carried in the bundle as data — executed by one generic interpreter
(`eval_node` in `reify/src/render/node.rs`). Detection happens in exegesis
while structured DWARF is available; the bundle records `Selector` paths;
reify reduces them to offsets once (`DisplayNode::resolve` in
`reify/src/debug_type.rs`). The normal cost is **one edit site**: a
detector under `exegesis/src/detect/`. `utf8_path_node` and `slice_node`
are the shape to aim for — a node literal and nothing else.

Workflow: discover the layout (§4) → pick the node shape (§1) → write the
detector (§2) → add coverage (§3) → verify + the usual gates (`cargo nextest run
-p exegesis -p reify -p hansei-bundle`, clippy, `cargo fmt --all` **and** `cargo fmt
--manifest-path test-programs/Cargo.toml`). A new node kind (§5) is the
exceptional path.

## 1. Pick the node shape

Compose the existing vocabulary; do not reach for a new node kind (§5 says
what that costs). The kinds, with the formatters that use them:

| Node | Renders | Used by |
| --- | --- | --- |
| `Scalar { at, decode }` | one machine word, decoded (see below) | atomics, `RawMutex`, watch state, semaphore permits |
| `Symbol { at }` | a code pointer as `0x… -> name` | function pointers, `RawWakerVTable` slots |
| `Struct { fields }` | a **curated** record `T { a, b }` | `Notify`, both semaphores, `Chan` |
| `List { head, next, node, node_ty }` | an intrusive singly-linked list | waiter queues |
| `Str { pointer, length, capacity }` | a quoted UTF-8 buffer | `&str`, `String`, camino paths |
| `Slice { pointer, length, capacity, element }` | a `(ptr, len)` buffer of elements | `Vec`, `&[T]`, `Box<[T]>` |
| `Bytes { at, notation }` | an inline byte array in a standard text form | `Ipv4Addr`/`Ipv6Addr`, `Uuid`, `ArtifactHash` |
| `Alias { at, follow_pointers }` | one inner member as the whole value | `NonNull`, `UnsafeCell`, loom shims, scalar newtypes |
| `SlotCount { bitmap, slots }` | a readiness bitmap as `[<n> slots]` | mpsc `Block` |
| `Pointer { at, via, then }` | one pointer hop, re-rooting `then` | mpsc `Receiver` → `Chan` |
| `DynPointer { … }` | a trait-object wide pointer + vtable | `Arc<dyn>`, `Box<dyn>` |
| `Map { length, key, value, entries }` | `{ k: v, … }` over a storage-specific walk | `BTreeMap` |
| `Variant { discriminant, arms, default }` | a sum type chosen by a *computed* discriminant | `watch::Receiver`'s unseen value |
| `CustomList { vars, condition, body, element }` | a sequence from a tiny imperative program | mpsc block-chain window |

A fixed-size byte array with a canonical text form is a `Notation` on
`Bytes`, not a kind of its own: a `Uuid` and an `Ipv6Addr` are both
`[u8; 16]`, so what separates them is the spelling. Adding one is a variant
plus a detector, with no format bump beyond the notation itself.

The last two are the escape hatches, and they are why new node kinds should
be rare: `Variant` + `ValueExpr` absorbed `watch::Receiver` (`74efab5`) and
`CustomList` absorbed the whole mpsc block chain (`f816c1c`), both of which
had looked irreducible.

Addressing is a `Selector` — a list of `Step::Member(MemberRef)` /
`Step::Deref` steps. A cross-pointer reach is not special: it is a selector
with a `Deref` in it, so an `Arc`-backed word is reachable from an outer
root. A `MemberRef` is `Named(s)` or `Index(i)`; **prefer the name**, and
you get it for free by going through `Emitter::walk` or `Emitter::address`
rather than writing an index. Extraction rewrites member lists *after*
display programs are attached (`drop_members_of_other_states` retains a
coroutine state's own members), which shifts positions but not names.

A `Struct` shows *only* the `Field`s it lists (a formatter's job is to hide
internal detail): `Field::Member { at, node }` renders a real member under
its DWARF name — structurally when `node` is `None`, and with a computed
value otherwise — and `Field::Synth { label, node }` synthesizes one under
an explicit label.

What a node requires of the types its selectors land on is stated once, in
`hansei-bundle/src/shape.rs`: `DisplayNode::addressed()` names each datum and the
`Shape` its type must have. Both universes check it — `shape_matches`
against the type table on save and load, `addressing_holds` against DWARF
as the program is built — so a detector that navigates to the wrong member
declines and renders structurally rather than producing a bundle that fails
validation. The table is the *floor*; a detector may screen more tightly
(`&str` insists on a byte pointer where `Str` takes any pointer) but never
less.

Word semantics are data too: `ScalarDecode::Bits(Vec<BitField>)` describes
the bit layout (`shift`, `width`, `FieldRender::Enum`/`Uint`), so old reify
renders new bundles correctly. Two contracts hold everywhere and you get
them free: an enum value missing from its table renders `<unknown: N>`, and
any word bit no field covers renders `<unknown bits: 0xNN>` — the rule that
actually catches upstream drift. Build tables with `Emitter::enum_field` /
the existing `mutex_byte_decode`, `notify_state_decode`,
`semaphore_permits_decode`, `watch_state_decode`, `bool_decode`; do not
re-derive a bit layout. A record field that is just a decoded word is one
call: `emitter.named_scalar(label, at, decode)`.

## 2. Write the detector (`exegesis/src/detect/`)

File it by who owns the layout: dispatch tables and shared machinery in
`detect/mod.rs`, std/core/alloc (plus the structural chain) in
`detect/std.rs`, third-party crates in `detect/crates.rs`,
version-invariant tokio in `detect/tokio.rs`, and per-family
`detect/tokio_v<floor>.rs` for the tokio types a release moved (doctrine
and the family-add procedure: CLAUDE.md *tokio version families* and the
`onboard-tokio-release` skill).

Detectors are **name-keyed and fail safe**: the dispatch table screens on
the name, the body describes the layout and returns `None` on any mismatch —
the type then renders structurally, no crash. Whatever a detector returns
is checked against the shape table before it is accepted
(`debug_format_of`). Every detector has one signature,
`fn(&mut Emitter<'_>, TypeId) -> Option<DisplayNode>`; one that only
navigates DWARF starts with `let reader = emitter.reader;`, and one that
needs `emitter.intern(…)` for a label or decode table or
`emitter.reserve(ty)` for an `element`/`key`/`node_ty` uses the emitter
directly. So **write the function, add a row, done** — pick the row by how
the type is *named*:

- **`BY_NAME`** — keyed by the fq name with generic arguments stripped.
  Nearly every formatter belongs here. Do not re-check the name in the
  body: the key is that check. A row is `All(detector)` unless a tokio
  release moved a layout the detector navigates, in which case it is
  `Versioned(&[(Family, detector), …])`.
- **`BY_PREFIX`** — keyed by a prefix of the *full* name, for a family no
  single base name spans (`&[T]` / `Box<[T]>`, the per-width
  `NonZero*Inner`, the per-width loom `atomic_*` modules). A prefix is a
  looser screen, so the body keeps the residual check the key cannot
  express.
- **`STRUCTURAL`** — only for a type no name selects: a
  `{ pointer, vtable }` pair, a pointer to a subroutine type, a bare scalar
  newtype. Tried in order, most specific first, with the scalar newtype
  deliberately last. Keep this list short; a name-keyed detector here is
  invisible to `--explain-format`.

A helper another detector calls on an arbitrary member type
(`is_generic_atomic`, `is_raw_mutex`, `is_batch_semaphore`,
`unsafe_cell_layout`, `non_null_layout`) *does* check the name, since no
table screened that member for it.

Where two spellings of one concept share a display program, give them one
node-building detector over a small shape struct holding the navigation
result (`VecShape`, `ChanShape`) rather than two detectors.

**Reach for a datum; do not walk to it.** A detector builds the
`DisplayNode` it wants and fills each `Selector` by handing `Emitter::walk`
a *reach* — a description of how to get there, which the walk resolves
against DWARF, lowers to a name-addressed selector, and declines on with an
`--explain-format` line naming the step that failed:

```rust
Some(DisplayNode::Str {
    pointer: emitter.walk(id, &reach![Named("data_ptr")])?.0,
    length: emitter.walk(id, &reach![Named("length")])?.0,
    capacity: None,
})
```

A `reach![…]` is a list of `ReachStep`s:
- `Named("a")` — the uniquely-named member. Two members of that name
  decline, as does none.
- `Deref` — follow the pointer reached so far.
- `PeelTo(shape)` — descend the zero-offset wrapper chain to the one value
  of that `Shape`. This is how every tokio atomic's word is reached: loom,
  `UnsafeCell` and atomic shims vary in spelling and depth, and `WORD` (a
  `usize`) or `Shape::Uint(1)` or `Shape::Pointer` says what is wanted
  without naming any of them. Unlike naming the atomic type, it has no
  blind spot between the generic `Atomic<T>` and a concrete `AtomicU8`.
- `PeelToParam` — the same descent, to the `T` a `Wrapper<T>` declares. For
  an atomic, whose stored type is its own parameter rather than a fixed
  shape.
- `FindParam` — the same descent through *any* member, for a `T` a type
  keeps past its own bookkeeping rather than behind wrappers: the value
  inside a lock, whose guard word sits at offset zero ahead of it.
- `Resolved(sel)` — splice in a path something else resolved, which is how
  a shape helper's selectors are anchored under the member holding them.
  The spliced steps are re-addressed, so a helper may return positional
  ones.

The rest of the emitter's vocabulary:
- `member_named(root, name)` — a `MemberRef` for a member addressed by
  name, checking it is there. What a `Field` wants.
- `visible_fields(root, overrides)` — every member structural display would
  show, in declaration order, with the named ones computed instead. Splice
  synthesized fields around the result; that is how the channel prepends
  its `queued`.
- `landed(root, reach)` — the type a reach lands on, for a screen tighter
  than the node's own requirement.
- `pointee(ty)` / `behind(ty)` — the type a pointer targets, to root
  something at the far side or to name it.
- `address(members, index)` — how a member *found* by shape becomes an
  address: by name where a name selects it, by position where none can.
  Every walk that finds rather than declares ends here, which is what keeps
  a discovered path as durable as a declared one.

Never write `Selector::member(index)` in a detector. A test asserts no
emitted program addresses a member by position (`assert_addresses_by_name`
in `exegesis/tests/golden.rs`), since only an unnamed member or one of
several sharing a name may be reached that way.

For a **transparent wrapper** — a newtype whose one member *is* the value —
the member is identified by a predicate, not a name, so it stays
imperative: `zero_offset_member(reader, &st.members, Some("pointer"),
accept)` finds the unique member at offset zero of that name (pass `None`
for whatever name) whose type `accept`s, `sole_param_target` gives the `T`
a `Wrapper<T>` declares so `accept` can require the member to be it, and
`transparent(emitter, &st.members, member)` builds the node — addressing it
by name through `Emitter::address`. The ten such wrappers (`UnsafeCell`,
`NonNull`, `Unique`, `NonZero` and its niche inner, `UsizeNoHighBit`, the
loom shims, the bare scalar newtype) are each a screen plus one call; an
eleventh should be too.

Anything else that finds a member by shape rather than by name —
`find_unique` with a `Want`/`Through`, as the two `Vec` spellings and the
B-tree use — must turn what it found into an address with
`Emitter::address` or `Emitter::readdress` rather than recording a
position.

The remaining reader-level helpers: `struct_of(reader, id)` (the struct a
type is, a detector's usual first line), `aggregate_members`,
`unique_member`, `is_unsigned_integer`, `raw_type_size`.

Shared shape builders are worth extending rather than copying:
`waiter_queue_field` serves both `Notify` and the bounded `Semaphore`,
`mpsc_queued_node` builds the block-chain program, and `mutex_byte_path` /
`permits_path` are the paths two detectors each reach for.

## 3. Add coverage

**Debug formats are not in the `.golden` files at all** — the summary
covers tasks, awaits, dyn-futures and infra/statics only. A new formatter
changes *no* golden, and re-blessing tells you nothing about it. The
coverage is the inline assertion:

1. Add or extend a fixture in `test-programs/src/bin/` that instantiates
   the type and reaches a steady parked state (the existing programs print
   a marker line — e.g. `READY` — once parked; see `capture-snapshots.sh`).
   Mind CLAUDE.md *Before every commit*: fixture line numbers are pinned by
   the goldens, so reflow means re-blessing and reviewing the shift.
2. Add an `assert_format(program, bundle, "<fq type name>", "<expected>")`
   to the matching test in `exegesis/tests/golden.rs`. Write the expected
   string as anything and run once: the panic prints the actual render, so
   blessing it is a copy-paste. `describe_debug_format` resolves every
   selector to its field-name chain *and* byte offset, which is what
   catches a detector that fires but lands on the wrong member.
3. For a formatter whose exact tree is not worth pinning, a presence-only
   `assert!` will do (grep the existing
   `debug_formats.values().any(|node| matches!(node, DisplayNode::X { .. }))`
   checks) — that catches a detector that stops matching at all, but not
   one that starts matching the wrong thing.
4. Only re-bless if the fixture change also moved a task shape or await
   line.

If the render side needed anything new (a decode, a degradation path), add
synthetic rendering tests beside the code (`reify/src/render/*.rs`) over
the hand-built bundles in `reify/src/testhelper.rs` — see CLAUDE.md
*Testing* for the `fixture_ids!` / `FakeMem` conventions.

## 4. Discovering a layout, and debugging a detector

**Verifying against real DWARF.** Do this *before* writing the
detector to learn the exact field names/offsets, and *after* to confirm it
attached — and for any type no fixture exercises yet. Extraction is
portable, so any debug build of a real tokio program will do, on any
host. Extract a tokio-info file that includes the type, then dump it:

```
hansei tokio-info extract <debug-binary> -o /tmp/x.tinfo \
    --include-type "tokio::sync::mpsc::bounded::Semaphore" --allow-missing-infra
hansei tokio-info dump /tmp/x.tinfo | grep -n "struct <Name> "  # read its members
```

`--include-type <fqn>` forces an otherwise-unreached type to be emitted;
`--allow-missing-infra` lets extraction proceed on a non-target binary. The
dump prints each aggregate's `+offset name : [type-id]` members and, for
types your detector claimed, a `debug: <DisplayNode>` line showing the
emitted node tree. A production-scale binary carries the full tokio/std
graph and extracts in seconds; the ones on hand for a particular checkout
are listed in the untracked `CLAUDE.local.md`. Extraction runs
`validate()` on save and `dump` runs it on load, so a bad path surfaces
there rather than silently.

**When a detector does not fire**, ask why instead of guessing —
`--explain-format <substring>` reports, for every emitted type whose name
contains the substring, which name-keyed detector was selected (or that
none was), where a named walk stopped and what members the type actually
has, whether a shape walk found nothing or found several candidates, and
what program was emitted:

```
hansei tokio-info extract <debug-binary> -o /tmp/x.tinfo --allow-missing-infra \
    --explain-format "tokio::sync::notify::Notify"
tokio::sync::notify::Notify [type 2263]
  name-keyed detector for `tokio::sync::notify::Notify` selected
  => Struct
```

A name-spelling mismatch (`&camino::Utf8Path` is not `camino::Utf8Path`)
shows up as "no name-keyed detector", a renamed field as "no unique member
`x` in T, which has …", and a wrong `Through` mode as "found N+
candidates". Since only the three `STRUCTURAL` detectors are not
name-keyed, "no name-keyed detector" on a type you wrote a formatter for
means the row's key is wrong. Nothing at all printed means no emitted type
matched the substring — reach the type with `--include-type`.

**Exercising the rendered output** needs a real cored target and a
tokio-info file extracted from its debug build; which cores and hosts a
checkout has, and the extract-and-trace loop for each, are in the
untracked `CLAUDE.local.md`. `config ugly on` disables every custom formatter for the session and prints
the raw structural view — the way to see what a formatter is hiding, and to
check that it hides only what you meant.

## 5. Only if no node can express it: add a node kind

The exceptional path: six sites plus a format bump (and a format bump means
the `format-bump` skill's fixture-regeneration loop).

1. `hansei-bundle/src/schema.rs` — the `DisplayNode` variant. Document it
   thoroughly; the doc comment is the contract for the rest.
2. `hansei-bundle/src/shape.rs` — an arm in `DisplayNode::addressed()`
   naming every datum the node reaches within the value it renders and the
   `Shape` its type must have (`Word` / `Uint(n)` / `PointerSized` /
   `Pointer` / `Array` / `Any`). Both the DWARF-side and table-side checks
   read this. A selector rooted somewhere else — across a `Deref`, or at a
   `node_ty` — does not belong here; its arm checks it against the root it
   resolves.
3. `hansei-bundle/src/io.rs` — an arm in `check_node` for whatever the
   shape table cannot express (a related type id being in range, a vtable
   slot being inside the array), and **bump `FORMAT_VERSION`** (bundles
   validate on save *and* load). A missing arm won't compile; a missing
   version bump breaks compatibility silently.
4. `reify/src/debug_type.rs` — the matching variant of reify's resolved
   `DisplayNode<'a>` (offsets and `BundleType`s, not selectors) and a
   `resolve_node` arm under `DisplayNode::resolve`; `resolve_selector` does
   the path→offset work.
5. `reify/src/render/node.rs` — an `eval_node` arm. Read scalars from the
   value's bytes, follow pointers through `ctx.proc`, guard with
   `ctx.visited`, and degrade to `<null>` / `<truncated>` /
   `<target unavailable>` / `<unreadable>` rather than erroring.
6. `exegesis/src/describe.rs` — a `describe_node` arm, so the golden
   summary keeps printing the fully resolved tree. (`exegesis/tests/
   golden.rs` only *calls* `describe_debug_format`; nothing to add there.)

Nothing in exegesis needs a counterpart: a detector builds the node
directly, so a new kind costs a `DisplayNode` variant and the arms that
read it, nothing more.

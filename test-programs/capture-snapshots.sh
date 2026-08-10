#!/usr/bin/env bash
#
# Produce the two-binary offline test fixtures (plan §11.3): for each
# test program, a target *snapshot* captured from one compilation
# (build A) and a debug *bundle* extracted from a second, separate
# compilation of the same sources (build B). The offline tests then
# join B's bundle against A's snapshot — the two-binary constraint,
# exercised in plain `cargo test` on any platform.
#
# Each program is driven to its steady state and cored with gcore(1),
# and the snapshot is captured from that core. Neither step is
# platform-specific: gcore takes a core under the same spelling on
# illumos and Linux, and hansei reads either format. Fixtures land in
# hansei-runtime/tests/fixtures (override with $1) and are small enough to
# check in; this script makes them regenerable either way.
#
# What a capture is worth does vary by platform, though. The bundle's
# symbol fingerprint is built from the tokio `poll` instantiations that
# survive into the binary's own symbol table, and illumos keeps far more
# of them than Linux does — 15 against 3 for simple-await. Both resolve
# complete, so both reject a mismatched pair, but a capture taken on
# illumos checks a pair against more names.
#
# Usage: capture-snapshots.sh [OUT_DIR]

set -euo pipefail

cd "$(dirname "$0")"
OUT="$(cd "${1:-../hansei-runtime/tests/fixtures}" 2>/dev/null && pwd || true)"
if [[ -z "$OUT" ]]; then
    OUT="${1:-../hansei-runtime/tests/fixtures}"
    mkdir -p "$OUT"
    OUT="$(cd "$OUT" && pwd)"
fi
FIXTURES="$PWD/fixtures"

# Program -> the stdout line marking its parked steady state. Reads
# block on the child's stdout; there are no timing sleeps anywhere.
PROGRAMS=(simple-await nested-await dyn-future futurelock sleep-join channels)
marker() {
    case "$1" in
        # Deadlocked for good once the background task drops the lock
        # (RFD 609: the handoff goes to the never-again-polled future1).
        futurelock) echo "background task: done (dropping lock)" ;;
        *) echo "READY" ;;
    esac
}

# Two separate compilations of the same sources (regen.sh): build A is
# the capture target, build B feeds the extractor. Build A carries no
# debug info — the shape of a production binary a core actually comes
# from — so the join is proven against a target whose only self-
# description is its symbol table, with all DWARF coming from B.
REGEN_BIN_DIR="$FIXTURES/bin-a" REGEN_TARGET_DIR="$FIXTURES/target-a" \
    ./regen.sh --no-debug-info "${PROGRAMS[@]}"
REGEN_BIN_DIR="$FIXTURES/bin-b" REGEN_TARGET_DIR="$FIXTURES/target-b" \
    ./regen.sh "${PROGRAMS[@]}"

# The capture tools themselves come from the workspace as-is, except
# that `snapshot` is not in a default hansei: it makes test data rather
# than answering anything about a target, so it is behind a feature.
(cd .. && cargo build -p exegesis && cargo build -p hansei --features snapshot)
EXEGESIS=../target/debug/exegesis
HANSEI=../target/debug/hansei

for p in "${PROGRAMS[@]}"; do
    "$EXEGESIS" extract "$FIXTURES/bin-b/$p" -o "$OUT/$p.bundle"

    fifo="$(mktemp -u)"
    mkfifo "$fifo"
    coredir="$(mktemp -d)"
    "$FIXTURES/bin-a/$p" >"$fifo" 2>&1 &
    pid=$!
    trap 'kill $pid 2>/dev/null || true; rm -f "$fifo"; rm -rf "$coredir"' EXIT

    want="$(marker "$p")"
    while IFS= read -r line; do
        [[ "$line" == "$want" ]] && break
    done <"$fifo"
    # Keep draining stdout so the child never blocks on a full pipe.
    cat "$fifo" >/dev/null &

    gcore -o "$coredir/core" "$pid"
    # hansei takes its commands on stdin, not as arguments.
    echo "snapshot $OUT/$p.snapshot" |
        "$HANSEI" --core "$coredir/core.$pid" --bundle "$OUT/$p.bundle"

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -rf "$coredir"
    rm -f "$fifo"
    trap - EXIT

    echo "capture-snapshots.sh: $p -> $OUT/$p.{bundle,snapshot}"
done

# What the pairs were captured from. A snapshot is frozen but the
# programs are not, and nothing else compares the two — the offline
# goldens quote line numbers out of sources they are never rebuilt
# against — so the offline suite checks this manifest and says to come
# back here when it no longer matches.
DEFAULT_OUT="$(cd ../hansei-runtime/tests/fixtures 2>/dev/null && pwd || true)"
if [[ "$OUT" == "$DEFAULT_OUT" ]]; then
    (cd .. && FIXTURE_SOURCES_BLESS=1 \
        cargo test -q -p hansei-runtime --test two_binary fixtures_record >/dev/null)
    echo "capture-snapshots.sh: recorded the fixture sources in $OUT/SOURCES"
else
    echo "capture-snapshots.sh: $OUT is not the checked-in fixture dir;" \
         "SOURCES not written" >&2
fi

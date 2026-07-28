#!/usr/bin/env bash
#
# Produce the two-binary offline test fixtures (plan §11.3): for each
# test program, a target *snapshot* captured from one compilation
# (build A) and a debug *bundle* extracted from a second, separate
# compilation of the same sources (build B). The offline tests then
# join B's bundle against A's snapshot — the two-binary constraint,
# exercised in plain `cargo test` on any platform.
#
# illumos-only: each program is driven to its steady state and cored
# with gcore(1), and the snapshot is captured from that core. Fixtures
# land in hansei-types/tests/fixtures (override with $1) and are small
# enough to check in; this script makes them regenerable either way.
#
# Usage: capture-snapshots.sh [OUT_DIR]

set -euo pipefail

if [[ "$(uname -s)" != "SunOS" ]]; then
    echo "capture-snapshots.sh: snapshots can only be captured on illumos" >&2
    exit 2
fi

cd "$(dirname "$0")"
OUT="$(cd "${1:-../hansei-types/tests/fixtures}" 2>/dev/null && pwd || true)"
if [[ -z "$OUT" ]]; then
    OUT="${1:-../hansei-types/tests/fixtures}"
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

# Two separate compilations, same pinned recipe (regen.sh): build A is
# the capture target, build B feeds the extractor.
REGEN_BIN_DIR="$FIXTURES/bin-a" REGEN_TARGET_DIR="$FIXTURES/target-a" \
    ./regen.sh "${PROGRAMS[@]}"
REGEN_BIN_DIR="$FIXTURES/bin-b" REGEN_TARGET_DIR="$FIXTURES/target-b" \
    ./regen.sh "${PROGRAMS[@]}"

# The capture tools themselves come from the workspace as-is.
(cd .. && cargo build -p exegesis -p hansei)
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
    "$HANSEI" snapshot --core "$coredir/core.$pid" \
        --bundle "$OUT/$p.bundle" -o "$OUT/$p.snapshot"

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -rf "$coredir"
    rm -f "$fifo"
    trap - EXIT

    echo "capture-snapshots.sh: $p -> $OUT/$p.{bundle,snapshot}"
done

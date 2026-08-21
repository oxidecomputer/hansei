#!/usr/bin/env bash
#
# Produce the two-binary offline test fixtures: for each
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
# So neither system stands for the other: each keeps a set of its own
# under tests/fixtures/<set>, this script writes the set belonging to
# the system it runs on, and the build reads the set matching it
# (testkit::FIXTURE_SET). Recapturing on one leaves the other's pairs,
# and its goldens, alone.
#
# Usage: capture-snapshots.sh [--tokio VER] [OUT_DIR [PROGRAM...]]
#
# With no PROGRAMs, every fixture pair is recaptured. Naming some
# captures only those, leaving the other checked-in pairs — and the
# goldens quoting them — exactly as they are.
#
# --tokio VER builds both compilations against locks/tokio-VER.lock and
# writes the version-endpoint set <os>-floor. Only matrix.toml's floor
# is accepted: the matrix pins that the walks *bind* per version, and
# this set is what *executes* them against memory from the range's far
# end — one endpoint set, not a per-cell cross product.

set -euo pipefail

cd "$(dirname "$0")"

TOKIO=""
if [[ "${1:-}" == --tokio ]]; then
    TOKIO="$2"
    shift 2
fi

# Each system that can core a process keeps a set of its own, named for
# itself, and `testkit::FIXTURE_SET` reads the one matching the build.
case "$(uname -s)" in
    SunOS) SET=illumos ;;
    Linux) SET=linux ;;
    *) echo "capture-snapshots.sh: $(uname -s) takes no ELF core to capture from" >&2
       exit 1 ;;
esac
if [[ -n "$TOKIO" ]]; then
    FLOOR="$(awk -F'"' '/^\[/{s=$0} s=="[tokio]" && /^floor/{print $2; exit}' matrix.toml)"
    if [[ "$TOKIO" != "$FLOOR" ]]; then
        echo "capture-snapshots.sh: --tokio $TOKIO is not the floor ($FLOOR);" \
             "only the endpoint set is captured per version" >&2
        exit 2
    fi
    SET="$SET-floor"
fi
OUT="${1:-../hansei-runtime/tests/fixtures/$SET}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
FIXTURES="$PWD/fixtures"

# Program -> the stdout line marking its parked steady state. Reads
# block on the child's stdout; there are no timing sleeps anywhere.
PROGRAMS=(simple-await nested-await dyn-future futurelock sleep-join channels
          unordered joinset ct-runtime local-set local-set-timer local-set-io
          foreign-runtime gen-0007 walk-shapes)
if [[ $# -gt 1 ]]; then
    PROGRAMS=("${@:2}")
fi
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
# description is its symbol table, with all DWARF coming from B. Build
# B is the standard fixture build in regen.sh's own dirs, shared with
# the extraction goldens and the acceptance suite; only A, the cored
# side, needs a compilation of its own. A --tokio build B cannot share
# those dirs (they hold the primary pin), so it gets a dir of its own;
# its target dir is regen.sh's cell default, shared with the matrix.
TOKIO_ARGS=()
if [[ -n "$TOKIO" ]]; then
    TOKIO_ARGS=(--tokio "$TOKIO")
fi
REGEN_BIN_DIR="$FIXTURES/bin-a" REGEN_TARGET_DIR="$FIXTURES/target-a" \
    ./regen.sh --no-debug-info "${TOKIO_ARGS[@]}" "${PROGRAMS[@]}"
if [[ -n "$TOKIO" ]]; then
    BIN_B="$FIXTURES/bin-b"
    REGEN_BIN_DIR="$BIN_B" ./regen.sh "${TOKIO_ARGS[@]}" "${PROGRAMS[@]}"
else
    BIN_B="$FIXTURES/bin"
    ./regen.sh "${PROGRAMS[@]}"
fi

# The capture tools themselves come from the workspace as-is, except
# that `snapshot` is not in a default hansei: it makes test data rather
# than answering anything about a target, so it is behind a feature.
(cd .. && cargo build -p exegesis && cargo build -p hansei --features snapshot)
EXEGESIS=../target/debug/exegesis
HANSEI=../target/debug/hansei

for p in "${PROGRAMS[@]}"; do
    "$EXEGESIS" extract "$BIN_B/$p" -o "$OUT/$p.bundle"

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
    # A Linux core carries no symbol table, so the executable that ran
    # has to be named alongside it — build A, not the debug build behind
    # --bundle, which shares none of its addresses. An illumos core
    # carries its own and warns if one is passed. The core is taken
    # right here, so which kind it is is this host's.
    program=()
    if [[ "$(uname -s)" == Linux ]]; then
        program=(--program "$FIXTURES/bin-a/$p")
    fi
    # hansei takes its commands on stdin, not as arguments.
    echo "snapshot $OUT/$p.snapshot" |
        "$HANSEI" --core "$coredir/core.$pid" --bundle "$OUT/$p.bundle" "${program[@]}"

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
DEFAULT_OUT="$(cd "../hansei-runtime/tests/fixtures/$SET" 2>/dev/null && pwd || true)"
if [[ "$OUT" == "$DEFAULT_OUT" ]]; then
    (cd .. && INSTA_UPDATE=always \
        cargo test -q -p hansei-runtime --test two_binary fixtures_record >/dev/null)
    echo "capture-snapshots.sh: recorded the fixture sources in $OUT/SOURCES.snap"
else
    echo "capture-snapshots.sh: $OUT is not the checked-in $SET fixture dir;" \
         "SOURCES not written" >&2
fi

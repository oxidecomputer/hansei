#!/usr/bin/env bash
#
# The churn capture loop: for each seed, emit a churn-mode program with
# genfix (`--churn`: every future completes shortly and is rebuilt,
# nothing registers), build the same two-binary pair the parked soak
# builds, run it, and capture snapshots at arbitrary instants — no
# readiness handshake; the random delay before each core *is* the
# point. Each capture is judged by the safety oracle alone
# (hansei-runtime/tests/churn.rs): no panic, no hang, the census's
# total audit clean. Exactness is unassertable mid-flight, so a clean
# contained failure of the capture-time pipeline — hansei's snapshot
# command reporting an error and exiting — is tolerated and counted as
# "declined", not a finding.
#
# A capture that panics, hangs, or fails the oracle is kept whole —
# source, core, binary, bundle, snapshot, log — under
# $OUT/failures/seed-<n>-snap-<m>/. The core is the whole replay: a
# snapshot is deterministic once taken, so there is no retry step here
# the way the parked soak has one.
#
# Needs a capture-capable host, same as soak.sh (the pinned toolchain,
# gcore, tracing permission). One program serves all of its seed's
# captures: gcore stops, dumps, and resumes the process, which keeps
# churning in between.
#
# Usage: churn.sh [--seeds N] [--start S] [--snaps M] [--out DIR]
#
# The summary ends with the outcome-coverage union across every capture
# that reached the oracle — which shapes the batch's arbitrary instants
# actually caught mid-flight.

set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

. "$ROOT/test-programs/genfix/lib.sh"

SEEDS=8
START=0
SNAPS=4
OUT="$ROOT/test-programs/genfix/churn-out"
parse_extra() { [[ "$1" == --snaps ]] && SNAPS="$2"; }
parse_args "$@"
mkdir -p "$OUT/failures"
PAIRS="$OUT/pairs"
mkdir -p "$PAIRS"

GEN_SRC="$ROOT/test-programs/src/bin/gen-churn.rs"
FIXTURES="$ROOT/test-programs/fixtures"
CHILD=""
cleanup() {
    [[ -n "$CHILD" ]] && kill "$CHILD" 2>/dev/null
    rm -f "$GEN_SRC"
}
trap cleanup EXIT

case "$(uname -s)" in
    Linux) BINARY_FLAG=1 ;;
    SunOS) BINARY_FLAG=0 ;;
    *) echo "churn.sh: $(uname -s) takes no ELF core to capture from" >&2; exit 1 ;;
esac

cargo build -q -p genfix
GENFIX="$ROOT/target/debug/genfix"
(cd "$ROOT" && cargo build -q -p hansei --features snapshot)
HANSEI="$ROOT/target/debug/hansei"
# Compile the oracle before the loop so its first run is not charged to
# the first capture's timeout.
(cd "$ROOT" && cargo test -q -p hansei-runtime --test churn --no-run >/dev/null 2>&1)

# Keep a failing capture's whole story for triage far from this host.
keep_failure() {
    local seed="$1" snap="$2" core="$3" log="$4"
    local keep="$OUT/failures/seed-$seed-snap-$snap"
    mkdir -p "$keep"
    cp -f "$GEN_SRC" "$keep/gen-churn.rs"
    cp -f "$FIXTURES/bin-a/gen-churn" "$keep/gen-churn.bin" 2>/dev/null
    cp -f "$PAIRS/gen-churn.tinfo" "$keep/" 2>/dev/null
    cp -f "$PAIRS/gen-churn.snapshot" "$keep/" 2>/dev/null
    [[ -f "$core" ]] && cp -f "$core" "$keep/core"
    cp -f "$log" "$keep/log"
    echo "churn.sh: seed $seed snap $snap FAILED; kept under $keep"
}

captures=0
declined=0
reached=0
failures=()
for (( seed = START; seed < START + SEEDS; seed++ )); do
    "$GENFIX" --seed "$seed" --churn > "$GEN_SRC"
    seedlog="$OUT/seed-$seed.log"
    : > "$seedlog"
    if ! { REGEN_BIN_DIR="$FIXTURES/bin-a" REGEN_TARGET_DIR="$FIXTURES/target-a" \
               "$ROOT/test-programs/regen.sh" --no-debug-info gen-churn &&
           "$ROOT/test-programs/regen.sh" gen-churn &&
           "$HANSEI" tokio-info extract "$FIXTURES/bin/gen-churn" -o "$PAIRS/gen-churn.tinfo";
         } >>"$seedlog" 2>&1; then
        echo "churn.sh: seed $seed: build failed (see $seedlog)"
        failures+=("$seed-build")
        continue
    fi

    fifo="$(mktemp -u)"
    mkfifo "$fifo"
    coredir="$(mktemp -d)"
    "$FIXTURES/bin-a/gen-churn" >"$fifo" 2>&1 &
    CHILD=$!
    # Liveness only — the program churns from the moment it says so;
    # there is no quiescent state to wait for.
    while IFS= read -r line; do
        [[ "$line" == "CHURNING" ]] && break
    done <"$fifo"
    cat "$fifo" >/dev/null &

    for (( snap = 0; snap < SNAPS; snap++ )); do
        sleep "$(printf '0.%03d' $(( RANDOM % 900 + 50 )))"
        rm -f "$coredir"/core.*
        if ! gcore -o "$coredir/core" "$CHILD" >>"$seedlog" 2>&1; then
            echo "churn.sh: seed $seed snap $snap: gcore failed" | tee -a "$seedlog"
            failures+=("$seed-$snap-gcore")
            continue
        fi
        core="$coredir/core.$CHILD"
        captures=$(( captures + 1 ))

        binary=()
        [[ "$BINARY_FLAG" == 1 ]] && binary=(--binary "$FIXTURES/bin-a/gen-churn")
        snaplog="$OUT/snap.log"
        echo "snapshot $PAIRS/gen-churn.snapshot" |
            timeout 300 "$HANSEI" --core "$core" --tokio-info "$PAIRS/gen-churn.tinfo" \
                "${binary[@]}" >"$snaplog" 2>&1
        status=$?
        cat "$snaplog" >>"$seedlog"
        if [[ $status -eq 124 ]]; then
            echo "churn.sh: seed $seed snap $snap: capture HUNG" | tee -a "$seedlog"
            keep_failure "$seed" "$snap" "$core" "$seedlog"
            failures+=("$seed-$snap-hang")
            continue
        elif grep -q 'panicked at' "$snaplog"; then
            echo "churn.sh: seed $seed snap $snap: capture PANICKED" | tee -a "$seedlog"
            keep_failure "$seed" "$snap" "$core" "$seedlog"
            failures+=("$seed-$snap-panic")
            continue
        elif [[ $status -ne 0 ]]; then
            # A contained refusal — mid-flight state the pipeline
            # declined cleanly. Tolerated; counted so a batch that
            # only ever declines is visible below.
            declined=$(( declined + 1 ))
            echo "churn.sh: seed $seed snap $snap: capture declined (contained)" >>"$seedlog"
            continue
        fi

        oraclelog="$OUT/oracle.log"
        HANSEI_CHURN_PAIR="$PAIRS/gen-churn" \
            timeout 600 cargo test -q -p hansei-runtime --test churn -- --nocapture \
            >"$oraclelog" 2>&1
        ostatus=$?
        cat "$oraclelog" >>"$seedlog"
        if [[ $ostatus -eq 0 ]]; then
            reached=$(( reached + 1 ))
            note_outcomes "$oraclelog"
        else
            echo "churn.sh: seed $seed snap $snap: oracle FAILED" | tee -a "$seedlog"
            keep_failure "$seed" "$snap" "$core" "$seedlog"
            failures+=("$seed-$snap-oracle")
        fi
    done

    kill "$CHILD" 2>/dev/null
    wait "$CHILD" 2>/dev/null
    CHILD=""
    rm -rf "$coredir"
    rm -f "$fifo"
    echo "churn.sh: seed $seed done"
done

echo
echo "churn.sh: $captures captures over seeds $START..$(( START + SEEDS - 1 )):" \
     "$reached passed the oracle, $declined declined, ${#failures[@]} failures"
if [[ ${#failures[@]} -gt 0 ]]; then
    echo "churn.sh: failures: ${failures[*]}"
fi
if [[ $reached -eq 0 ]]; then
    echo "churn.sh: NO capture reached the oracle — the loop is not testing the census"
fi
print_coverage
assert_coverage "$reached" || exit 1
[[ ${#failures[@]} -eq 0 && $reached -gt 0 ]]

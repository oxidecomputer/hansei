#!/usr/bin/env bash
#
# The generated-fixture soak loop: for each seed, emit a program with
# genfix, capture a real snapshot pair from it (capture-snapshots.sh —
# the same two-binary capture the checked-in fixtures get), and hold
# the census to the program's own registry (the opt-in oracle in
# hansei-runtime/tests/genfix.rs). A seed that fails is recaptured and
# rechecked once, so a capture racing a body's first poll does not
# read as a census bug; a seed that fails twice is recorded whole —
# source, pair, log — under $OUT/failures/seed-<n>/ for triage, and a
# deterministically failing seed's source becomes a quarantined
# checked-in fixture.
#
# Needs a capture-capable host (Linux or illumos: the pinned toolchain,
# gcore, and tracing permission — everything capture-snapshots.sh
# already needs). The per-seed cost is dominated by the two fixture
# builds, which are incremental against persistent target dirs, so a
# soak's first seed is slow and the rest are not.
#
# Usage: soak.sh [--seeds N] [--start S] [--out DIR]
#
# The summary ends with the outcome-coverage union across the batch —
# the generated corpus's version of the checked-in corpus's
# "sometimes" list — so a generator change that quietly stops
# exercising a shape shows up as a zero there.

set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

. "$ROOT/test-programs/genfix/lib.sh"

SEEDS=32
START=0
OUT="$ROOT/test-programs/genfix/out"
parse_args "$@"
mkdir -p "$OUT/failures"
PAIRS="$OUT/pairs"
mkdir -p "$PAIRS"

GEN_SRC="$ROOT/test-programs/src/bin/gen-soak.rs"
trap 'rm -f "$GEN_SRC"' EXIT

cargo build -q -p genfix
GENFIX="$ROOT/target/debug/genfix"

# One check per seed: capture, then the oracle. Everything lands in
# the seed's log; the caller decides what a failure means.
run_seed() {
    local seed="$1" log="$2"
    "$GENFIX" --seed "$seed" > "$GEN_SRC"
    if ! "$ROOT/test-programs/capture-snapshots.sh" "$PAIRS" gen-soak \
            >>"$log" 2>&1; then
        echo "soak.sh: seed $seed: capture failed" >>"$log"
        return 1
    fi
    HANSEI_GENFIX_PAIR="$PAIRS/gen-soak" \
        cargo test -q -p hansei-runtime --test genfix -- --nocapture \
        >>"$log" 2>&1
}

passed=0
failed=()
for (( seed = START; seed < START + SEEDS; seed++ )); do
    log="$OUT/seed-$seed.log"
    : > "$log"
    if run_seed "$seed" "$log"; then
        passed=$(( passed + 1 ))
        note_outcomes "$log"
        rm -f "$log"
        echo "soak.sh: seed $seed ok"
        continue
    fi
    # Once more from the top: a capture racing a body's first poll is
    # the capture's problem, and a recapture settles which this is.
    echo "soak.sh: seed $seed: retrying after a failure" | tee -a "$log"
    if run_seed "$seed" "$log"; then
        passed=$(( passed + 1 ))
        note_outcomes "$log"
        echo "soak.sh: seed $seed ok on retry (transient; log kept)"
        continue
    fi
    failed+=("$seed")
    keep="$OUT/failures/seed-$seed"
    mkdir -p "$keep"
    cp -f "$GEN_SRC" "$keep/gen-soak.rs"
    cp -f "$PAIRS/gen-soak.tinfo" "$PAIRS/gen-soak.snapshot" "$keep/" 2>/dev/null
    mv -f "$log" "$keep/log"
    note_outcomes "$keep/log"
    echo "soak.sh: seed $seed FAILED; kept under $keep"
done

echo
echo "soak.sh: $passed/$SEEDS passed (seeds $START..$(( START + SEEDS - 1 )))"
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "soak.sh: failing seeds: ${failed[*]}"
fi
print_coverage
# Every passed seed ran the oracle, so a batch with passes and no
# parsed outcomes is coverage decay, not an empty batch.
assert_coverage "$passed" || exit 1
[[ ${#failed[@]} -eq 0 ]]

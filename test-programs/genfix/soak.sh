#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# The generated-fixture soak loop: for each seed, emit a program with
# genfix and hold a fresh core of it to the program's own registry
# (the opt-in oracle in hansei-runtime/tests/genfix.rs, which takes
# the core itself — the same two-binary capture every fixture gets —
# into $OUT/capture). A seed that fails is recaptured and rechecked
# once, so a capture racing a body's first poll does not read as a
# census bug; a seed that fails twice is recorded whole — source,
# core, build A, build B, log — under $OUT/failures/seed-<n>/ for
# triage, and a deterministically failing seed's source becomes a
# quarantined checked-in fixture.
#
# Needs a capture-capable host (Linux or illumos: the pinned toolchain,
# gcore, and tracing permission). The per-seed cost is dominated by
# the two fixture builds, which are incremental against persistent
# target dirs, so a soak's first seed is slow and the rest are not.
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
CAPTURE="$OUT/capture"
mkdir -p "$CAPTURE"

GEN_SRC="$ROOT/test-programs/src/bin/gen-soak.rs"
trap 'rm -f "$GEN_SRC"' EXIT

cargo build -q -p genfix
GENFIX="$ROOT/target/debug/genfix"

# One check per seed: the oracle captures and judges. Everything lands
# in the seed's log; the caller decides what a failure means.
run_seed() {
    local seed="$1" log="$2"
    "$GENFIX" --seed "$seed" > "$GEN_SRC"
    HANSEI_GENFIX_CAPTURE="$CAPTURE" \
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
    # The capture as the oracle laid it out: the core, build A beside
    # it, build B under debug/ (the set directory is this system's).
    for taken in "$CAPTURE"/*/gen-soak; do
        cp -f "$taken/core" "$keep/core" 2>/dev/null
        cp -f "$taken/gen-soak" "$keep/gen-soak.bin" 2>/dev/null
        cp -f "$taken/debug/gen-soak" "$keep/gen-soak.debug" 2>/dev/null
    done
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

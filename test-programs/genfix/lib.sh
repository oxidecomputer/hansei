# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Shared reporting for the capture loops (soak.sh, churn.sh): the
# common argument loop, the outcome-coverage tally and its parser, and
# the coverage decay guard. Sourced, not executed.
#
# The lines note_outcomes parses are printed by testkit's
# print_outcomes as `outcome: <name> = <bool>`, one per outcome. The
# format is an interface between that printer and this parser, so it
# changes only with both — and the decay guard below is what makes
# drifting apart loud instead of a summary of zeros.

SCRIPT="$(basename "$0")"

# The flags every loop takes. A script with flags of its own overrides
# parse_extra after sourcing; it is handed "$flag" "$value" and answers
# nonzero for a flag it does not know.
parse_extra() { return 1; }
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --seeds) SEEDS="$2"; shift 2 ;;
            --start) START="$2"; shift 2 ;;
            --out) OUT="$2"; shift 2 ;;
            *)
                if ! parse_extra "$1" "${2-}"; then
                    echo "$SCRIPT: unknown argument $1" >&2
                    exit 2
                fi
                shift 2 ;;
        esac
    done
}

# Per-outcome hit counts across the batch, fed one oracle log at a
# time by note_outcomes. Every outcome line names its outcome even
# when unhit, so any parsed run makes the tally non-empty.
declare -A HITS=()
note_outcomes() {
    local log="$1"
    while IFS= read -r line; do
        local name="${line#outcome: }"
        local hit="${name##* = }"
        name="${name% = *}"
        [[ -v HITS[$name] ]] || HITS[$name]=0
        [[ "$hit" == true ]] && HITS[$name]=$(( HITS[$name] + 1 ))
    done < <(grep '^outcome: ' "$log" || true)
}

print_coverage() {
    echo "$SCRIPT: outcome coverage across the batch:"
    for name in "${!HITS[@]}"; do
        printf '  %3d  %s\n' "${HITS[$name]}" "$name"
    done | sort -rn
}

# The decay guard: runs reached the oracle, yet not one outcome line
# parsed. That is the signature of the printer and the parser drifting
# apart (or an outcome list stubbed to nothing) — every summary from
# then on would print no counts without failing anything, so fail the
# batch instead.
assert_coverage() {
    local reached="$1"
    if [[ "$reached" -gt 0 && ${#HITS[@]} -eq 0 ]]; then
        echo "$SCRIPT: $reached runs reached the oracle but no outcome line" \
             "parsed — the printer and parser have drifted; failing the batch"
        return 1
    fi
    return 0
}

#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Hold another project's dependencies and toolchain to what hansei was
# reviewed against and what its fixtures build, and open an issue for
# each finding no issue has named yet.
#
#   review-drift.sh OWNER/REPO
#
# Reads the project's Cargo.lock and rust-toolchain.toml at the head of
# its default branch and runs review-drift over them, which finds:
# a release outside a review, which extraction binds nothing of and
# refuses unless allowed; a toolchain test-programs/matrix.toml does
# not build, which no golden has seen; a tokio or rustc minor newer
# than the matrix's primary pin, which the fresh-core suites run and
# which advances by hand; and a reviewed crate locked newer than the
# fixtures lock it, which the fixtures therefore do not exercise.
#
# One issue per finding, titled by the release it names, so a release
# is reported once however many weeks it stays, and a newer one gets
# an issue of its own. A primary pin is named by its minor, the
# granularity it advances at. The two lags, primary and fixture, close
# themselves once a run no longer finds them. REVIEW_DRIFT names the
# binary (default: the debug build); DRY_RUN=1 prints what it would
# open and close instead.

set -euo pipefail

project=${1:?usage: review-drift.sh OWNER/REPO}
repo=${GITHUB_REPOSITORY:-oxidecomputer/hansei}
root=$(git rev-parse --show-toplevel)
review_drift=${REVIEW_DRIFT:-$root/target/debug/review-drift}
label=review-drift
dry_run=${DRY_RUN:-0}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

sha=$(gh api "repos/$project/commits/HEAD" --jq .sha)
for file in Cargo.lock rust-toolchain.toml; do
    gh api -H "Accept: application/vnd.github.raw" \
        "repos/$project/contents/$file?ref=$sha" >"$work/$file"
done

# Exit 1 says there were findings, 2 that the check itself failed.
status=0
"$review_drift" --json \
    --lockfile "$work/Cargo.lock" \
    --toolchain "$work/rust-toolchain.toml" >"$work/drift.json" || status=$?
if [ "$status" -gt 1 ]; then
    echo "review-drift.sh: review-drift exited $status" >&2
    exit "$status"
fi

# Every title ever opened under the label, open or closed: a closed one
# was dealt with, and reopening it weekly would only nag. A dry run
# reads the lists too, so what it prints is what a run would do.
if [ "$dry_run" != 1 ]; then
    gh label create "$label" --repo "$repo" --force --color FBCA04 \
        --description "A library hansei parses has a new version" >/dev/null
fi
gh issue list --repo "$repo" --label "$label" --state all --limit 1000 \
    --json title --jq '.[].title' >"$work/titles"
gh issue list --repo "$repo" --label "$label" --state open --limit 1000 \
    --json number,title --jq '.[] | "\(.number)\t\(.title)"' >"$work/open"

blob="https://github.com/$project/blob/$sha"
at="\`$project\` at [\`${sha:0:12}\`]($blob)"
report() {
    local title=$1 body=$2
    if grep -qxF "$title" "$work/titles"; then
        echo "already reported: $title"
    elif [ "$dry_run" = 1 ]; then
        printf 'would open: %s\n\n%s\n\n' "$title" "$body"
    else
        gh issue create --repo "$repo" --label "$label" --title "$title" --body "$body" </dev/null
    fi
}

# The lags' titles. A lag's issue closes once no run finds it, so these
# are also what an open issue is recognized by.
primary_title() {
    case $1 in
        tokio) echo "Version Drift: $project uses tokio $2, newer than the matrix's primary tokio" ;;
        rustc) echo "Version Drift: $project builds with rustc $2, newer than the matrix's primary toolchain" ;;
    esac
}
fixture_title() {
    echo "Version Drift: $project uses $1 $2, newer than the fixtures build"
}

# One finding a line, its fields split by the unit separator: a tab
# would do, but `read` folds a run of tabs into one, so an empty field
# would shift every field after it.
fields='[.kind, .subject, .found, .summary // "", .minor // "", .pin // "", .fixture // ""] | join("\u001f")'
jq -r ".findings[] | $fields" "$work/drift.json" >"$work/findings"
: >"$work/lags"
while IFS=$'\x1f' read -r kind subject found summary minor pin fixture; do
    case $kind in
        unreviewed)
            report "Version Drift: $project uses $subject $found, which is unreviewed." \
"$at ([\`Cargo.lock\`]($blob/Cargo.lock), [\`rust-toolchain.toml\`]($blob/rust-toolchain.toml)):

    $summary

Review the release for any changes in internal structure and semantics."
            ;;
        unmatrixed)
            report "Version Drift: $project builds with rustc $found, which is not currently in the test matrix" \
"$at pins rustc \`$found\` in
[\`rust-toolchain.toml\`]($blob/rust-toolchain.toml).
Onboard it with \`test-programs/matrix.sh add rust-$found\` (the
\`onboard-tokio-release\` skill)."
            ;;
        primary)
            case $subject in
                tokio) where="locks tokio \`$found\` in [\`Cargo.lock\`]($blob/Cargo.lock)" ;;
                rustc) where="pins rustc \`$found\` in [\`rust-toolchain.toml\`]($blob/rust-toolchain.toml)" ;;
            esac
            title=$(primary_title "$subject" "$minor")
            echo "$title" >>"$work/lags"
            report "$title" \
"$at $where, a newer minor
than the matrix's primary $subject pin, \`$pin\` (\`test-programs/matrix.toml\`).
The primary is what the fresh-core suites and the extraction goldens run,
so it follows the newest $subject the project runs: advance it by hand (see
\`test-programs/matrix.sh\`'s header), onboarding the release first if
the matrix does not list it. The floor, which tracks the oldest deployed
release, does not move with it.

This issue closes itself once the primary reaches $subject $minor."
            ;;
        fixture)
            title=$(fixture_title "$subject" "$found")
            echo "$title" >>"$work/lags"
            report "$title" \
"$at locks $subject \`$found\` in [\`Cargo.lock\`]($blob/Cargo.lock),
a reviewed release newer than the \`$fixture\` test-programs locks, so
no fixture exercises what the project runs. Move the fixtures to it:
raise an exact \`=\` requirement in \`test-programs/Cargo.toml\` first,
then \`cargo update -p $subject --precise $found\` for \`Cargo.lock\`
and each \`locks/tokio-*.lock\`, and re-bless the goldens it shifts.

This issue closes itself once the fixtures lock $subject $found."
            ;;
        *)
            echo "review-drift.sh: unknown finding kind '$kind'" >&2
            exit 2
            ;;
    esac
done <"$work/findings"

# An open lag this run did not find has been caught up with, or the
# project has moved on to a release a newer issue names.
while IFS=$'\t' read -r number title; do
    case $title in
        "Version Drift: $project uses tokio "*", newer than the matrix's primary tokio") ;;
        "Version Drift: $project builds with rustc "*", newer than the matrix's primary toolchain") ;;
        "Version Drift: $project uses "*", newer than the fixtures build") ;;
        *) continue ;;
    esac
    grep -qxF "$title" "$work/lags" && continue
    if [ "$dry_run" = 1 ]; then
        echo "would close #$number: $title"
    else
        gh issue close "$number" --repo "$repo" \
            --comment "No longer found at $at." </dev/null
    fi
done <"$work/open"

#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Hold another project's dependencies and toolchain to what hansei was
# reviewed against, and open an issue for each one outside that no
# issue has named yet.
#
#   review-drift.sh OWNER/REPO
#
# Reads the project's Cargo.lock and rust-toolchain.toml at the head of
# its default branch and runs `hansei tokio-info reviewed` over them:
# a release outside a review is one extraction binds nothing of, and
# refuses unless allowed. It adds one finding of its own, a toolchain
# test-programs/matrix.toml does not build, which no golden has seen.
#
# One issue per finding, titled by the release it names, so a release
# is reported once however many weeks it stays, and a newer one gets
# an issue of its own. HANSEI names the binary (default: the debug
# build); DRY_RUN=1 prints the issues instead of opening them.

set -euo pipefail

project=${1:?usage: review-drift.sh OWNER/REPO}
repo=${GITHUB_REPOSITORY:-oxidecomputer/hansei}
root=$(git rev-parse --show-toplevel)
hansei=${HANSEI:-$root/target/debug/hansei}
label=review-drift
dry_run=${DRY_RUN:-0}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

sha=$(gh api "repos/$project/commits/HEAD" --jq .sha)
for file in Cargo.lock rust-toolchain.toml; do
    gh api -H "Accept: application/vnd.github.raw" \
        "repos/$project/contents/$file?ref=$sha" >"$work/$file"
done

# One finding per line; exit 1 says there were some, anything else
# that the check itself failed.
status=0
"$hansei" tokio-info reviewed \
    --lockfile "$work/Cargo.lock" \
    --toolchain "$work/rust-toolchain.toml" >"$work/outside" || status=$?
if [ "$status" -gt 1 ]; then
    echo "review-drift.sh: hansei exited $status" >&2
    exit "$status"
fi

channel=$(python3 -c '
import sys, tomllib
print(tomllib.load(open(sys.argv[1], "rb"))["toolchain"]["channel"])
' "$work/rust-toolchain.toml")
matrix_has() {
    python3 -c '
import sys, tomllib
sys.exit(sys.argv[2] not in tomllib.load(open(sys.argv[1], "rb"))["toolchain"]["versions"])
' "$root/test-programs/matrix.toml" "$1"
}

# Every title ever opened under the label, open or closed: a closed one
# was dealt with, and reopening it weekly would only nag.
if [ "$dry_run" = 1 ]; then
    : >"$work/titles"
else
    gh label create "$label" --repo "$repo" --force --color FBCA04 \
        --description "A library hansei parses has a new version" >/dev/null
    gh issue list --repo "$repo" --label "$label" --state all --limit 1000 \
        --json title --jq '.[].title' >"$work/titles"
fi

blob="https://github.com/$project/blob/$sha"
report() {
    local title=$1 body=$2
    if grep -qxF "$title" "$work/titles"; then
        echo "already reported: $title"
    elif [ "$dry_run" = 1 ]; then
        printf 'would open: %s\n\n%s\n\n' "$title" "$body"
    else
        gh issue create --repo "$repo" --label "$label" --title "$title" --body "$body"
    fi
}

while IFS= read -r line; do
    [ -n "$line" ] || continue
    found=${line%%:*}
    report "Version Drift: $project uses $found, which is unreviewed." \
"\`$project\` at [\`${sha:0:12}\`]($blob) ([\`Cargo.lock\`]($blob/Cargo.lock), [\`rust-toolchain.toml\`]($blob/rust-toolchain.toml)):

    $line

Review the release for any changes in internal structure and semantics."
done <"$work/outside"

if ! matrix_has "$channel"; then
    report "Version Drift: $project builds with rustc $channel, which is not currently in the test matrix" \
"\`$project\` at [\`${sha:0:12}\`]($blob) pins rustc \`$channel\` in
[\`rust-toolchain.toml\`]($blob/rust-toolchain.toml).
Onboard it with \`test-programs/matrix.sh add rust-$channel\` (the
\`onboard-tokio-release\` skill)."
fi

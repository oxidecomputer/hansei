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
# refuses unless allowed. It adds findings of its own: a toolchain
# test-programs/matrix.toml does not build, which no golden has seen,
# and a tokio or rustc minor newer than the matrix's primary pin, which
# the fresh-core suites run and which advances by hand.
#
# One issue per finding, titled by the release it names, so a release
# is reported once however many weeks it stays, and a newer one gets
# an issue of its own. A primary pin is named by its minor, the
# granularity it advances at, and its issue closes itself once the
# primary reaches that minor. HANSEI names the binary (default: the
# debug build); DRY_RUN=1 prints what it would open and close instead.

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

# The project's newest tokio and its toolchain beside the primary pins,
# one `KIND THEIRS OURS THEIRS_MINOR OURS_MINOR` line each; THEIRS is
# `-` where there is nothing to compare: no tokio, or a channel such as
# `stable` that names no release. Only the minors are compared. A newer
# patch of the primary's own minor is no lag: the primary is the newest
# reviewed patch of its minor, so the findings above already name it.
python3 -c '
import sys, tomllib
matrix, lock, channel = sys.argv[1:]
primary = tomllib.load(open(matrix, "rb"))["primary"]
def release(version):
    parts = version.split("-")[0].split(".")
    try:
        return tuple(int(p) for p in parts) if len(parts) >= 2 else None
    except ValueError:
        return None
def name(r, n=None):
    return ".".join(map(str, r[:n])) if r else "-"
packages = tomllib.load(open(lock, "rb")).get("package", [])
tokio = max(
    (r for r in (release(p["version"]) for p in packages if p["name"] == "tokio") if r),
    default=None,
)
for kind, theirs, ours in (
    ("tokio", tokio, release(primary["tokio"])),
    ("rustc", release(channel), release(primary["toolchain"])),
):
    print(kind, name(theirs), name(ours), name(theirs, 2), name(ours, 2))
' "$root/test-programs/matrix.toml" "$work/Cargo.lock" "$channel" >"$work/minors"

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

# The primary pins: one issue per minor of the project's newer than the
# primary's, and a close for each open one the primary has reached.
lag_title() {
    case $1 in
        tokio) echo "Version Drift: $project uses tokio $2, newer than the matrix's primary tokio" ;;
        rustc) echo "Version Drift: $project builds with rustc $2, newer than the matrix's primary toolchain" ;;
    esac
}
# Whether release $1 is newer than $2.
newer() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}
while read -r kind theirs ours theirs_minor ours_minor; do
    if [ "$theirs" != - ] && newer "$theirs_minor" "$ours_minor"; then
        case $kind in
            tokio) where="locks tokio \`$theirs\` in [\`Cargo.lock\`]($blob/Cargo.lock)" ;;
            rustc) where="pins rustc \`$theirs\` in [\`rust-toolchain.toml\`]($blob/rust-toolchain.toml)" ;;
        esac
        report "$(lag_title "$kind" "$theirs_minor")" \
"\`$project\` at [\`${sha:0:12}\`]($blob) $where, a newer minor
than the matrix's primary $kind pin, \`$ours\` (\`test-programs/matrix.toml\`).
The primary is what the fresh-core suites and the extraction goldens run,
so it follows the newest $kind the project runs: advance it by hand (see
\`test-programs/matrix.sh\`'s header), onboarding the release first if
the matrix does not list it. The floor, which tracks the oldest deployed
release, does not move with it.

This issue closes itself once the primary reaches $kind $theirs_minor."
    fi
    # Other findings' titles can begin the same way, so a title is this
    # kind's only if the minor it names rebuilds it exactly.
    prefix=$(lag_title "$kind" @)
    prefix=${prefix%%@*}
    while IFS=$'\t' read -r number title; do
        case $title in "$prefix"*) ;; *) continue ;; esac
        reached=${title#"$prefix"}
        reached=${reached%%,*}
        [ "$title" = "$(lag_title "$kind" "$reached")" ] || continue
        newer "$reached" "$ours_minor" && continue
        if [ "$dry_run" = 1 ]; then
            echo "would close #$number: $title"
        else
            gh issue close "$number" --repo "$repo" \
                --comment "The matrix's primary $kind pin is now \`$ours\`." </dev/null
        fi
    done <"$work/open"
done <"$work/minors"

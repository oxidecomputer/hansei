#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Wait for buildomat's helios job on a commit to finish, then unpack
# the illumos fixture set it published into a directory.
#
#   wait-helios.sh SHA DIR
#
# The job is not an Actions job, so nothing here can `needs:` it: this
# polls its check run instead, for as long as buildomat takes to queue
# and run it, up to a ceiling that only a hang should reach. A failed
# helios job fails this at once, naming it, so a red macOS check says
# which side broke. A queue that is merely slow delays the check
# without failing it.
#
# Environment:
#   GH_TOKEN             a token that can read the repository's checks
#   GITHUB_REPOSITORY    owner/repo (default: oxidecomputer/hansei)
#   HELIOS_WAIT_MINUTES  the ceiling (default: 90)

set -euo pipefail

die() { printf 'wait-helios.sh: %s\n' "$*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: wait-helios.sh SHA DIR"
sha=$1
dest=$2
repo=${GITHUB_REPOSITORY:-oxidecomputer/hansei}
check=helios
deadline=$(( $(date +%s) + ${HELIOS_WAIT_MINUTES:-90} * 60 ))
url=https://buildomat.eng.oxide.computer/public/file/$repo/cores-illumos/$sha/cores-illumos.tar.zst

while :; do
    # A rerun adds a check run under the same name; the newest is the
    # one that counts.
    run=$(gh api "repos/$repo/commits/$sha/check-runs?check_name=$check" \
        --jq '.check_runs | max_by(.id) // empty | [.status, (.conclusion // "-"), .html_url] | @tsv')
    if [ -n "$run" ]; then
        IFS=$'\t' read -r status conclusion link <<<"$run"
        if [ "$status" = completed ]; then
            [ "$conclusion" = success ] \
                || die "the $check check on $sha concluded $conclusion, so it published no illumos cores: $link"
            break
        fi
        printf '%s: %s check %s\n' "$(date -u +%H:%M:%S)" "$check" "$status"
    else
        printf '%s: no %s check on %s yet\n' "$(date -u +%H:%M:%S)" "$check" "$sha"
    fi
    [ "$(date +%s)" -lt "$deadline" ] \
        || die "gave up on the $check check on $sha after ${HELIOS_WAIT_MINUTES:-90} minutes"
    sleep 60
done

# To a file first: a retry restarts the download, which it cannot do
# into a pipe. Every error is retried, a missing file included, since
# the check can complete a moment before its file is served.
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
curl -sSfL --retry 10 --retry-all-errors --retry-delay 15 -o "$archive" "$url" \
    || die "the $check check on $sha passed, but its illumos cores are not at $url"
mkdir -p "$dest"
zstd -dc "$archive" | tar -xf - -C "$dest"

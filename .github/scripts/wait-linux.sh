#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Wait for this workflow run's linux job to finish, then unpack the
# Linux fixture sets it archived (cores-linux) into a directory.
#
#   wait-linux.sh DIR
#
# The macOS job builds while the linux job runs, so it cannot `needs:`
# it: this polls the job instead, as wait-helios.sh polls buildomat's.
# The linux job archives whatever it captured whether or not its own
# suite passed, so a red linux job still has cores to read; one that
# finished with none — cancelled, or never given a runner — fails this
# at once, naming it.
#
# Environment:
#   GH_TOKEN             a token that can read the run's jobs and
#                        artifacts
#   GITHUB_REPOSITORY    owner/repo
#   GITHUB_RUN_ID        the run whose linux job to wait for
#   LINUX_WAIT_MINUTES   the ceiling (default: 150)

set -euo pipefail

die() { printf 'wait-linux.sh: %s\n' "$*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: wait-linux.sh DIR"
dest=$1
repo=${GITHUB_REPOSITORY:?}
run=${GITHUB_RUN_ID:?}
job=linux
deadline=$(( $(date +%s) + ${LINUX_WAIT_MINUTES:-150} * 60 ))

while :; do
    # The latest attempt of each job: a rerun of failed jobs reuses
    # the linux job's earlier result, and its artifact with it.
    state=$(gh api "repos/$repo/actions/runs/$run/jobs?filter=latest&per_page=100" \
        --jq ".jobs[] | select(.name == \"$job\") | [.status, (.conclusion // \"-\"), .html_url] | @tsv")
    if [ -n "$state" ]; then
        IFS=$'\t' read -r status conclusion link <<<"$state"
        [ "$status" = completed ] && break
        printf '%s: %s job %s\n' "$(date -u +%H:%M:%S)" "$job" "$status"
    else
        printf '%s: no %s job in run %s yet\n' "$(date -u +%H:%M:%S)" "$job" "$run"
    fi
    [ "$(date +%s)" -lt "$deadline" ] \
        || die "gave up on the $job job after ${LINUX_WAIT_MINUTES:-150} minutes"
    sleep 30
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh run download "$run" --repo "$repo" -n cores-linux -D "$work" \
    || die "the $job job finished $conclusion without archiving any cores: $link"
mkdir -p "$dest"
zstd -dc "$work/cores-linux.tar.zst" | tar -xf - -C "$dest"

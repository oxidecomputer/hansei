#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Run a command in the pinned Linux test image (.github/image/), with
# this checkout mounted. CI's Linux jobs and a Linux host's own runs
# both go through here, so the two run the same command in the same
# environment.
#
#   in-image.sh COMMAND [ARG]...
#   in-image.sh cargo nextest run --no-fail-fast
#
# The checkout is mounted at the path it has on the host, and so is
# HANSEI_CORES when it names a directory outside the checkout, so a
# path written into a core or a capture record reads the same inside
# and out. The host's target/container is mounted over target/, so
# cargo in the image builds there and cargo on the host and in the
# image never invalidate each other's builds. It is a mount rather
# than CARGO_TARGET_DIR because the variable would reach every cargo a
# test runs, and a test that builds a scratch crate reads that crate's
# own target/. HANSEI_IMAGE_SCRATCH moves both the build dirs — that
# one and test-programs/fixtures, where the fixture programs build —
# out of the checkout the same way, by mounting them from there; CI
# keeps them in one directory with its cores and toolchains.
#
# Toolchains and the crates cargo downloads persist across runs in
# host directories mounted over RUSTUP_HOME and CARGO_HOME's registry
# and git dirs; CI restores them from the Actions cache. They are bind
# mounts rather than named volumes because podman copies an image's
# content into an empty named volume on its first mount and never
# again, so a volume would go on serving the first image's files after
# a bump.
#
# The container runs as its own root, which rootless podman maps to the
# invoking user, so everything it writes belongs to that user.
# SYS_PTRACE lets gcore attach to a fixture that is its sibling rather
# than its child, with no host sysctl. The container is removed on
# exit, and with it whatever a killed test left in its /tmp. Its init
# is the image's own (tini, the entrypoint).
#
# Environment:
#   HANSEI_IMAGE        the image to run instead of the pinned one, for
#                       trying a Containerfile change before pinning it
#   HANSEI_IMAGE_CACHE  where toolchains and downloaded crates persist
#                       (default: ~/.cache/hansei-image)
#   HANSEI_IMAGE_SCRATCH
#                       where the build dirs live: <dir>/target and
#                       <dir>/fixtures (default: target/container and
#                       test-programs/fixtures in the checkout)
#   HANSEI_*, INSTA_*, NEXTEST_*, CI, GITHUB_ACTIONS, RUST_BACKTRACE,
#   CARGO_TERM_COLOR, CARGO_INCREMENTAL
#                       passed into the container when set

set -euo pipefail

die() { printf 'in-image.sh: %s\n' "$*" >&2; exit 2; }

[ $# -gt 0 ] || die "usage: in-image.sh COMMAND [ARG]..."

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

image=${HANSEI_IMAGE:-$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' \
    "$root/.github/image/pinned" | head -1)}
if [ -z "$image" ] || [ "$image" = unpinned ]; then
    die "no image is pinned in .github/image/pinned; set HANSEI_IMAGE" \
        "to try one (see .github/image/Containerfile)"
fi

cache=${HANSEI_IMAGE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/hansei-image}
mkdir -p "$cache/rustup" "$cache/registry" "$cache/git"
mounts=(
    -v "$root:$root"
    -v "$cache/rustup:/usr/local/rustup"
    -v "$cache/registry:/usr/local/cargo/registry"
    -v "$cache/git:/usr/local/cargo/git"
)
if [ -n "${HANSEI_IMAGE_SCRATCH:-}" ]; then
    mkdir -p "$HANSEI_IMAGE_SCRATCH/target" "$HANSEI_IMAGE_SCRATCH/fixtures" \
        "$root/target" "$root/test-programs/fixtures"
    mounts+=(
        -v "$HANSEI_IMAGE_SCRATCH/target:$root/target"
        -v "$HANSEI_IMAGE_SCRATCH/fixtures:$root/test-programs/fixtures"
    )
else
    mkdir -p "$root/target/container"
    mounts+=(-v "$root/target/container:$root/target")
fi

if [ -n "${HANSEI_CORES:-}" ]; then
    mkdir -p "$HANSEI_CORES"
    HANSEI_CORES=$(cd "$HANSEI_CORES" && pwd -P)
    export HANSEI_CORES
    case $HANSEI_CORES/ in
        "$root"/*) ;;
        *) mounts+=(-v "$HANSEI_CORES:$HANSEI_CORES") ;;
    esac
fi

# Run where we were run from, when that is inside the checkout.
workdir=$(pwd -P)
case $workdir/ in
    "$root"/*) ;;
    *) workdir=$root ;;
esac

tty=()
[ -t 0 ] && [ -t 1 ] && tty=(-it)

# A walk that loops allocating has to fail inside its own test, not
# take the machine with it. Every process gets 16 GiB of address space
# (podman's --ulimit has no address-space limit, so the shell that
# starts the command sets it), so a runaway's own allocation fails and
# the test with it; the container as a whole gets 48 GiB where the
# user's cgroup can be given a memory limit at all, which rootless
# podman needs delegated to it.
limits=()
if podman info --format '{{.Host.CgroupControllers}}' 2>/dev/null | grep -qw memory; then
    limits+=(--memory=48g)
fi

# label=disable: the checkout is mounted as it is, not relabelled for
# SELinux. --pids-limit: the suites run many fixtures at once, each with
# its worker threads, past podman's default of 2048.
exec podman run --rm "${tty[@]}" \
    --cap-add=SYS_PTRACE \
    --security-opt label=disable \
    --pids-limit=-1 \
    "${limits[@]}" \
    "${mounts[@]}" \
    -w "$workdir" \
    -e 'HANSEI_*' -e 'INSTA_*' -e 'NEXTEST_*' \
    -e CI -e GITHUB_ACTIONS -e RUST_BACKTRACE \
    -e CARGO_TERM_COLOR -e CARGO_INCREMENTAL \
    "$image" sh -c 'ulimit -v 16777216 && exec "$@"' sh "$@"

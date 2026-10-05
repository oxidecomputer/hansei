#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
#:
#: name = "helios"
#: variety = "basic"
#: target = "helios-3.0-16c64gb"
#: rust_toolchain = true
#: output_rules = [
#:	"/work/cores-illumos.tar.zst",
#:	"/work/failed/*",
#: ]
#:
#: [[publish]]
#: series = "cores-illumos"
#: name = "cores-illumos.tar.zst"
#: from_output = "/work/cores-illumos.tar.zst"
#
# The whole suite on illumos, acceptance included, capturing the
# illumos fixture set. The set is published for the macOS check that
# reads it (`macos (illumos cores)` in .github/workflows/ci.yml), which
# fetches it by commit once this job's check run has passed.
#
# Buildomat publishes the first file it is given for a commit and
# refuses every later one, even from a rerun, so the archive is built
# only once the suite has passed: a failed run publishes nothing, and
# its rerun can. What a failed run captured goes in plain outputs
# instead, which are per job and have no such rule.

set -o errexit
set -o pipefail
set -o xtrace

# Which Helios this is. The illumos goldens are blessed on a developer
# host, so a failure here that the host does not show starts with
# comparing the two.
uname -v

# bindgen, for libproc-sys, which the proc suites' libproc reference
# reader binds. 4 is pkg's "nothing to do".
rc=0
pfexec pkg install clang-15 || rc=$?
if (( rc != 0 && rc != 4 )); then
	exit "$rc"
fi
export LIBCLANG_PATH=/opt/ooce/llvm-15/lib

NEXTEST_VERSION=0.9.143
NEXTEST_SHA256=91e6d9fa6bd5c4f30ab8b8bdc3cd3a7e225d2f91b4a2c35a1164c9e5d972e9c9
curl -sSfL --retry 10 -o /tmp/nextest.tar.gz \
	"https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$NEXTEST_VERSION/cargo-nextest-$NEXTEST_VERSION-x86_64-unknown-illumos.tar.gz"
[[ $(digest -a sha256 /tmp/nextest.tar.gz) == "$NEXTEST_SHA256" ]]
gtar -xzf /tmp/nextest.tar.gz -C ~/.cargo/bin cargo-nextest

cargo --version
rustc --version
cargo nextest --version

export CARGO_INCREMENTAL=0
export RUST_BACKTRACE=1
export HANSEI_CORES=/var/tmp/hansei-cores
# The fixture work done before the suite counts as the suite's own only
# under one run name. Any name new to this machine will do, and every
# job here is a new machine.
HANSEI_RUN_ID=helios-$(date +%s)-$$
export HANSEI_RUN_ID
mkdir -p "$HANSEI_CORES" /work

# A build and a core per program, the dot-named bookkeeping left out:
# everything a system that cannot core needs to read the set.
archive_set() {
	gtar -C "$HANSEI_CORES" --exclude='.*' -cf - illumos | zstd -3 -T0 -q -o "$1"
}

banner build
# The suite's build builds the fixture example with it. `cargo run -p
# hansei-runtime --example` would resolve features for that one package
# and compile the workspace a second time.
ptime -m cargo nextest run --locked --no-run --cargo-profile ci

banner fixtures
# Outside the suite, so no test waits on it under the per-test limit
# (.config/nextest.toml) or holds a slot while it does.
ptime -m target/ci/examples/build_fixtures

banner test
status=0
ptime -m timeout 2h cargo nextest run --locked --no-fail-fast --profile ci --cargo-profile ci || status=$?

if (( status != 0 )); then
	mkdir -p /work/failed
	if [[ -d $HANSEI_CORES/illumos ]]; then
		archive_set /work/failed/cores-illumos.tar.zst || true
	fi
	exit "$status"
fi

banner archive
archive_set /work/cores-illumos.tar.zst
ls -l /work/cores-illumos.tar.zst

# Buildomat does not upload an output over its per-file cap (1 GiB by
# default), and the publish naming it then publishes nothing, silently.
# A red check here says so, where a missing file would only time out
# the macOS check waiting for it.
max=$((1024 * 1024 * 1024))
size=$(wc -c </work/cores-illumos.tar.zst)
if (( size > max )); then
	echo "the illumos set archive is $size bytes, over buildomat's $max" >&2
	rm /work/cores-illumos.tar.zst
	exit 1
fi

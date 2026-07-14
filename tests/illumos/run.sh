#!/usr/bin/env bash
#
# Run the hansei illumos integration suite (plan §11.4) on the illumos
# box: sync the working tree there and run
#
#   cargo test -p hansei --features illumos-integration -- --ignored
#
# The sync covers everything git knows about, local modifications
# included; `git add` (or commit) brand-new files first or they will not
# be seen remotely. Remote build state (target/, fixture builds) is left
# in place so runs stay incremental.
#
# Usage: tests/illumos/run.sh [extra test-harness args...]
#   ILLUMOS_HOST (default: illumos)     ssh destination
#   ILLUMOS_DIR  (default: /data/durin) remote checkout

set -euo pipefail

HOST="${ILLUMOS_HOST:-illumos}"
DIR="${ILLUMOS_DIR:-/data/durin}"

cd "$(dirname "$0")/../.."

# No -t: preserving source mtimes lets a restored-but-older file slip
# past cargo's mtime-based rebuild check and reuse a stale artifact.
# -c keeps unchanged files untouched instead; changed files land with a
# fresh mtime and rebuild exactly what the sync changed.
git ls-files --cached --exclude-standard |
    rsync -rlpzc --no-times --files-from=- . "$HOST:$DIR/"

REMOTE_CMD="cd $(printf %q "$DIR") && \
cargo test -p hansei --features illumos-integration -- --ignored"
for arg in "$@"; do
    REMOTE_CMD+=" $(printf %q "$arg")"
done

# A login shell for the toolchain environment (LIBCLANG_PATH et al.).
ssh "$HOST" "bash -lc $(printf %q "$REMOTE_CMD")"

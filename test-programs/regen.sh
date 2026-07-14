#!/usr/bin/env bash
#
# Build the test-program fixture binaries with the pinned
# "bundle-compatible" recipe (docs/v0-mangling-spike.md §5):
#
#   - pinned toolchain (v0 mangling, stable std internals)
#   - RUSTFLAGS="--cfg tokio_unstable" (oxide-tokio-rt; feeds -Cmetadata)
#   - release profile with full debug info for the whole graph
#   - the workspace Cargo.lock
#
# No binaries are checked in: tests that need a fixture run this script
# (or skip with a message when the toolchain is unavailable). Fixtures
# land in test-programs/fixtures/bin; on macOS a .dSYM is produced next
# to each binary and the extraction tests read the DWARF from there.
#
# Usage: regen.sh [PROGRAM]...   (default: all)

set -euo pipefail

TOOLCHAIN=1.97.0
ALL_PROGRAMS=(futurelock simple-await nested-await dyn-future select-combinator many-tasks)

cd "$(dirname "$0")"
FIXTURES="$PWD/fixtures"

if ! command -v rustup >/dev/null; then
    echo "regen.sh: rustup not found; cannot build pinned fixtures" >&2
    exit 2
fi
if ! rustup toolchain list | grep -q "^$TOOLCHAIN"; then
    echo "regen.sh: toolchain $TOOLCHAIN not installed" >&2
    echo "  run: rustup toolchain install $TOOLCHAIN" >&2
    exit 2
fi

PROGRAMS=("${@:-${ALL_PROGRAMS[@]}}")

# Overridable so capture-snapshots.sh can produce two *separate*
# compilations of the same sources (the two-binary constraint, §11.3).
BIN_DIR="${REGEN_BIN_DIR:-$FIXTURES/bin}"
TARGET_DIR="${REGEN_TARGET_DIR:-$FIXTURES/target}"

# Full debug info for every crate in the graph, not just test-programs:
# tokio's own CUs carry the statics (CONTEXT, WAKER_VTABLE) the extractor
# needs. A dedicated target dir keeps this profile from thrashing the
# regular build cache.
export RUSTFLAGS="--cfg tokio_unstable"
export CARGO_PROFILE_RELEASE_DEBUG=2
export CARGO_TARGET_DIR="$TARGET_DIR"

bins=()
for p in "${PROGRAMS[@]}"; do
    bins+=(--bin "$p")
done
cargo "+$TOOLCHAIN" build --release -p test-programs "${bins[@]}"

mkdir -p "$BIN_DIR"
for p in "${PROGRAMS[@]}"; do
    cp -f "$TARGET_DIR/release/$p" "$BIN_DIR/$p"
    if [[ "$(uname)" == "Darwin" ]]; then
        # Mach-O executables don't carry DWARF; link it into a dSYM.
        dsymutil "$BIN_DIR/$p" -o "$BIN_DIR/$p.dSYM"
    fi
    echo "regen.sh: built $BIN_DIR/$p"
done

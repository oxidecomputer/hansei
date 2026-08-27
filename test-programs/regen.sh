#!/usr/bin/env bash
#
# Build the test-program fixture binaries with the pinned
# "bundle-compatible" recipe:
#
#   - pinned toolchain (v0 mangling, stable std internals)
#   - RUSTFLAGS="--cfg tokio_unstable" (oxide-tokio-rt; feeds -Cmetadata)
#   - release profile with full debug info for the whole graph
#   - the crate's own checked-in Cargo.lock
#
# No binaries are checked in: tests that need a fixture run this script
# (or skip with a message when the toolchain is unavailable). Fixtures
# land in test-programs/fixtures/bin; on macOS a .dSYM is produced next
# to each binary and the extraction tests read the DWARF from there.
#
# Usage: regen.sh [OPTION]... [PROGRAM]...   (default: all programs)
#
#   --tokio VER      build against locks/tokio-VER.lock (or the crate's
#                    own Cargo.lock when that is what it resolves)
#   --toolchain VER  build with the named toolchain instead of the pin
#   --no-unstable    drop --cfg tokio_unstable and the oxide-tokio-rt
#                    runtime (--no-default-features --features full-tokio)
#   --ct-only        build tokio without rt-multi-thread (--features
#                    ct-tokio, no unstable cfg): the features-limited
#                    cell, whose goldens pin the "multi_thread rows
#                    absent" shape. Only ct-runtime builds without that
#                    scheduler, so it is the default program set.
#   --no-debug-info  build without debug info — the shape of a binary a
#                    production core comes from. A bundle can never be
#                    extracted from such a build; pair it with a full
#                    debug build of the same cell, which is what
#                    capture-snapshots.sh does for its core target.
#   --dwp            build with -C split-debuginfo=packed (via the cargo
#                    profile), producing a skeleton-DWARF binary and its
#                    .dwp package side by side under fixtures/bin/dwp.
#                    ELF hosts only — this is the Linux split shape; the
#                    dSYM covers the same ground on macOS.
#
# The tokio/toolchain/unstable axes come from matrix.toml. A build with
# any non-primary axis value is a matrix *cell*: it is compiled from a
# scratch copy of this crate under fixtures/cells/ (so it can carry its
# own lockfile without touching the checked-in one, and so concurrent
# primary builds see nothing), and its binaries land in a per-cell
# directory, fixtures/bin/rust-TOOLCHAIN-tokio-VER-{unstable,stable}.
# Cells sharing a (toolchain, unstable) pair share one target dir; the
# lockfile difference re-resolves only tokio and its dependents.

set -euo pipefail

PRIMARY_TOOLCHAIN=1.97.1
ALL_PROGRAMS=(futurelock simple-await nested-await dyn-future select-combinator many-tasks sleep-join channels park-target core-target unordered joinset ct-runtime local-set local-set-timer local-set-io foreign-runtime gen-0007 walk-shapes spin-poll stale-local)

cd "$(dirname "$0")"
FIXTURES="$PWD/fixtures"

TOOLCHAIN="$PRIMARY_TOOLCHAIN"
TOKIO=""
UNSTABLE=1
CT_ONLY=0
DEBUG_INFO=1
DWP=0
PROGRAMS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tokio) TOKIO="$2"; shift 2 ;;
        --toolchain) TOOLCHAIN="$2"; shift 2 ;;
        --no-unstable) UNSTABLE=0; shift ;;
        --ct-only) CT_ONLY=1; UNSTABLE=0; shift ;;
        --no-debug-info) DEBUG_INFO=0; shift ;;
        --dwp) DWP=1; shift ;;
        --*) echo "regen.sh: unknown option $1" >&2; exit 2 ;;
        *) PROGRAMS+=("$1"); shift ;;
    esac
done
if [[ ${#PROGRAMS[@]} -eq 0 ]]; then
    if [[ "$CT_ONLY" == 1 ]]; then
        PROGRAMS=(ct-runtime)
    else
        PROGRAMS=("${ALL_PROGRAMS[@]}")
    fi
fi

if ! command -v rustup >/dev/null; then
    echo "regen.sh: rustup not found; cannot build pinned fixtures" >&2
    exit 2
fi
if ! rustup toolchain list | grep -q "^$TOOLCHAIN"; then
    echo "regen.sh: toolchain $TOOLCHAIN not installed" >&2
    echo "  run: rustup toolchain install $TOOLCHAIN" >&2
    exit 2
fi

# The version the checked-in Cargo.lock resolves — the primary cell.
locked_tokio() {
    awk '/^name = "tokio"$/ { getline; gsub(/[^0-9.]/, "", $3); print $3 }' \
        Cargo.lock
}

# Decide whether this is the primary build or a matrix cell, and where
# its sources, lockfile, and binaries live.
CRATE_DIR="$PWD"
if [[ -n "$TOKIO" && "$TOKIO" != "$(locked_tokio)" ]]; then
    LOCK="locks/tokio-$TOKIO.lock"
    if [[ ! -f "$LOCK" ]]; then
        echo "regen.sh: no $LOCK; add the version to matrix.toml and" \
             "derive its lockfile from Cargo.lock with" \
             "\`cargo update -p tokio --precise $TOKIO\`" >&2
        exit 2
    fi
else
    LOCK="Cargo.lock"
    TOKIO="$(locked_tokio)"
fi

if [[ "$CT_ONLY" == 1 ]]; then
    CFG_SUFFIX=ctonly
elif [[ "$UNSTABLE" == 1 ]]; then
    CFG_SUFFIX=unstable
else
    CFG_SUFFIX=stable
fi
CELL="rust-$TOOLCHAIN-tokio-$TOKIO-$CFG_SUFFIX"

if [[ "$LOCK" == "Cargo.lock" && "$TOOLCHAIN" == "$PRIMARY_TOOLCHAIN" \
      && "$UNSTABLE" == 1 ]]; then
    # The primary build: in place, with the everyday dirs, exactly the
    # recipe the golden tests and the dev loop have always used.
    BIN_DIR="${REGEN_BIN_DIR:-$FIXTURES/bin}"
    TARGET_DIR="${REGEN_TARGET_DIR:-$FIXTURES/target}"
else
    # A matrix cell: compile from a scratch copy carrying the cell's
    # lockfile. One copy and one target dir per (toolchain, unstable)
    # pair — switching tokio versions inside a pair swaps only the
    # lockfile, so the pair's std/dep cache is shared.
    PAIR="rust-$TOOLCHAIN-$CFG_SUFFIX"
    CRATE_DIR="$FIXTURES/cells/$PAIR/crate"
    mkdir -p "$CRATE_DIR"
    rsync -a --delete Cargo.toml src "$CRATE_DIR/"
    cp -f "$LOCK" "$CRATE_DIR/Cargo.lock"
    BIN_DIR="${REGEN_BIN_DIR:-$FIXTURES/bin/$CELL}"
    TARGET_DIR="${REGEN_TARGET_DIR:-$FIXTURES/cells/$PAIR/target}"
fi

# The packed-split build is the primary recipe with the debug info
# split out, kept in its own bin and target dirs so it never writes a
# skeleton-DWARF binary over a fixture the goldens read whole.
if [[ "$DWP" == 1 ]]; then
    BIN_DIR="${REGEN_BIN_DIR:-$FIXTURES/bin/dwp}"
    TARGET_DIR="${REGEN_TARGET_DIR:-$FIXTURES/target-dwp}"
    export CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO=packed
fi

# Full debug info for every crate in the graph, not just test-programs:
# tokio's own CUs carry the statics (CONTEXT, WAKER_VTABLE) the extractor
# needs. A dedicated target dir keeps this profile from thrashing the
# regular build cache. (--no-debug-info drops all of it instead; see
# above.)
if [[ "$CT_ONLY" == 1 ]]; then
    export RUSTFLAGS=""
    FEATURES=(--no-default-features --features ct-tokio)
elif [[ "$UNSTABLE" == 1 ]]; then
    export RUSTFLAGS="--cfg tokio_unstable"
    FEATURES=()
else
    export RUSTFLAGS=""
    FEATURES=(--no-default-features --features full-tokio)
fi
export CARGO_PROFILE_RELEASE_DEBUG=$((DEBUG_INFO ? 2 : 0))
export CARGO_TARGET_DIR="$TARGET_DIR"

bins=()
for p in "${PROGRAMS[@]}"; do
    bins+=(--bin "$p")
done
(cd "$CRATE_DIR" && \
    cargo "+$TOOLCHAIN" build --locked --release "${FEATURES[@]}" "${bins[@]}")

mkdir -p "$BIN_DIR"

# Install by rename, never by writing over a file in place. The extraction
# tests mmap these, and several test binaries regenerate fixtures at once
# under a workspace-wide `cargo test`; rewriting a file would change the
# bytes under another process's live mapping, which reads as a corrupt
# binary or a parse that disagrees with itself. A rename replaces the
# directory entry instead, so a reader keeps the file it opened.
install() {
    local src="$1" dst="$2"
    mkdir -p "$(dirname "$dst")"
    cp -f "$src" "$dst.tmp$$"
    mv -f "$dst.tmp$$" "$dst"
}

trap 'rm -rf "$BIN_DIR"/*.tmp$$ "$BIN_DIR"/*.dSYM.tmp$$' EXIT

for p in "${PROGRAMS[@]}"; do
    install "$TARGET_DIR/release/$p" "$BIN_DIR/$p"
    if [[ "$DWP" == 1 ]]; then
        # cargo uplifts the package rustc's thorin wrote beside the
        # binary; without it the pair above is only half an input.
        install "$TARGET_DIR/release/$p.dwp" "$BIN_DIR/$p.dwp"
    fi
    if [[ "$(uname)" == "Darwin" && "$DEBUG_INFO" == 1 ]]; then
        # Mach-O executables don't carry DWARF; link it into a dSYM. The
        # bundle is built aside and its one file of interest — the linked
        # DWARF the tests read — renamed in, since replacing a whole
        # directory would leave a window with no dSYM at all, and a
        # reader finding none falls back to the DWARF-less executable.
        rm -rf "$BIN_DIR/$p.dSYM.tmp$$"
        dsymutil "$BIN_DIR/$p" -o "$BIN_DIR/$p.dSYM.tmp$$"
        dwarf="Contents/Resources/DWARF/$p"
        install "$BIN_DIR/$p.dSYM.tmp$$/$dwarf" "$BIN_DIR/$p.dSYM/$dwarf"
        rm -rf "$BIN_DIR/$p.dSYM.tmp$$"
    fi
    echo "regen.sh: built $BIN_DIR/$p"
done

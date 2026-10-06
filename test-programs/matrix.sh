#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Track new tokio and Rust releases against the version matrix
# (matrix.toml) and mechanically onboard them.
#
# Usage: matrix.sh COMMAND [ARG]
#
#   update           check crates.io and the Rust stable channel for
#                    releases the matrix does not cover and print the add
#                    command for each; exits 1 when behind, 0 when current
#   add tokio-VER    onboard a tokio version: derive locks/tokio-VER.lock
#                    from the primary Cargo.lock, update matrix.toml (a
#                    new minor is inserted; a newer patch of a listed
#                    minor replaces its pin), delete golden dirs the edit
#                    orphans, build and bless the new cells' goldens, then
#                    run the whole matrix un-blessed to prove no existing
#                    cell's goldens moved
#   add rust-VER     onboard a toolchain: rustup-install it with rust-src,
#                    update matrix.toml the same way (a new minor is
#                    inserted; a newer patch of a listed minor replaces
#                    its pin), delete golden dirs the edit orphans, bless
#                    its cells, run the whole matrix
#   bless [FILTER]   bless the goldens of every cell, or of the cells
#                    whose name contains FILTER: after a change that moves
#                    them, before pushing, so CI's matrix workflow passes
#   cells            list the fixture cells matrix.toml declares
#
# The goldens are the rendering in the Linux test image (.github/image/),
# so add and bless run every build and the matrix suite in it, through
# .github/scripts/in-image.sh: they need an x86_64 Linux host with
# podman, and no Rust of the host's own. Anywhere else their goldens
# would be another platform's, so they refuse.
#
# Every review in exegesis/src/detect/semantics.rs reads tokio and rustc
# release by release (TOKIO_RELEASES, RUSTC_RELEASES), each minor
# through the newest patch the matrix pins, and the matrix suite holds
# the two to each other and every listed checksum to the sources the
# cells build. So before add, read the files each review names at the
# new release, list the checksum of every revision that changed, and
# raise the minor's span (or add one) to it: add's runs then pass once
# its manifest edit lands, and fail on any file nobody read.
#
# add prepares the working tree and never commits. Review the manifest,
# lockfile, and golden diffs — a respelled member is one more ordered
# structural alternative in place; a restructure is a new
# exegesis/src/detect/tokio_v<floor> family module, with every existing
# cell's goldens showing zero diff — then run the per-cell acceptance
# suite on a host that can take cores (HANSEI_CELL=<cell> cargo test -p
# hansei --test acceptance) and commit. The floor and primary pins, of
# tokio and of Rust alike, advance deliberately, by hand; add refuses to
# touch them, and update names a new patch of either Rust pin's minor
# as a pin to advance. Advancing the primary toolchain edits
# rust-toolchain.toml in the same change. Advancing the tokio floor also
# moves the linux-floor set, whose cores are captured at the floor:
# re-bless its @linux-floor goldens on a Linux host.

set -uo pipefail

cd "$(dirname "$0")" || exit 2
SELF=$(basename "$0")
REPO=$(cd .. && pwd)
GOLDENS=$REPO/hansei-runtime/tests/matrix
MANIFEST=matrix.toml
INDEX_URL=https://index.crates.io/to/ki/tokio
CHANNEL_URL=https://static.rust-lang.org/dist/channel-rust-stable.toml

die() { printf 'matrix.sh: %s\n' "$*" >&2; exit 2; }
usage() { awk 'NR < 3 { next } !/^#/ { exit } { sub(/^# ?/, ""); print }' "$SELF"; }

# ---------------------------------------------------------------------------
# matrix.toml
#
# The grammar is deliberately rigid — single-line arrays, every value
# quoted — because several tools parse it independently
# (hansei-runtime/tests/matrix.rs is the reference). Keep the file that way
# or the parsers drift.
# ---------------------------------------------------------------------------

load_manifest() {
    eval "$(awk '
        /^[ \t]*#/ { next }
        /^\[/ { sect = $0; gsub(/[^a-z_]/, "", sect); next }
        {
            n = split($0, q, "\"")
            if ($0 ~ /^primary/) printf "P_TOKIO=%s P_TC=%s\n", q[2], q[4]
            else if (sect == "tokio" && $0 ~ /^floor/) printf "T_FLOOR=%s\n", q[2]
            else if (sect == "toolchain" && $0 ~ /^floor/) printf "TC_FLOOR=%s\n", q[2]
            else {
                if (sect == "tokio" && $0 ~ /^versions/) v = "T_VERS"
                else if (sect == "toolchain" && $0 ~ /^versions/) v = "TC_VERS"
                else if (sect == "cells" && $0 ~ /^no_unstable_tokio/) v = "NU_ROLES"
                else if (sect == "cells" && $0 ~ /^secondary_toolchain_tokio/) v = "ST_ROLES"
                else if (sect == "cells" && $0 ~ /^ct_only_tokio/) v = "CT_ROLES"
                else next
                printf "%s=\"", v
                for (i = 2; i <= n; i += 2) printf "%s%s", (i > 2 ? " " : ""), q[i]
                print "\""
            }
        }
    ' "$MANIFEST")"
    [ -n "${P_TOKIO:-}" ] && [ -n "${T_VERS:-}" ] && [ -n "${TC_VERS:-}" ] \
        || die "failed to parse $MANIFEST"
    read -ra TOKIO_VERSIONS <<<"$T_VERS"
    read -ra TOOLCHAINS <<<"$TC_VERS"
    read -ra NU_LIST <<<"${NU_ROLES:-}"
    read -ra ST_LIST <<<"${ST_ROLES:-}"
    read -ra CT_LIST <<<"${CT_ROLES:-}"
}

resolve_role() {
    case $1 in
        floor) echo "$T_FLOOR" ;;
        primary) echo "$P_TOKIO" ;;
        latest) echo "${TOKIO_VERSIONS[${#TOKIO_VERSIONS[@]}-1]}" ;;
        *) echo "$1" ;;
    esac
}

# One cell name per line, mirroring matrix.rs's enumeration exactly:
# the whole tokio axis on the primary toolchain with the cfg on, then
# the role-trimmed secondary axes, deduplicated per role list, then the
# features-limited ct-only cells.
enumerate_cells() {
    local v r tc seen
    for v in "${TOKIO_VERSIONS[@]}"; do
        echo "rust-$P_TC-tokio-$v-unstable"
    done
    seen=" "
    for r in "${NU_LIST[@]}"; do
        v=$(resolve_role "$r")
        case $seen in *" $v "*) continue ;; esac
        seen="$seen$v "
        echo "rust-$P_TC-tokio-$v-stable"
    done
    for tc in "${TOOLCHAINS[@]}"; do
        [ "$tc" = "$P_TC" ] && continue
        seen=" "
        for r in "${ST_LIST[@]}"; do
            v=$(resolve_role "$r")
            case $seen in *" $v "*) continue ;; esac
            seen="$seen$v "
            echo "rust-$tc-tokio-$v-unstable"
        done
    done
    seen=" "
    for r in "${CT_LIST[@]}"; do
        v=$(resolve_role "$r")
        case $seen in *" $v "*) continue ;; esac
        seen="$seen$v "
        echo "rust-$P_TC-tokio-$v-ctonly"
    done
}

# Rewrite one section's `versions` line in place, portably (no sed -i).
rewrite_versions() { # section, space-separated new list
    awk -v want="[$1]" -v list="$2" '
        /^\[/ { sect = $0 }
        sect == want && /^versions = / {
            n = split(list, a, " ")
            printf "versions = ["
            for (i = 1; i <= n; i++) printf "%s\"%s\"", (i > 1 ? ", " : ""), a[i]
            print "]"
            next
        }
        { print }
    ' "$MANIFEST" >"$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST" \
        || die "rewriting $MANIFEST failed"
}

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

ver_cmp() { # -1, 0, or 1
    awk -v a="$1" -v b="$2" 'BEGIN {
        n = split(a, x, "."); m = split(b, y, ".")
        for (i = 1; i <= (n > m ? n : m); i++) {
            if (x[i] + 0 < y[i] + 0) { print -1; exit }
            if (x[i] + 0 > y[i] + 0) { print 1; exit }
        }
        print 0
    }'
}

minor_of() { echo "${1%.*}"; }

check_semver() {
    printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || die "malformed version: $1"
}

# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

cmd_update() {
    load_manifest
    local behind=0 index channel stable v lv have latest_per_minor

    index=$(curl -fsS --max-time 30 "$INDEX_URL") \
        || die "fetching $INDEX_URL failed"
    # Latest non-yanked, non-prerelease patch of each minor, ascending.
    latest_per_minor=$(printf '%s\n' "$index" | awk '
        /"yanked":true/ { next }
        match($0, /"vers":"[^"]+"/) {
            v = substr($0, RSTART + 8, RLENGTH - 9)
            if (v ~ /-/) next
            split(v, p, ".")
            key = p[1] "." p[2]
            if (!(key in patch) || p[3] + 0 > patch[key]) {
                best[key] = v; patch[key] = p[3] + 0
            }
        }
        END { for (k in best) print best[k] }
    ' | sort -t. -k1,1n -k2,2n)
    [ -n "$latest_per_minor" ] || die "no tokio versions parsed from the index"

    for v in $latest_per_minor; do
        # Below the floor, or the floor/primary minor itself: those pins
        # advance deliberately, not by release-tracking.
        [ "$(ver_cmp "$v" "$T_FLOOR")" -lt 0 ] && continue
        [ "$(minor_of "$v")" = "$(minor_of "$T_FLOOR")" ] && continue
        [ "$(minor_of "$v")" = "$(minor_of "$P_TOKIO")" ] && continue
        have=""
        for lv in "${TOKIO_VERSIONS[@]}"; do
            [ "$(minor_of "$lv")" = "$(minor_of "$v")" ] && have=$lv
        done
        if [ -z "$have" ]; then
            echo "matrix is behind: tokio $v released (new minor) — run \`test-programs/matrix.sh add tokio-$v\`"
            behind=1
        elif [ "$(ver_cmp "$have" "$v")" -lt 0 ]; then
            echo "matrix is behind: tokio $v released ($have is pinned) — run \`test-programs/matrix.sh add tokio-$v\`"
            behind=1
        fi
    done

    channel=$(curl -fsS --max-time 30 "$CHANNEL_URL") \
        || die "fetching $CHANNEL_URL failed"
    stable=$(printf '%s\n' "$channel" | awk '
        /^\[pkg\.rust\]/ { in_rust = 1; next }
        /^\[/ { in_rust = 0 }
        in_rust && /^version = / {
            split($0, q, "\""); split(q[2], w, " "); print w[1]; exit
        }
    ')
    [ -n "$stable" ] || die "no stable version parsed from the channel manifest"
    # The channel names only the newest release, so this sees a new
    # minor, or a new patch of the newest listed one.
    local newer=1 tc
    have=""
    for tc in "${TOOLCHAINS[@]}"; do
        [ "$(minor_of "$tc")" = "$(minor_of "$stable")" ] && have=$tc
        [ "$(ver_cmp "$stable" "$tc")" -gt 0 ] || newer=0
    done
    if [ -n "$have" ] && [ "$(ver_cmp "$have" "$stable")" -lt 0 ]; then
        if [ "$have" = "$P_TC" ] || [ "$have" = "${TC_FLOOR:-}" ]; then
            echo "matrix is behind: Rust $stable released ($have is pinned) — advance that pin by hand, in matrix.toml and rust-toolchain.toml"
        else
            echo "matrix is behind: Rust $stable released ($have is pinned) — run \`test-programs/matrix.sh add rust-$stable\`"
        fi
        behind=1
    elif [ -z "$have" ] && [ $newer = 1 ]; then
        echo "matrix is behind: Rust $stable is stable (new minor) — run \`test-programs/matrix.sh add rust-$stable\`"
        behind=1
    fi

    if [ $behind = 0 ]; then
        echo "matrix is current (tokio ${TOKIO_VERSIONS[*]}; rust ${TOOLCHAINS[*]}; stable is $stable)"
    fi
    exit $behind
}

# ---------------------------------------------------------------------------
# add — shared plumbing
# ---------------------------------------------------------------------------

require_clean() {
    local dirty
    dirty=$(git -C "$REPO" status --porcelain -- \
        test-programs/Cargo.lock test-programs/matrix.toml test-programs/locks \
        hansei-runtime/tests/matrix)
    [ -z "$dirty" ] || die "uncommitted changes in the paths add rewrites — commit or stash first:
$dirty"
}

# Run a command in the Linux test image, from this directory.
in_image() {
    "$REPO/.github/scripts/in-image.sh" "$@"
}

# What add and bless need: the image, which only an x86_64 Linux host
# runs natively. An arm64 one would build the fixtures for its own
# architecture, whose DWARF the goldens do not describe.
require_image_host() {
    [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] \
        || die "the matrix goldens are blessed in the Linux test image, which needs an x86_64 Linux host (this is $(uname -s) $(uname -m))"
    command -v podman >/dev/null \
        || die "podman not found: the matrix goldens are blessed in the Linux test image (see .github/scripts/in-image.sh)"
}

ensure_toolchain() {
    in_image rustup toolchain install --profile minimal "$1" \
        || die "installing toolchain $1 failed"
    # The matrix suite holds the rustc reviews to the standard library
    # sources each toolchain ships.
    in_image rustup component add rust-src --toolchain "$1" >/dev/null 2>&1 \
        || die "adding rust-src to toolchain $1 failed"
}

# The matrix suite in the image, over the cells whose names contain
# $1 ("1" for all of them); further arguments are environment settings.
run_matrix() {
    local filter=$1; shift
    (cd "$REPO" && in_image env HANSEI_MATRIX="$filter" "$@" \
        cargo nextest run --profile ci --cargo-profile ci -p hansei-runtime --test matrix)
}

lock_packages() {
    awk '
        /^name = / { n = $3; gsub(/"/, "", n) }
        /^version = / && n != "" { v = $3; gsub(/"/, "", v); print n, v; n = "" }
    ' "$1"
}

# Diff the enumerated cell sets around the manifest edit: bless what is
# new, delete the golden dirs of what the edit orphaned (the "latest"
# role slides when a version is appended, and a patch bump renames its
# cells).
reconcile_cells() { # before, after (newline-separated), bless substring
    local new orphans c missing
    new=$(comm -13 <(printf '%s\n' "$1" | sort) <(printf '%s\n' "$2" | sort))
    orphans=$(comm -23 <(printf '%s\n' "$1" | sort) <(printf '%s\n' "$2" | sort))
    [ -n "$new" ] || die "the manifest edit added no cells"

    for c in $orphans; do
        if [ -d "$GOLDENS/$c" ]; then
            rm -rf "${GOLDENS:?}/$c"
            echo "deleted orphaned goldens: $c"
        fi
    done
    printf 'new cells:\n%s\n' "$(printf '%s\n' "$new" | sed 's/^/  /')"

    echo "building and blessing the new cells..."
    run_matrix "$3" INSTA_UPDATE=always || die "blessing the new cells failed"
    # Goldens are the proof every new cell actually ran.
    missing=0
    for c in $new; do
        [ -d "$GOLDENS/$c" ] || { echo "no goldens were written for $c" >&2; missing=1; }
    done
    [ $missing = 0 ] || die "blessing skipped cells"

    echo "running the whole matrix un-blessed (no existing cell's goldens may move)..."
    run_matrix 1 \
        || die "the full matrix run failed — an existing cell's goldens moved, or a new golden is unstable"
}

report() {
    echo
    echo "working tree is ready for review:"
    git -C "$REPO" status --short -- \
        test-programs/matrix.toml test-programs/locks hansei-runtime/tests/matrix \
        | sed 's/^/  /'
    echo
    echo "next: review the golden diffs (a respelled member = an ordered"
    echo "alternative in place; a restructure = a new detect/tokio_v<floor>"
    echo "family module, existing cells zero-diff), run the per-cell"
    echo "acceptance suite on a host that can take cores, then commit."
}

# ---------------------------------------------------------------------------
# add tokio-VER
# ---------------------------------------------------------------------------

cmd_add_tokio() {
    local ver=$1 old="" lv before after backup changes newlist inserted
    check_semver "$ver"
    load_manifest
    require_clean
    require_image_host

    [ "$(ver_cmp "$ver" "$T_FLOOR")" -ge 0 ] \
        || die "tokio $ver is below the floor ($T_FLOOR)"
    if [ "$(minor_of "$ver")" = "$(minor_of "$T_FLOOR")" ] \
        || [ "$(minor_of "$ver")" = "$(minor_of "$P_TOKIO")" ]; then
        die "the floor/primary pins ($T_FLOOR/$P_TOKIO) advance deliberately — edit matrix.toml by hand (a floor advance also means re-blessing the linux-floor goldens; see the header)"
    fi
    for lv in "${TOKIO_VERSIONS[@]}"; do
        [ "$(minor_of "$lv")" = "$(minor_of "$ver")" ] && old=$lv
    done
    [ "$old" = "$ver" ] && die "tokio $ver is already in the matrix"
    if [ -n "$old" ] && [ "$(ver_cmp "$ver" "$old")" -lt 0 ]; then
        die "refusing to downgrade the $(minor_of "$ver") pin ($old); retirement is a deliberate edit"
    fi

    local tc
    for tc in "${TOOLCHAINS[@]}"; do ensure_toolchain "$tc"; done
    before=$(enumerate_cells)

    # Derive the lockfile from the primary lock so only tokio and its
    # dependents move, then restore the primary lock byte-for-byte.
    echo "deriving locks/tokio-$ver.lock from the primary lock..."
    backup=$(mktemp) || die "mktemp failed"
    cp Cargo.lock "$backup" || die "backing up Cargo.lock failed"
    if ! in_image cargo "+$P_TC" update -p tokio --precise "$ver"; then
        git -C "$REPO" checkout -- test-programs/Cargo.lock
        die "cargo update -p tokio --precise $ver failed (does the release exist?)"
    fi
    cp Cargo.lock "locks/tokio-$ver.lock" || die "writing locks/tokio-$ver.lock failed"
    git -C "$REPO" checkout -- test-programs/Cargo.lock \
        || die "restoring Cargo.lock failed"
    cmp -s Cargo.lock "$backup" || die "Cargo.lock did not restore to its committed state"
    rm -f "$backup"

    # Sanity: the derivation moved tokio to exactly VER, and left
    # oxide-tokio-rt alone (the primary lock pins it back so tokio
    # 1.50/1.51 stay expressible).
    changes=$(diff <(lock_packages Cargo.lock) <(lock_packages "locks/tokio-$ver.lock") \
        | grep '^[<>]')
    printf '%s\n' "$changes" | grep -q "^> tokio $ver\$" \
        || die "the derived lock does not resolve tokio to $ver"
    if printf '%s\n' "$changes" | grep -q '^[<>] oxide-tokio-rt '; then
        die "the derivation moved oxide-tokio-rt — it must stay at the primary lock's pin"
    fi
    printf 'packages moved by the derivation:\n%s\n' \
        "$(printf '%s\n' "$changes" | sed 's/^</  -/; s/^>/  +/')"

    if [ -n "$old" ]; then
        rm -f "locks/tokio-$old.lock"
        echo "deleted locks/tokio-$old.lock (patch bump)"
    fi

    # The manifest edit: replace the old patch in place, or insert the
    # new minor in version order.
    newlist=""
    inserted=0
    for lv in "${TOKIO_VERSIONS[@]}"; do
        if [ "$lv" = "$old" ]; then
            newlist="$newlist $ver"; inserted=1
        elif [ -z "$old" ] && [ $inserted = 0 ] && [ "$(ver_cmp "$ver" "$lv")" -lt 0 ]; then
            newlist="$newlist $ver $lv"; inserted=1
        else
            newlist="$newlist $lv"
        fi
    done
    [ $inserted = 0 ] && newlist="$newlist $ver"
    rewrite_versions tokio "${newlist# }"
    echo "matrix.toml: tokio versions are now [${newlist# }]"

    load_manifest
    after=$(enumerate_cells)
    reconcile_cells "$before" "$after" "tokio-$ver-"
    report
}

# ---------------------------------------------------------------------------
# add rust-VER
# ---------------------------------------------------------------------------

cmd_add_rust() {
    local ver=$1 old="" tc before after newlist inserted
    check_semver "$ver"
    load_manifest
    require_clean
    require_image_host

    [ -n "${TC_FLOOR:-}" ] && [ "$(ver_cmp "$ver" "$TC_FLOOR")" -lt 0 ] \
        && die "rust $ver is below the floor ($TC_FLOOR)"
    if [ "$(minor_of "$ver")" = "$(minor_of "${TC_FLOOR:-}")" ] \
        || [ "$(minor_of "$ver")" = "$(minor_of "$P_TC")" ]; then
        die "the floor/primary toolchain pins (${TC_FLOOR:-}/$P_TC) advance deliberately — edit matrix.toml by hand (the primary with rust-toolchain.toml; see the header)"
    fi
    # The matrix holds one patch per minor, the latest: a newer patch
    # replaces its minor's pin.
    for tc in "${TOOLCHAINS[@]}"; do
        [ "$(minor_of "$tc")" = "$(minor_of "$ver")" ] && old=$tc
    done
    [ "$old" = "$ver" ] && die "rust $ver is already in the matrix"
    if [ -n "$old" ] && [ "$(ver_cmp "$ver" "$old")" -lt 0 ]; then
        die "refusing to downgrade the $(minor_of "$ver") pin ($old); retirement is a deliberate edit"
    fi

    ensure_toolchain "$ver"
    for tc in "${TOOLCHAINS[@]}"; do ensure_toolchain "$tc"; done
    before=$(enumerate_cells)

    # The manifest edit: replace the old patch in place, or insert the
    # new minor in version order.
    newlist=""
    inserted=0
    for tc in "${TOOLCHAINS[@]}"; do
        if [ "$tc" = "$old" ]; then
            newlist="$newlist $ver"; inserted=1
        elif [ -z "$old" ] && [ $inserted = 0 ] && [ "$(ver_cmp "$ver" "$tc")" -lt 0 ]; then
            newlist="$newlist $ver $tc"; inserted=1
        else
            newlist="$newlist $tc"
        fi
    done
    [ $inserted = 0 ] && newlist="$newlist $ver"
    rewrite_versions toolchain "${newlist# }"
    echo "matrix.toml: toolchains are now [${newlist# }]"

    load_manifest
    after=$(enumerate_cells)
    reconcile_cells "$before" "$after" "rust-$ver-"
    report
}

# ---------------------------------------------------------------------------
# bless [FILTER]
# ---------------------------------------------------------------------------

cmd_bless() {
    local filter=${1:-1} tc
    load_manifest
    require_image_host
    for tc in "${TOOLCHAINS[@]}"; do ensure_toolchain "$tc"; done
    echo "blessing the cells matching '$filter'..."
    run_matrix "$filter" INSTA_UPDATE=always || die "blessing failed"
    echo
    echo "blessed; review before committing:"
    git -C "$REPO" status --short -- hansei-runtime/tests/matrix | sed 's/^/  /'
}

# ---------------------------------------------------------------------------

case ${1:-} in
    update)
        [ $# -eq 1 ] || die "update takes no arguments"
        cmd_update ;;
    add)
        [ $# -eq 2 ] || die "add takes exactly one of tokio-VER / rust-VER"
        case $2 in
            tokio-*) cmd_add_tokio "${2#tokio-}" ;;
            rust-*) cmd_add_rust "${2#rust-}" ;;
            *) die "add takes tokio-VER or rust-VER, not '$2'" ;;
        esac ;;
    bless)
        [ $# -le 2 ] || die "bless takes at most one cell filter"
        cmd_bless "${2:-}" ;;
    cells)
        [ $# -eq 1 ] || die "cells takes no arguments"
        load_manifest
        enumerate_cells ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac

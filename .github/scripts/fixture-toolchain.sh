#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Install the toolchain the fixture programs build with: the matrix's
# primary (test-programs/matrix.toml), which regen.sh selects by name
# and refuses to build without.
#
#   fixture-toolchain.sh
#
# rustup installs the workspace's own toolchain (rust-toolchain.toml)
# the first time cargo runs, but that is another release, and nothing
# installs the fixtures' unless asked.

set -euo pipefail

cd "$(dirname "$0")/../.."
tc=$(sed -n 's/^primary = .*toolchain = "\([^"]*\)".*/\1/p' test-programs/matrix.toml)
if [ -z "$tc" ]; then
    echo "fixture-toolchain.sh: no primary toolchain in test-programs/matrix.toml" >&2
    exit 1
fi
rustup toolchain install --profile minimal "$tc"

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// mimalloc's vendored C sources fail to assemble with the illumos
// gcc/gas toolchain. Everywhere else it is what extraction's
// allocation-heavy interning was tuned against. It is the binary's
// choice, not the library's: a host that embeds hansei keeps its own.
#[cfg(not(target_os = "illumos"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    hansei::cli_main();
}

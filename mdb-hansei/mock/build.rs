// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

fn main() {
    // mdb_printf and mdb_warn are C varargs functions, which stable Rust
    // cannot define; a few lines of C format and hand the text over.
    cc::Build::new()
        .file("src/printf.c")
        .compile("mdbmock_printf");
    // The dmod resolves the mdb_* functions against the host process,
    // so the host must export them.
    println!("cargo:rustc-link-arg-bins=-Wl,--export-dynamic");
    println!("cargo:rerun-if-changed=src/printf.c");
}

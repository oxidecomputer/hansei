// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Generate the libproc bindings, on the one system that has libproc.
//!
//! bindgen links libclang, so it is a build-dependency only where the
//! bindings are actually generated. Everywhere else this crate builds
//! to nothing, and pulling libclang in to reach that conclusion would
//! cost the rest of the workspace its build: the script would need a
//! `libclang.so` matching whatever clang-sys linked it against, which
//! on a machine with more than one LLVM around is not the one the
//! loader finds.

fn main() {
    #[cfg(target_os = "illumos")]
    generate();
}

/// Cross-compiling to illumos was never possible here — the header is
/// read from the building machine's `/usr/include` — so the host's
/// `cfg` above and the target's `CARGO_CFG_TARGET_OS` agree in every
/// case this crate supports.
#[cfg(target_os = "illumos")]
fn generate() {
    use std::env;
    use std::path::PathBuf;

    let bindings = bindgen::Builder::default()
        .header("/usr/include/libproc.h")
        .generate_comments(true)
        .derive_debug(false)
        .wrap_unsafe_ops(true) // https://github.com/rust-lang/rust-bindgen/issues/3147
        .ctypes_prefix("std::ffi")
        .generate()
        .expect("unable to generate libproc bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("unable to write libproc bindings");

    println!("cargo:rustc-link-lib=proc");
    println!("cargo:rerun-if-changed=/usr/include/libproc.h");
    println!("cargo:out_dir={}", env::var("OUT_DIR").unwrap());
}

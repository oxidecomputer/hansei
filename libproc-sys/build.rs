use std::env;
use std::path::PathBuf;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "illumos" {
        eprintln!("ERROR: This crate requires illumos");
        eprintln!("Current target OS: {target_os}");
        std::process::exit(1);
    }

    let bindings = bindgen::Builder::default()
        .header("/usr/include/libproc.h")
        //.header("/usr/include/procfs.h")
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

    //fs::copy(out_path.join("bindings.rs"), "src/lib.rs").unwrap();

    println!("cargo:rustc-link-lib=proc");
    println!("cargo:rerun-if-changed=/usr/include/libproc.h");
    println!("cargo:out_dir={}", env::var("OUT_DIR").unwrap());

    // Allow dependent crates to locate the sources and output directory of this crate.
    // println!(
    //     "cargo:cargo_manifest_dir={}",
    //     env::var("CARGO_MANIFEST_DIR").unwrap()
    // );
}

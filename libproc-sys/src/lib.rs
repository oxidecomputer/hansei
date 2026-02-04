mod bindings;

pub use bindings::*;

#[cfg(not(target_os = "illumos"))]
compile_error!("this crate only supports illumos");

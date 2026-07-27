#[cfg(not(target_os = "illumos"))]
compile_error!("this crate only supports illumos");

// Gated so that elsewhere the line above is the whole story: the
// bindings are written by the build script, which does not run off
// illumos, so an ungated `include!` of them would bury it in errors
// about a file that was never going to exist.
#[cfg(target_os = "illumos")]
mod bindings;

#[cfg(target_os = "illumos")]
pub use bindings::*;

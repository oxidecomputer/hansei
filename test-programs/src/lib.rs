//! What every fixture program needs before it parks.
//!
//! The fixtures exist to be cored while they run, and the suites take
//! that core by pid — `gcore <pid>` from a sibling test process. Linux's
//! Yama LSM decides whether that is allowed, and its common default
//! (`kernel.yama.ptrace_scope = 1`) permits tracing only a descendant,
//! which a sibling is not. A fixture that says nothing therefore cannot
//! be cored at all on a Debian or Ubuntu box, so each one declares who
//! may trace it.

/// Let any process of this uid trace this one, so a test harness can
/// core it by pid whatever `ptrace_scope` says.
///
/// The relation is the calling process's own, so this has to run in the
/// fixture rather than in whatever spawned it, and it is only ever a
/// widening: a system that already allows the attach is unaffected, and
/// no other system's tracing rules are involved.
#[cfg(target_os = "linux")]
pub fn allow_any_tracer() {
    // Yama's own `prctl(2)` option and its "anybody" argument. Both are
    // spelled out here because `libc` does not carry the second.
    const PR_SET_PTRACER: libc::c_int = 0x59616d61;
    const PR_SET_PTRACER_ANY: libc::c_ulong = libc::c_ulong::MAX;

    // SAFETY: `prctl` is variadic; this option takes one unsigned-long
    // argument and touches nothing of ours. A kernel without Yama fails
    // it with EINVAL, which is as good an answer as success.
    unsafe {
        libc::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    }
}

/// Nothing to declare: no other system gates tracing on the tracee's
/// say-so.
#[cfg(not(target_os = "linux"))]
pub fn allow_any_tracer() {}

/// The builder every fixture parks a runtime from. `oxide-tokio-rt`
/// re-exports this same type, so both arms of [`run_builder`] take it.
pub use tokio::runtime::Builder;

/// With the `unstable` feature (the default recipe, built with
/// `--cfg tokio_unstable`), the runtime is oxide-tokio-rt's.
#[cfg(feature = "unstable")]
pub use oxide_tokio_rt::run_builder;

/// Without it, a plain tokio runtime with the same call shape, so a
/// fixture's `main` is identical however the cell is built.
#[cfg(not(feature = "unstable"))]
pub fn run_builder<T>(builder: &mut Builder, main: impl std::future::Future<Output = T>) -> T {
    match builder.enable_all().build() {
        Ok(rt) => rt.block_on(main),
        Err(e) => panic!("failed to initialize Tokio runtime: {e:?}"),
    }
}

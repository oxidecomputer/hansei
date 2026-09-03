// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bindings to illumos' `libproc`, generated at build time from the
//! header on the building machine.
//!
//! Off illumos there is no libproc to bind and this crate is empty: the
//! build script generates nothing, and the module below is gated out so
//! that an `include!` of bindings which were never written cannot fail.
//! Empty rather than refusing to compile is what lets the workspace
//! build anywhere — a member that fails on sight fails
//! `cargo check --workspace` on every host, whether or not anything
//! asked for it.
//!
//! What keeps the emptiness from being a trap is the consumer: `proc`
//! names this crate only under `cfg(target_os = "illumos")`, so nothing
//! can reach for a binding that is not there.

#[cfg(target_os = "illumos")]
mod bindings;

#[cfg(target_os = "illumos")]
pub use bindings::*;

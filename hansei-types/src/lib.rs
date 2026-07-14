// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Useful types for building async debuggers based on tokio

#[cfg(target_os = "illumos")]
pub mod debugger;
pub mod tokio;

use derive_more::Display;
use std::fmt;

/// A newtype that always debug prints in hex.
#[derive(Clone, Copy)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:x}", self.0))
    }
}

/// A thread id read via libproc
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadId(u32);

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Allocator corroboration: what the target's own malloc says about an
//! address, read out of its metadata rather than inferred from the
//! bytes at it.
//!
//! Nothing here is tokio's, which is why it sits beside [`crate::tokio`]
//! rather than inside it: a pointer either lands in an allocation the
//! allocator still considers live or it does not, whatever the value
//! walk believed it pointed at.

pub mod umem;
pub mod view;

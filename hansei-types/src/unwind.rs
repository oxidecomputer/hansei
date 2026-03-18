// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Backtrace types extracted from hansei for use across crates.

use proc::{Regs, SymbolBuf};

#[derive(Clone, PartialEq, Default, Debug)]
pub struct Backtrace {
    pub frames: Vec<Frame>,
}

impl Backtrace {
    pub fn new(frames: Vec<Frame>) -> Self {
        Self { frames }
    }

    pub fn stack_trace(&self, max_frames: usize) -> Vec<String> {
        self.frames
            .iter()
            .take(max_frames)
            .map(|frame| {
                let mangled = frame
                    .symbol
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or_default();
                format!(
                    "{:#018x} {:#}",
                    frame.regs.rip,
                    rustc_demangle::demangle(mangled)
                )
            })
            .collect()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Frame {
    pub pc: u64,
    pub regs: Regs,
    pub symbol: Option<SymbolBuf>,
}

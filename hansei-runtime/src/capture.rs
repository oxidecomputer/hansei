// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Detect threads a core failed to capture.
//!
//! A dump may record a mapping but capture no data. We have
//! seen this with `gdb` older than 18.0 and on hosts with `glibc` 2.42+.
//!
//! We cannot directly distinguish between genuinely zeroed data, vs
//! regions the dumper failed to capture, but we can use knowledge
//! of the invariants that must hold for a live thread to deduce it.
//! We can assume two things:
//!
//! - A thread's frame is located above its stack pointer and holds its
//!   return address.
//! - Its thread-local storage can be assumed to be non-zero for any
//!   process that uses tokio.
//!
//! The latter holds even if the thread never entered a runtime. The
//! thread-local is const-initialized into `.tdata` as `None` for
//! `Option<scheduler::Handle>`, which is discriminant 2. We read it at
//! the static's address rather than at the thread pointer because the
//! module's thread-local block sits below the latter.
//!
//! Merely checking the runtime handle is insufficient. A zeroed region
//! will be parsed as an `Arc` with a null pointer, which may be from a
//! genuinely corrupted process.

use proc::{LwpInfo, SymbolBuf, Target};

/// How much to read at an anchor. A page is far more than the
/// invariant needs, the thinnest margin over two hundred threads of
/// three captured targets was 86 nonzero bytes, and we will not read
/// past the end of the mapping if this is too large.
const WINDOW: u64 = 0x1000;

/// The results of the mapping checks on a lwp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LwpCapture {
    /// The target lwp.
    pub tid: u32,
    /// Whether the core carries the thread's own stack.
    pub stack: bool,
    /// Whether the core carries the thread's thread-local storage.
    pub tls: bool,
}

impl LwpCapture {
    /// Whether the core carries all expected data for the thread.
    pub fn is_whole(&self) -> bool {
        self.stack && self.tls
    }
}

/// Returns the lwps that were not fully captured, in the order provided
/// in `lwps`.
///
/// `context` is the thread-local runtime static specified by the bundle.
///  If not set, default to `fsbase`.
pub fn incomplete<T: Target>(
    proc: &T,
    lwps: &[LwpInfo],
    context: Option<&SymbolBuf>,
) -> Vec<LwpCapture> {
    lwps.iter()
        .map(|lwp| {
            let anchor = context
                .and_then(|sym| proc.tls_var_addr(&lwp.regs, sym).ok().flatten())
                .unwrap_or(lwp.regs.fsbase);
            LwpCapture {
                tid: lwp.tid,
                stack: captured(proc, lwp.regs.rsp),
                // A thread with no thread pointer reaches no
                // thread-local storage, and `tls_var_addr` skips it for
                // the same reason. Absent is not missing.
                tls: anchor == 0 || captured(proc, anchor),
            }
        })
        .filter(|capture| !capture.is_whole())
        .collect()
}

/// What to report about threads the core carries neither the stack nor
/// the thread-local storage of, or `None` when there are none.
pub fn missing_stacks_and_contexts(incomplete: &[LwpCapture]) -> Option<String> {
    let runs = lwp_runs(incomplete, |capture| !capture.stack && !capture.tls);
    match listed(&runs)? {
        (one, false) => Some(format!(
            "the stack and thread-local storage for lwp {one} were not \
             captured in the core dump. A native stack trace will not be \
             available for this thread, and it will not be attributed to a \
             runtime."
        )),
        (many, true) => Some(format!(
            "the stacks and thread-local storage for lwps {many} were not \
             captured in the core dump. Native stack traces will not be \
             available for these threads, and they will not be attributed \
             to a runtime."
        )),
    }
}

/// What to report about threads whose stack the core is missing while
/// their thread-local storage survived, or `None` when there are none.
pub fn missing_stacks(incomplete: &[LwpCapture]) -> Option<String> {
    let runs = lwp_runs(incomplete, |capture| !capture.stack && capture.tls);
    match listed(&runs)? {
        (one, false) => Some(format!(
            "the stack for lwp {one} was not captured in the core dump. \
             A native stack trace will not be available for this thread."
        )),
        (many, true) => Some(format!(
            "the stacks for lwps {many} were not captured in the core dump. \
             Native stack traces will not be available for these threads."
        )),
    }
}

/// What to report about threads whose thread-local storage the core is
/// missing while their stack survived, or `None` when there are none.
pub fn missing_contexts(incomplete: &[LwpCapture]) -> Option<String> {
    let runs = lwp_runs(incomplete, |capture| !capture.tls && capture.stack);
    match listed(&runs)? {
        (one, false) => Some(format!(
            "the thread-local storage for lwp {one} was not captured in the \
             core dump. This thread will not be attributed to a runtime."
        )),
        (many, true) => Some(format!(
            "the thread-local storage for lwps {many} was not captured in the \
             core dump. These threads will not be attributed to a runtime."
        )),
    }
}

/// Whether the core carries non-zero bytes for the window at `addr`.
///
/// We do not page-align the window because the targets we're checking
/// are also not aligned. Stack frames are above the stack pointer,
/// and a libc's per-thread state sits at and above the thread pointer.
///
/// Clamp the length to the end of the region; stack pointers are
/// frequently near the end of their mappings.
fn captured<T: Target>(proc: &T, addr: u64) -> bool {
    let len = proc.readable_len(addr, WINDOW);
    len != 0
        && proc
            .read_bytes(addr, len)
            .is_ok_and(|bytes| bytes.iter().any(|&byte| byte != 0))
}

/// The lwps a predicate selects, as ascending contiguous runs.
///
/// The three callers' predicates partition the incomplete lwps, so no
/// thread is named by more than one line.
fn lwp_runs(
    incomplete: &[LwpCapture],
    mut want: impl FnMut(&LwpCapture) -> bool,
) -> Vec<(u32, u32)> {
    let mut tids: Vec<u32> = incomplete
        .iter()
        .filter(|capture| want(capture))
        .map(|capture| capture.tid)
        .collect();
    // Lwps arrive in whatever order the core notes them, which on a
    // Linux core is neither ascending nor the order they were made.
    tids.sort_unstable();
    tids.dedup();
    runs(&tids)
}

/// Ascending ids as inclusive contiguous runs.
fn runs(ids: &[u32]) -> Vec<(u32, u32)> {
    let mut runs: Vec<(u32, u32)> = Vec::new();
    for &id in ids {
        match runs.last_mut() {
            Some(run) if id == run.1 + 1 => run.1 = id,
            _ => runs.push((id, id)),
        }
    }
    runs
}

/// Runs as they are named in a line, and whether that naming is
/// plural.
fn listed(runs: &[(u32, u32)]) -> Option<(String, bool)> {
    let (first, rest) = runs.split_first()?;
    if rest.is_empty() && first.0 == first.1 {
        return Some((first.0.to_string(), false));
    }
    let named: Vec<String> = runs
        .iter()
        .map(|&(from, to)| {
            if from == to {
                format!("{from}")
            } else {
                format!("[{from}-{to}]")
            }
        })
        .collect();
    Some((named.join(", "), true))
}

#[cfg(test)]
mod tests {
    use super::*;

    use proc::{Mappings, Regs, SymbolBuf, Timespec};

    use std::ops::Range;

    /// One region of memory: bytes a live thread could have left, with
    /// chosen ranges zeroed or denied outright.
    struct Fake {
        base: u64,
        bytes: Vec<u8>,
        denied: Vec<Range<u64>>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                base: REGION.start,
                bytes: vec![0xa5; (REGION.end - REGION.start) as usize],
                denied: Vec::new(),
            }
        }

        fn blank(mut self, range: Range<u64>) -> Self {
            let from = (range.start - self.base) as usize;
            let to = (range.end - self.base) as usize;
            self.bytes[from..to].fill(0);
            self
        }

        fn deny(mut self, range: Range<u64>) -> Self {
            self.denied.push(range);
            self
        }
    }

    impl Target for Fake {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            let end = addr + len;
            if self
                .denied
                .iter()
                .any(|range| addr < range.end && end > range.start)
            {
                return Err(proc::Error::unmapped(addr, len));
            }
            let start = addr
                .checked_sub(self.base)
                .filter(|_| end <= self.base + self.bytes.len() as u64)
                .ok_or_else(|| proc::Error::unmapped(addr, len))?;
            Ok(&self.bytes[start as usize..(start + len) as usize])
        }

        fn readable_len(&self, addr: u64, max: u64) -> u64 {
            let end = self.base + self.bytes.len() as u64;
            if addr < self.base || addr >= end {
                return 0;
            }
            max.min(end - addr)
        }

        fn lookup_symbol_by_addr(&self, _: u64) -> Option<SymbolBuf> {
            None
        }

        fn lookup_symbol_by_name(&self, _: &str) -> Option<SymbolBuf> {
            None
        }

        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            Ok(Vec::new())
        }

        fn mappings(&self) -> proc::Result<Mappings> {
            unimplemented!("the capture check never asks")
        }

        fn lwps(&self) -> proc::Result<Vec<LwpInfo>> {
            unimplemented!("the caller brings its own")
        }

        /// The one TLS model a fake needs: the static sits a fixed
        /// distance *below* the thread pointer on x86_64.
        fn tls_var_addr(&self, regs: &Regs, _: &SymbolBuf) -> proc::Result<Option<u64>> {
            if regs.fsbase == 0 {
                return Ok(None);
            }
            Ok(Some(regs.fsbase - TLS_BELOW_TP))
        }
    }

    fn lwp(tid: u32, rsp: u64, fsbase: u64) -> LwpInfo {
        LwpInfo {
            tid,
            regs: Regs {
                rsp,
                fsbase,
                ..Regs::default()
            },
            stack_range: 0..0,
            altstack: 0..0,
            tstamp: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        }
    }

    /// The one region the fake lends from, with a thread's two anchors
    /// inside it. Neither anchor is page-aligned, matching real
    /// environments.
    const REGION: Range<u64> = 0x7000_0000..0x7001_0000;
    const STACK: u64 = 0x7000_0040;
    /// The thread pointer. The fake's thread-local static resolves a
    /// page and a half below it, far enough that a window above one
    /// cannot reach the other.
    const TP: u64 = 0x7000_8240;
    const TLS_BELOW_TP: u64 = 0x1800;
    const CONTEXT: u64 = TP - TLS_BELOW_TP;

    /// A symbol to pass to `incomplete`; the fake resolves it by
    /// arithmetic, not by name.
    fn context_symbol() -> SymbolBuf {
        SymbolBuf {
            name: "CONTEXT".to_string(),
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: 0,
            st_size: 0,
        }
    }

    /// The anchors.
    fn probe(fake: &Fake, lwps: &[LwpInfo]) -> Vec<LwpCapture> {
        incomplete(fake, lwps, Some(&context_symbol()))
    }

    #[test]
    fn test_a_complete_core_reports_nothing() {
        let fake = Fake::new();
        let lwps = [lwp(1, STACK, TP)];
        assert!(probe(&fake, &lwps).is_empty());
        assert_eq!(missing_stacks(&probe(&fake, &lwps)), None);
        assert_eq!(missing_contexts(&probe(&fake, &lwps)), None);
    }

    #[test]
    fn test_a_blank_window_is_a_thread_the_core_lost() {
        let fake = Fake::new().blank(STACK..STACK + WINDOW);
        let lwps = [lwp(7, STACK, TP)];
        assert_eq!(
            probe(&fake, &lwps),
            [LwpCapture {
                tid: 7,
                stack: false,
                tls: true
            }]
        );
    }

    /// A failing read is also reported.
    #[test]
    fn test_an_unreadable_window_counts_too() {
        let fake = Fake::new().deny(STACK..STACK + WINDOW);
        let lwps = [lwp(7, STACK, TP)];
        assert_eq!(
            probe(&fake, &lwps),
            [LwpCapture {
                tid: 7,
                stack: false,
                tls: true
            }]
        );
    }

    /// The thread-local anchor is the static's address, not the thread
    /// pointer: memory the walk will read, rather than a neighbour of
    /// it. Blanking the static's page alone is enough, and blanking
    /// the thread pointer's page alone is not.
    #[test]
    fn test_the_context_is_what_the_thread_local_anchor_reads() {
        let lwps = [lwp(7, STACK, TP)];

        let lost = Fake::new().blank(CONTEXT..CONTEXT + WINDOW);
        assert_eq!(
            probe(&lost, &lwps),
            [LwpCapture {
                tid: 7,
                stack: true,
                tls: false
            }]
        );

        let neighbour = Fake::new().blank(TP..TP + WINDOW);
        assert!(
            probe(&neighbour, &lwps).is_empty(),
            "the static still reads, whatever sits above the thread pointer"
        );
    }

    /// Without a static to resolve, the thread pointer is the anchor
    /// the check falls back to.
    #[test]
    fn test_a_bundle_naming_no_static_falls_back_to_the_thread_pointer() {
        let fake = Fake::new().blank(TP..TP + WINDOW);
        let lwps = [lwp(7, STACK, TP)];
        assert_eq!(
            incomplete(&fake, &lwps, None),
            [LwpCapture {
                tid: 7,
                stack: true,
                tls: false
            }]
        );
    }

    /// The two anchors are independent: a spawned thread keeps its
    /// stack and its thread-local storage in one mapping, but the
    /// initial thread's are separate. Each loss has its own line.
    #[test]
    fn test_each_anchor_has_its_own_line() {
        let lwps = [lwp(7, STACK, TP)];

        let fake = Fake::new().blank(CONTEXT..CONTEXT + WINDOW);
        let found = probe(&fake, &lwps);
        assert_eq!(missing_stacks(&found), None);
        assert_eq!(
            missing_contexts(&found).unwrap(),
            "the thread-local storage for lwp 7 was not captured in the \
             core dump. This thread will not be attributed to a runtime."
        );
        // Losing one is not losing both.
        assert_eq!(missing_stacks_and_contexts(&found), None);

        let fake = Fake::new().blank(STACK..STACK + WINDOW);
        let found = probe(&fake, &lwps);
        assert_eq!(
            missing_stacks(&found).unwrap(),
            "the stack for lwp 7 was not captured in the core dump. \
             A native stack trace will not be available for this thread."
        );
        assert_eq!(missing_contexts(&found), None);
        assert_eq!(missing_stacks_and_contexts(&found), None);
    }

    /// A thread that lost both is named once, by the line that says so.
    #[test]
    fn test_a_thread_that_lost_both_is_named_once() {
        let fake = Fake::new()
            .blank(STACK..STACK + WINDOW)
            .blank(CONTEXT..CONTEXT + WINDOW);
        let lwps = [lwp(7, STACK, TP)];
        let found = probe(&fake, &lwps);
        assert_eq!(
            found,
            [LwpCapture {
                tid: 7,
                stack: false,
                tls: false
            }]
        );
        assert_eq!(
            missing_stacks_and_contexts(&found).unwrap(),
            "the stack and thread-local storage for lwp 7 were not captured \
             in the core dump. A native stack trace will not be available \
             for this thread, and it will not be attributed to a runtime."
        );
        // The other two lines cover the losses this one does not.
        assert_eq!(missing_stacks(&found), None);
        assert_eq!(missing_contexts(&found), None);
    }

    /// Several threads that lost both, as the usual truncated core
    /// presents them: one run, named in the plural.
    #[test]
    fn test_several_threads_that_lost_both_read_as_runs() {
        let found: Vec<LwpCapture> = [16, 17]
            .into_iter()
            .map(|tid| LwpCapture {
                tid,
                stack: false,
                tls: false,
            })
            .collect();
        assert_eq!(
            missing_stacks_and_contexts(&found).unwrap(),
            "the stacks and thread-local storage for lwps [16-17] were not \
             captured in the core dump. Native stack traces will not be \
             available for these threads, and they will not be attributed \
             to a runtime."
        );
    }

    /// A thread with no thread pointer may not have had its TLS
    /// initialized yet. We cannot assume that zeroed TLS is a
    /// problem.
    #[test]
    fn test_a_thread_without_a_thread_pointer_keeps_its_verdict() {
        let fake = Fake::new();
        let lwps = [lwp(7, STACK, 0)];
        assert!(probe(&fake, &lwps).is_empty());
    }

    /// The window starts at the stack, not on the page boundary.
    /// The space below a stack pointer may be an popped frame.
    #[test]
    fn test_what_lies_below_an_anchor_is_not_held_against_it() {
        let fake = Fake::new().blank(STACK - 0x40..STACK);
        let lwps = [lwp(7, STACK, 0)];
        assert!(
            probe(&fake, &lwps).is_empty(),
            "the frame at and above the anchor still reads"
        );
    }

    /// Ensure we don't read off the end of the region.
    #[test]
    fn test_an_anchor_near_the_end_of_its_region_is_clamped() {
        let fake = Fake::new();
        let lwps = [lwp(7, REGION.end - 0x40, 0)];
        assert!(probe(&fake, &lwps).is_empty(), "the clamped window reads");
    }

    #[test]
    fn test_runs_collapse_to_contiguous_spans() {
        assert_eq!(runs(&[]), []);
        assert_eq!(runs(&[5]), [(5, 5)]);
        assert_eq!(runs(&[5, 6, 7]), [(5, 7)]);
        assert_eq!(runs(&[2, 3, 5]), [(2, 3), (5, 5)]);
        assert_eq!(
            runs(&[2, 3, 4, 9, 11, 12]),
            [(2, 4), (9, 9), (11, 12)],
            "a gap of one breaks a run"
        );
    }

    /// Each line takes only the lwps its own loss selects, and sorts
    /// what the core handed over in whatever order it liked.
    #[test]
    fn test_each_line_sorts_and_selects_what_the_core_hands_over() {
        let found = [
            LwpCapture {
                tid: 34,
                stack: false,
                tls: true,
            },
            LwpCapture {
                tid: 33,
                stack: false,
                tls: true,
            },
            LwpCapture {
                tid: 9,
                stack: true,
                tls: false,
            },
        ];
        assert_eq!(
            missing_stacks(&found).unwrap(),
            "the stacks for lwps [33-34] were not captured in the core dump. \
             Native stack traces will not be available for these threads.",
            "sorted, and 9 kept its stack"
        );
        assert_eq!(
            missing_contexts(&found).unwrap(),
            "the thread-local storage for lwp 9 was not captured in the \
             core dump. This thread will not be attributed to a runtime.",
            "only 9 lost its thread-local storage"
        );
        assert_eq!(missing_stacks_and_contexts(&found), None, "none lost both");
    }

    #[test]
    fn test_one_lost_thread_reads_as_one_thread() {
        let found = [LwpCapture {
            tid: 433,
            stack: false,
            tls: true,
        }];
        assert_eq!(
            missing_stacks(&found).unwrap(),
            "the stack for lwp 433 was not captured in the core dump. \
             A native stack trace will not be available for this thread."
        );
    }

    /// One run still shows a range.
    #[test]
    fn test_one_run_of_several_lwps_still_reads_as_several() {
        let found: Vec<LwpCapture> = [16, 17]
            .into_iter()
            .map(|tid| LwpCapture {
                tid,
                stack: false,
                tls: true,
            })
            .collect();
        assert_eq!(
            missing_stacks(&found).unwrap(),
            "the stacks for lwps [16-17] were not captured in the core dump. \
             Native stack traces will not be available for these threads."
        );
    }

    #[test]
    fn test_several_lost_threads_read_as_runs() {
        let found: Vec<LwpCapture> = [2, 3, 4, 17, 31, 32]
            .into_iter()
            .map(|tid| LwpCapture {
                tid,
                stack: false,
                tls: true,
            })
            .collect();
        assert_eq!(
            missing_stacks(&found).unwrap(),
            "the stacks for lwps [2-4], 17, [31-32] were not captured in \
             the core dump. Native stack traces will not be available for \
             these threads."
        );
    }
}

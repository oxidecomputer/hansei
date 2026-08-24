// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Joining a running task's committed await chain to the native stack
//! of the thread polling it.
//!
//! The chain a trace prints stops at the last committed await, and for
//! a mid-poll task the truth of what the poll is doing right now is on
//! the polling thread's native stack. This module is the pure
//! classifier over both: given the unwound frames, the address range
//! of the task's resolved poll symbol, and the committed chain's
//! future types, it finds the anchor, cuts the seam, and lays out the
//! novel frames as printable rows with panic plumbing folded. Reading
//! the target, resolving symbols and rendering stay with the caller.

use hansei_bundle::BundleTypeId;

use std::ops::Range;

/// One native frame as the classifier sees it, laid out by the caller
/// from the unwinder's output: innermost first, the order an unwinder
/// yields them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeFrame {
    /// The frame's program counter, tested against the poll symbol's
    /// address range.
    pub pc: u64,
    /// The demangled symbol name, empty for a frame without one. The
    /// classifier reads it only to recognize panic plumbing; what a
    /// row prints is the caller's business.
    pub name: String,
    /// The future types the frame's symbol resolved to through the
    /// bundle's poll-symbol join — empty for a symbol that is no
    /// known future's poll. Matching by resolved type id rather than
    /// by spelling is what bridges the coroutine namings: the frame's
    /// symbol demangles to `{closure#0}` where the bundle's type says
    /// `{async_fn_env#0}`, and the join already recorded the resume
    /// symbol against the env type.
    pub futures: Vec<BundleTypeId>,
}

/// Where the native stack continues a task's committed await chain:
/// the section below the seam, ready to number after the chain's last
/// frame. All indices index the input frames.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Continuation {
    /// The anchor: the innermost frame whose pc falls inside the
    /// task's resolved poll symbol. The scheduler frames outward of it
    /// never print.
    pub anchor: usize,
    /// The seam: the deepest native frame matching a committed chain
    /// frame's future type. `None` when no frame below the anchor
    /// matches — every committed counterpart was inlined away — and
    /// the section then starts directly below the anchor.
    pub seam: Option<Seam>,
    /// The section, in chain order — outermost native frame first,
    /// the unwinder's order reversed — with panic plumbing folded.
    pub rows: Vec<Row>,
}

/// The frame the native stack and the committed chain agree on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seam {
    /// Index of the matching native frame.
    pub frame: usize,
    /// Index into the committed chain of the matched future type —
    /// the deepest such chain frame, when one type recurs.
    pub chain: usize,
}

/// One printable row of the continuation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Row {
    /// One native frame, by index into the input frames.
    Frame(usize),
    /// A run of panic plumbing collapsed to one counted line: the
    /// half-open input-index range it spans. Printed whole under
    /// verbose, outermost first — descending index.
    Fold(Range<usize>),
}

/// Classify the polling thread's `frames` (innermost first) against a
/// running task: `poll` is the address range of the task's resolved
/// poll symbol, `chain` the committed await chain's future types, root
/// first.
///
/// `None` when no frame's pc falls inside `poll` — a stale claim, a
/// torn stack, the wrong thread — where gluing anything native onto
/// the chain would join two things that are not joined.
pub fn classify(
    frames: &[NativeFrame],
    poll: &Range<u64>,
    chain: &[BundleTypeId],
) -> Option<Continuation> {
    // The innermost frame inside the poll symbol. One task's poll is
    // on its thread's stack at most once; against a reentrant stack of
    // one shared monomorphization, the innermost poll is the one the
    // thread's claim names, and everything below it is that poll's own
    // work.
    let anchor = frames.iter().position(|f| poll.contains(&f.pc))?;

    // The deepest frame below the anchor whose resolved type is a
    // committed chain frame's: everything outward of it the chain
    // already tells, and better. The anchor itself is the task
    // harness, never a chain frame, and nothing above it can be one.
    let seam = frames[..anchor].iter().enumerate().find_map(|(i, f)| {
        let chain_ix = chain.iter().rposition(|ty| f.futures.contains(ty))?;
        Some(Seam {
            frame: i,
            chain: chain_ix,
        })
    });

    let below = seam.map_or(anchor, |s| s.frame);
    Some(Continuation {
        anchor,
        seam,
        rows: rows(&frames[..below]),
    })
}

/// The section as printable rows, outermost first, each maximal run of
/// panic plumbing folded to one row. A lone plumbing frame stays a
/// plain row: there is no run to count.
fn rows(section: &[NativeFrame]) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut i = section.len();
    while i > 0 {
        i -= 1;
        if !is_panic_plumbing(&section[i].name) {
            rows.push(Row::Frame(i));
            continue;
        }
        let mut lo = i;
        while lo > 0 && is_panic_plumbing(&section[lo - 1].name) {
            lo -= 1;
        }
        if lo == i {
            rows.push(Row::Frame(i));
        } else {
            rows.push(Row::Fold(lo..i + 1));
            i = lo;
        }
    }
    rows
}

/// Panic plumbing: the frames a panic-abort lays between the panic
/// site and the signal — `panic_fmt` through `abort`/`raise`/
/// `_lwp_kill` — which fold to one counted line. The rule errs
/// narrow: a spelling it misses splits one fold into two, which still
/// reads fine, where a spelling claimed wrongly hides a real frame —
/// so `std::sys` locks, allocators and thread plumbing must all stay
/// out.
fn is_panic_plumbing(name: &str) -> bool {
    // abort_internal has moved namespaces across toolchains
    // (`std::sys::unix`, `std::sys::pal::unix`); the leaf name is the
    // stable part.
    if name.starts_with("std::sys::") && name.ends_with("::abort_internal") {
        return true;
    }
    const PREFIXES: &[&str] = &[
        "core::panicking::",
        "std::panicking::",
        // The __rust_{begin,end}_short_backtrace markers.
        "std::sys::backtrace::",
        // __rustc::rust_begin_unwind and its unmangled shim spellings
        // (__rust_start_panic, __rust_end_short_backtrace).
        "__rust",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || matches!(
            name,
            "std::process::abort"
                | "abort"
                | "raise"
                | "gsignal"
                | "_lwp_kill"
                | "__lwp_kill"
                | "thr_kill"
                | "pthread_kill"
                | "__pthread_kill"
                | "__pthread_kill_implementation"
                | "__pthread_kill_internal"
        )
}

#[cfg(test)]
mod tests {
    use super::{Continuation, NativeFrame, Row, Seam, classify, is_panic_plumbing};

    use hansei_bundle::BundleTypeId;

    /// A frame whose symbol is no known future's poll.
    fn frame(pc: u64, name: &str) -> NativeFrame {
        NativeFrame {
            pc,
            name: name.to_owned(),
            futures: Vec::new(),
        }
    }

    /// A frame whose symbol the poll-symbol join resolved to future
    /// types.
    fn poll_frame(pc: u64, name: &str, futures: &[u32]) -> NativeFrame {
        NativeFrame {
            futures: futures.iter().map(|&id| BundleTypeId(id)).collect(),
            ..frame(pc, name)
        }
    }

    const POLL: std::ops::Range<u64> = 0x5000..0x5100;

    /// The healthy-capture shape: the chain bottoms in a set, and the
    /// join shows the specific child parked on the allocator mutex.
    /// The seam cuts at the deepest chain counterpart — the set's poll
    /// — and every novel frame below it prints, outermost first, with
    /// nothing folded: contended locks and allocator frames are the
    /// finding, not plumbing.
    #[test]
    fn test_the_seam_cuts_at_the_deepest_chain_counterpart() {
        let chain = [BundleTypeId(10), BundleTypeId(11), BundleTypeId(12)];
        let frames = [
            frame(0x9000, "__lwp_park"),                                          // 0
            frame(0x9010, "mutex_lock"),                                          // 1
            frame(0x9020, "vmem_xalloc"),                                         // 2
            frame(0x9030, "memalign"),                                            // 3
            poll_frame(0x9040, "reqwest::connect::{closure#0}", &[77]), // 4: a child, not in the chain
            poll_frame(0x9050, "<FuturesUnordered as Future>::poll_next", &[12]), // 5: chain #2
            poll_frame(0x9060, "nexus::saga::{closure#0}", &[10]),      // 6: chain #0
            frame(0x9070, "tokio::runtime::task::harness::poll"),       // 7
            frame(0x5010, "tokio::runtime::task::raw::poll"),           // 8: anchor
            frame(0x9090, "tokio::runtime::scheduler::run"),            // 9
        ];
        let joined = classify(&frames, &POLL, &chain).expect("the poll frame anchors");
        assert_eq!(
            joined,
            Continuation {
                anchor: 8,
                seam: Some(Seam { frame: 5, chain: 2 }),
                rows: vec![
                    Row::Frame(4),
                    Row::Frame(3),
                    Row::Frame(2),
                    Row::Frame(1),
                    Row::Frame(0),
                ],
            }
        );
    }

    /// The panic-abort shape: the seam cuts at the panicking async
    /// fn's counterpart, the panic site prints, and the plumbing run
    /// from `panic_fmt` to the kill folds to one row spanning exactly
    /// those frames.
    #[test]
    fn test_the_plumbing_run_folds_to_one_row() {
        let chain = [BundleTypeId(20)];
        let frames = [
            frame(0x9000, "_lwp_kill"),                                        // 0
            frame(0x9010, "raise"),                                            // 1
            frame(0x9020, "abort"),                                            // 2
            frame(0x9030, "std::sys::pal::unix::abort_internal"),              // 3
            frame(0x9040, "std::panicking::rust_panic"),                       // 4
            frame(0x9050, "std::panicking::rust_panic_with_hook"),             // 5
            frame(0x9060, "std::panicking::begin_panic_handler::{closure#0}"), // 6
            frame(0x9070, "std::sys::backtrace::__rust_end_short_backtrace"),  // 7
            frame(0x9080, "std::panicking::begin_panic_handler"),              // 8
            frame(0x9090, "core::panicking::panic_fmt"),                       // 9
            frame(0x90a0, "panic_join::boom"),                                 // 10
            poll_frame(0x90b0, "panic_join::main::{closure#0}", &[20]),        // 11: chain #0
            frame(0x90c0, "core::panic::unwind_safe::AssertUnwindSafe"),       // 12
            frame(0x5020, "tokio::runtime::task::raw::poll"),                  // 13: anchor
            frame(0x90e0, "tokio::runtime::scheduler::run"),                   // 14
        ];
        let joined = classify(&frames, &POLL, &chain).expect("the poll frame anchors");
        assert_eq!(
            joined,
            Continuation {
                anchor: 13,
                seam: Some(Seam {
                    frame: 11,
                    chain: 0
                }),
                rows: vec![Row::Frame(10), Row::Fold(0..10)],
            }
        );
    }

    /// The release-crash shape: chain counterparts inlined away leave
    /// nothing to match, so the section starts directly below the
    /// anchor — including the frame the wild call left with no symbol
    /// at all. A chain-typed frame *above* the anchor is scheduler
    /// territory and never binds the seam.
    #[test]
    fn test_committed_counterparts_inlined_away_cut_below_the_anchor() {
        let chain = [BundleTypeId(30), BundleTypeId(31)];
        let frames = [
            frame(0x0, ""),                                        // 0: the wild pc
            frame(0x9010, "rama::service::dispatch"),              // 1
            frame(0x9020, "rama::stream::next"),                   // 2
            frame(0x5000, "tokio::runtime::task::raw::poll"), // 3: anchor, at the range's first byte
            poll_frame(0x9040, "other::task::{closure#0}", &[30]), // 4: above the anchor
        ];
        let joined = classify(&frames, &POLL, &chain).expect("the poll frame anchors");
        assert_eq!(
            joined,
            Continuation {
                anchor: 3,
                seam: None,
                rows: vec![Row::Frame(2), Row::Frame(1), Row::Frame(0)],
            }
        );
    }

    /// No frame inside the poll symbol refuses the join outright, even
    /// when chain-typed frames are present: that is the stale-claim /
    /// torn-stack shape, where the native stack is somebody else's.
    #[test]
    fn test_a_stack_without_the_poll_symbol_refuses() {
        let chain = [BundleTypeId(10)];
        let frames = [
            poll_frame(0x9000, "nexus::saga::{closure#0}", &[10]),
            frame(0x9010, "tokio::runtime::scheduler::run"),
        ];
        assert_eq!(classify(&frames, &POLL, &chain), None);
    }

    /// The anchor's containment is half-open — the symbol's end is the
    /// next symbol's start — and of several frames inside the range
    /// the innermost anchors: on a reentrant stack of one shared
    /// monomorphization, the innermost poll is the claimed one.
    #[test]
    fn test_the_anchor_is_the_innermost_frame_in_the_poll_symbol() {
        let frames = [
            frame(0x9000, "work"),
            frame(POLL.end, "past::the::symbol"),
            frame(POLL.start, "task::raw::poll"),
            frame(POLL.end - 1, "task::raw::poll"),
        ];
        let joined = classify(&frames, &POLL, &[]).expect("two frames are in range");
        assert_eq!(joined.anchor, 2);
        assert_eq!(joined.rows, vec![Row::Frame(1), Row::Frame(0)]);
    }

    /// A seam at the innermost frame means execution is exactly at the
    /// committed leaf: there is nothing novel to print.
    #[test]
    fn test_an_execution_at_the_committed_leaf_prints_nothing() {
        let chain = [BundleTypeId(10), BundleTypeId(11)];
        let frames = [
            poll_frame(0x9000, "leaf::{closure#0}", &[11]),
            frame(0x5000, "task::raw::poll"),
        ];
        let joined = classify(&frames, &POLL, &chain).expect("the poll frame anchors");
        assert_eq!(
            joined,
            Continuation {
                anchor: 1,
                seam: Some(Seam { frame: 0, chain: 1 }),
                rows: Vec::new(),
            }
        );
    }

    /// When one future type recurs in the chain, the seam reports the
    /// deepest committed frame of that type — the numbering below it
    /// continues from the chain's own leaf, so the join must not claim
    /// the section continues an outer frame. An ambiguous symbol
    /// resolution (several candidate types) matches through any of
    /// its candidates.
    #[test]
    fn test_the_seam_reports_the_deepest_chain_frame_of_a_recurring_type() {
        let chain = [
            BundleTypeId(40),
            BundleTypeId(41),
            BundleTypeId(40),
            BundleTypeId(42),
        ];
        let frames = [
            frame(0x9000, "work"),
            poll_frame(0x9010, "recurse::{closure#0}", &[99, 40]),
            frame(0x5000, "task::raw::poll"),
        ];
        let joined = classify(&frames, &POLL, &chain).expect("the poll frame anchors");
        assert_eq!(joined.seam, Some(Seam { frame: 1, chain: 2 }));
    }

    /// A lone plumbing frame prints plain — there is no run to count —
    /// and two runs split by a real frame fold separately rather than
    /// swallowing what sits between them.
    #[test]
    fn test_folds_span_only_unbroken_runs() {
        let frames = [
            frame(0x9000, "raise"),                      // 0
            frame(0x9010, "abort"),                      // 1
            frame(0x9020, "app::handler"),               // 2
            frame(0x9030, "core::panicking::panic_fmt"), // 3
            frame(0x9040, "app::outer"),                 // 4
            frame(0x5000, "task::raw::poll"),            // 5: anchor
        ];
        let joined = classify(&frames, &POLL, &[]).expect("the poll frame anchors");
        assert_eq!(
            joined.rows,
            vec![Row::Frame(4), Row::Frame(3), Row::Frame(2), Row::Fold(0..2),]
        );
    }

    /// The plumbing rule errs narrow: the panic and abort paths fold,
    /// and everything a task legitimately parks in — `std::sys` locks,
    /// allocator internals, unnamed frames — stays a printed row.
    #[test]
    fn test_the_plumbing_rule_errs_narrow() {
        for name in [
            "core::panicking::panic_fmt",
            "std::panicking::rust_panic_with_hook",
            "std::panicking::begin_panic_handler::{closure#0}",
            "std::sys::backtrace::__rust_end_short_backtrace",
            "std::sys::pal::unix::abort_internal",
            "std::sys::unix::abort_internal",
            "std::process::abort",
            "__rustc::rust_begin_unwind",
            "__rust_start_panic",
            "abort",
            "raise",
            "_lwp_kill",
            "__pthread_kill_implementation",
        ] {
            assert!(is_panic_plumbing(name), "{name} should fold");
        }
        for name in [
            "",
            "std::sys::sync::mutex::futex::Mutex::lock",
            "std::sys::pal::unix::thread::Thread::new",
            "memalign",
            "mutex_lock",
            "__lwp_park",
            "aborted::cleanup",
            "app::abort",
        ] {
            assert!(!is_panic_plumbing(name), "{name} should print");
        }
    }
}

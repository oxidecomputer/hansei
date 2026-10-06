// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Waiting, from outside a fixture, until every one of its threads is
//! asleep: the check `test_programs::quiesce` makes from inside, which
//! cannot include the thread making it.
//!
//! A fixture prints its readiness marker from a thread that is still
//! running: it goes on to finish what it was doing and park, and in
//! futurelock the marker's thread is a task that then completes and is
//! freed. A core taken the moment the marker is read can catch any of
//! that half done. So [`settle`] holds the capture until two passes in
//! a row find every thread asleep, each having left the CPU no further
//! times between them — nothing ran in the interval, so nothing was set
//! in motion in it either.
//!
//! The procfs reads mirror test-programs' own (`test_programs::sleeping`),
//! which the fixture crate cannot share: it is a workspace of its own,
//! its dependencies pinned per matrix cell.

use std::time::{Duration, Instant};

/// How long a fixture may take to settle before the capture fails
/// naming the threads still awake: a program that never settles is a
/// fixture bug, better reported as one than as a per-test timeout.
const LIMIT: Duration = Duration::from_secs(60);

/// Block until every thread of `pid` is asleep on two passes in a row,
/// with no context switch between them. `program` names it in the
/// failure.
pub(super) fn settle(pid: u32, program: &str) {
    let start = Instant::now();
    let mut last = None;
    loop {
        match pass(pid) {
            Some(now) if last.as_ref() == Some(&now) => return,
            now => last = now,
        }
        if start.elapsed() > LIMIT {
            panic!(
                "{program} (pid {pid}) did not settle within {LIMIT:?} of its \
                 readiness marker; threads still awake: {:?}",
                awake(pid)
            );
        }
        std::thread::yield_now();
    }
}

/// Each thread's id and switch count, in id order, if every thread is
/// asleep; `None` if any is not.
fn pass(pid: u32) -> Option<Vec<(u32, u64)>> {
    thread_ids(pid)
        .into_iter()
        .map(|id| asleep(pid, id).then(|| (id, switches(pid, id))))
        .collect()
}

fn awake(pid: u32) -> Vec<u32> {
    thread_ids(pid)
        .into_iter()
        .filter(|&id| !asleep(pid, id))
        .collect()
}

/// The numeric entries of a procfs directory, in order. A process that
/// has gone has none, and settles at once: the capture then fails on
/// its own terms.
#[cfg(any(target_os = "linux", target_os = "illumos"))]
fn listed(dir: &str) -> Vec<u32> {
    let mut ids: Vec<u32> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    ids.sort_unstable();
    ids
}

/// A thread's `stat` holds its state after its parenthesized comm: `S`,
/// interruptible sleep, is where a parked worker, a blocked `recv` and
/// an `epoll_wait` all are. Its `status` counts the voluntary and
/// involuntary context switches.
#[cfg(target_os = "linux")]
mod procfs {
    pub fn thread_ids(pid: u32) -> Vec<u32> {
        super::listed(&format!("/proc/{pid}/task"))
    }

    pub fn asleep(pid: u32, id: u32) -> bool {
        let Ok(line) = std::fs::read_to_string(format!("/proc/{pid}/task/{id}/stat")) else {
            // The thread is gone, which is as quiet as it gets.
            return true;
        };
        let after_comm = line.rsplit_once(')').map_or("", |(_, rest)| rest);
        after_comm.split_whitespace().next() == Some("S")
    }

    pub fn switches(pid: u32, id: u32) -> u64 {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/task/{id}/status")) else {
            return 0;
        };
        status
            .lines()
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.ends_with("voluntary_ctxt_switches")
                    .then(|| value.trim().parse::<u64>().ok())
                    .flatten()
            })
            .sum()
    }
}

/// An lwp's `lwpstatus` opens with `pr_flags`, which carries
/// `PR_ASLEEP` while it sleeps in a system call; its `lwpusage` holds
/// the voluntary and involuntary context switches at their offsets in
/// the 64-bit `prusage_t` of `<procfs.h>`.
#[cfg(target_os = "illumos")]
mod procfs {
    const PR_ASLEEP: i32 = 0x10;
    const PR_VCTX: usize = 392;
    const PR_ICTX: usize = 400;

    pub fn thread_ids(pid: u32) -> Vec<u32> {
        super::listed(&format!("/proc/{pid}/lwp"))
    }

    pub fn asleep(pid: u32, id: u32) -> bool {
        let Ok(bytes) = std::fs::read(format!("/proc/{pid}/lwp/{id}/lwpstatus")) else {
            // The lwp is gone, which is as quiet as it gets.
            return true;
        };
        let head = bytes.get(..4).expect("lwpstatus opens with pr_flags");
        let flags = i32::from_ne_bytes(head.try_into().expect("four bytes are an int"));
        flags & PR_ASLEEP != 0
    }

    pub fn switches(pid: u32, id: u32) -> u64 {
        let Ok(bytes) = std::fs::read(format!("/proc/{pid}/lwp/{id}/lwpusage")) else {
            return 0;
        };
        let word = |at: usize| {
            let b = bytes.get(at..at + 8).expect("lwpusage holds a prusage_t");
            u64::from_ne_bytes(b.try_into().expect("eight bytes are a ulong"))
        };
        word(PR_VCTX) + word(PR_ICTX)
    }
}

/// No fixture is cored anywhere else, so there is nothing to wait for.
#[cfg(not(any(target_os = "linux", target_os = "illumos")))]
mod procfs {
    pub fn thread_ids(_pid: u32) -> Vec<u32> {
        Vec::new()
    }

    pub fn asleep(_pid: u32, _id: u32) -> bool {
        true
    }

    pub fn switches(_pid: u32, _id: u32) -> u64 {
        0
    }
}

use procfs::{asleep, switches, thread_ids};

#[cfg(all(test, any(target_os = "linux", target_os = "illumos")))]
mod tests {
    use super::{pass, settle};

    use std::process::{Command, Stdio};

    /// A process asleep in a system call settles: two passes find its
    /// one thread asleep with nothing run between them. One that has
    /// gone settles at once, leaving the capture to fail on its own
    /// terms.
    #[test]
    fn test_a_sleeping_process_settles_and_a_gone_one_does_not_block() {
        let mut child = Command::new("sleep")
            .arg("600")
            .stdout(Stdio::null())
            .spawn()
            .expect("failed to run sleep");
        let pid = child.id();
        settle(pid, "sleep");
        assert!(
            pass(pid).is_some_and(|threads| threads.len() == 1),
            "sleep did not read back as one sleeping thread"
        );
        let _ = child.kill();
        let _ = child.wait();
        settle(pid, "a reaped process");
        assert_eq!(pass(pid), Some(Vec::new()));
    }
}

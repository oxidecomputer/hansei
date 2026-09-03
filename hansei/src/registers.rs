// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The annotated `registers:` block `threads` and `trace` share: one
//! line per general-purpose register, each annotated with what the
//! value points into — the claims the pure classifier
//! ([`hansei_runtime::tokio::registers`]) makes from the session's
//! recorded joins, spelled here.

use crate::Session;
use crate::tasks::task_label;

use anyhow::{Result, anyhow};
use hansei_runtime::heap::umem::Liveness;
use hansei_runtime::tokio::registers::{LwpStack, RegClass, RegClassifier};

use std::io;

/// The 17 general-purpose registers, in the order the block prints
/// them: the trap trio first, then the argument/value registers, then
/// the numbered ones. Segments, flags and fsbase are noise here;
/// anyone who needs them has the core.
fn gprs(regs: &proc::Regs) -> [(&'static str, u64); 17] {
    [
        ("rip", regs.rip),
        ("rsp", regs.rsp),
        ("rbp", regs.rbp),
        ("rax", regs.rax),
        ("rbx", regs.rbx),
        ("rcx", regs.rcx),
        ("rdx", regs.rdx),
        ("rsi", regs.rsi),
        ("rdi", regs.rdi),
        ("r8", regs.r8),
        ("r9", regs.r9),
        ("r10", regs.r10),
        ("r11", regs.r11),
        ("r12", regs.r12),
        ("r13", regs.r13),
        ("r14", regs.r14),
        ("r15", regs.r15),
    ]
}

/// `regs`: the cursor lwp's annotated register block — a thread
/// cursor, or a task cursor whose task is mid-poll on one (selecting
/// a running task selects the lwp polling it). A task off every
/// thread has no trap state to show, which the refusal says.
pub(crate) fn exec_regs<T: proc::Target>(
    session: &Session<'_, T>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let cursor = *session.cursor.borrow();
    if let Some(lwp) = cursor.lwp {
        return print_lwp_registers(session, lwp, "", out);
    }
    if cursor.root.is_some() {
        writeln!(out, "registers not available, task is not on a thread")?;
        return Ok(());
    }
    Err(anyhow!(
        "no task or thread selected; `task`, `future` or `thread` selects one"
    ))
}

/// Print one lwp's annotated register block, indented for the caller's
/// section. Frame-0 trap state only: past frame 0 the unwinder
/// restores only callee-saved registers, and printing the rest would
/// be confident zeros.
pub(crate) fn print_lwp_registers<T: proc::Target>(
    session: &Session<'_, T>,
    lwp: u32,
    indent: &str,
    out: &mut dyn io::Write,
) -> Result<()> {
    let Some(info) = session.lwps.iter().find(|l| l.tid == lwp) else {
        // Workers come from the lwp list, so this is a torn core's
        // path, not an expected one.
        writeln!(out, "{indent}registers: none recorded for lwp {lwp}")?;
        return Ok(());
    };
    let stacks: Vec<LwpStack> = session
        .lwps
        .iter()
        .map(|l| LwpStack {
            tid: l.tid,
            rsp: l.regs.rsp,
            range: l.stack_range.clone(),
            altstack: l.altstack.clone(),
        })
        .collect();
    let classifier = RegClassifier {
        mappings: &session.ctx.mappings,
        stacks: &stacks,
        extents: session.extents(),
    };
    let list = &session.tasks;
    let symbol = |addr: u64| session.proc.lookup_symbol_by_addr(addr);
    let heap = session.umem();
    let annotate = |value: u64| {
        let claim = spelled(&classifier.classify(lwp, value, &symbol), lwp, &|index| {
            task_label(list, index)
        });
        let freed = matches!(
            heap.map(|heap| heap.locate(value)),
            Some(Liveness::Freed { .. })
        );
        marked(claim, freed)
    };
    print_registers(out, indent, &info.regs, &annotate)
}

/// Lay the block out: the `registers:` heading, then one line per
/// register — name, value, and the annotation when there is a claim.
fn print_registers(
    out: &mut dyn io::Write,
    indent: &str,
    regs: &proc::Regs,
    annotate: &dyn Fn(u64) -> Option<String>,
) -> Result<()> {
    writeln!(out, "{indent}registers:")?;
    for (name, value) in gprs(regs) {
        match annotate(value) {
            Some(claim) => writeln!(out, "{indent}  {name:<3}  {value:#018x}  — {claim}")?,
            None => writeln!(out, "{indent}  {name:<3}  {value:#018x}")?,
        }
    }
    Ok(())
}

/// Add the one word an allocator verdict is worth here: a register
/// pointing into memory the allocator has taken back is holding a
/// pointer to nothing, whatever the classifier made of where it points.
///
/// Only `freed` is marked. Live is the ordinary case — most of a
/// register file that holds pointers at all points into live
/// allocations — and a word on every one of seventeen lines per thread
/// would bury the one line worth reading. The mark is an alarm, not a
/// status.
fn marked(claim: Option<String>, freed: bool) -> Option<String> {
    match (claim, freed) {
        (Some(claim), true) => Some(format!("{claim} (freed)")),
        (claim, _) => claim,
    }
}

/// Spell one classification as the annotation the block prints — or
/// nothing, for a value with no claim to make. `label` names a task by
/// its index in the session's list, the way every listing does, and
/// `lwp` is the thread whose registers these are, which is what lets a
/// stack say whose it is.
///
/// Every mapping-kind claim is spelled the way `pmap` spells it,
/// brackets and all. That is not decoration: someone reading a core has
/// `pmap` open in the next window, and a descriptor they can match by
/// eye is worth more than prose that says the same thing differently.
fn spelled(class: &RegClass, lwp: u32, label: &dyn Fn(usize) -> String) -> Option<String> {
    Some(match class {
        RegClass::Task { index, offset } => match offset {
            0 => label(*index),
            offset => format!("{} +{offset:#x}", label(*index)),
        },
        RegClass::OwnStack => format!("[ stack tid={lwp} ]"),
        RegClass::LwpStack(tid) => format!("[ stack tid={tid} ]"),
        // `pmap`'s bare `[ stack ]`: a stack mapping it cannot pin to
        // one thread, which is the same thing this class means.
        RegClass::StackRegion => "[ stack ]".to_string(),
        RegClass::Symbol { name, offset } => {
            let name = format!("{:#}", rustc_demangle::demangle(name));
            match offset {
                0 => name,
                offset => format!("{name} +{offset:#x}"),
            }
        }
        // The path whole would drown the line; the object's name and
        // the region within it are the claim. The region is what is
        // left to say where no symbol covers the address: text is a
        // return address or a constant beside the code, data a static
        // nothing named.
        RegClass::Object { path, region } => {
            let base = path.rsplit('/').next().unwrap_or(path);
            format!("in {base} {region}")
        }
        // Exactly one anonymous mapping is the break, and the rest —
        // an allocator's mmap-backed arenas, a threading library's own
        // tables, guard pages — are only anonymous. Naming them all
        // heap would assert something false about all but one.
        RegClass::AltStack(tid) => format!("[ altstack tid={tid} ]"),
        RegClass::Heap => "[ heap ]".to_string(),
        RegClass::Anon => "[ anon ]".to_string(),
        RegClass::Unmapped => "unmapped".to_string(),
        // A zero register is legible as zero; annotating it says
        // nothing the value has not already said, and on a thread
        // where most registers are zero the annotations that matter
        // are the ones lost in that column.
        RegClass::Null | RegClass::Small => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{marked, print_registers, spelled};
    use hansei_runtime::tokio::registers::RegClass;

    /// Each claim's spelling, and the one silence: offsets ride along
    /// only when nonzero, symbols demangle, objects shed their
    /// directories.
    #[test]
    fn test_each_claim_has_one_spelling() {
        let label = |index: usize| format!("task {}", index + 30);
        // 2 is the lwp whose registers are being read, which is
        // what an `OwnStack` claim names itself with.
        let spell = |class| spelled(&class, 2, &label);
        assert_eq!(
            spell(RegClass::Task {
                index: 5,
                offset: 0x10
            })
            .as_deref(),
            Some("task 35 +0x10")
        );
        assert_eq!(
            spell(RegClass::Task {
                index: 5,
                offset: 0
            })
            .as_deref(),
            Some("task 35")
        );
        // A stack names whose it is, and the lwp being read names
        // its own — so the two are told apart by the tid rather than
        // by a different sentence.
        assert_eq!(
            spell(RegClass::OwnStack).as_deref(),
            Some("[ stack tid=2 ]")
        );
        assert_eq!(
            spell(RegClass::LwpStack(12)).as_deref(),
            Some("[ stack tid=12 ]")
        );
        assert_eq!(spell(RegClass::StackRegion).as_deref(), Some("[ stack ]"));
        assert_eq!(
            spell(RegClass::Symbol {
                name: "_ZN4core3fut4pollE".to_string(),
                offset: 0x1c
            })
            .as_deref(),
            Some("core::fut::poll +0x1c")
        );
        assert_eq!(
            spell(RegClass::Object {
                path: "/usr/lib/libc.so.6".to_string(),
                region: "data",
            })
            .as_deref(),
            Some("in libc.so.6 data")
        );
        // Every mapping-kind claim is spelled exactly as `pmap`
        // spells it, so a reader can match the two by eye. The three
        // anonymous ones stay apart because they are three different
        // facts: the break, a thread's alternate signal stack, and
        // memory that is merely anonymous.
        assert_eq!(spell(RegClass::Heap).as_deref(), Some("[ heap ]"));
        assert_eq!(spell(RegClass::Anon).as_deref(), Some("[ anon ]"));
        assert_eq!(
            spell(RegClass::AltStack(12)).as_deref(),
            Some("[ altstack tid=12 ]")
        );
        assert_eq!(spell(RegClass::Unmapped).as_deref(), Some("unmapped"));
        // Zero and a small integer both make no claim worth printing;
        // the classifier still tells them apart, the block does not.
        assert_eq!(spell(RegClass::Null), None);
        assert_eq!(spell(RegClass::Small), None);
    }

    /// The freed mark rides on the claim rather than replacing it, and
    /// nothing else changes: a live value is spelled exactly as it was
    /// before the allocator had anything to say, and a value with no
    /// claim to make stays silent whether or not it is freed.
    #[test]
    fn test_only_a_freed_value_is_marked() {
        let claim = || Some("heap".to_string());
        assert_eq!(marked(claim(), true).as_deref(), Some("heap (freed)"));
        assert_eq!(marked(claim(), false).as_deref(), Some("heap"));
        assert_eq!(marked(None, true), None);
        assert_eq!(marked(None, false), None);
    }

    /// The block whole: the heading at the caller's indent, all 17
    /// registers in their fixed order, the annotation set off by the
    /// dash only where there is a claim.
    #[test]
    fn test_the_block_prints_seventeen_annotated_gprs() {
        let regs = proc::Regs {
            rip: 0x40_0000,
            rsp: 0x9000_0800,
            rbp: 0x9000_0900,
            rax: 0,
            rbx: 0x14,
            ..proc::Regs::default()
        };
        let annotate = |value: u64| match value {
            0x40_0000 => Some("app_main".to_string()),
            0x9000_0800 | 0x9000_0900 => Some("[ stack tid=2 ]".to_string()),
            _ => None,
        };
        let mut out = Vec::new();
        print_registers(&mut out, "  ", &regs, &annotate).expect("the block renders");
        let out = String::from_utf8(out).expect("rendered output is UTF-8");
        assert_eq!(
            out,
            "  registers:
    rip  0x0000000000400000  — app_main
    rsp  0x0000000090000800  — [ stack tid=2 ]
    rbp  0x0000000090000900  — [ stack tid=2 ]
    rax  0x0000000000000000
    rbx  0x0000000000000014
    rcx  0x0000000000000000
    rdx  0x0000000000000000
    rsi  0x0000000000000000
    rdi  0x0000000000000000
    r8   0x0000000000000000
    r9   0x0000000000000000
    r10  0x0000000000000000
    r11  0x0000000000000000
    r12  0x0000000000000000
    r13  0x0000000000000000
    r14  0x0000000000000000
    r15  0x0000000000000000
",
        );
    }
}

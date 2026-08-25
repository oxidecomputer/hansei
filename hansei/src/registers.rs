//! The annotated `registers:` block `threads` and `trace` share: one
//! line per general-purpose register, each annotated with what the
//! value points into — the claims the pure classifier
//! ([`hansei_runtime::tokio::registers`]) makes from the session's
//! recorded joins, spelled here.

use crate::Session;
use crate::tasks::task_label;

use anyhow::Result;
use hansei_runtime::tokio::registers::{LwpStack, RegClass, RegClassifier};
use proc::Target as _;

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

/// Print one lwp's annotated register block, indented for the caller's
/// section. Frame-0 trap state only: past frame 0 the unwinder
/// restores only callee-saved registers, and printing the rest would
/// be confident zeros.
pub(crate) fn print_lwp_registers(
    session: &Session<'_>,
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
        })
        .collect();
    let classifier = RegClassifier {
        mappings: &session.ctx.mappings,
        stacks: &stacks,
        extents: session.extents(),
        reach: Some(session.reach()),
    };
    let list = &session.tasks;
    let symbol = |addr: u64| session.proc.lookup_symbol_by_addr(addr);
    let type_name = |ty| match session.ctx.view.ty(ty) {
        Some(ty) => {
            hansei_bundle::names::fold_type_name(ty.name(), &session.impl_fold).into_owned()
        }
        None => "<type the bundle does not carry>".to_string(),
    };
    let annotate = |value: u64| {
        spelled(
            &classifier.classify(lwp, value, &symbol),
            &|index| task_label(list, index),
            &type_name,
        )
    };
    print_registers(out, indent, &info.regs, &annotate)
}

/// One annotation, as the hop segments it may wrap between: a simple
/// claim is one segment, a reachability path one per hop. Segments are
/// joined with ` -> ` when laid out, and a line breaks only between
/// them — never inside a step or a type name, whatever arrows those
/// happen to contain.
type Claim = Vec<String>;

/// Where a wrapped annotation line ends: total columns, prefix and
/// claim together.
const ANNOTATION_WIDTH: usize = 80;

/// Lay the block out: the `registers:` heading, then one line per
/// register — name, value, and the annotation when there is a claim.
/// A claim past [`ANNOTATION_WIDTH`] columns wraps at its hops, each
/// continuation indented four columns past where the claim starts.
fn print_registers(
    out: &mut dyn io::Write,
    indent: &str,
    regs: &proc::Regs,
    annotate: &dyn Fn(u64) -> Option<Claim>,
) -> Result<()> {
    writeln!(out, "{indent}registers:")?;
    for (name, value) in gprs(regs) {
        match annotate(value) {
            Some(claim) => {
                let prefix = format!("{indent}  {name:<3}  {value:#018x}  — ");
                let start = prefix.chars().count();
                let mut lines = wrap_hops(&claim, start, ANNOTATION_WIDTH).into_iter();
                writeln!(out, "{prefix}{}", lines.next().unwrap_or_default())?;
                for line in lines {
                    writeln!(out, "{}{line}", " ".repeat(start + 4))?;
                }
            }
            None => writeln!(out, "{indent}  {name:<3}  {value:#018x}")?,
        }
    }
    Ok(())
}

/// Lay a claim's segments into lines for a first line starting at
/// column `start`, breaking only between segments: the first rides the
/// register's own line, each continuation opens with its arrow. A
/// segment longer than the width stays whole.
fn wrap_hops(claim: &[String], start: usize, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut col = start;
    for (i, hop) in claim.iter().enumerate() {
        let sep = if i == 0 { 0 } else { " -> ".len() };
        let len = hop.chars().count();
        if i > 0 && col + sep + len > width {
            lines.push(std::mem::take(&mut current));
            current = format!("-> {hop}");
            col = start + 4 + current.chars().count();
            continue;
        }
        if i > 0 {
            current.push_str(" -> ");
        }
        current.push_str(hop);
        col += sep + len;
    }
    lines.push(current);
    lines
}

/// Spell one classification as the annotation the block prints — or
/// nothing, for a value with no claim to make. `label` names a task by
/// its index in the session's list, the way every listing does;
/// `type_name` folds a bundle type id to its display name.
fn spelled(
    class: &RegClass,
    label: &dyn Fn(usize) -> String,
    type_name: &dyn Fn(hansei_bundle::BundleTypeId) -> String,
) -> Option<Claim> {
    Some(vec![match class {
        RegClass::Reached {
            owner,
            via,
            path,
            ty,
            offset,
            claimants,
            claimants_clipped,
        } => {
            // One segment per hop: the head carries the task and the
            // path's first step, the landing type is the last — with
            // the offset and the sharers riding it.
            let mut head = label(*owner);
            if !via.is_empty() {
                head.push_str(&format!(" ({via})"));
            }
            head.push_str(" via ");
            let mut steps = path.iter();
            head.push_str(steps.next().map(String::as_str).unwrap_or_default());
            let mut segments = vec![head];
            segments.extend(steps.cloned());
            let mut last = type_name(*ty);
            if *offset != 0 {
                last.push_str(&format!(" +{offset:#x}"));
            }
            if !claimants.is_empty() {
                let tasks: Vec<String> = claimants.iter().map(|&t| label(t as usize)).collect();
                let more = if *claimants_clipped {
                    " (and others)"
                } else {
                    ""
                };
                last.push_str(&format!(", shared with {}{more}", tasks.join(", ")));
            }
            segments.push(last);
            return Some(segments);
        }
        RegClass::Task { index, offset } => match offset {
            0 => label(*index),
            offset => format!("{} +{offset:#x}", label(*index)),
        },
        RegClass::OwnStack => "this lwp's stack".to_string(),
        RegClass::LwpStack(tid) => format!("lwp {tid}'s stack"),
        RegClass::StackRegion => "thread-stack region".to_string(),
        RegClass::Symbol { name, offset } => {
            let name = format!("{:#}", rustc_demangle::demangle(name));
            match offset {
                0 => name,
                offset => format!("{name} +{offset:#x}"),
            }
        }
        // The path whole would drown the line; the object's name is
        // the claim.
        RegClass::Object(path) => {
            let base = path.rsplit('/').next().unwrap_or(path);
            format!("in {base}")
        }
        RegClass::Heap => "heap".to_string(),
        RegClass::Unmapped => "unmapped".to_string(),
        RegClass::Small => return None,
    }])
}

#[cfg(test)]
mod tests {
    use super::{print_registers, spelled};
    use hansei_runtime::tokio::registers::RegClass;

    /// Each claim's spelling, and the one silence: offsets ride along
    /// only when nonzero, symbols demangle, objects shed their
    /// directories.
    #[test]
    fn test_each_claim_has_one_spelling() {
        let label = |index: usize| format!("task {}", index + 30);
        let ty = |_| "T".to_string();
        let spell = |class| spelled(&class, &label, &ty).map(|claim| claim.join(" -> "));
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
        assert_eq!(
            spell(RegClass::OwnStack).as_deref(),
            Some("this lwp's stack")
        );
        assert_eq!(
            spell(RegClass::LwpStack(12)).as_deref(),
            Some("lwp 12's stack")
        );
        assert_eq!(
            spell(RegClass::StackRegion).as_deref(),
            Some("thread-stack region")
        );
        assert_eq!(
            spell(RegClass::Symbol {
                name: "_ZN4core3fut4pollE".to_string(),
                offset: 0x1c
            })
            .as_deref(),
            Some("core::fut::poll +0x1c")
        );
        assert_eq!(
            spell(RegClass::Object("/usr/lib/libc.so.6".to_string())).as_deref(),
            Some("in libc.so.6")
        );
        assert_eq!(spell(RegClass::Heap).as_deref(), Some("heap"));
        assert_eq!(spell(RegClass::Unmapped).as_deref(), Some("unmapped"));
        assert_eq!(spell(RegClass::Small), None);
    }

    /// The top rung's spelling: the owning task, the root's via in
    /// parens when there is one, the path with the landing type as the
    /// final hop, the offset only when nonzero, and the sharing tasks.
    #[test]
    fn test_a_reached_claim_spells_the_path() {
        let label = |index: usize| format!("task {}", index + 30);
        let ty = |_| "ArcInner<Notify>".to_string();
        let reached = |via: &str, offset, claimants: Vec<u32>, clipped| RegClass::Reached {
            owner: 4,
            via: via.to_string(),
            path: vec!["#2 conn.inner".to_string(), "handlers[0]".to_string()],
            ty: hansei_bundle::BundleTypeId(0),
            offset,
            claimants,
            claimants_clipped: clipped,
        };

        assert_eq!(
            spelled(&reached("", 0x10, vec![], false), &label, &ty),
            Some(vec![
                "task 34 via #2 conn.inner".to_string(),
                "handlers[0]".to_string(),
                "ArcInner<Notify> +0x10".to_string(),
            ])
        );
        assert_eq!(
            spelled(&reached("held #1", 0, vec![5], true), &label, &ty),
            Some(vec![
                "task 34 (held #1) via #2 conn.inner".to_string(),
                "handlers[0]".to_string(),
                "ArcInner<Notify>, shared with task 35 (and others)".to_string(),
            ])
        );
    }

    /// Wrapping breaks only between segments: a claim within the width
    /// is one line, a long one continues with its arrow four columns
    /// past the claim's start, and a segment longer than the width
    /// stays whole — never split inside, whatever arrows a type name
    /// happens to contain.
    #[test]
    fn test_wrapping_breaks_at_hops() {
        use super::wrap_hops;
        let seg = |parts: &[&str]| -> Vec<String> { parts.iter().map(|s| s.to_string()).collect() };

        assert_eq!(
            wrap_hops(&seg(&["task 3 via #0 n", "T"]), 30, 80),
            vec!["task 3 via #0 n -> T"]
        );

        // Start column 60 leaves room for one 12-char hop plus one
        // 4-char separator and a bit — the second hop must wrap.
        assert_eq!(
            wrap_hops(
                &seg(&["aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"]),
                60,
                80
            ),
            vec!["aaaaaaaaaaaa", "-> bbbbbbbbbbbb", "-> cccccccccccc"]
        );

        // A single over-wide segment is not split inside itself — the
        // fn-arrow it contains is part of a name, not a hop.
        let wide = format!("fn(A) -> {}", "x".repeat(80));
        assert_eq!(wrap_hops(&seg(&[&wide]), 60, 80), vec![wide.clone()]);
        // ...and a second segment after it still wraps to its own line.
        assert_eq!(
            wrap_hops(&seg(&[&wide, "tail"]), 60, 80),
            vec![wide, "-> tail".to_string()]
        );
    }

    /// The wrap arithmetic at its exact boundaries: a line landing on
    /// the width stays whole, one column more breaks it, and a
    /// continuation's own column — the claim's start, plus four, plus
    /// its arrow and text — decides the next break.
    #[test]
    fn test_wrapping_boundaries_are_exact() {
        use super::wrap_hops;
        let seg = |parts: &[&str]| -> Vec<String> { parts.iter().map(|s| s.to_string()).collect() };

        // start 10 + 6 + " -> " + 10 lands exactly on width 30: whole.
        assert_eq!(
            wrap_hops(&seg(&["aaaaaa", "bbbbbbbbbb"]), 10, 30),
            vec!["aaaaaa -> bbbbbbbbbb"]
        );
        // One more column breaks before the hop.
        assert_eq!(
            wrap_hops(&seg(&["aaaaaaa", "bbbbbbbbbb"]), 10, 30),
            vec!["aaaaaaa", "-> bbbbbbbbbb"]
        );

        // A 20-column head wraps the second hop to a continuation at
        // column 14 holding 13 columns of arrow-and-text; the third
        // hop's arrow and 9 columns land exactly on width 40 and stay,
        // while 10 columns break to a third line.
        let head = "a".repeat(20);
        let mid = "b".repeat(10);
        assert_eq!(
            wrap_hops(&seg(&[&head, &mid, &"c".repeat(9)]), 10, 40),
            vec![head.clone(), format!("-> {mid} -> {}", "c".repeat(9))]
        );
        assert_eq!(
            wrap_hops(&seg(&[&head, &mid, &"c".repeat(10)]), 10, 40),
            vec![head, format!("-> {mid}"), format!("-> {}", "c".repeat(10))]
        );
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
            0x40_0000 => Some(vec!["app_main".to_string()]),
            0x9000_0800 | 0x9000_0900 => Some(vec!["this lwp's stack".to_string()]),
            0 => Some(vec!["unmapped".to_string()]),
            _ => None,
        };
        let mut out = Vec::new();
        print_registers(&mut out, "  ", &regs, &annotate).expect("the block renders");
        let out = String::from_utf8(out).expect("rendered output is UTF-8");
        assert_eq!(
            out,
            "  registers:
    rip  0x0000000000400000  — app_main
    rsp  0x0000000090000800  — this lwp's stack
    rbp  0x0000000090000900  — this lwp's stack
    rax  0x0000000000000000  — unmapped
    rbx  0x0000000000000014
    rcx  0x0000000000000000  — unmapped
    rdx  0x0000000000000000  — unmapped
    rsi  0x0000000000000000  — unmapped
    rdi  0x0000000000000000  — unmapped
    r8   0x0000000000000000  — unmapped
    r9   0x0000000000000000  — unmapped
    r10  0x0000000000000000  — unmapped
    r11  0x0000000000000000  — unmapped
    r12  0x0000000000000000  — unmapped
    r13  0x0000000000000000  — unmapped
    r14  0x0000000000000000  — unmapped
    r15  0x0000000000000000  — unmapped
",
        );
    }
}

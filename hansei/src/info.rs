// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `info` command: the process-facts oracle.
//!
//! One screen of everything the target records about itself: what was
//! attached and how far its symbols resolve, who the process was —
//! what gdb's `info proc` and mdb's `::status`, `::pargs` and `::penv`
//! answer — and what ended it. What the runtime holds is the
//! listings' question (`threads`, `tasks`, `runtimes`).

use crate::{Session, summary};

use anyhow::Result;
use proc::Target;

use std::io;

pub fn exec_info<T: Target>(session: &Session<'_, T>, out: &mut dyn io::Write) -> Result<()> {
    // Each part rendered whole, then joined — so the blank-line seams
    // cannot drift from the part count.
    let render = |part: fn(&Session<'_, T>, &mut dyn io::Write) -> Result<()>| -> Result<String> {
        let mut buf = Vec::new();
        part(session, &mut buf)?;
        Ok(String::from_utf8(buf).expect("info output is UTF-8"))
    };
    let parts = [render(attach)?, render(process)?, render(signal)?];
    write!(out, "{}", parts.join("\n"))?;
    Ok(())
}

/// What was attached, and how far its symbols resolve in the target.
fn attach<T: Target>(session: &Session<'_, T>, out: &mut dyn io::Write) -> Result<()> {
    let fp = session.ctx.validate_fingerprint();
    writeln!(out, "core:       {}", session.core.display())?;
    writeln!(out, "tokio info: {}", session.bundle_source)?;
    writeln!(
        out,
        "symbols resolved: {}/{}{}",
        fp.matched,
        fp.total,
        if fp.is_complete() { "" } else { " (forced)" }
    )?;
    Ok(())
}

/// The identity out of the core's own notes — mdb's `::status`,
/// `::pargs` and `::penv` in one place.
fn process<T: Target>(session: &Session<'_, T>, out: &mut dyn io::Write) -> Result<()> {
    let Some(facts) = session.proc.process_facts() else {
        writeln!(out, "process: not recorded by this target")?;
        return Ok(());
    };
    // A Linux core records no data model where an illumos psinfo
    // always does — which is what tells "a Linux core records no
    // argv" from "an illumos argv this dump cannot serve".
    let linux = facts.model.is_none();
    writeln!(out, "pid:    {} ({})", facts.pid, facts.fname)?;
    writeln!(out, "ppid:   {}", facts.ppid)?;
    match facts.euid {
        Some(euid) => writeln!(out, "uid:    {} (effective {euid})", facts.uid)?,
        None => writeln!(out, "uid:    {}", facts.uid)?,
    }
    match facts.egid {
        Some(egid) => writeln!(out, "gid:    {} (effective {egid})", facts.gid)?,
        None => writeln!(out, "gid:    {}", facts.gid)?,
    }
    if let Some(model) = facts.model {
        writeln!(out, "model:  {model}")?;
    }
    if let Some(start) = &facts.start {
        writeln!(out, "start:  {}", utc(start))?;
    }
    writeln!(out, "psargs: {}", facts.psargs)?;
    if let Some(execfn) = &facts.execfn {
        writeln!(out, "execfn: {execfn}")?;
    }
    if let Some(path) = session.proc.exec_path() {
        writeln!(out, "executable: {}", path.display())?;
    }
    build_id_lines(session.proc.build_ids().as_ref(), out)?;
    match &facts.argv {
        Some(argv) => {
            writeln!(out, "argv:")?;
            for arg in argv {
                writeln!(out, "  {arg}")?;
            }
        }
        None => writeln!(out, "argv: {}", argv_absence(linux))?,
    }
    match &facts.env {
        Some(env) => {
            writeln!(out, "environment:")?;
            for var in env {
                writeln!(out, "  {var}")?;
            }
        }
        None => writeln!(out, "environment: {}", env_absence(linux))?,
    }
    Ok(())
}

/// The absence spellings, split by which core cannot answer: a Linux
/// core records neither argv nor the environment at all, while an
/// illumos core records pointers this dump happens not to serve.
fn argv_absence(linux: bool) -> &'static str {
    match linux {
        true => "not recorded in a Linux core (psargs is its 80-byte spelling)",
        false => "not readable from this core",
    }
}

fn env_absence(linux: bool) -> &'static str {
    match linux {
        true => "not recorded in a Linux core",
        false => "not readable from this core",
    }
}

/// Both build ids and whether they agree, for the targets where the
/// question arises (a Linux core beside its `--binary`).
fn build_id_lines(ids: Option<&proc::BuildIds>, out: &mut dyn io::Write) -> Result<()> {
    let Some(ids) = ids else { return Ok(()) };
    let hex = |id: &Option<Vec<u8>>| match id {
        Some(id) => id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        None => "none".to_owned(),
    };
    let verdict = match (ids.disagree(), &ids.core, &ids.binary) {
        (true, ..) => "disagree: the file is not the binary this core was taken from",
        (false, Some(_), Some(_)) => "agree",
        _ => "unverifiable: one side records no id",
    };
    writeln!(out, "build id (core):   {}", hex(&ids.core))?;
    writeln!(out, "build id (binary): {} — {verdict}", hex(&ids.binary))?;
    Ok(())
}

/// What ended the process, who sent it where the siginfo says, and
/// where the taking lwp was — its registers stay in `thread`. A core
/// with no fatal signal is a live capture, which is worth saying
/// outright: "why does hansei show no crash?" is the question this
/// preempts.
fn signal<T: Target>(session: &Session<'_, T>, out: &mut dyn io::Write) -> Result<()> {
    let Some(sig) = session.proc.fatal_signal() else {
        writeln!(out, "signal: none recorded (a live capture, not a crash)")?;
        return Ok(());
    };
    writeln!(out, "signal: {}", summary::fatal_signal_line(&sig))?;
    if let Some(pid) = sig.sender {
        writeln!(out, "sender: pid {pid}")?;
    }
    if let Some(lwp) = sig.lwp {
        let pc = pc_of(&session.lwps, lwp);
        let sym = |pc: u64| {
            session
                .proc
                .lookup_symbol_by_addr(pc)
                .map(|sym| symbol_label(&sym.name, sym.st_value, pc))
        };
        writeln!(out, "{}", taken_on(lwp, pc, sym))?;
    }
    Ok(())
}

/// The taking lwp's pc, where the target still lists that lwp.
fn pc_of(lwps: &[proc::LwpInfo], lwp: u32) -> Option<u64> {
    lwps.iter().find(|l| l.tid == lwp).map(|l| l.regs.rip)
}

/// `symbol+0xoff`, demangled without the hash; the bare name at its
/// own address.
fn symbol_label(name: &str, value: u64, pc: u64) -> String {
    let name = format!("{:#}", rustc_demangle::demangle(name));
    match pc - value {
        0 => name,
        off => format!("{name}+{off:#x}"),
    }
}

/// `taken on: lwp N, pc 0x… <symbol+0x…>`, with each part present
/// only as far as the target answers.
fn taken_on(lwp: u32, pc: Option<u64>, sym: impl Fn(u64) -> Option<String>) -> String {
    let mut line = format!("taken on: lwp {lwp}");
    if let Some(pc) = pc {
        line.push_str(&format!(", pc {pc:#x}"));
        if let Some(name) = sym(pc) {
            line.push_str(&format!(" <{name}>"));
        }
    }
    line
}

/// An epoch timestamp as a civil UTC date — `pr_start`'s clock. The
/// nanoseconds are dropped: a start time is read for "when", not for
/// ordering events.
fn utc(ts: &proc::Timespec) -> String {
    let days = ts.tv_sec.div_euclid(86_400);
    let sod = ts.tv_sec.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), Howard Hinnant's
/// `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    use proc::Timespec;

    fn ts(tv_sec: i64) -> Timespec {
        Timespec { tv_sec, tv_nsec: 0 }
    }

    #[test]
    fn test_utc_spells_civil_dates() {
        assert_eq!(utc(&ts(0)), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(&ts(86_399)), "1970-01-01 23:59:59 UTC");
        // A leap day, which is where a civil conversion goes wrong.
        assert_eq!(utc(&ts(951_782_400)), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(&ts(951_868_800)), "2000-03-01 00:00:00 UTC");
    }

    #[test]
    fn test_utc_survives_the_2100_century() {
        // 2100 is not a leap year: the Gregorian century correction's
        // one observable seam inside the epoch's useful range.
        assert_eq!(utc(&ts(4_107_542_399)), "2100-02-28 23:59:59 UTC");
        assert_eq!(utc(&ts(4_107_542_400)), "2100-03-01 00:00:00 UTC");
    }

    #[test]
    fn test_pc_of_reads_exactly_the_named_lwp() {
        let lwp = |tid: u32, rip: u64| proc::LwpInfo {
            tid,
            regs: proc::Regs {
                rip,
                ..Default::default()
            },
            stack_range: 0..0,
            altstack: 0..0,
            tstamp: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        };
        let lwps = [lwp(3, 0x30), lwp(7, 0x70)];
        assert_eq!(pc_of(&lwps, 7), Some(0x70));
        assert_eq!(pc_of(&lwps, 3), Some(0x30));
        assert_eq!(pc_of(&lwps, 9), None);
    }

    #[test]
    fn test_symbol_label_demangles_and_offsets() {
        assert_eq!(symbol_label("abort", 0x1000, 0x1000), "abort");
        assert_eq!(symbol_label("abort", 0x1000, 0x1008), "abort+0x8");
        assert_eq!(
            symbol_label("_ZN3std9panicking11begin_panic17h1234567890abcdefE", 0, 0),
            "std::panicking::begin_panic"
        );
    }

    #[test]
    fn test_absence_spellings() {
        assert_eq!(
            argv_absence(true),
            "not recorded in a Linux core (psargs is its 80-byte spelling)"
        );
        assert_eq!(argv_absence(false), "not readable from this core");
        assert_eq!(env_absence(true), "not recorded in a Linux core");
        assert_eq!(env_absence(false), "not readable from this core");
    }

    #[test]
    fn test_taken_on_grows_with_what_the_target_answers() {
        assert_eq!(taken_on(7, None, |_| None), "taken on: lwp 7");
        assert_eq!(
            taken_on(7, Some(0x1000), |_| None),
            "taken on: lwp 7, pc 0x1000"
        );
        assert_eq!(
            taken_on(7, Some(0x1008), |_| Some("abort+0x8".to_string())),
            "taken on: lwp 7, pc 0x1008 <abort+0x8>"
        );
    }

    #[test]
    fn test_build_id_verdicts() {
        let render = |ids: &proc::BuildIds| {
            let mut out = Vec::new();
            build_id_lines(Some(ids), &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        let agree = proc::BuildIds {
            core: Some(vec![0xab]),
            binary: Some(vec![0xab]),
        };
        assert_eq!(
            render(&agree),
            "build id (core):   ab\nbuild id (binary): ab — agree\n"
        );
        let disagree = proc::BuildIds {
            core: Some(vec![0xab]),
            binary: Some(vec![0xcd]),
        };
        assert!(
            render(&disagree).contains("disagree"),
            "{}",
            render(&disagree)
        );
        let oneside = proc::BuildIds {
            core: None,
            binary: Some(vec![0xcd]),
        };
        assert!(
            render(&oneside).contains("unverifiable"),
            "{}",
            render(&oneside)
        );
    }
}

//! The `info` command: the process-facts oracle.
//!
//! Bare `info` prints the one-screen attach summary; `info <section>`
//! prints one section in full — what gdb's `info proc` and mdb's
//! `::status`, `::pargs`, `::penv`, `::pfiles` and `::objects` answer
//! — and `info -v` prints every section.

use crate::{Session, summary};

use anyhow::Result;
use proc::Target;

use std::io;

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Section {
    Process,
    Signal,
    Objects,
    Fds,
}

pub fn exec_info<T: Target>(
    session: &Session<'_, T>,
    section: Option<Section>,
    verbose: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    match section {
        Some(section) => print_section(session, section, out),
        None if verbose => {
            let all = [
                Section::Process,
                Section::Signal,
                Section::Objects,
                Section::Fds,
            ];
            // Each section rendered whole, then joined — so the
            // blank-line seams cannot drift from the section count.
            let mut sections = Vec::new();
            for section in all {
                let mut buf = Vec::new();
                print_section(session, section, &mut buf)?;
                sections.push(String::from_utf8(buf).expect("section output is UTF-8"));
            }
            write!(out, "{}", sections.join("\n"))?;
            Ok(())
        }
        None => attach_summary(session, out),
    }
}

fn print_section<T: Target>(
    session: &Session<'_, T>,
    section: Section,
    out: &mut dyn io::Write,
) -> Result<()> {
    match section {
        Section::Process => process(session, out),
        Section::Signal => signal(session, out),
        Section::Objects => objects(session, out),
        Section::Fds => fds(session, out),
    }
}

/// The one-screen attach summary: what was attached, how far its
/// symbols resolve, who the process was, what ended it, and how much
/// there is for the listings to go and look at.
fn attach_summary<T: Target>(session: &Session<'_, T>, out: &mut dyn io::Write) -> Result<()> {
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
    if let Some(facts) = session.proc.process_facts() {
        writeln!(
            out,
            "pid: {} ({}), parent {}",
            facts.pid, facts.fname, facts.ppid
        )?;
        let line = match &facts.argv {
            Some(argv) => argv.join(" "),
            None => facts.psargs.clone(),
        };
        writeln!(out, "argv: {line}")?;
    }
    // What ended the process, or that nothing did: a core with no
    // fatal signal is a live capture, which is worth saying outright —
    // "why does hansei show no crash?" is the question this preempts.
    match session.proc.fatal_signal() {
        Some(sig) => {
            let lwp = sig
                .lwp
                .map(|tid| format!(", taken on lwp {tid}"))
                .unwrap_or_default();
            writeln!(out, "signal: {}{lwp}", summary::fatal_signal_line(&sig))?;
        }
        None => writeln!(out, "signal: none recorded (a live capture, not a crash)")?,
    }
    if let Ok(mappings) = session.proc.mappings() {
        let mut paths: Vec<&str> = mappings.iter().filter_map(|m| m.path.as_deref()).collect();
        paths.sort_unstable();
        paths.dedup();
        if !paths.is_empty() {
            writeln!(out, "objects: {} loaded (see `info objects`)", paths.len())?;
        }
    }
    if let Some(fds) = session.proc.fds() {
        writeln!(out, "fds: {} recorded (see `info fds`)", fds.len())?;
    }
    writeln!(
        out,
        "{} worker thread(s), {} task(s)",
        session.workers.len(),
        session.tasks.tasks.len()
    )?;
    // What the target's executors are is `runtimes`' question: an
    // attach summary says how many there are to go and look at, and
    // leaves naming them to the listing that can afford the room.
    let sets = match session.local_sets.is_empty() {
        true => String::new(),
        false => format!(
            ", {}",
            summary::counted(session.local_sets.len(), "local set")
        ),
    };
    writeln!(
        out,
        "{}{sets} (see `runtimes --list`)",
        summary::counted(session.runtimes.len(), "runtime")
    )?;
    Ok(())
}

/// `info process`: the identity out of the core's own notes — mdb's
/// `::status`, `::pargs` and `::penv` in one place.
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

/// The fd table's: `Some(true)` is a Linux core — process facts with
/// no data model — whose system records no fd table; anything else is
/// a target with no fd story at all.
fn fds_absence(linux: Option<bool>) -> &'static str {
    match linux {
        Some(true) => "not recorded in a Linux core",
        _ => "not recorded by this target",
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

/// `info signal`: what ended the process, who sent it where the
/// siginfo says, and where the taking lwp was — its registers stay in
/// `threads -v`.
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

/// `info objects`: every file-backed object, with whether this target
/// can source its symbols and its CFI — asked of the symbolizer's and
/// the unwinder's own lookups, so a stack cut short by missing CFI
/// has its reason surfaced here.
fn objects<T: Target>(session: &Session<'_, T>, out: &mut dyn io::Write) -> Result<()> {
    let survey = unwind::cfi_survey(session.proc)?;
    if survey.is_empty() {
        writeln!(out, "no file-backed objects in the target's mappings")?;
        return Ok(());
    }
    let symbols = session.proc.symbol_object_bases();
    let rows: Vec<[String; 4]> = survey
        .iter()
        .map(|s| {
            [
                format!("{:#x}..{:#x}", s.range.start, s.range.end),
                s.path.clone(),
                match symbols.iter().any(|b| s.range.contains(b)) {
                    true => "yes".to_string(),
                    false => "—".to_string(),
                },
                match &s.cfi {
                    Ok(()) => "yes".to_string(),
                    Err(why) => format!("no ({why})"),
                },
            ]
        })
        .collect();
    write!(
        out,
        "{}",
        table(&["RANGE", "PATH", "SYMBOLS", "CFI"], &rows)
    )?;
    if let Some(ids) = session.proc.build_ids()
        && ids.disagree()
    {
        writeln!(
            out,
            "warning: the substituted binary's build id disagrees with the core's"
        )?;
    }
    Ok(())
}

/// `info fds`: the open-fd table an illumos core records, whole — a
/// count first, since a busy target records tens of thousands.
fn fds<T: Target>(session: &Session<'_, T>, out: &mut dyn io::Write) -> Result<()> {
    let Some(fds) = session.proc.fds() else {
        let linux = session.proc.process_facts().map(|f| f.model.is_none());
        writeln!(out, "fds: {}", fds_absence(linux))?;
        return Ok(());
    };
    writeln!(out, "{} fds recorded", fds.len())?;
    write!(out, "{}", fd_table(fds))?;
    Ok(())
}

/// The fd table: the type word out of the mode, size and offset, and
/// the recorded path — `—` where the kernel wrote none (a socket).
fn fd_table(fds: &[proc::FdInfo]) -> String {
    let rows: Vec<[String; 5]> = fds
        .iter()
        .map(|fd| {
            [
                fd.fd.to_string(),
                kind(fd.mode).to_string(),
                fd.size.to_string(),
                fd.offset.to_string(),
                match fd.path.is_empty() {
                    true => "—".to_string(),
                    false => fd.path.clone(),
                },
            ]
        })
        .collect();
    table(&["FD", "TYPE", "SIZE", "OFFSET", "PATH"], &rows)
}

/// The `S_IFMT` type words, illumos's set — `door` and `port` exist
/// nowhere else, and no Linux target reaches this table.
fn kind(mode: u32) -> &'static str {
    match mode & 0o170000 {
        0o010000 => "fifo",
        0o020000 => "chr",
        0o040000 => "dir",
        0o060000 => "blk",
        0o100000 => "reg",
        0o120000 => "lnk",
        0o140000 => "sock",
        0o150000 => "door",
        0o160000 => "port",
        _ => "?",
    }
}

/// Left-aligned columns two spaces apart, the last column ragged and
/// trailing space trimmed. Nothing is truncated — `! less -S` is the
/// answer to width, as everywhere.
fn table<const N: usize>(header: &[&str; N], rows: &[[String; N]]) -> String {
    let width = |cell: &str| cell.chars().count();
    let mut widths = header.map(width);
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(width(cell));
        }
    }
    let mut out = String::new();
    let mut line = |cells: &[&str]| {
        let mut text = String::new();
        for (i, (cell, w)) in cells.iter().zip(widths).enumerate() {
            if i > 0 {
                text.push_str("  ");
            }
            text.push_str(cell);
            // The last column's padding is trailing space, trimmed
            // below — so every column can pad alike.
            for _ in width(cell)..w {
                text.push(' ');
            }
        }
        out.push_str(text.trim_end());
        out.push('\n');
    };
    line(header);
    for row in rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        line(&cells);
    }
    out
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
    fn test_kind_words_cover_the_ifmt_range() {
        assert_eq!(kind(0o100644), "reg");
        assert_eq!(kind(0o140666), "sock");
        assert_eq!(kind(0o020620), "chr");
        assert_eq!(kind(0o040755), "dir");
        assert_eq!(kind(0o150000), "door");
        assert_eq!(kind(0o010644), "fifo");
        assert_eq!(kind(0o060640), "blk");
        assert_eq!(kind(0o120777), "lnk");
        assert_eq!(kind(0o160000), "port");
        assert_eq!(kind(0), "?");
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
        assert_eq!(fds_absence(Some(true)), "not recorded in a Linux core");
        assert_eq!(fds_absence(Some(false)), "not recorded by this target");
        assert_eq!(fds_absence(None), "not recorded by this target");
    }

    #[test]
    fn test_fd_table_spells_rows_and_sockets() {
        let fds = vec![
            proc::FdInfo {
                fd: 1,
                mode: 0o100644,
                ino: 7,
                offset: 128,
                size: 4096,
                fileflags: 2,
                path: "/var/log/x.log".to_string(),
            },
            proc::FdInfo {
                fd: 12,
                mode: 0o140666,
                ino: 0,
                offset: 0,
                size: 0,
                fileflags: 2,
                path: String::new(),
            },
        ];
        assert_eq!(
            fd_table(&fds),
            "FD  TYPE  SIZE  OFFSET  PATH\n\
             1   reg   4096  128     /var/log/x.log\n\
             12  sock  0     0       —\n"
        );
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

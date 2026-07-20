//! Milestone-1 spike (HANSEI_V0_MANGLING_PLAN §6 items 3+4): verify that
//! symtab-only discovery of the tokio runtime works against a live process
//! and a core, with no DWARF on the target side.
//!
//! Usage: tls_spike <pid|core-path> [mangled-poll-symbol]

#![cfg_attr(not(target_os = "illumos"), allow(unused))]

#[cfg(target_os = "illumos")]
use proc::Proc;

const TLS_KEY_SYM: &str =
    "_RNvNCNvNtNtCscIwcofkaqOM_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";

#[cfg(not(target_os = "illumos"))]
fn main() {
    eprintln!("tls_spike only runs on illumos");
}

#[cfg(target_os = "illumos")]
fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().expect("usage: tls_spike <pid|core> [poll-sym]");
    let p = match target.parse::<u32>() {
        Ok(pid) => Proc::grab_pid(pid).expect("failed to grab pid"),
        Err(_) => Proc::open_core(std::path::Path::new(&target)).expect("failed to open core"),
    };

    // 1. Resolve the TLS-key static by name in the target symtab (no DWARF).
    let sym = p
        .lookup_symbol_by_name(TLS_KEY_SYM)
        .expect("TLS key symbol not found in symtab");
    println!(
        "TLS key static: {:#x} (size {}, st_info {:#x})",
        sym.st_value, sym.st_size, sym.st_info
    );
    let raw = p.read_u64(sym.st_value).expect("failed to read key");
    println!("value at static: u64={raw:#x} u32={:#x}", raw as u32);
    let key = raw as usize;
    assert!(key <= 8, "key {key} not in fast TSD range");

    // 2. Probe every LWP's fast TSD slot for the Context pointer.
    let mut found = 0;
    for lwp in p.lwps().expect("failed to list lwps") {
        let name = p.lwp_name(lwp.tid).unwrap_or_default();
        let Ok(ftsd) = p.tsd_from_regs(&lwp.regs) else {
            println!("tid {:3} {:24} <no tsd>", lwp.tid, name);
            continue;
        };
        let ctx = ftsd[key];
        let mapped = ctx != 0 && p.addr_is_mapped(ctx);
        println!(
            "tid {:3} {:24} context={ctx:#x} mapped={mapped}",
            lwp.tid, name
        );
        if mapped {
            // Prove the pointer is readable, not just mapped.
            let first = p.read_u64(ctx).expect("context not readable");
            println!("        first word of Context: {first:#x}");
            found += 1;
        }
    }
    println!("LWPs with live Context: {found}");
    assert!(found > 0, "no LWP had a Context pointer");

    // 3. Local-symbol round trip: task::raw::poll instantiations have local
    //    (STB_LOCAL) binding; confirm Plookup by-name and by-addr both see them.
    if let Some(poll_sym) = args.next() {
        let s = p
            .lookup_symbol_by_name(&poll_sym)
            .expect("poll instantiation not found by name (local syms invisible?)");
        println!(
            "poll sym by name: {:#x} (st_info {:#x})",
            s.st_value, s.st_info
        );
        let back = p
            .lookup_symbol_by_addr(s.st_value)
            .expect("poll instantiation not found by addr");
        assert_eq!(back.name, poll_sym, "by-addr returned a different symbol");
        println!("by-addr round trip OK: {}", back.name);
    }

    println!("SPIKE OK");
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `umem-audit`: what the allocator index found, in the shape a check
//! against mdb's own reading of the same core can be diffed against.

use crate::Session;

use anyhow::Result;
use hansei_runtime::heap::umem::{Liveness, UmemHeap, malloc_tag};

use std::io;

/// Which set of chunks `--dump` prints. Both are what a differential
/// against another reader of the same core — mdb's `::walk umem`, its
/// `::whatis` — needs from this side: one address per line, nothing
/// else on it.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Dump {
    Live,
    Freed,
}

pub fn exec_umem_audit(
    session: &Session<'_>,
    addrs: &[u64],
    dump: Option<Dump>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let Some(heap) = session.umem() else {
        writeln!(
            out,
            "no umem metadata in this target: libumem is not mapped, or the \
             allocator never finished initializing"
        )?;
        return Ok(());
    };

    if let Some(dump) = dump {
        let buffers: Box<dyn Iterator<Item = _>> = match dump {
            Dump::Live => Box::new(heap.live_buffers()),
            Dump::Freed => Box::new(heap.freed_buffers()),
        };
        for buffer in buffers {
            writeln!(out, "{:#x}", buffer.start)?;
        }
        return Ok(());
    }

    let stats = heap.stats();
    writeln!(
        out,
        "umem: layout {}, {} cache(s), {} slab(s)",
        stats.layout, stats.caches, stats.slabs
    )?;
    writeln!(
        out,
        "live: {} chunk(s), {} bytes; freed: {} chunk(s), {} parked",
        stats.live_chunks, stats.live_bytes, stats.freed_chunks, stats.parked_chunks
    )?;
    // What is missing errs toward Live, so it belongs in the header
    // rather than in a footnote: a verdict from this index is only ever
    // as complete as this line says.
    let missing: Vec<&str> = [
        (
            stats.magazines_walked,
            "the per-CPU magazines and the depot",
        ),
        (stats.ptc_walked, "the threads' own caches"),
        (stats.oversize_walked, "the oversize and memalign arenas"),
    ]
    .iter()
    .filter(|(walked, _)| !walked)
    .map(|&(_, layer)| layer)
    .collect();
    if !missing.is_empty() {
        writeln!(out, "not walked: {}", missing.join("; "))?;
    }

    writeln!(out)?;
    writeln!(
        out,
        "{:<24} {:>9} {:>10} {:>8} {:>10} {:>9} {:>8} {:>8}",
        "CACHE", "BUFSIZE", "CHUNKSIZE", "SLABS", "LIVE", "FREED", "PARKED", "DECLINED"
    )?;
    for cache in heap.caches() {
        writeln!(
            out,
            "{:<24} {:>9} {:>10} {:>8} {:>10} {:>9} {:>8} {:>8}",
            cache.name,
            cache.bufsize,
            cache.chunksize,
            cache.slabs,
            cache.live,
            cache.freed,
            match cache.parked_walked {
                true => cache.parked.to_string(),
                // Not zero: the layer declined, so what it holds is
                // unknown rather than nothing.
                false => "-".to_string(),
            },
            cache.slabs_declined
        )?;
    }

    if stats.incomplete() {
        writeln!(out)?;
        writeln!(
            out,
            "declined: {} cache(s), {} slab(s), {} overlapping slab(s), \
             {} cache(s)' parked buffers",
            stats.caches_declined,
            stats.slabs_declined,
            stats.overlaps,
            stats.caches_parked_declined
        )?;
    }
    // Every note, whether or not something was declined: a layer that
    // did not walk at all declines nothing and is exactly what someone
    // reading this needs told.
    if !stats.notes.is_empty() {
        writeln!(out)?;
        for note in &stats.notes {
            writeln!(out, "  {note}")?;
        }
    }

    // The invariants the index claims about itself, checked rather than
    // asserted: a violation here means a walker bug or a torn core, and
    // either way the verdicts above are not to be believed.
    let violations = heap.violations();
    writeln!(out)?;
    match violations.is_empty() {
        true => writeln!(out, "self-check: clean")?,
        false => {
            writeln!(out, "self-check: {} violation(s)", violations.len())?;
            for violation in &violations {
                writeln!(out, "  {violation}")?;
            }
        }
    }

    // What the corroboration has actually refused so far. A gate that
    // fires prints nothing where it fired — that is the point — so this
    // is the only account of it, and the numbers are what decide
    // whether the base-match count is worth promoting to a decline.
    let gates = session.gates();
    writeln!(out)?;
    writeln!(
        out,
        "gates: {} pointer(s) into freed memory, {} sequence(s) cut to their \
         allocation, {} owning buffer(s) off base (counted only)",
        gates.freed(),
        gates.clipped(),
        gates.base_mismatch()
    )?;

    for &addr in addrs {
        writeln!(out)?;
        write!(out, "{addr:#x}: ")?;
        locate_line(heap, addr, out)?;
        // The malloc header is a second opinion the walk does not need:
        // it is written by the shim rather than the slab layer, so it
        // corroborates a pointer even where no cache covers it.
        match malloc_tag(session.proc(), addr) {
            Some(tag) => writeln!(
                out,
                "  tag: {:?}, {} byte allocation based at {:#x}",
                tag.kind, tag.total, tag.base
            )?,
            None => writeln!(out, "  tag: no malloc header precedes it")?,
        }
    }
    Ok(())
}

fn locate_line(heap: &UmemHeap, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    let (verdict, buffer, cache) = match heap.locate(addr) {
        Liveness::Live { buffer, cache } => ("live", buffer, cache),
        Liveness::Freed { buffer, cache } => ("freed", buffer, cache),
        Liveness::Unknown => {
            writeln!(out, "no walked buffer covers it")?;
            return Ok(());
        }
    };
    writeln!(
        out,
        "{verdict}, in {} buffer {:#x}..{:#x}{}",
        heap.caches()[cache].name,
        buffer.start,
        buffer.end,
        match addr == buffer.start {
            true => String::new(),
            false => format!(" (+{})", addr - buffer.start),
        }
    )?;
    Ok(())
}

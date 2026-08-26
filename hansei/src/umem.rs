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
        let chunks: Box<dyn Iterator<Item = _>> = match dump {
            Dump::Live => Box::new(heap.live_chunks()),
            Dump::Freed => Box::new(heap.freed_chunks()),
        };
        for chunk in chunks {
            writeln!(out, "{:#x}", chunk.start)?;
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
        "live: {} chunk(s), {} bytes; freed: {} chunk(s)",
        stats.live_chunks, stats.live_bytes, stats.freed_chunks
    )?;
    // What is missing errs toward Live, so it belongs in the header
    // rather than in a footnote: a verdict from this index is only ever
    // as complete as this line says.
    writeln!(
        out,
        "not walked: {}{}",
        match stats.magazines_walked {
            true => "",
            false =>
                "magazine, depot and per-thread layers (their buffers \
                     read live)",
        },
        match stats.oversize_walked {
            true => "",
            false =>
                "; the oversize and memalign arenas (their allocations \
                      read unknown)",
        }
    )?;

    writeln!(out)?;
    writeln!(
        out,
        "{:<24} {:>9} {:>10} {:>8} {:>10} {:>9} {:>8}",
        "CACHE", "BUFSIZE", "CHUNKSIZE", "SLABS", "LIVE", "FREED", "DECLINED"
    )?;
    for cache in heap.caches() {
        writeln!(
            out,
            "{:<24} {:>9} {:>10} {:>8} {:>10} {:>9} {:>8}",
            cache.name,
            cache.bufsize,
            cache.chunksize,
            cache.slabs,
            cache.live,
            cache.freed,
            cache.slabs_declined
        )?;
    }

    if stats.incomplete() {
        writeln!(out)?;
        writeln!(
            out,
            "declined: {} cache(s), {} slab(s), {} overlapping slab(s)",
            stats.caches_declined, stats.slabs_declined, stats.overlaps
        )?;
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
    let (verdict, chunk, cache) = match heap.locate(addr) {
        Liveness::Live { chunk, cache } => ("live", chunk, cache),
        Liveness::Freed { chunk, cache } => ("freed", chunk, cache),
        Liveness::Unknown => {
            writeln!(out, "no walked chunk covers it")?;
            return Ok(());
        }
    };
    writeln!(
        out,
        "{verdict}, in {} chunk {:#x}..{:#x}{}",
        heap.caches()[cache].name,
        chunk.start,
        chunk.end,
        match addr == chunk.start {
            true => String::new(),
            false => format!(" (+{})", addr - chunk.start),
        }
    )?;
    Ok(())
}

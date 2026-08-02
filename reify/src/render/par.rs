//! Fanning a collection's entries out across worker threads.
//!
//! A deep trace's bytes come overwhelmingly from one or two huge
//! collections — a map of hundreds of ~quarter-megabyte entries — so
//! the renderer parallelizes there: entries are formatted into chunk
//! buffers on worker threads and stitched into the output in order,
//! making the chunking invisible in the text. Everything a worker
//! needs is either `Sync` (the target, the bundle behind the type
//! handles) or built task-locally (the cycle-guard path, the format
//! cache); [`WorkerCtx`] is the context slice that crosses the thread
//! boundary.

use crate::debug_type::DebugType;
use crate::render::ElideOverride;
use crate::target::ReadFromProc;

use super::{FormatCache, RenderCtx};

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;

/// How many entries a collection must have before formatting them is
/// worth fanning out; below this, spawn and stitch overhead outweighs
/// the work.
pub(crate) const MIN_PARALLEL_ITEMS: u64 = 64;

/// A `Display` carrying a closure, so a worker can drive the render
/// machinery into a `String` of its own: `core::fmt` only hands out a
/// `Formatter` inside a formatting call.
pub(crate) struct DisplayWith<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result>(pub F);

impl<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result> fmt::Display for DisplayWith<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.0)(f)
    }
}

/// The `Send + Sync` slice of a [`RenderCtx`]: what it carries minus the
/// cycle guard and format cache, which each worker owns for itself.
#[derive(Copy, Clone)]
pub(crate) struct WorkerCtx<'buf> {
    pub(super) depth: usize,
    pub(super) max_depth: usize,
    pub(super) proc: Option<&'buf (dyn ReadFromProc + Sync)>,
    pub(super) hex_integers: bool,
    pub(super) ugly: bool,
    pub(super) elide: Option<&'buf ElideOverride>,
}

impl<'buf> WorkerCtx<'buf> {
    /// A worker's own [`RenderCtx`]: this slice around the task-local
    /// cycle guard and format cache, with no further fan-out — the
    /// entries of the collection that spawned the worker are the one
    /// level that parallelizes.
    pub(crate) fn ctx<'x, 'a, T: DebugType<'a>>(
        &self,
        visited: &'x RefCell<HashSet<(u64, &'a str)>>,
        formats: &'x FormatCache<T>,
    ) -> RenderCtx<'x, 'a, T>
    where
        'buf: 'x,
    {
        RenderCtx {
            depth: self.depth,
            max_depth: self.max_depth,
            proc: self.proc,
            visited: Some(visited),
            formats: Some(formats),
            parallel: false,
            hex_integers: self.hex_integers,
            ugly: self.ugly,
            elide: self.elide,
        }
    }
}

/// Render `total` items into `f` in order, formatting contiguous chunks
/// on worker threads. `render(range, out)` must write the items of
/// `range` into `out` exactly as the sequential path would have,
/// punctuation included.
///
/// Waves bound the memory in flight: one chunk per worker is buffered
/// at a time, and each wave is written out (and freed) before the next
/// spawns. Chunks are a quarter of a worker's even share, so a straggler
/// delays its own wave by at most that much.
pub(crate) fn render_chunked<F>(f: &mut fmt::Formatter<'_>, total: usize, render: F) -> fmt::Result
where
    F: Fn(std::ops::Range<usize>, &mut String) + Sync,
{
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let chunk = total.div_ceil(workers * 4).max(1);
    let starts: Vec<usize> = (0..total).step_by(chunk).collect();
    for wave in starts.chunks(workers) {
        let mut bufs = vec![String::new(); wave.len()];
        std::thread::scope(|scope| {
            for (buf, &start) in bufs.iter_mut().zip(wave) {
                let render = &render;
                scope.spawn(move || render(start..total.min(start + chunk), buf));
            }
        });
        for buf in &bufs {
            f.write_str(buf)?;
        }
    }
    Ok(())
}

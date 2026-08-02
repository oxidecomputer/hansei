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

use foldhash::HashSet;

use std::cell::RefCell;
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
/// on rayon's worker threads. `render(range, out)` must write the items
/// of `range` into `out` exactly as the sequential path would have,
/// punctuation included.
///
/// Chunks are an eighth of a worker's even share, small enough for work
/// stealing to level uneven chunks (and uneven cores) instead of the
/// whole render waiting on a straggler. Finished chunks stream back over
/// a channel and are stitched into `f` in index order as they arrive, so
/// writing overlaps rendering and a buffer lives only until its turn
/// comes: the text in flight stays near one chunk per worker plus
/// whatever finished ahead of turn.
///
/// The stitch loop blocks the calling thread, so this must not be
/// reached from inside a rayon worker — a pool thread parked on the
/// channel is lost to the very pool that has to produce into it. The
/// one caller is the root of a target-backed render (the fan-out that
/// spends `parallel`), which runs on the application's own thread.
pub(crate) fn render_chunked<F>(f: &mut fmt::Formatter<'_>, total: usize, render: F) -> fmt::Result
where
    F: Fn(std::ops::Range<usize>, &mut String) + Sync,
{
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let chunk = total.div_ceil(rayon::current_num_threads() * 8).max(1);
    let count = total.div_ceil(chunk);
    let (tx, rx) = std::sync::mpsc::channel::<(usize, String)>();
    let mut result = Ok(());
    rayon::in_place_scope(|scope| {
        let render = &render;
        scope.spawn(move |_| {
            (0..count).into_par_iter().for_each_with(tx, |tx, index| {
                let start = index * chunk;
                let mut buf = String::new();
                render(start..total.min(start + chunk), &mut buf);
                // The stitcher hanging up early (a write error) is fine.
                let _ = tx.send((index, buf));
            });
        });

        let rx = rx; // moved in, so breaking early hangs up on the workers
        let mut next = 0usize;
        let mut held: std::collections::BTreeMap<usize, String> = std::collections::BTreeMap::new();
        for (index, buf) in rx {
            held.insert(index, buf);
            while let Some(buf) = held.remove(&next) {
                result = f.write_str(&buf);
                next += 1;
                if result.is_err() {
                    return;
                }
            }
        }
    });
    result
}

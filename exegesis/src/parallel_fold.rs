use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::sync::{Condvar, Mutex, mpsc};
use std::thread;

/// Pulls items from a fallible source, processes them in parallel, and folds
/// the results on a single collector thread. The goal is to get most of the
/// benefit of parallel execution while keeping an upper bound on the number of
/// potentially large objects held in memory at once.
///
/// The source is an `FnMut() -> Result<Option<T>, E>` — matching the
/// convention used by gimli's fallible iterators. `Ok(Some(item))` yields
/// an item, `Ok(None)` signals end-of-input, and `Err(e)` aborts the
/// pipeline.
///
/// Back-pressure is applied via an in-flight counter: workers block when the
/// number of dispatched-but-not-yet-folded items reaches `max_in_flight`, so
/// no more than roughly `max_in_flight` results are ever alive at once. A slot
/// is freed each time a result is delivered to the fold function.
///
/// By default results are folded **in source order**, buffering out-of-order
/// completions in a reorder heap. That guarantee is not free: one slow item
/// stalls every later completion behind it (head-of-line blocking) and lets
/// those completions consume the in-flight budget. When the fold does not care
/// about order, [`BoundedParallelFold::unordered`] folds each result the moment it
/// arrives, which removes the stall.
pub struct BoundedParallelFold<S, F, A, G> {
    source: S,
    map_fn: F,
    init: A,
    fold_fn: G,
    parallelism: usize,
    max_in_flight: Option<usize>,
    preserve_order: bool,
}

impl<S, F, A, G> BoundedParallelFold<S, F, A, G> {
    pub fn new<T, R, E>(source: S, map_fn: F, init: A, fold_fn: G) -> Self
    where
        S: FnMut() -> Result<Option<T>, E> + Send,
        F: Fn(T) -> Result<R, E> + Send + Sync,
        G: FnMut(&mut A, R) + Send,
    {
        let parallelism = thread::available_parallelism()
            .map(|c| c.get())
            .unwrap_or(1);
        Self {
            source,
            map_fn,
            init,
            fold_fn,
            parallelism,
            max_in_flight: None,
            preserve_order: true,
        }
    }

    pub fn parallelism(mut self, n: usize) -> Self {
        self.parallelism = n;
        self
    }

    pub fn max_in_flight(mut self, n: usize) -> Self {
        self.max_in_flight = Some(n);
        self
    }

    /// Fold results as they complete rather than in source order. The
    /// back-pressure bound is unchanged; only the ordering guarantee is
    /// dropped. Use this when the fold is commutative — it removes the
    /// head-of-line blocking a single slow item would otherwise cause.
    // Opt-in mode with no in-crate caller yet; exercised by the tests below.
    #[allow(dead_code)]
    pub fn unordered(mut self) -> Self {
        self.preserve_order = false;
        self
    }
}

impl<S, T, E, F, R, A, G> BoundedParallelFold<S, F, A, G>
where
    S: FnMut() -> Result<Option<T>, E> + Send,
    T: Send,
    R: Send,
    E: Send,
    F: Fn(T) -> Result<R, E> + Send + Sync,
    A: Send,
    G: FnMut(&mut A, R) + Send,
{
    pub fn run(self) -> Result<A, E> {
        let Self {
            source,
            map_fn,
            mut init,
            mut fold_fn,
            parallelism,
            max_in_flight,
            preserve_order,
        } = self;
        let max_in_flight = max_in_flight.unwrap_or(parallelism * 2);

        let source = Mutex::new((0_usize, source));

        // Tracks dispatched-but-not-yet-folded items. Workers wait when this
        // reaches max_in_flight; the collector decrements it as items are
        // delivered to fold_fn in order.
        let in_flight = Mutex::new(0_usize);
        let in_flight_cv = Condvar::new();

        let map_fn = &map_fn;

        thread::scope(|scope| {
            let (tx, rx) = mpsc::channel::<Sequenced<Result<R, E>>>();
            let source = &source;
            let in_flight = &in_flight;
            let in_flight_cv = &in_flight_cv;

            for _ in 0..parallelism {
                let tx = tx.clone();
                scope.spawn(move || {
                    loop {
                        let (seq, item) = {
                            // Wait until there's room for another in-flight item.
                            let mut count = in_flight.lock().unwrap();
                            count = in_flight_cv
                                .wait_while(count, |c| *c >= max_in_flight)
                                .unwrap();
                            *count += 1;
                            drop(count);

                            let mut guard = source.lock().unwrap();
                            let seq = guard.0;
                            let source_fn = &mut guard.1;

                            let next = match (source_fn)() {
                                Ok(Some(item)) => Some(item),
                                Ok(None) => None,
                                Err(e) => {
                                    // Release the in-flight slot and propagate.
                                    *in_flight.lock().unwrap() -= 1;
                                    in_flight_cv.notify_all();
                                    tx.send(Sequenced { seq, value: Err(e) }).ok();
                                    return;
                                }
                            };

                            let Some(item) = next else {
                                // No more items — release the in-flight slot.
                                *in_flight.lock().unwrap() -= 1;
                                in_flight_cv.notify_all();
                                return;
                            };
                            guard.0 += 1;
                            (seq, item)
                        };

                        let result = (map_fn)(item);
                        let is_err = result.is_err();
                        // If the receiver is gone, the collector has already
                        // exited (likely due to an earlier error). Just stop.
                        if tx.send(Sequenced { seq, value: result }).is_err() {
                            return;
                        }
                        if is_err {
                            return;
                        }
                    }
                });
            }
            drop(tx);

            // Collector thread. In ordered mode it buffers results in a
            // min-heap and delivers them to fold_fn in sequence order; in
            // unordered mode it folds each result as it arrives. Either way it
            // frees an in-flight slot per delivered item.
            let collector = scope.spawn(move || {
                let mut heap: BinaryHeap<Reverse<Sequenced<R>>> = BinaryHeap::new();
                let mut next_seq: usize = 0;

                for item in rx {
                    let value = match item.value {
                        Ok(value) => value,
                        Err(e) => return Err(e),
                    };

                    if !preserve_order {
                        // Fold immediately — no head-of-line blocking.
                        (fold_fn)(&mut init, value);
                        *in_flight.lock().unwrap() -= 1;
                        in_flight_cv.notify_all();
                        continue;
                    }

                    heap.push(Reverse(Sequenced {
                        seq: item.seq,
                        value,
                    }));

                    // Drain all consecutive ready items.
                    let mut drained = 0_usize;
                    while let Some(front) = heap.peek() {
                        if front.0.seq != next_seq {
                            break;
                        }
                        let item = heap.pop().unwrap().0;
                        (fold_fn)(&mut init, item.value);
                        next_seq += 1;
                        drained += 1;
                    }

                    if drained > 0 {
                        *in_flight.lock().unwrap() -= drained;
                        in_flight_cv.notify_all();
                    }
                }

                Ok(init)
            });

            collector.join().unwrap()
        })
    }
}

/// A value tagged with its position in the input sequence.
struct Sequenced<T> {
    seq: usize,
    value: T,
}

impl<T> PartialEq for Sequenced<T> {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}

impl<T> Eq for Sequenced<T> {}

impl<T> PartialOrd for Sequenced<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Sequenced<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seq.cmp(&other.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: wrap a Vec into the fallible source signature.
    fn vec_source<T, E>(items: Vec<Result<T, E>>) -> impl FnMut() -> Result<Option<T>, E> {
        let mut iter = items.into_iter();
        move || match iter.next() {
            Some(Ok(item)) => Ok(Some(item)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    #[test]
    fn test_preserves_order() {
        let result = BoundedParallelFold::new(
            vec_source((0..20u64).map(Ok).collect()),
            |x| Ok::<_, ()>(x * 2),
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .parallelism(4)
        .run()
        .unwrap();

        let expected: Vec<u64> = (0..20).map(|x| x * 2).collect();
        assert_eq!(result, expected);
    }

    /// Forces workers to finish out of the original source order and
    /// verifies the fold still sees items in sequence.
    ///
    /// Even items increment a shared "ready" counter and notify; odd
    /// items block until the counter is non-zero, then decrement it.
    /// Because the source yields items sequentially (0, 1, 2, 3, …)
    /// to the 4 workers, every batch of 4 has exactly 2 even and 2
    /// odd, so even items always complete before odd items in the
    /// same batch — guaranteeing out-of-order worker completion
    /// without relying on sleeps.
    #[test]
    fn test_preserves_order_with_variable_latency() {
        use std::sync::Arc;

        let ready = Arc::new((Mutex::new(0usize), Condvar::new()));
        let ready_c = Arc::clone(&ready);

        let result = BoundedParallelFold::new(
            vec_source((0..20u64).map(Ok).collect()),
            move |x| {
                let (lock, cv) = &*ready_c;
                if x % 2 == 0 {
                    // Even: signal that a result is available.
                    *lock.lock().unwrap() += 1;
                    cv.notify_one();
                } else {
                    // Odd: wait for an even item to finish first.
                    let mut count = lock.lock().unwrap();
                    count = cv.wait_while(count, |c| *c == 0).unwrap();
                    *count -= 1;
                }
                Ok::<_, ()>(x)
            },
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .parallelism(4)
        .run()
        .unwrap();

        let expected: Vec<u64> = (0..20).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_backpressure_with_tiny_limit() {
        // max_in_flight = 1 with many workers — maximizes contention.
        let result = BoundedParallelFold::new(
            vec_source((0..50u64).map(Ok).collect()),
            Ok::<_, ()>,
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .parallelism(8)
        .max_in_flight(1)
        .run()
        .unwrap();

        let expected: Vec<u64> = (0..50).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_empty_source() {
        let result = BoundedParallelFold::new(
            vec_source::<u64, ()>(vec![]),
            Ok::<_, ()>,
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .run()
        .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_single_item() {
        let result = BoundedParallelFold::new(
            vec_source(vec![Ok(42u64)]),
            |x| Ok::<_, ()>(x * 2),
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .run()
        .unwrap();

        assert_eq!(result, vec![84]);
    }

    #[test]
    fn test_map_error_propagates() {
        let result = BoundedParallelFold::new(
            vec_source((0..10u64).map(Ok).collect()),
            |x| {
                if x == 5 { Err("boom") } else { Ok(x) }
            },
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .parallelism(1)
        .run();

        assert_eq!(result.unwrap_err(), "boom");
    }

    /// Blocks all map workers on a gate, waits (via channel recv, no sleeps)
    /// until exactly `max_in_flight` are inside the map function, then
    /// verifies no additional workers managed to enter.
    #[test]
    fn test_in_flight_bounded_by_max() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let max = 4;
        let parallelism = 8;
        let n_items = 20u64;

        let in_map = Arc::new(AtomicUsize::new(0));
        let (arrived_tx, arrived_rx) = mpsc::channel::<()>();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));

        let in_map_c = Arc::clone(&in_map);
        let gate_c = Arc::clone(&gate);

        // Run the pipeline on a background thread so we can observe state.
        let handle = thread::spawn(move || {
            BoundedParallelFold::new(
                vec_source((0..n_items).map(Ok).collect()),
                move |x| {
                    in_map_c.fetch_add(1, Ordering::SeqCst);
                    arrived_tx.send(()).unwrap();

                    let (lock, cv) = &*gate_c;
                    let _g = cv
                        .wait_while(lock.lock().unwrap(), |open| !*open)
                        .unwrap();

                    in_map_c.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, ()>(x)
                },
                Vec::new(),
                |acc: &mut Vec<u64>, x| acc.push(x),
            )
            .parallelism(parallelism)
            .max_in_flight(max)
            .run()
        });

        // Block until exactly `max` workers have entered map_fn.
        for _ in 0..max {
            arrived_rx.recv().unwrap();
        }

        // All max_in_flight slots are occupied by workers blocked on the
        // gate. Backpressure prevents additional workers from entering.
        assert_eq!(
            in_map.load(Ordering::SeqCst),
            max,
            "expected exactly {max} concurrent map calls"
        );
        assert!(
            arrived_rx.try_recv().is_err(),
            "a worker entered map_fn beyond the max_in_flight limit"
        );

        // Open the gate so the pipeline can complete.
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();

        let result = handle.join().unwrap().unwrap();
        assert_eq!(result, (0..n_items).collect::<Vec<_>>());
    }

    #[test]
    fn test_source_error_propagates() {
        let result = BoundedParallelFold::new(
            vec_source(vec![Ok(1u64), Ok(2), Err("source failed"), Ok(4)]),
            Ok::<_, &str>,
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .parallelism(1)
        .run();

        assert_eq!(result.unwrap_err(), "source failed");
    }

    /// Unordered mode makes no ordering promise, but every item must still be
    /// folded exactly once.
    #[test]
    fn test_unordered_folds_every_item() {
        let mut result = BoundedParallelFold::new(
            vec_source((0..100u64).map(Ok).collect()),
            |x| Ok::<_, ()>(x * 2),
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .parallelism(8)
        .unordered()
        .run()
        .unwrap();

        result.sort_unstable();
        let expected: Vec<u64> = (0..100).map(|x| x * 2).collect();
        assert_eq!(result, expected);
    }

    /// Unordered mode keeps the in-flight bound, so a tiny limit with many
    /// workers must still complete (no deadlock) and lose nothing.
    #[test]
    fn test_unordered_with_tiny_limit_folds_all() {
        let mut result = BoundedParallelFold::new(
            vec_source((0..50u64).map(Ok).collect()),
            Ok::<_, ()>,
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .parallelism(8)
        .max_in_flight(1)
        .unordered()
        .run()
        .unwrap();

        result.sort_unstable();
        assert_eq!(result, (0..50).collect::<Vec<_>>());
    }

    #[test]
    fn test_unordered_map_error_propagates() {
        let result = BoundedParallelFold::new(
            vec_source((0..10u64).map(Ok).collect()),
            |x| if x == 5 { Err("boom") } else { Ok(x) },
            Vec::new(),
            |acc: &mut Vec<u64>, x| acc.push(x),
        )
        .parallelism(1)
        .unordered()
        .run();

        assert_eq!(result.unwrap_err(), "boom");
    }
}

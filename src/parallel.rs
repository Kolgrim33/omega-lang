// A tiny bounded parallel-map, built on std::thread::scope so it needs no
// external crates (and therefore no minimum-rustc surprises for anyone
// building Omega). Used to probe many hosts/ports concurrently instead of
// one at a time, which is what makes `discover hosts` and `scan ports`
// practical on anything wider than a single IP.

// Discovery nests port-level parallelism inside host-level parallelism
// (each host's liveness check probes several ports concurrently), so this
// cap bounds the worst case at MAX_CONCURRENCY^2 simultaneous threads
// rather than an unbounded burst.
const MAX_CONCURRENCY: usize = 32;

pub fn parallel_map<T, R, F>(items: &[T], worker: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let mut results = Vec::with_capacity(items.len());
    for chunk in items.chunks(MAX_CONCURRENCY) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|item| scope.spawn(|| worker(item)))
                .collect();
            for h in handles {
                // A worker panicking (e.g. from a bug in a probe) shouldn't
                // take the whole scan down silently; propagate it the same
                // way a sequential call would.
                results.push(h.join().expect("omega worker thread panicked"));
            }
        });
    }
    results
}

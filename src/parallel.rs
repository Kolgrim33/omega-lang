// A tiny bounded parallel-map, built on std::thread::scope so it needs no
// external crates (and therefore no minimum-rustc surprises for anyone
// building Omega). Used to probe many hosts/ports concurrently instead of
// one at a time, which is what makes `discover hosts` and `scan ports`
// practical on anything wider than a single IP.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// Discovery nests port-level parallelism inside host-level parallelism
// (each host's liveness check probes several ports concurrently), so this
// cap bounds the worst case at MAX_CONCURRENCY^2 simultaneous threads
// rather than an unbounded burst.
const MAX_CONCURRENCY: usize = 32;

/// Delay (ms) inserted between chunks of concurrent work, set globally via
/// the `timing` statement. 0 (the default, "aggressive") means no
/// throttling — current behavior unchanged. This throttles between chunks
/// of up to MAX_CONCURRENCY items, not between every individual probe
/// within a chunk — staggering every single probe would defeat the point
/// of running them concurrently at all. "normal"/"slow" trade scan speed
/// for being less likely to trip IDS/IPS or rate limits on the target.
static CHUNK_DELAY_MS: AtomicU64 = AtomicU64::new(0);

pub fn set_timing(profile: &str) -> Result<(), String> {
    let ms = match profile {
        "aggressive" => 0,
        "normal" => 200,
        "slow" => 1000,
        other => {
            return Err(format!(
                "unknown timing profile '{}': expected aggressive, normal, or slow",
                other
            ))
        }
    };
    CHUNK_DELAY_MS.store(ms, Ordering::Relaxed);
    Ok(())
}

pub fn parallel_map<T, R, F>(items: &[T], worker: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let delay_ms = CHUNK_DELAY_MS.load(Ordering::Relaxed);
    let chunks: Vec<&[T]> = items.chunks(MAX_CONCURRENCY).collect();
    let num_chunks = chunks.len();
    let mut results = Vec::with_capacity(items.len());
    for (i, chunk) in chunks.into_iter().enumerate() {
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
        if delay_ms > 0 && i + 1 < num_chunks {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
    }
    results
}

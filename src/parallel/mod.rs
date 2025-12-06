//! Parallel processing module for multi-core packet processing
//!
//! Provides parallel batch processing for high-throughput NIDS operation.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Configuration for parallel processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelConfig {
    /// Number of worker threads (0 = auto-detect CPU count)
    pub num_threads: usize,
    /// Number of packets per batch for parallel processing
    pub batch_size: usize,
    /// Queue depth per worker thread
    pub queue_depth: usize,
    /// Enable parallel signature matching
    pub parallel_signatures: bool,
    /// Enable parallel flow processing
    pub parallel_flows: bool,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_threads: 0, // Auto-detect
            batch_size: 1000,
            queue_depth: 16,
            parallel_signatures: true,
            parallel_flows: true,
        }
    }
}

impl ParallelConfig {
    /// Get actual number of threads to use
    pub fn actual_threads(&self) -> usize {
        if self.num_threads == 0 {
            #[cfg(feature = "parallel")]
            {
                num_cpus::get().max(1)
            }
            #[cfg(not(feature = "parallel"))]
            {
                1
            }
        } else {
            self.num_threads
        }
    }

    /// Initialize the global thread pool with configured thread count
    #[cfg(feature = "parallel")]
    pub fn init_thread_pool(&self) -> Result<(), rayon::ThreadPoolBuildError> {
        rayon::ThreadPoolBuilder::new()
            .num_threads(self.actual_threads())
            .build_global()
    }

    /// Create a new config with specified thread count
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.num_threads = threads;
        self
    }

    /// Create a new config with specified batch size
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }
}

/// Thread-safe statistics for parallel processing
#[derive(Debug, Default)]
pub struct ParallelStats {
    /// Total packets processed across all threads
    pub packets_processed: AtomicU64,
    /// Total signature matches
    pub signature_matches: AtomicU64,
    /// Total bytes processed
    pub bytes_processed: AtomicU64,
    /// Total batches processed
    pub batches_processed: AtomicU64,
    /// Current active workers
    pub active_workers: AtomicUsize,
}

impl ParallelStats {
    /// Create new stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Create shared stats
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Add packets processed (thread-safe)
    #[inline]
    pub fn add_packets(&self, count: u64) {
        self.packets_processed.fetch_add(count, Ordering::Relaxed);
    }

    /// Add signature matches (thread-safe)
    #[inline]
    pub fn add_matches(&self, count: u64) {
        self.signature_matches.fetch_add(count, Ordering::Relaxed);
    }

    /// Add bytes processed (thread-safe)
    #[inline]
    pub fn add_bytes(&self, count: u64) {
        self.bytes_processed.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment batch count (thread-safe)
    #[inline]
    pub fn inc_batches(&self) {
        self.batches_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get packets processed
    pub fn get_packets(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }

    /// Get signature matches
    pub fn get_matches(&self) -> u64 {
        self.signature_matches.load(Ordering::Relaxed)
    }

    /// Get bytes processed
    pub fn get_bytes(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    /// Get batches processed
    pub fn get_batches(&self) -> u64 {
        self.batches_processed.load(Ordering::Relaxed)
    }

    /// Reset all counters
    pub fn reset(&self) {
        self.packets_processed.store(0, Ordering::Relaxed);
        self.signature_matches.store(0, Ordering::Relaxed);
        self.bytes_processed.store(0, Ordering::Relaxed);
        self.batches_processed.store(0, Ordering::Relaxed);
    }
}

/// Result from processing a batch of packets
#[derive(Debug, Default)]
pub struct BatchResult {
    /// Number of packets processed in this batch
    pub packets: usize,
    /// Number of signature matches in this batch
    pub matches: usize,
    /// Total bytes in this batch
    pub bytes: u64,
    /// Processing time in nanoseconds
    pub time_ns: u64,
}

impl BatchResult {
    /// Create a new batch result
    pub fn new(packets: usize, matches: usize, bytes: u64, time_ns: u64) -> Self {
        Self {
            packets,
            matches,
            bytes,
            time_ns,
        }
    }

    /// Merge multiple batch results
    pub fn merge(results: Vec<BatchResult>) -> BatchResult {
        let mut merged = BatchResult::default();
        for r in results {
            merged.packets += r.packets;
            merged.matches += r.matches;
            merged.bytes += r.bytes;
            merged.time_ns = merged.time_ns.max(r.time_ns); // Max time for parallel
        }
        merged
    }
}

/// Process items in parallel batches
#[cfg(feature = "parallel")]
pub fn parallel_process<T, F, R>(items: Vec<T>, batch_size: usize, process_fn: F) -> Vec<R>
where
    T: Send + Sync,
    R: Send,
    F: Fn(&[T]) -> R + Send + Sync,
{
    items
        .par_chunks(batch_size)
        .map(|batch| process_fn(batch))
        .collect()
}

/// Process items in parallel batches (non-parallel fallback)
#[cfg(not(feature = "parallel"))]
pub fn parallel_process<T, F, R>(items: Vec<T>, batch_size: usize, process_fn: F) -> Vec<R>
where
    F: Fn(&[T]) -> R,
{
    items
        .chunks(batch_size)
        .map(|batch| process_fn(batch))
        .collect()
}

/// Parallel iterator extension for processing
#[cfg(feature = "parallel")]
pub trait ParallelExt<T> {
    /// Process items in parallel, returning results
    fn par_map<F, R>(self, f: F) -> Vec<R>
    where
        F: Fn(T) -> R + Send + Sync,
        R: Send;
}

#[cfg(feature = "parallel")]
impl<T: Send> ParallelExt<T> for Vec<T> {
    fn par_map<F, R>(self, f: F) -> Vec<R>
    where
        F: Fn(T) -> R + Send + Sync,
        R: Send,
    {
        self.into_par_iter().map(f).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_config_default() {
        let config = ParallelConfig::default();
        assert_eq!(config.batch_size, 1000);
        assert!(config.parallel_signatures);
    }

    #[test]
    fn test_parallel_config_builder() {
        let config = ParallelConfig::default()
            .with_threads(8)
            .with_batch_size(5000);
        assert_eq!(config.num_threads, 8);
        assert_eq!(config.batch_size, 5000);
    }

    #[test]
    fn test_parallel_stats() {
        let stats = ParallelStats::new();
        stats.add_packets(100);
        stats.add_matches(5);
        stats.add_bytes(50000);

        assert_eq!(stats.get_packets(), 100);
        assert_eq!(stats.get_matches(), 5);
        assert_eq!(stats.get_bytes(), 50000);
    }

    #[test]
    fn test_batch_result_merge() {
        let results = vec![
            BatchResult::new(100, 5, 10000, 1000),
            BatchResult::new(100, 3, 10000, 2000),
            BatchResult::new(100, 7, 10000, 1500),
        ];
        let merged = BatchResult::merge(results);
        assert_eq!(merged.packets, 300);
        assert_eq!(merged.matches, 15);
        assert_eq!(merged.bytes, 30000);
        assert_eq!(merged.time_ns, 2000); // Max time
    }

    #[test]
    fn test_parallel_process() {
        let items: Vec<i32> = (0..100).collect();
        let results = parallel_process(items, 10, |batch| batch.iter().sum::<i32>());
        assert_eq!(results.len(), 10);
        let total: i32 = results.iter().sum();
        assert_eq!(total, (0..100).sum::<i32>());
    }
}

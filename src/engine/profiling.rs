//! Pipeline profiling with histogram-based latency tracking
//!
//! Provides detailed performance metrics for each pipeline stage including:
//! - Per-stage latency histograms (p50, p95, p99)
//! - Per-stage throughput (packets/sec)
//! - Total pipeline latency and throughput
//! - Bottleneck identification

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use hdrhistogram::Histogram;
use parking_lot::Mutex;
use serde::Serialize;

use super::pipeline::PipelineStage;

/// Per-stage metrics with histogram-based latency tracking
#[derive(Debug)]
pub struct StageProfile {
    /// Packets that passed through this stage
    pub pass_count: AtomicU64,
    /// Packets marked as suspicious by this stage
    pub marked_count: AtomicU64,
    /// Errors encountered
    pub errors: AtomicU64,
    /// Latency histogram (nanoseconds)
    latency_histogram: Mutex<Histogram<u64>>,
    /// Total processing time for throughput calculation
    total_time_ns: AtomicU64,
}

impl Default for StageProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl StageProfile {
    /// Create new stage profile
    pub fn new() -> Self {
        // Histogram: 1ns to 1 second, 3 significant digits
        let histogram = Histogram::new_with_bounds(1, 1_000_000_000, 3)
            .expect("Failed to create histogram");

        Self {
            pass_count: AtomicU64::new(0),
            marked_count: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            latency_histogram: Mutex::new(histogram),
            total_time_ns: AtomicU64::new(0),
        }
    }

    /// Record a packet passing through with latency
    pub fn record(&self, latency_ns: u64) {
        self.pass_count.fetch_add(1, Ordering::Relaxed);
        self.total_time_ns.fetch_add(latency_ns, Ordering::Relaxed);

        let mut hist = self.latency_histogram.lock();
        // Clamp to histogram bounds
        let clamped = latency_ns.max(1).min(1_000_000_000);
        let _ = hist.record(clamped);
    }

    /// Record a packet being marked as suspicious
    pub fn record_marked(&self) {
        self.marked_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an error
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get latency percentile in nanoseconds
    pub fn percentile(&self, p: f64) -> u64 {
        self.latency_histogram.lock().value_at_percentile(p)
    }

    /// Get p50 latency
    pub fn p50(&self) -> u64 {
        self.percentile(50.0)
    }

    /// Get p95 latency
    pub fn p95(&self) -> u64 {
        self.percentile(95.0)
    }

    /// Get p99 latency
    pub fn p99(&self) -> u64 {
        self.percentile(99.0)
    }

    /// Get max latency
    pub fn max(&self) -> u64 {
        self.latency_histogram.lock().max()
    }

    /// Get mean latency
    pub fn mean(&self) -> f64 {
        self.latency_histogram.lock().mean()
    }

    /// Get total processing time in nanoseconds
    pub fn total_time_ns(&self) -> u64 {
        self.total_time_ns.load(Ordering::Relaxed)
    }

    /// Get snapshot of metrics
    pub fn snapshot(&self, stage_name: &'static str, total_pipeline_time_ns: u64) -> StageProfileSnapshot {
        let hist = self.latency_histogram.lock();
        let pass_count = self.pass_count.load(Ordering::Relaxed);
        let stage_time = self.total_time_ns.load(Ordering::Relaxed);

        let time_percent = if total_pipeline_time_ns > 0 {
            (stage_time as f64 / total_pipeline_time_ns as f64 * 100.0) as f32
        } else {
            0.0
        };

        StageProfileSnapshot {
            name: stage_name,
            pass_count,
            marked_count: self.marked_count.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            latency_p50_ns: hist.value_at_percentile(50.0),
            latency_p95_ns: hist.value_at_percentile(95.0),
            latency_p99_ns: hist.value_at_percentile(99.0),
            latency_mean_ns: hist.mean(),
            latency_max_ns: hist.max(),
            time_percent,
        }
    }

    /// Reset histogram for interval-based reporting
    pub fn reset_histogram(&self) {
        self.latency_histogram.lock().reset();
    }
}

/// Snapshot of stage profile (for reporting)
#[derive(Debug, Clone, Serialize)]
pub struct StageProfileSnapshot {
    /// Stage name
    pub name: &'static str,
    /// Packets that passed through
    pub pass_count: u64,
    /// Packets marked as suspicious
    pub marked_count: u64,
    /// Errors encountered
    pub errors: u64,
    /// p50 latency (nanoseconds)
    pub latency_p50_ns: u64,
    /// p95 latency (nanoseconds)
    pub latency_p95_ns: u64,
    /// p99 latency (nanoseconds)
    pub latency_p99_ns: u64,
    /// Mean latency (nanoseconds)
    pub latency_mean_ns: f64,
    /// Max latency (nanoseconds)
    pub latency_max_ns: u64,
    /// Percentage of total pipeline time
    pub time_percent: f32,
}

impl StageProfileSnapshot {
    /// Format latency as human-readable string
    pub fn format_latency(ns: u64) -> String {
        if ns >= 1_000_000 {
            format!("{:.1}ms", ns as f64 / 1_000_000.0)
        } else if ns >= 1_000 {
            format!("{:.1}µs", ns as f64 / 1_000.0)
        } else {
            format!("{}ns", ns)
        }
    }
}

/// Full pipeline profiler
#[derive(Debug)]
pub struct PipelineProfiler {
    /// Per-stage profiles
    stages: HashMap<PipelineStage, StageProfile>,
    /// Total pipeline latency histogram
    total_latency: Mutex<Histogram<u64>>,
    /// Start time for throughput calculation
    start_time: Instant,
    /// Total packets processed
    total_packets: AtomicU64,
    /// Last reset time for interval reporting
    last_reset: Mutex<Instant>,
}

impl Default for PipelineProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineProfiler {
    /// Create new pipeline profiler with all stages
    pub fn new() -> Self {
        let mut stages = HashMap::new();
        for stage in PipelineStage::all() {
            stages.insert(stage, StageProfile::new());
        }

        let total_latency = Histogram::new_with_bounds(1, 1_000_000_000, 3)
            .expect("Failed to create histogram");

        Self {
            stages,
            total_latency: Mutex::new(total_latency),
            start_time: Instant::now(),
            total_packets: AtomicU64::new(0),
            last_reset: Mutex::new(Instant::now()),
        }
    }

    /// Get profile for a specific stage
    pub fn stage(&self, stage: PipelineStage) -> Option<&StageProfile> {
        self.stages.get(&stage)
    }

    /// Record total pipeline latency for a packet
    pub fn record_total(&self, latency_ns: u64) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        let mut hist = self.total_latency.lock();
        let clamped = latency_ns.max(1).min(1_000_000_000);
        let _ = hist.record(clamped);
    }

    /// Get total packets processed
    pub fn total_packets(&self) -> u64 {
        self.total_packets.load(Ordering::Relaxed)
    }

    /// Get throughput (packets per second)
    pub fn throughput(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.total_packets.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Get interval throughput since last reset
    pub fn interval_throughput(&self) -> f64 {
        let last_reset = self.last_reset.lock();
        let elapsed = last_reset.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.total_packets.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Identify bottleneck stage (highest average latency)
    pub fn bottleneck(&self) -> Option<PipelineStage> {
        self.stages
            .iter()
            .filter(|(_, profile)| profile.pass_count.load(Ordering::Relaxed) > 0)
            .max_by(|(_, a), (_, b)| {
                a.mean().partial_cmp(&b.mean()).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(stage, _)| *stage)
    }

    /// Get full pipeline profile snapshot
    pub fn snapshot(&self) -> PipelineProfileSnapshot {
        // Calculate total pipeline time
        let total_pipeline_time_ns: u64 = self.stages
            .values()
            .map(|s| s.total_time_ns())
            .sum();

        let stages: Vec<StageProfileSnapshot> = PipelineStage::all()
            .iter()
            .filter_map(|stage| {
                self.stages.get(stage).map(|profile| {
                    profile.snapshot(stage.name(), total_pipeline_time_ns)
                })
            })
            .collect();

        let total_hist = self.total_latency.lock();
        let uptime = self.start_time.elapsed().as_secs();

        PipelineProfileSnapshot {
            stages,
            total_latency_p50_ns: total_hist.value_at_percentile(50.0),
            total_latency_p95_ns: total_hist.value_at_percentile(95.0),
            total_latency_p99_ns: total_hist.value_at_percentile(99.0),
            total_latency_mean_ns: total_hist.mean(),
            total_latency_max_ns: total_hist.max(),
            total_throughput_pps: self.throughput() as u64,
            total_packets: self.total_packets.load(Ordering::Relaxed),
            bottleneck_stage: self.bottleneck().map(|s| s.name()),
            uptime_secs: uptime,
        }
    }

    /// Reset all histograms (for interval-based reporting)
    pub fn reset_histograms(&self) {
        for profile in self.stages.values() {
            profile.reset_histogram();
        }
        self.total_latency.lock().reset();
        *self.last_reset.lock() = Instant::now();
    }

    /// Log profile summary (for debug output)
    pub fn log_summary(&self) {
        use tracing::debug;

        let snapshot = self.snapshot();

        debug!("┌────────────────────────┬──────────┬─────────┬─────────┬─────────┬─────────┬────────┐");
        debug!("│ Stage                  │ Pass     │ Marked  │ p50     │ p95     │ p99     │ Time % │");
        debug!("├────────────────────────┼──────────┼─────────┼─────────┼─────────┼─────────┼────────┤");

        for stage in &snapshot.stages {
            if stage.pass_count > 0 {
                let bottleneck = if Some(stage.name) == snapshot.bottleneck_stage {
                    " ←"
                } else {
                    ""
                };
                debug!(
                    "│ {:22} │ {:>8} │ {:>7} │ {:>7} │ {:>7} │ {:>7} │ {:>5.1}%{}│",
                    stage.name,
                    stage.pass_count,
                    stage.marked_count,
                    StageProfileSnapshot::format_latency(stage.latency_p50_ns),
                    StageProfileSnapshot::format_latency(stage.latency_p95_ns),
                    StageProfileSnapshot::format_latency(stage.latency_p99_ns),
                    stage.time_percent,
                    bottleneck
                );
            }
        }

        debug!("├────────────────────────┼──────────┼─────────┼─────────┼─────────┼─────────┼────────┤");
        debug!(
            "│ TOTAL                  │ {:>8} │         │ {:>7} │ {:>7} │ {:>7} │  100%  │",
            snapshot.total_packets,
            StageProfileSnapshot::format_latency(snapshot.total_latency_p50_ns),
            StageProfileSnapshot::format_latency(snapshot.total_latency_p95_ns),
            StageProfileSnapshot::format_latency(snapshot.total_latency_p99_ns),
        );
        debug!("└────────────────────────┴──────────┴─────────┴─────────┴─────────┴─────────┴────────┘");

        if let Some(bottleneck) = &snapshot.bottleneck_stage {
            debug!("Throughput: {} pps | Bottleneck: {}", snapshot.total_throughput_pps, bottleneck);
        } else {
            debug!("Throughput: {} pps", snapshot.total_throughput_pps);
        }
    }
}

/// Full pipeline profile snapshot
#[derive(Debug, Clone, Serialize)]
pub struct PipelineProfileSnapshot {
    /// Per-stage snapshots
    pub stages: Vec<StageProfileSnapshot>,
    /// Total p50 latency (nanoseconds)
    pub total_latency_p50_ns: u64,
    /// Total p95 latency (nanoseconds)
    pub total_latency_p95_ns: u64,
    /// Total p99 latency (nanoseconds)
    pub total_latency_p99_ns: u64,
    /// Total mean latency (nanoseconds)
    pub total_latency_mean_ns: f64,
    /// Total max latency (nanoseconds)
    pub total_latency_max_ns: u64,
    /// Total throughput (packets/sec)
    pub total_throughput_pps: u64,
    /// Total packets processed
    pub total_packets: u64,
    /// Bottleneck stage name
    pub bottleneck_stage: Option<&'static str>,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_profile_creation() {
        let profile = StageProfile::new();
        assert_eq!(profile.pass_count.load(Ordering::Relaxed), 0);
        assert_eq!(profile.p50(), 0);
    }

    #[test]
    fn test_stage_profile_recording() {
        let profile = StageProfile::new();

        // Record some latencies
        for i in 1..=100 {
            profile.record(i * 1000); // 1µs to 100µs
        }

        assert_eq!(profile.pass_count.load(Ordering::Relaxed), 100);

        // p50 should be around 50µs
        let p50 = profile.p50();
        assert!(p50 >= 40_000 && p50 <= 60_000, "p50={}", p50);

        // p99 should be around 99µs
        let p99 = profile.p99();
        assert!(p99 >= 90_000 && p99 <= 100_000, "p99={}", p99);
    }

    #[test]
    fn test_pipeline_profiler_creation() {
        let profiler = PipelineProfiler::new();

        // Should have all stages
        assert!(profiler.stage(PipelineStage::FlowTracker).is_some());
        assert!(profiler.stage(PipelineStage::SignatureMatching).is_some());
        assert!(profiler.stage(PipelineStage::Correlation).is_some());
    }

    #[test]
    fn test_bottleneck_detection() {
        let profiler = PipelineProfiler::new();

        // Record fast latencies for flow tracker
        if let Some(flow) = profiler.stage(PipelineStage::FlowTracker) {
            for _ in 0..100 {
                flow.record(1_000); // 1µs
            }
        }

        // Record slow latencies for signature matching
        if let Some(sig) = profiler.stage(PipelineStage::SignatureMatching) {
            for _ in 0..100 {
                sig.record(100_000); // 100µs
            }
        }

        // Signature matching should be the bottleneck
        let bottleneck = profiler.bottleneck();
        assert_eq!(bottleneck, Some(PipelineStage::SignatureMatching));
    }

    #[test]
    fn test_format_latency() {
        assert_eq!(StageProfileSnapshot::format_latency(500), "500ns");
        assert_eq!(StageProfileSnapshot::format_latency(1_500), "1.5µs");
        assert_eq!(StageProfileSnapshot::format_latency(1_500_000), "1.5ms");
    }

    #[test]
    fn test_snapshot() {
        let profiler = PipelineProfiler::new();

        // Record some data
        if let Some(flow) = profiler.stage(PipelineStage::FlowTracker) {
            flow.record(1_000);
            flow.record_marked();
        }
        profiler.record_total(5_000);

        let snapshot = profiler.snapshot();
        assert_eq!(snapshot.total_packets, 1);
        assert!(!snapshot.stages.is_empty());
    }
}

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
    /// Packets marked as suspicious by this stage (detections)
    pub marked_count: AtomicU64,
    /// True positives (confirmed detections)
    pub true_positives: AtomicU64,
    /// False positives (confirmed false alarms)
    pub false_positives: AtomicU64,
    /// False negatives (missed detections - from external feedback)
    pub false_negatives: AtomicU64,
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
            true_positives: AtomicU64::new(0),
            false_positives: AtomicU64::new(0),
            false_negatives: AtomicU64::new(0),
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

    /// Record a confirmed true positive (detection was correct)
    pub fn record_true_positive(&self) {
        self.true_positives.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a confirmed false positive (detection was wrong)
    pub fn record_false_positive(&self) {
        self.false_positives.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a false negative (missed detection - from external feedback)
    pub fn record_false_negative(&self) {
        self.false_negatives.fetch_add(1, Ordering::Relaxed);
    }

    /// Get detection rate (marked / pass)
    /// Returns 0.0 - 1.0 (percentage as decimal)
    pub fn detection_rate(&self) -> f64 {
        let pass = self.pass_count.load(Ordering::Relaxed);
        let marked = self.marked_count.load(Ordering::Relaxed);
        if pass > 0 {
            marked as f64 / pass as f64
        } else {
            0.0
        }
    }

    /// Get false positive rate (FP / (FP + TN))
    /// Note: TN is estimated as pass_count - marked_count - FN
    /// Returns 0.0 - 1.0 (percentage as decimal)
    pub fn false_positive_rate(&self) -> f64 {
        let fp = self.false_positives.load(Ordering::Relaxed);
        let marked = self.marked_count.load(Ordering::Relaxed);
        if marked > 0 {
            fp as f64 / marked as f64
        } else {
            0.0
        }
    }

    /// Get precision (TP / (TP + FP))
    /// Returns 0.0 - 1.0, or None if no confirmed feedback
    pub fn precision(&self) -> Option<f64> {
        let tp = self.true_positives.load(Ordering::Relaxed);
        let fp = self.false_positives.load(Ordering::Relaxed);
        let total = tp + fp;
        if total > 0 {
            Some(tp as f64 / total as f64)
        } else {
            None
        }
    }

    /// Get recall (TP / (TP + FN))
    /// Returns 0.0 - 1.0, or None if no confirmed feedback
    pub fn recall(&self) -> Option<f64> {
        let tp = self.true_positives.load(Ordering::Relaxed);
        let fn_ = self.false_negatives.load(Ordering::Relaxed);
        let total = tp + fn_;
        if total > 0 {
            Some(tp as f64 / total as f64)
        } else {
            None
        }
    }

    /// Get F1 score (harmonic mean of precision and recall)
    pub fn f1_score(&self) -> Option<f64> {
        let precision = self.precision()?;
        let recall = self.recall()?;
        if precision + recall > 0.0 {
            Some(2.0 * precision * recall / (precision + recall))
        } else {
            None
        }
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
        let marked_count = self.marked_count.load(Ordering::Relaxed);
        let stage_time = self.total_time_ns.load(Ordering::Relaxed);

        let time_percent = if total_pipeline_time_ns > 0 {
            (stage_time as f64 / total_pipeline_time_ns as f64 * 100.0) as f32
        } else {
            0.0
        };

        let detection_rate = if pass_count > 0 {
            marked_count as f64 / pass_count as f64
        } else {
            0.0
        };

        let tp = self.true_positives.load(Ordering::Relaxed);
        let fp = self.false_positives.load(Ordering::Relaxed);
        let fn_ = self.false_negatives.load(Ordering::Relaxed);

        let precision = if tp + fp > 0 {
            Some(tp as f64 / (tp + fp) as f64)
        } else {
            None
        };

        let recall = if tp + fn_ > 0 {
            Some(tp as f64 / (tp + fn_) as f64)
        } else {
            None
        };

        let false_positive_rate = if marked_count > 0 {
            fp as f64 / marked_count as f64
        } else {
            0.0
        };

        StageProfileSnapshot {
            name: stage_name,
            pass_count,
            marked_count,
            true_positives: tp,
            false_positives: fp,
            false_negatives: fn_,
            errors: self.errors.load(Ordering::Relaxed),
            latency_p50_ns: hist.value_at_percentile(50.0),
            latency_p95_ns: hist.value_at_percentile(95.0),
            latency_p99_ns: hist.value_at_percentile(99.0),
            latency_mean_ns: hist.mean(),
            latency_max_ns: hist.max(),
            time_percent,
            detection_rate,
            false_positive_rate,
            precision,
            recall,
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
    /// Packets marked as suspicious (detections)
    pub marked_count: u64,
    /// Confirmed true positives
    pub true_positives: u64,
    /// Confirmed false positives
    pub false_positives: u64,
    /// Confirmed false negatives
    pub false_negatives: u64,
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
    /// Detection rate (marked / pass)
    pub detection_rate: f64,
    /// False positive rate (FP / marked)
    pub false_positive_rate: f64,
    /// Precision (TP / (TP + FP)), None if no feedback
    pub precision: Option<f64>,
    /// Recall (TP / (TP + FN)), None if no feedback
    pub recall: Option<f64>,
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
        let total_packets = self.total_packets.load(Ordering::Relaxed);

        // Aggregate detection metrics across stages
        let total_detections: u64 = stages.iter().map(|s| s.marked_count).sum();
        let total_true_positives: u64 = stages.iter().map(|s| s.true_positives).sum();
        let total_false_positives: u64 = stages.iter().map(|s| s.false_positives).sum();
        let total_false_negatives: u64 = stages.iter().map(|s| s.false_negatives).sum();

        let total_detection_rate = if total_packets > 0 {
            total_detections as f64 / total_packets as f64
        } else {
            0.0
        };

        let total_precision = if total_true_positives + total_false_positives > 0 {
            Some(total_true_positives as f64 / (total_true_positives + total_false_positives) as f64)
        } else {
            None
        };

        let total_recall = if total_true_positives + total_false_negatives > 0 {
            Some(total_true_positives as f64 / (total_true_positives + total_false_negatives) as f64)
        } else {
            None
        };

        let total_f1_score = match (total_precision, total_recall) {
            (Some(p), Some(r)) if p + r > 0.0 => Some(2.0 * p * r / (p + r)),
            _ => None,
        };

        PipelineProfileSnapshot {
            stages,
            total_latency_p50_ns: total_hist.value_at_percentile(50.0),
            total_latency_p95_ns: total_hist.value_at_percentile(95.0),
            total_latency_p99_ns: total_hist.value_at_percentile(99.0),
            total_latency_mean_ns: total_hist.mean(),
            total_latency_max_ns: total_hist.max(),
            total_throughput_pps: self.throughput() as u64,
            total_packets,
            total_detections,
            total_detection_rate,
            total_true_positives,
            total_false_positives,
            total_false_negatives,
            total_precision,
            total_recall,
            total_f1_score,
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

    /// Record feedback for a specific stage
    pub fn record_feedback(&self, stage: PipelineStage, is_true_positive: bool) {
        if let Some(profile) = self.stages.get(&stage) {
            if is_true_positive {
                profile.record_true_positive();
            } else {
                profile.record_false_positive();
            }
        }
    }

    /// Record a missed detection (false negative) for a stage
    pub fn record_missed_detection(&self, stage: PipelineStage) {
        if let Some(profile) = self.stages.get(&stage) {
            profile.record_false_negative();
        }
    }

    /// Log profile summary (for debug output)
    pub fn log_summary(&self) {
        use tracing::debug;

        let snapshot = self.snapshot();

        debug!("┌────────────────────────┬──────────┬─────────┬─────────┬─────────┬─────────┬─────────┬────────┐");
        debug!("│ Stage                  │ Pass     │ Detect  │ Det%    │ p50     │ p95     │ p99     │ Time % │");
        debug!("├────────────────────────┼──────────┼─────────┼─────────┼─────────┼─────────┼─────────┼────────┤");

        for stage in &snapshot.stages {
            if stage.pass_count > 0 {
                let bottleneck = if Some(stage.name) == snapshot.bottleneck_stage {
                    " ←"
                } else {
                    ""
                };
                debug!(
                    "│ {:22} │ {:>8} │ {:>7} │ {:>6.2}% │ {:>7} │ {:>7} │ {:>7} │ {:>5.1}%{}│",
                    stage.name,
                    stage.pass_count,
                    stage.marked_count,
                    stage.detection_rate * 100.0,
                    StageProfileSnapshot::format_latency(stage.latency_p50_ns),
                    StageProfileSnapshot::format_latency(stage.latency_p95_ns),
                    StageProfileSnapshot::format_latency(stage.latency_p99_ns),
                    stage.time_percent,
                    bottleneck
                );
            }
        }

        debug!("├────────────────────────┼──────────┼─────────┼─────────┼─────────┼─────────┼─────────┼────────┤");
        debug!(
            "│ TOTAL                  │ {:>8} │ {:>7} │ {:>6.2}% │ {:>7} │ {:>7} │ {:>7} │  100%  │",
            snapshot.total_packets,
            snapshot.total_detections,
            snapshot.total_detection_rate * 100.0,
            StageProfileSnapshot::format_latency(snapshot.total_latency_p50_ns),
            StageProfileSnapshot::format_latency(snapshot.total_latency_p95_ns),
            StageProfileSnapshot::format_latency(snapshot.total_latency_p99_ns),
        );
        debug!("└────────────────────────┴──────────┴─────────┴─────────┴─────────┴─────────┴─────────┴────────┘");

        // Show throughput and bottleneck
        let mut summary = format!("Throughput: {} pps", snapshot.total_throughput_pps);
        if let Some(bottleneck) = &snapshot.bottleneck_stage {
            summary.push_str(&format!(" | Bottleneck: {}", bottleneck));
        }
        debug!("{}", summary);

        // Show detection accuracy if feedback available
        if snapshot.total_true_positives > 0 || snapshot.total_false_positives > 0 {
            debug!(
                "Detection Accuracy: TP={} FP={} FN={} | Precision={} Recall={} F1={}",
                snapshot.total_true_positives,
                snapshot.total_false_positives,
                snapshot.total_false_negatives,
                PipelineProfileSnapshot::format_optional_percent(snapshot.total_precision),
                PipelineProfileSnapshot::format_optional_percent(snapshot.total_recall),
                PipelineProfileSnapshot::format_optional_percent(snapshot.total_f1_score),
            );
        }
    }

    /// Log detailed detection metrics for each stage
    pub fn log_detection_metrics(&self) {
        use tracing::info;

        let snapshot = self.snapshot();

        info!("┌────────────────────────┬─────────┬─────────┬─────────┬───────────┬───────────┐");
        info!("│ Stage                  │ Detect  │ TP      │ FP      │ Precision │ FP Rate   │");
        info!("├────────────────────────┼─────────┼─────────┼─────────┼───────────┼───────────┤");

        for stage in &snapshot.stages {
            if stage.marked_count > 0 || stage.true_positives > 0 || stage.false_positives > 0 {
                info!(
                    "│ {:22} │ {:>7} │ {:>7} │ {:>7} │ {:>9} │ {:>9} │",
                    stage.name,
                    stage.marked_count,
                    stage.true_positives,
                    stage.false_positives,
                    PipelineProfileSnapshot::format_optional_percent(stage.precision),
                    PipelineProfileSnapshot::format_percent(stage.false_positive_rate),
                );
            }
        }

        info!("├────────────────────────┼─────────┼─────────┼─────────┼───────────┼───────────┤");
        info!(
            "│ TOTAL                  │ {:>7} │ {:>7} │ {:>7} │ {:>9} │           │",
            snapshot.total_detections,
            snapshot.total_true_positives,
            snapshot.total_false_positives,
            PipelineProfileSnapshot::format_optional_percent(snapshot.total_precision),
        );
        info!("└────────────────────────┴─────────┴─────────┴─────────┴───────────┴───────────┘");
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
    /// Total detections (sum of all stages' marked_count)
    pub total_detections: u64,
    /// Total detection rate (detections / packets)
    pub total_detection_rate: f64,
    /// Total true positives (sum across stages)
    pub total_true_positives: u64,
    /// Total false positives (sum across stages)
    pub total_false_positives: u64,
    /// Total false negatives (sum across stages)
    pub total_false_negatives: u64,
    /// Overall precision (if feedback available)
    pub total_precision: Option<f64>,
    /// Overall recall (if feedback available)
    pub total_recall: Option<f64>,
    /// Overall F1 score (if feedback available)
    pub total_f1_score: Option<f64>,
    /// Bottleneck stage name
    pub bottleneck_stage: Option<&'static str>,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

impl PipelineProfileSnapshot {
    /// Format percentage as string
    pub fn format_percent(rate: f64) -> String {
        format!("{:.2}%", rate * 100.0)
    }

    /// Format optional percentage
    pub fn format_optional_percent(rate: Option<f64>) -> String {
        rate.map(|r| format!("{:.2}%", r * 100.0))
            .unwrap_or_else(|| "N/A".to_string())
    }
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

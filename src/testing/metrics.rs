//! Metrics collection and calculation for detection benchmarking
//!
//! Provides per-stage metrics including latency, throughput, and detection accuracy.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

#[cfg(feature = "profiling")]
use hdrhistogram::Histogram;

/// Per-stage performance and accuracy metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageMetrics {
    /// Stage name (e.g., "ipfilter", "layer234", "signatures")
    pub name: String,

    // === Latency metrics (nanoseconds) ===
    /// 50th percentile latency
    pub latency_p50_ns: u64,
    /// 95th percentile latency
    pub latency_p95_ns: u64,
    /// 99th percentile latency
    pub latency_p99_ns: u64,
    /// Maximum latency observed
    pub latency_max_ns: u64,
    /// Mean latency
    pub latency_mean_ns: f64,
    /// Total processing time
    pub total_time_ns: u64,

    // === Throughput metrics ===
    /// Total packets processed by this stage
    pub packets_processed: u64,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Packets per second
    pub packets_per_second: f64,
    /// Throughput in megabits per second
    pub megabits_per_second: f64,

    // === Detection accuracy ===
    /// True positives (correctly detected attacks)
    pub true_positives: u64,
    /// False positives (benign traffic flagged as attack)
    pub false_positives: u64,
    /// False negatives (missed attacks)
    pub false_negatives: u64,
    /// True negatives (correctly passed benign traffic)
    pub true_negatives: u64,

    // === Calculated metrics ===
    /// Detection rate: TP / (TP + FN)
    pub detection_rate: f64,
    /// Precision: TP / (TP + FP)
    pub precision: f64,
    /// False positive rate: FP / (FP + TN)
    pub false_positive_rate: f64,
    /// F1 score: 2 * (precision * recall) / (precision + recall)
    pub f1_score: f64,

    // === Detection breakdown ===
    /// Count of detections by type (e.g., "port_scan": 123)
    pub detections_by_type: HashMap<String, u64>,

    /// Percentage of total pipeline time spent in this stage
    pub time_percentage: f64,
}

impl StageMetrics {
    /// Create new stage metrics
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            latency_p50_ns: 0,
            latency_p95_ns: 0,
            latency_p99_ns: 0,
            latency_max_ns: 0,
            latency_mean_ns: 0.0,
            total_time_ns: 0,
            packets_processed: 0,
            bytes_processed: 0,
            packets_per_second: 0.0,
            megabits_per_second: 0.0,
            true_positives: 0,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 0,
            detection_rate: 0.0,
            precision: 0.0,
            false_positive_rate: 0.0,
            f1_score: 0.0,
            detections_by_type: HashMap::new(),
            time_percentage: 0.0,
        }
    }

    /// Calculate derived metrics after data collection
    pub fn calculate_derived(&mut self, total_duration: Duration) {
        let secs = total_duration.as_secs_f64();
        if secs > 0.0 {
            self.packets_per_second = self.packets_processed as f64 / secs;
            self.megabits_per_second = (self.bytes_processed as f64 * 8.0) / (secs * 1_000_000.0);
        }

        // Detection rate (recall)
        let tp_fn = self.true_positives + self.false_negatives;
        if tp_fn > 0 {
            self.detection_rate = self.true_positives as f64 / tp_fn as f64;
        }

        // Precision
        let tp_fp = self.true_positives + self.false_positives;
        if tp_fp > 0 {
            self.precision = self.true_positives as f64 / tp_fp as f64;
        }

        // False positive rate
        let fp_tn = self.false_positives + self.true_negatives;
        if fp_tn > 0 {
            self.false_positive_rate = self.false_positives as f64 / fp_tn as f64;
        }

        // F1 score
        if self.precision + self.detection_rate > 0.0 {
            self.f1_score = 2.0 * (self.precision * self.detection_rate)
                / (self.precision + self.detection_rate);
        }
    }

    /// Format latency for display
    pub fn format_latency(&self, ns: u64) -> String {
        if ns < 1_000 {
            format!("{}ns", ns)
        } else if ns < 1_000_000 {
            format!("{:.1}μs", ns as f64 / 1_000.0)
        } else if ns < 1_000_000_000 {
            format!("{:.2}ms", ns as f64 / 1_000_000.0)
        } else {
            format!("{:.2}s", ns as f64 / 1_000_000_000.0)
        }
    }
}

/// Overall accuracy metrics across all stages
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    /// Total true positives
    pub total_true_positives: u64,
    /// Total false positives
    pub total_false_positives: u64,
    /// Total false negatives
    pub total_false_negatives: u64,
    /// Total true negatives
    pub total_true_negatives: u64,
    /// Overall detection rate
    pub overall_detection_rate: f64,
    /// Overall precision
    pub overall_precision: f64,
    /// Overall false positive rate
    pub overall_false_positive_rate: f64,
    /// Overall F1 score
    pub overall_f1_score: f64,
    /// Per-attack-type detection rates
    pub detection_rates_by_type: HashMap<String, f64>,
}

impl AccuracyMetrics {
    /// Calculate from raw counts
    pub fn calculate(&mut self) {
        let tp_fn = self.total_true_positives + self.total_false_negatives;
        if tp_fn > 0 {
            self.overall_detection_rate = self.total_true_positives as f64 / tp_fn as f64;
        }

        let tp_fp = self.total_true_positives + self.total_false_positives;
        if tp_fp > 0 {
            self.overall_precision = self.total_true_positives as f64 / tp_fp as f64;
        }

        let fp_tn = self.total_false_positives + self.total_true_negatives;
        if fp_tn > 0 {
            self.overall_false_positive_rate = self.total_false_positives as f64 / fp_tn as f64;
        }

        if self.overall_precision + self.overall_detection_rate > 0.0 {
            self.overall_f1_score = 2.0 * (self.overall_precision * self.overall_detection_rate)
                / (self.overall_precision + self.overall_detection_rate);
        }
    }
}

/// Overall performance metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total duration of benchmark
    pub total_duration_ms: u64,
    /// Total packets processed
    pub total_packets: u64,
    /// Total bytes processed
    pub total_bytes: u64,
    /// Overall packets per second
    pub overall_pps: f64,
    /// Overall megabits per second
    pub overall_mbps: f64,
    /// Slowest stage (bottleneck)
    pub bottleneck_stage: String,
    /// Bottleneck p99 latency
    pub bottleneck_latency_ns: u64,
}

/// Collector for building stage metrics during benchmark
#[derive(Debug)]
pub struct MetricsCollector {
    name: String,
    start_time: Instant,
    packets: u64,
    bytes: u64,
    #[cfg(feature = "profiling")]
    latency_histogram: Histogram<u64>,
    #[cfg(not(feature = "profiling"))]
    latencies: Vec<u64>,
    detections_by_type: HashMap<String, u64>,
    true_positives: u64,
    false_positives: u64,
    false_negatives: u64,
    true_negatives: u64,
}

impl MetricsCollector {
    /// Create a new collector for a stage
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            start_time: Instant::now(),
            packets: 0,
            bytes: 0,
            #[cfg(feature = "profiling")]
            latency_histogram: Histogram::new_with_bounds(1, 1_000_000_000, 3)
                .expect("Failed to create histogram"),
            #[cfg(not(feature = "profiling"))]
            latencies: Vec::new(),
            detections_by_type: HashMap::new(),
            true_positives: 0,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 0,
        }
    }

    /// Record a packet processing
    pub fn record_packet(&mut self, bytes: u64, latency_ns: u64) {
        self.packets += 1;
        self.bytes += bytes;

        #[cfg(feature = "profiling")]
        {
            let _ = self.latency_histogram.record(latency_ns.clamp(1, 1_000_000_000));
        }
        #[cfg(not(feature = "profiling"))]
        {
            self.latencies.push(latency_ns);
        }
    }

    /// Record a detection
    pub fn record_detection(&mut self, detection_type: &str, is_true_positive: bool) {
        *self.detections_by_type.entry(detection_type.to_string()).or_insert(0) += 1;

        if is_true_positive {
            self.true_positives += 1;
        } else {
            self.false_positives += 1;
        }
    }

    /// Record a missed detection (false negative)
    pub fn record_miss(&mut self) {
        self.false_negatives += 1;
    }

    /// Record a correct pass (true negative)
    pub fn record_pass(&mut self) {
        self.true_negatives += 1;
    }

    /// Finalize and return metrics
    pub fn finalize(self) -> StageMetrics {
        let duration = self.start_time.elapsed();

        #[cfg(feature = "profiling")]
        let (p50, p95, p99, max, mean) = {
            let h = &self.latency_histogram;
            (
                h.value_at_percentile(50.0),
                h.value_at_percentile(95.0),
                h.value_at_percentile(99.0),
                h.max(),
                h.mean(),
            )
        };

        #[cfg(not(feature = "profiling"))]
        let (p50, p95, p99, max, mean) = {
            let mut sorted = self.latencies.clone();
            sorted.sort_unstable();
            let len = sorted.len();
            if len == 0 {
                (0, 0, 0, 0, 0.0)
            } else {
                let p50_idx = (len as f64 * 0.50) as usize;
                let p95_idx = (len as f64 * 0.95) as usize;
                let p99_idx = (len as f64 * 0.99) as usize;
                let sum: u64 = sorted.iter().sum();
                (
                    sorted.get(p50_idx).copied().unwrap_or(0),
                    sorted.get(p95_idx.min(len - 1)).copied().unwrap_or(0),
                    sorted.get(p99_idx.min(len - 1)).copied().unwrap_or(0),
                    sorted.last().copied().unwrap_or(0),
                    sum as f64 / len as f64,
                )
            }
        };

        let mut metrics = StageMetrics {
            name: self.name,
            latency_p50_ns: p50,
            latency_p95_ns: p95,
            latency_p99_ns: p99,
            latency_max_ns: max,
            latency_mean_ns: mean,
            total_time_ns: duration.as_nanos() as u64,
            packets_processed: self.packets,
            bytes_processed: self.bytes,
            packets_per_second: 0.0,
            megabits_per_second: 0.0,
            true_positives: self.true_positives,
            false_positives: self.false_positives,
            false_negatives: self.false_negatives,
            true_negatives: self.true_negatives,
            detection_rate: 0.0,
            precision: 0.0,
            false_positive_rate: 0.0,
            f1_score: 0.0,
            detections_by_type: self.detections_by_type,
            time_percentage: 0.0,
        };

        metrics.calculate_derived(duration);
        metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_calculation() {
        let mut metrics = StageMetrics::new("test");
        metrics.true_positives = 90;
        metrics.false_positives = 10;
        metrics.false_negatives = 10;
        metrics.true_negatives = 890;
        metrics.packets_processed = 1000;
        metrics.bytes_processed = 1_000_000;

        metrics.calculate_derived(Duration::from_secs(1));

        assert!((metrics.detection_rate - 0.9).abs() < 0.01);
        assert!((metrics.precision - 0.9).abs() < 0.01);
        assert!((metrics.false_positive_rate - 0.011).abs() < 0.01);
        assert_eq!(metrics.packets_per_second, 1000.0);
        assert_eq!(metrics.megabits_per_second, 8.0);
    }

    #[test]
    fn test_collector() {
        let mut collector = MetricsCollector::new("test_stage");

        for i in 0..100 {
            collector.record_packet(1000, (i * 1000) as u64);
        }

        collector.record_detection("port_scan", true);
        collector.record_detection("port_scan", true);
        collector.record_detection("brute_force", false);
        collector.record_miss();
        collector.record_pass();

        let metrics = collector.finalize();

        assert_eq!(metrics.packets_processed, 100);
        assert_eq!(metrics.bytes_processed, 100_000);
        assert_eq!(metrics.true_positives, 2);
        assert_eq!(metrics.false_positives, 1);
        assert_eq!(metrics.false_negatives, 1);
        assert_eq!(metrics.true_negatives, 1);
        assert_eq!(*metrics.detections_by_type.get("port_scan").unwrap(), 2);
    }
}

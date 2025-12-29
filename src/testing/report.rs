//! Report generation for detection benchmarks
//!
//! Supports multiple output formats: JSON, Markdown, CSV, and text.

use std::collections::HashMap;
use std::fmt::Write;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ground_truth::GroundTruthStats;
use super::metrics::{AccuracyMetrics, PerformanceMetrics, StageMetrics};

/// Report output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Markdown,
    Csv,
    Text,
}

/// Summary of benchmark results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total packets processed
    pub total_packets: u64,
    /// Total bytes processed
    pub total_bytes: u64,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
    /// Overall throughput in packets per second
    pub throughput_pps: f64,
    /// Overall throughput in megabits per second
    pub throughput_mbps: f64,
    /// Total detections made
    pub total_detections: u64,
    /// Overall detection rate (recall)
    pub detection_rate: f64,
    /// Overall precision
    pub precision: f64,
    /// Overall false positive rate
    pub false_positive_rate: f64,
    /// Overall F1 score
    pub f1_score: f64,
    /// Bottleneck stage name
    pub bottleneck_stage: String,
    /// Bottleneck p99 latency (microseconds)
    pub bottleneck_latency_us: f64,
}

/// Recommendation for improving detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority level
    pub priority: String,
    /// Category (performance, accuracy, configuration)
    pub category: String,
    /// Description of the issue
    pub description: String,
    /// Suggested action
    pub action: String,
}

/// Complete benchmark report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Report generation timestamp
    pub timestamp: DateTime<Utc>,
    /// Summary metrics
    pub summary: ReportSummary,
    /// Per-stage metrics
    pub stages: Vec<StageMetrics>,
    /// Accuracy metrics
    pub accuracy: AccuracyMetrics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// Ground truth statistics (if available)
    pub ground_truth_stats: Option<GroundTruthStats>,
    /// Recommendations
    pub recommendations: Vec<Recommendation>,
    /// Detection breakdown by type
    pub detection_breakdown: HashMap<String, DetectionTypeStats>,
}

/// Statistics for a detection type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionTypeStats {
    pub count: u64,
    pub true_positives: u64,
    pub false_positives: u64,
}

impl BenchmarkReport {
    /// Create a new benchmark report
    pub fn new(
        stages: Vec<StageMetrics>,
        accuracy: AccuracyMetrics,
        performance: PerformanceMetrics,
        gt_stats: Option<GroundTruthStats>,
    ) -> Self {
        // Calculate totals
        let mut total_detections = 0u64;
        let mut detection_breakdown: HashMap<String, DetectionTypeStats> = HashMap::new();

        for stage in &stages {
            if stage.name != "overall" {
                for (det_type, count) in &stage.detections_by_type {
                    let entry = detection_breakdown.entry(det_type.clone()).or_default();
                    entry.count += count;
                }
                total_detections += stage.true_positives + stage.false_positives;
            }
        }

        let summary = ReportSummary {
            total_packets: performance.total_packets,
            total_bytes: performance.total_bytes,
            total_duration_ms: performance.total_duration_ms,
            throughput_pps: performance.overall_pps,
            throughput_mbps: performance.overall_mbps,
            total_detections,
            detection_rate: accuracy.overall_detection_rate,
            precision: accuracy.overall_precision,
            false_positive_rate: accuracy.overall_false_positive_rate,
            f1_score: accuracy.overall_f1_score,
            bottleneck_stage: performance.bottleneck_stage.clone(),
            bottleneck_latency_us: performance.bottleneck_latency_ns as f64 / 1000.0,
        };

        // Generate recommendations
        let mut recommendations = Vec::new();

        // Check for performance issues
        if performance.bottleneck_latency_ns > 100_000_000 { // > 100ms
            recommendations.push(Recommendation {
                priority: "High".to_string(),
                category: "Performance".to_string(),
                description: format!(
                    "{} stage has high latency (p99: {:.1}ms)",
                    performance.bottleneck_stage,
                    performance.bottleneck_latency_ns as f64 / 1_000_000.0
                ),
                action: "Consider enabling parallel processing or reducing rule complexity".to_string(),
            });
        }

        // Check for accuracy issues
        if accuracy.overall_false_positive_rate > 0.05 {
            recommendations.push(Recommendation {
                priority: "Medium".to_string(),
                category: "Accuracy".to_string(),
                description: format!(
                    "High false positive rate: {:.1}%",
                    accuracy.overall_false_positive_rate * 100.0
                ),
                action: "Review detection thresholds and tune sensitivity".to_string(),
            });
        }

        if accuracy.overall_detection_rate < 0.80 {
            recommendations.push(Recommendation {
                priority: "High".to_string(),
                category: "Accuracy".to_string(),
                description: format!(
                    "Low detection rate: {:.1}%",
                    accuracy.overall_detection_rate * 100.0
                ),
                action: "Review missed attacks and add detection rules".to_string(),
            });
        }

        Self {
            timestamp: Utc::now(),
            summary,
            stages,
            accuracy,
            performance,
            ground_truth_stats: gt_stats,
            recommendations,
            detection_breakdown,
        }
    }

    /// Format as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as Markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        writeln!(md, "# Detection Benchmark Report").unwrap();
        writeln!(md, "Generated: {}\n", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")).unwrap();

        // Summary
        writeln!(md, "## Summary\n").unwrap();
        writeln!(md, "| Metric | Value |").unwrap();
        writeln!(md, "|--------|-------|").unwrap();
        writeln!(md, "| Total Packets | {} |", format_number(self.summary.total_packets)).unwrap();
        writeln!(md, "| Duration | {:.2}s |", self.summary.total_duration_ms as f64 / 1000.0).unwrap();
        writeln!(md, "| Throughput | {:.0} pps / {:.1} Mbps |",
            self.summary.throughput_pps, self.summary.throughput_mbps).unwrap();
        writeln!(md, "| Total Detections | {} |", self.summary.total_detections).unwrap();
        writeln!(md, "| Detection Rate | {:.1}% |", self.summary.detection_rate * 100.0).unwrap();
        writeln!(md, "| Precision | {:.1}% |", self.summary.precision * 100.0).unwrap();
        writeln!(md, "| False Positive Rate | {:.2}% |", self.summary.false_positive_rate * 100.0).unwrap();
        writeln!(md, "| F1 Score | {:.3} |", self.summary.f1_score).unwrap();
        writeln!(md).unwrap();

        // Per-stage performance
        writeln!(md, "## Per-Stage Performance\n").unwrap();
        writeln!(md, "| Stage | Latency p50 | p95 | p99 | Max | Throughput | Time % |").unwrap();
        writeln!(md, "|-------|-------------|-----|-----|-----|------------|--------|").unwrap();

        for stage in &self.stages {
            if stage.name == "overall" {
                continue;
            }
            writeln!(md, "| {} | {} | {} | {} | {} | {:.0} pps | {:.1}% |",
                stage.name,
                format_latency(stage.latency_p50_ns),
                format_latency(stage.latency_p95_ns),
                format_latency(stage.latency_p99_ns),
                format_latency(stage.latency_max_ns),
                stage.packets_per_second,
                stage.time_percentage,
            ).unwrap();
        }
        writeln!(md).unwrap();

        // Per-stage accuracy
        writeln!(md, "## Per-Stage Accuracy\n").unwrap();
        writeln!(md, "| Stage | TP | FP | FN | Detection Rate | Precision | FP Rate |").unwrap();
        writeln!(md, "|-------|-----|-----|-----|---------------|-----------|---------|").unwrap();

        for stage in &self.stages {
            if stage.name == "overall" {
                continue;
            }
            writeln!(md, "| {} | {} | {} | {} | {:.1}% | {:.1}% | {:.2}% |",
                stage.name,
                stage.true_positives,
                stage.false_positives,
                stage.false_negatives,
                stage.detection_rate * 100.0,
                stage.precision * 100.0,
                stage.false_positive_rate * 100.0,
            ).unwrap();
        }
        writeln!(md).unwrap();

        // Detection breakdown
        if !self.detection_breakdown.is_empty() {
            writeln!(md, "## Detection Breakdown\n").unwrap();
            writeln!(md, "| Detection Type | Count |").unwrap();
            writeln!(md, "|----------------|-------|").unwrap();

            let mut types: Vec<_> = self.detection_breakdown.iter().collect();
            types.sort_by(|a, b| b.1.count.cmp(&a.1.count));

            for (det_type, stats) in types {
                writeln!(md, "| {} | {} |", det_type, stats.count).unwrap();
            }
            writeln!(md).unwrap();
        }

        // Ground truth stats
        if let Some(ref gt) = self.ground_truth_stats {
            writeln!(md, "## Ground Truth Statistics\n").unwrap();
            writeln!(md, "| Metric | Value |").unwrap();
            writeln!(md, "|--------|-------|").unwrap();
            writeln!(md, "| Total Attacks | {} |", gt.total_attacks).unwrap();
            writeln!(md, "| Detected | {} |", gt.detected_attacks).unwrap();
            writeln!(md, "| Missed | {} |", gt.missed_attacks).unwrap();
            writeln!(md, "| Benign Traffic | {} |", gt.benign_count).unwrap();
            writeln!(md, "| Unique Attackers | {} |", gt.unique_attackers).unwrap();
            writeln!(md).unwrap();

            if !gt.missed_by_type.is_empty() {
                writeln!(md, "### Missed Attacks by Type\n").unwrap();
                writeln!(md, "| Type | Missed |").unwrap();
                writeln!(md, "|------|--------|").unwrap();
                for (attack_type, count) in &gt.missed_by_type {
                    writeln!(md, "| {} | {} |", attack_type, count).unwrap();
                }
                writeln!(md).unwrap();
            }
        }

        // Bottleneck analysis
        writeln!(md, "## Bottleneck Analysis\n").unwrap();
        if !self.summary.bottleneck_stage.is_empty() {
            writeln!(md, "- **Primary bottleneck:** {} (p99: {})",
                self.summary.bottleneck_stage,
                format_latency((self.summary.bottleneck_latency_us * 1000.0) as u64)).unwrap();
        } else {
            writeln!(md, "- No significant bottleneck detected").unwrap();
        }
        writeln!(md).unwrap();

        // Recommendations
        if !self.recommendations.is_empty() {
            writeln!(md, "## Recommendations\n").unwrap();
            for rec in &self.recommendations {
                writeln!(md, "### [{}] {}\n", rec.priority, rec.category).unwrap();
                writeln!(md, "**Issue:** {}\n", rec.description).unwrap();
                writeln!(md, "**Action:** {}\n", rec.action).unwrap();
            }
        }

        md
    }

    /// Format as CSV
    pub fn to_csv(&self) -> String {
        let mut csv = String::new();

        // Header
        writeln!(csv, "stage,latency_p50_ns,latency_p95_ns,latency_p99_ns,latency_max_ns,\
            packets_processed,pps,mbps,true_positives,false_positives,false_negatives,\
            detection_rate,precision,fp_rate,f1_score,time_pct").unwrap();

        // Data rows
        for stage in &self.stages {
            writeln!(csv, "{},{},{},{},{},{},{:.2},{:.2},{},{},{},{:.4},{:.4},{:.4},{:.4},{:.2}",
                stage.name,
                stage.latency_p50_ns,
                stage.latency_p95_ns,
                stage.latency_p99_ns,
                stage.latency_max_ns,
                stage.packets_processed,
                stage.packets_per_second,
                stage.megabits_per_second,
                stage.true_positives,
                stage.false_positives,
                stage.false_negatives,
                stage.detection_rate,
                stage.precision,
                stage.false_positive_rate,
                stage.f1_score,
                stage.time_percentage,
            ).unwrap();
        }

        csv
    }

    /// Format as plain text
    pub fn to_text(&self) -> String {
        let mut text = String::new();

        writeln!(text, "═══════════════════════════════════════════════════════════════").unwrap();
        writeln!(text, "                   DETECTION BENCHMARK REPORT").unwrap();
        writeln!(text, "═══════════════════════════════════════════════════════════════").unwrap();
        writeln!(text, "Generated: {}\n", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")).unwrap();

        writeln!(text, "SUMMARY").unwrap();
        writeln!(text, "───────────────────────────────────────────────────────────────").unwrap();
        writeln!(text, "  Total Packets:     {}", format_number(self.summary.total_packets)).unwrap();
        writeln!(text, "  Duration:          {:.2}s", self.summary.total_duration_ms as f64 / 1000.0).unwrap();
        writeln!(text, "  Throughput:        {:.0} pps / {:.1} Mbps",
            self.summary.throughput_pps, self.summary.throughput_mbps).unwrap();
        writeln!(text, "  Total Detections:  {}", self.summary.total_detections).unwrap();
        writeln!(text, "  Detection Rate:    {:.1}%", self.summary.detection_rate * 100.0).unwrap();
        writeln!(text, "  Precision:         {:.1}%", self.summary.precision * 100.0).unwrap();
        writeln!(text, "  False Positive:    {:.2}%", self.summary.false_positive_rate * 100.0).unwrap();
        writeln!(text, "  F1 Score:          {:.3}", self.summary.f1_score).unwrap();
        writeln!(text).unwrap();

        writeln!(text, "PER-STAGE PERFORMANCE").unwrap();
        writeln!(text, "───────────────────────────────────────────────────────────────").unwrap();

        for stage in &self.stages {
            if stage.name == "overall" {
                continue;
            }
            writeln!(text, "  {} ({:.1}% of time)", stage.name, stage.time_percentage).unwrap();
            writeln!(text, "    Latency:   p50={}, p95={}, p99={}, max={}",
                format_latency(stage.latency_p50_ns),
                format_latency(stage.latency_p95_ns),
                format_latency(stage.latency_p99_ns),
                format_latency(stage.latency_max_ns),
            ).unwrap();
            writeln!(text, "    Accuracy:  TP={}, FP={}, FN={}, Rate={:.1}%",
                stage.true_positives, stage.false_positives, stage.false_negatives,
                stage.detection_rate * 100.0,
            ).unwrap();
        }
        writeln!(text).unwrap();

        if !self.summary.bottleneck_stage.is_empty() {
            writeln!(text, "BOTTLENECK: {} (p99: {})",
                self.summary.bottleneck_stage,
                format_latency((self.summary.bottleneck_latency_us * 1000.0) as u64)).unwrap();
        }

        text
    }

    /// Print summary to stdout
    pub fn print_summary(&self) {
        println!("{}", self.to_text());
    }
}

/// Format a number with thousands separators
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format latency for display
fn format_latency(ns: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1000000), "1,000,000");
        assert_eq!(format_number(123), "123");
    }

    #[test]
    fn test_format_latency() {
        assert_eq!(format_latency(500), "500ns");
        assert_eq!(format_latency(1500), "1.5μs");
        assert_eq!(format_latency(1_500_000), "1.50ms");
        assert_eq!(format_latency(1_500_000_000), "1.50s");
    }
}

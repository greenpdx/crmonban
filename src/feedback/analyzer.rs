//! Feedback analyzer for computing detection accuracy and generating recommendations
//!
//! Analyzes correlation results to compute FP/FN rates per module and generate
//! actionable recommendations for tuning detection parameters.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::correlation::{CorrelationEngine, CorrelationResult, CorrelationStats, DetectionEvent, MatchType};
use super::log_parsers::{LogEvent, LogParser, Service};

/// Configuration for the feedback analyzer
#[derive(Debug, Clone)]
pub struct FeedbackConfig {
    /// Time window for analysis (default: 24 hours)
    pub analysis_window: Duration,
    /// Time tolerance for correlation (default: 5 seconds)
    pub time_tolerance: Duration,
    /// Minimum events required for analysis
    pub min_samples: u64,
    /// Alert if FP rate exceeds this threshold
    pub fp_threshold: f64,
    /// Alert if FN rate exceeds this threshold
    pub fn_threshold: f64,
    /// Enable automatic parameter adjustment
    pub auto_adjust: bool,
    /// Safe bounds for auto-adjustment
    pub safe_bounds: SafeBounds,
}

impl Default for FeedbackConfig {
    fn default() -> Self {
        Self {
            analysis_window: Duration::from_secs(24 * 3600),
            time_tolerance: Duration::from_secs(5),
            min_samples: 100,
            fp_threshold: 0.05,  // 5%
            fn_threshold: 0.10,  // 10%
            auto_adjust: false,
            safe_bounds: SafeBounds::default(),
        }
    }
}

/// Safe bounds for automatic parameter adjustment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeBounds {
    /// Minimum threshold value (never go below)
    pub min_threshold: f32,
    /// Maximum threshold value (never go above)
    pub max_threshold: f32,
    /// Maximum adjustment percentage per cycle
    pub max_adjustment_pct: f32,
}

impl Default for SafeBounds {
    fn default() -> Self {
        Self {
            min_threshold: 0.3,
            max_threshold: 0.95,
            max_adjustment_pct: 0.20,  // 20%
        }
    }
}

/// Feedback analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackReport {
    /// Analysis period start
    pub period_start: DateTime<Utc>,
    /// Analysis period end
    pub period_end: DateTime<Utc>,
    /// Overall summary
    pub summary: FeedbackSummary,
    /// Per-module statistics
    pub per_module: HashMap<String, ModuleStats>,
    /// Recommendations for improvement
    pub recommendations: Vec<Recommendation>,
    /// Auto-adjustments applied (if auto_adjust enabled)
    pub auto_adjustments: Vec<super::adjuster::ConfigChange>,
}

/// Overall feedback summary
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedbackSummary {
    /// Total log events analyzed
    pub total_log_events: u64,
    /// Total detections from crmonban
    pub total_detections: u64,
    /// True positives
    pub true_positives: u64,
    /// False positives
    pub false_positives: u64,
    /// False negatives
    pub false_negatives: u64,
    /// True negatives
    pub true_negatives: u64,
    /// Precision: TP / (TP + FP)
    pub precision: f64,
    /// Recall: TP / (TP + FN)
    pub recall: f64,
    /// F1 Score
    pub f1_score: f64,
    /// False positive rate
    pub fp_rate: f64,
    /// False negative rate
    pub fn_rate: f64,
}

impl FeedbackSummary {
    /// Create from correlation stats
    pub fn from_stats(stats: &CorrelationStats) -> Self {
        Self {
            total_log_events: stats.total_events(),
            total_detections: stats.total_detections(),
            true_positives: stats.true_positives,
            false_positives: stats.false_positives,
            false_negatives: stats.false_negatives,
            true_negatives: stats.true_negatives,
            precision: stats.precision,
            recall: stats.recall,
            f1_score: stats.f1_score,
            fp_rate: stats.fp_rate,
            fn_rate: stats.fn_rate,
        }
    }
}

/// Per-module statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleStats {
    /// Module name
    pub module: String,
    /// True positives
    pub true_positives: u64,
    /// False positives
    pub false_positives: u64,
    /// False negatives
    pub false_negatives: u64,
    /// FP rate for this module
    pub fp_rate: f64,
    /// FN rate for this module
    pub fn_rate: f64,
    /// Top patterns causing false positives
    pub top_fp_patterns: Vec<(String, u64)>,
    /// Attack types being missed
    pub missed_attacks: Vec<(String, u64)>,
}

impl ModuleStats {
    /// Compute rates after populating counts
    pub fn compute_rates(&mut self) {
        let tp = self.true_positives as f64;
        let fp = self.false_positives as f64;
        let fn_ = self.false_negatives as f64;

        self.fp_rate = if tp + fp > 0.0 { fp / (tp + fp) } else { 0.0 };
        self.fn_rate = if tp + fn_ > 0.0 { fn_ / (tp + fn_) } else { 0.0 };
    }
}

/// Priority level for recommendations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::Critical => write!(f, "CRITICAL"),
            Priority::High => write!(f, "HIGH"),
            Priority::Medium => write!(f, "MEDIUM"),
            Priority::Low => write!(f, "LOW"),
        }
    }
}

/// A recommendation for improvement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority level
    pub priority: Priority,
    /// Module this affects
    pub module: String,
    /// Parameter path (e.g., "layer234.brute_force.auth_port_threshold")
    pub path: String,
    /// Current value (as string)
    pub current_value: Option<String>,
    /// Suggested value
    pub suggested_value: String,
    /// Reason for the recommendation
    pub reason: String,
    /// Expected improvement
    pub expected_improvement: String,
}

/// Feedback analyzer
pub struct FeedbackAnalyzer {
    config: FeedbackConfig,
    parsers: Vec<Box<dyn LogParser>>,
    correlation: CorrelationEngine,
}

impl FeedbackAnalyzer {
    /// Create a new feedback analyzer with default config
    pub fn new(config: FeedbackConfig) -> Self {
        let correlation = CorrelationEngine::new()
            .with_time_window(config.time_tolerance);

        Self {
            config,
            parsers: Vec::new(),
            correlation,
        }
    }

    /// Add a log parser
    pub fn add_parser(&mut self, parser: Box<dyn LogParser>) {
        self.parsers.push(parser);
    }

    /// Parse log events from a file
    pub fn parse_log_file(&self, path: &Path) -> anyhow::Result<Vec<LogEvent>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line_result in reader.lines() {
            let line = line_result?;
            if line.is_empty() {
                continue;
            }

            for parser in &self.parsers {
                if let Some(event) = parser.parse_line(&line) {
                    events.push(event);
                    break;  // Only one parser should match
                }
            }
        }

        Ok(events)
    }

    /// Parse log events from multiple files
    pub fn parse_log_files(&self, paths: &[&Path]) -> anyhow::Result<Vec<LogEvent>> {
        let mut all_events = Vec::new();

        for path in paths {
            match self.parse_log_file(path) {
                Ok(events) => {
                    info!("Parsed {} events from {}", events.len(), path.display());
                    all_events.extend(events);
                }
                Err(e) => {
                    warn!("Failed to parse {}: {}", path.display(), e);
                }
            }
        }

        // Sort by timestamp
        all_events.sort_by_key(|e| e.timestamp);

        Ok(all_events)
    }

    /// Analyze log events against detections
    pub fn analyze(
        &self,
        log_events: &[LogEvent],
        detections: &[DetectionEvent],
    ) -> anyhow::Result<FeedbackReport> {
        let period_end = Utc::now();
        let period_start = period_end - chrono::Duration::from_std(self.config.analysis_window)?;

        // Filter to analysis window
        let filtered_logs: Vec<_> = log_events
            .iter()
            .filter(|e| e.timestamp >= period_start && e.timestamp <= period_end)
            .cloned()
            .collect();

        let filtered_detections: Vec<_> = detections
            .iter()
            .filter(|d| d.timestamp >= period_start && d.timestamp <= period_end)
            .cloned()
            .collect();

        info!(
            "Analyzing {} log events and {} detections",
            filtered_logs.len(),
            filtered_detections.len()
        );

        // Correlate events
        let correlation_results = self.correlation.correlate(&filtered_logs, &filtered_detections);
        let stats = self.correlation.compute_stats(&correlation_results);

        // Build summary
        let summary = FeedbackSummary::from_stats(&stats);

        // Build per-module stats
        let per_module = self.compute_per_module_stats(&correlation_results);

        // Generate recommendations
        let recommendations = self.generate_recommendations(&summary, &per_module);

        // Auto-adjustments (placeholder - actual implementation in adjuster)
        let auto_adjustments = Vec::new();

        Ok(FeedbackReport {
            period_start,
            period_end,
            summary,
            per_module,
            recommendations,
            auto_adjustments,
        })
    }

    /// Compute per-module statistics
    fn compute_per_module_stats(
        &self,
        results: &[CorrelationResult],
    ) -> HashMap<String, ModuleStats> {
        let mut stats: HashMap<String, ModuleStats> = HashMap::new();
        let mut fp_patterns: HashMap<String, HashMap<String, u64>> = HashMap::new();
        let mut missed_attacks: HashMap<String, HashMap<String, u64>> = HashMap::new();

        for result in results {
            let module = result
                .detection
                .as_ref()
                .map(|d| d.module.clone())
                .unwrap_or_else(|| self.infer_module(&result.log_event));

            let entry = stats.entry(module.clone()).or_insert_with(|| ModuleStats {
                module: module.clone(),
                ..Default::default()
            });

            match result.match_type {
                MatchType::TruePositive => entry.true_positives += 1,
                MatchType::FalsePositive => {
                    entry.false_positives += 1;
                    // Track FP patterns
                    if let Some(ref det) = result.detection {
                        *fp_patterns
                            .entry(module.clone())
                            .or_default()
                            .entry(det.detection_type.clone())
                            .or_default() += 1;
                    }
                }
                MatchType::FalseNegative => {
                    entry.false_negatives += 1;
                    // Track missed attack types
                    if let Some(attack_type) = result.log_event.event_type.expected_detection_type() {
                        *missed_attacks
                            .entry(module.clone())
                            .or_default()
                            .entry(attack_type.to_string())
                            .or_default() += 1;
                    }
                }
                MatchType::TrueNegative => {}
            }
        }

        // Compute rates and add top patterns
        for (module, entry) in stats.iter_mut() {
            entry.compute_rates();

            // Add top FP patterns
            if let Some(patterns) = fp_patterns.get(module) {
                let mut sorted: Vec<_> = patterns.iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                entry.top_fp_patterns = sorted
                    .into_iter()
                    .take(5)
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
            }

            // Add missed attacks
            if let Some(attacks) = missed_attacks.get(module) {
                let mut sorted: Vec<_> = attacks.iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                entry.missed_attacks = sorted
                    .into_iter()
                    .take(5)
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
            }
        }

        stats
    }

    /// Infer which module should have detected an event
    fn infer_module(&self, event: &LogEvent) -> String {
        match event.service {
            Service::Sshd | Service::Postfix | Service::Dovecot => "layer234".to_string(),
            Service::NginxAccess | Service::NginxError => "http_detect".to_string(),
            Service::Custom => "signatures".to_string(),
        }
    }

    /// Generate recommendations based on analysis
    fn generate_recommendations(
        &self,
        summary: &FeedbackSummary,
        per_module: &HashMap<String, ModuleStats>,
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Check overall FP rate
        if summary.fp_rate > self.config.fp_threshold {
            recommendations.push(Recommendation {
                priority: if summary.fp_rate > 0.10 {
                    Priority::High
                } else {
                    Priority::Medium
                },
                module: "global".to_string(),
                path: "detection.sensitivity".to_string(),
                current_value: None,
                suggested_value: "reduce".to_string(),
                reason: format!(
                    "Overall FP rate is {:.1}% (threshold: {:.1}%)",
                    summary.fp_rate * 100.0,
                    self.config.fp_threshold * 100.0
                ),
                expected_improvement: format!(
                    "Reduce FP rate by ~{:.0}%",
                    (summary.fp_rate - self.config.fp_threshold) * 100.0
                ),
            });
        }

        // Check overall FN rate
        if summary.fn_rate > self.config.fn_threshold {
            recommendations.push(Recommendation {
                priority: if summary.fn_rate > 0.20 {
                    Priority::High
                } else {
                    Priority::Medium
                },
                module: "global".to_string(),
                path: "detection.sensitivity".to_string(),
                current_value: None,
                suggested_value: "increase".to_string(),
                reason: format!(
                    "Overall FN rate is {:.1}% (threshold: {:.1}%)",
                    summary.fn_rate * 100.0,
                    self.config.fn_threshold * 100.0
                ),
                expected_improvement: format!(
                    "Reduce missed attacks by ~{:.0}%",
                    (summary.fn_rate - self.config.fn_threshold) * 100.0
                ),
            });
        }

        // Per-module recommendations
        for (module, stats) in per_module {
            // High FP rate for brute force detection
            if module == "layer234" && stats.fp_rate > self.config.fp_threshold {
                if stats.top_fp_patterns.iter().any(|(p, _)| p.contains("brute")) {
                    recommendations.push(Recommendation {
                        priority: Priority::High,
                        module: module.clone(),
                        path: "layer234.brute_force.auth_port_threshold".to_string(),
                        current_value: Some("0.50".to_string()),
                        suggested_value: format!("{:.2}", 0.50 + 0.05),
                        reason: format!(
                            "Brute force FP rate: {:.1}%",
                            stats.fp_rate * 100.0
                        ),
                        expected_improvement: "Reduce false positives by ~40%".to_string(),
                    });
                }
            }

            // High FN rate for scans
            if module == "layer234" && stats.fn_rate > self.config.fn_threshold {
                if stats.missed_attacks.iter().any(|(a, _)| a.contains("scan")) {
                    recommendations.push(Recommendation {
                        priority: Priority::High,
                        module: module.clone(),
                        path: "layer234.scan.signature_threshold".to_string(),
                        current_value: Some("0.85".to_string()),
                        suggested_value: format!("{:.2}", 0.85 - 0.05),
                        reason: format!(
                            "Scan FN rate: {:.1}%",
                            stats.fn_rate * 100.0
                        ),
                        expected_improvement: "Detect more scan attacks".to_string(),
                    });
                }
            }

            // HTTP detection recommendations
            if module == "http_detect" {
                if stats.fp_rate > self.config.fp_threshold {
                    recommendations.push(Recommendation {
                        priority: Priority::Medium,
                        module: module.clone(),
                        path: "http_detect.patterns.sensitivity".to_string(),
                        current_value: None,
                        suggested_value: "reduce".to_string(),
                        reason: format!(
                            "HTTP detection FP rate: {:.1}%",
                            stats.fp_rate * 100.0
                        ),
                        expected_improvement: "Reduce web attack false positives".to_string(),
                    });
                }

                if stats.fn_rate > self.config.fn_threshold {
                    // Check what's being missed
                    for (attack_type, count) in &stats.missed_attacks {
                        recommendations.push(Recommendation {
                            priority: Priority::Medium,
                            module: module.clone(),
                            path: format!("http_detect.patterns.{}", attack_type),
                            current_value: None,
                            suggested_value: "enable or tune".to_string(),
                            reason: format!("Missing {} {} attacks", count, attack_type),
                            expected_improvement: format!("Detect {} more attacks", count),
                        });
                    }
                }
            }

            // Signature recommendations
            if module == "signatures" {
                if stats.fn_rate > self.config.fn_threshold {
                    // Check if excluded classtypes are causing misses
                    recommendations.push(Recommendation {
                        priority: Priority::Medium,
                        module: module.clone(),
                        path: "signatures.excluded_classtypes".to_string(),
                        current_value: None,
                        suggested_value: "review exclusions".to_string(),
                        reason: format!(
                            "Signature FN rate: {:.1}%",
                            stats.fn_rate * 100.0
                        ),
                        expected_improvement: "Enable signatures for missed attack types".to_string(),
                    });
                }
            }
        }

        // Sort by priority
        recommendations.sort_by(|a, b| {
            let priority_order = |p: &Priority| match p {
                Priority::Critical => 0,
                Priority::High => 1,
                Priority::Medium => 2,
                Priority::Low => 3,
            };
            priority_order(&a.priority).cmp(&priority_order(&b.priority))
        });

        recommendations
    }
}

impl FeedbackReport {
    /// Format as text for display
    pub fn to_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        writeln!(out, "═══════════════════════════════════════════════════════════════").unwrap();
        writeln!(out, "                    FEEDBACK ANALYSIS REPORT").unwrap();
        writeln!(
            out,
            "                    {} - {}",
            self.period_start.format("%Y-%m-%d %H:%M"),
            self.period_end.format("%Y-%m-%d %H:%M")
        )
        .unwrap();
        writeln!(out, "═══════════════════════════════════════════════════════════════").unwrap();
        writeln!(out).unwrap();

        writeln!(out, "SUMMARY").unwrap();
        writeln!(out, "───────────────────────────────────────────────────────────────").unwrap();
        writeln!(out, "Log Events:        {:>8}", self.summary.total_log_events).unwrap();
        writeln!(out, "Detections:        {:>8}", self.summary.total_detections).unwrap();
        writeln!(
            out,
            "True Positives:    {:>8} ({:.1}%)",
            self.summary.true_positives,
            self.summary.precision * 100.0
        )
        .unwrap();
        writeln!(
            out,
            "False Positives:   {:>8} ({:.1}%)",
            self.summary.false_positives,
            self.summary.fp_rate * 100.0
        )
        .unwrap();
        writeln!(out, "False Negatives:   {:>8}", self.summary.false_negatives).unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "Precision: {:.1}%   Recall: {:.1}%   F1: {:.1}%",
            self.summary.precision * 100.0,
            self.summary.recall * 100.0,
            self.summary.f1_score * 100.0
        )
        .unwrap();
        writeln!(out).unwrap();

        // Per-module breakdown
        if !self.per_module.is_empty() {
            writeln!(out, "PER-MODULE BREAKDOWN").unwrap();
            writeln!(out, "───────────────────────────────────────────────────────────────").unwrap();

            for (module, stats) in &self.per_module {
                writeln!(out, "{}:", module).unwrap();
                writeln!(
                    out,
                    "  TP: {}  FP: {}  FN: {}",
                    stats.true_positives, stats.false_positives, stats.false_negatives
                )
                .unwrap();

                if stats.fp_rate > 0.05 {
                    writeln!(out, "  FP Rate: {:.1}%  ← HIGH", stats.fp_rate * 100.0).unwrap();
                } else {
                    writeln!(out, "  FP Rate: {:.1}%  ✓ OK", stats.fp_rate * 100.0).unwrap();
                }

                if !stats.top_fp_patterns.is_empty() {
                    write!(out, "  Top FP cause: ").unwrap();
                    for (i, (pattern, _count)) in stats.top_fp_patterns.iter().take(2).enumerate() {
                        if i > 0 {
                            write!(out, ", ").unwrap();
                        }
                        write!(out, "{}", pattern).unwrap();
                    }
                    writeln!(out).unwrap();
                }

                if !stats.missed_attacks.is_empty() {
                    write!(out, "  Missed: ").unwrap();
                    for (i, (attack, count)) in stats.missed_attacks.iter().take(3).enumerate() {
                        if i > 0 {
                            write!(out, ", ").unwrap();
                        }
                        write!(out, "{} ({})", attack, count).unwrap();
                    }
                    writeln!(out).unwrap();
                }
                writeln!(out).unwrap();
            }
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            writeln!(out, "RECOMMENDATIONS").unwrap();
            writeln!(out, "───────────────────────────────────────────────────────────────").unwrap();

            for rec in &self.recommendations {
                writeln!(out, "[{}] {}", rec.priority, rec.path).unwrap();
                if let Some(ref current) = rec.current_value {
                    writeln!(out, "  Current: {}  →  Suggested: {}", current, rec.suggested_value).unwrap();
                } else {
                    writeln!(out, "  Suggested: {}", rec.suggested_value).unwrap();
                }
                writeln!(out, "  Reason: {}", rec.reason).unwrap();
                writeln!(out, "  Expected: {}", rec.expected_improvement).unwrap();
                writeln!(out).unwrap();
            }
        }

        out
    }

    /// Format as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as markdown
    pub fn to_markdown(&self) -> String {
        use std::fmt::Write;
        let mut md = String::new();

        writeln!(md, "# Feedback Analysis Report\n").unwrap();
        writeln!(
            md,
            "**Period:** {} to {}\n",
            self.period_start.format("%Y-%m-%d %H:%M"),
            self.period_end.format("%Y-%m-%d %H:%M")
        )
        .unwrap();

        writeln!(md, "## Summary\n").unwrap();
        writeln!(md, "| Metric | Value |").unwrap();
        writeln!(md, "|--------|-------|").unwrap();
        writeln!(md, "| Log Events | {} |", self.summary.total_log_events).unwrap();
        writeln!(md, "| Detections | {} |", self.summary.total_detections).unwrap();
        writeln!(md, "| Precision | {:.1}% |", self.summary.precision * 100.0).unwrap();
        writeln!(md, "| Recall | {:.1}% |", self.summary.recall * 100.0).unwrap();
        writeln!(md, "| F1 Score | {:.1}% |", self.summary.f1_score * 100.0).unwrap();
        writeln!(md).unwrap();

        if !self.recommendations.is_empty() {
            writeln!(md, "## Recommendations\n").unwrap();
            for rec in &self.recommendations {
                writeln!(md, "### [{}] `{}`\n", rec.priority, rec.path).unwrap();
                writeln!(md, "- **Reason:** {}", rec.reason).unwrap();
                writeln!(md, "- **Suggested:** {}", rec.suggested_value).unwrap();
                writeln!(md, "- **Expected:** {}\n", rec.expected_improvement).unwrap();
            }
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::log_parsers::LogEventType;
    use std::collections::HashMap;

    fn make_summary(tp: u64, fp: u64, fn_: u64, tn: u64) -> FeedbackSummary {
        let total = tp + fp + fn_ + tn;
        let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 };
        let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { 0.0 };

        FeedbackSummary {
            total_log_events: total,
            total_detections: tp + fp,
            true_positives: tp,
            false_positives: fp,
            false_negatives: fn_,
            true_negatives: tn,
            precision,
            recall,
            f1_score: if precision + recall > 0.0 {
                2.0 * precision * recall / (precision + recall)
            } else {
                0.0
            },
            fp_rate: if tp + fp > 0 { fp as f64 / (tp + fp) as f64 } else { 0.0 },
            fn_rate: if tp + fn_ > 0 { fn_ as f64 / (tp + fn_) as f64 } else { 0.0 },
        }
    }

    #[test]
    fn test_feedback_summary() {
        let summary = make_summary(90, 10, 5, 895);

        assert!((summary.precision - 0.9).abs() < 0.01);
        assert!((summary.recall - 0.947).abs() < 0.01);
    }

    #[test]
    fn test_report_formatting() {
        let report = FeedbackReport {
            period_start: Utc::now() - chrono::Duration::hours(24),
            period_end: Utc::now(),
            summary: make_summary(100, 5, 10, 885),
            per_module: HashMap::new(),
            recommendations: vec![Recommendation {
                priority: Priority::High,
                module: "layer234".to_string(),
                path: "layer234.brute_force.auth_port_threshold".to_string(),
                current_value: Some("0.50".to_string()),
                suggested_value: "0.55".to_string(),
                reason: "High FP rate".to_string(),
                expected_improvement: "Reduce FP by 40%".to_string(),
            }],
            auto_adjustments: vec![],
        };

        let text = report.to_text();
        assert!(text.contains("FEEDBACK ANALYSIS REPORT"));
        assert!(text.contains("RECOMMENDATIONS"));

        let json = report.to_json();
        assert!(json.contains("true_positives"));

        let md = report.to_markdown();
        assert!(md.contains("# Feedback Analysis Report"));
    }
}

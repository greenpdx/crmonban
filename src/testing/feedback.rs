//! Feedback analyzer for improving detection
//!
//! Analyzes detection logs to identify patterns, false positives,
//! and generates recommendations for improving detection accuracy.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::database::Database;

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
            Priority::Critical => write!(f, "Critical"),
            Priority::High => write!(f, "High"),
            Priority::Medium => write!(f, "Medium"),
            Priority::Low => write!(f, "Low"),
        }
    }
}

/// A finding from log analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Type of finding
    pub finding_type: FindingType,
    /// Associated stage/detector
    pub stage: Option<String>,
    /// Numeric value (rate, count, etc.)
    pub value: f64,
    /// Additional details
    pub details: String,
    /// Sample evidence
    pub samples: Vec<String>,
}

/// Types of findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingType {
    /// High false positive rate detected
    HighFalsePositiveRate,
    /// Low detection rate
    LowDetectionRate,
    /// Threshold too sensitive
    ThresholdTooSensitive,
    /// Threshold too loose
    ThresholdTooLoose,
    /// Pattern generating many FPs
    NoisyPattern,
    /// Missed attack pattern
    MissedAttackPattern,
    /// Performance bottleneck
    PerformanceBottleneck,
    /// Repeated alerts from same source
    AlertFatigue,
    /// Unusual traffic pattern
    UnusualPattern,
}

/// Recommendation for improvement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority level
    pub priority: Priority,
    /// Category (accuracy, performance, configuration)
    pub category: String,
    /// Description of the issue
    pub description: String,
    /// Suggested action
    pub action: String,
    /// Expected improvement
    pub expected_improvement: String,
}

/// Suggested configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    /// Config path (e.g., "detection.brute_force.threshold")
    pub path: String,
    /// Current value
    pub current_value: String,
    /// Suggested value
    pub suggested_value: String,
    /// Reason for change
    pub reason: String,
}

/// Feedback analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackReport {
    /// Analysis time window
    pub analysis_start: DateTime<Utc>,
    pub analysis_end: DateTime<Utc>,
    /// Total events analyzed
    pub total_events: u64,
    /// Findings from analysis
    pub findings: Vec<Finding>,
    /// Recommendations
    pub recommendations: Vec<Recommendation>,
    /// Suggested config changes
    pub config_changes: Vec<ConfigChange>,
    /// Statistics by detection type
    pub stats_by_type: HashMap<String, DetectionTypeStats>,
    /// Statistics by source IP
    pub top_sources: Vec<SourceStats>,
    /// Statistics by stage
    pub stats_by_stage: HashMap<String, StageStats>,
}

/// Statistics for a detection type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionTypeStats {
    pub count: u64,
    pub unique_sources: u64,
    pub unique_targets: u64,
    pub avg_confidence: f64,
    pub marked_false_positive: u64,
}

/// Statistics for a source IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceStats {
    pub ip: String,
    pub alert_count: u64,
    pub detection_types: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Statistics for a detection stage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageStats {
    pub total_detections: u64,
    pub avg_latency_us: f64,
    pub max_latency_us: f64,
    pub false_positive_count: u64,
}

/// Configuration for feedback analyzer
#[derive(Debug, Clone)]
pub struct FeedbackConfig {
    /// How far back to analyze
    pub analysis_window: Duration,
    /// Minimum events required for analysis
    pub min_samples: u64,
    /// Threshold for high false positive rate
    pub fp_rate_threshold: f64,
    /// Threshold for low detection rate
    pub low_detection_threshold: f64,
    /// Maximum alerts per source before fatigue warning
    pub alert_fatigue_threshold: u64,
}

impl Default for FeedbackConfig {
    fn default() -> Self {
        Self {
            analysis_window: Duration::from_secs(24 * 3600), // 24 hours
            min_samples: 100,
            fp_rate_threshold: 0.05, // 5%
            low_detection_threshold: 0.80, // 80%
            alert_fatigue_threshold: 100,
        }
    }
}

/// Feedback analyzer for improving detection
pub struct FeedbackAnalyzer {
    config: FeedbackConfig,
    db_path: Option<String>,
}

impl FeedbackAnalyzer {
    /// Create a new feedback analyzer
    pub fn new(config: FeedbackConfig) -> Self {
        Self {
            config,
            db_path: None,
        }
    }

    /// Set database path
    pub fn with_database(mut self, path: &str) -> Self {
        self.db_path = Some(path.to_string());
        self
    }

    /// Analyze detection logs from database
    pub fn analyze_from_database(&self) -> anyhow::Result<FeedbackReport> {
        let db_path = self.db_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Database path not set"))?;

        let db = Database::open(Path::new(db_path))?;

        let end_time = Utc::now();
        let start_time = end_time - chrono::Duration::from_std(self.config.analysis_window)?;

        // Query detection events
        let events = self.query_events(&db, start_time, end_time)?;

        self.analyze_events(events, start_time, end_time)
    }

    /// Analyze a collection of detection events
    pub fn analyze_events(
        &self,
        events: Vec<DetectionEventRecord>,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> anyhow::Result<FeedbackReport> {
        let mut findings = Vec::new();
        let mut recommendations = Vec::new();
        let mut config_changes = Vec::new();

        // Statistics tracking
        let mut stats_by_type: HashMap<String, DetectionTypeStats> = HashMap::new();
        let mut stats_by_stage: HashMap<String, StageStats> = HashMap::new();
        let mut alerts_by_source: HashMap<String, Vec<&DetectionEventRecord>> = HashMap::new();

        // Collect statistics
        for event in &events {
            // By type
            let type_stats = stats_by_type
                .entry(event.detection_type.clone())
                .or_default();
            type_stats.count += 1;
            if event.marked_fp {
                type_stats.marked_false_positive += 1;
            }

            // By stage
            if let Some(ref stage) = event.detector {
                let stage_stats = stats_by_stage.entry(stage.clone()).or_default();
                stage_stats.total_detections += 1;
                if event.marked_fp {
                    stage_stats.false_positive_count += 1;
                }
            }

            // By source
            alerts_by_source
                .entry(event.src_ip.clone())
                .or_default()
                .push(event);
        }

        // Analyze false positive patterns
        for (det_type, stats) in &stats_by_type {
            if stats.count >= self.config.min_samples {
                let fp_rate = stats.marked_false_positive as f64 / stats.count as f64;

                if fp_rate > self.config.fp_rate_threshold {
                    findings.push(Finding {
                        finding_type: FindingType::HighFalsePositiveRate,
                        stage: None,
                        value: fp_rate,
                        details: format!(
                            "{} has {:.1}% false positive rate ({} FPs out of {} total)",
                            det_type, fp_rate * 100.0, stats.marked_false_positive, stats.count
                        ),
                        samples: Vec::new(),
                    });

                    recommendations.push(Recommendation {
                        priority: if fp_rate > 0.10 { Priority::High } else { Priority::Medium },
                        category: "Accuracy".to_string(),
                        description: format!("{} detection has high FP rate", det_type),
                        action: "Review threshold settings and add exclusions for legitimate traffic".to_string(),
                        expected_improvement: format!("Reduce FP rate by ~{:.0}%", (fp_rate - 0.02) * 100.0),
                    });
                }
            }
        }

        // Analyze alert fatigue
        for (src_ip, src_events) in &alerts_by_source {
            if src_events.len() as u64 > self.config.alert_fatigue_threshold {
                findings.push(Finding {
                    finding_type: FindingType::AlertFatigue,
                    stage: None,
                    value: src_events.len() as f64,
                    details: format!(
                        "Source {} generated {} alerts - possible alert fatigue",
                        src_ip, src_events.len()
                    ),
                    samples: src_events.iter()
                        .take(5)
                        .map(|e| format!("{}: {}", e.timestamp, e.detection_type))
                        .collect(),
                });

                recommendations.push(Recommendation {
                    priority: Priority::Medium,
                    category: "Operations".to_string(),
                    description: format!("Alert fatigue from source {}", src_ip),
                    action: "Consider aggregating alerts or adding to watchlist instead of individual alerts".to_string(),
                    expected_improvement: "Reduce alert volume by consolidating repeated alerts".to_string(),
                });
            }
        }

        // Analyze stage performance
        for (stage, stats) in &stats_by_stage {
            let fp_rate = if stats.total_detections > 0 {
                stats.false_positive_count as f64 / stats.total_detections as f64
            } else {
                0.0
            };

            if fp_rate > self.config.fp_rate_threshold && stats.total_detections >= self.config.min_samples {
                findings.push(Finding {
                    finding_type: FindingType::HighFalsePositiveRate,
                    stage: Some(stage.clone()),
                    value: fp_rate,
                    details: format!(
                        "Stage {} has {:.1}% FP rate",
                        stage, fp_rate * 100.0
                    ),
                    samples: Vec::new(),
                });
            }
        }

        // Generate config change suggestions
        for finding in &findings {
            match finding.finding_type {
                FindingType::HighFalsePositiveRate if finding.value > 0.10 => {
                    let stage = finding.stage.as_deref().unwrap_or("unknown");
                    config_changes.push(ConfigChange {
                        path: format!("detection.{}.threshold", stage),
                        current_value: "current".to_string(),
                        suggested_value: "increase by 20%".to_string(),
                        reason: format!("High FP rate ({:.1}%) detected", finding.value * 100.0),
                    });
                }
                FindingType::AlertFatigue => {
                    config_changes.push(ConfigChange {
                        path: "alerting.aggregation.enabled".to_string(),
                        current_value: "false".to_string(),
                        suggested_value: "true".to_string(),
                        reason: "Reduce alert fatigue by aggregating similar alerts".to_string(),
                    });
                }
                _ => {}
            }
        }

        // Build top sources
        let mut top_sources: Vec<_> = alerts_by_source
            .iter()
            .map(|(ip, events)| {
                let detection_types: Vec<_> = events
                    .iter()
                    .map(|e| e.detection_type.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                SourceStats {
                    ip: ip.clone(),
                    alert_count: events.len() as u64,
                    detection_types,
                    first_seen: events.iter().map(|e| e.timestamp).min().unwrap_or(start_time),
                    last_seen: events.iter().map(|e| e.timestamp).max().unwrap_or(end_time),
                }
            })
            .collect();

        top_sources.sort_by(|a, b| b.alert_count.cmp(&a.alert_count));
        top_sources.truncate(20);

        Ok(FeedbackReport {
            analysis_start: start_time,
            analysis_end: end_time,
            total_events: events.len() as u64,
            findings,
            recommendations,
            config_changes,
            stats_by_type,
            top_sources,
            stats_by_stage,
        })
    }

    /// Query events from database (simplified)
    fn query_events(
        &self,
        _db: &Database,
        _start: DateTime<Utc>,
        _end: DateTime<Utc>,
    ) -> anyhow::Result<Vec<DetectionEventRecord>> {
        // This would query the actual database
        // For now, return empty - real implementation would use rusqlite
        Ok(Vec::new())
    }
}

/// Simplified detection event record for analysis
#[derive(Debug, Clone)]
pub struct DetectionEventRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub detection_type: String,
    pub severity: String,
    pub confidence: f64,
    pub detector: Option<String>,
    pub rule_id: Option<String>,
    pub marked_fp: bool,
}

impl FeedbackReport {
    /// Format as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as Markdown
    pub fn to_markdown(&self) -> String {
        use std::fmt::Write;
        let mut md = String::new();

        writeln!(md, "# Detection Feedback Report\n").unwrap();
        writeln!(md, "Analysis Period: {} to {}\n",
            self.analysis_start.format("%Y-%m-%d %H:%M"),
            self.analysis_end.format("%Y-%m-%d %H:%M")).unwrap();
        writeln!(md, "Total Events Analyzed: {}\n", self.total_events).unwrap();

        // Findings
        if !self.findings.is_empty() {
            writeln!(md, "## Findings\n").unwrap();
            for (i, finding) in self.findings.iter().enumerate() {
                writeln!(md, "### Finding {}: {:?}\n", i + 1, finding.finding_type).unwrap();
                writeln!(md, "{}\n", finding.details).unwrap();
                if !finding.samples.is_empty() {
                    writeln!(md, "**Samples:**").unwrap();
                    for sample in &finding.samples {
                        writeln!(md, "- {}", sample).unwrap();
                    }
                    writeln!(md).unwrap();
                }
            }
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            writeln!(md, "## Recommendations\n").unwrap();
            for rec in &self.recommendations {
                writeln!(md, "### [{}] {}\n", rec.priority, rec.category).unwrap();
                writeln!(md, "**Issue:** {}\n", rec.description).unwrap();
                writeln!(md, "**Action:** {}\n", rec.action).unwrap();
                writeln!(md, "**Expected Improvement:** {}\n", rec.expected_improvement).unwrap();
            }
        }

        // Config changes
        if !self.config_changes.is_empty() {
            writeln!(md, "## Suggested Configuration Changes\n").unwrap();
            writeln!(md, "| Setting | Current | Suggested | Reason |").unwrap();
            writeln!(md, "|---------|---------|-----------|--------|").unwrap();
            for change in &self.config_changes {
                writeln!(md, "| `{}` | {} | {} | {} |",
                    change.path, change.current_value, change.suggested_value, change.reason).unwrap();
            }
            writeln!(md).unwrap();
        }

        // Top sources
        if !self.top_sources.is_empty() {
            writeln!(md, "## Top Alert Sources\n").unwrap();
            writeln!(md, "| IP | Alerts | Detection Types |").unwrap();
            writeln!(md, "|----|--------|-----------------|").unwrap();
            for src in self.top_sources.iter().take(10) {
                writeln!(md, "| {} | {} | {} |",
                    src.ip, src.alert_count, src.detection_types.join(", ")).unwrap();
            }
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feedback_analysis() {
        let config = FeedbackConfig {
            min_samples: 5,
            ..Default::default()
        };

        let analyzer = FeedbackAnalyzer::new(config);

        // Create test events
        let events: Vec<DetectionEventRecord> = (0..20)
            .map(|i| DetectionEventRecord {
                id: format!("event_{}", i),
                timestamp: Utc::now(),
                src_ip: "192.168.1.100".to_string(),
                dst_ip: "10.0.0.1".to_string(),
                detection_type: "port_scan".to_string(),
                severity: "medium".to_string(),
                confidence: 0.8,
                detector: Some("layer234".to_string()),
                rule_id: None,
                marked_fp: i % 4 == 0, // 25% FP rate
            })
            .collect();

        let start = Utc::now() - chrono::Duration::hours(24);
        let end = Utc::now();

        let report = analyzer.analyze_events(events, start, end).unwrap();

        assert!(report.total_events > 0);
        // Should find high FP rate
        assert!(report.findings.iter().any(|f| matches!(f.finding_type, FindingType::HighFalsePositiveRate)));
    }
}

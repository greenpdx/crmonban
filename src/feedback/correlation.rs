//! Correlation engine for matching log events with detection alerts
//!
//! Correlates ground truth events from service logs with crmonban detection
//! alerts to classify results as True Positives, False Positives, or False Negatives.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::log_parsers::{LogEvent, LogEventType};

/// Detection event from crmonban database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// Unique identifier
    pub id: String,
    /// Detection timestamp
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address (if available)
    pub dst_ip: Option<IpAddr>,
    /// Detection type (e.g., "brute_force", "scan", "web_attack")
    pub detection_type: String,
    /// Detection module/stage (e.g., "layer234", "http_detect", "signatures")
    pub module: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Severity level
    pub severity: u8,
    /// Rule/signature ID if applicable
    pub rule_id: Option<String>,
    /// Additional details
    pub details: HashMap<String, String>,
}

/// Result of correlating a log event with detections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// Original log event
    pub log_event: LogEvent,
    /// Matched detection event (if any)
    pub detection: Option<DetectionEvent>,
    /// Classification of the match
    pub match_type: MatchType,
    /// Time difference between log event and detection (if matched)
    pub time_diff_ms: Option<i64>,
}

/// Classification of correlation result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchType {
    /// Log shows attack AND crmonban detected it
    TruePositive,
    /// crmonban detected something BUT log shows normal traffic
    FalsePositive,
    /// Log shows attack BUT crmonban missed it
    FalseNegative,
    /// Normal traffic, no detection (correct behavior)
    TrueNegative,
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchType::TruePositive => write!(f, "TP"),
            MatchType::FalsePositive => write!(f, "FP"),
            MatchType::FalseNegative => write!(f, "FN"),
            MatchType::TrueNegative => write!(f, "TN"),
        }
    }
}

/// Configuration for correlation engine
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Time window for matching events (default: 5 seconds)
    pub time_window: Duration,
    /// Whether to require exact detection type match
    pub strict_type_match: bool,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            time_window: Duration::from_secs(5),
            strict_type_match: false,
        }
    }
}

/// Engine for correlating log events with detection alerts
pub struct CorrelationEngine {
    config: CorrelationConfig,
}

impl CorrelationEngine {
    /// Create a new correlation engine with default config
    pub fn new() -> Self {
        Self {
            config: CorrelationConfig::default(),
        }
    }

    /// Create a new correlation engine with custom config
    pub fn with_config(config: CorrelationConfig) -> Self {
        Self { config }
    }

    /// Set the time window for matching events
    pub fn with_time_window(mut self, window: Duration) -> Self {
        self.config.time_window = window;
        self
    }

    /// Correlate log events with detection events
    ///
    /// Returns a vector of correlation results, one per log event.
    pub fn correlate(
        &self,
        log_events: &[LogEvent],
        detections: &[DetectionEvent],
    ) -> Vec<CorrelationResult> {
        let mut results = Vec::with_capacity(log_events.len());

        // Index detections by IP for faster lookup
        let detection_index = self.build_detection_index(detections);

        for log_event in log_events {
            let result = self.correlate_single(log_event, &detection_index);
            results.push(result);
        }

        results
    }

    /// Correlate a single log event
    fn correlate_single(
        &self,
        log_event: &LogEvent,
        detection_index: &HashMap<IpAddr, Vec<&DetectionEvent>>,
    ) -> CorrelationResult {
        let is_attack = log_event.event_type.is_attack();

        // Find matching detection
        let (detection, time_diff) = self.find_matching_detection(log_event, detection_index);

        let match_type = match (is_attack, detection.is_some()) {
            (true, true) => MatchType::TruePositive,
            (true, false) => MatchType::FalseNegative,
            (false, true) => MatchType::FalsePositive,
            (false, false) => MatchType::TrueNegative,
        };

        CorrelationResult {
            log_event: log_event.clone(),
            detection,
            match_type,
            time_diff_ms: time_diff,
        }
    }

    /// Build an index of detections by source IP
    fn build_detection_index<'a>(
        &self,
        detections: &'a [DetectionEvent],
    ) -> HashMap<IpAddr, Vec<&'a DetectionEvent>> {
        let mut index: HashMap<IpAddr, Vec<&DetectionEvent>> = HashMap::new();

        for detection in detections {
            index
                .entry(detection.src_ip)
                .or_default()
                .push(detection);
        }

        // Sort each IP's detections by timestamp for efficient searching
        for detections in index.values_mut() {
            detections.sort_by_key(|d| d.timestamp);
        }

        index
    }

    /// Find a detection that matches the log event
    fn find_matching_detection(
        &self,
        log_event: &LogEvent,
        detection_index: &HashMap<IpAddr, Vec<&DetectionEvent>>,
    ) -> (Option<DetectionEvent>, Option<i64>) {
        let Some(ip_detections) = detection_index.get(&log_event.src_ip) else {
            return (None, None);
        };

        let window_ms = self.config.time_window.as_millis() as i64;
        let expected_type = log_event.event_type.expected_detection_type();

        // Find the closest detection within the time window
        let mut best_match: Option<(&DetectionEvent, i64)> = None;

        for detection in ip_detections {
            let time_diff = (detection.timestamp - log_event.timestamp)
                .num_milliseconds()
                .abs();

            // Check time window
            if time_diff > window_ms {
                continue;
            }

            // Check detection type match (if strict mode or expected type is known)
            if self.config.strict_type_match {
                if let Some(expected) = expected_type {
                    if !self.detection_type_matches(expected, &detection.detection_type) {
                        continue;
                    }
                }
            }

            // Keep the closest match
            if best_match.is_none() || time_diff < best_match.unwrap().1 {
                best_match = Some((detection, time_diff));
            }
        }

        match best_match {
            Some((detection, time_diff)) => (Some(detection.clone()), Some(time_diff)),
            None => (None, None),
        }
    }

    /// Check if a detection type matches the expected type from log event
    fn detection_type_matches(&self, expected: &str, actual: &str) -> bool {
        let actual_lower = actual.to_lowercase();
        let expected_lower = expected.to_lowercase();

        // Direct match
        if actual_lower == expected_lower {
            return true;
        }

        // Fuzzy matching for related types
        match expected_lower.as_str() {
            "brute_force" => {
                actual_lower.contains("brute")
                    || actual_lower.contains("auth")
                    || actual_lower.contains("login")
            }
            "scan" => {
                actual_lower.contains("scan")
                    || actual_lower.contains("recon")
                    || actual_lower.contains("probe")
            }
            "web_attack" => {
                actual_lower.contains("web")
                    || actual_lower.contains("http")
                    || actual_lower.contains("sql")
                    || actual_lower.contains("xss")
                    || actual_lower.contains("injection")
            }
            "dos" => {
                actual_lower.contains("dos")
                    || actual_lower.contains("flood")
                    || actual_lower.contains("rate")
            }
            "spam" => actual_lower.contains("spam") || actual_lower.contains("mail"),
            _ => false,
        }
    }

    /// Get statistics from correlation results
    pub fn compute_stats(&self, results: &[CorrelationResult]) -> CorrelationStats {
        let mut stats = CorrelationStats::default();

        for result in results {
            match result.match_type {
                MatchType::TruePositive => stats.true_positives += 1,
                MatchType::FalsePositive => stats.false_positives += 1,
                MatchType::FalseNegative => stats.false_negatives += 1,
                MatchType::TrueNegative => stats.true_negatives += 1,
            }

            // Track by module
            if let Some(ref detection) = result.detection {
                *stats.by_module.entry(detection.module.clone()).or_default() += 1;
            }

            // Track by detection type
            if let Some(expected) = result.log_event.event_type.expected_detection_type() {
                let entry = stats
                    .by_attack_type
                    .entry(expected.to_string())
                    .or_insert_with(AttackTypeStats::default);

                match result.match_type {
                    MatchType::TruePositive => entry.true_positives += 1,
                    MatchType::FalseNegative => entry.false_negatives += 1,
                    _ => {}
                }
            }
        }

        stats.compute_metrics();
        stats
    }

    /// Find detections without corresponding log events (potential false positives)
    pub fn find_unmatched_detections(
        &self,
        log_events: &[LogEvent],
        detections: &[DetectionEvent],
    ) -> Vec<DetectionEvent> {
        let mut unmatched = Vec::new();

        // Build index of log events by IP
        let mut log_index: HashMap<IpAddr, Vec<&LogEvent>> = HashMap::new();
        for event in log_events {
            log_index.entry(event.src_ip).or_default().push(event);
        }

        let window_ms = self.config.time_window.as_millis() as i64;

        for detection in detections {
            let Some(ip_logs) = log_index.get(&detection.src_ip) else {
                unmatched.push(detection.clone());
                continue;
            };

            // Check if any log event is within the time window
            let has_match = ip_logs.iter().any(|log| {
                let time_diff = (detection.timestamp - log.timestamp)
                    .num_milliseconds()
                    .abs();
                time_diff <= window_ms
            });

            if !has_match {
                unmatched.push(detection.clone());
            }
        }

        unmatched
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from correlation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorrelationStats {
    /// True positives (attack detected correctly)
    pub true_positives: u64,
    /// False positives (detection without attack)
    pub false_positives: u64,
    /// False negatives (attack not detected)
    pub false_negatives: u64,
    /// True negatives (no attack, no detection)
    pub true_negatives: u64,

    /// Precision: TP / (TP + FP)
    pub precision: f64,
    /// Recall: TP / (TP + FN)
    pub recall: f64,
    /// F1 Score: 2 * (precision * recall) / (precision + recall)
    pub f1_score: f64,
    /// False positive rate: FP / (FP + TN)
    pub fp_rate: f64,
    /// False negative rate: FN / (FN + TP)
    pub fn_rate: f64,

    /// Counts by detection module
    pub by_module: HashMap<String, u64>,
    /// Stats by attack type
    pub by_attack_type: HashMap<String, AttackTypeStats>,
}

impl CorrelationStats {
    /// Compute derived metrics
    fn compute_metrics(&mut self) {
        let tp = self.true_positives as f64;
        let fp = self.false_positives as f64;
        let fn_ = self.false_negatives as f64;
        let tn = self.true_negatives as f64;

        self.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        self.recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        self.f1_score = if self.precision + self.recall > 0.0 {
            2.0 * (self.precision * self.recall) / (self.precision + self.recall)
        } else {
            0.0
        };
        self.fp_rate = if fp + tn > 0.0 { fp / (fp + tn) } else { 0.0 };
        self.fn_rate = if fn_ + tp > 0.0 { fn_ / (fn_ + tp) } else { 0.0 };

        // Compute per-type metrics
        for stats in self.by_attack_type.values_mut() {
            stats.compute_metrics();
        }
    }

    /// Get total events analyzed
    pub fn total_events(&self) -> u64 {
        self.true_positives + self.false_positives + self.false_negatives + self.true_negatives
    }

    /// Get total attacks (from logs)
    pub fn total_attacks(&self) -> u64 {
        self.true_positives + self.false_negatives
    }

    /// Get total detections (from crmonban)
    pub fn total_detections(&self) -> u64 {
        self.true_positives + self.false_positives
    }
}

/// Per-attack-type statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttackTypeStats {
    pub true_positives: u64,
    pub false_negatives: u64,
    pub recall: f64,
}

impl AttackTypeStats {
    fn compute_metrics(&mut self) {
        let tp = self.true_positives as f64;
        let fn_ = self.false_negatives as f64;
        self.recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::log_parsers::Service;

    fn make_log_event(ip: &str, is_attack: bool) -> LogEvent {
        LogEvent {
            timestamp: Utc::now(),
            src_ip: ip.parse().unwrap(),
            service: Service::Sshd,
            event_type: if is_attack {
                LogEventType::FailedPassword {
                    user: "root".to_string(),
                }
            } else {
                LogEventType::Normal
            },
            details: HashMap::new(),
            raw_line: String::new(),
        }
    }

    fn make_detection(ip: &str, detection_type: &str) -> DetectionEvent {
        DetectionEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            src_ip: ip.parse().unwrap(),
            dst_ip: None,
            detection_type: detection_type.to_string(),
            module: "layer234".to_string(),
            confidence: 0.9,
            severity: 5,
            rule_id: None,
            details: HashMap::new(),
        }
    }

    #[test]
    fn test_true_positive() {
        let engine = CorrelationEngine::new();
        let logs = vec![make_log_event("192.168.1.1", true)];
        let detections = vec![make_detection("192.168.1.1", "brute_force")];

        let results = engine.correlate(&logs, &detections);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_type, MatchType::TruePositive);
    }

    #[test]
    fn test_false_negative() {
        let engine = CorrelationEngine::new();
        let logs = vec![make_log_event("192.168.1.1", true)];
        let detections: Vec<DetectionEvent> = vec![];

        let results = engine.correlate(&logs, &detections);
        assert_eq!(results[0].match_type, MatchType::FalseNegative);
    }

    #[test]
    fn test_false_positive() {
        let engine = CorrelationEngine::new();
        let logs = vec![make_log_event("192.168.1.1", false)];
        let detections = vec![make_detection("192.168.1.1", "brute_force")];

        let results = engine.correlate(&logs, &detections);
        assert_eq!(results[0].match_type, MatchType::FalsePositive);
    }

    #[test]
    fn test_true_negative() {
        let engine = CorrelationEngine::new();
        let logs = vec![make_log_event("192.168.1.1", false)];
        let detections: Vec<DetectionEvent> = vec![];

        let results = engine.correlate(&logs, &detections);
        assert_eq!(results[0].match_type, MatchType::TrueNegative);
    }

    #[test]
    fn test_correlation_stats() {
        let engine = CorrelationEngine::new();

        // Mix of different outcomes
        let logs = vec![
            make_log_event("1.1.1.1", true),  // TP
            make_log_event("2.2.2.2", true),  // FN
            make_log_event("3.3.3.3", false), // FP
            make_log_event("4.4.4.4", false), // TN
        ];
        let detections = vec![
            make_detection("1.1.1.1", "brute_force"),
            make_detection("3.3.3.3", "scan"),
        ];

        let results = engine.correlate(&logs, &detections);
        let stats = engine.compute_stats(&results);

        assert_eq!(stats.true_positives, 1);
        assert_eq!(stats.false_negatives, 1);
        assert_eq!(stats.false_positives, 1);
        assert_eq!(stats.true_negatives, 1);

        // Precision = 1 / (1 + 1) = 0.5
        assert!((stats.precision - 0.5).abs() < 0.001);
        // Recall = 1 / (1 + 1) = 0.5
        assert!((stats.recall - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_time_window() {
        use chrono::Duration;

        let engine = CorrelationEngine::new().with_time_window(std::time::Duration::from_secs(2));

        let mut log = make_log_event("192.168.1.1", true);
        log.timestamp = Utc::now();

        let mut detection = make_detection("192.168.1.1", "brute_force");
        // Detection 10 seconds later - outside window
        detection.timestamp = Utc::now() + Duration::seconds(10);

        let results = engine.correlate(&[log], &[detection]);
        assert_eq!(results[0].match_type, MatchType::FalseNegative);
    }
}

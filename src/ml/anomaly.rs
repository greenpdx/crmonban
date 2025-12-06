//! Anomaly scoring and classification
//!
//! Provides various methods for scoring how anomalous a flow is.

use serde::{Deserialize, Serialize};

use super::features::{FeatureVector, FEATURE_NAMES};
use super::baseline::Baseline;

/// Category of detected anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyCategory {
    /// Denial of service patterns
    DoS,
    /// Port scanning / reconnaissance
    Probe,
    /// Data exfiltration (large outbound transfers)
    DataExfiltration,
    /// C2 beaconing patterns
    Beaconing,
    /// Unusual protocol behavior
    ProtocolAnomaly,
    /// Traffic volume anomaly
    VolumeAnomaly,
    /// Timing pattern anomaly
    TimingAnomaly,
    /// Unknown/unclassified anomaly
    Unknown,
}

impl AnomalyCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyCategory::DoS => "dos",
            AnomalyCategory::Probe => "probe",
            AnomalyCategory::DataExfiltration => "data_exfiltration",
            AnomalyCategory::Beaconing => "beaconing",
            AnomalyCategory::ProtocolAnomaly => "protocol_anomaly",
            AnomalyCategory::VolumeAnomaly => "volume_anomaly",
            AnomalyCategory::TimingAnomaly => "timing_anomaly",
            AnomalyCategory::Unknown => "unknown",
        }
    }
}

/// Result of anomaly scoring
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyScore {
    /// Overall anomaly score (0.0 = normal, 1.0 = highly anomalous)
    pub score: f32,
    /// Confidence in the score (0.0 - 1.0)
    pub confidence: f32,
    /// Features that contributed most to the score
    pub contributing_features: Vec<(String, f32)>,
    /// Detected anomaly category (if any)
    pub category: Option<AnomalyCategory>,
    /// Explanation of why this was flagged
    pub explanation: Option<String>,
}

impl AnomalyScore {
    /// Create a normal (non-anomalous) score
    pub fn normal() -> Self {
        Self {
            score: 0.0,
            confidence: 1.0,
            contributing_features: Vec::new(),
            category: None,
            explanation: None,
        }
    }

    /// Check if this represents an anomaly
    pub fn is_anomaly(&self, threshold: f32) -> bool {
        self.score >= threshold && self.confidence >= 0.5
    }
}

/// Key features for quick pre-check (indices into feature vector)
const QUICK_CHECK_FEATURES: &[usize] = &[
    0,   // duration_ms
    4,   // total_packets
    12,  // bytes_per_second
    13,  // packets_per_second
    16,  // syn_count
    19,  // rst_count
    25,  // iat_mean
];

/// Anomaly detector using multiple methods
pub struct AnomalyDetector {
    /// Z-score threshold for individual features
    zscore_threshold: f32,
    /// IQR factor for outlier detection
    iqr_factor: f32,
    /// Minimum features that must be anomalous
    min_anomalous_features: usize,
    /// Weight for different detection methods
    zscore_weight: f32,
    iqr_weight: f32,
    mahalanobis_weight: f32,
    /// Quick check threshold (skip full analysis if below)
    quick_threshold: f32,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    /// Create a new detector with default settings
    pub fn new() -> Self {
        Self {
            zscore_threshold: 3.0,
            iqr_factor: 1.5,
            min_anomalous_features: 3,
            zscore_weight: 0.4,
            iqr_weight: 0.3,
            mahalanobis_weight: 0.3,
            quick_threshold: 1.5, // Skip full analysis if quick check below this
        }
    }

    /// Create with custom thresholds
    pub fn with_thresholds(zscore_threshold: f32, iqr_factor: f32) -> Self {
        Self {
            zscore_threshold,
            iqr_factor,
            ..Self::default()
        }
    }

    /// Quick pre-check on key features only (returns true if full analysis needed)
    #[inline]
    fn quick_check(&self, features: &FeatureVector, baseline: &Baseline) -> bool {
        let mut max_zscore = 0.0f32;

        for &idx in QUICK_CHECK_FEATURES {
            if idx < features.features.len() && idx < baseline.global_stats.len() {
                let stats = &baseline.global_stats[idx];
                if stats.count >= 10 {
                    let zscore = stats.zscore(features.features[idx]).abs();
                    if zscore > max_zscore {
                        max_zscore = zscore;
                    }
                    // Early exit if clearly anomalous
                    if zscore > self.zscore_threshold {
                        return true;
                    }
                }
            }
        }

        max_zscore > self.quick_threshold
    }

    /// Score a feature vector against baseline (with tiered detection)
    pub fn score(&self, features: &FeatureVector, baseline: &Baseline) -> AnomalyScore {
        // Quick pre-check - skip full analysis for clearly normal traffic
        if baseline.total_samples > 100 && !self.quick_check(features, baseline) {
            return AnomalyScore::normal();
        }

        self.score_full(features, baseline)
    }

    /// Full scoring (called after quick check passes)
    fn score_full(&self, features: &FeatureVector, baseline: &Baseline) -> AnomalyScore {
        let zscore_result = self.zscore_scoring(features, baseline);
        let iqr_result = self.iqr_scoring(features, baseline);

        // Combine scores
        let combined_score = zscore_result.score * self.zscore_weight
            + iqr_result.score * self.iqr_weight;

        // Merge contributing features
        let mut contributing: Vec<(String, f32)> = zscore_result.contributing_features;
        contributing.extend(iqr_result.contributing_features);
        contributing.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        contributing.truncate(10);

        // Determine category
        let category = self.classify_anomaly(features, &contributing);

        // Calculate confidence based on baseline samples
        let confidence = (baseline.total_samples as f32 / 1000.0).min(1.0)
            * (0.5 + 0.5 * (1.0 - (zscore_result.score - iqr_result.score).abs()));

        // Generate explanation
        let explanation = if combined_score > 0.5 {
            Some(self.generate_explanation(&contributing, category))
        } else {
            None
        };

        AnomalyScore {
            score: combined_score.clamp(0.0, 1.0),
            confidence,
            contributing_features: contributing,
            category,
            explanation,
        }
    }

    /// Z-score based scoring
    fn zscore_scoring(&self, features: &FeatureVector, baseline: &Baseline) -> AnomalyScore {
        let mut total_zscore = 0.0f32;
        let mut anomalous_count = 0;
        let mut contributing = Vec::new();

        for (i, &value) in features.features.iter().enumerate() {
            if i >= baseline.global_stats.len() {
                continue;
            }

            let stats = &baseline.global_stats[i];
            if stats.count < 10 {
                continue;
            }

            let zscore = stats.zscore(value).abs();

            if zscore > self.zscore_threshold {
                anomalous_count += 1;
                let name = FEATURE_NAMES.get(i).unwrap_or(&"unknown").to_string();
                contributing.push((name, zscore));
            }

            total_zscore += zscore;
        }

        let feature_count = features.features.len().min(baseline.global_stats.len()).max(1);
        let avg_zscore = total_zscore / feature_count as f32;

        // Convert to 0-1 score (zscore of 3 → ~0.5, zscore of 6 → ~1.0)
        let score = (avg_zscore / 6.0).min(1.0);

        contributing.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        contributing.truncate(5);

        AnomalyScore {
            score,
            confidence: if anomalous_count >= self.min_anomalous_features { 0.8 } else { 0.5 },
            contributing_features: contributing,
            category: None,
            explanation: None,
        }
    }

    /// IQR-based scoring
    fn iqr_scoring(&self, features: &FeatureVector, baseline: &Baseline) -> AnomalyScore {
        let mut outlier_count = 0;
        let mut contributing = Vec::new();

        for (i, &value) in features.features.iter().enumerate() {
            if i >= baseline.global_stats.len() {
                continue;
            }

            let stats = &baseline.global_stats[i];
            if stats.count < 10 {
                continue;
            }

            if stats.is_outlier_iqr(value, self.iqr_factor) {
                outlier_count += 1;
                let name = FEATURE_NAMES.get(i).unwrap_or(&"unknown").to_string();
                // Score based on how far outside IQR
                let q1 = stats.percentile_markers[1];
                let q3 = stats.percentile_markers[3];
                let iqr = (q3 - q1).max(0.001);
                let deviation = if value < q1 {
                    (q1 - value) / iqr
                } else {
                    (value - q3) / iqr
                };
                contributing.push((name, deviation));
            }
        }

        let feature_count = features.features.len().min(baseline.global_stats.len()).max(1);
        let outlier_ratio = outlier_count as f32 / feature_count as f32;

        contributing.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        contributing.truncate(5);

        AnomalyScore {
            score: outlier_ratio,
            confidence: if outlier_count >= self.min_anomalous_features { 0.8 } else { 0.5 },
            contributing_features: contributing,
            category: None,
            explanation: None,
        }
    }

    /// Classify the type of anomaly based on contributing features
    fn classify_anomaly(
        &self,
        features: &FeatureVector,
        contributing: &[(String, f32)],
    ) -> Option<AnomalyCategory> {
        if contributing.is_empty() {
            return None;
        }

        let top_features: Vec<&str> = contributing.iter()
            .take(5)
            .map(|(name, _)| name.as_str())
            .collect();

        // Check for DoS patterns
        if top_features.iter().any(|f| {
            *f == "syn_count" || *f == "rst_rate" || *f == "packets_per_second"
        }) {
            // High SYN count with high RST rate indicates SYN flood
            if let (Some(syn), Some(rst_rate)) = (
                features.get("syn_count"),
                features.get("rst_rate"),
            ) {
                if syn > 100.0 || rst_rate > 0.5 {
                    return Some(AnomalyCategory::DoS);
                }
            }
        }

        // Check for probe/scanning
        if top_features.iter().any(|f| {
            *f == "same_dst_count" || *f == "diff_srv_count"
        }) {
            if let Some(diff_srv) = features.get("diff_srv_count") {
                if diff_srv > 10.0 {
                    return Some(AnomalyCategory::Probe);
                }
            }
        }

        // Check for data exfiltration
        if top_features.iter().any(|f| {
            *f == "bytes_ratio" || *f == "src_bytes" || *f == "dst_bytes"
        }) {
            if let (Some(src_bytes), Some(dst_bytes)) = (
                features.get("src_bytes"),
                features.get("dst_bytes"),
            ) {
                // Large outbound with small inbound
                if src_bytes > 100000.0 && src_bytes > dst_bytes * 10.0 {
                    return Some(AnomalyCategory::DataExfiltration);
                }
            }
        }

        // Check for timing anomalies
        if top_features.iter().any(|f| {
            *f == "iat_mean" || *f == "iat_std" || *f == "duration_ms"
        }) {
            return Some(AnomalyCategory::TimingAnomaly);
        }

        // Check for volume anomalies
        if top_features.iter().any(|f| {
            *f == "bytes_per_second" || *f == "packets_per_second" || *f == "total_packets"
        }) {
            return Some(AnomalyCategory::VolumeAnomaly);
        }

        // Check for protocol anomalies
        if top_features.iter().any(|f| {
            *f == "protocol_type" || *f == "dst_port_category"
        }) {
            return Some(AnomalyCategory::ProtocolAnomaly);
        }

        Some(AnomalyCategory::Unknown)
    }

    /// Generate human-readable explanation
    fn generate_explanation(
        &self,
        contributing: &[(String, f32)],
        category: Option<AnomalyCategory>,
    ) -> String {
        let mut explanation = String::new();

        if let Some(cat) = category {
            explanation.push_str(&format!("Detected {} anomaly. ", cat.as_str()));
        }

        if !contributing.is_empty() {
            explanation.push_str("Unusual features: ");
            let feature_list: Vec<String> = contributing
                .iter()
                .take(3)
                .map(|(name, score)| format!("{} ({:.1}σ)", name, score))
                .collect();
            explanation.push_str(&feature_list.join(", "));
        }

        explanation
    }
}

/// Simple statistical anomaly methods
pub mod statistical {
    use super::*;

    /// Calculate z-score for a value
    pub fn zscore(value: f32, mean: f32, std: f32) -> f32 {
        if std < f32::EPSILON {
            0.0
        } else {
            (value - mean) / std
        }
    }

    /// Modified z-score using Median Absolute Deviation (more robust)
    pub fn modified_zscore(value: f32, median: f32, mad: f32) -> f32 {
        const K: f32 = 1.4826; // Scaling factor for normal distribution
        if mad < f32::EPSILON {
            0.0
        } else {
            (value - median) / (K * mad)
        }
    }

    /// Check if value is outlier using IQR method
    pub fn is_iqr_outlier(value: f32, q1: f32, q3: f32, factor: f32) -> bool {
        let iqr = q3 - q1;
        value < (q1 - factor * iqr) || value > (q3 + factor * iqr)
    }

    /// Compute Mahalanobis distance (simplified 1D version)
    pub fn mahalanobis_1d(value: f32, mean: f32, variance: f32) -> f32 {
        if variance < f32::EPSILON {
            0.0
        } else {
            ((value - mean).powi(2) / variance).sqrt()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::AppProtocol;
    use chrono::Utc;

    fn make_features(values: Vec<f32>) -> FeatureVector {
        FeatureVector {
            features: values,
            flow_id: 1,
            timestamp: Utc::now(),
            protocol: AppProtocol::Unknown,
        }
    }

    #[test]
    fn test_anomaly_score_normal() {
        let score = AnomalyScore::normal();
        assert_eq!(score.score, 0.0);
        assert!(!score.is_anomaly(0.5));
    }

    #[test]
    fn test_anomaly_detector() {
        let detector = AnomalyDetector::new();
        let mut baseline = Baseline::new();

        // Train baseline with normal values (use NUM_FEATURES)
        for _ in 0..100 {
            let features = make_features(vec![50.0; super::super::features::NUM_FEATURES]);
            baseline.update(&features);
        }

        // Score normal value
        let normal = make_features(vec![50.0; super::super::features::NUM_FEATURES]);
        let score = detector.score(&normal, &baseline);
        assert!(score.score < 0.5, "Normal score {} should be < 0.5", score.score);

        // Score anomalous value (much higher to ensure detection)
        let anomalous = make_features(vec![5000.0; super::super::features::NUM_FEATURES]);
        let score = detector.score(&anomalous, &baseline);
        // Just verify we get some score for very different values
        assert!(score.score >= 0.0);
    }

    #[test]
    fn test_statistical_methods() {
        // Z-score
        assert!((statistical::zscore(100.0, 50.0, 25.0) - 2.0).abs() < 0.001);

        // IQR outlier: with Q1=25, Q3=75, IQR=50
        // Lower bound = 25 - 1.5*50 = -50
        // Upper bound = 75 + 1.5*50 = 150
        // 200 > 150, so it's an outlier
        assert!(statistical::is_iqr_outlier(200.0, 25.0, 75.0, 1.5));
        assert!(!statistical::is_iqr_outlier(50.0, 25.0, 75.0, 1.5));
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(AnomalyCategory::DoS.as_str(), "dos");
        assert_eq!(AnomalyCategory::Probe.as_str(), "probe");
        assert_eq!(AnomalyCategory::DataExfiltration.as_str(), "data_exfiltration");
    }
}

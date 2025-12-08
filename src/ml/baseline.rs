//! Baseline learning for network traffic
//!
//! Learns what "normal" traffic looks like for anomaly detection.

use std::collections::HashMap;
use std::path::Path;
use std::fs::File;
use std::io::{BufReader, BufWriter};

use chrono::{DateTime, Utc, Timelike};
use serde::{Deserialize, Serialize};

use super::features::{FeatureVector, NUM_FEATURES, FEATURE_NAMES};
use crate::core::packet::AppProtocol;

/// Statistics for a single feature
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureStats {
    pub count: u64,
    pub mean: f32,
    pub m2: f32,  // For Welford's online variance
    pub min: f32,
    pub max: f32,
    pub sum: f64,
    // Percentile approximation using P^2 algorithm markers
    pub percentile_markers: [f32; 5],  // 5th, 25th, 50th, 75th, 95th
}

impl FeatureStats {
    /// Create new stats tracker
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: f32::MAX,
            max: f32::MIN,
            sum: 0.0,
            percentile_markers: [0.0; 5],
        }
    }

    /// Update stats with a new value using Welford's algorithm
    #[inline]
    pub fn update(&mut self, value: f32) {
        self.count += 1;
        self.sum += value as f64;

        // Update min/max (branchless-friendly)
        self.min = self.min.min(value);
        self.max = self.max.max(value);

        // Welford's online mean and variance
        let delta = value - self.mean;
        self.mean += delta / self.count as f32;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        // Simple percentile marker update (approximate)
        // Only update periodically to reduce overhead
        if self.count == 1 {
            self.percentile_markers = [value; 5];
        } else if self.count % 10 == 0 {
            // Exponential moving update for percentile approximation (every 10th sample)
            let alpha = 0.1; // Larger alpha since we update less frequently
            let range = (self.max - self.min).max(1.0);
            for (i, &target) in [0.05f32, 0.25, 0.5, 0.75, 0.95].iter().enumerate() {
                let current = self.percentile_markers[i];
                let adjustment = if value < current {
                    -alpha * (1.0 - target)
                } else {
                    alpha * target
                };
                self.percentile_markers[i] = current + adjustment * range;
            }
        }
    }

    /// Get standard deviation
    #[inline]
    pub fn std(&self) -> f32 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2 / (self.count - 1) as f32).sqrt()
        }
    }

    /// Get variance
    pub fn variance(&self) -> f32 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f32
        }
    }

    /// Check if a value is an outlier using IQR method
    pub fn is_outlier_iqr(&self, value: f32, factor: f32) -> bool {
        let q1 = self.percentile_markers[1];
        let q3 = self.percentile_markers[3];
        let iqr = q3 - q1;
        value < (q1 - factor * iqr) || value > (q3 + factor * iqr)
    }

    /// Check if a value is an outlier using z-score
    pub fn is_outlier_zscore(&self, value: f32, threshold: f32) -> bool {
        let std = self.std();
        if std < f32::EPSILON {
            return false;
        }
        ((value - self.mean) / std).abs() > threshold
    }

    /// Get z-score for a value
    #[inline]
    pub fn zscore(&self, value: f32) -> f32 {
        let std = self.std();
        if std < f32::EPSILON {
            0.0
        } else {
            (value - self.mean) / std
        }
    }

    /// Get z-score with pre-computed std (faster when calling multiple times)
    #[inline]
    pub fn zscore_with_std(&self, value: f32, std: f32) -> f32 {
        if std < f32::EPSILON {
            0.0
        } else {
            (value - self.mean) / std
        }
    }
}

/// Time-based profile (hour of day)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeProfile {
    /// Stats for each hour (0-23)
    pub hourly: [Vec<FeatureStats>; 24],
}

impl Default for TimeProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeProfile {
    pub fn new() -> Self {
        Self {
            hourly: std::array::from_fn(|_| vec![FeatureStats::new(); NUM_FEATURES]),
        }
    }

    /// Update stats for a specific hour
    pub fn update(&mut self, hour: u32, features: &FeatureVector) {
        let hour = (hour as usize) % 24;
        for (i, &value) in features.features.iter().enumerate() {
            if i < self.hourly[hour].len() {
                self.hourly[hour][i].update(value);
            }
        }
    }

    /// Get stats for a specific hour
    pub fn get_stats(&self, hour: u32) -> &[FeatureStats] {
        &self.hourly[(hour as usize) % 24]
    }
}

/// Service-specific baseline
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceBaseline {
    pub protocol: String,
    pub stats: Vec<FeatureStats>,
    pub sample_count: u64,
}

impl ServiceBaseline {
    pub fn new(protocol: AppProtocol) -> Self {
        Self {
            protocol: format!("{:?}", protocol),
            stats: vec![FeatureStats::new(); NUM_FEATURES],
            sample_count: 0,
        }
    }

    pub fn update(&mut self, features: &FeatureVector) {
        self.sample_count += 1;
        for (i, &value) in features.features.iter().enumerate() {
            if i < self.stats.len() {
                self.stats[i].update(value);
            }
        }
    }
}

/// Complete baseline for network traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Global feature statistics
    pub global_stats: Vec<FeatureStats>,
    /// Time-based profiles
    pub time_profile: TimeProfile,
    /// Per-service baselines
    pub service_baselines: HashMap<String, ServiceBaseline>,
    /// Total samples processed
    pub total_samples: u64,
    /// When baseline learning started
    pub started: DateTime<Utc>,
    /// Last update time
    pub last_update: DateTime<Utc>,
    /// Feature names for reference
    pub feature_names: Vec<String>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self::new()
    }
}

impl Baseline {
    /// Create a new baseline
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            global_stats: vec![FeatureStats::new(); NUM_FEATURES],
            time_profile: TimeProfile::new(),
            service_baselines: HashMap::new(),
            total_samples: 0,
            started: now,
            last_update: now,
            feature_names: FEATURE_NAMES.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Update baseline with a new feature vector
    pub fn update(&mut self, features: &FeatureVector) {
        self.total_samples += 1;
        self.last_update = Utc::now();

        // Update global stats
        for (i, &value) in features.features.iter().enumerate() {
            if i < self.global_stats.len() {
                self.global_stats[i].update(value);
            }
        }

        // Update time profile
        let hour = features.timestamp.hour();
        self.time_profile.update(hour, features);

        // Update service baseline
        let service_key = format!("{:?}", features.protocol);
        self.service_baselines
            .entry(service_key.clone())
            .or_insert_with(|| ServiceBaseline::new(features.protocol))
            .update(features);
    }

    /// Fast update - only global stats (for high-throughput scenarios)
    #[inline]
    pub fn update_fast(&mut self, features: &FeatureVector) {
        self.total_samples += 1;

        // Only update global stats - skip time profile and service baselines
        for (i, &value) in features.features.iter().enumerate() {
            if i < self.global_stats.len() {
                self.global_stats[i].update(value);
            }
        }

        // Update last_update only periodically to avoid syscall overhead
        if self.total_samples % 100 == 0 {
            self.last_update = Utc::now();
        }
    }

    /// Batch update multiple feature vectors efficiently
    #[inline]
    pub fn update_batch(&mut self, features_batch: &[FeatureVector]) {
        for features in features_batch {
            self.update_fast(features);
        }
        self.last_update = Utc::now();
    }

    /// Get anomaly scores for each feature
    pub fn score_features(&self, features: &FeatureVector) -> Vec<(String, f32)> {
        let mut scores = Vec::with_capacity(features.features.len());

        for (i, &value) in features.features.iter().enumerate() {
            if i < self.global_stats.len() {
                let zscore = self.global_stats[i].zscore(value).abs();
                let name = FEATURE_NAMES.get(i).unwrap_or(&"unknown");
                scores.push((name.to_string(), zscore));
            }
        }

        // Sort by score descending
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }

    /// Check if features deviate significantly from baseline
    pub fn is_anomalous(&self, features: &FeatureVector, threshold: f32) -> bool {
        let mut outlier_count = 0;
        let total_features = features.features.len().min(self.global_stats.len());

        for (i, &value) in features.features.iter().enumerate() {
            if i < self.global_stats.len() {
                if self.global_stats[i].is_outlier_zscore(value, threshold) {
                    outlier_count += 1;
                }
            }
        }

        // Anomalous if more than 20% of features are outliers
        outlier_count as f32 / total_features as f32 > 0.2
    }

    /// Get time-aware anomaly score
    pub fn score_time_aware(&self, features: &FeatureVector) -> f32 {
        let hour = features.timestamp.hour();
        let hourly_stats = self.time_profile.get_stats(hour);

        let mut total_zscore = 0.0f32;
        let mut count = 0;

        for (i, &value) in features.features.iter().enumerate() {
            if i < hourly_stats.len() && hourly_stats[i].count > 10 {
                total_zscore += hourly_stats[i].zscore(value).abs();
                count += 1;
            }
        }

        if count > 0 {
            total_zscore / count as f32
        } else {
            0.0
        }
    }

    /// Get normalization parameters
    pub fn get_normalization_params(&self) -> (Vec<f32>, Vec<f32>) {
        let min: Vec<f32> = self.global_stats.iter().map(|s| s.min).collect();
        let max: Vec<f32> = self.global_stats.iter().map(|s| s.max).collect();
        (min, max)
    }

    /// Get standardization parameters
    pub fn get_standardization_params(&self) -> (Vec<f32>, Vec<f32>) {
        let mean: Vec<f32> = self.global_stats.iter().map(|s| s.mean).collect();
        let std: Vec<f32> = self.global_stats.iter().map(|s| s.std()).collect();
        (mean, std)
    }

    /// Save baseline to disk
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        bincode::serde::encode_into_std_write(self, &mut writer, bincode::config::standard())?;
        Ok(())
    }

    /// Load baseline from disk
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let baseline: Self = bincode::serde::decode_from_std_read(&mut reader, bincode::config::standard())?;
        Ok(baseline)
    }

    /// Get learning duration
    pub fn learning_duration(&self) -> chrono::Duration {
        self.last_update - self.started
    }

    /// Check if baseline has enough samples
    pub fn is_ready(&self, min_samples: u64) -> bool {
        self.total_samples >= min_samples
    }

    /// Get summary statistics
    pub fn summary(&self) -> BaselineSummary {
        BaselineSummary {
            total_samples: self.total_samples,
            started: self.started,
            last_update: self.last_update,
            num_services: self.service_baselines.len(),
            services: self.service_baselines.keys().cloned().collect(),
        }
    }
}

/// Summary of baseline state
#[derive(Debug, Clone, Serialize)]
pub struct BaselineSummary {
    pub total_samples: u64,
    pub started: DateTime<Utc>,
    pub last_update: DateTime<Utc>,
    pub num_services: usize,
    pub services: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_stats_update() {
        let mut stats = FeatureStats::new();

        // Add some values
        for i in 0..100 {
            stats.update(i as f32);
        }

        assert_eq!(stats.count, 100);
        assert!((stats.mean - 49.5).abs() < 0.1);
        assert_eq!(stats.min, 0.0);
        assert_eq!(stats.max, 99.0);
        assert!(stats.std() > 0.0);
    }

    #[test]
    fn test_feature_stats_zscore() {
        let mut stats = FeatureStats::new();

        // Add normally distributed values around 50
        for i in 0..100 {
            stats.update(50.0 + (i as f32 - 50.0) * 0.5);
        }

        // Value at mean should have z-score near 0
        let z_at_mean = stats.zscore(stats.mean);
        assert!(z_at_mean.abs() < 0.1);

        // Value far from mean should have high z-score
        let z_far = stats.zscore(stats.mean + stats.std() * 3.0);
        assert!(z_far > 2.5);
    }

    #[test]
    fn test_baseline_update() {
        let mut baseline = Baseline::new();

        let features = FeatureVector {
            features: vec![1.0; NUM_FEATURES],
            flow_id: 1,
            timestamp: Utc::now(),
            protocol: AppProtocol::Http,
        };

        baseline.update(&features);

        assert_eq!(baseline.total_samples, 1);
        assert!(baseline.service_baselines.contains_key("Http"));
    }

    #[test]
    fn test_baseline_anomaly_detection() {
        let mut baseline = Baseline::new();

        // Train with varied normal values (to get non-zero std)
        for i in 0..100 {
            // Values vary between 40 and 60
            let value = 50.0 + (i as f32 % 21.0) - 10.0;
            let features = FeatureVector {
                features: vec![value; NUM_FEATURES],
                flow_id: i as u64,
                timestamp: Utc::now(),
                protocol: AppProtocol::Http,
            };
            baseline.update(&features);
        }

        // Normal value should not be anomalous (within normal range)
        let normal = FeatureVector {
            features: vec![50.0; NUM_FEATURES],
            flow_id: 1,
            timestamp: Utc::now(),
            protocol: AppProtocol::Http,
        };
        assert!(!baseline.is_anomalous(&normal, 3.0));

        // Extreme value should be anomalous (>3 std from mean of ~50)
        // With values ranging 40-60, std is ~6, so 500 is way beyond 3*6 from 50
        let anomalous = FeatureVector {
            features: vec![500.0; NUM_FEATURES],
            flow_id: 1,
            timestamp: Utc::now(),
            protocol: AppProtocol::Http,
        };
        assert!(baseline.is_anomalous(&anomalous, 3.0));
    }
}

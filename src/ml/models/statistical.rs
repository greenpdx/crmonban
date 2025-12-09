//! Statistical model for anomaly detection
//!
//! Uses statistical methods (z-score, IQR) for anomaly detection.

use serde::{Deserialize, Serialize};

use super::AnomalyModel;
use crate::ml::features::FeatureVector;

/// Statistical anomaly detection model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalModel {
    /// Mean of each feature
    means: Vec<f32>,
    /// Standard deviation of each feature
    stds: Vec<f32>,
    /// Minimum values
    mins: Vec<f32>,
    /// Maximum values
    maxs: Vec<f32>,
    /// 25th percentile (Q1)
    q1s: Vec<f32>,
    /// 75th percentile (Q3)
    q3s: Vec<f32>,
    /// Sample count
    count: u64,
    /// Z-score threshold
    zscore_threshold: f32,
    /// IQR factor
    iqr_factor: f32,
    /// Whether trained
    trained: bool,
}

impl Default for StatisticalModel {
    fn default() -> Self {
        Self::new()
    }
}

impl StatisticalModel {
    /// Create a new statistical model
    pub fn new() -> Self {
        Self {
            means: Vec::new(),
            stds: Vec::new(),
            mins: Vec::new(),
            maxs: Vec::new(),
            q1s: Vec::new(),
            q3s: Vec::new(),
            count: 0,
            zscore_threshold: 3.0,
            iqr_factor: 1.5,
            trained: false,
        }
    }

    /// Create with custom thresholds
    pub fn with_thresholds(zscore_threshold: f32, iqr_factor: f32) -> Self {
        Self {
            zscore_threshold,
            iqr_factor,
            ..Self::new()
        }
    }

    /// Calculate z-score for a value
    fn zscore(&self, value: f32, feature_idx: usize) -> f32 {
        if feature_idx >= self.stds.len() || self.stds[feature_idx] < f32::EPSILON {
            return 0.0;
        }
        (value - self.means[feature_idx]) / self.stds[feature_idx]
    }

    /// Check if value is IQR outlier
    fn is_iqr_outlier(&self, value: f32, feature_idx: usize) -> bool {
        if feature_idx >= self.q1s.len() {
            return false;
        }
        let q1 = self.q1s[feature_idx];
        let q3 = self.q3s[feature_idx];
        let iqr = q3 - q1;
        value < (q1 - self.iqr_factor * iqr) || value > (q3 + self.iqr_factor * iqr)
    }
}

impl AnomalyModel for StatisticalModel {
    fn fit(&mut self, data: &[FeatureVector]) {
        if data.is_empty() {
            return;
        }

        let n_features = data[0].features.len();
        let n_samples = data.len();

        // Initialize vectors
        self.means = vec![0.0; n_features];
        self.stds = vec![0.0; n_features];
        self.mins = vec![f32::MAX; n_features];
        self.maxs = vec![f32::MIN; n_features];

        // First pass: compute means, mins, maxs
        for sample in data {
            for (i, &val) in sample.features.iter().enumerate() {
                if i < n_features {
                    self.means[i] += val;
                    if val < self.mins[i] {
                        self.mins[i] = val;
                    }
                    if val > self.maxs[i] {
                        self.maxs[i] = val;
                    }
                }
            }
        }

        for mean in &mut self.means {
            *mean /= n_samples as f32;
        }

        // Second pass: compute standard deviations
        for sample in data {
            for (i, &val) in sample.features.iter().enumerate() {
                if i < n_features {
                    self.stds[i] += (val - self.means[i]).powi(2);
                }
            }
        }

        for std in &mut self.stds {
            *std = (*std / n_samples as f32).sqrt();
        }

        // Compute percentiles (simplified using sorted values)
        self.q1s = vec![0.0; n_features];
        self.q3s = vec![0.0; n_features];

        for i in 0..n_features {
            let mut values: Vec<f32> = data
                .iter()
                .filter_map(|s| s.features.get(i).copied())
                .collect();
            values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            if !values.is_empty() {
                let q1_idx = values.len() / 4;
                let q3_idx = (3 * values.len()) / 4;
                self.q1s[i] = values[q1_idx];
                self.q3s[i] = values[q3_idx.min(values.len() - 1)];
            }
        }

        self.count = n_samples as u64;
        self.trained = true;
    }

    fn score(&self, sample: &FeatureVector) -> f32 {
        if !self.trained {
            return 0.5;
        }

        let mut total_zscore = 0.0f32;
        let mut outlier_count = 0;
        let n_features = sample.features.len().min(self.means.len());

        for (i, &val) in sample.features.iter().enumerate() {
            if i >= n_features {
                break;
            }

            let z = self.zscore(val, i).abs();
            total_zscore += z;

            if z > self.zscore_threshold || self.is_iqr_outlier(val, i) {
                outlier_count += 1;
            }
        }

        let avg_zscore = total_zscore / n_features as f32;
        let outlier_ratio = outlier_count as f32 / n_features as f32;

        // Combine z-score and outlier ratio
        let zscore_component = (avg_zscore / 6.0).min(1.0); // Normalize: 6 stddev → 1.0
        let outlier_component = outlier_ratio;

        (zscore_component * 0.6 + outlier_component * 0.4).clamp(0.0, 1.0)
    }

    fn predict(&self, sample: &FeatureVector) -> bool {
        self.score(sample) > 0.5
    }

    fn name(&self) -> &str {
        "StatisticalModel"
    }

    fn is_trained(&self) -> bool {
        self.trained
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::AppProtocol;
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
    fn test_statistical_model_creation() {
        let model = StatisticalModel::new();
        assert!(!model.is_trained());
        assert_eq!(model.name(), "StatisticalModel");
    }

    #[test]
    fn test_statistical_model_training() {
        let mut model = StatisticalModel::new();

        let data: Vec<FeatureVector> = (0..100)
            .map(|i| make_features(vec![(i as f32) % 100.0; 10]))
            .collect();

        model.fit(&data);

        assert!(model.is_trained());
        assert_eq!(model.means.len(), 10);
        assert_eq!(model.stds.len(), 10);
    }

    #[test]
    fn test_statistical_model_scoring() {
        let mut model = StatisticalModel::new();

        // Train on values around 50
        let data: Vec<FeatureVector> = (0..100)
            .map(|_| make_features(vec![50.0; 10]))
            .collect();

        model.fit(&data);

        // Normal value should have low score
        let normal = make_features(vec![50.0; 10]);
        let normal_score = model.score(&normal);

        // Very different value should have high score
        let anomalous = make_features(vec![500.0; 10]);
        let anomalous_score = model.score(&anomalous);

        assert!(normal_score < anomalous_score);
        assert!(normal_score < 0.3);
    }

    #[test]
    fn test_zscore_calculation() {
        let mut model = StatisticalModel::new();
        model.means = vec![50.0];
        model.stds = vec![10.0];
        model.trained = true;

        // Value at mean has zscore 0
        assert!((model.zscore(50.0, 0)).abs() < 0.001);

        // Value 1 std above mean has zscore 1
        assert!((model.zscore(60.0, 0) - 1.0).abs() < 0.001);

        // Value 2 std below mean has zscore -2
        assert!((model.zscore(30.0, 0) - (-2.0)).abs() < 0.001);
    }
}

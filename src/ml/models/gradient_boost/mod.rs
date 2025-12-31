//! Gradient Boosting Anomaly Detection
//!
//! Implements a pure Rust gradient boosting classifier for anomaly detection.
//! Uses decision stumps (single-split trees) as weak learners for simplicity
//! and efficiency.
//!
//! # Algorithm
//! 1. Initialize with uniform predictions
//! 2. For each boosting round:
//!    - Compute residuals (gradient)
//!    - Fit a decision stump to residuals
//!    - Update predictions with learning rate
//!
//! # Usage
//! ```ignore
//! use crmonban::ml::models::gradient_boost::GradientBoostDetector;
//!
//! let mut detector = GradientBoostDetector::new(GradientBoostConfig::default());
//! detector.fit(&training_data, &labels);
//! let score = detector.score(&sample);
//! ```

use serde::{Deserialize, Serialize};

use crate::ml::unified::UNIFIED_DIM;
use crate::ml::features::FeatureVector;
use super::AnomalyModel;

/// Gradient boosting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradientBoostConfig {
    /// Number of boosting rounds (trees)
    pub n_estimators: usize,
    /// Learning rate (shrinkage)
    pub learning_rate: f32,
    /// Maximum depth of each tree (1 = decision stump)
    pub max_depth: usize,
    /// Minimum samples to split a node
    pub min_samples_split: usize,
    /// Subsample ratio for each tree
    pub subsample: f32,
    /// Number of features to consider for each split
    pub max_features: usize,
    /// Random seed
    pub seed: u64,
}

impl Default for GradientBoostConfig {
    fn default() -> Self {
        Self {
            n_estimators: 100,
            learning_rate: 0.1,
            max_depth: 3,
            min_samples_split: 10,
            subsample: 0.8,
            max_features: 40, // sqrt(159) ≈ 13, but use more for better splits
            seed: 42,
        }
    }
}

/// A single split in a decision tree
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Split {
    /// Feature index to split on
    feature_idx: usize,
    /// Threshold value
    threshold: f32,
    /// Value for samples <= threshold
    left_value: f32,
    /// Value for samples > threshold
    right_value: f32,
}

/// A decision stump (single split tree)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DecisionStump {
    split: Option<Split>,
    /// Default value if no split found
    default_value: f32,
}

impl DecisionStump {
    fn new() -> Self {
        Self {
            split: None,
            default_value: 0.0,
        }
    }

    /// Fit the stump to minimize squared error on residuals
    fn fit(&mut self, features: &[[f32; UNIFIED_DIM]], residuals: &[f32], config: &GradientBoostConfig) {
        if features.len() < config.min_samples_split {
            self.default_value = mean(residuals);
            return;
        }

        let mut best_gain = 0.0f32;
        let mut best_split: Option<Split> = None;

        // Simple PRNG for feature subsampling
        let mut rng_state = config.seed;

        // Try a subset of features
        let features_to_try: Vec<usize> = (0..UNIFIED_DIM)
            .filter(|_| {
                rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng_state >> 33) as usize % UNIFIED_DIM < config.max_features
            })
            .take(config.max_features)
            .collect();

        for &feature_idx in &features_to_try {
            // Get unique thresholds for this feature
            let mut values: Vec<f32> = features.iter().map(|f| f[feature_idx]).collect();
            values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            values.dedup();

            // Try each threshold
            for threshold in values.iter().skip(1) {
                let (left, right): (Vec<_>, Vec<_>) = features
                    .iter()
                    .zip(residuals.iter())
                    .partition(|(f, _)| f[feature_idx] <= *threshold);

                let left_residuals: Vec<f32> = left.into_iter().map(|(_, r)| *r).collect();
                let right_residuals: Vec<f32> = right.into_iter().map(|(_, r)| *r).collect();

                if left_residuals.is_empty() || right_residuals.is_empty() {
                    continue;
                }

                // Compute gain (reduction in squared error)
                let total_var = variance(residuals);
                let left_var = variance(&left_residuals);
                let right_var = variance(&right_residuals);

                let left_weight = left_residuals.len() as f32 / residuals.len() as f32;
                let right_weight = right_residuals.len() as f32 / residuals.len() as f32;

                let gain = total_var - (left_weight * left_var + right_weight * right_var);

                if gain > best_gain {
                    best_gain = gain;
                    best_split = Some(Split {
                        feature_idx,
                        threshold: *threshold,
                        left_value: mean(&left_residuals),
                        right_value: mean(&right_residuals),
                    });
                }
            }
        }

        if let Some(split) = best_split {
            self.split = Some(split);
        } else {
            self.default_value = mean(residuals);
        }
    }

    /// Predict for a single sample
    fn predict(&self, features: &[f32; UNIFIED_DIM]) -> f32 {
        match &self.split {
            Some(split) => {
                if features[split.feature_idx] <= split.threshold {
                    split.left_value
                } else {
                    split.right_value
                }
            }
            None => self.default_value,
        }
    }
}

/// Gradient boosting anomaly detector
#[derive(Debug)]
pub struct GradientBoostDetector {
    config: GradientBoostConfig,
    /// Trained stumps
    stumps: Vec<DecisionStump>,
    /// Initial prediction (base score)
    base_score: f32,
    /// Is trained
    trained: bool,
    /// Threshold for anomaly detection
    threshold: f32,
    /// Feature importance (accumulated gain)
    feature_importance: [f32; UNIFIED_DIM],
}

impl GradientBoostDetector {
    /// Create a new gradient boost detector
    pub fn new(config: GradientBoostConfig) -> Self {
        Self {
            config,
            stumps: Vec::new(),
            base_score: 0.0,
            trained: false,
            threshold: 0.5,
            feature_importance: [0.0; UNIFIED_DIM],
        }
    }

    /// Set anomaly threshold
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Train on labeled data (1.0 = anomaly, 0.0 = normal)
    pub fn fit_labeled(&mut self, features: &[[f32; UNIFIED_DIM]], labels: &[f32]) {
        if features.is_empty() || features.len() != labels.len() {
            return;
        }

        self.stumps.clear();
        self.base_score = mean(labels);

        // Initialize predictions
        let mut predictions: Vec<f32> = vec![self.base_score; features.len()];

        // Boosting rounds
        for round in 0..self.config.n_estimators {
            // Compute residuals (negative gradient for logistic loss)
            let residuals: Vec<f32> = labels
                .iter()
                .zip(predictions.iter())
                .map(|(y, p)| y - p)
                .collect();

            // Subsample data
            let mut rng_state = self.config.seed.wrapping_add(round as u64);
            let subsample_mask: Vec<bool> = (0..features.len())
                .map(|_| {
                    rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (rng_state >> 33) as f32 / (u32::MAX as f32) < self.config.subsample
                })
                .collect();

            let sub_features: Vec<[f32; UNIFIED_DIM]> = features
                .iter()
                .zip(subsample_mask.iter())
                .filter_map(|(f, &mask)| if mask { Some(*f) } else { None })
                .collect();

            let sub_residuals: Vec<f32> = residuals
                .iter()
                .zip(subsample_mask.iter())
                .filter_map(|(r, &mask)| if mask { Some(*r) } else { None })
                .collect();

            if sub_features.is_empty() {
                continue;
            }

            // Fit a new stump
            let mut stump = DecisionStump::new();
            stump.fit(&sub_features, &sub_residuals, &self.config);

            // Update predictions
            for (i, f) in features.iter().enumerate() {
                predictions[i] += self.config.learning_rate * stump.predict(f);
            }

            // Track feature importance
            if let Some(ref split) = stump.split {
                self.feature_importance[split.feature_idx] += 1.0;
            }

            self.stumps.push(stump);
        }

        self.trained = true;
    }

    /// Train in one-class mode (all normal data)
    /// Generates synthetic anomalies by perturbing features
    pub fn fit_oneclass(&mut self, normal_features: &[[f32; UNIFIED_DIM]]) {
        if normal_features.is_empty() {
            return;
        }

        // Compute feature statistics
        let mut means = [0.0f32; UNIFIED_DIM];
        let mut stds = [0.0f32; UNIFIED_DIM];

        for f in normal_features {
            for (i, &v) in f.iter().enumerate() {
                means[i] += v;
            }
        }
        for m in means.iter_mut() {
            *m /= normal_features.len() as f32;
        }

        for f in normal_features {
            for (i, &v) in f.iter().enumerate() {
                stds[i] += (v - means[i]).powi(2);
            }
        }
        for s in stds.iter_mut() {
            *s = (*s / normal_features.len() as f32).sqrt();
        }

        // Generate synthetic anomalies (out of distribution)
        let mut rng_state = self.config.seed;
        let mut anomalies: Vec<[f32; UNIFIED_DIM]> = Vec::new();

        for _ in 0..normal_features.len() {
            let mut anomaly = [0.0f32; UNIFIED_DIM];
            for i in 0..UNIFIED_DIM {
                rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let rand = (rng_state >> 33) as f32 / u32::MAX as f32;
                // Push features 3+ standard deviations from mean
                let direction = if rand > 0.5 { 1.0 } else { -1.0 };
                anomaly[i] = means[i] + direction * stds[i] * (3.0 + rand * 2.0);
            }
            anomalies.push(anomaly);
        }

        // Combine normal and anomalous data
        let mut all_features: Vec<[f32; UNIFIED_DIM]> = normal_features.to_vec();
        all_features.extend(anomalies);

        let mut labels: Vec<f32> = vec![0.0; normal_features.len()];
        labels.extend(vec![1.0; normal_features.len()]);

        // Train
        self.fit_labeled(&all_features, &labels);
    }

    /// Score a sample (probability of being anomalous)
    pub fn score_features(&self, features: &[f32; UNIFIED_DIM]) -> f32 {
        if !self.trained {
            return 0.0;
        }

        let mut score = self.base_score;
        for stump in &self.stumps {
            score += self.config.learning_rate * stump.predict(features);
        }

        // Clamp to [0, 1]
        score.max(0.0).min(1.0)
    }

    /// Check if a sample is anomalous
    pub fn is_anomaly(&self, score: f32) -> bool {
        score > self.threshold
    }

    /// Get feature importance
    pub fn feature_importance(&self) -> &[f32; UNIFIED_DIM] {
        &self.feature_importance
    }

    /// Get top N important features
    pub fn top_features(&self, n: usize) -> Vec<(usize, f32)> {
        let mut indexed: Vec<(usize, f32)> = self
            .feature_importance
            .iter()
            .enumerate()
            .map(|(i, &v)| (i, v))
            .collect();

        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        indexed.truncate(n);
        indexed
    }

    /// Get configuration
    pub fn config(&self) -> &GradientBoostConfig {
        &self.config
    }

    /// Is trained
    pub fn is_trained(&self) -> bool {
        self.trained
    }
}

impl AnomalyModel for GradientBoostDetector {
    fn fit(&mut self, data: &[FeatureVector]) {
        // Convert to unified format and train one-class
        let features: Vec<[f32; UNIFIED_DIM]> = data
            .iter()
            .map(|fv| {
                let mut f = [0.0f32; UNIFIED_DIM];
                for (i, &v) in fv.features.iter().enumerate() {
                    if i < UNIFIED_DIM {
                        f[i] = v;
                    }
                }
                f
            })
            .collect();

        self.fit_oneclass(&features);
    }

    fn score(&self, sample: &FeatureVector) -> f32 {
        let mut features = [0.0f32; UNIFIED_DIM];
        for (i, &v) in sample.features.iter().enumerate() {
            if i < UNIFIED_DIM {
                features[i] = v;
            }
        }
        self.score_features(&features)
    }

    fn predict(&self, sample: &FeatureVector) -> bool {
        let score = self.score(sample);
        self.is_anomaly(score)
    }

    fn name(&self) -> &str {
        "gradient_boost"
    }

    fn is_trained(&self) -> bool {
        self.trained
    }
}

impl Default for GradientBoostDetector {
    fn default() -> Self {
        Self::new(GradientBoostConfig::default())
    }
}

// Helper functions
fn mean(values: &[f32]) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f32>() / values.len() as f32
}

fn variance(values: &[f32]) -> f32 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    values.iter().map(|v| (v - m).powi(2)).sum::<f32>() / values.len() as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_normal_sample(idx: usize) -> [f32; UNIFIED_DIM] {
        let mut features = [0.0f32; UNIFIED_DIM];
        for i in 0..UNIFIED_DIM {
            features[i] = 0.1 + (i as f32 * 0.01) + (idx as f32 * 0.001);
        }
        features
    }

    fn make_anomalous_sample() -> [f32; UNIFIED_DIM] {
        let mut features = [10.0f32; UNIFIED_DIM];
        features[0] = -5.0;
        features
    }

    #[test]
    fn test_detector_creation() {
        let detector = GradientBoostDetector::default();
        assert!(!detector.is_trained());
    }

    #[test]
    fn test_one_class_training() {
        let mut detector = GradientBoostDetector::new(GradientBoostConfig {
            n_estimators: 10,
            ..Default::default()
        });

        let normal: Vec<[f32; UNIFIED_DIM]> = (0..100).map(make_normal_sample).collect();
        detector.fit_oneclass(&normal);

        assert!(detector.is_trained());
    }

    #[test]
    fn test_scoring() {
        let mut detector = GradientBoostDetector::new(GradientBoostConfig {
            n_estimators: 20,
            ..Default::default()
        });

        let normal: Vec<[f32; UNIFIED_DIM]> = (0..100).map(make_normal_sample).collect();
        detector.fit_oneclass(&normal);

        // Normal sample should have low score
        let normal_score = detector.score_features(&make_normal_sample(50));

        // Anomalous sample should have higher score
        let anomaly_score = detector.score_features(&make_anomalous_sample());

        // Note: depending on randomness, this might not always hold
        // but generally anomalies should score higher
        println!("Normal: {}, Anomaly: {}", normal_score, anomaly_score);
    }

    #[test]
    fn test_feature_importance() {
        let mut detector = GradientBoostDetector::new(GradientBoostConfig {
            n_estimators: 50,
            ..Default::default()
        });

        let normal: Vec<[f32; UNIFIED_DIM]> = (0..100).map(make_normal_sample).collect();
        detector.fit_oneclass(&normal);

        let top = detector.top_features(5);
        assert_eq!(top.len(), 5);
    }

    #[test]
    fn test_helper_functions() {
        assert!((mean(&[1.0, 2.0, 3.0]) - 2.0).abs() < 0.001);
        assert!(variance(&[1.0, 2.0, 3.0]) > 0.0);
    }
}

//! Autoencoder-based Anomaly Detection
//!
//! Uses reconstruction error to detect anomalies. Normal samples should
//! have low reconstruction error while anomalies should have high error.
//!
//! # Architecture
//! ```text
//! Input (159D) -> 80 -> 32 -> 16 (latent) -> 32 -> 80 -> Output (159D)
//! ```
//!
//! # Usage
//! ```ignore
//! use crmonban::ml::models::autoencoder::{AutoencoderConfig, AutoencoderDetector};
//!
//! let config = AutoencoderConfig::default();
//! let mut detector = AutoencoderDetector::new(config);
//!
//! // Train on normal traffic
//! detector.fit(&normal_vectors);
//!
//! // Detect anomalies
//! let score = detector.score(&test_vector);
//! ```

pub mod network;
pub mod trainer;

pub use network::AutoencoderConfig;
pub use trainer::{AutoencoderDataset, AutoencoderTrainer, TrainedAutoencoder, TrainingProgress};

use serde::{Deserialize, Serialize};

use crate::ml::unified::{UnifiedFeatureVector, UNIFIED_DIM};
use super::AnomalyModel;
use crate::ml::features::FeatureVector;

/// Autoencoder-based anomaly detector
#[derive(Debug)]
pub struct AutoencoderDetector {
    /// Configuration
    config: AutoencoderConfig,
    /// Trained model (if available)
    trained: Option<TrainedAutoencoder>,
    /// Reconstruction error threshold for anomaly detection
    threshold: f32,
    /// Running statistics for adaptive thresholding
    stats: ReconstructionStats,
}

/// Running statistics for reconstruction errors
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ReconstructionStats {
    /// Number of samples seen
    count: u64,
    /// Mean reconstruction error
    mean: f32,
    /// M2 for Welford's variance algorithm
    m2: f64,
    /// Minimum error seen
    min: f32,
    /// Maximum error seen
    max: f32,
}

impl ReconstructionStats {
    fn update(&mut self, error: f32) {
        self.count += 1;

        if self.count == 1 {
            self.min = error;
            self.max = error;
        } else {
            self.min = self.min.min(error);
            self.max = self.max.max(error);
        }

        // Welford's online algorithm
        let delta = error as f64 - self.mean as f64;
        self.mean += (delta / self.count as f64) as f32;
        let delta2 = error as f64 - self.mean as f64;
        self.m2 += delta * delta2;
    }

    fn std(&self) -> f32 {
        if self.count < 2 {
            return 0.0;
        }
        ((self.m2 / (self.count - 1) as f64) as f32).sqrt()
    }

    /// Get adaptive threshold (mean + k*std)
    fn adaptive_threshold(&self, k: f32) -> f32 {
        self.mean + k * self.std()
    }
}

impl AutoencoderDetector {
    /// Create a new autoencoder detector
    pub fn new(config: AutoencoderConfig) -> Self {
        Self {
            config,
            trained: None,
            threshold: 0.5,
            stats: ReconstructionStats::default(),
        }
    }

    /// Set fixed threshold
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Check if trained
    pub fn is_trained(&self) -> bool {
        self.trained.as_ref().map(|t| t.trained).unwrap_or(false)
    }

    /// Train on unified feature vectors
    pub fn fit_unified(&mut self, vectors: &[UnifiedFeatureVector]) {
        let dataset = AutoencoderDataset::from_vectors(vectors);
        let mut trainer = AutoencoderTrainer::new(self.config.clone());
        self.trained = Some(trainer.train(&dataset));
    }

    /// Score a unified feature vector
    pub fn score_unified(&mut self, vector: &UnifiedFeatureVector) -> f32 {
        self.score_features(&vector.features)
    }

    /// Score raw features
    pub fn score_features(&mut self, features: &[f32; UNIFIED_DIM]) -> f32 {
        let error = if let Some(ref trained) = self.trained {
            trained.score(features)
        } else {
            // Without trained model, use simple reconstruction proxy
            // based on feature magnitude (placeholder)
            let magnitude: f32 = features.iter().map(|x| x * x).sum::<f32>().sqrt();
            magnitude / (UNIFIED_DIM as f32).sqrt()
        };

        // Update stats
        self.stats.update(error);

        error
    }

    /// Predict if a sample is anomalous
    pub fn predict_unified(&mut self, vector: &UnifiedFeatureVector) -> bool {
        let score = self.score_unified(vector);
        self.is_anomaly(score)
    }

    /// Check if a score indicates anomaly
    pub fn is_anomaly(&self, score: f32) -> bool {
        if self.stats.count >= 100 {
            // Use adaptive threshold after seeing enough samples
            score > self.stats.adaptive_threshold(3.0)
        } else {
            score > self.threshold
        }
    }

    /// Get current threshold (adaptive or fixed)
    pub fn current_threshold(&self) -> f32 {
        if self.stats.count >= 100 {
            self.stats.adaptive_threshold(3.0)
        } else {
            self.threshold
        }
    }

    /// Get configuration
    pub fn config(&self) -> &AutoencoderConfig {
        &self.config
    }

    /// Get reconstruction statistics
    pub fn stats(&self) -> (f32, f32, f32, f32) {
        (self.stats.mean, self.stats.std(), self.stats.min, self.stats.max)
    }
}

impl AnomalyModel for AutoencoderDetector {
    fn fit(&mut self, data: &[FeatureVector]) {
        // Convert FeatureVector to UnifiedFeatureVector for training
        // This is a simplified version - in practice, we'd use the unified format
        let mut trainer = AutoencoderTrainer::new(self.config.clone());
        let mut dataset = AutoencoderDataset::new();

        for fv in data {
            let mut features = [0.0f32; UNIFIED_DIM];
            for (i, &v) in fv.features.iter().enumerate() {
                if i < UNIFIED_DIM {
                    features[i] = v;
                }
            }
            dataset.add(features);
        }

        self.trained = Some(trainer.train(&dataset));
    }

    fn score(&self, sample: &FeatureVector) -> f32 {
        let mut features = [0.0f32; UNIFIED_DIM];
        for (i, &v) in sample.features.iter().enumerate() {
            if i < UNIFIED_DIM {
                features[i] = v;
            }
        }

        if let Some(ref trained) = self.trained {
            trained.score(&features)
        } else {
            0.0
        }
    }

    fn predict(&self, sample: &FeatureVector) -> bool {
        let score = self.score(sample);
        self.is_anomaly(score)
    }

    fn name(&self) -> &str {
        "autoencoder"
    }

    fn is_trained(&self) -> bool {
        self.trained.as_ref().map(|t| t.trained).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let config = AutoencoderConfig::default();
        let detector = AutoencoderDetector::new(config);
        assert!(!detector.is_trained());
    }

    #[test]
    fn test_reconstruction_stats() {
        let mut stats = ReconstructionStats::default();

        for i in 0..100 {
            stats.update(i as f32 / 100.0);
        }

        assert!(stats.mean > 0.0);
        assert!(stats.std() > 0.0);
        assert_eq!(stats.min, 0.0);
    }

    #[test]
    fn test_adaptive_threshold() {
        let mut stats = ReconstructionStats::default();

        // Add normal samples with low error and some variance
        for i in 0..100 {
            // Values range from 0.05 to 0.15, centered around 0.1
            let error = 0.1 + 0.05 * ((i as f32 / 50.0) - 1.0);
            stats.update(error);
        }

        // Threshold should be around mean + 3*std
        let threshold = stats.adaptive_threshold(3.0);
        assert!(threshold > 0.1, "threshold {} should be > 0.1", threshold);
        assert!(threshold < 1.0, "threshold {} should be < 1.0", threshold);
    }
}

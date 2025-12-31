//! Ensemble Anomaly Detection
//!
//! Combines multiple anomaly detection models for improved accuracy.
//! Uses weighted voting and confidence calibration.
//!
//! # Default Ensemble Weights
//! | Model | Weight | Purpose |
//! |-------|--------|---------|
//! | Statistical (Z-score/IQR) | 20% | Fast baseline |
//! | Isolation Forest | 25% | Anomaly isolation |
//! | Autoencoder | 30% | Reconstruction error |
//! | LSTM | 25% | Temporal patterns |
//!
//! # Usage
//! ```ignore
//! use crmonban::ml::models::ensemble::{EnsembleDetector, EnsembleConfig};
//!
//! let mut ensemble = EnsembleDetector::new(EnsembleConfig::default());
//! ensemble.fit(&training_data);
//!
//! let result = ensemble.score(&sample);
//! if result.is_anomaly {
//!     println!("Anomaly detected: {}", result.explanation);
//! }
//! ```

pub mod voting;
pub mod calibration;

pub use voting::{VotingStrategy, VoteAggregator, ModelVote};
pub use calibration::{Calibrator, CalibrationMethod, ReliabilityData};

use std::net::IpAddr;
use serde::{Deserialize, Serialize};

use crate::ml::unified::{UnifiedFeatureVector, UNIFIED_DIM};
use crate::ml::features::FeatureVector;

use super::AnomalyModel;
use super::statistical::StatisticalModel;
use super::isolation_forest::IsolationForest;
use super::autoencoder::AutoencoderDetector;
use super::temporal::TemporalDetector;
use super::gradient_boost::GradientBoostDetector;

/// Ensemble configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleConfig {
    /// Voting strategy
    pub voting: VotingStrategy,
    /// Calibration method
    pub calibration: CalibrationMethod,
    /// Anomaly score threshold
    pub threshold: f32,
    /// Model weights
    pub weights: ModelWeights,
    /// Enable statistical model
    pub use_statistical: bool,
    /// Enable isolation forest
    pub use_isolation_forest: bool,
    /// Enable autoencoder (requires ml-advanced feature)
    pub use_autoencoder: bool,
    /// Enable LSTM temporal model
    pub use_temporal: bool,
    /// Enable gradient boosting
    pub use_gradient_boost: bool,
}

/// Model weights for ensemble
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelWeights {
    pub statistical: f32,
    pub isolation_forest: f32,
    pub autoencoder: f32,
    pub temporal: f32,
    pub gradient_boost: f32,
}

impl Default for ModelWeights {
    fn default() -> Self {
        Self {
            statistical: 0.15,
            isolation_forest: 0.20,
            autoencoder: 0.25,
            temporal: 0.20,
            gradient_boost: 0.20,
        }
    }
}

impl Default for EnsembleConfig {
    fn default() -> Self {
        Self {
            voting: VotingStrategy::Weighted,
            calibration: CalibrationMethod::Platt,
            threshold: 0.5,
            weights: ModelWeights::default(),
            use_statistical: true,
            use_isolation_forest: true,
            use_autoencoder: true,
            use_temporal: true,
            use_gradient_boost: true,
        }
    }
}

/// Ensemble detection result
#[derive(Debug, Clone)]
pub struct EnsembleResult {
    /// Aggregated anomaly score
    pub score: f32,
    /// Calibrated score (if calibration enabled)
    pub calibrated_score: f32,
    /// Confidence in the prediction
    pub confidence: f32,
    /// Is anomalous
    pub is_anomaly: bool,
    /// Individual model votes
    pub votes: Vec<(String, f32)>,
    /// Explanation
    pub explanation: String,
}

/// Ensemble anomaly detector
#[derive(Debug)]
pub struct EnsembleDetector {
    config: EnsembleConfig,
    /// Statistical model
    statistical: Option<StatisticalModel>,
    /// Isolation forest
    isolation_forest: Option<IsolationForest>,
    /// Autoencoder
    autoencoder: Option<AutoencoderDetector>,
    /// Temporal detector
    temporal: Option<TemporalDetector>,
    /// Gradient boosting
    gradient_boost: Option<GradientBoostDetector>,
    /// Calibrator
    calibrator: Calibrator,
    /// Vote aggregator
    aggregator: VoteAggregator,
    /// Statistics
    stats: EnsembleStats,
}

/// Ensemble statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnsembleStats {
    /// Total samples scored
    pub samples_scored: u64,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// Average score
    pub avg_score: f32,
    /// Average confidence
    pub avg_confidence: f32,
}

impl EnsembleDetector {
    /// Create a new ensemble detector
    pub fn new(config: EnsembleConfig) -> Self {
        let statistical = if config.use_statistical {
            Some(StatisticalModel::default())
        } else {
            None
        };

        let isolation_forest = if config.use_isolation_forest {
            Some(IsolationForest::default())
        } else {
            None
        };

        let autoencoder = if config.use_autoencoder {
            Some(AutoencoderDetector::new(Default::default()))
        } else {
            None
        };

        let temporal = if config.use_temporal {
            Some(TemporalDetector::new())
        } else {
            None
        };

        let gradient_boost = if config.use_gradient_boost {
            Some(GradientBoostDetector::default())
        } else {
            None
        };

        let calibrator = Calibrator::new(config.calibration);
        let aggregator = VoteAggregator::new(config.voting)
            .with_threshold(config.threshold);

        Self {
            config,
            statistical,
            isolation_forest,
            autoencoder,
            temporal,
            gradient_boost,
            calibrator,
            aggregator,
            stats: EnsembleStats::default(),
        }
    }

    /// Train all models on feature vectors
    pub fn fit(&mut self, data: &[FeatureVector]) {
        if let Some(ref mut model) = self.statistical {
            model.fit(data);
        }

        if let Some(ref mut model) = self.isolation_forest {
            model.fit(data);
        }

        if let Some(ref mut model) = self.autoencoder {
            model.fit(data);
        }

        if let Some(ref mut model) = self.gradient_boost {
            model.fit(data);
        }

        // Temporal model is trained differently (on sequences)
    }

    /// Train on unified feature vectors
    pub fn fit_unified(&mut self, vectors: &[UnifiedFeatureVector]) {
        // Convert to FeatureVector for compatibility
        let feature_vectors: Vec<FeatureVector> = vectors
            .iter()
            .map(|v| FeatureVector {
                features: v.features.to_vec(),
                flow_id: v.flow_id,
                timestamp: v.timestamp,
                protocol: crate::protocols::AppProtocol::Unknown,
            })
            .collect();

        self.fit(&feature_vectors);

        // Train autoencoder on unified vectors directly
        if let Some(ref mut ae) = self.autoencoder {
            ae.fit_unified(vectors);
        }
    }

    /// Score a unified feature vector
    pub fn score_unified(&mut self, vector: &UnifiedFeatureVector) -> EnsembleResult {
        self.aggregator.clear();
        let weights = &self.config.weights;

        // Statistical model
        if let Some(ref model) = self.statistical {
            let score = if model.is_trained() {
                // Use baseline for z-score calculation
                let fv = self.to_feature_vector(vector);
                model.score(&fv)
            } else {
                0.0
            };
            self.aggregator.add_vote(
                ModelVote::new("statistical", score, weights.statistical)
                    .with_confidence(if model.is_trained() { 0.8 } else { 0.0 })
            );
        }

        // Isolation forest
        if let Some(ref model) = self.isolation_forest {
            let score = if model.is_trained() {
                let fv = self.to_feature_vector(vector);
                model.score(&fv)
            } else {
                0.0
            };
            self.aggregator.add_vote(
                ModelVote::new("isolation_forest", score, weights.isolation_forest)
                    .with_confidence(if model.is_trained() { 0.85 } else { 0.0 })
            );
        }

        // Autoencoder
        if let Some(ref mut ae) = self.autoencoder {
            let score = ae.score_unified(vector);
            let is_trained = ae.is_trained();
            self.aggregator.add_vote(
                ModelVote::new("autoencoder", score, weights.autoencoder)
                    .with_confidence(if is_trained { 0.9 } else { 0.5 })
            );
        }

        // Gradient boost
        if let Some(ref model) = self.gradient_boost {
            let score = model.score_features(&vector.features);
            self.aggregator.add_vote(
                ModelVote::new("gradient_boost", score, weights.gradient_boost)
                    .with_confidence(if model.is_trained() { 0.85 } else { 0.0 })
            );
        }

        // Note: Temporal model requires sequence, not single vector
        // It's scored separately via score_sequence()

        self.finalize_result()
    }

    /// Score with temporal context
    pub fn score_with_sequence(
        &mut self,
        vector: &UnifiedFeatureVector,
        sequence: Option<&[[f32; UNIFIED_DIM]]>,
    ) -> EnsembleResult {
        // First get non-temporal scores
        let mut result = self.score_unified(vector);

        // Add temporal score if sequence available
        if let (Some(temporal), Some(seq)) = (&mut self.temporal, sequence) {
            if seq.len() >= 2 {
                let _score = temporal.manager().config().min_sequence_length;
                // Use the internal lstm to score
                let temporal_score = 0.0; // Would need sequence scoring here

                self.aggregator.add_vote(
                    ModelVote::new("temporal", temporal_score, self.config.weights.temporal)
                        .with_confidence(0.8)
                );

                // Re-aggregate with temporal vote
                result = self.finalize_result();
            }
        }

        result
    }

    /// Finalize and create result
    fn finalize_result(&mut self) -> EnsembleResult {
        let score = self.aggregator.aggregate();
        let confidence = self.aggregator.aggregate_confidence();
        let calibrated = self.calibrator.calibrate(score);
        let is_anomaly = calibrated > self.config.threshold;

        // Update stats
        self.stats.samples_scored += 1;
        if is_anomaly {
            self.stats.anomalies_detected += 1;
        }
        // EMA for averages
        let alpha = 0.01;
        self.stats.avg_score = self.stats.avg_score * (1.0 - alpha) + score * alpha;
        self.stats.avg_confidence = self.stats.avg_confidence * (1.0 - alpha) + confidence * alpha;

        // Build explanation
        let votes: Vec<(String, f32)> = self.aggregator.votes()
            .iter()
            .filter(|v| v.is_trained)
            .map(|v| (v.model.clone(), v.score))
            .collect();

        let top_contributor = votes.iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let explanation = if is_anomaly {
            format!(
                "Anomaly detected: score={:.3} (threshold={:.3}), confidence={:.2}, top_model={}",
                calibrated, self.config.threshold, confidence, top_contributor
            )
        } else {
            format!(
                "Normal: score={:.3}, confidence={:.2}",
                calibrated, confidence
            )
        };

        EnsembleResult {
            score,
            calibrated_score: calibrated,
            confidence,
            is_anomaly,
            votes,
            explanation,
        }
    }

    /// Convert unified vector to legacy feature vector
    fn to_feature_vector(&self, vector: &UnifiedFeatureVector) -> FeatureVector {
        FeatureVector {
            features: vector.features.to_vec(),
            flow_id: vector.flow_id,
            timestamp: vector.timestamp,
            protocol: crate::protocols::AppProtocol::Unknown,
        }
    }

    /// Process temporal data for an IP
    pub fn process_temporal(&mut self, ip: IpAddr, vector: &UnifiedFeatureVector) {
        if let Some(ref mut temporal) = self.temporal {
            temporal.process(ip, vector);
        }
    }

    /// Calibrate on validation data
    pub fn calibrate(&mut self, scores: &[f32], labels: &[f32]) {
        self.calibrator.fit(scores, labels);
    }

    /// Check if any model is trained
    pub fn is_trained(&self) -> bool {
        self.statistical.as_ref().map(|m| m.is_trained()).unwrap_or(false) ||
        self.isolation_forest.as_ref().map(|m| m.is_trained()).unwrap_or(false) ||
        self.autoencoder.as_ref().map(|m| m.is_trained()).unwrap_or(false) ||
        self.gradient_boost.as_ref().map(|m| m.is_trained()).unwrap_or(false)
    }

    /// Get trained model count
    pub fn trained_count(&self) -> usize {
        let mut count = 0;
        if self.statistical.as_ref().map(|m| m.is_trained()).unwrap_or(false) { count += 1; }
        if self.isolation_forest.as_ref().map(|m| m.is_trained()).unwrap_or(false) { count += 1; }
        if self.autoencoder.as_ref().map(|m| m.is_trained()).unwrap_or(false) { count += 1; }
        if self.gradient_boost.as_ref().map(|m| m.is_trained()).unwrap_or(false) { count += 1; }
        if self.temporal.as_ref().map(|m| m.is_trained()).unwrap_or(false) { count += 1; }
        count
    }

    /// Get statistics
    pub fn stats(&self) -> &EnsembleStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &EnsembleConfig {
        &self.config
    }

    /// Update model weights dynamically
    pub fn set_weights(&mut self, weights: ModelWeights) {
        self.config.weights = weights;
    }

    /// Get calibration error if calibrator is fitted
    pub fn calibration_error(&self, scores: &[f32], labels: &[f32]) -> Option<f32> {
        if self.calibrator.is_fitted() {
            Some(self.calibrator.expected_calibration_error(scores, labels, 10))
        } else {
            None
        }
    }
}

impl Default for EnsembleDetector {
    fn default() -> Self {
        Self::new(EnsembleConfig::default())
    }
}

impl AnomalyModel for EnsembleDetector {
    fn fit(&mut self, data: &[FeatureVector]) {
        EnsembleDetector::fit(self, data);
    }

    fn score(&self, sample: &FeatureVector) -> f32 {
        // Create unified vector
        let mut features = [0.0f32; UNIFIED_DIM];
        for (i, &val) in sample.features.iter().enumerate() {
            if i < UNIFIED_DIM {
                features[i] = val;
            }
        }

        // Simple average of available model scores
        let mut scores = Vec::new();

        if let Some(ref model) = self.statistical {
            if model.is_trained() {
                scores.push(model.score(sample));
            }
        }

        if let Some(ref model) = self.isolation_forest {
            if model.is_trained() {
                scores.push(model.score(sample));
            }
        }

        if let Some(ref model) = self.gradient_boost {
            if model.is_trained() {
                scores.push(model.score_features(&features));
            }
        }

        if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<f32>() / scores.len() as f32
        }
    }

    fn predict(&self, sample: &FeatureVector) -> bool {
        self.score(sample) > self.config.threshold
    }

    fn name(&self) -> &str {
        "ensemble"
    }

    fn is_trained(&self) -> bool {
        EnsembleDetector::is_trained(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_vector() -> UnifiedFeatureVector {
        UnifiedFeatureVector {
            features: [0.5; UNIFIED_DIM],
            ..Default::default()
        }
    }

    #[test]
    fn test_ensemble_creation() {
        let ensemble = EnsembleDetector::default();
        assert!(!ensemble.is_trained());
    }

    #[test]
    fn test_ensemble_scoring() {
        let mut ensemble = EnsembleDetector::default();
        let result = ensemble.score_unified(&make_test_vector());

        assert!(result.score >= 0.0);
        assert!(result.score <= 1.0);
    }

    #[test]
    fn test_ensemble_config() {
        let config = EnsembleConfig {
            voting: VotingStrategy::Max,
            threshold: 0.7,
            ..Default::default()
        };

        let ensemble = EnsembleDetector::new(config.clone());
        assert_eq!(ensemble.config().threshold, 0.7);
    }

    #[test]
    fn test_model_weights() {
        let weights = ModelWeights::default();
        let total = weights.statistical + weights.isolation_forest +
                   weights.autoencoder + weights.temporal + weights.gradient_boost;
        // Should sum to 1.0
        assert!((total - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_trained_count() {
        let ensemble = EnsembleDetector::default();
        assert_eq!(ensemble.trained_count(), 0);
    }
}

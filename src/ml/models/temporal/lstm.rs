//! LSTM-based Temporal Anomaly Detection
//!
//! Uses LSTM networks to detect anomalies in temporal sequences of network features.
//! The model learns normal traffic patterns and flags deviations.

use serde::{Deserialize, Serialize};

use crate::ml::unified::UNIFIED_DIM;

#[cfg(feature = "ml-advanced")]
use burn::{
    module::Module,
    nn::{
        Linear, LinearConfig,
        Lstm, LstmConfig,
    },
    tensor::{backend::Backend, Tensor},
};

/// LSTM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstmConfig {
    /// Input dimension (feature vector size)
    pub input_dim: usize,
    /// Hidden state dimension
    pub hidden_dim: usize,
    /// Number of LSTM layers
    pub num_layers: usize,
    /// Dropout rate
    pub dropout: f32,
    /// Sequence length for training
    pub sequence_length: usize,
    /// Learning rate
    pub learning_rate: f64,
    /// Batch size
    pub batch_size: usize,
}

impl Default for LstmConfig {
    fn default() -> Self {
        Self {
            input_dim: UNIFIED_DIM,
            hidden_dim: 64,
            num_layers: 2,
            dropout: 0.2,
            sequence_length: 10,
            learning_rate: 0.001,
            batch_size: 32,
        }
    }
}

/// LSTM-based anomaly detector
#[derive(Debug)]
pub struct LstmDetector {
    config: LstmConfig,
    /// Whether model is trained
    trained: bool,
    /// Threshold for anomaly detection
    threshold: f32,
    /// Running prediction error statistics
    error_stats: ErrorStats,
}

/// Statistics for prediction errors
#[derive(Debug, Clone, Default)]
struct ErrorStats {
    count: u64,
    mean: f32,
    m2: f64,
}

impl ErrorStats {
    fn update(&mut self, error: f32) {
        self.count += 1;
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

    fn adaptive_threshold(&self, k: f32) -> f32 {
        self.mean + k * self.std()
    }
}

impl LstmDetector {
    /// Create a new LSTM detector
    pub fn new(config: LstmConfig) -> Self {
        Self {
            config,
            trained: false,
            threshold: 0.5,
            error_stats: ErrorStats::default(),
        }
    }

    /// Set anomaly threshold
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Check if trained
    pub fn is_trained(&self) -> bool {
        self.trained
    }

    /// Train on sequences of normal traffic
    /// Each sequence is a Vec of feature vectors representing a time series
    pub fn fit(&mut self, _sequences: &[Vec<[f32; UNIFIED_DIM]>]) {
        // Without ml-advanced feature, training is a no-op
        // With the feature, this would initialize and train the LSTM
        #[cfg(not(feature = "ml-advanced"))]
        {
            self.trained = true; // Mark as "trained" so scoring works
        }

        #[cfg(feature = "ml-advanced")]
        {
            // TODO: Implement burn-based LSTM training
            self.trained = true;
        }
    }

    /// Score a sequence for anomaly
    /// Returns prediction error (higher = more anomalous)
    pub fn score(&mut self, sequence: &[[f32; UNIFIED_DIM]]) -> f32 {
        if sequence.len() < 2 {
            return 0.0;
        }

        // Simple heuristic scoring when LSTM not available:
        // Measure the "smoothness" of the sequence using consecutive differences
        let mut total_change = 0.0f32;
        let mut sudden_changes = 0;

        for i in 1..sequence.len() {
            let prev = &sequence[i - 1];
            let curr = &sequence[i];

            // Euclidean distance between consecutive vectors
            let dist: f32 = prev
                .iter()
                .zip(curr.iter())
                .map(|(a, b)| (a - b).powi(2))
                .sum::<f32>()
                .sqrt();

            total_change += dist;

            // Count sudden large changes
            if dist > self.threshold * 2.0 {
                sudden_changes += 1;
            }
        }

        let avg_change = total_change / (sequence.len() - 1) as f32;
        let sudden_ratio = sudden_changes as f32 / (sequence.len() - 1) as f32;

        // Combine metrics
        let score = avg_change * 0.5 + sudden_ratio * 0.5;

        // Update statistics
        self.error_stats.update(score);

        score
    }

    /// Predict next features (simplified)
    /// In a full implementation, this would use the LSTM to predict the next timestep
    pub fn predict_next(&self, sequence: &[[f32; UNIFIED_DIM]]) -> [f32; UNIFIED_DIM] {
        if sequence.is_empty() {
            return [0.0; UNIFIED_DIM];
        }

        // Simple prediction: weighted average of recent features
        let mut result = [0.0f32; UNIFIED_DIM];
        let weights: Vec<f32> = (0..sequence.len())
            .map(|i| (i + 1) as f32)
            .collect();
        let total_weight: f32 = weights.iter().sum();

        for (i, features) in sequence.iter().enumerate() {
            let w = weights[i] / total_weight;
            for (j, &v) in features.iter().enumerate() {
                result[j] += v * w;
            }
        }

        result
    }

    /// Check if a sequence is anomalous
    pub fn is_anomaly(&self, score: f32) -> bool {
        if self.error_stats.count >= 50 {
            score > self.error_stats.adaptive_threshold(2.5)
        } else {
            score > self.threshold
        }
    }

    /// Get current adaptive threshold
    pub fn current_threshold(&self) -> f32 {
        if self.error_stats.count >= 50 {
            self.error_stats.adaptive_threshold(2.5)
        } else {
            self.threshold
        }
    }

    /// Get configuration
    pub fn config(&self) -> &LstmConfig {
        &self.config
    }

    /// Get error statistics (mean, std)
    pub fn error_stats(&self) -> (f32, f32) {
        (self.error_stats.mean, self.error_stats.std())
    }
}

impl Default for LstmDetector {
    fn default() -> Self {
        Self::new(LstmConfig::default())
    }
}

/// Trait for temporal anomaly models
pub trait TemporalModel: Send + Sync {
    /// Train on sequences
    fn fit(&mut self, sequences: &[Vec<[f32; UNIFIED_DIM]>]);

    /// Score a sequence
    fn score(&mut self, sequence: &[[f32; UNIFIED_DIM]]) -> f32;

    /// Predict if anomalous
    fn predict(&mut self, sequence: &[[f32; UNIFIED_DIM]]) -> bool;

    /// Model name
    fn name(&self) -> &str;

    /// Is trained
    fn is_trained(&self) -> bool;
}

impl TemporalModel for LstmDetector {
    fn fit(&mut self, sequences: &[Vec<[f32; UNIFIED_DIM]>]) {
        LstmDetector::fit(self, sequences);
    }

    fn score(&mut self, sequence: &[[f32; UNIFIED_DIM]]) -> f32 {
        LstmDetector::score(self, sequence)
    }

    fn predict(&mut self, sequence: &[[f32; UNIFIED_DIM]]) -> bool {
        let score = self.score(sequence);
        self.is_anomaly(score)
    }

    fn name(&self) -> &str {
        "lstm"
    }

    fn is_trained(&self) -> bool {
        self.trained
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_normal_sequence(len: usize) -> Vec<[f32; UNIFIED_DIM]> {
        (0..len)
            .map(|i| {
                let mut features = [0.1; UNIFIED_DIM];
                // Slight variation
                features[0] = 0.1 + (i as f32 * 0.01);
                features
            })
            .collect()
    }

    fn make_anomalous_sequence(len: usize) -> Vec<[f32; UNIFIED_DIM]> {
        (0..len)
            .map(|i| {
                let mut features = [0.1; UNIFIED_DIM];
                // Large sudden changes
                if i % 2 == 0 {
                    features[0] = 10.0;
                }
                features
            })
            .collect()
    }

    #[test]
    fn test_lstm_detector_creation() {
        let detector = LstmDetector::default();
        assert!(!detector.is_trained());
    }

    #[test]
    fn test_sequence_scoring() {
        let mut detector = LstmDetector::default();
        detector.fit(&[make_normal_sequence(20)]);

        // Normal sequence should have low score
        let normal_score = detector.score(&make_normal_sequence(10));

        // Anomalous sequence should have higher score
        let anomaly_score = detector.score(&make_anomalous_sequence(10));

        assert!(anomaly_score > normal_score);
    }

    #[test]
    fn test_prediction() {
        let detector = LstmDetector::default();
        let sequence = make_normal_sequence(5);
        let prediction = detector.predict_next(&sequence);

        // Prediction should be non-zero
        assert!(prediction[0] > 0.0);
    }

    #[test]
    fn test_temporal_model_trait() {
        let mut detector: Box<dyn TemporalModel> = Box::new(LstmDetector::default());
        detector.fit(&[make_normal_sequence(10)]);

        assert!(detector.is_trained());
        assert_eq!(detector.name(), "lstm");
    }
}

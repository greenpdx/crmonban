//! ML Models for anomaly detection
//!
//! Provides various model implementations for detecting anomalies.
//!
//! # Available Models
//! - **Statistical**: Z-score and IQR-based anomaly detection
//! - **Isolation Forest**: Tree-based anomaly isolation
//! - **Autoencoder**: Reconstruction error-based detection (requires ml-advanced feature)
//! - **Temporal/LSTM**: Sequence-based pattern detection
//! - **Gradient Boost**: Decision tree-based classification
//! - **Ensemble**: Weighted combination of all models

pub mod isolation_forest;
pub mod statistical;
pub mod autoencoder;
pub mod temporal;
pub mod gradient_boost;
pub mod ensemble;

pub use isolation_forest::IsolationForest;
pub use statistical::StatisticalModel;
pub use autoencoder::{AutoencoderDetector, AutoencoderConfig};
pub use temporal::{TemporalDetector, TemporalConfig, SequenceManager, WindowConfig};
pub use gradient_boost::{GradientBoostDetector, GradientBoostConfig};
pub use ensemble::{
    EnsembleDetector, EnsembleConfig, EnsembleResult, ModelWeights,
    VotingStrategy, VoteAggregator, Calibrator, CalibrationMethod,
};

use serde::{Deserialize, Serialize};

use super::features::FeatureVector;

/// Trait for anomaly detection models
pub trait AnomalyModel: Send + Sync {
    /// Train the model on normal data
    fn fit(&mut self, data: &[FeatureVector]);

    /// Score a sample (higher = more anomalous)
    fn score(&self, sample: &FeatureVector) -> f32;

    /// Predict if a sample is anomalous
    fn predict(&self, sample: &FeatureVector) -> bool;

    /// Get model name
    fn name(&self) -> &str;

    /// Check if model is trained
    fn is_trained(&self) -> bool;
}

/// Model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Anomaly threshold (scores above this are anomalies)
    pub threshold: f32,
    /// Number of trees for ensemble methods
    pub num_trees: usize,
    /// Sample size for each tree
    pub sample_size: usize,
    /// Random seed for reproducibility
    pub seed: Option<u64>,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            threshold: 0.5,
            num_trees: 100,
            sample_size: 256,
            seed: None,
        }
    }
}

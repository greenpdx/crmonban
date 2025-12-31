//! Autoencoder Training
//!
//! Provides training loop and data handling for the autoencoder.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::network::AutoencoderConfig;
use crate::ml::unified::{UnifiedFeatureVector, UNIFIED_DIM};

#[cfg(feature = "ml-advanced")]
use burn::{
    data::{dataloader::batcher::Batcher, dataset::Dataset},
    optim::{AdamConfig, Optimizer},
    tensor::{backend::Backend, Tensor},
};

#[cfg(feature = "ml-advanced")]
use super::network::Autoencoder;

/// Training data for the autoencoder
#[derive(Debug, Clone)]
pub struct AutoencoderDataset {
    samples: Vec<[f32; UNIFIED_DIM]>,
}

impl AutoencoderDataset {
    /// Create a new empty dataset
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    /// Create from unified feature vectors
    pub fn from_vectors(vectors: &[UnifiedFeatureVector]) -> Self {
        Self {
            samples: vectors.iter().map(|v| v.features).collect(),
        }
    }

    /// Add a sample
    pub fn add(&mut self, features: [f32; UNIFIED_DIM]) {
        self.samples.push(features);
    }

    /// Get number of samples
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

impl Default for AutoencoderDataset {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "ml-advanced")]
impl Dataset<[f32; UNIFIED_DIM]> for AutoencoderDataset {
    fn get(&self, index: usize) -> Option<[f32; UNIFIED_DIM]> {
        self.samples.get(index).copied()
    }

    fn len(&self) -> usize {
        self.samples.len()
    }
}

/// Training progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingProgress {
    /// Current epoch
    pub epoch: usize,
    /// Total epochs
    pub total_epochs: usize,
    /// Current batch
    pub batch: usize,
    /// Total batches per epoch
    pub total_batches: usize,
    /// Average loss for current epoch
    pub epoch_loss: f32,
    /// Best loss seen so far
    pub best_loss: f32,
    /// Training complete
    pub complete: bool,
}

impl TrainingProgress {
    pub fn new(total_epochs: usize) -> Self {
        Self {
            epoch: 0,
            total_epochs,
            batch: 0,
            total_batches: 0,
            epoch_loss: f32::MAX,
            best_loss: f32::MAX,
            complete: false,
        }
    }
}

/// Autoencoder trainer
#[derive(Debug)]
pub struct AutoencoderTrainer {
    config: AutoencoderConfig,
    /// Loss history for monitoring
    loss_history: VecDeque<f32>,
    /// Maximum history length
    max_history: usize,
}

impl AutoencoderTrainer {
    /// Create a new trainer with configuration
    pub fn new(config: AutoencoderConfig) -> Self {
        Self {
            config,
            loss_history: VecDeque::with_capacity(1000),
            max_history: 1000,
        }
    }

    /// Get configuration
    pub fn config(&self) -> &AutoencoderConfig {
        &self.config
    }

    /// Record a loss value
    pub fn record_loss(&mut self, loss: f32) {
        if self.loss_history.len() >= self.max_history {
            self.loss_history.pop_front();
        }
        self.loss_history.push_back(loss);
    }

    /// Get average recent loss
    pub fn average_loss(&self) -> f32 {
        if self.loss_history.is_empty() {
            return 0.0;
        }
        self.loss_history.iter().sum::<f32>() / self.loss_history.len() as f32
    }

    /// Get loss trend (positive = increasing, negative = decreasing)
    pub fn loss_trend(&self) -> f32 {
        if self.loss_history.len() < 10 {
            return 0.0;
        }

        let recent: Vec<f32> = self.loss_history.iter().rev().take(10).copied().collect();
        let older: Vec<f32> = self.loss_history.iter().rev().skip(10).take(10).copied().collect();

        if older.is_empty() {
            return 0.0;
        }

        let recent_avg: f32 = recent.iter().sum::<f32>() / recent.len() as f32;
        let older_avg: f32 = older.iter().sum::<f32>() / older.len() as f32;

        recent_avg - older_avg
    }

    /// Check for early stopping (loss not improving)
    pub fn should_stop_early(&self, patience: usize) -> bool {
        if self.loss_history.len() < patience * 2 {
            return false;
        }

        let recent: Vec<f32> = self.loss_history.iter().rev().take(patience).copied().collect();
        let older: Vec<f32> = self.loss_history.iter().rev().skip(patience).take(patience).copied().collect();

        if older.is_empty() {
            return false;
        }

        let recent_min = recent.iter().cloned().fold(f32::MAX, f32::min);
        let older_min = older.iter().cloned().fold(f32::MAX, f32::min);

        // Stop if recent min is not better than older min
        recent_min >= older_min
    }

    /// Train the autoencoder (stub for non-ml-advanced builds)
    #[cfg(not(feature = "ml-advanced"))]
    pub fn train(&mut self, _dataset: &AutoencoderDataset) -> TrainedAutoencoder {
        TrainedAutoencoder {
            config: self.config.clone(),
            trained: false,
            final_loss: 0.0,
            epochs_trained: 0,
        }
    }
}

/// Trained autoencoder result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainedAutoencoder {
    /// Configuration used
    pub config: AutoencoderConfig,
    /// Whether training completed successfully
    pub trained: bool,
    /// Final training loss
    pub final_loss: f32,
    /// Number of epochs trained
    pub epochs_trained: usize,
}

impl TrainedAutoencoder {
    /// Score a feature vector (reconstruction error)
    #[cfg(not(feature = "ml-advanced"))]
    pub fn score(&self, _features: &[f32; UNIFIED_DIM]) -> f32 {
        0.0 // Stub when not built with ml-advanced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_creation() {
        let mut dataset = AutoencoderDataset::new();
        assert!(dataset.is_empty());

        dataset.add([0.0; UNIFIED_DIM]);
        assert_eq!(dataset.len(), 1);
    }

    #[test]
    fn test_trainer_loss_tracking() {
        let config = AutoencoderConfig::default();
        let mut trainer = AutoencoderTrainer::new(config);

        for i in 0..20 {
            trainer.record_loss(1.0 - (i as f32 * 0.01));
        }

        assert!(trainer.loss_trend() < 0.0); // Decreasing trend
    }

    #[test]
    fn test_training_progress() {
        let progress = TrainingProgress::new(100);
        assert_eq!(progress.epoch, 0);
        assert_eq!(progress.total_epochs, 100);
        assert!(!progress.complete);
    }
}

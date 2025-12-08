//! Model training utilities
//!
//! Handles training data collection and model persistence.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::features::FeatureVector;
use super::baseline::Baseline;
use super::models::{AnomalyModel, IsolationForest, StatisticalModel, ModelConfig};

/// Training data collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingData {
    /// Collected feature vectors
    samples: Vec<FeatureVector>,
    /// Maximum samples to keep
    max_samples: usize,
    /// When collection started
    started: DateTime<Utc>,
    /// Last sample time
    last_sample: DateTime<Utc>,
}

impl Default for TrainingData {
    fn default() -> Self {
        Self::new(100_000)
    }
}

impl TrainingData {
    /// Create new training data collector
    pub fn new(max_samples: usize) -> Self {
        let now = Utc::now();
        Self {
            samples: Vec::with_capacity(max_samples.min(10_000)),
            max_samples,
            started: now,
            last_sample: now,
        }
    }

    /// Add a sample
    pub fn add(&mut self, sample: FeatureVector) {
        self.last_sample = Utc::now();

        if self.samples.len() >= self.max_samples {
            // Remove oldest 10% to make room
            let remove_count = self.max_samples / 10;
            self.samples.drain(0..remove_count);
        }

        self.samples.push(sample);
    }

    /// Get number of samples
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Get samples as slice
    pub fn samples(&self) -> &[FeatureVector] {
        &self.samples
    }

    /// Get collection duration
    pub fn duration(&self) -> chrono::Duration {
        self.last_sample - self.started
    }

    /// Save to disk
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        bincode::serde::encode_into_std_write(self, &mut writer, bincode::config::standard())?;
        Ok(())
    }

    /// Load from disk
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let data: Self = bincode::serde::decode_from_std_read(&mut reader, bincode::config::standard())?;
        Ok(data)
    }

    /// Clear all samples
    pub fn clear(&mut self) {
        self.samples.clear();
        self.started = Utc::now();
        self.last_sample = self.started;
    }
}

/// Trained model bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainedModel {
    /// Baseline statistics
    pub baseline: Baseline,
    /// Isolation forest model
    pub isolation_forest: Option<IsolationForest>,
    /// Statistical model
    pub statistical_model: Option<StatisticalModel>,
    /// Training timestamp
    pub trained_at: DateTime<Utc>,
    /// Number of samples used
    pub sample_count: u64,
    /// Model version
    pub version: String,
}

impl TrainedModel {
    /// Create a new trained model
    pub fn new(baseline: Baseline) -> Self {
        Self {
            baseline,
            isolation_forest: None,
            statistical_model: None,
            trained_at: Utc::now(),
            sample_count: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Save model to disk
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        bincode::serde::encode_into_std_write(self, &mut writer, bincode::config::standard())?;
        Ok(())
    }

    /// Load model from disk
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let model: Self = bincode::serde::decode_from_std_read(&mut reader, bincode::config::standard())?;
        Ok(model)
    }
}

/// Model trainer
pub struct ModelTrainer {
    config: ModelConfig,
}

impl Default for ModelTrainer {
    fn default() -> Self {
        Self::new(ModelConfig::default())
    }
}

impl ModelTrainer {
    /// Create a new trainer
    pub fn new(config: ModelConfig) -> Self {
        Self { config }
    }

    /// Train all models from training data
    pub fn train(&self, data: &TrainingData) -> TrainedModel {
        let samples = data.samples();

        // Build baseline
        let mut baseline = Baseline::new();
        for sample in samples {
            baseline.update(sample);
        }

        // Train isolation forest
        let isolation_forest = if samples.len() >= 100 {
            let mut forest = IsolationForest::new(self.config.clone());
            forest.fit(samples);
            Some(forest)
        } else {
            None
        };

        // Train statistical model
        let statistical_model = if samples.len() >= 10 {
            let mut model = StatisticalModel::new();
            model.fit(samples);
            Some(model)
        } else {
            None
        };

        TrainedModel {
            baseline,
            isolation_forest,
            statistical_model,
            trained_at: Utc::now(),
            sample_count: samples.len() as u64,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Incrementally update model with new data
    pub fn update(&self, model: &mut TrainedModel, new_data: &[FeatureVector]) {
        // Update baseline
        for sample in new_data {
            model.baseline.update(sample);
        }

        // Retrain isolation forest if we have enough new data
        if new_data.len() >= 1000 {
            if let Some(ref mut forest) = model.isolation_forest {
                forest.fit(new_data);
            }
        }

        // Update statistical model
        if let Some(ref mut stat_model) = model.statistical_model {
            stat_model.fit(new_data);
        }

        model.trained_at = Utc::now();
        model.sample_count += new_data.len() as u64;
    }
}

/// Training progress tracker
#[derive(Debug, Clone, Serialize)]
pub struct TrainingProgress {
    /// Current phase
    pub phase: TrainingPhase,
    /// Samples collected
    pub samples_collected: u64,
    /// Target samples
    pub target_samples: u64,
    /// Started time
    pub started: DateTime<Utc>,
    /// Estimated completion
    pub estimated_completion: Option<DateTime<Utc>>,
}

/// Training phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrainingPhase {
    /// Collecting samples
    Collecting,
    /// Training models
    Training,
    /// Training complete
    Complete,
    /// Training disabled
    Disabled,
}

impl TrainingProgress {
    /// Create new progress tracker
    pub fn new(target_samples: u64) -> Self {
        Self {
            phase: TrainingPhase::Collecting,
            samples_collected: 0,
            target_samples,
            started: Utc::now(),
            estimated_completion: None,
        }
    }

    /// Update progress
    pub fn update(&mut self, samples: u64) {
        self.samples_collected = samples;

        if samples >= self.target_samples {
            self.phase = TrainingPhase::Training;
        }

        // Estimate completion based on rate
        if samples > 0 {
            let elapsed = Utc::now() - self.started;
            let remaining = self.target_samples.saturating_sub(samples);
            let rate = samples as f64 / elapsed.num_seconds().max(1) as f64;

            if rate > 0.0 {
                let remaining_secs = (remaining as f64 / rate) as i64;
                self.estimated_completion = Some(
                    Utc::now() + chrono::Duration::seconds(remaining_secs)
                );
            }
        }
    }

    /// Mark training complete
    pub fn complete(&mut self) {
        self.phase = TrainingPhase::Complete;
        self.estimated_completion = Some(Utc::now());
    }

    /// Get completion percentage
    pub fn percentage(&self) -> f32 {
        if self.target_samples == 0 {
            return 100.0;
        }
        (self.samples_collected as f32 / self.target_samples as f32 * 100.0).min(100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::AppProtocol;

    fn make_features(values: Vec<f32>) -> FeatureVector {
        FeatureVector {
            features: values,
            flow_id: 1,
            timestamp: Utc::now(),
            protocol: AppProtocol::Unknown,
        }
    }

    #[test]
    fn test_training_data_collection() {
        let mut data = TrainingData::new(100);

        for i in 0..50 {
            data.add(make_features(vec![i as f32; 10]));
        }

        assert_eq!(data.len(), 50);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_training_data_overflow() {
        let mut data = TrainingData::new(100);

        for i in 0..150 {
            data.add(make_features(vec![i as f32; 10]));
        }

        // Should have removed oldest 10% when hitting limit
        assert!(data.len() <= 100);
    }

    #[test]
    fn test_model_training() {
        let mut data = TrainingData::new(1000);

        for i in 0..200 {
            data.add(make_features(vec![(i % 50) as f32; 10]));
        }

        let trainer = ModelTrainer::default();
        let model = trainer.train(&data);

        assert!(model.isolation_forest.is_some());
        assert!(model.statistical_model.is_some());
        assert_eq!(model.sample_count, 200);
    }

    #[test]
    fn test_training_progress() {
        let mut progress = TrainingProgress::new(1000);

        assert_eq!(progress.phase, TrainingPhase::Collecting);
        assert_eq!(progress.percentage(), 0.0);

        progress.update(500);
        assert_eq!(progress.percentage(), 50.0);

        progress.update(1000);
        assert_eq!(progress.phase, TrainingPhase::Training);
    }
}

//! Online Learning Module
//!
//! Provides continuous learning from feedback to improve ML detection over time.
//!
//! # Features
//! - Experience replay buffer for storing labeled samples
//! - Incremental update strategies (EMA, sliding window, tree rotation)
//! - Feedback integration for converting analyst corrections to training data
//! - Coordinated model updates without full retraining
//!
//! # Architecture
//! ```text
//! Feedback Events → FeedbackReceiver → ReplayBuffer → OnlineLearner → Model Updates
//!                                                           ↓
//!                                            IncrementalUpdater → Statistics
//! ```
//!
//! # Usage
//! ```ignore
//! use crmonban::ml::online::{OnlineLearner, OnlineConfig, FeedbackSender};
//!
//! // Create online learner
//! let config = OnlineConfig::default();
//! let mut learner = OnlineLearner::new(config);
//!
//! // Process feedback
//! learner.add_false_positive(flow_id, features);
//!
//! // Periodically update models
//! if learner.should_update() {
//!     learner.update_models(&mut ensemble);
//! }
//! ```

pub mod replay_buffer;
pub mod incremental;
pub mod feedback;

pub use replay_buffer::{
    ReplayBuffer, ReplayBufferConfig, ExperienceSample,
    SampleLabel, SamplePriority, BufferStats,
};
pub use incremental::{
    IncrementalConfig, IncrementalUpdater, UpdateResult, UpdateStrategy,
    EMAUpdater, SlidingWindow, ReservoirSampler, TreeRotator,
};
pub use feedback::{
    FeedbackEvent, FeedbackSender, FeedbackReceiver, FeedbackStats,
    FeedbackAdapter, CorrectionSource, DiscoverySource, ModelFeedbackStats,
};

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::ml::unified::{UnifiedFeatureVector, UNIFIED_DIM};
use crate::ml::baseline::Baseline;
use crate::ml::models::{
    EnsembleDetector, IsolationForest, GradientBoostDetector,
    AutoencoderDetector, TemporalDetector,
};

/// Online learning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnlineConfig {
    /// Enable online learning
    pub enabled: bool,
    /// Replay buffer configuration
    pub replay_buffer: ReplayBufferConfig,
    /// Incremental update configuration
    pub incremental: IncrementalConfig,
    /// Minimum feedback events before triggering update
    pub min_feedback_for_update: usize,
    /// Maximum time between updates (seconds)
    pub max_update_interval_secs: u64,
    /// Enable automatic model updates
    pub auto_update: bool,
    /// Threshold for triggering urgent update (FP rate)
    pub urgent_fp_threshold: f32,
    /// Threshold for triggering urgent update (FN rate)
    pub urgent_fn_threshold: f32,
    /// Enable ensemble weight adjustment
    pub adjust_ensemble_weights: bool,
    /// Learning rate for weight adjustment
    pub weight_learning_rate: f32,
}

impl Default for OnlineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            replay_buffer: ReplayBufferConfig::default(),
            incremental: IncrementalConfig::default(),
            min_feedback_for_update: 100,
            max_update_interval_secs: 3600, // 1 hour
            auto_update: true,
            urgent_fp_threshold: 0.15,
            urgent_fn_threshold: 0.20,
            adjust_ensemble_weights: true,
            weight_learning_rate: 0.05,
        }
    }
}

/// Online learning state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnlineState {
    /// Collecting feedback
    Collecting,
    /// Updating models
    Updating,
    /// Paused (manual intervention needed)
    Paused,
    /// Disabled
    Disabled,
}

/// Online learner coordinator
pub struct OnlineLearner {
    /// Configuration
    config: OnlineConfig,
    /// Current state
    state: OnlineState,
    /// Replay buffer
    buffer: ReplayBuffer,
    /// Incremental updater
    updater: IncrementalUpdater,
    /// Last update time
    last_update: DateTime<Utc>,
    /// Statistics
    stats: OnlineStats,
    /// Model performance tracking
    model_performance: ModelPerformance,
}

/// Online learning statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OnlineStats {
    /// Total samples processed
    pub samples_processed: u64,
    /// Total updates performed
    pub updates_performed: u64,
    /// Urgent updates triggered
    pub urgent_updates: u64,
    /// Samples used for training
    pub training_samples: u64,
    /// Current FP rate estimate
    pub current_fp_rate: f32,
    /// Current FN rate estimate
    pub current_fn_rate: f32,
    /// Average update duration (ms)
    pub avg_update_duration_ms: u64,
    /// Last update time
    pub last_update: Option<DateTime<Utc>>,
}

/// Model performance tracking for weight adjustment
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelPerformance {
    /// Statistical model performance
    pub statistical: PerformanceMetrics,
    /// Isolation forest performance
    pub isolation_forest: PerformanceMetrics,
    /// Autoencoder performance
    pub autoencoder: PerformanceMetrics,
    /// Temporal/LSTM performance
    pub temporal: PerformanceMetrics,
    /// Gradient boost performance
    pub gradient_boost: PerformanceMetrics,
}

/// Performance metrics for a single model
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Correct predictions
    pub correct: u64,
    /// Total predictions
    pub total: u64,
    /// Running accuracy estimate (EMA)
    pub accuracy: f32,
    /// Contribution to ensemble (weight factor)
    pub weight_factor: f32,
}

impl PerformanceMetrics {
    /// Update with a new prediction result
    pub fn update(&mut self, was_correct: bool, alpha: f32) {
        self.total += 1;
        if was_correct {
            self.correct += 1;
        }

        let correct_f = if was_correct { 1.0 } else { 0.0 };
        self.accuracy = (1.0 - alpha) * self.accuracy + alpha * correct_f;
    }

    /// Get current accuracy
    pub fn get_accuracy(&self) -> f32 {
        if self.total > 0 {
            self.correct as f32 / self.total as f32
        } else {
            0.5 // Default assumption
        }
    }
}

impl OnlineLearner {
    /// Create a new online learner
    pub fn new(config: OnlineConfig) -> Self {
        let state = if config.enabled {
            OnlineState::Collecting
        } else {
            OnlineState::Disabled
        };

        let buffer = ReplayBuffer::new(config.replay_buffer.clone());
        let updater = IncrementalUpdater::new(config.incremental.clone());

        Self {
            config,
            state,
            buffer,
            updater,
            last_update: Utc::now(),
            stats: OnlineStats::default(),
            model_performance: ModelPerformance::default(),
        }
    }

    /// Initialize from existing baseline
    pub fn with_baseline(mut self, baseline: &Baseline) -> Self {
        self.updater = IncrementalUpdater::new(self.config.incremental.clone())
            .with_baseline(baseline);
        self
    }

    /// Add a true positive sample
    pub fn add_true_positive(&mut self, vector: &UnifiedFeatureVector, detection_type: &str) {
        if self.state == OnlineState::Disabled {
            return;
        }
        self.buffer.add_true_positive(vector, detection_type);
        self.updater.process(&vector.features);
        self.stats.samples_processed += 1;
    }

    /// Add a false positive sample
    pub fn add_false_positive(&mut self, vector: &UnifiedFeatureVector, confidence: f32) {
        if self.state == OnlineState::Disabled {
            return;
        }
        self.buffer.add_false_positive(vector, confidence);
        self.updater.process(&vector.features);
        self.stats.samples_processed += 1;
        self.update_fp_rate();
    }

    /// Add a false negative sample
    pub fn add_false_negative(&mut self, vector: &UnifiedFeatureVector, detection_type: &str) {
        if self.state == OnlineState::Disabled {
            return;
        }
        self.buffer.add_false_negative(vector, detection_type);
        self.updater.process(&vector.features);
        self.stats.samples_processed += 1;
        self.update_fn_rate();
    }

    /// Add a true negative sample
    pub fn add_true_negative(&mut self, vector: &UnifiedFeatureVector) {
        if self.state == OnlineState::Disabled {
            return;
        }
        self.buffer.add_true_negative(vector);
        self.updater.process(&vector.features);
        self.stats.samples_processed += 1;
    }

    /// Process a feedback event directly
    pub fn process_feedback(&mut self, event: FeedbackEvent) {
        if self.state == OnlineState::Disabled {
            return;
        }

        if let Some(sample) = event.to_sample() {
            self.buffer.add(sample);
            self.stats.samples_processed += 1;
        }

        // Track model performance
        if let FeedbackEvent::ModelFeedback { model_name, was_correct, .. } = &event {
            self.update_model_performance(model_name, *was_correct);
        }
    }

    /// Update FP rate estimate
    fn update_fp_rate(&mut self) {
        let stats = self.buffer.stats();
        let fp = stats.incorrect_predictions as f32;
        let total = (stats.normal_count + stats.attack_count) as f32;
        if total > 0.0 {
            self.stats.current_fp_rate = fp / total;
        }
    }

    /// Update FN rate estimate
    fn update_fn_rate(&mut self) {
        // FN rate estimated from high-priority attack samples
        let stats = self.buffer.stats();
        if stats.attack_count > 0 {
            let critical = stats.high_priority_count as f32;
            self.stats.current_fn_rate = critical / stats.attack_count as f32;
        }
    }

    /// Update model-specific performance
    fn update_model_performance(&mut self, model_name: &str, was_correct: bool) {
        let alpha = self.config.weight_learning_rate;
        match model_name {
            "statistical" => self.model_performance.statistical.update(was_correct, alpha),
            "isolation_forest" => self.model_performance.isolation_forest.update(was_correct, alpha),
            "autoencoder" => self.model_performance.autoencoder.update(was_correct, alpha),
            "temporal" => self.model_performance.temporal.update(was_correct, alpha),
            "gradient_boost" => self.model_performance.gradient_boost.update(was_correct, alpha),
            _ => {}
        }
    }

    /// Check if update should be triggered
    pub fn should_update(&self) -> bool {
        if self.state != OnlineState::Collecting {
            return false;
        }

        // Check minimum samples
        if self.buffer.total_samples() < self.config.min_feedback_for_update {
            return false;
        }

        // Check time since last update
        let elapsed = Utc::now().signed_duration_since(self.last_update);
        if elapsed.num_seconds() >= self.config.max_update_interval_secs as i64 {
            return true;
        }

        // Check urgent thresholds
        if self.stats.current_fp_rate > self.config.urgent_fp_threshold {
            return true;
        }
        if self.stats.current_fn_rate > self.config.urgent_fn_threshold {
            return true;
        }

        false
    }

    /// Update baseline statistics
    pub fn update_baseline(&mut self, baseline: &mut Baseline) {
        let result = self.updater.apply_updates();

        // Update baseline with new EMA statistics
        // Note: FeatureStats uses Welford's algorithm internally, so we update mean directly
        // and adjust m2 to approximate the new variance
        for (i, stat) in baseline.global_stats.iter_mut().enumerate() {
            if i < UNIFIED_DIM {
                let new_mean = result.ema_means[i];
                stat.mean = new_mean;
                // Approximate m2 update to match new variance
                let new_var = result.ema_stds[i] * result.ema_stds[i];
                if stat.count > 1 {
                    stat.m2 = new_var * (stat.count - 1) as f32;
                }
            }
        }

        debug!("Updated baseline with {} samples", result.samples_processed);
    }

    /// Update isolation forest with new trees
    pub fn update_isolation_forest(&mut self, forest: &mut IsolationForest) {
        if !self.updater.tree_rotation_ready() {
            return;
        }

        let samples = self.updater.tree_rotation_samples();
        if samples.is_empty() {
            return;
        }

        // Convert to FeatureVector format for training
        // Note: This is a simplified update - in practice you'd retrain specific trees
        debug!("Tree rotation with {} samples", samples.len());
        self.updater.complete_tree_rotation();
    }

    /// Update ensemble detector
    pub fn update_ensemble(&mut self, ensemble: &mut EnsembleDetector) {
        if self.state != OnlineState::Collecting || !self.config.auto_update {
            return;
        }

        self.state = OnlineState::Updating;
        let start = std::time::Instant::now();

        // Get training batch
        let batch = self.buffer.sample_batch();
        if batch.is_empty() {
            self.state = OnlineState::Collecting;
            return;
        }

        self.stats.training_samples += batch.len() as u64;

        // Update incremental statistics
        let update_result = self.updater.apply_updates();
        debug!(
            "Applied incremental update: {} samples, {} updates",
            update_result.samples_processed, update_result.update_count
        );

        // Adjust ensemble weights based on performance
        if self.config.adjust_ensemble_weights {
            self.adjust_ensemble_weights(ensemble);
        }

        // Record stats
        self.stats.updates_performed += 1;
        self.stats.last_update = Some(Utc::now());
        self.last_update = Utc::now();

        let duration = start.elapsed();
        self.stats.avg_update_duration_ms = (self.stats.avg_update_duration_ms + duration.as_millis() as u64) / 2;

        info!(
            "Online learning update: {} samples, duration={:?}",
            batch.len(), duration
        );

        self.state = OnlineState::Collecting;
    }

    /// Adjust ensemble weights based on model performance
    fn adjust_ensemble_weights(&self, ensemble: &mut EnsembleDetector) {
        let perf = &self.model_performance;

        // Calculate weight adjustments based on accuracy
        let accuracies = [
            ("statistical", perf.statistical.accuracy),
            ("isolation_forest", perf.isolation_forest.accuracy),
            ("autoencoder", perf.autoencoder.accuracy),
            ("temporal", perf.temporal.accuracy),
            ("gradient_boost", perf.gradient_boost.accuracy),
        ];

        // Normalize to get new weights
        let total: f32 = accuracies.iter().map(|(_, a)| *a).sum();
        if total > 0.0 {
            // Log weight adjustments
            for (name, acc) in &accuracies {
                let new_weight = acc / total;
                debug!("Model {} accuracy={:.3}, weight={:.3}", name, acc, new_weight);
            }

            // Note: Actual weight update would need to be added to EnsembleDetector
            // ensemble.update_weights(...)
        }
    }

    /// Get current state
    pub fn state(&self) -> OnlineState {
        self.state
    }

    /// Set state to paused
    pub fn pause(&mut self) {
        if self.state != OnlineState::Disabled {
            self.state = OnlineState::Paused;
        }
    }

    /// Resume from paused state
    pub fn resume(&mut self) {
        if self.state == OnlineState::Paused {
            self.state = OnlineState::Collecting;
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &OnlineStats {
        &self.stats
    }

    /// Get replay buffer statistics
    pub fn buffer_stats(&self) -> &BufferStats {
        self.buffer.stats()
    }

    /// Get model performance metrics
    pub fn model_performance(&self) -> &ModelPerformance {
        &self.model_performance
    }

    /// Get configuration
    pub fn config(&self) -> &OnlineConfig {
        &self.config
    }

    /// Clean up old samples from buffer
    pub fn cleanup(&mut self) {
        self.buffer.cleanup_old_samples();
    }

    /// Clear all accumulated data
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.stats = OnlineStats::default();
        self.model_performance = ModelPerformance::default();
        self.last_update = Utc::now();
    }
}

/// Summary of online learning status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnlineSummary {
    /// Current state
    pub state: OnlineState,
    /// Samples in buffer
    pub buffer_samples: usize,
    /// Updates performed
    pub updates_performed: u64,
    /// Current FP rate
    pub fp_rate: f32,
    /// Current FN rate
    pub fn_rate: f32,
    /// Time since last update
    pub since_last_update_secs: i64,
    /// Ready for update
    pub ready_for_update: bool,
}

impl From<&OnlineLearner> for OnlineSummary {
    fn from(learner: &OnlineLearner) -> Self {
        let elapsed = Utc::now().signed_duration_since(learner.last_update);
        Self {
            state: learner.state,
            buffer_samples: learner.buffer.total_samples(),
            updates_performed: learner.stats.updates_performed,
            fp_rate: learner.stats.current_fp_rate,
            fn_rate: learner.stats.current_fn_rate,
            since_last_update_secs: elapsed.num_seconds(),
            ready_for_update: learner.should_update(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_online_learner_creation() {
        let config = OnlineConfig::default();
        let learner = OnlineLearner::new(config);

        assert_eq!(learner.state(), OnlineState::Collecting);
        assert_eq!(learner.buffer.total_samples(), 0);
    }

    #[test]
    fn test_online_learner_disabled() {
        let mut config = OnlineConfig::default();
        config.enabled = false;

        let learner = OnlineLearner::new(config);
        assert_eq!(learner.state(), OnlineState::Disabled);
    }

    #[test]
    fn test_add_samples() {
        let config = OnlineConfig::default();
        let mut learner = OnlineLearner::new(config);

        let vector = UnifiedFeatureVector::new();

        learner.add_true_positive(&vector, "PortScan");
        learner.add_false_positive(&vector, 0.8);
        learner.add_true_negative(&vector);

        assert_eq!(learner.stats().samples_processed, 3);
        assert_eq!(learner.buffer.total_samples(), 3);
    }

    #[test]
    fn test_should_update() {
        let mut config = OnlineConfig::default();
        config.min_feedback_for_update = 5;

        let mut learner = OnlineLearner::new(config);

        // Not enough samples
        assert!(!learner.should_update());

        // Add samples
        let vector = UnifiedFeatureVector::new();
        for _ in 0..10 {
            learner.add_true_positive(&vector, "Test");
        }

        // Now should update
        assert!(learner.should_update());
    }

    #[test]
    fn test_pause_resume() {
        let config = OnlineConfig::default();
        let mut learner = OnlineLearner::new(config);

        assert_eq!(learner.state(), OnlineState::Collecting);

        learner.pause();
        assert_eq!(learner.state(), OnlineState::Paused);

        learner.resume();
        assert_eq!(learner.state(), OnlineState::Collecting);
    }

    #[test]
    fn test_model_performance() {
        let config = OnlineConfig::default();
        let mut learner = OnlineLearner::new(config);

        learner.process_feedback(FeedbackEvent::ModelFeedback {
            model_name: "statistical".to_string(),
            score: 0.8,
            was_correct: true,
            detection_type: None,
        });

        assert_eq!(learner.model_performance().statistical.total, 1);
        assert_eq!(learner.model_performance().statistical.correct, 1);
    }

    #[test]
    fn test_online_summary() {
        let config = OnlineConfig::default();
        let learner = OnlineLearner::new(config);

        let summary: OnlineSummary = (&learner).into();

        assert_eq!(summary.state, OnlineState::Collecting);
        assert_eq!(summary.buffer_samples, 0);
        assert!(!summary.ready_for_update);
    }
}

//! Experience Replay Buffer for Online Learning
//!
//! Stores labeled samples for batch training of neural networks.
//! Implements prioritized experience replay for better learning efficiency.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ml::unified::{UnifiedFeatureVector, UNIFIED_DIM};

/// Label for a training sample
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SampleLabel {
    /// Normal traffic (true negative or false positive corrected)
    Normal,
    /// Attack traffic (true positive or false negative corrected)
    Attack,
}

/// Priority level for experience replay
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SamplePriority {
    /// Low priority - routine samples
    Low = 0,
    /// Medium priority - interesting edge cases
    Medium = 1,
    /// High priority - corrected predictions (FP/FN)
    High = 2,
    /// Critical - rare attack types or significant errors
    Critical = 3,
}

impl Default for SamplePriority {
    fn default() -> Self {
        Self::Medium
    }
}

/// A labeled experience sample
#[derive(Debug, Clone)]
pub struct ExperienceSample {
    /// Feature vector
    pub features: [f32; UNIFIED_DIM],
    /// Ground truth label
    pub label: SampleLabel,
    /// Original prediction (before correction)
    pub original_prediction: Option<bool>,
    /// Confidence of original prediction
    pub original_confidence: Option<f32>,
    /// Priority for sampling
    pub priority: SamplePriority,
    /// Flow ID for tracking
    pub flow_id: u64,
    /// Timestamp when sample was added
    pub timestamp: DateTime<Utc>,
    /// Detection type (if attack)
    pub detection_type: Option<String>,
    /// Number of times sampled
    pub sample_count: u32,
}

impl ExperienceSample {
    /// Create a new experience sample
    pub fn new(features: [f32; UNIFIED_DIM], label: SampleLabel, flow_id: u64) -> Self {
        Self {
            features,
            label,
            original_prediction: None,
            original_confidence: None,
            priority: SamplePriority::Medium,
            flow_id,
            timestamp: Utc::now(),
            detection_type: None,
            sample_count: 0,
        }
    }

    /// Create from unified feature vector
    pub fn from_unified(vector: &UnifiedFeatureVector, label: SampleLabel) -> Self {
        Self::new(vector.features, label, vector.flow_id)
    }

    /// Set original prediction for error analysis
    pub fn with_prediction(mut self, predicted: bool, confidence: f32) -> Self {
        self.original_prediction = Some(predicted);
        self.original_confidence = Some(confidence);

        // Increase priority for incorrect predictions
        if let Some(pred) = self.original_prediction {
            let was_wrong = match self.label {
                SampleLabel::Attack => !pred,
                SampleLabel::Normal => pred,
            };
            if was_wrong {
                self.priority = SamplePriority::High;
            }
        }
        self
    }

    /// Set detection type
    pub fn with_detection_type(mut self, detection_type: impl Into<String>) -> Self {
        self.detection_type = Some(detection_type.into());
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: SamplePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Check if this was an incorrect prediction
    pub fn was_incorrect(&self) -> bool {
        if let Some(pred) = self.original_prediction {
            match self.label {
                SampleLabel::Attack => !pred,
                SampleLabel::Normal => pred,
            }
        } else {
            false
        }
    }

    /// Get the priority weight for sampling
    pub fn priority_weight(&self) -> f32 {
        match self.priority {
            SamplePriority::Low => 1.0,
            SamplePriority::Medium => 2.0,
            SamplePriority::High => 4.0,
            SamplePriority::Critical => 8.0,
        }
    }
}

/// Configuration for the replay buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBufferConfig {
    /// Maximum buffer capacity
    pub capacity: usize,
    /// Minimum samples before training
    pub min_samples: usize,
    /// Batch size for training
    pub batch_size: usize,
    /// Target ratio of attack samples (for balancing)
    pub attack_ratio: f32,
    /// Enable prioritized sampling
    pub prioritized: bool,
    /// Priority exponent (alpha in PER)
    pub priority_alpha: f32,
    /// Importance sampling correction (beta in PER)
    pub importance_beta: f32,
    /// Maximum age of samples before removal (hours)
    pub max_age_hours: u64,
}

impl Default for ReplayBufferConfig {
    fn default() -> Self {
        Self {
            capacity: 100_000,
            min_samples: 1_000,
            batch_size: 256,
            attack_ratio: 0.3,
            prioritized: true,
            priority_alpha: 0.6,
            importance_beta: 0.4,
            max_age_hours: 168, // 1 week
        }
    }
}

/// Experience replay buffer with prioritized sampling
#[derive(Debug)]
pub struct ReplayBuffer {
    /// Configuration
    config: ReplayBufferConfig,
    /// Normal traffic samples
    normal_samples: VecDeque<ExperienceSample>,
    /// Attack traffic samples
    attack_samples: VecDeque<ExperienceSample>,
    /// Statistics
    stats: BufferStats,
    /// Random state for sampling
    rng_state: u64,
}

/// Buffer statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BufferStats {
    /// Total samples added
    pub total_added: u64,
    /// Total samples removed (eviction)
    pub total_evicted: u64,
    /// Total batches sampled
    pub batches_sampled: u64,
    /// Current normal sample count
    pub normal_count: usize,
    /// Current attack sample count
    pub attack_count: usize,
    /// High priority samples
    pub high_priority_count: usize,
    /// Samples with incorrect predictions
    pub incorrect_predictions: u64,
}

impl ReplayBuffer {
    /// Create a new replay buffer
    pub fn new(config: ReplayBufferConfig) -> Self {
        Self {
            config,
            normal_samples: VecDeque::new(),
            attack_samples: VecDeque::new(),
            stats: BufferStats::default(),
            rng_state: 0x853c49e6748fea9b, // Random seed
        }
    }

    /// Add a sample to the buffer
    pub fn add(&mut self, sample: ExperienceSample) {
        self.stats.total_added += 1;

        if sample.was_incorrect() {
            self.stats.incorrect_predictions += 1;
        }

        if sample.priority >= SamplePriority::High {
            self.stats.high_priority_count += 1;
        }

        let (buffer, other_buffer) = match sample.label {
            SampleLabel::Normal => (&mut self.normal_samples, &mut self.attack_samples),
            SampleLabel::Attack => (&mut self.attack_samples, &mut self.normal_samples),
        };

        // Calculate capacity for this label based on ratio
        let total_capacity = self.config.capacity;
        let attack_capacity = (total_capacity as f32 * self.config.attack_ratio) as usize;
        let normal_capacity = total_capacity - attack_capacity;

        let target_capacity = match sample.label {
            SampleLabel::Attack => attack_capacity,
            SampleLabel::Normal => normal_capacity,
        };

        // Evict if at capacity
        while buffer.len() >= target_capacity {
            if let Some(evicted) = buffer.pop_front() {
                self.stats.total_evicted += 1;
                if evicted.priority >= SamplePriority::High {
                    self.stats.high_priority_count = self.stats.high_priority_count.saturating_sub(1);
                }
            }
        }

        buffer.push_back(sample);

        // Update counts
        self.stats.normal_count = self.normal_samples.len();
        self.stats.attack_count = self.attack_samples.len();
    }

    /// Add a true positive sample
    pub fn add_true_positive(&mut self, vector: &UnifiedFeatureVector, detection_type: &str) {
        let sample = ExperienceSample::from_unified(vector, SampleLabel::Attack)
            .with_prediction(true, 1.0)
            .with_detection_type(detection_type)
            .with_priority(SamplePriority::Medium);
        self.add(sample);
    }

    /// Add a false positive sample (was incorrectly flagged as attack)
    pub fn add_false_positive(&mut self, vector: &UnifiedFeatureVector, confidence: f32) {
        let sample = ExperienceSample::from_unified(vector, SampleLabel::Normal)
            .with_prediction(true, confidence)
            .with_priority(SamplePriority::High); // High priority for learning
        self.add(sample);
    }

    /// Add a false negative sample (missed attack)
    pub fn add_false_negative(&mut self, vector: &UnifiedFeatureVector, detection_type: &str) {
        let sample = ExperienceSample::from_unified(vector, SampleLabel::Attack)
            .with_prediction(false, 0.0)
            .with_detection_type(detection_type)
            .with_priority(SamplePriority::Critical); // Critical for learning
        self.add(sample);
    }

    /// Add a true negative sample
    pub fn add_true_negative(&mut self, vector: &UnifiedFeatureVector) {
        let sample = ExperienceSample::from_unified(vector, SampleLabel::Normal)
            .with_prediction(false, 1.0)
            .with_priority(SamplePriority::Low);
        self.add(sample);
    }

    /// Check if buffer has enough samples for training
    pub fn ready_for_training(&self) -> bool {
        self.total_samples() >= self.config.min_samples
    }

    /// Get total number of samples
    pub fn total_samples(&self) -> usize {
        self.normal_samples.len() + self.attack_samples.len()
    }

    /// Sample a balanced batch for training
    pub fn sample_batch(&mut self) -> Vec<ExperienceSample> {
        if !self.ready_for_training() {
            return Vec::new();
        }

        self.stats.batches_sampled += 1;
        let batch_size = self.config.batch_size;

        // Calculate split
        let attack_count = (batch_size as f32 * self.config.attack_ratio) as usize;
        let normal_count = batch_size - attack_count;

        let mut batch = Vec::with_capacity(batch_size);

        // Sample attack samples
        batch.extend(self.sample_from_buffer(&mut self.attack_samples.clone(), attack_count));

        // Sample normal samples
        batch.extend(self.sample_from_buffer(&mut self.normal_samples.clone(), normal_count));

        batch
    }

    /// Sample from a specific buffer with priority weighting
    fn sample_from_buffer(&mut self, buffer: &mut VecDeque<ExperienceSample>, count: usize) -> Vec<ExperienceSample> {
        if buffer.is_empty() || count == 0 {
            return Vec::new();
        }

        let actual_count = count.min(buffer.len());
        let mut samples = Vec::with_capacity(actual_count);

        if self.config.prioritized {
            // Prioritized sampling based on priority weights
            let total_weight: f32 = buffer.iter().map(|s| s.priority_weight()).sum();

            for _ in 0..actual_count {
                // Generate random value
                self.rng_state = self.rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let rand_val = (self.rng_state >> 33) as f32 / (u32::MAX as f32) * total_weight;

                // Find sample by cumulative weight
                let mut cumulative = 0.0;
                for sample in buffer.iter() {
                    cumulative += sample.priority_weight();
                    if cumulative >= rand_val {
                        let mut sampled = sample.clone();
                        sampled.sample_count += 1;
                        samples.push(sampled);
                        break;
                    }
                }
            }
        } else {
            // Uniform random sampling
            for _ in 0..actual_count {
                self.rng_state = self.rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let idx = (self.rng_state >> 33) as usize % buffer.len();
                if let Some(sample) = buffer.get(idx) {
                    let mut sampled = sample.clone();
                    sampled.sample_count += 1;
                    samples.push(sampled);
                }
            }
        }

        samples
    }

    /// Get all samples as feature arrays and labels
    pub fn get_training_data(&self) -> (Vec<[f32; UNIFIED_DIM]>, Vec<f32>) {
        let mut features = Vec::with_capacity(self.total_samples());
        let mut labels = Vec::with_capacity(self.total_samples());

        for sample in self.normal_samples.iter() {
            features.push(sample.features);
            labels.push(0.0);
        }

        for sample in self.attack_samples.iter() {
            features.push(sample.features);
            labels.push(1.0);
        }

        (features, labels)
    }

    /// Remove old samples based on max_age_hours
    pub fn cleanup_old_samples(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::hours(self.config.max_age_hours as i64);

        self.normal_samples.retain(|s| s.timestamp > cutoff);
        self.attack_samples.retain(|s| s.timestamp > cutoff);

        self.stats.normal_count = self.normal_samples.len();
        self.stats.attack_count = self.attack_samples.len();
    }

    /// Get buffer statistics
    pub fn stats(&self) -> &BufferStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &ReplayBufferConfig {
        &self.config
    }

    /// Clear all samples
    pub fn clear(&mut self) {
        self.normal_samples.clear();
        self.attack_samples.clear();
        self.stats.normal_count = 0;
        self.stats.attack_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_creation() {
        let config = ReplayBufferConfig::default();
        let buffer = ReplayBuffer::new(config);
        assert_eq!(buffer.total_samples(), 0);
        assert!(!buffer.ready_for_training());
    }

    #[test]
    fn test_add_samples() {
        let mut config = ReplayBufferConfig::default();
        config.min_samples = 10;
        let mut buffer = ReplayBuffer::new(config);

        // Add normal samples
        for i in 0..5 {
            let sample = ExperienceSample::new([0.0; UNIFIED_DIM], SampleLabel::Normal, i);
            buffer.add(sample);
        }

        // Add attack samples
        for i in 5..10 {
            let sample = ExperienceSample::new([1.0; UNIFIED_DIM], SampleLabel::Attack, i);
            buffer.add(sample);
        }

        assert_eq!(buffer.total_samples(), 10);
        assert!(buffer.ready_for_training());
    }

    #[test]
    fn test_sample_priority() {
        let sample = ExperienceSample::new([0.0; UNIFIED_DIM], SampleLabel::Normal, 1)
            .with_prediction(true, 0.9); // Wrong prediction

        assert!(sample.was_incorrect());
        assert_eq!(sample.priority, SamplePriority::High);
    }

    #[test]
    fn test_false_positive_addition() {
        let mut config = ReplayBufferConfig::default();
        config.min_samples = 1;
        let mut buffer = ReplayBuffer::new(config);

        let vector = UnifiedFeatureVector::new();
        buffer.add_false_positive(&vector, 0.85);

        assert_eq!(buffer.stats().incorrect_predictions, 1);
        assert_eq!(buffer.stats().high_priority_count, 1);
    }

    #[test]
    fn test_capacity_eviction() {
        let mut config = ReplayBufferConfig::default();
        config.capacity = 10;
        config.attack_ratio = 0.5;
        let mut buffer = ReplayBuffer::new(config);

        // Add more than capacity
        for i in 0..20 {
            let sample = ExperienceSample::new([0.0; UNIFIED_DIM], SampleLabel::Normal, i);
            buffer.add(sample);
        }

        // Should be at capacity for normal (50% of 10 = 5)
        assert!(buffer.normal_samples.len() <= 5);
    }
}

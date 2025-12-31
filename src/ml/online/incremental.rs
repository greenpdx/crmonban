//! Incremental Update Strategies for Online Learning
//!
//! Provides different update strategies for adapting models to new data
//! without full retraining.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ml::unified::UNIFIED_DIM;
use crate::ml::baseline::Baseline;

/// Update strategy type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateStrategy {
    /// Exponential Moving Average for statistics
    EMA,
    /// Sliding window for bounded memory
    SlidingWindow,
    /// Mini-batch gradient descent for neural networks
    MiniBatch,
    /// Add new trees, retire oldest for forests
    TreeRotation,
    /// Reservoir sampling for bounded storage
    ReservoirSampling,
}

/// Configuration for incremental updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalConfig {
    /// Update interval in seconds
    pub update_interval_secs: u64,
    /// EMA decay factor (0-1, lower = faster adaptation)
    pub ema_alpha: f32,
    /// Sliding window size
    pub window_size: usize,
    /// Mini-batch size for neural network updates
    pub mini_batch_size: usize,
    /// Learning rate for gradient updates
    pub learning_rate: f32,
    /// Number of trees to rotate per update
    pub trees_per_rotation: usize,
    /// Reservoir sample size
    pub reservoir_size: usize,
    /// Enable automatic strategy selection
    pub auto_select: bool,
}

impl Default for IncrementalConfig {
    fn default() -> Self {
        Self {
            update_interval_secs: 3600, // 1 hour
            ema_alpha: 0.1,
            window_size: 10_000,
            mini_batch_size: 256,
            learning_rate: 0.001,
            trees_per_rotation: 10,
            reservoir_size: 50_000,
            auto_select: true,
        }
    }
}

/// Exponential Moving Average updater for feature statistics
#[derive(Debug, Clone)]
pub struct EMAUpdater {
    /// Decay factor
    alpha: f32,
    /// Current means
    means: [f32; UNIFIED_DIM],
    /// Current variances
    variances: [f32; UNIFIED_DIM],
    /// Sample count
    count: u64,
    /// Initialized flag
    initialized: bool,
}

impl EMAUpdater {
    /// Create a new EMA updater
    pub fn new(alpha: f32) -> Self {
        Self {
            alpha: alpha.clamp(0.001, 1.0),
            means: [0.0; UNIFIED_DIM],
            variances: [1.0; UNIFIED_DIM],
            count: 0,
            initialized: false,
        }
    }

    /// Initialize from baseline
    pub fn from_baseline(baseline: &Baseline, alpha: f32) -> Self {
        let mut updater = Self::new(alpha);

        // Copy baseline stats
        for (i, stat) in baseline.global_stats.iter().enumerate() {
            if i < UNIFIED_DIM {
                updater.means[i] = stat.mean as f32;
                updater.variances[i] = (stat.variance() as f32).max(1e-6);
            }
        }
        updater.initialized = true;
        updater.count = baseline.total_samples;

        updater
    }

    /// Update with a new sample
    pub fn update(&mut self, features: &[f32; UNIFIED_DIM]) {
        self.count += 1;

        if !self.initialized {
            // First sample - initialize
            self.means = *features;
            self.variances = [1.0; UNIFIED_DIM];
            self.initialized = true;
            return;
        }

        // EMA update for mean and variance
        for i in 0..UNIFIED_DIM {
            let old_mean = self.means[i];
            let delta = features[i] - old_mean;

            // Update mean: new_mean = (1 - alpha) * old_mean + alpha * new_value
            self.means[i] = (1.0 - self.alpha) * old_mean + self.alpha * features[i];

            // Update variance using Welford-like EMA
            let delta2 = features[i] - self.means[i];
            self.variances[i] = (1.0 - self.alpha) * self.variances[i] + self.alpha * delta * delta2;
            self.variances[i] = self.variances[i].max(1e-6);
        }
    }

    /// Update with a batch of samples
    pub fn update_batch(&mut self, batch: &[[f32; UNIFIED_DIM]]) {
        for features in batch {
            self.update(features);
        }
    }

    /// Get current means
    pub fn means(&self) -> &[f32; UNIFIED_DIM] {
        &self.means
    }

    /// Get current variances
    pub fn variances(&self) -> &[f32; UNIFIED_DIM] {
        &self.variances
    }

    /// Get standard deviations
    pub fn stds(&self) -> [f32; UNIFIED_DIM] {
        let mut stds = [0.0; UNIFIED_DIM];
        for i in 0..UNIFIED_DIM {
            stds[i] = self.variances[i].sqrt();
        }
        stds
    }

    /// Compute z-score for a sample
    pub fn zscore(&self, features: &[f32; UNIFIED_DIM]) -> [f32; UNIFIED_DIM] {
        let mut zscores = [0.0; UNIFIED_DIM];
        for i in 0..UNIFIED_DIM {
            let std = self.variances[i].sqrt().max(1e-6);
            zscores[i] = (features[i] - self.means[i]) / std;
        }
        zscores
    }

    /// Get sample count
    pub fn count(&self) -> u64 {
        self.count
    }
}

/// Sliding window for bounded memory statistics
#[derive(Debug)]
pub struct SlidingWindow {
    /// Window size
    capacity: usize,
    /// Samples in window
    samples: VecDeque<[f32; UNIFIED_DIM]>,
    /// Running sums for means
    sums: [f64; UNIFIED_DIM],
    /// Running squared sums for variance
    sq_sums: [f64; UNIFIED_DIM],
}

impl SlidingWindow {
    /// Create a new sliding window
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            samples: VecDeque::with_capacity(capacity),
            sums: [0.0; UNIFIED_DIM],
            sq_sums: [0.0; UNIFIED_DIM],
        }
    }

    /// Add a sample to the window
    pub fn add(&mut self, features: [f32; UNIFIED_DIM]) {
        // Remove oldest if at capacity
        if self.samples.len() >= self.capacity {
            if let Some(old) = self.samples.pop_front() {
                for i in 0..UNIFIED_DIM {
                    self.sums[i] -= old[i] as f64;
                    self.sq_sums[i] -= (old[i] as f64).powi(2);
                }
            }
        }

        // Add new sample
        for i in 0..UNIFIED_DIM {
            self.sums[i] += features[i] as f64;
            self.sq_sums[i] += (features[i] as f64).powi(2);
        }
        self.samples.push_back(features);
    }

    /// Get current means
    pub fn means(&self) -> [f32; UNIFIED_DIM] {
        let n = self.samples.len() as f64;
        if n == 0.0 {
            return [0.0; UNIFIED_DIM];
        }

        let mut means = [0.0f32; UNIFIED_DIM];
        for i in 0..UNIFIED_DIM {
            means[i] = (self.sums[i] / n) as f32;
        }
        means
    }

    /// Get current variances
    pub fn variances(&self) -> [f32; UNIFIED_DIM] {
        let n = self.samples.len() as f64;
        if n < 2.0 {
            return [1.0; UNIFIED_DIM];
        }

        let mut vars = [0.0f32; UNIFIED_DIM];
        for i in 0..UNIFIED_DIM {
            let mean = self.sums[i] / n;
            vars[i] = ((self.sq_sums[i] / n - mean.powi(2)) as f32).max(1e-6);
        }
        vars
    }

    /// Get sample count in window
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Check if window is empty
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Check if window is full
    pub fn is_full(&self) -> bool {
        self.samples.len() >= self.capacity
    }

    /// Clear the window
    pub fn clear(&mut self) {
        self.samples.clear();
        self.sums = [0.0; UNIFIED_DIM];
        self.sq_sums = [0.0; UNIFIED_DIM];
    }
}

/// Reservoir sampler for bounded random sampling
#[derive(Debug)]
pub struct ReservoirSampler {
    /// Reservoir capacity
    capacity: usize,
    /// Stored samples
    samples: Vec<[f32; UNIFIED_DIM]>,
    /// Total samples seen
    total_seen: u64,
    /// Random state
    rng_state: u64,
}

impl ReservoirSampler {
    /// Create a new reservoir sampler
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            samples: Vec::with_capacity(capacity),
            total_seen: 0,
            rng_state: 0xdeadbeef12345678,
        }
    }

    /// Add a sample (may be dropped if reservoir full and not selected)
    pub fn add(&mut self, features: [f32; UNIFIED_DIM]) {
        self.total_seen += 1;

        if self.samples.len() < self.capacity {
            self.samples.push(features);
        } else {
            // Reservoir sampling: replace with probability k/n
            self.rng_state = self.rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let rand_idx = (self.rng_state >> 33) as u64 % self.total_seen;

            if (rand_idx as usize) < self.capacity {
                self.samples[rand_idx as usize] = features;
            }
        }
    }

    /// Get all samples
    pub fn samples(&self) -> &[[f32; UNIFIED_DIM]] {
        &self.samples
    }

    /// Get sample count
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Get total samples seen
    pub fn total_seen(&self) -> u64 {
        self.total_seen
    }
}

/// Tree rotation updater for isolation forests
#[derive(Debug)]
pub struct TreeRotator {
    /// Number of trees to rotate per update
    trees_per_update: usize,
    /// Current rotation index
    rotation_idx: usize,
    /// Sample buffer for new trees
    sample_buffer: Vec<[f32; UNIFIED_DIM]>,
    /// Buffer capacity
    buffer_capacity: usize,
    /// Last rotation time
    last_rotation: DateTime<Utc>,
}

impl TreeRotator {
    /// Create a new tree rotator
    pub fn new(trees_per_update: usize, buffer_capacity: usize) -> Self {
        Self {
            trees_per_update,
            rotation_idx: 0,
            sample_buffer: Vec::with_capacity(buffer_capacity),
            buffer_capacity,
            last_rotation: Utc::now(),
        }
    }

    /// Add samples to buffer
    pub fn add_samples(&mut self, samples: &[[f32; UNIFIED_DIM]]) {
        for sample in samples {
            if self.sample_buffer.len() < self.buffer_capacity {
                self.sample_buffer.push(*sample);
            } else {
                // Replace random sample
                let idx = (self.rotation_idx * 31337) % self.buffer_capacity;
                self.sample_buffer[idx] = *sample;
                self.rotation_idx = self.rotation_idx.wrapping_add(1);
            }
        }
    }

    /// Check if ready for rotation
    pub fn ready_for_rotation(&self, min_samples: usize) -> bool {
        self.sample_buffer.len() >= min_samples
    }

    /// Get samples for new tree training
    pub fn get_training_samples(&self) -> &[[f32; UNIFIED_DIM]] {
        &self.sample_buffer
    }

    /// Clear buffer after rotation
    pub fn clear_buffer(&mut self) {
        self.sample_buffer.clear();
        self.last_rotation = Utc::now();
    }

    /// Get trees per update
    pub fn trees_per_update(&self) -> usize {
        self.trees_per_update
    }
}

/// Incremental update coordinator
#[derive(Debug)]
pub struct IncrementalUpdater {
    /// Configuration
    config: IncrementalConfig,
    /// EMA updater for statistics
    ema: EMAUpdater,
    /// Sliding window
    window: SlidingWindow,
    /// Reservoir sampler
    reservoir: ReservoirSampler,
    /// Tree rotator
    tree_rotator: TreeRotator,
    /// Last update time
    last_update: DateTime<Utc>,
    /// Update count
    update_count: u64,
}

impl IncrementalUpdater {
    /// Create a new incremental updater
    pub fn new(config: IncrementalConfig) -> Self {
        let ema = EMAUpdater::new(config.ema_alpha);
        let window = SlidingWindow::new(config.window_size);
        let reservoir = ReservoirSampler::new(config.reservoir_size);
        let tree_rotator = TreeRotator::new(config.trees_per_rotation, config.window_size);

        Self {
            config,
            ema,
            window,
            reservoir,
            tree_rotator,
            last_update: Utc::now(),
            update_count: 0,
        }
    }

    /// Initialize from baseline
    pub fn with_baseline(mut self, baseline: &Baseline) -> Self {
        self.ema = EMAUpdater::from_baseline(baseline, self.config.ema_alpha);
        self
    }

    /// Process a new sample
    pub fn process(&mut self, features: &[f32; UNIFIED_DIM]) {
        self.ema.update(features);
        self.window.add(*features);
        self.reservoir.add(*features);
        self.tree_rotator.add_samples(&[*features]);
    }

    /// Process a batch of samples
    pub fn process_batch(&mut self, batch: &[[f32; UNIFIED_DIM]]) {
        for features in batch {
            self.process(features);
        }
    }

    /// Check if update interval has passed
    pub fn should_update(&self) -> bool {
        let elapsed = Utc::now().signed_duration_since(self.last_update);
        elapsed.num_seconds() >= self.config.update_interval_secs as i64
    }

    /// Apply updates and return updated statistics
    pub fn apply_updates(&mut self) -> UpdateResult {
        self.update_count += 1;
        self.last_update = Utc::now();

        UpdateResult {
            ema_means: self.ema.means().clone(),
            ema_stds: self.ema.stds(),
            window_means: self.window.means(),
            window_vars: self.window.variances(),
            samples_processed: self.ema.count(),
            update_count: self.update_count,
        }
    }

    /// Get EMA statistics
    pub fn ema_stats(&self) -> (&[f32; UNIFIED_DIM], [f32; UNIFIED_DIM]) {
        (self.ema.means(), self.ema.stds())
    }

    /// Get window statistics
    pub fn window_stats(&self) -> ([f32; UNIFIED_DIM], [f32; UNIFIED_DIM]) {
        (self.window.means(), self.window.variances())
    }

    /// Get configuration
    pub fn config(&self) -> &IncrementalConfig {
        &self.config
    }

    /// Get update count
    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    /// Check if tree rotation is ready
    pub fn tree_rotation_ready(&self) -> bool {
        self.tree_rotator.ready_for_rotation(self.config.mini_batch_size)
    }

    /// Get samples for tree rotation
    pub fn tree_rotation_samples(&self) -> &[[f32; UNIFIED_DIM]] {
        self.tree_rotator.get_training_samples()
    }

    /// Complete tree rotation
    pub fn complete_tree_rotation(&mut self) {
        self.tree_rotator.clear_buffer();
    }
}

/// Result of applying updates
#[derive(Debug, Clone)]
pub struct UpdateResult {
    /// EMA means
    pub ema_means: [f32; UNIFIED_DIM],
    /// EMA standard deviations
    pub ema_stds: [f32; UNIFIED_DIM],
    /// Window means
    pub window_means: [f32; UNIFIED_DIM],
    /// Window variances
    pub window_vars: [f32; UNIFIED_DIM],
    /// Total samples processed
    pub samples_processed: u64,
    /// Update count
    pub update_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ema_updater() {
        let mut ema = EMAUpdater::new(0.1);

        // First sample initializes
        let mut sample = [0.0f32; UNIFIED_DIM];
        sample[0] = 1.0;
        ema.update(&sample);

        assert!(ema.initialized);
        assert!((ema.means()[0] - 1.0).abs() < 0.001);

        // Second sample updates
        sample[0] = 2.0;
        ema.update(&sample);

        // Mean should move towards 2.0
        assert!(ema.means()[0] > 1.0);
        assert!(ema.means()[0] < 2.0);
    }

    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new(5);

        for i in 0..10 {
            let mut sample = [0.0f32; UNIFIED_DIM];
            sample[0] = i as f32;
            window.add(sample);
        }

        // Should only have last 5 samples (5, 6, 7, 8, 9)
        assert_eq!(window.len(), 5);

        // Mean should be (5+6+7+8+9)/5 = 7.0
        let means = window.means();
        assert!((means[0] - 7.0).abs() < 0.001);
    }

    #[test]
    fn test_reservoir_sampler() {
        let mut reservoir = ReservoirSampler::new(10);

        for i in 0..100 {
            let mut sample = [0.0f32; UNIFIED_DIM];
            sample[0] = i as f32;
            reservoir.add(sample);
        }

        // Should have exactly 10 samples
        assert_eq!(reservoir.len(), 10);
        assert_eq!(reservoir.total_seen(), 100);
    }

    #[test]
    fn test_incremental_updater() {
        let config = IncrementalConfig::default();
        let mut updater = IncrementalUpdater::new(config);

        for i in 0..100 {
            let mut sample = [0.0f32; UNIFIED_DIM];
            sample[0] = (i % 10) as f32;
            updater.process(&sample);
        }

        let (means, _stds) = updater.ema_stats();
        assert!(means[0] > 0.0);
    }
}

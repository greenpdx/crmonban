//! Machine Learning / Anomaly Detection Engine
//!
//! Provides ML-based anomaly detection for network traffic analysis.
//!
//! # Features
//! - Feature extraction from network flows (CICIDS2017-compatible)
//! - Baseline learning for normal traffic patterns
//! - Multiple anomaly detection methods (statistical, isolation forest)
//! - Automatic training and model persistence
//!
//! # Example
//! ```ignore
//! use crmonban::ml::{MLEngine, MLConfig};
//!
//! let config = MLConfig::default();
//! let mut engine = MLEngine::new(config);
//!
//! // During learning phase
//! engine.learn_from_flow(&flow);
//!
//! // After training
//! let score = engine.score(&flow);
//! if score.is_anomaly(0.7) {
//!     println!("Anomaly detected: {}", score.explanation.unwrap_or_default());
//! }
//! ```

pub mod features;
pub mod baseline;
pub mod anomaly;
pub mod models;
pub mod training;
pub mod storage;

use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::core::flow::Flow;

pub use features::{FeatureVector, FeatureExtractor, NUM_FEATURES, FEATURE_NAMES};
pub use baseline::{Baseline, FeatureStats, BaselineSummary};
pub use anomaly::{AnomalyScore, AnomalyCategory, AnomalyDetector};
pub use models::{AnomalyModel, ModelConfig, IsolationForest, StatisticalModel};
pub use training::{TrainingData, TrainedModel, ModelTrainer, TrainingProgress, TrainingPhase};
pub use storage::{MLStorage, MLStorageConfig, MLDataMetadata, ML_DATA_DIR};

/// ML Engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLConfig {
    /// Enable ML detection
    pub enabled: bool,
    /// Path to save/load models
    pub model_path: Option<PathBuf>,

    /// Baseline configuration
    pub baseline: BaselineConfig,
    /// Detection configuration
    pub detection: DetectionConfig,
    /// Feature configuration
    pub features: FeatureConfig,
    /// Model configuration
    pub model: ModelConfig,
}

impl Default for MLConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_path: None,
            baseline: BaselineConfig::default(),
            detection: DetectionConfig::default(),
            features: FeatureConfig::default(),
            model: ModelConfig::default(),
        }
    }
}

/// Baseline learning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    /// Enable baseline learning
    pub enabled: bool,
    /// Minimum samples before training
    pub min_samples: u64,
    /// Learning period duration
    pub learning_period: Duration,
    /// Baseline update interval
    pub update_interval: Duration,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_samples: 10_000,
            learning_period: Duration::from_secs(7 * 24 * 60 * 60), // 1 week
            update_interval: Duration::from_secs(24 * 60 * 60),     // 1 day
        }
    }
}

/// Detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Anomaly score threshold (0.0-1.0)
    pub anomaly_threshold: f32,
    /// Minimum confidence to report
    pub min_confidence: f32,
    /// Alert on unknown anomaly categories
    pub alert_on_unknown: bool,
    /// Z-score threshold for statistical methods
    pub zscore_threshold: f32,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            anomaly_threshold: 0.7,
            min_confidence: 0.6,
            alert_on_unknown: false,
            zscore_threshold: 3.0,
        }
    }
}

/// Feature extraction configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// Use timing features
    pub use_timing: bool,
    /// Use packet size features
    pub use_packet_sizes: bool,
    /// Use TCP flag features
    pub use_tcp_flags: bool,
    /// Use connection statistics
    pub use_connection_stats: bool,
    /// Connection window duration
    pub window_duration: Duration,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            use_timing: true,
            use_packet_sizes: true,
            use_tcp_flags: true,
            use_connection_stats: true,
            window_duration: Duration::from_secs(120),
        }
    }
}

/// ML Engine state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MLState {
    /// Collecting training data
    Learning,
    /// Training models
    Training,
    /// Actively detecting anomalies
    Detecting,
    /// Engine is disabled
    Disabled,
}

/// Main ML Engine
pub struct MLEngine {
    /// Configuration
    config: MLConfig,
    /// Current state
    state: MLState,
    /// Feature extractor
    feature_extractor: FeatureExtractor,
    /// Anomaly detector
    anomaly_detector: AnomalyDetector,
    /// Training data (during learning phase)
    training_data: Option<TrainingData>,
    /// Trained model
    trained_model: Option<TrainedModel>,
    /// Training progress
    progress: TrainingProgress,
    /// When learning started
    learning_started: DateTime<Utc>,
    /// Statistics
    stats: MLStats,
}

/// ML Engine statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct MLStats {
    pub flows_processed: u64,
    pub anomalies_detected: u64,
    pub learning_samples: u64,
    pub false_positives_reported: u64,
}

impl MLEngine {
    /// Create a new ML engine
    pub fn new(config: MLConfig) -> Self {
        let state = if config.enabled {
            MLState::Learning
        } else {
            MLState::Disabled
        };

        let feature_extractor = FeatureExtractor::with_window(
            config.features.window_duration,
            10_000,
        );

        let anomaly_detector = AnomalyDetector::with_thresholds(
            config.detection.zscore_threshold,
            1.5,
        );

        let progress = TrainingProgress::new(config.baseline.min_samples);

        Self {
            config,
            state,
            feature_extractor,
            anomaly_detector,
            training_data: Some(TrainingData::new(100_000)),
            trained_model: None,
            progress,
            learning_started: Utc::now(),
            stats: MLStats::default(),
        }
    }

    /// Load existing model if available
    pub fn load_model(&mut self) -> anyhow::Result<bool> {
        if let Some(ref path) = self.config.model_path {
            if path.exists() {
                let model = TrainedModel::load(path)?;
                info!("Loaded ML model from {:?} ({} samples)", path, model.sample_count);
                self.trained_model = Some(model);
                self.state = MLState::Detecting;
                self.progress.complete();
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Save current model
    pub fn save_model(&self) -> anyhow::Result<()> {
        if let (Some(path), Some(model)) = (&self.config.model_path, &self.trained_model) {
            model.save(path)?;
            info!("Saved ML model to {:?}", path);
        }
        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> MLState {
        self.state
    }

    /// Check if in learning mode
    pub fn is_learning(&self) -> bool {
        self.state == MLState::Learning
    }

    /// Check if ready for detection
    pub fn is_detecting(&self) -> bool {
        self.state == MLState::Detecting
    }

    /// Process a flow and learn/detect
    pub fn process_flow(&mut self, flow: &Flow) -> Option<AnomalyScore> {
        if self.state == MLState::Disabled {
            return None;
        }

        self.stats.flows_processed += 1;

        // Extract features
        let features = self.feature_extractor.extract(flow);

        match self.state {
            MLState::Learning => {
                self.learn_from_features(features);
                None
            }
            MLState::Training => {
                // During training, don't process new flows
                None
            }
            MLState::Detecting => {
                self.detect_anomaly(&features)
            }
            MLState::Disabled => None,
        }
    }

    /// Learn from features during training phase
    fn learn_from_features(&mut self, features: FeatureVector) {
        if let Some(ref mut data) = self.training_data {
            data.add(features);
            self.stats.learning_samples = data.len() as u64;
            self.progress.update(data.len() as u64);

            // Check if ready to train
            if data.len() as u64 >= self.config.baseline.min_samples {
                debug!("Collected {} samples, starting training", data.len());
                self.start_training();
            }
        }
    }

    /// Start model training
    fn start_training(&mut self) {
        self.state = MLState::Training;
        self.progress.phase = TrainingPhase::Training;

        if let Some(ref data) = self.training_data {
            let trainer = ModelTrainer::new(self.config.model.clone());
            let model = trainer.train(data);

            info!(
                "ML training complete: {} samples, baseline ready",
                model.sample_count
            );

            self.trained_model = Some(model);
            self.training_data = None; // Free memory
            self.state = MLState::Detecting;
            self.progress.complete();

            // Save model
            if let Err(e) = self.save_model() {
                warn!("Failed to save ML model: {}", e);
            }
        }
    }

    /// Detect anomaly in features
    fn detect_anomaly(&mut self, features: &FeatureVector) -> Option<AnomalyScore> {
        let model = self.trained_model.as_ref()?;

        // Score using anomaly detector with baseline
        let mut score = self.anomaly_detector.score(features, &model.baseline);

        // Also score with isolation forest if available
        if let Some(ref forest) = model.isolation_forest {
            let forest_score = forest.score(features);
            // Combine scores (weighted average)
            score.score = score.score * 0.6 + forest_score * 0.4;
        }

        // Check threshold
        if score.is_anomaly(self.config.detection.anomaly_threshold) {
            self.stats.anomalies_detected += 1;

            // Filter out unknown if configured
            if !self.config.detection.alert_on_unknown
                && score.category == Some(AnomalyCategory::Unknown)
            {
                return None;
            }

            // Check confidence threshold
            if score.confidence >= self.config.detection.min_confidence {
                return Some(score);
            }
        }

        None
    }

    /// Force training with current data
    pub fn force_train(&mut self) {
        if self.state == MLState::Learning {
            self.start_training();
        }
    }

    /// Reset to learning state
    pub fn reset(&mut self) {
        self.state = if self.config.enabled {
            MLState::Learning
        } else {
            MLState::Disabled
        };
        self.training_data = Some(TrainingData::new(100_000));
        self.trained_model = None;
        self.progress = TrainingProgress::new(self.config.baseline.min_samples);
        self.learning_started = Utc::now();
        self.stats = MLStats::default();
        self.feature_extractor.clear_window();
    }

    /// Get training progress
    pub fn progress(&self) -> &TrainingProgress {
        &self.progress
    }

    /// Get statistics
    pub fn stats(&self) -> &MLStats {
        &self.stats
    }

    /// Get baseline summary (if trained)
    pub fn baseline_summary(&self) -> Option<BaselineSummary> {
        self.trained_model.as_ref().map(|m| m.baseline.summary())
    }

    /// Manually update baseline with normal traffic
    pub fn update_baseline(&mut self, flow: &Flow) {
        if let Some(ref mut model) = self.trained_model {
            let features = self.feature_extractor.extract(flow);
            model.baseline.update(&features);
        }
    }

    /// Report false positive (for feedback learning)
    pub fn report_false_positive(&mut self, _flow_id: u64) {
        self.stats.false_positives_reported += 1;
        // Future: could adjust model based on this feedback
    }

    /// Get configuration
    pub fn config(&self) -> &MLConfig {
        &self.config
    }
}

impl Default for MLEngine {
    fn default() -> Self {
        Self::new(MLConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::core::packet::{Packet, IpProtocol};

    fn make_test_flow(id: u64) -> Flow {
        let mut pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
        );
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = 54321;
            tcp.dst_port = 80;
        }
        pkt.raw_len = 100;

        let mut flow = Flow::new(id, &pkt);
        flow.fwd_bytes = 1000;
        flow.bwd_bytes = 5000;
        flow.fwd_packets = 10;
        flow.bwd_packets = 20;
        flow
    }

    #[test]
    fn test_ml_engine_creation() {
        let engine = MLEngine::default();
        assert!(engine.is_learning());
        assert!(!engine.is_detecting());
    }

    #[test]
    fn test_ml_engine_disabled() {
        let mut config = MLConfig::default();
        config.enabled = false;

        let engine = MLEngine::new(config);
        assert_eq!(engine.state(), MLState::Disabled);
    }

    #[test]
    fn test_ml_engine_learning() {
        let mut config = MLConfig::default();
        config.baseline.min_samples = 10; // Low threshold for testing

        let mut engine = MLEngine::new(config);

        // Process flows
        for i in 0..15 {
            let flow = make_test_flow(i);
            engine.process_flow(&flow);
        }

        // Should have trained
        assert!(engine.is_detecting());
    }

    #[test]
    fn test_ml_config_defaults() {
        let config = MLConfig::default();
        assert!(config.enabled);
        assert_eq!(config.detection.anomaly_threshold, 0.7);
        assert_eq!(config.baseline.min_samples, 10_000);
    }

    #[test]
    fn test_ml_stats() {
        let mut engine = MLEngine::default();

        for i in 0..5 {
            let flow = make_test_flow(i);
            engine.process_flow(&flow);
        }

        assert_eq!(engine.stats().flows_processed, 5);
        assert_eq!(engine.stats().learning_samples, 5);
    }
}

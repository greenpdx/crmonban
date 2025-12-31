//! Temporal Sequence Analysis
//!
//! Provides per-IP sequence tracking and LSTM-based temporal anomaly detection.
//! Detects attack patterns that unfold over time, such as:
//! - Gradual reconnaissance
//! - Slow brute force attacks
//! - Multi-stage exploits
//! - C2 beaconing patterns
//!
//! # Architecture
//! ```text
//! Per-IP Sequences -> LSTM Network -> Prediction Error -> Anomaly Score
//! ```
//!
//! # Usage
//! ```ignore
//! use crmonban::ml::models::temporal::{SequenceManager, TemporalDetector, WindowConfig};
//!
//! let config = WindowConfig::default();
//! let mut manager = SequenceManager::new(config);
//! let mut detector = TemporalDetector::new();
//!
//! // Add features as they arrive
//! manager.add(src_ip, &features);
//!
//! // Check for temporal anomalies
//! if manager.is_ready(&src_ip) {
//!     if let Some(seq) = manager.get_sequence(&src_ip) {
//!         let score = detector.score(&seq);
//!     }
//! }
//! ```

pub mod window;
pub mod lstm;

pub use window::{SequenceManager, WindowConfig, ManagerStats};
pub use lstm::{LstmDetector, LstmConfig, TemporalModel};

use std::net::IpAddr;
use serde::{Deserialize, Serialize};

use crate::ml::unified::{UnifiedFeatureVector, UNIFIED_DIM};

/// Combined temporal anomaly detector
/// Manages both sequence collection and anomaly scoring
#[derive(Debug)]
pub struct TemporalDetector {
    /// Sequence manager
    manager: SequenceManager,
    /// LSTM detector
    lstm: LstmDetector,
    /// Detection configuration
    config: TemporalConfig,
    /// Statistics
    stats: TemporalStats,
}

/// Temporal detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalConfig {
    /// Window configuration
    pub window: WindowConfig,
    /// LSTM configuration
    pub lstm: LstmConfig,
    /// Anomaly score threshold
    pub threshold: f32,
    /// Minimum sequences for training
    pub min_training_sequences: usize,
}

impl Default for TemporalConfig {
    fn default() -> Self {
        Self {
            window: WindowConfig::default(),
            lstm: LstmConfig::default(),
            threshold: 0.5,
            min_training_sequences: 100,
        }
    }
}

/// Temporal detection statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemporalStats {
    /// Features processed
    pub features_processed: u64,
    /// Sequences analyzed
    pub sequences_analyzed: u64,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// IPs flagged as anomalous
    pub ips_flagged: u64,
}

/// Result of temporal analysis
#[derive(Debug, Clone)]
pub struct TemporalResult {
    /// Source IP
    pub ip: IpAddr,
    /// Anomaly score
    pub score: f32,
    /// Is anomalous
    pub is_anomaly: bool,
    /// Sequence length used
    pub sequence_length: usize,
    /// Explanation
    pub explanation: Option<String>,
}

impl TemporalDetector {
    /// Create a new temporal detector with default configuration
    pub fn new() -> Self {
        Self::with_config(TemporalConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: TemporalConfig) -> Self {
        let manager = SequenceManager::new(config.window.clone());
        let lstm = LstmDetector::new(config.lstm.clone())
            .with_threshold(config.threshold);

        Self {
            manager,
            lstm,
            config,
            stats: TemporalStats::default(),
        }
    }

    /// Process a new feature vector for an IP
    pub fn process(&mut self, ip: IpAddr, vector: &UnifiedFeatureVector) {
        self.stats.features_processed += 1;
        self.manager.add(ip, vector);
    }

    /// Analyze temporal patterns for an IP
    pub fn analyze(&mut self, ip: &IpAddr) -> Option<TemporalResult> {
        // Get sequence if ready
        let sequence = self.manager.get_sequence(ip)?;
        self.stats.sequences_analyzed += 1;

        // Score the sequence
        let score = self.lstm.score(&sequence);
        let is_anomaly = self.lstm.is_anomaly(score);

        if is_anomaly {
            self.stats.anomalies_detected += 1;
        }

        // Generate explanation
        let explanation = if is_anomaly {
            Some(format!(
                "Temporal anomaly: score={:.3} (threshold={:.3}), {} samples",
                score,
                self.lstm.current_threshold(),
                sequence.len()
            ))
        } else {
            None
        };

        Some(TemporalResult {
            ip: *ip,
            score,
            is_anomaly,
            sequence_length: sequence.len(),
            explanation,
        })
    }

    /// Analyze all ready IPs
    pub fn analyze_all(&mut self) -> Vec<TemporalResult> {
        let ips = self.manager.ready_ips();
        ips.iter()
            .filter_map(|ip| self.analyze(ip))
            .collect()
    }

    /// Get anomalous IPs
    pub fn anomalous_ips(&mut self) -> Vec<TemporalResult> {
        self.analyze_all()
            .into_iter()
            .filter(|r| r.is_anomaly)
            .collect()
    }

    /// Train the LSTM on normal sequences
    pub fn train(&mut self) {
        let sequences: Vec<Vec<[f32; UNIFIED_DIM]>> = self
            .manager
            .ready_ips()
            .iter()
            .filter_map(|ip| self.manager.get_sequence(ip))
            .collect();

        if sequences.len() >= self.config.min_training_sequences {
            self.lstm.fit(&sequences);
        }
    }

    /// Check if LSTM is trained
    pub fn is_trained(&self) -> bool {
        self.lstm.is_trained()
    }

    /// Get sequence manager reference
    pub fn manager(&self) -> &SequenceManager {
        &self.manager
    }

    /// Get mutable sequence manager reference
    pub fn manager_mut(&mut self) -> &mut SequenceManager {
        &mut self.manager
    }

    /// Get statistics
    pub fn stats(&self) -> &TemporalStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &TemporalConfig {
        &self.config
    }

    /// Cleanup expired sequences
    pub fn cleanup(&mut self) {
        self.manager.cleanup();
    }

    /// Clear all state
    pub fn clear(&mut self) {
        self.manager.clear();
        self.stats = TemporalStats::default();
    }
}

impl Default for TemporalDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_vector(value: f32) -> UnifiedFeatureVector {
        UnifiedFeatureVector {
            features: [value; UNIFIED_DIM],
            ..Default::default()
        }
    }

    #[test]
    fn test_temporal_detector_creation() {
        let detector = TemporalDetector::new();
        assert!(!detector.is_trained());
    }

    #[test]
    fn test_process_and_analyze() {
        let config = TemporalConfig {
            window: WindowConfig {
                min_sequence_length: 3,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut detector = TemporalDetector::with_config(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Add features
        for i in 0..5 {
            detector.process(ip, &make_test_vector(i as f32 * 0.1));
        }

        // Should be ready for analysis
        let result = detector.analyze(&ip);
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.ip, ip);
        assert_eq!(result.sequence_length, 5);
    }

    #[test]
    fn test_analyze_all() {
        let config = TemporalConfig {
            window: WindowConfig {
                min_sequence_length: 2,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut detector = TemporalDetector::with_config(config);

        // Add data for multiple IPs
        for i in 0..3 {
            let ip: IpAddr = format!("10.0.0.{}", i + 1).parse().unwrap();
            for j in 0..5 {
                detector.process(ip, &make_test_vector(j as f32 * 0.1));
            }
        }

        let results = detector.analyze_all();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_stats() {
        let mut detector = TemporalDetector::new();
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        detector.process(ip, &make_test_vector(0.5));
        assert_eq!(detector.stats().features_processed, 1);
    }
}

//! Feedback Integration for Online Learning
//!
//! Provides integration between the feedback system and ML online learning,
//! converting feedback events into training samples.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::ml::unified::{UnifiedFeatureVector, UNIFIED_DIM};
use super::replay_buffer::{ExperienceSample, ReplayBuffer, SampleLabel, SamplePriority};

/// Feedback event types from the detection system
#[derive(Debug, Clone)]
pub enum FeedbackEvent {
    /// True positive - correctly detected attack
    TruePositive {
        flow_id: u64,
        features: [f32; UNIFIED_DIM],
        detection_type: String,
        confidence: f32,
        timestamp: DateTime<Utc>,
    },
    /// False positive - incorrectly flagged as attack
    FalsePositive {
        flow_id: u64,
        features: [f32; UNIFIED_DIM],
        original_detection: String,
        confidence: f32,
        timestamp: DateTime<Utc>,
        correction_source: CorrectionSource,
    },
    /// False negative - missed attack
    FalseNegative {
        flow_id: u64,
        features: [f32; UNIFIED_DIM],
        actual_attack: String,
        timestamp: DateTime<Utc>,
        discovery_source: DiscoverySource,
    },
    /// True negative - correctly classified as normal
    TrueNegative {
        flow_id: u64,
        features: [f32; UNIFIED_DIM],
        timestamp: DateTime<Utc>,
    },
    /// Model performance feedback
    ModelFeedback {
        model_name: String,
        score: f32,
        was_correct: bool,
        detection_type: Option<String>,
    },
}

impl FeedbackEvent {
    /// Get flow ID if available
    pub fn flow_id(&self) -> Option<u64> {
        match self {
            FeedbackEvent::TruePositive { flow_id, .. } => Some(*flow_id),
            FeedbackEvent::FalsePositive { flow_id, .. } => Some(*flow_id),
            FeedbackEvent::FalseNegative { flow_id, .. } => Some(*flow_id),
            FeedbackEvent::TrueNegative { flow_id, .. } => Some(*flow_id),
            FeedbackEvent::ModelFeedback { .. } => None,
        }
    }

    /// Get timestamp
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            FeedbackEvent::TruePositive { timestamp, .. } => *timestamp,
            FeedbackEvent::FalsePositive { timestamp, .. } => *timestamp,
            FeedbackEvent::FalseNegative { timestamp, .. } => *timestamp,
            FeedbackEvent::TrueNegative { timestamp, .. } => *timestamp,
            FeedbackEvent::ModelFeedback { .. } => Utc::now(),
        }
    }

    /// Check if this is a correction (FP or FN)
    pub fn is_correction(&self) -> bool {
        matches!(self, FeedbackEvent::FalsePositive { .. } | FeedbackEvent::FalseNegative { .. })
    }

    /// Convert to experience sample for replay buffer
    pub fn to_sample(&self) -> Option<ExperienceSample> {
        match self {
            FeedbackEvent::TruePositive {
                flow_id,
                features,
                detection_type,
                confidence,
                timestamp,
            } => {
                let mut sample = ExperienceSample::new(*features, SampleLabel::Attack, *flow_id);
                sample.timestamp = *timestamp;
                sample.original_prediction = Some(true);
                sample.original_confidence = Some(*confidence);
                sample.detection_type = Some(detection_type.clone());
                sample.priority = SamplePriority::Medium;
                Some(sample)
            }
            FeedbackEvent::FalsePositive {
                flow_id,
                features,
                original_detection,
                confidence,
                timestamp,
                ..
            } => {
                let mut sample = ExperienceSample::new(*features, SampleLabel::Normal, *flow_id);
                sample.timestamp = *timestamp;
                sample.original_prediction = Some(true); // Was predicted as attack
                sample.original_confidence = Some(*confidence);
                sample.detection_type = Some(original_detection.clone());
                sample.priority = SamplePriority::High; // Important for learning
                Some(sample)
            }
            FeedbackEvent::FalseNegative {
                flow_id,
                features,
                actual_attack,
                timestamp,
                ..
            } => {
                let mut sample = ExperienceSample::new(*features, SampleLabel::Attack, *flow_id);
                sample.timestamp = *timestamp;
                sample.original_prediction = Some(false); // Was predicted as normal
                sample.original_confidence = Some(0.0);
                sample.detection_type = Some(actual_attack.clone());
                sample.priority = SamplePriority::Critical; // Very important for learning
                Some(sample)
            }
            FeedbackEvent::TrueNegative {
                flow_id,
                features,
                timestamp,
            } => {
                let mut sample = ExperienceSample::new(*features, SampleLabel::Normal, *flow_id);
                sample.timestamp = *timestamp;
                sample.original_prediction = Some(false);
                sample.original_confidence = Some(1.0);
                sample.priority = SamplePriority::Low;
                Some(sample)
            }
            FeedbackEvent::ModelFeedback { .. } => None,
        }
    }
}

/// Source of false positive correction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrectionSource {
    /// Analyst marked as false positive
    Analyst { analyst_id: Option<String> },
    /// Correlated with auth logs (legitimate access)
    AuthLogCorrelation,
    /// Correlated with known service behavior
    ServiceCorrelation,
    /// Automatic tuning based on threshold
    AutoTuning,
    /// External threat intel indicates benign
    ThreatIntel,
}

/// Source of false negative discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoverySource {
    /// Discovered during incident response
    IncidentResponse,
    /// Found in external threat intel
    ThreatIntel { source: String },
    /// Detected by signature after ML missed
    SignatureDetection,
    /// Found in forensic analysis
    ForensicAnalysis,
    /// Correlated from auth/system logs
    LogCorrelation,
}

/// Feedback receiver that processes events into training data
pub struct FeedbackReceiver {
    /// Receiver channel
    rx: mpsc::Receiver<FeedbackEvent>,
    /// Replay buffer for storing samples
    buffer: ReplayBuffer,
    /// Statistics
    stats: FeedbackStats,
    /// Per-model feedback tracking
    model_stats: HashMap<String, ModelFeedbackStats>,
}

impl FeedbackReceiver {
    /// Create a new feedback receiver
    pub fn new(rx: mpsc::Receiver<FeedbackEvent>, buffer: ReplayBuffer) -> Self {
        Self {
            rx,
            buffer,
            stats: FeedbackStats::default(),
            model_stats: HashMap::new(),
        }
    }

    /// Process a single feedback event
    pub fn process_event(&mut self, event: FeedbackEvent) {
        self.stats.total_events += 1;

        match &event {
            FeedbackEvent::TruePositive { .. } => {
                self.stats.true_positives += 1;
            }
            FeedbackEvent::FalsePositive { .. } => {
                self.stats.false_positives += 1;
            }
            FeedbackEvent::FalseNegative { .. } => {
                self.stats.false_negatives += 1;
            }
            FeedbackEvent::TrueNegative { .. } => {
                self.stats.true_negatives += 1;
            }
            FeedbackEvent::ModelFeedback {
                model_name,
                was_correct,
                ..
            } => {
                let model_stats = self.model_stats.entry(model_name.clone()).or_default();
                model_stats.total += 1;
                if *was_correct {
                    model_stats.correct += 1;
                }
            }
        }

        // Convert to sample and add to buffer
        if let Some(sample) = event.to_sample() {
            self.buffer.add(sample);
        }
    }

    /// Try to receive and process events (non-blocking)
    pub fn try_receive(&mut self) -> usize {
        let mut count = 0;
        while let Ok(event) = self.rx.try_recv() {
            self.process_event(event);
            count += 1;
        }
        count
    }

    /// Receive and process events (blocking until channel closes)
    pub async fn receive_all(&mut self) {
        while let Some(event) = self.rx.recv().await {
            self.process_event(event);
        }
    }

    /// Get replay buffer
    pub fn buffer(&self) -> &ReplayBuffer {
        &self.buffer
    }

    /// Get mutable replay buffer
    pub fn buffer_mut(&mut self) -> &mut ReplayBuffer {
        &mut self.buffer
    }

    /// Get statistics
    pub fn stats(&self) -> &FeedbackStats {
        &self.stats
    }

    /// Get model-specific stats
    pub fn model_stats(&self) -> &HashMap<String, ModelFeedbackStats> {
        &self.model_stats
    }
}

/// Feedback sender for emitting events
#[derive(Clone)]
pub struct FeedbackSender {
    tx: mpsc::Sender<FeedbackEvent>,
}

impl FeedbackSender {
    /// Create a new feedback channel pair
    pub fn channel(buffer_size: usize) -> (Self, mpsc::Receiver<FeedbackEvent>) {
        let (tx, rx) = mpsc::channel(buffer_size);
        (Self { tx }, rx)
    }

    /// Send a feedback event
    pub async fn send(&self, event: FeedbackEvent) -> Result<(), mpsc::error::SendError<FeedbackEvent>> {
        self.tx.send(event).await
    }

    /// Try to send a feedback event (non-blocking)
    pub fn try_send(&self, event: FeedbackEvent) -> Result<(), mpsc::error::TrySendError<FeedbackEvent>> {
        self.tx.try_send(event)
    }

    /// Report a true positive
    pub async fn report_true_positive(
        &self,
        flow_id: u64,
        features: [f32; UNIFIED_DIM],
        detection_type: &str,
        confidence: f32,
    ) -> Result<(), mpsc::error::SendError<FeedbackEvent>> {
        self.send(FeedbackEvent::TruePositive {
            flow_id,
            features,
            detection_type: detection_type.to_string(),
            confidence,
            timestamp: Utc::now(),
        }).await
    }

    /// Report a false positive
    pub async fn report_false_positive(
        &self,
        flow_id: u64,
        features: [f32; UNIFIED_DIM],
        original_detection: &str,
        confidence: f32,
        source: CorrectionSource,
    ) -> Result<(), mpsc::error::SendError<FeedbackEvent>> {
        self.send(FeedbackEvent::FalsePositive {
            flow_id,
            features,
            original_detection: original_detection.to_string(),
            confidence,
            timestamp: Utc::now(),
            correction_source: source,
        }).await
    }

    /// Report a false negative
    pub async fn report_false_negative(
        &self,
        flow_id: u64,
        features: [f32; UNIFIED_DIM],
        actual_attack: &str,
        source: DiscoverySource,
    ) -> Result<(), mpsc::error::SendError<FeedbackEvent>> {
        self.send(FeedbackEvent::FalseNegative {
            flow_id,
            features,
            actual_attack: actual_attack.to_string(),
            timestamp: Utc::now(),
            discovery_source: source,
        }).await
    }

    /// Report model-specific feedback
    pub async fn report_model_feedback(
        &self,
        model_name: &str,
        score: f32,
        was_correct: bool,
        detection_type: Option<&str>,
    ) -> Result<(), mpsc::error::SendError<FeedbackEvent>> {
        self.send(FeedbackEvent::ModelFeedback {
            model_name: model_name.to_string(),
            score,
            was_correct,
            detection_type: detection_type.map(String::from),
        }).await
    }
}

/// Feedback statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedbackStats {
    /// Total events received
    pub total_events: u64,
    /// True positives
    pub true_positives: u64,
    /// False positives
    pub false_positives: u64,
    /// False negatives
    pub false_negatives: u64,
    /// True negatives
    pub true_negatives: u64,
}

impl FeedbackStats {
    /// Compute precision (TP / (TP + FP))
    pub fn precision(&self) -> f64 {
        let tp = self.true_positives as f64;
        let fp = self.false_positives as f64;
        if tp + fp > 0.0 {
            tp / (tp + fp)
        } else {
            1.0
        }
    }

    /// Compute recall (TP / (TP + FN))
    pub fn recall(&self) -> f64 {
        let tp = self.true_positives as f64;
        let fn_ = self.false_negatives as f64;
        if tp + fn_ > 0.0 {
            tp / (tp + fn_)
        } else {
            1.0
        }
    }

    /// Compute F1 score
    pub fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r > 0.0 {
            2.0 * p * r / (p + r)
        } else {
            0.0
        }
    }

    /// False positive rate
    pub fn fp_rate(&self) -> f64 {
        let fp = self.false_positives as f64;
        let tn = self.true_negatives as f64;
        if fp + tn > 0.0 {
            fp / (fp + tn)
        } else {
            0.0
        }
    }

    /// False negative rate
    pub fn fn_rate(&self) -> f64 {
        let fn_ = self.false_negatives as f64;
        let tp = self.true_positives as f64;
        if fn_ + tp > 0.0 {
            fn_ / (fn_ + tp)
        } else {
            0.0
        }
    }
}

/// Per-model feedback statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelFeedbackStats {
    /// Total predictions
    pub total: u64,
    /// Correct predictions
    pub correct: u64,
}

impl ModelFeedbackStats {
    /// Get accuracy
    pub fn accuracy(&self) -> f64 {
        if self.total > 0 {
            self.correct as f64 / self.total as f64
        } else {
            0.0
        }
    }
}

/// Feedback adapter for connecting to existing feedback analyzer
pub struct FeedbackAdapter {
    /// Sender for emitting events
    sender: FeedbackSender,
}

impl FeedbackAdapter {
    /// Create a new adapter
    pub fn new(sender: FeedbackSender) -> Self {
        Self { sender }
    }

    /// Convert correlation result to feedback events
    pub fn from_correlation_stats(
        &self,
        stats: &crate::feedback::correlation::CorrelationStats,
        features_cache: &HashMap<u64, [f32; UNIFIED_DIM]>,
    ) -> Vec<FeedbackEvent> {
        let mut events = Vec::new();

        // This would be called when correlation completes with per-flow results
        // For now, we just track aggregate stats
        // In practice, you'd iterate over individual flow results

        events
    }

    /// Get sender for external use
    pub fn sender(&self) -> &FeedbackSender {
        &self.sender
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml::online::replay_buffer::ReplayBufferConfig;

    #[test]
    fn test_feedback_event_to_sample() {
        let event = FeedbackEvent::TruePositive {
            flow_id: 123,
            features: [0.5; UNIFIED_DIM],
            detection_type: "PortScan".to_string(),
            confidence: 0.9,
            timestamp: Utc::now(),
        };

        let sample = event.to_sample().unwrap();
        assert_eq!(sample.flow_id, 123);
        assert_eq!(sample.label, SampleLabel::Attack);
        assert_eq!(sample.original_prediction, Some(true));
    }

    #[test]
    fn test_false_positive_priority() {
        let event = FeedbackEvent::FalsePositive {
            flow_id: 456,
            features: [0.3; UNIFIED_DIM],
            original_detection: "BruteForce".to_string(),
            confidence: 0.8,
            timestamp: Utc::now(),
            correction_source: CorrectionSource::Analyst { analyst_id: None },
        };

        let sample = event.to_sample().unwrap();
        assert_eq!(sample.label, SampleLabel::Normal);
        assert_eq!(sample.priority, SamplePriority::High);
    }

    #[test]
    fn test_false_negative_priority() {
        let event = FeedbackEvent::FalseNegative {
            flow_id: 789,
            features: [0.7; UNIFIED_DIM],
            actual_attack: "SQLInjection".to_string(),
            timestamp: Utc::now(),
            discovery_source: DiscoverySource::IncidentResponse,
        };

        let sample = event.to_sample().unwrap();
        assert_eq!(sample.label, SampleLabel::Attack);
        assert_eq!(sample.priority, SamplePriority::Critical);
    }

    #[test]
    fn test_feedback_stats() {
        let mut stats = FeedbackStats::default();
        stats.true_positives = 90;
        stats.false_positives = 10;
        stats.false_negatives = 5;
        stats.true_negatives = 895;

        assert!((stats.precision() - 0.9).abs() < 0.001);
        assert!((stats.recall() - 0.947).abs() < 0.01);
        assert!(stats.f1() > 0.9);
    }

    #[tokio::test]
    async fn test_feedback_channel() {
        let (sender, rx) = FeedbackSender::channel(100);
        let config = ReplayBufferConfig::default();
        let buffer = ReplayBuffer::new(config);
        let mut receiver = FeedbackReceiver::new(rx, buffer);

        // Send an event
        sender.report_true_positive(1, [0.0; UNIFIED_DIM], "Test", 0.9).await.unwrap();

        // Process it
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let count = receiver.try_receive();

        assert_eq!(count, 1);
        assert_eq!(receiver.stats().true_positives, 1);
    }
}

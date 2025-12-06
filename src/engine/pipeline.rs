//! Processing pipeline
//!
//! Routes packets through the detection engines.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, trace};

use crate::core::event::DetectionEvent;
use crate::core::packet::Packet;

use super::workers::{WorkerPool, WorkerConfig};
use super::EngineStats;

/// Pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Packet buffer size
    pub buffer_size: usize,
    /// Enable flow tracking
    pub enable_flows: bool,
    /// Enable protocol analysis
    pub enable_protocols: bool,
    /// Enable signature matching
    pub enable_signatures: bool,
    /// Enable ML/anomaly detection
    pub enable_ml: bool,
    /// Enable threat intel lookup
    pub enable_intel: bool,
    /// Enable correlation
    pub enable_correlation: bool,
    /// Stats update interval (seconds)
    pub stats_interval_secs: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            buffer_size: 10_000,
            enable_flows: true,
            enable_protocols: true,
            enable_signatures: true,
            enable_ml: true,
            enable_intel: true,
            enable_correlation: true,
            stats_interval_secs: 1,
        }
    }
}

/// Processing pipeline
pub struct Pipeline {
    /// Configuration
    config: PipelineConfig,
    /// Packet input channel
    packet_rx: Receiver<Packet>,
    /// Event output channel
    event_tx: mpsc::Sender<DetectionEvent>,
}

impl Pipeline {
    /// Create a new pipeline
    pub fn new(
        config: PipelineConfig,
        packet_rx: Receiver<Packet>,
        event_tx: mpsc::Sender<DetectionEvent>,
    ) -> Self {
        Self {
            config,
            packet_rx,
            event_tx,
        }
    }

    /// Run the pipeline
    pub async fn run(
        self,
        worker_config: WorkerConfig,
        stats: Arc<RwLock<EngineStats>>,
    ) -> anyhow::Result<()> {
        // Create worker pool
        let mut worker_pool = WorkerPool::new(worker_config);

        // Processing loop
        let mut last_stats = Instant::now();
        let mut packets_this_interval = 0u64;
        let mut events_this_interval = 0u64;

        loop {
            // Try to receive a packet with timeout
            match self.packet_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(packet) => {
                    packets_this_interval += 1;

                    // Process packet through worker pool
                    let events = worker_pool.process(packet, &self.config);

                    // Send events
                    for event in events {
                        events_this_interval += 1;
                        if self.event_tx.send(event).await.is_err() {
                            // Channel closed
                            return Ok(());
                        }
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // No packet, continue
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    // Channel closed
                    debug!("Packet channel closed, stopping pipeline");
                    break;
                }
            }

            // Update stats periodically
            if last_stats.elapsed().as_secs() >= self.config.stats_interval_secs {
                let elapsed = last_stats.elapsed().as_secs_f64();

                let mut s = stats.write();
                s.packets_processed += packets_this_interval;
                s.events_generated += events_this_interval;
                s.packets_per_second = packets_this_interval as f64 / elapsed;
                s.events_per_second = events_this_interval as f64 / elapsed;
                s.worker_utilization = worker_pool.utilization();

                packets_this_interval = 0;
                events_this_interval = 0;
                last_stats = Instant::now();
            }
        }

        Ok(())
    }
}

/// A processing stage in the pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    /// Flow tracking
    FlowTracker,
    /// Protocol analysis
    ProtocolAnalysis,
    /// Signature matching
    SignatureMatching,
    /// Threat intel lookup
    ThreatIntel,
    /// ML/Anomaly detection
    MLDetection,
    /// Correlation
    Correlation,
}

impl PipelineStage {
    /// Get all stages in order
    pub fn all() -> Vec<Self> {
        vec![
            PipelineStage::FlowTracker,
            PipelineStage::ProtocolAnalysis,
            PipelineStage::SignatureMatching,
            PipelineStage::ThreatIntel,
            PipelineStage::MLDetection,
            PipelineStage::Correlation,
        ]
    }

    /// Get stage name
    pub fn name(&self) -> &'static str {
        match self {
            PipelineStage::FlowTracker => "flow_tracker",
            PipelineStage::ProtocolAnalysis => "protocol_analysis",
            PipelineStage::SignatureMatching => "signature_matching",
            PipelineStage::ThreatIntel => "threat_intel",
            PipelineStage::MLDetection => "ml_detection",
            PipelineStage::Correlation => "correlation",
        }
    }
}

/// Per-stage metrics
#[derive(Debug, Clone, Default)]
pub struct StageMetrics {
    /// Packets processed
    pub packets_processed: u64,
    /// Events generated
    pub events_generated: u64,
    /// Processing time (microseconds)
    pub processing_time_us: u64,
    /// Errors
    pub errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        assert!(config.enable_flows);
        assert!(config.enable_signatures);
        assert_eq!(config.buffer_size, 10_000);
    }

    #[test]
    fn test_pipeline_stages() {
        let stages = PipelineStage::all();
        assert_eq!(stages.len(), 6);
        assert_eq!(stages[0], PipelineStage::FlowTracker);
    }

    #[test]
    fn test_stage_names() {
        assert_eq!(PipelineStage::FlowTracker.name(), "flow_tracker");
        assert_eq!(PipelineStage::MLDetection.name(), "ml_detection");
    }
}

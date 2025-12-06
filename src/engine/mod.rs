//! Packet Engine
//!
//! Multi-threaded packet capture and processing pipeline that integrates
//! all detection engines.
//!
//! # Architecture
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
//! │   Capture   │────▶│   Pipeline   │────▶│   Workers    │
//! │  (NFQUEUE)  │     │   (channel)  │     │  (N threads) │
//! └─────────────┘     └──────────────┘     └──────────────┘
//!                                                │
//!                     ┌──────────────────────────┼──────────────────────────┐
//!                     │                          │                          │
//!                     ▼                          ▼                          ▼
//!              ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
//!              │ Flow Tracker │          │   Protocol   │          │  Signature   │
//!              │              │          │  Analyzers   │          │   Engine     │
//!              └──────────────┘          └──────────────┘          └──────────────┘
//!                     │                          │                          │
//!                     └──────────────────────────┼──────────────────────────┘
//!                                                ▼
//!                                         ┌──────────────┐
//!                                         │ ML/Anomaly   │
//!                                         │   Engine     │
//!                                         └──────────────┘
//!                                                │
//!                                                ▼
//!                                         ┌──────────────┐
//!                                         │ Correlation  │
//!                                         │   Engine     │
//!                                         └──────────────┘
//!                                                │
//!                                                ▼
//!                                         ┌──────────────┐
//!                                         │   Actions    │
//!                                         │ (ban/alert)  │
//!                                         └──────────────┘
//! ```

pub mod capture;
pub mod pipeline;
pub mod workers;
pub mod actions;

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::core::event::DetectionEvent;
use crate::core::packet::Packet;

pub use capture::{PacketCapture, CaptureConfig, CaptureMethod};
pub use pipeline::{Pipeline, PipelineConfig};
pub use workers::{WorkerPool, WorkerConfig};
pub use actions::{ActionExecutor, Action, ActionConfig};

/// Packet engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEngineConfig {
    /// Enable the engine
    pub enabled: bool,
    /// Capture configuration
    pub capture: CaptureConfig,
    /// Pipeline configuration
    pub pipeline: PipelineConfig,
    /// Worker configuration
    pub worker: WorkerConfig,
    /// Action configuration
    pub action: ActionConfig,
}

impl Default for PacketEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            capture: CaptureConfig::default(),
            pipeline: PipelineConfig::default(),
            worker: WorkerConfig::default(),
            action: ActionConfig::default(),
        }
    }
}

/// Engine state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    /// Not started
    Stopped,
    /// Starting up
    Starting,
    /// Running
    Running,
    /// Stopping
    Stopping,
    /// Error state
    Error,
}

/// Packet engine statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct EngineStats {
    /// Packets captured
    pub packets_captured: u64,
    /// Packets processed
    pub packets_processed: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Events generated
    pub events_generated: u64,
    /// Actions executed
    pub actions_executed: u64,
    /// Current packets per second
    pub packets_per_second: f64,
    /// Current events per second
    pub events_per_second: f64,
    /// Worker utilization (0.0-1.0)
    pub worker_utilization: f64,
}

/// Main packet processing engine
pub struct PacketEngine {
    /// Configuration
    config: PacketEngineConfig,
    /// Current state
    state: Arc<RwLock<EngineState>>,
    /// Statistics
    stats: Arc<RwLock<EngineStats>>,
    /// Event output channel sender
    event_tx: Option<mpsc::Sender<DetectionEvent>>,
    /// Shutdown signal
    shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
}

impl PacketEngine {
    /// Create a new packet engine
    pub fn new(config: PacketEngineConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(EngineState::Stopped)),
            stats: Arc::new(RwLock::new(EngineStats::default())),
            event_tx: None,
            shutdown_tx: None,
        }
    }

    /// Set event output channel
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<DetectionEvent>) {
        self.event_tx = Some(tx);
    }

    /// Get current state
    pub fn state(&self) -> EngineState {
        *self.state.read()
    }

    /// Get statistics
    pub fn stats(&self) -> EngineStats {
        self.stats.read().clone()
    }

    /// Get configuration
    pub fn config(&self) -> &PacketEngineConfig {
        &self.config
    }

    /// Start the engine
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if !self.config.enabled {
            warn!("Packet engine is disabled");
            return Ok(());
        }

        // Update state
        {
            let mut state = self.state.write();
            if *state != EngineState::Stopped {
                anyhow::bail!("Engine is not in stopped state");
            }
            *state = EngineState::Starting;
        }

        info!("Starting packet engine...");

        // Create shutdown channel
        let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Create packet channel
        let (packet_tx, packet_rx) = crossbeam_channel::bounded::<Packet>(
            self.config.pipeline.buffer_size,
        );

        // Create event channel if not provided
        let event_tx = self.event_tx.clone().unwrap_or_else(|| {
            let (tx, _rx) = mpsc::channel(1000);
            tx
        });

        // Create pipeline
        let pipeline = Pipeline::new(
            self.config.pipeline.clone(),
            packet_rx,
            event_tx.clone(),
        );

        // Create action executor
        let action_executor = ActionExecutor::new(self.config.action.clone());

        // Clone shared state for tasks
        let state = self.state.clone();
        let stats = self.stats.clone();

        // Start capture thread
        let capture_config = self.config.capture.clone();
        let capture_packet_tx = packet_tx.clone();
        let capture_state = state.clone();
        let capture_stats = stats.clone();

        std::thread::spawn(move || {
            match capture::create_capture(&capture_config) {
                Ok(mut capture) => {
                    info!("Capture started: {:?}", capture_config.method);

                    loop {
                        // Check if should stop
                        if *capture_state.read() == EngineState::Stopping {
                            break;
                        }

                        match capture.next_packet() {
                            Ok(Some(packet)) => {
                                capture_stats.write().packets_captured += 1;

                                if capture_packet_tx.send(packet).is_err() {
                                    // Channel closed
                                    break;
                                }
                            }
                            Ok(None) => {
                                // No packet available, brief sleep
                                std::thread::sleep(Duration::from_micros(100));
                            }
                            Err(e) => {
                                error!("Capture error: {}", e);
                                std::thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    info!("Capture stopped");
                }
                Err(e) => {
                    error!("Failed to create capture: {}", e);
                    *capture_state.write() = EngineState::Error;
                }
            }
        });

        // Start worker pool
        let worker_config = self.config.worker.clone();
        let pipeline_state = state.clone();
        let pipeline_stats = stats.clone();

        tokio::spawn(async move {
            if let Err(e) = pipeline.run(worker_config, pipeline_stats.clone()).await {
                error!("Pipeline error: {}", e);
                *pipeline_state.write() = EngineState::Error;
            }
        });

        // Update state to running
        *self.state.write() = EngineState::Running;
        info!("Packet engine started");

        Ok(())
    }

    /// Stop the engine
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        info!("Stopping packet engine...");

        // Update state
        *self.state.write() = EngineState::Stopping;

        // Send shutdown signal
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }

        // Wait a bit for graceful shutdown
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Update state
        *self.state.write() = EngineState::Stopped;
        info!("Packet engine stopped");

        Ok(())
    }

    /// Process a single packet (for testing or manual injection)
    pub fn process_packet(&self, _packet: Packet) -> Vec<DetectionEvent> {
        // This would normally go through the pipeline
        // For now just return empty
        Vec::new()
    }

    /// Check if engine is running
    pub fn is_running(&self) -> bool {
        *self.state.read() == EngineState::Running
    }
}

impl Default for PacketEngine {
    fn default() -> Self {
        Self::new(PacketEngineConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = PacketEngine::default();
        assert_eq!(engine.state(), EngineState::Stopped);
    }

    #[test]
    fn test_engine_config() {
        let config = PacketEngineConfig::default();
        assert!(config.enabled);
    }

    #[test]
    fn test_engine_stats() {
        let engine = PacketEngine::default();
        let stats = engine.stats();
        assert_eq!(stats.packets_captured, 0);
    }
}

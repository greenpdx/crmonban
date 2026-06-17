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
pub mod flow_buffer;
pub mod flow_disposition;

#[cfg(feature = "profiling")]
pub mod profiling;

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::core::{DetectionEvent, Packet};
use crate::database::BatchedWriterHandle;

pub use capture::{PacketCapture, CaptureConfig, CaptureMethod};
pub use pipeline::{Pipeline, PipelineConfig, PipelineStage, StageProcessor};
pub use workers::{WorkerPool, WorkerThread, WorkerConfig};
pub use actions::{ActionExecutor, Action, ActionConfig};
pub use flow_buffer::{FlowBuffer, FlowBufferConfig, FlowBatch, FlushTrigger};
pub use flow_disposition::{
    FlowCacheStats, FlowDisposition, FlowVerdictCache, FlowVerdictCacheConfig,
};

#[cfg(feature = "profiling")]
pub use profiling::{PipelineProfiler, PipelineProfileSnapshot, StageProfile, StageProfileSnapshot};

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
    /// Optional database writer for event persistence
    db_writer: Option<BatchedWriterHandle>,
    /// Capture thread handle, joined on stop() so in-flight verdicts drain
    /// before the queue is closed.
    capture_handle: Option<std::thread::JoinHandle<()>>,
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
            db_writer: None,
            capture_handle: None,
        }
    }

    /// Set event output channel
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<DetectionEvent>) {
        self.event_tx = Some(tx);
    }

    /// Set database writer for event persistence
    pub fn set_db_writer(&mut self, writer: BatchedWriterHandle) {
        self.db_writer = Some(writer);
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

        // Create verdict channel: pipeline -> capture thread, (packet_id, accept).
        // Unbounded on purpose: the async pipeline must never block issuing a
        // verdict, or it would deadlock against the bounded packet channel above
        // (capture blocked sending a packet, pipeline blocked sending a verdict).
        // The capture thread drains this before each blocking packet send, so in
        // steady state the backlog stays small (~NFQUEUE depth); it can grow
        // transiently during a packet-send stall, bounded by packets the pipeline
        // processed meanwhile.
        let (verdict_tx, verdict_rx) = crossbeam_channel::unbounded::<(u64, bool)>();

        // Create event channel if not provided
        let event_tx = self.event_tx.clone().unwrap_or_else(|| {
            let (tx, _rx) = mpsc::channel(1000);
            tx
        });

        // Create pipeline with optional database writer
        let mut pipeline = Pipeline::new(
            self.config.pipeline.clone(),
            packet_rx,
            event_tx.clone(),
        );
        if let Some(ref writer) = self.db_writer {
            pipeline = pipeline.with_db_writer(writer.clone());
        }
        // Route inline ACCEPT/DROP verdicts back to the capture (NFQUEUE).
        pipeline = pipeline.with_verdict_sink(verdict_tx);

        // Create action executor
        let _action_executor = ActionExecutor::new(self.config.action.clone());

        // Clone shared state for tasks
        let state = self.state.clone();
        let stats = self.stats.clone();

        // Start capture thread
        let capture_config = self.config.capture.clone();
        let capture_packet_tx = packet_tx.clone();
        let capture_state = state.clone();
        let capture_stats = stats.clone();

        self.capture_handle = Some(std::thread::spawn(move || {
            match capture::create_capture(&capture_config) {
                Ok(mut capture) => {
                    info!("Capture started: {:?}", capture_config.method);

                    loop {
                        // Check if should stop
                        if *capture_state.read() == EngineState::Stopping {
                            break;
                        }

                        // Apply verdicts the pipeline produced for previously
                        // captured packets. For NFQUEUE this issues the kernel
                        // ACCEPT/DROP; for passive captures set_verdict is a no-op.
                        while let Ok((id, accept)) = verdict_rx.try_recv() {
                            if let Err(e) = capture.set_verdict(id, accept) {
                                warn!("Failed to set verdict for packet {}: {}", id, e);
                            }
                        }

                        match capture.next_packet(0) {
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

                    // Shutdown: we stopped capturing new packets, but the pipeline
                    // is still computing verdicts for packets already handed off.
                    // Keep applying them until none remain parked, so close()'s
                    // default ACCEPT cannot override a real DROP for in-flight
                    // packets (otherwise every restart would leak blocked traffic).
                    // Bounded by a deadline so a wedged pipeline can't hang shutdown.
                    let drain_deadline =
                        std::time::Instant::now() + Duration::from_secs(5);
                    loop {
                        while let Ok((id, accept)) = verdict_rx.try_recv() {
                            if let Err(e) = capture.set_verdict(id, accept) {
                                warn!("Failed to set verdict for packet {}: {}", id, e);
                            }
                        }
                        if capture.pending_verdicts() == 0 {
                            break;
                        }
                        if std::time::Instant::now() >= drain_deadline {
                            warn!(
                                "Shutdown drain timed out with {} packet(s) still \
                                 awaiting a verdict; accepting them",
                                capture.pending_verdicts()
                            );
                            break;
                        }
                        // The inner loop drained every ready verdict; wait briefly
                        // for the pipeline to produce the next one rather than
                        // busy-polling try_recv.
                        std::thread::sleep(Duration::from_millis(1));
                    }

                    // Flush a default ACCEPT for any genuinely-unverdicted leftovers
                    // (deadline case only) and unbind the queue.
                    capture.close();

                    info!("Capture stopped");
                }
                Err(e) => {
                    error!("Failed to create capture: {}", e);
                    *capture_state.write() = EngineState::Error;
                }
            }
        }));

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

        // Wait for the capture thread to drain in-flight verdicts and close the
        // queue cleanly before reporting stopped, so blocking decisions for
        // in-flight packets are not lost. Join off the async runtime
        // (spawn_blocking) so the pipeline task keeps being polled and feeding
        // verdicts during the drain. Termination is guaranteed by the capture
        // thread's 5s drain deadline, NOT by pipeline liveness — keep that
        // deadline as the load-bearing backstop so stop() can never hang.
        if let Some(handle) = self.capture_handle.take() {
            let _ = tokio::task::spawn_blocking(move || handle.join()).await;
        } else {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Update state
        *self.state.write() = EngineState::Stopped;
        info!("Packet engine stopped");

        Ok(())
    }

    /// Process a single packet synchronously (for testing or manual injection)
    ///
    /// Note: For production use, prefer the async worker pool processing.
    /// This method is for testing and simple single-packet processing scenarios.
    pub fn process_packet(&self, _packet: Packet) -> Vec<DetectionEvent> {
        // This would normally go through the pipeline
        // For now just return empty
        // TODO: Implement synchronous single-packet processing
        Vec::new()
    }

    /// Get the pipeline configuration
    pub fn pipeline_config(&self) -> &PipelineConfig {
        &self.config.pipeline
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

//! Processing pipeline
//!
//! Routes packets through the detection engines.
//!
//! ## Pipeline Design (v4)
//!
//! The pipeline processes packets through 8 sequential stages:
//! 0. IP Filter - IP blocklist, GeoIP, threat intel IOC matching (ipfilter + threat intel)
//! 1. Flow Tracker - Connection state tracking
//! 2. Layer2 Detect - Scans, DoS, brute force via vector similarity (layer2detect)
//! 3. Signature Matching - Aho-Corasick + rule verification
//! 4. Protocol Analysis - HTTP/DNS/TLS parsers + attack detection (httpAttack, DNS, TLS)
//! 5. WASM Plugins - Custom analysis via WebAssembly
//! 6. ML Detection - Flow-based anomaly scoring
//! 7. Correlation - DB write + alert generation
//!
//! Stage order is configurable via `PipelineConfig::stage_order` for optimization.
//! Each stage has pass_count and marked_count counters for debugging.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::debug;

use crate::core::{PacketAnalysis, DetectionEvent, Packet};
use crate::database::{BatchedWriterHandle, IntervalStats};

use super::workers::{WorkerPool, WorkerConfig};
use super::EngineStats;

// Re-export StageProcessor from crmonban-types
pub use crate::types::StageProcessor;

/// Pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Packet buffer size
    pub buffer_size: usize,
    /// Enable IP filtering (Stage 0) - includes GeoIP and threat intel
    pub enable_ipfilter: bool,
    /// Enable flow tracking
    pub enable_flows: bool,
    /// Enable Layer 2 detection (Stage 2) - scans, DoS, brute force
    /// Replaces: enable_scan_detect, enable_dos, enable_brute_force
    pub enable_layer2detect: bool,
    /// Enable protocol analysis
    pub enable_protocols: bool,
    /// Enable signature matching
    pub enable_signatures: bool,
    /// Enable ML/anomaly detection
    pub enable_ml: bool,
    /// Enable correlation
    pub enable_correlation: bool,
    /// Enable port scan detection (DEPRECATED - use enable_layer2detect)
    #[deprecated(note = "Use enable_layer2detect instead")]
    pub enable_scan_detect: bool,
    /// Enable brute force detection (DEPRECATED - use enable_layer2detect)
    #[deprecated(note = "Use enable_layer2detect instead")]
    pub enable_brute_force: bool,
    /// Enable DoS/flood detection (DEPRECATED - use enable_layer2detect)
    #[deprecated(note = "Use enable_layer2detect instead")]
    pub enable_dos: bool,
    /// Enable WASM plugin processing
    pub enable_wasm: bool,
    /// Stats update interval (seconds)
    pub stats_interval_secs: u64,
    /// Stage execution order (configurable for optimization)
    /// Default order: IpFilter, Flow, Layer2Detect, Signatures, Protocols, Wasm, ML, Correlation
    #[serde(default = "default_stage_order")]
    pub stage_order: Vec<PipelineStage>,
}

/// Default stage order per v4 spec (with Layer2Detect replacing individual stages)
#[allow(deprecated)]
fn default_stage_order() -> Vec<PipelineStage> {
    vec![
        PipelineStage::IpFilter,        // Stage 0: IP filtering + GeoIP + Threat Intel
        PipelineStage::FlowTracker,     // Stage 1: Connection tracking
        PipelineStage::Layer2Detect,    // Stage 2: Scans, DoS, brute force (replaces Stages 2, 2b, 3)
        PipelineStage::SignatureMatching,   // Stage 3: Signature matching
        PipelineStage::ProtocolAnalysis,    // Stage 4: Protocol parsing
        PipelineStage::WasmPlugins,         // Stage 5: WASM plugins
        PipelineStage::MLDetection,         // Stage 6: ML anomaly detection
        PipelineStage::Correlation,         // Stage 7: Alert correlation
    ]
}

#[allow(deprecated)]
impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            buffer_size: 10_000,
            enable_ipfilter: true,       // Stage 0: IP filtering enabled by default
            enable_flows: true,          // Stage 1: Flow tracking enabled
            enable_layer2detect: true,   // Stage 2: Layer 2 detection enabled
            enable_protocols: false,
            enable_signatures: false,
            enable_ml: false,
            enable_correlation: false,
            enable_scan_detect: false,   // DEPRECATED - use enable_layer2detect
            enable_brute_force: false,   // DEPRECATED - use enable_layer2detect
            enable_dos: false,           // DEPRECATED - use enable_layer2detect
            enable_wasm: false,
            stats_interval_secs: 1,
            stage_order: default_stage_order(),
        }
    }
}

#[allow(deprecated)]
impl PipelineConfig {
    /// Check if a stage is enabled based on its type
    pub fn is_stage_enabled(&self, stage: PipelineStage) -> bool {
        match stage {
            PipelineStage::IpFilter => self.enable_ipfilter,
            PipelineStage::FlowTracker => self.enable_flows,
            PipelineStage::Layer2Detect => self.enable_layer2detect,
            PipelineStage::ScanDetection => self.enable_scan_detect,
            PipelineStage::DoSDetection => self.enable_dos,
            PipelineStage::BruteForceDetection => self.enable_brute_force,
            PipelineStage::SignatureMatching => self.enable_signatures,
            PipelineStage::ProtocolAnalysis => self.enable_protocols,
            PipelineStage::WasmPlugins => self.enable_wasm,
            PipelineStage::MLDetection => self.enable_ml,
            PipelineStage::Correlation => self.enable_correlation,
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
    /// Optional batched writer for database persistence
    db_writer: Option<BatchedWriterHandle>,
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
            db_writer: None,
        }
    }

    /// Set the database writer for event persistence
    pub fn with_db_writer(mut self, writer: BatchedWriterHandle) -> Self {
        self.db_writer = Some(writer);
        self
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
        let mut bytes_this_interval = 0u64;
        let mut events_this_interval = 0u64;
        let mut latency_sum_us = 0u64;
        let mut latency_max_us = 0u64;

        loop {
            // Try to receive a packet with timeout
            match self.packet_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(packet) => {
                    let packet_start = Instant::now();
                    packets_this_interval += 1;
                    bytes_this_interval += packet.raw_len as u64;

                    // Process packet through worker pool
                    let events = worker_pool.process(packet, &self.config).await;

                    // Record latency
                    let latency_us = packet_start.elapsed().as_micros() as u64;
                    latency_sum_us += latency_us;
                    if latency_us > latency_max_us {
                        latency_max_us = latency_us;
                    }

                    // Send events and record to database
                    for event in events {
                        events_this_interval += 1;

                        // Record to database if writer is available
                        if let Some(ref writer) = self.db_writer {
                            writer.record_event(event.clone());
                        }

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

                // Record interval stats to database
                if let Some(ref writer) = self.db_writer {
                    let mut interval_stats = IntervalStats::new(self.config.stats_interval_secs as u32);
                    interval_stats.packets_processed = packets_this_interval;
                    interval_stats.bytes_processed = bytes_this_interval;
                    interval_stats.signature_matches = events_this_interval; // Simplified
                    interval_stats.latency_sum_us = latency_sum_us;
                    interval_stats.latency_count = packets_this_interval;
                    interval_stats.latency_max_us = latency_max_us;
                    writer.record_stats(interval_stats);
                }

                packets_this_interval = 0;
                bytes_this_interval = 0;
                events_this_interval = 0;
                latency_sum_us = 0;
                latency_max_us = 0;
                last_stats = Instant::now();
            }
        }

        Ok(())
    }
}

/// A processing stage in the pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    /// IP filtering (Stage 0) - IP blocklist, GeoIP, threat intel IOCs
    IpFilter,
    /// Flow tracking (Stage 1)
    FlowTracker,
    /// Layer 2 detection (Stage 2) - scans, DoS, brute force via vector similarity
    /// Replaces: ScanDetection, DoSDetection, BruteForceDetection
    Layer2Detect,
    /// Port scan detection (Stage 2 - DEPRECATED, use Layer2Detect)
    #[deprecated(note = "Use Layer2Detect instead")]
    ScanDetection,
    /// DoS/Flood detection (Stage 2b - DEPRECATED, use Layer2Detect)
    #[deprecated(note = "Use Layer2Detect instead")]
    DoSDetection,
    /// Brute force detection (Stage 3 - DEPRECATED, use Layer2Detect)
    #[deprecated(note = "Use Layer2Detect instead")]
    BruteForceDetection,
    /// Signature matching (Stage 4) - Aho-Corasick + rules
    SignatureMatching,
    /// Protocol analysis (Stage 5) - HTTP/DNS/TLS/SSH parsers
    ProtocolAnalysis,
    /// WASM plugin processing (Stage 6) - custom detection plugins
    WasmPlugins,
    /// ML/Anomaly detection (Stage 7) - flow-based scoring
    MLDetection,
    /// Correlation (Stage 8) - DB write + alert generation
    Correlation,
}

#[allow(deprecated)]
impl PipelineStage {
    /// Get all stages in default order (v4 spec)
    pub fn all() -> Vec<Self> {
        default_stage_order()
    }

    /// Get stage name
    pub fn name(&self) -> &'static str {
        match self {
            PipelineStage::IpFilter => "ip_filter",
            PipelineStage::FlowTracker => "flow_tracker",
            PipelineStage::Layer2Detect => "layer2_detect",
            PipelineStage::ScanDetection => "scan_detection",
            PipelineStage::DoSDetection => "dos_detection",
            PipelineStage::BruteForceDetection => "brute_force_detection",
            PipelineStage::SignatureMatching => "signature_matching",
            PipelineStage::ProtocolAnalysis => "protocol_analysis",
            PipelineStage::WasmPlugins => "wasm_plugins",
            PipelineStage::MLDetection => "ml_detection",
            PipelineStage::Correlation => "correlation",
        }
    }

    /// Get stage index in default order (0-7)
    pub fn default_index(&self) -> usize {
        match self {
            PipelineStage::IpFilter => 0,
            PipelineStage::FlowTracker => 1,
            PipelineStage::Layer2Detect => 2,
            PipelineStage::ScanDetection => 2,  // DEPRECATED - same as Layer2Detect
            PipelineStage::DoSDetection => 2,   // DEPRECATED - same as Layer2Detect
            PipelineStage::BruteForceDetection => 2, // DEPRECATED - same as Layer2Detect
            PipelineStage::SignatureMatching => 3,
            PipelineStage::ProtocolAnalysis => 4,
            PipelineStage::WasmPlugins => 5,
            PipelineStage::MLDetection => 6,
            PipelineStage::Correlation => 7,
        }
    }
}

/// Per-stage metrics with atomic counters for thread-safe updates
#[derive(Debug, Default)]
pub struct StageMetrics {
    /// Packets that passed through this stage
    pub pass_count: AtomicU64,
    /// Packets marked as suspicious by this stage
    pub marked_count: AtomicU64,
    /// Processing time (nanoseconds)
    pub processing_time_ns: AtomicU64,
    /// Errors encountered
    pub errors: AtomicU64,
}

impl StageMetrics {
    /// Create new stage metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a packet passing through
    pub fn record_pass(&self) {
        self.pass_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a packet being marked
    pub fn record_marked(&self) {
        self.marked_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record processing time
    pub fn record_time(&self, ns: u64) {
        self.processing_time_ns.fetch_add(ns, Ordering::Relaxed);
    }

    /// Record an error
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get snapshot of metrics
    pub fn snapshot(&self) -> StageMetricsSnapshot {
        StageMetricsSnapshot {
            pass_count: self.pass_count.load(Ordering::Relaxed),
            marked_count: self.marked_count.load(Ordering::Relaxed),
            processing_time_ns: self.processing_time_ns.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of stage metrics (for reporting)
#[derive(Debug, Clone, Default)]
pub struct StageMetricsSnapshot {
    /// Packets that passed through this stage
    pub pass_count: u64,
    /// Packets marked as suspicious by this stage
    pub marked_count: u64,
    /// Processing time (nanoseconds)
    pub processing_time_ns: u64,
    /// Errors encountered
    pub errors: u64,
}

/// All pipeline stage metrics
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    /// Metrics per stage
    pub stages: HashMap<PipelineStage, StageMetrics>,
}

impl PipelineMetrics {
    /// Create new pipeline metrics with all stages initialized
    pub fn new() -> Self {
        let mut stages = HashMap::new();
        for stage in PipelineStage::all() {
            stages.insert(stage, StageMetrics::new());
        }
        Self { stages }
    }

    /// Get metrics for a specific stage
    pub fn get(&self, stage: PipelineStage) -> Option<&StageMetrics> {
        self.stages.get(&stage)
    }

    /// Log all stage metrics (for debug)
    pub fn log_summary(&self) {
        for stage in PipelineStage::all() {
            if let Some(metrics) = self.stages.get(&stage) {
                let snap = metrics.snapshot();
                debug!(
                    "Stage {:20} | pass: {:>10} | marked: {:>10} | time: {:>10}ns | errors: {}",
                    stage.name(),
                    snap.pass_count,
                    snap.marked_count,
                    snap.processing_time_ns,
                    snap.errors
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        // Check defaults (v4 spec)
        assert!(config.enable_ipfilter);       // Stage 0 enabled by default
        assert!(config.enable_flows);          // Stage 1 enabled by default
        assert!(config.enable_layer2detect);   // Stage 2 enabled by default (replaces scan/dos/brute)
        assert!(!config.enable_signatures);    // Off by default
        assert!(!config.enable_wasm);          // Off by default
        assert_eq!(config.buffer_size, 10_000);
        // Default stage order should have 8 stages (v4 spec)
        assert_eq!(config.stage_order.len(), 8);
        // Verify v4 stage order
        assert_eq!(config.stage_order[0], PipelineStage::IpFilter);
        assert_eq!(config.stage_order[1], PipelineStage::FlowTracker);
        assert_eq!(config.stage_order[2], PipelineStage::Layer2Detect);
        assert_eq!(config.stage_order[3], PipelineStage::SignatureMatching);
        assert_eq!(config.stage_order[4], PipelineStage::ProtocolAnalysis);
        assert_eq!(config.stage_order[5], PipelineStage::WasmPlugins);
        assert_eq!(config.stage_order[6], PipelineStage::MLDetection);
        assert_eq!(config.stage_order[7], PipelineStage::Correlation);
    }

    #[test]
    fn test_pipeline_stages_order() {
        let stages = PipelineStage::all();
        // v4 spec: 8 stages (Layer2Detect replaces ScanDetection, DoSDetection, BruteForceDetection)
        assert_eq!(stages.len(), 8);
        // Verify order: IpFilter, Flow, Layer2Detect, Sig, Proto, Wasm, ML, Corr
        assert_eq!(stages[0], PipelineStage::IpFilter);
        assert_eq!(stages[1], PipelineStage::FlowTracker);
        assert_eq!(stages[2], PipelineStage::Layer2Detect);
        assert_eq!(stages[3], PipelineStage::SignatureMatching);
        assert_eq!(stages[4], PipelineStage::ProtocolAnalysis);
        assert_eq!(stages[5], PipelineStage::WasmPlugins);
        assert_eq!(stages[6], PipelineStage::MLDetection);
        assert_eq!(stages[7], PipelineStage::Correlation);
    }

    #[allow(deprecated)]
    #[test]
    fn test_stage_names() {
        assert_eq!(PipelineStage::IpFilter.name(), "ip_filter");
        assert_eq!(PipelineStage::FlowTracker.name(), "flow_tracker");
        assert_eq!(PipelineStage::Layer2Detect.name(), "layer2_detect");
        assert_eq!(PipelineStage::ScanDetection.name(), "scan_detection");
        assert_eq!(PipelineStage::BruteForceDetection.name(), "brute_force_detection");
        assert_eq!(PipelineStage::MLDetection.name(), "ml_detection");
        assert_eq!(PipelineStage::Correlation.name(), "correlation");
    }

    #[test]
    fn test_stage_metrics() {
        let metrics = StageMetrics::new();
        metrics.record_pass();
        metrics.record_pass();
        metrics.record_marked();
        metrics.record_time(1000);

        let snap = metrics.snapshot();
        assert_eq!(snap.pass_count, 2);
        assert_eq!(snap.marked_count, 1);
        assert_eq!(snap.processing_time_ns, 1000);
    }

    #[test]
    fn test_pipeline_metrics() {
        let metrics = PipelineMetrics::new();
        // Should have all 8 stages (v4 spec)
        assert_eq!(metrics.stages.len(), 8);
        // Should be able to get each v4 stage
        assert!(metrics.get(PipelineStage::IpFilter).is_some());
        assert!(metrics.get(PipelineStage::FlowTracker).is_some());
        assert!(metrics.get(PipelineStage::Layer2Detect).is_some());
        assert!(metrics.get(PipelineStage::WasmPlugins).is_some());
        assert!(metrics.get(PipelineStage::Correlation).is_some());
    }

    #[test]
    fn test_is_stage_enabled() {
        let mut config = PipelineConfig::default();
        assert!(config.is_stage_enabled(PipelineStage::IpFilter));
        assert!(config.is_stage_enabled(PipelineStage::FlowTracker));
        assert!(config.is_stage_enabled(PipelineStage::Layer2Detect));

        config.enable_ipfilter = false;
        assert!(!config.is_stage_enabled(PipelineStage::IpFilter));

        config.enable_layer2detect = false;
        assert!(!config.is_stage_enabled(PipelineStage::Layer2Detect));

        config.enable_flows = false;
        assert!(!config.is_stage_enabled(PipelineStage::FlowTracker));
    }
}

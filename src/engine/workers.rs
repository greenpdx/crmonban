//! Worker thread pool for packet processing
//!
//! Manages multiple worker threads for parallel packet processing.
//!
//! ## Pipeline Stage Order (v3 spec)
//!
//! 1. Flow Tracking - connection state tracking
//! 2. Port Scan Detection - NULL/XMAS/FIN/Maimon/ACK/SYN scans
//! 3. Brute Force Detection - session-based login attempt tracking
//! 4. Signature Matching - Aho-Corasick + rule verification
//! 5. Threat Intel - IOC lookups
//! 6. Protocol Analysis - HTTP/DNS/TLS/SSH parsers
//! 7. ML Anomaly Detection - flow-based scoring
//! 8. Correlation - DB write + alert generation (only if marked)
//!
//! Stage order is configurable via PipelineConfig::stage_order.
//! Each stage has pass_count and marked_count counters for debugging.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{trace, debug};

use crate::brute_force::BruteForceTracker;
use crate::core::event::{DetectionEvent, DetectionType, Severity};
use crate::core::packet::Packet;
use crate::scan_detect::{ScanDetectEngine, ScanDetectConfig, Classification, AlertType};

use super::pipeline::{PipelineConfig, PipelineStage, PipelineMetrics};

/// Worker pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Number of worker threads (0 = auto)
    pub num_workers: usize,
    /// Queue depth per worker
    pub queue_depth: usize,
    /// Enable CPU affinity
    pub cpu_affinity: bool,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            num_workers: 0, // Auto-detect
            queue_depth: 1000,
            cpu_affinity: false,
        }
    }
}

impl WorkerConfig {
    /// Get actual number of workers
    pub fn actual_workers(&self) -> usize {
        if self.num_workers == 0 {
            num_cpus::get().max(1)
        } else {
            self.num_workers
        }
    }
}

/// Worker pool for parallel packet processing
pub struct WorkerPool {
    /// Configuration
    config: WorkerConfig,
    /// Packets processed counter
    packets_processed: Arc<AtomicU64>,
    /// Events generated counter
    events_generated: Arc<AtomicU64>,
    /// Worker busy time (nanoseconds)
    busy_time_ns: Arc<AtomicU64>,
    /// Total time (nanoseconds)
    total_time_ns: Arc<AtomicU64>,
    /// Start time
    start_time: Instant,
    /// Scan detection engine
    scan_detect_engine: ScanDetectEngine,
    /// Brute force tracker
    brute_force_tracker: BruteForceTracker,
    /// Per-stage metrics
    stage_metrics: PipelineMetrics,
    /// Last metrics log time
    last_metrics_log: Instant,
}

impl WorkerPool {
    /// Create a new worker pool
    pub fn new(config: WorkerConfig) -> Self {
        Self {
            config,
            packets_processed: Arc::new(AtomicU64::new(0)),
            events_generated: Arc::new(AtomicU64::new(0)),
            busy_time_ns: Arc::new(AtomicU64::new(0)),
            total_time_ns: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            scan_detect_engine: ScanDetectEngine::new(ScanDetectConfig::default()),
            brute_force_tracker: BruteForceTracker::new(),
            stage_metrics: PipelineMetrics::new(),
            last_metrics_log: Instant::now(),
        }
    }

    /// Process a packet and return generated events
    ///
    /// Processes packet through stages in order defined by config.stage_order:
    /// Default v3 order: Flow → Scan → Brute → Sig → Intel → Proto → ML → Corr
    pub fn process(&mut self, packet: Packet, config: &PipelineConfig) -> Vec<DetectionEvent> {
        let start = Instant::now();
        let mut events = Vec::new();
        let mut is_marked = false;

        // Extract TCP flags once for all stages
        let is_syn = packet.tcp_flags.as_ref().map(|f| f.syn && !f.ack).unwrap_or(false);
        let is_syn_ack = packet.tcp_flags.as_ref().map(|f| f.syn && f.ack).unwrap_or(false);
        let is_ack = packet.tcp_flags.as_ref().map(|f| f.ack && !f.syn).unwrap_or(false);
        let is_rst = packet.tcp_flags.as_ref().map(|f| f.rst).unwrap_or(false);
        let is_fin = packet.tcp_flags.as_ref().map(|f| f.fin).unwrap_or(false);
        let is_psh = packet.tcp_flags.as_ref().map(|f| f.psh).unwrap_or(false);
        let is_urg = packet.tcp_flags.as_ref().map(|f| f.urg).unwrap_or(false);

        // Process through each stage in configured order
        for stage in &config.stage_order {
            // Skip disabled stages
            if !config.is_stage_enabled(*stage) {
                continue;
            }

            let stage_start = Instant::now();
            let stage_marked = match stage {
                // Stage 1: Flow Tracking
                PipelineStage::FlowTracker => {
                    trace!("Stage 1: Flow tracking");
                    // Flow tracking - connection state machine
                    // TODO: implement flow table
                    false
                }

                // Stage 2: Port Scan Detection
                PipelineStage::ScanDetection => {
                    trace!("Stage 2: Port scan detection");
                    if let Some(alert) = self.scan_detect_engine.process_packet_full(
                        packet.src_ip,
                        packet.dst_port,
                        is_syn, is_syn_ack, is_ack, is_rst,
                        is_fin, is_psh, is_urg,
                        packet.payload.len(),
                        None, None,
                    ) {
                        let severity = match alert.severity() {
                            s if s >= 8 => Severity::Critical,
                            s if s >= 6 => Severity::High,
                            s if s >= 4 => Severity::Medium,
                            _ => Severity::Low,
                        };
                        let classification_str = match alert.classification {
                            Classification::Normal => "normal",
                            Classification::Suspicious => "suspicious",
                            Classification::ProbableScan => "probable scan",
                            Classification::LikelyAttack => "likely attack",
                            Classification::ConfirmedScan => "confirmed scan",
                            Classification::NetworkIssue => "network issue",
                            Classification::Unverifiable => "unverifiable",
                        };
                        let (alert_type_str, score) = match &alert.alert_type {
                            AlertType::Suspicious { score } => ("suspicious activity", *score),
                            AlertType::ProbableScan { score, .. } => ("probable port scan", *score),
                            AlertType::LikelyAttack { score, .. } => ("likely attack", *score),
                            AlertType::ConfirmedScan { score, .. } => ("confirmed scan", *score),
                            AlertType::VerifiedAttack { score, .. } => ("verified attack", *score),
                            AlertType::NetworkIssue { .. } => ("network issue", 0.0),
                        };
                        let evidence = alert.top_rules.first()
                            .map(|(rule, _)| rule.clone())
                            .unwrap_or_default();
                        events.push(
                            DetectionEvent::new(
                                DetectionType::PortScan,
                                severity,
                                alert.src_ip,
                                packet.dst_ip,
                                format!("{} {} ({}): {} unique ports, score={:.1}",
                                    classification_str, alert_type_str, evidence,
                                    alert.unique_ports, score),
                            )
                            .with_detector("scan_detect")
                            .with_ports(packet.src_port, packet.dst_port)
                        );
                        true
                    } else {
                        false
                    }
                }

                // Stage 3: Brute Force Detection
                PipelineStage::BruteForceDetection => {
                    trace!("Stage 3: Brute force detection");
                    let brute_force_alert = if is_syn {
                        self.brute_force_tracker.session_start(packet.src_ip, packet.dst_ip, packet.dst_port);
                        None
                    } else if is_fin || is_rst {
                        self.brute_force_tracker.session_end(packet.src_ip, packet.dst_ip, packet.dst_port, is_rst)
                    } else {
                        self.brute_force_tracker.session_packet(packet.src_ip, packet.dst_ip, packet.dst_port, packet.payload.len());
                        None
                    };

                    if let Some(alert) = brute_force_alert {
                        let severity = match alert.severity() {
                            s if s >= 8 => Severity::Critical,
                            s if s >= 6 => Severity::High,
                            s if s >= 4 => Severity::Medium,
                            _ => Severity::Low,
                        };
                        events.push(
                            DetectionEvent::new(
                                DetectionType::BruteForce,
                                severity,
                                alert.src_ip,
                                alert.dst_ip,
                                format!("Brute force on {} ({}): {} attempts",
                                    alert.service, alert.dst_port, alert.attempt_count),
                            )
                            .with_detector("brute_force")
                            .with_ports(packet.src_port, alert.dst_port)
                        );
                        true
                    } else {
                        false
                    }
                }

                // Stage 4: Signature Matching
                PipelineStage::SignatureMatching => {
                    trace!("Stage 4: Signature matching");
                    // TODO: integrate SignatureEngine here
                    // For now, sample detection for sensitive ports
                    if packet.dst_port == 22 || packet.dst_port == 3389 {
                        events.push(self.create_event(
                            &packet,
                            DetectionType::SignatureMatch,
                            Severity::Low,
                            "Connection to sensitive service",
                        ));
                        true
                    } else {
                        false
                    }
                }

                // Stage 5: Threat Intel
                PipelineStage::ThreatIntel => {
                    trace!("Stage 5: Threat intel lookup");
                    // TODO: IOC matching
                    false
                }

                // Stage 6: Protocol Analysis
                PipelineStage::ProtocolAnalysis => {
                    trace!("Stage 6: Protocol analysis");
                    // TODO: HTTP/DNS/TLS/SSH parsers
                    false
                }

                // Stage 7: ML Anomaly Detection
                PipelineStage::MLDetection => {
                    trace!("Stage 7: ML detection");
                    // TODO: Flow-based anomaly scoring
                    false
                }

                // Stage 8: Correlation (final stage)
                PipelineStage::Correlation => {
                    trace!("Stage 8: Correlation");
                    // Correlation combines events, writes to DB
                    // Events are already collected, this is where we'd deduplicate
                    // TODO: implement correlation logic
                    !events.is_empty()
                }
            };

            // Update stage metrics
            if let Some(metrics) = self.stage_metrics.get(*stage) {
                metrics.record_pass();
                metrics.record_time(stage_start.elapsed().as_nanos() as u64);
                if stage_marked {
                    metrics.record_marked();
                    is_marked = true;
                }
            }
        }

        // Update global counters
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.events_generated.fetch_add(events.len() as u64, Ordering::Relaxed);

        let elapsed = start.elapsed().as_nanos() as u64;
        self.busy_time_ns.fetch_add(elapsed, Ordering::Relaxed);
        self.total_time_ns.store(
            self.start_time.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );

        // Log stage metrics periodically (every 10 seconds)
        if self.last_metrics_log.elapsed().as_secs() >= 10 {
            self.stage_metrics.log_summary();
            self.last_metrics_log = Instant::now();
        }

        events
    }

    /// Create a detection event from a packet
    fn create_event(
        &self,
        packet: &Packet,
        event_type: DetectionType,
        severity: Severity,
        message: &str,
    ) -> DetectionEvent {
        DetectionEvent::new(
            event_type,
            severity,
            packet.src_ip,
            packet.dst_ip,
            message.to_string(),
        )
        .with_detector("packet_engine")
        .with_ports(packet.src_port, packet.dst_port)
        .with_protocol(&format!("{:?}", packet.protocol))
    }

    /// Get worker utilization (0.0-1.0)
    pub fn utilization(&self) -> f64 {
        let busy = self.busy_time_ns.load(Ordering::Relaxed) as f64;
        let total = self.total_time_ns.load(Ordering::Relaxed) as f64;

        if total > 0.0 {
            (busy / total).min(1.0)
        } else {
            0.0
        }
    }

    /// Get packets processed
    pub fn packets_processed(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }

    /// Get events generated
    pub fn events_generated(&self) -> u64 {
        self.events_generated.load(Ordering::Relaxed)
    }

    /// Get number of workers
    pub fn worker_count(&self) -> usize {
        self.config.actual_workers()
    }

    /// Get reference to scan detect engine
    pub fn scan_detect_engine(&self) -> &ScanDetectEngine {
        &self.scan_detect_engine
    }

    /// Get reference to brute force tracker
    pub fn brute_force_tracker(&self) -> &BruteForceTracker {
        &self.brute_force_tracker
    }

    /// Get reference to stage metrics
    pub fn stage_metrics(&self) -> &PipelineMetrics {
        &self.stage_metrics
    }

    /// Log stage metrics summary
    pub fn log_metrics(&self) {
        self.stage_metrics.log_summary();
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new(WorkerConfig::default())
    }
}

/// Statistics for a single worker
#[derive(Debug, Clone, Default)]
pub struct WorkerStats {
    /// Packets processed by this worker
    pub packets_processed: u64,
    /// Events generated by this worker
    pub events_generated: u64,
    /// Processing errors
    pub errors: u64,
    /// Average processing time (microseconds)
    pub avg_processing_time_us: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::IpProtocol;

    fn make_packet() -> Packet {
        let src_ip = "192.168.1.100".parse().unwrap();
        let dst_ip = "10.0.0.1".parse().unwrap();

        let mut packet = Packet::new(src_ip, dst_ip, IpProtocol::Tcp);
        packet.src_port = 12345;
        packet.dst_port = 80;
        packet.raw_len = 100;
        packet
    }

    #[test]
    fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.num_workers, 0); // Auto
        assert!(config.actual_workers() >= 1);
    }

    #[test]
    fn test_worker_pool_creation() {
        let pool = WorkerPool::default();
        assert!(pool.worker_count() >= 1);
        assert_eq!(pool.packets_processed(), 0);
    }

    #[test]
    fn test_worker_pool_processing() {
        let mut pool = WorkerPool::default();
        let config = PipelineConfig::default();

        let packet = make_packet();
        let events = pool.process(packet, &config);

        assert_eq!(pool.packets_processed(), 1);
        // Normal HTTP packet shouldn't generate events
        assert!(events.is_empty());
    }

    #[test]
    fn test_worker_pool_event_generation() {
        let mut pool = WorkerPool::default();
        let config = PipelineConfig::default();

        // SSH packet should generate event
        let mut packet = make_packet();
        packet.dst_port = 22;

        let events = pool.process(packet, &config);
        assert_eq!(events.len(), 1);
        assert_eq!(pool.events_generated(), 1);
    }

    #[test]
    fn test_worker_utilization() {
        let mut pool = WorkerPool::default();
        let config = PipelineConfig::default();

        // Process some packets
        for _ in 0..100 {
            let packet = make_packet();
            pool.process(packet, &config);
        }

        let util = pool.utilization();
        assert!(util >= 0.0 && util <= 1.0);
    }
}

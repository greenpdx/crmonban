//! Worker thread pool for packet processing
//!
//! Manages multiple worker threads for parallel packet processing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::brute_force::{BruteForceTracker, BruteForceAlert};
use crate::core::event::{DetectionEvent, DetectionType, DetectionAction, Severity};
use crate::core::packet::Packet;
use crate::scan_detect::{PortScanTracker, ScanAlert, ScanType};

use super::pipeline::PipelineConfig;

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
    /// Port scan tracker
    port_scan_tracker: PortScanTracker,
    /// Brute force tracker
    brute_force_tracker: BruteForceTracker,
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
            port_scan_tracker: PortScanTracker::new(),
            brute_force_tracker: BruteForceTracker::new(),
        }
    }

    /// Process a packet and return generated events
    pub fn process(&mut self, packet: Packet, config: &PipelineConfig) -> Vec<DetectionEvent> {
        let start = Instant::now();
        let mut events = Vec::new();

        // Process through each enabled stage
        if config.enable_flows {
            // Flow tracking would go here
            trace!("Flow tracking for packet");
        }

        if config.enable_protocols {
            // Protocol analysis would go here
            trace!("Protocol analysis for packet");
        }

        if config.enable_signatures {
            // Signature matching - generate sample event for certain ports
            if packet.dst_port == 22 || packet.dst_port == 3389 {
                events.push(self.create_event(
                    &packet,
                    DetectionType::SignatureMatch,
                    Severity::Low,
                    "Connection to sensitive service",
                ));
            }
        }

        if config.enable_intel {
            // Threat intel lookup would go here
            trace!("Threat intel lookup for packet");
        }

        if config.enable_ml {
            // ML detection would go here on flow completion
            trace!("ML detection check");
        }

        // Port scan detection
        if config.enable_scan_detect {
            let is_syn = packet.tcp_flags.as_ref().map(|f| f.syn && !f.ack).unwrap_or(false);
            if let Some(alert) = self.port_scan_tracker.track(packet.src_ip, packet.dst_port, is_syn) {
                let severity = match alert.severity() {
                    s if s >= 8 => Severity::Critical,
                    s if s >= 6 => Severity::High,
                    s if s >= 4 => Severity::Medium,
                    _ => Severity::Low,
                };
                let scan_type_str = match alert.scan_type {
                    ScanType::Targeted => "targeted",
                    ScanType::Horizontal => "horizontal",
                };
                events.push(
                    DetectionEvent::new(
                        DetectionType::PortScan,
                        severity,
                        packet.src_ip,
                        packet.dst_ip,
                        format!("{} port scan: {} unique ports", scan_type_str, alert.unique_ports),
                    )
                    .with_detector("scan_detector")
                    .with_ports(packet.src_port, packet.dst_port)
                );
            }
        }

        // Brute force detection
        if config.enable_brute_force {
            let is_syn = packet.tcp_flags.as_ref().map(|f| f.syn && !f.ack).unwrap_or(false);
            let is_fin = packet.tcp_flags.as_ref().map(|f| f.fin).unwrap_or(false);
            let is_rst = packet.tcp_flags.as_ref().map(|f| f.rst).unwrap_or(false);

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
                        format!("Brute force attack on {} ({}): {} attempts",
                            alert.service, alert.dst_port, alert.attempt_count),
                    )
                    .with_detector("brute_force_detector")
                    .with_ports(packet.src_port, alert.dst_port)
                );
            }
        }

        // Update counters
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.events_generated.fetch_add(events.len() as u64, Ordering::Relaxed);

        let elapsed = start.elapsed().as_nanos() as u64;
        self.busy_time_ns.fetch_add(elapsed, Ordering::Relaxed);
        self.total_time_ns.store(
            self.start_time.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );

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

    /// Get reference to port scan tracker
    pub fn port_scan_tracker(&self) -> &PortScanTracker {
        &self.port_scan_tracker
    }

    /// Get reference to brute force tracker
    pub fn brute_force_tracker(&self) -> &BruteForceTracker {
        &self.brute_force_tracker
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

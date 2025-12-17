//! DoS (Denial of Service) Detection Module
//!
//! Provides a unified DoS detection pipeline that orchestrates multiple
//! detection engines:
//! - SYN flood detection (volume-based)
//! - (Future) UDP flood detection
//! - (Future) ICMP flood detection
//! - (Future) Amplification attack detection
//!
//! The DoSDetector acts as a pipeline that runs packets through all enabled
//! detection engines and aggregates alerts.

pub mod syn_flood;

use std::time::Instant;
use serde::{Deserialize, Serialize};

use crate::core::analysis::PacketAnalysis;
use crate::core::packet::Packet;
use crate::core::event::{DetectionEvent, DetectionType, Severity};
use crate::engine::pipeline::{PipelineConfig, PipelineStage, StageProcessor};

pub use syn_flood::{
    SynFloodDetector, SynFloodConfig, SynFloodAlert, FloodType,
    FloodMetrics, FloodSeverity,
};

/// Unified DoS alert that wraps alerts from different detectors
#[derive(Debug, Clone)]
pub enum DoSAlert {
    /// SYN flood alert
    SynFlood(SynFloodAlert),
    // Future: UdpFlood(UdpFloodAlert),
    // Future: IcmpFlood(IcmpFloodAlert),
    // Future: Amplification(AmplificationAlert),
}

impl DoSAlert {
    /// Get severity as a numeric score (0-10)
    pub fn severity_score(&self) -> u8 {
        match self {
            DoSAlert::SynFlood(alert) => match alert.severity {
                FloodSeverity::Critical => 9,
                FloodSeverity::High => 7,
                FloodSeverity::Warning => 4,
            },
        }
    }

    /// Get the severity level
    pub fn severity(&self) -> Severity {
        match self.severity_score() {
            s if s >= 8 => Severity::Critical,
            s if s >= 6 => Severity::High,
            s if s >= 4 => Severity::Medium,
            _ => Severity::Low,
        }
    }

    /// Convert to DetectionEvent
    pub fn to_detection_event(&self, packet: &Packet) -> DetectionEvent {
        match self {
            DoSAlert::SynFlood(alert) => {
                let description = format!(
                    "{:?} from {}: {} pps, {} half-open, {} ports ({})",
                    alert.flood_type,
                    alert.source_ip,
                    alert.packets_per_sec,
                    alert.half_open_count,
                    alert.unique_ports,
                    alert.description,
                );

                DetectionEvent::new(
                    DetectionType::DoS,
                    self.severity(),
                    alert.source_ip,
                    packet.dst_ip(),
                    description,
                )
                .with_detector("dos_detector")
                .with_ports(packet.src_port(), packet.dst_port())
            }
        }
    }
}

/// Configuration for the unified DoS detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoSConfig {
    /// Enable DoS detection
    pub enabled: bool,
    /// SYN flood detector configuration
    pub syn_flood: SynFloodConfig,
    // Future: pub udp_flood: UdpFloodConfig,
    // Future: pub icmp_flood: IcmpFloodConfig,
    // Future: pub amplification: AmplificationConfig,
}

impl Default for DoSConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            syn_flood: SynFloodConfig::default(),
        }
    }
}

/// Unified DoS detector that orchestrates multiple detection engines
///
/// This is the main entry point for DoS detection. It processes packets
/// through all enabled sub-detectors and returns aggregated alerts.
pub struct DoSDetector {
    config: DoSConfig,
    /// SYN flood detector
    syn_flood_detector: SynFloodDetector,
    // Future: udp_flood_detector: UdpFloodDetector,
    // Future: icmp_flood_detector: IcmpFloodDetector,
    // Future: amplification_detector: AmplificationDetector,
    /// Statistics
    packets_processed: u64,
    alerts_generated: u64,
    last_alert_time: Option<Instant>,
}

impl DoSDetector {
    /// Create a new DoS detector with default configuration
    pub fn new() -> Self {
        Self::with_config(DoSConfig::default())
    }

    /// Create a new DoS detector with custom configuration
    pub fn with_config(config: DoSConfig) -> Self {
        Self {
            syn_flood_detector: SynFloodDetector::new(config.syn_flood.clone()),
            config,
            packets_processed: 0,
            alerts_generated: 0,
            last_alert_time: None,
        }
    }

    /// Process a packet through all DoS detection engines
    ///
    /// Returns alerts from any detector that triggers. Multiple alerts
    /// can be generated for a single packet if it triggers multiple
    /// detection engines.
    pub fn process_packet(&mut self, packet: &Packet) -> Vec<DoSAlert> {
        if !self.config.enabled {
            return Vec::new();
        }

        self.packets_processed += 1;
        let mut alerts = Vec::new();

        // SYN flood detection (TCP only, checks internally)
        if self.config.syn_flood.enabled {
            if let Some(syn_alert) = self.syn_flood_detector.process(packet) {
                alerts.push(DoSAlert::SynFlood(syn_alert));
            }
        }

        // Future: UDP flood detection
        // if self.config.udp_flood.enabled {
        //     if let Some(udp_alert) = self.udp_flood_detector.process(packet) {
        //         alerts.push(DoSAlert::UdpFlood(udp_alert));
        //     }
        // }

        // Future: ICMP flood detection
        // if self.config.icmp_flood.enabled {
        //     if let Some(icmp_alert) = self.icmp_flood_detector.process(packet) {
        //         alerts.push(DoSAlert::IcmpFlood(icmp_alert));
        //     }
        // }

        // Future: Amplification attack detection
        // if self.config.amplification.enabled {
        //     if let Some(amp_alert) = self.amplification_detector.process(packet) {
        //         alerts.push(DoSAlert::Amplification(amp_alert));
        //     }
        // }

        if !alerts.is_empty() {
            self.alerts_generated += alerts.len() as u64;
            self.last_alert_time = Some(Instant::now());
        }

        alerts
    }

    /// Get statistics
    pub fn stats(&self) -> DoSStats {
        DoSStats {
            packets_processed: self.packets_processed,
            alerts_generated: self.alerts_generated,
            syn_flood_tracked_sources: self.syn_flood_detector.tracked_sources(),
            syn_flood_global_half_open: self.syn_flood_detector.global_half_open(),
        }
    }

    /// Check if detection is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get reference to SYN flood detector
    pub fn syn_flood_detector(&self) -> &SynFloodDetector {
        &self.syn_flood_detector
    }
}

impl Default for DoSDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StageProcessor for DoSDetector {
    fn process(&mut self, mut analysis: PacketAnalysis, _config: &PipelineConfig) -> PacketAnalysis {
        let alerts = self.process_packet(&analysis.packet);
        for alert in alerts {
            let event = alert.to_detection_event(&analysis.packet);
            analysis.add_event(event);
        }
        analysis
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::DoSDetection
    }
}

/// DoS detection statistics
#[derive(Debug, Clone, Default)]
pub struct DoSStats {
    /// Total packets processed
    pub packets_processed: u64,
    /// Total alerts generated
    pub alerts_generated: u64,
    /// SYN flood: tracked source IPs
    pub syn_flood_tracked_sources: usize,
    /// SYN flood: global half-open connections
    pub syn_flood_global_half_open: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::core::packet::{IpProtocol, TcpFlags};

    fn make_syn_packet(src_ip: Ipv4Addr, dst_port: u16, src_port: u16) -> Packet {
        let mut pkt = Packet::new(
            0,
            IpAddr::V4(src_ip),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
            "lo",
        );
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = src_port;
            tcp.dst_port = dst_port;
            tcp.flags = TcpFlags { syn: true, ..Default::default() };
        }
        pkt
    }

    #[test]
    fn test_dos_detector_new() {
        let detector = DoSDetector::new();
        assert!(detector.is_enabled());
        let stats = detector.stats();
        assert_eq!(stats.packets_processed, 0);
        assert_eq!(stats.alerts_generated, 0);
    }

    #[test]
    fn test_dos_detector_disabled() {
        let config = DoSConfig {
            enabled: false,
            ..Default::default()
        };
        let mut detector = DoSDetector::with_config(config);

        let pkt = make_syn_packet(Ipv4Addr::new(192, 168, 1, 100), 80, 50000);
        let alerts = detector.process_packet(&pkt);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_dos_detector_processes_packets() {
        let mut detector = DoSDetector::new();

        let pkt = make_syn_packet(Ipv4Addr::new(192, 168, 1, 100), 80, 50000);
        let _ = detector.process_packet(&pkt);

        let stats = detector.stats();
        assert_eq!(stats.packets_processed, 1);
    }

    #[test]
    fn test_dos_alert_severity() {
        let alert = DoSAlert::SynFlood(SynFloodAlert {
            flood_type: FloodType::SynFlood,
            severity: FloodSeverity::Critical,
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            target_port: Some(80),
            packets_per_sec: 1500,
            duration_secs: 10,
            half_open_count: 5000,
            unique_ports: 1,
            confidence: 0.9,
            description: "test alert".to_string(),
            timestamp: Instant::now(),
        });

        assert_eq!(alert.severity_score(), 9);
        assert_eq!(alert.severity(), Severity::Critical);
    }

    #[test]
    fn test_dos_alert_to_detection_event() {
        let pkt = make_syn_packet(Ipv4Addr::new(192, 168, 1, 100), 80, 50000);
        let alert = DoSAlert::SynFlood(SynFloodAlert {
            flood_type: FloodType::SynFlood,
            severity: FloodSeverity::High,
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            target_port: Some(80),
            packets_per_sec: 500,
            duration_secs: 5,
            half_open_count: 1000,
            unique_ports: 1,
            confidence: 0.8,
            description: "test".to_string(),
            timestamp: Instant::now(),
        });

        let event = alert.to_detection_event(&pkt);
        assert!(matches!(event.event_type, DetectionType::DoS));
        assert_eq!(event.severity, Severity::High);
    }
}

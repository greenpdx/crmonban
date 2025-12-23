//! Protocol detection and routing
//!
//! Automatically detects application protocol and routes to appropriate analyzer.

use crate::core::{PacketAnalysis, DetectionEvent, DetectionType, Severity, Flow, Packet};
use crate::engine::pipeline::{PipelineConfig, PipelineStage, StageProcessor};
use super::AppProtocol;
use super::{
    ProtocolAnalyzer, ProtocolConfig, ProtocolEvent,
    HttpAnalyzer, DnsAnalyzer, TlsAnalyzer,
};

/// Protocol detector that routes packets to appropriate analyzers
pub struct ProtocolDetector {
    config: ProtocolConfig,
    http: HttpAnalyzer,
    dns: DnsAnalyzer,
    tls: TlsAnalyzer,
}

impl ProtocolDetector {
    /// Create a new protocol detector
    pub fn new(config: ProtocolConfig) -> Self {
        Self {
            http: HttpAnalyzer::new(config.http.clone()),
            dns: DnsAnalyzer::new(config.dns.clone()),
            tls: TlsAnalyzer::new(config.tls.clone()),
            config,
        }
    }

    /// Analyze a packet and return protocol events
    pub fn analyze(&self, packet: &Packet, flow: &mut Flow) -> Vec<ProtocolEvent> {
        if !self.config.enabled || packet.payload().is_empty() {
            return Vec::new();
        }

        let mut events = Vec::new();

        // Try to detect protocol
        let detected = self.detect_protocol(packet, flow);

        // Update flow's app protocol if we detected one
        if detected != AppProtocol::Unknown && flow.app_protocol == AppProtocol::Unknown {
            flow.app_protocol = detected;
        }

        // Parse based on detected/configured protocol
        match flow.app_protocol {
            AppProtocol::Http => {
                if let Some(event) = self.http.parse(packet, flow) {
                    events.push(event);
                }
            }
            AppProtocol::Dns => {
                if let Some(event) = self.dns.parse(packet, flow) {
                    events.push(event);
                }
            }
            AppProtocol::Https => {
                if let Some(event) = self.tls.parse(packet, flow) {
                    events.push(event);
                }
            }
            _ => {
                // Try TLS detection on common TLS ports
                if self.config.tls.ports.contains(&packet.dst_port())
                    || self.config.tls.ports.contains(&packet.src_port())
                {
                    if let Some(event) = self.tls.parse(packet, flow) {
                        flow.app_protocol = AppProtocol::Https;
                        events.push(event);
                    }
                }
            }
        }

        events
    }

    /// Detect protocol from packet payload
    fn detect_protocol(&self, packet: &Packet, _flow: &Flow) -> AppProtocol {
        let payload = &packet.payload();
        if payload.is_empty() {
            return AppProtocol::Unknown;
        }

        // Check HTTP
        if self.config.http.enabled && self.http.detect(payload, packet.dst_port()) {
            return AppProtocol::Http;
        }

        // Check DNS
        if self.config.dns.enabled && self.dns.detect(payload, packet.dst_port()) {
            return AppProtocol::Dns;
        }

        // Check TLS
        if self.config.tls.enabled && self.tls.detect(payload, packet.dst_port()) {
            return AppProtocol::Https;
        }

        // Fall back to port-based detection
        AppProtocol::from_port(packet.dst_port(), packet.protocol())
    }

    /// Get HTTP analyzer
    pub fn http(&self) -> &HttpAnalyzer {
        &self.http
    }

    /// Get DNS analyzer
    pub fn dns(&self) -> &DnsAnalyzer {
        &self.dns
    }

    /// Get TLS analyzer
    pub fn tls(&self) -> &TlsAnalyzer {
        &self.tls
    }

    /// Convert protocol event to detection event (for anomalies/alerts)
    /// Note: Current ProtocolEvent doesn't have anomaly variants, so this always returns None.
    /// Anomalies would need to be detected by analyzers and stored in ProtocolEvent.
    #[allow(dead_code, unused_variables)]
    fn event_to_detection(&self, pe: &ProtocolEvent, packet: &Packet) -> Option<DetectionEvent> {
        // Currently ProtocolEvent doesn't have anomaly variants
        // When anomaly variants are added, match on them here
        None
    }
}

impl StageProcessor<PipelineConfig, PipelineStage> for ProtocolDetector {
    fn process(&mut self, mut analysis: PacketAnalysis, _config: &PipelineConfig) -> PacketAnalysis {
        // Need a mutable flow to analyze
        if let Some(ref mut flow) = analysis.flow {
            let events = self.analyze(&analysis.packet, flow);

            // Convert any anomaly events to detection events
            for pe in &events {
                if let Some(event) = self.event_to_detection(pe, &analysis.packet) {
                    analysis.add_event(event);
                }
            }
        }

        analysis
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::ProtocolAnalysis
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::IpProtocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_packet(payload: &[u8], dst_port: u16) -> Packet {
        let mut pkt = Packet::new(
            0,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
            "lo",
        );
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = 54321;
            tcp.dst_port = dst_port;
            tcp.payload = payload.to_vec();
        }
        pkt
    }

    #[test]
    fn test_http_detection() {
        let config = ProtocolConfig::default();
        let detector = ProtocolDetector::new(config);

        let http_request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let pkt = make_packet(http_request, 80);
        let mut flow = Flow::new(1, &pkt);

        let events = detector.analyze(&pkt, &mut flow);

        assert_eq!(flow.app_protocol, AppProtocol::Http);
    }

    #[test]
    fn test_dns_detection() {
        let config = ProtocolConfig::default();
        let detector = ProtocolDetector::new(config);

        // Minimal DNS query header
        let dns_query = [
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
        ];
        let pkt = make_packet(&dns_query, 53);
        let mut flow = Flow::new(1, &pkt);

        let _ = detector.analyze(&pkt, &mut flow);

        assert_eq!(flow.app_protocol, AppProtocol::Dns);
    }
}

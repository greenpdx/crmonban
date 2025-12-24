//! Protocol detection and routing
//!
//! Automatically detects application protocol and routes to appropriate analyzer.
//! Integrates attack detection engines for HTTP, DNS, and TLS.

use std::collections::HashMap;

use crate::core::{PacketAnalysis, DetectionEvent, DetectionType, Severity, Flow, Packet};
use crate::engine::pipeline::{PipelineConfig, PipelineStage, StageProcessor};
use super::AppProtocol;
use super::{
    ProtocolAnalyzer, ProtocolConfig, ProtocolEvent,
    HttpAnalyzer, DnsAnalyzer, TlsAnalyzer, HttpTransaction, DnsMessage, TlsEvent,
};

// HTTP attack detection engine
use crmonban_detection::{DetectionEngine as HttpAttackEngine, ScanReport};

/// Protocol detector that routes packets to appropriate analyzers
/// and runs attack detection on parsed protocol data
pub struct ProtocolDetector {
    config: ProtocolConfig,
    http: HttpAnalyzer,
    dns: DnsAnalyzer,
    tls: TlsAnalyzer,
    /// HTTP attack detection engine (optional - requires patterns file)
    http_attack_engine: Option<HttpAttackEngine>,
}

impl ProtocolDetector {
    /// Create a new protocol detector
    pub fn new(config: ProtocolConfig) -> Self {
        Self {
            http: HttpAnalyzer::new(config.http.clone()),
            dns: DnsAnalyzer::new(config.dns.clone()),
            tls: TlsAnalyzer::new(config.tls.clone()),
            config,
            http_attack_engine: None,
        }
    }

    /// Create a new protocol detector with HTTP attack detection
    pub fn with_http_attack_engine(config: ProtocolConfig, patterns_file: &str) -> Self {
        let http_attack_engine = HttpAttackEngine::from_file(patterns_file)
            .map_err(|e| tracing::warn!("Failed to load HTTP attack patterns: {}", e))
            .ok();

        Self {
            http: HttpAnalyzer::new(config.http.clone()),
            dns: DnsAnalyzer::new(config.dns.clone()),
            tls: TlsAnalyzer::new(config.tls.clone()),
            config,
            http_attack_engine,
        }
    }

    /// Set the HTTP attack engine
    pub fn set_http_attack_engine(&mut self, engine: HttpAttackEngine) {
        self.http_attack_engine = Some(engine);
    }

    /// Check if HTTP attack detection is enabled
    pub fn has_http_attack_engine(&self) -> bool {
        self.http_attack_engine.is_some()
    }

    /// Analyze HTTP transaction for attacks
    fn analyze_http_attacks(&self, tx: &HttpTransaction, packet: &Packet) -> Vec<DetectionEvent> {
        let engine = match &self.http_attack_engine {
            Some(e) => e,
            None => return Vec::new(),
        };

        let mut events = Vec::new();

        if let Some(ref request) = tx.request {
            // Build headers map
            let headers: HashMap<String, String> = request.headers.clone();

            // Get body as string if present
            let body = if request.body.is_empty() {
                None
            } else {
                std::str::from_utf8(&request.body).ok()
            };

            // Scan the request
            let report: ScanReport = engine.scan_request(
                &request.method,
                &request.uri,
                &headers,
                body,
            );

            // Convert detections to DetectionEvents
            for detection in report.detections {
                let severity = match detection.severity {
                    crmonban_detection::Severity::Critical => Severity::Critical,
                    crmonban_detection::Severity::High => Severity::High,
                    crmonban_detection::Severity::Medium => Severity::Medium,
                    crmonban_detection::Severity::Low => Severity::Low,
                    crmonban_detection::Severity::Info => Severity::Info,
                };

                let detection_type = match detection.category.as_str() {
                    "sql_injection" => DetectionType::SqlInjection,
                    "xss" => DetectionType::Xss,
                    "path_traversal" => DetectionType::PathTraversal,
                    "command_injection" => DetectionType::CommandInjection,
                    "rce" => DetectionType::CommandInjection,
                    _ => DetectionType::Custom(format!("http:{}", detection.category)),
                };

                let event = DetectionEvent::new(
                    detection_type,
                    severity,
                    packet.src_ip(),
                    packet.dst_ip(),
                    format!("{}: {} (pattern: {})",
                        detection.category,
                        detection.description,
                        detection.matched_pattern
                    ),
                )
                .with_detector("httpAttack")
                .with_confidence(0.9)
                .with_ports(packet.src_port(), packet.dst_port());

                events.push(event);
            }
        }

        events
    }

    /// Analyze DNS message for attacks
    fn analyze_dns_attacks(&self, msg: &DnsMessage, packet: &Packet) -> Vec<DetectionEvent> {
        let mut events = Vec::new();

        // Check for DNS tunneling via the DNS analyzer's detect_tunneling method
        for query in &msg.queries {
            if self.dns.detect_tunneling(query) {
                let event = DetectionEvent::new(
                    DetectionType::DnsTunneling,
                    Severity::High,
                    packet.src_ip(),
                    packet.dst_ip(),
                    format!("DNS tunneling detected: {} (type {:?})", query.name, query.qtype),
                )
                .with_detector("dnsAnalyzer")
                .with_confidence(0.85)
                .with_ports(packet.src_port(), packet.dst_port());

                events.push(event);
            }

            // Check for DGA-like domain names (high entropy, random-looking)
            if self.detect_dga_domain(&query.name) {
                let event = DetectionEvent::new(
                    DetectionType::DnsDga,
                    Severity::Medium,
                    packet.src_ip(),
                    packet.dst_ip(),
                    format!("Possible DGA domain: {}", query.name),
                )
                .with_detector("dnsAnalyzer")
                .with_confidence(0.7)
                .with_ports(packet.src_port(), packet.dst_port());

                events.push(event);
            }
        }

        // Check for DNS amplification (large responses to small queries)
        if msg.is_response && !msg.answers.is_empty() {
            let answer_count = msg.answers.len() + msg.authorities.len() + msg.additionals.len();
            if answer_count > 10 {
                let event = DetectionEvent::new(
                    DetectionType::DnsAmplification,
                    Severity::Medium,
                    packet.src_ip(),
                    packet.dst_ip(),
                    format!("Potential DNS amplification: {} records in response", answer_count),
                )
                .with_detector("dnsAnalyzer")
                .with_confidence(0.6)
                .with_ports(packet.src_port(), packet.dst_port());

                events.push(event);
            }
        }

        events
    }

    /// Detect DGA (Domain Generation Algorithm) domain names
    fn detect_dga_domain(&self, domain: &str) -> bool {
        // Skip well-known TLDs and short domains
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return false;
        }

        // Get the main part (excluding TLD)
        let main_part = if parts.len() > 2 {
            parts[..parts.len() - 1].join(".")
        } else {
            parts[0].to_string()
        };

        // Skip short names
        if main_part.len() < 10 {
            return false;
        }

        // Calculate entropy
        let mut char_counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
        for c in main_part.chars() {
            *char_counts.entry(c.to_ascii_lowercase()).or_insert(0) += 1;
        }

        let len = main_part.len() as f64;
        let entropy: f64 = char_counts.values()
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum();

        // High entropy (> 3.5) and many numeric characters suggests DGA
        let numeric_ratio = main_part.chars().filter(|c| c.is_ascii_digit()).count() as f64 / len;

        entropy > 3.5 || (entropy > 3.0 && numeric_ratio > 0.3)
    }

    /// Analyze TLS event for attacks
    fn analyze_tls_attacks(&self, tls_event: &TlsEvent, packet: &Packet) -> Vec<DetectionEvent> {
        let mut events = Vec::new();

        match tls_event {
            TlsEvent::ClientHello { ja3, versions, cipher_suites, .. } => {
                // Check for weak/deprecated ciphers
                for cipher in cipher_suites {
                    if Self::is_weak_cipher(*cipher) {
                        let event = DetectionEvent::new(
                            DetectionType::TlsWeakCipher,
                            Severity::Medium,
                            packet.src_ip(),
                            packet.dst_ip(),
                            format!("Weak cipher suite offered: 0x{:04x}", cipher),
                        )
                        .with_detector("tlsAnalyzer")
                        .with_confidence(0.8)
                        .with_ports(packet.src_port(), packet.dst_port());

                        events.push(event);
                        break; // Only alert once per handshake
                    }
                }

                // Check for TLS downgrade (only SSLv3 or TLS 1.0 in supported versions)
                let has_modern = versions.iter().any(|v| *v >= 0x0303); // TLS 1.2+
                if !has_modern && !versions.is_empty() {
                    let event = DetectionEvent::new(
                        DetectionType::TlsDowngrade,
                        Severity::Medium,
                        packet.src_ip(),
                        packet.dst_ip(),
                        format!("Client only supports legacy TLS versions: {:?}", versions),
                    )
                    .with_detector("tlsAnalyzer")
                    .with_confidence(0.7)
                    .with_ports(packet.src_port(), packet.dst_port());

                    events.push(event);
                }

                // Check for known malicious JA3 hashes
                if self.is_known_malicious_ja3(&ja3.hash) {
                    let event = DetectionEvent::new(
                        DetectionType::TlsKnownMalwareJa3,
                        Severity::Critical,
                        packet.src_ip(),
                        packet.dst_ip(),
                        format!("Known malicious JA3 fingerprint: {}", ja3.hash),
                    )
                    .with_detector("tlsAnalyzer")
                    .with_confidence(0.95)
                    .with_ports(packet.src_port(), packet.dst_port());

                    events.push(event);
                }
            }
            TlsEvent::ServerHello { version, cipher_suite, .. } => {
                // Check for weak cipher selection
                if Self::is_weak_cipher(*cipher_suite) {
                    let event = DetectionEvent::new(
                        DetectionType::TlsWeakCipher,
                        Severity::High,
                        packet.src_ip(),
                        packet.dst_ip(),
                        format!("Server selected weak cipher: 0x{:04x}", cipher_suite),
                    )
                    .with_detector("tlsAnalyzer")
                    .with_confidence(0.9)
                    .with_ports(packet.src_port(), packet.dst_port());

                    events.push(event);
                }

                // Check for legacy TLS version
                if *version < 0x0303 {
                    let event = DetectionEvent::new(
                        DetectionType::TlsDowngrade,
                        Severity::Medium,
                        packet.src_ip(),
                        packet.dst_ip(),
                        format!("Server using legacy TLS version: 0x{:04x}", version),
                    )
                    .with_detector("tlsAnalyzer")
                    .with_confidence(0.8)
                    .with_ports(packet.src_port(), packet.dst_port());

                    events.push(event);
                }
            }
            TlsEvent::Certificate { subject, issuer, not_after, .. } => {
                // Check for self-signed certificates
                if subject == issuer {
                    let event = DetectionEvent::new(
                        DetectionType::TlsSelfSigned,
                        Severity::Medium,
                        packet.src_ip(),
                        packet.dst_ip(),
                        format!("Self-signed certificate detected: {}", subject),
                    )
                    .with_detector("tlsAnalyzer")
                    .with_confidence(0.7)
                    .with_ports(packet.src_port(), packet.dst_port());

                    events.push(event);
                }

                // Check for expired certificates (basic check - not_after in past)
                // TODO: Parse not_after and compare with current time
                if not_after.contains("1970") || not_after.contains("expired") {
                    let event = DetectionEvent::new(
                        DetectionType::TlsExpiredCert,
                        Severity::Medium,
                        packet.src_ip(),
                        packet.dst_ip(),
                        format!("Expired certificate detected: not_after={}", not_after),
                    )
                    .with_detector("tlsAnalyzer")
                    .with_confidence(0.6)
                    .with_ports(packet.src_port(), packet.dst_port());

                    events.push(event);
                }
                // TODO: Integrate crvecdb for certificate fingerprint matching
            }
            TlsEvent::HandshakeComplete { .. } => {
                // Handshake completed - no attack detection needed
            }
        }

        events
    }

    /// Check if cipher suite is considered weak
    fn is_weak_cipher(cipher: u16) -> bool {
        // Export ciphers, NULL ciphers, RC4, DES, 3DES
        matches!(cipher,
            0x0000..=0x0003 |  // NULL ciphers
            0x0004..=0x0005 |  // RC4
            0x0006..=0x000A |  // DES/3DES
            0x0014..=0x001E |  // Export ciphers
            0x0024..=0x0027 |  // Export ciphers
            0x002E..=0x0032 |  // DES/3DES
            0x0060..=0x0066 |  // Export ciphers
            0x0084..=0x009F |  // Some legacy ciphers
            0xC002..=0xC006 |  // ECDH NULL
            0xC010..=0xC012    // ECDHE with weak ciphers
        )
    }

    /// Check if JA3 hash is known to be malicious
    /// TODO: Integrate with crvecdb for large-scale fingerprint matching
    fn is_known_malicious_ja3(&self, _ja3_hash: &str) -> bool {
        // Placeholder for JA3 lookup
        // In production, this would query crvecdb or a blocklist
        // Some well-known malicious JA3 hashes:
        // - "e7d705a3286e19ea42f587b344ee6865" (Cobalt Strike)
        // - "05af1f5ca1b87cc9cc9b25185115607d" (Metasploit)
        // - "07f362f0e28d490e9a4bcf18c1fa22ec" (Empire)
        // etc.
        false
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
    async fn process(&mut self, mut analysis: PacketAnalysis, _config: &PipelineConfig) -> PacketAnalysis {
        // Need a mutable flow to analyze
        if let Some(ref mut flow) = analysis.flow {
            let events = self.analyze(&analysis.packet, flow);

            // Store protocol events for later stages (attack engines, ML, correlation)
            analysis.add_protocol_events(events.clone());

            // Run attack detection on protocol events
            for pe in &events {
                match pe {
                    ProtocolEvent::Http(tx) => {
                        // Run HTTP attack detection
                        let attack_events = self.analyze_http_attacks(tx, &analysis.packet);
                        for event in attack_events {
                            analysis.add_event(event);
                        }
                    }
                    ProtocolEvent::Dns(msg) => {
                        // Run DNS attack detection
                        let attack_events = self.analyze_dns_attacks(msg, &analysis.packet);
                        for event in attack_events {
                            analysis.add_event(event);
                        }
                    }
                    ProtocolEvent::Tls(tls_event) => {
                        // Run TLS attack detection
                        let attack_events = self.analyze_tls_attacks(tls_event, &analysis.packet);
                        for event in attack_events {
                            analysis.add_event(event);
                        }
                    }
                    ProtocolEvent::Generic { .. } => {
                        // Generic events - no attack detection
                    }
                }

                // Also check for protocol-level anomalies
                if let Some(event) = self.event_to_detection(pe, &analysis.packet) {
                    analysis.add_event(event);
                }
            }
        }

        analysis
    }

    async fn stage(&self) -> PipelineStage {
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

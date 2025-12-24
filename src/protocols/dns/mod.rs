//! DNS protocol analyzer
//!
//! Parses DNS queries and responses and matches Suricata rules.

pub mod types;
pub mod state;
pub mod parser;
pub mod match_;

pub use types::*;
pub use state::DnsState;
pub use parser::{DnsParser, DnsConfig};
pub use match_::DnsMatcher;

use crate::signatures::ast::Protocol;
use crate::protocols::registry::ProtocolRegistration;

/// Get DNS protocol registration
pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration {
        name: "dns",
        protocol: Protocol::Dns,
        tcp_ports: &[53],
        udp_ports: &[53, 5353],
        create_parser: || Box::new(DnsParser::new()),
        priority: 70, // High priority - common protocol
        keywords: DNS_KEYWORDS,
    }
}

// Legacy compatibility
use crate::core::{Flow, Packet};
use super::{DnsConfig as LegacyDnsConfig, ProtocolAnalyzer, ProtocolEvent};

/// Legacy DNS protocol analyzer for backwards compatibility
pub struct DnsAnalyzer {
    config: LegacyDnsConfig,
    parser: DnsParser,
}

impl DnsAnalyzer {
    pub fn new(config: LegacyDnsConfig) -> Self {
        let parser_config = parser::DnsConfig {
            enabled: config.enabled,
            ports: config.ports.clone(),
            detect_tunneling: config.detect_tunneling,
            detect_dga: true, // Default to true for legacy config
        };

        Self {
            config,
            parser: DnsParser::with_config(parser_config),
        }
    }

    /// Parse DNS message from payload
    pub fn parse_message(&self, payload: &[u8]) -> Option<DnsMessage> {
        self.parser.parse_message(payload)
    }

    /// Detect DNS tunneling attempts
    pub fn detect_tunneling(&self, query: &DnsQuery) -> bool {
        self.parser.detect_tunneling(query)
    }
}

impl ProtocolAnalyzer for DnsAnalyzer {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn detect(&self, payload: &[u8], port: u16) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check port
        if self.config.ports.contains(&port) {
            // Basic validation of DNS header
            if payload.len() >= 12 {
                let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
                if qdcount <= 10 {
                    return true;
                }
            }
        }

        false
    }

    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent> {
        if !self.config.enabled || packet.payload().is_empty() {
            return None;
        }

        let msg = self.parse_message(&packet.payload())?;

        // Store query names in flow
        for query in &msg.queries {
            flow.set_app_data("dns.query", serde_json::json!(&query.name));
            flow.set_app_data("dns.qtype", serde_json::json!(query.qtype.to_string()));

            // Check for tunneling
            if self.config.detect_tunneling && self.detect_tunneling(query) {
                flow.add_tag("dns_tunneling_suspect");
                flow.risk_score = (flow.risk_score + 0.5).min(1.0);
            }
        }

        // Store answer IPs
        for answer in &msg.answers {
            if let DnsRdata::A(ip) = &answer.rdata {
                flow.set_app_data("dns.answer_a", serde_json::json!(ip.to_string()));
            }
            if let DnsRdata::AAAA(ip) = &answer.rdata {
                flow.set_app_data("dns.answer_aaaa", serde_json::json!(ip.to_string()));
            }
        }

        Some(ProtocolEvent::Dns(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query() {
        let config = LegacyDnsConfig::default();
        let analyzer = DnsAnalyzer::new(config);

        let dns_query = [
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let msg = analyzer.parse_message(&dns_query).unwrap();

        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].name, "example.com");
        assert_eq!(msg.queries[0].qtype, DnsRecordType::A);
    }

    #[test]
    fn test_detect_tunneling() {
        let config = LegacyDnsConfig::default();
        let analyzer = DnsAnalyzer::new(config);

        let normal = DnsQuery {
            name: "www.example.com".to_string(),
            qtype: DnsRecordType::A,
            qclass: 1,
        };
        assert!(!analyzer.detect_tunneling(&normal));

        let suspicious = DnsQuery {
            name: "abcdefghij.klmnopqrst.uvwxyz0123.456789abcd.efghijklmn.opqrstuvwx.yzABCDEFGH.IJKLMNOPQR.tunnel.example.com".to_string(),
            qtype: DnsRecordType::TXT,
            qclass: 1,
        };
        assert!(analyzer.detect_tunneling(&suspicious));
    }
}

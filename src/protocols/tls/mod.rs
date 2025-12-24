//! TLS protocol analyzer with JA3/JA3S fingerprinting

pub mod types;
pub mod state;
pub mod parser;
pub mod match_;

pub use types::*;
pub use state::TlsState;
pub use parser::{TlsParser, TlsConfig};
pub use match_::TlsMatcher;

use crate::signatures::ast::Protocol;
use crate::protocols::registry::ProtocolRegistration;

/// Get TLS protocol registration
pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration {
        name: "tls",
        protocol: Protocol::Tls,
        tcp_ports: &[443, 8443, 993, 995, 465, 636],
        udp_ports: &[],
        create_parser: || Box::new(TlsParser::new()),
        priority: 80,
        keywords: TLS_KEYWORDS,
    }
}

// Legacy compatibility
use crate::core::{Flow, Direction, Packet};
use super::{TlsConfig as LegacyTlsConfig, ProtocolAnalyzer, ProtocolEvent, TlsEvent};

pub struct TlsAnalyzer {
    config: LegacyTlsConfig,
    parser: TlsParser,
}

impl TlsAnalyzer {
    pub fn new(config: LegacyTlsConfig) -> Self {
        let parser_config = parser::TlsConfig {
            enabled: config.enabled,
            ports: config.ports.clone(),
            ja3_enabled: config.ja3_enabled,
            ja3s_enabled: config.ja3s_enabled,
        };
        Self { config, parser: TlsParser::with_config(parser_config) }
    }

    pub fn parse_client_hello(&self, data: &[u8]) -> Option<TlsHandshake> {
        self.parser.parse_client_hello(data)
    }
}

impl ProtocolAnalyzer for TlsAnalyzer {
    fn name(&self) -> &'static str { "tls" }

    fn detect(&self, payload: &[u8], port: u16) -> bool {
        if !self.config.enabled { return false; }
        if payload.len() >= 5 {
            let record_type = payload[0];
            let version = u16::from_be_bytes([payload[1], payload[2]]);
            if record_type == 22 && version >= 0x0300 && version <= 0x0304 { return true; }
        }
        self.config.ports.contains(&port)
    }

    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent> {
        if !self.config.enabled || packet.payload().is_empty() { return None; }

        let payload = packet.payload();
        if payload.len() < 5 { return None; }

        let record_type = TlsRecordType::from(payload[0]);
        if record_type != TlsRecordType::Handshake { return None; }

        let length = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        if payload.len() < 5 + length { return None; }

        let record_data = &payload[5..5 + length];
        if record_data.is_empty() { return None; }

        let handshake_type = TlsHandshakeType::from(record_data[0]);

        match (handshake_type, packet.direction) {
            (TlsHandshakeType::ClientHello, Direction::ToServer | Direction::Unknown) => {
                let handshake = self.parse_client_hello(record_data)?;
                if let Some(ref sni) = handshake.sni {
                    flow.set_app_data("tls.sni", serde_json::json!(sni));
                }
                if let Some(ref ja3) = handshake.ja3 {
                    flow.set_app_data("tls.ja3_hash", serde_json::json!(&ja3.hash));
                }

                Some(ProtocolEvent::Tls(TlsEvent::ClientHello {
                    sni: handshake.sni.clone(),
                    ja3: handshake.ja3.clone().unwrap_or_default(),
                    versions: handshake.supported_versions.clone(),
                    cipher_suites: handshake.cipher_suites.clone(),
                }))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_detection() {
        let config = LegacyTlsConfig::default();
        let analyzer = TlsAnalyzer::new(config);
        let tls_header = [22, 0x03, 0x01, 0x00, 0x05];
        assert!(analyzer.detect(&tls_header, 443));
    }
}

//! Protocol analyzers for deep packet inspection
//!
//! Provides parsers and analyzers for application layer protocols:
//! - HTTP: Request/response parsing, header extraction
//! - DNS: Query/answer parsing
//! - TLS: Handshake parsing, JA3/JA3S fingerprinting
//!
//! # Architecture
//!
//! Each protocol module implements the `ProtocolAnalyzer` trait:
//!
//! ```ignore
//! pub trait ProtocolAnalyzer {
//!     fn name(&self) -> &'static str;
//!     fn detect(&self, payload: &[u8], port: u16) -> bool;
//!     fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent>;
//! }
//! ```

pub mod detector;
pub mod http;
pub mod dns;
pub mod tls;

pub use detector::ProtocolDetector;
pub use http::{HttpAnalyzer, HttpRequest, HttpResponse, HttpTransaction};
pub use dns::{DnsAnalyzer, DnsMessage, DnsQuery, DnsAnswer};
pub use tls::{TlsAnalyzer, TlsHandshake, Ja3Fingerprint};

use serde::{Deserialize, Serialize};
use crate::core::flow::Flow;
use crate::core::packet::Packet;

/// Protocol analyzer trait
pub trait ProtocolAnalyzer: Send + Sync {
    /// Protocol name
    fn name(&self) -> &'static str;

    /// Check if payload looks like this protocol
    fn detect(&self, payload: &[u8], port: u16) -> bool;

    /// Parse packet and extract protocol data
    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent>;
}

/// Events emitted by protocol analyzers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolEvent {
    /// HTTP transaction
    Http(HttpTransaction),
    /// DNS message
    Dns(DnsMessage),
    /// TLS handshake event
    Tls(TlsEvent),
    /// Generic protocol event
    Generic {
        protocol: String,
        event_type: String,
        data: serde_json::Value,
    },
}

/// TLS-specific events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsEvent {
    /// Client Hello parsed
    ClientHello {
        sni: Option<String>,
        ja3: Ja3Fingerprint,
        versions: Vec<u16>,
        cipher_suites: Vec<u16>,
    },
    /// Server Hello parsed
    ServerHello {
        ja3s: Ja3Fingerprint,
        version: u16,
        cipher_suite: u16,
    },
    /// Certificate received
    Certificate {
        subject: String,
        issuer: String,
        serial: String,
        not_before: String,
        not_after: String,
        fingerprint_sha256: String,
    },
    /// Handshake complete
    HandshakeComplete {
        version: String,
        cipher_suite: String,
    },
}

/// Configuration for protocol analyzers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    /// Enable protocol analysis
    pub enabled: bool,

    /// HTTP configuration
    pub http: HttpConfig,

    /// DNS configuration
    pub dns: DnsConfig,

    /// TLS configuration
    pub tls: TlsConfig,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            http: HttpConfig::default(),
            dns: DnsConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

/// HTTP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub max_request_body: usize,
    pub max_response_body: usize,
    pub extract_headers: bool,
    pub extract_cookies: bool,
    pub log_requests: bool,
    pub log_responses: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![80, 8080, 8000, 8888, 3000, 5000],
            max_request_body: 1_048_576,  // 1 MB
            max_response_body: 10_485_760, // 10 MB
            extract_headers: true,
            extract_cookies: true,
            log_requests: true,
            log_responses: true,
        }
    }
}

/// DNS analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub log_queries: bool,
    pub log_answers: bool,
    pub detect_tunneling: bool,
    pub max_query_length: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![53],
            log_queries: true,
            log_answers: true,
            detect_tunneling: true,
            max_query_length: 253,
        }
    }
}

/// TLS analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub ja3_enabled: bool,
    pub ja3s_enabled: bool,
    pub extract_certificates: bool,
    pub log_sni: bool,
    pub detect_suspicious: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![443, 8443, 993, 995, 465, 587, 636, 989, 990],
            ja3_enabled: true,
            ja3s_enabled: true,
            extract_certificates: true,
            log_sni: true,
            detect_suspicious: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProtocolConfig::default();
        assert!(config.enabled);
        assert!(config.http.enabled);
        assert!(config.dns.enabled);
        assert!(config.tls.enabled);
    }
}

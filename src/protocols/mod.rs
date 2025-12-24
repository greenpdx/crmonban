//! Protocol analyzers for deep packet inspection
//!
//! Provides parsers and analyzers for application layer protocols:
//! - HTTP: Request/response parsing, header extraction
//! - DNS: Query/answer parsing
//! - TLS: Handshake parsing, JA3/JA3S fingerprinting
//! - SSH: Version detection, HASSH fingerprinting, brute force detection
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

pub mod types;
pub mod detector;
pub mod http;
pub mod dns;
pub mod tls;
pub mod ssh;
pub mod smtp;

// Re-export core protocol types from crmonban-types
pub use crmonban_types::{AppProtocol, ProtocolEvent};
pub use crmonban_types::protocols::{
    HttpTransaction, HttpRequest, HttpResponse,
    DnsMessage, DnsQuery, DnsAnswer,
    TlsEvent, Ja3Fingerprint,
    SshEvent, SshAuthMethod, HasshFingerprint,
    SmtpEvent, SmtpAuthMechanism, SmtpTransaction, SmtpHeaders, SmtpAttachment, EmailAddress,
};

pub use detector::ProtocolDetector;
// Re-export analyzer implementations
pub use http::HttpAnalyzer;
pub use dns::DnsAnalyzer;
pub use tls::TlsAnalyzer;
pub use ssh::SshAnalyzer;
pub use smtp::SmtpAnalyzer;

use serde::{Deserialize, Serialize};
use crmonban_types::{Flow, Packet};

/// Protocol analyzer trait
pub trait ProtocolAnalyzer: Send + Sync {
    /// Protocol name
    fn name(&self) -> &'static str;

    /// Check if payload looks like this protocol
    fn detect(&self, payload: &[u8], port: u16) -> bool;

    /// Parse packet and extract protocol data
    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent>;
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

    /// SSH configuration
    pub ssh: SshConfig,

    /// SMTP configuration
    pub smtp: SmtpConfig,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            http: HttpConfig::default(),
            dns: DnsConfig::default(),
            tls: TlsConfig::default(),
            ssh: SshConfig::default(),
            smtp: SmtpConfig::default(),
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

/// SSH analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_brute_force: bool,
    pub brute_force_threshold: u32,
    pub brute_force_window_secs: u64,
    pub detect_vulnerable_versions: bool,
    pub block_ssh1: bool,
    pub hassh_enabled: bool,
    pub detect_weak_algorithms: bool,
    pub alert_root_login: bool,
    pub cve_database_path: Option<String>,
    pub hassh_database_path: Option<String>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![22, 2222, 22222],
            detect_brute_force: true,
            brute_force_threshold: 5,
            brute_force_window_secs: 60,
            detect_vulnerable_versions: true,
            block_ssh1: true,
            hassh_enabled: true,
            detect_weak_algorithms: true,
            alert_root_login: true,
            cve_database_path: None,
            hassh_database_path: None,
        }
    }
}

/// SMTP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    /// Detect spam based on subject patterns and recipient count
    pub detect_spam: bool,
    /// Detect phishing emails
    pub detect_phishing: bool,
    /// Detect email spoofing (SPF/DKIM/DMARC failures)
    pub detect_spoofing: bool,
    /// Detect open relay abuse attempts
    pub detect_open_relay: bool,
    /// Local domains for open relay detection
    pub local_domains: Vec<String>,
    /// Detect authentication brute force attacks
    pub detect_auth_brute_force: bool,
    /// Auth brute force threshold (failed attempts)
    pub auth_brute_force_threshold: u32,
    /// Auth brute force time window in seconds
    pub auth_brute_force_window_secs: u64,
    /// Detect dangerous attachments
    pub detect_malware_attachments: bool,
    /// Detect mass mailer activity
    pub detect_mass_mailer: bool,
    /// Mass mailer mail count threshold
    pub mass_mailer_threshold: u32,
    /// Mass mailer unique recipient threshold
    pub mass_mailer_recipient_threshold: u32,
    /// Mass mailer time window in seconds
    pub mass_mailer_window_secs: u64,
    /// Log all mail transactions
    pub log_transactions: bool,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![25, 465, 587, 2525],
            detect_spam: true,
            detect_phishing: true,
            detect_spoofing: true,
            detect_open_relay: true,
            local_domains: Vec::new(),
            detect_auth_brute_force: true,
            auth_brute_force_threshold: 5,
            auth_brute_force_window_secs: 60,
            detect_malware_attachments: true,
            detect_mass_mailer: true,
            mass_mailer_threshold: 100,
            mass_mailer_recipient_threshold: 50,
            mass_mailer_window_secs: 300,
            log_transactions: true,
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
        assert!(config.ssh.enabled);
        assert!(config.ssh.detect_brute_force);
        assert!(config.ssh.block_ssh1);
        assert!(config.smtp.enabled);
        assert!(config.smtp.detect_spam);
        assert!(config.smtp.detect_phishing);
        assert!(config.smtp.detect_auth_brute_force);
    }
}

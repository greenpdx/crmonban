//! Protocol analyzers for deep packet inspection
//!
//! Provides parsers and analyzers for application layer protocols.
//!
//! # Architecture
//!
//! Each protocol module implements the `ProtocolParser` trait:
//!
//! ```ignore
//! #[async_trait]
//! pub trait ProtocolParser: Send + Sync {
//!     fn name(&self) -> &'static str;
//!     fn protocol(&self) -> Protocol;
//!     fn probe(&self, payload: &[u8], direction: Direction) -> u8;
//!     async fn parse(&mut self, analysis: &AnalysisPacket, state: &mut ProtocolState) -> ParseResult;
//!     fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet) -> Vec<ProtocolAlert>;
//!     // ...
//! }
//! ```
//!
//! # Feature Flags
//!
//! Each protocol is gated behind a feature flag (all on by default):
//! - `proto-http`, `proto-dns`, `proto-tls`, `proto-ssh`, `proto-smtp`
//! - `proto-smb`, `proto-dcerpc`, `proto-ftp`, `proto-nfs`, `proto-kerberos`
//! - `proto-rdp`, `proto-dhcp`, `proto-snmp`, `proto-sip`, `proto-mqtt`
//! - `proto-modbus`, `proto-dnp3`, `proto-tftp`, `proto-ntp`, `proto-enip`
//! - `proto-rfb`, `proto-ike`

// Core infrastructure
pub mod traits;
pub mod registry;
pub mod rules;
pub mod alerts;
pub mod types;
pub mod detector;

// Re-export core types
pub use traits::{ProtocolParser, ProtocolState, ProtocolStateData, ParserStage, Transaction};
pub use registry::{ProtocolRegistry, ProtocolRegistration, check_port_mismatch};
pub use rules::{ProtocolRuleSet, RuleSetBuilder};
pub use alerts::{ParseResult, ParseError, ProtocolAlert, MatchInfo};

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol modules - feature-gated at declaration
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "proto-http")]
pub mod http;

#[cfg(feature = "proto-dns")]
pub mod dns;

#[cfg(feature = "proto-tls")]
pub mod tls;

#[cfg(feature = "proto-ssh")]
pub mod ssh;

#[cfg(feature = "proto-smtp")]
pub mod smtp;

#[cfg(feature = "proto-smb")]
pub mod smb;

#[cfg(feature = "proto-dcerpc")]
pub mod dcerpc;

#[cfg(feature = "proto-ftp")]
pub mod ftp;

#[cfg(feature = "proto-nfs")]
pub mod nfs;

#[cfg(feature = "proto-kerberos")]
pub mod kerberos;

#[cfg(feature = "proto-rdp")]
pub mod rdp;

#[cfg(feature = "proto-dhcp")]
pub mod dhcp;

#[cfg(feature = "proto-snmp")]
pub mod snmp;

#[cfg(feature = "proto-sip")]
pub mod sip;

#[cfg(feature = "proto-mqtt")]
pub mod mqtt;

#[cfg(feature = "proto-modbus")]
pub mod modbus;

#[cfg(feature = "proto-dnp3")]
pub mod dnp3;

#[cfg(feature = "proto-tftp")]
pub mod tftp;

#[cfg(feature = "proto-ntp")]
pub mod ntp;

#[cfg(feature = "proto-enip")]
pub mod enip;

#[cfg(feature = "proto-rfb")]
pub mod rfb;

#[cfg(feature = "proto-ike")]
pub mod ike;

// ═══════════════════════════════════════════════════════════════════════════════
// Legacy re-exports (for backward compatibility during retrofit)
// ═══════════════════════════════════════════════════════════════════════════════

// Re-export core protocol types from crmonban-types
pub use crate::types::{AppProtocol, ProtocolEvent};
pub use crate::types::protocols::{
    HttpTransaction, HttpRequest, HttpResponse,
    DnsMessage, DnsQuery, DnsAnswer,
    TlsEvent, Ja3Fingerprint,
    SshEvent, SshAuthMethod, HasshFingerprint,
    SmtpEvent, SmtpAuthMechanism, SmtpTransaction, SmtpHeaders, SmtpAttachment, EmailAddress,
};

pub use detector::ProtocolDetector;

// Re-export analyzer implementations
#[cfg(feature = "proto-http")]
pub use http::HttpAnalyzer;
#[cfg(feature = "proto-dns")]
pub use dns::DnsAnalyzer;
#[cfg(feature = "proto-tls")]
pub use tls::TlsAnalyzer;
#[cfg(feature = "proto-ssh")]
pub use ssh::SshAnalyzer;
#[cfg(feature = "proto-smtp")]
pub use smtp::SmtpAnalyzer;

use serde::{Deserialize, Serialize};
use crate::types::{Flow, Packet};

// ═══════════════════════════════════════════════════════════════════════════════
// Legacy ProtocolAnalyzer trait (for backward compatibility)
// ═══════════════════════════════════════════════════════════════════════════════

/// Legacy protocol analyzer trait (deprecated, use ProtocolParser instead)
pub trait ProtocolAnalyzer: Send + Sync {
    /// Protocol name
    fn name(&self) -> &'static str;

    /// Check if payload looks like this protocol
    fn detect(&self, payload: &[u8], port: u16) -> bool;

    /// Parse packet and extract protocol data
    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol Registry Initialization
// ═══════════════════════════════════════════════════════════════════════════════

/// Initialize protocol registry with all enabled protocols
pub fn init_registry() -> ProtocolRegistry {
    let mut registry = ProtocolRegistry::new();

    // Retrofitted protocols with new interface
    #[cfg(feature = "proto-http")]
    registry.register(http::registration());

    #[cfg(feature = "proto-dns")]
    registry.register(dns::registration());

    #[cfg(feature = "proto-tls")]
    registry.register(tls::registration());

    #[cfg(feature = "proto-ssh")]
    registry.register(ssh::registration());

    #[cfg(feature = "proto-smtp")]
    registry.register(smtp::registration());

    // New protocols with new interface
    #[cfg(feature = "proto-smb")]
    registry.register(smb::registration());

    #[cfg(feature = "proto-dcerpc")]
    registry.register(dcerpc::registration());

    #[cfg(feature = "proto-ftp")]
    registry.register(ftp::registration());

    #[cfg(feature = "proto-nfs")]
    registry.register(nfs::registration());

    #[cfg(feature = "proto-kerberos")]
    registry.register(kerberos::registration());

    #[cfg(feature = "proto-rdp")]
    registry.register(rdp::registration());

    #[cfg(feature = "proto-dhcp")]
    registry.register(dhcp::registration());

    #[cfg(feature = "proto-snmp")]
    registry.register(snmp::registration());

    #[cfg(feature = "proto-sip")]
    registry.register(sip::registration());

    #[cfg(feature = "proto-mqtt")]
    registry.register(mqtt::registration());

    #[cfg(feature = "proto-modbus")]
    registry.register(modbus::registration());

    #[cfg(feature = "proto-dnp3")]
    registry.register(dnp3::registration());

    #[cfg(feature = "proto-tftp")]
    registry.register(tftp::registration());

    #[cfg(feature = "proto-ntp")]
    registry.register(ntp::registration());

    #[cfg(feature = "proto-enip")]
    registry.register(enip::registration());

    #[cfg(feature = "proto-rfb")]
    registry.register(rfb::registration());

    #[cfg(feature = "proto-ike")]
    registry.register(ike::registration());

    registry
}

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for all protocol analyzers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    /// Enable protocol analysis
    pub enabled: bool,

    /// HTTP configuration
    #[cfg(feature = "proto-http")]
    pub http: HttpConfig,

    /// DNS configuration
    #[cfg(feature = "proto-dns")]
    pub dns: DnsConfig,

    /// TLS configuration
    #[cfg(feature = "proto-tls")]
    pub tls: TlsConfig,

    /// SSH configuration
    #[cfg(feature = "proto-ssh")]
    pub ssh: SshConfig,

    /// SMTP configuration
    #[cfg(feature = "proto-smtp")]
    pub smtp: SmtpConfig,

    /// SMB configuration
    #[cfg(feature = "proto-smb")]
    pub smb: SmbConfig,

    /// DCERPC configuration
    #[cfg(feature = "proto-dcerpc")]
    pub dcerpc: DcerpcConfig,

    /// FTP configuration
    #[cfg(feature = "proto-ftp")]
    pub ftp: FtpConfig,

    /// NFS configuration
    #[cfg(feature = "proto-nfs")]
    pub nfs: NfsConfig,

    /// Kerberos configuration
    #[cfg(feature = "proto-kerberos")]
    pub kerberos: KerberosConfig,

    /// RDP configuration
    #[cfg(feature = "proto-rdp")]
    pub rdp: RdpConfig,

    /// DHCP configuration
    #[cfg(feature = "proto-dhcp")]
    pub dhcp: DhcpConfig,

    /// SNMP configuration
    #[cfg(feature = "proto-snmp")]
    pub snmp: SnmpConfig,

    /// SIP configuration
    #[cfg(feature = "proto-sip")]
    pub sip: SipConfig,

    /// MQTT configuration
    #[cfg(feature = "proto-mqtt")]
    pub mqtt: MqttConfig,

    /// Modbus configuration
    #[cfg(feature = "proto-modbus")]
    pub modbus: ModbusConfig,

    /// DNP3 configuration
    #[cfg(feature = "proto-dnp3")]
    pub dnp3: Dnp3Config,

    /// TFTP configuration
    #[cfg(feature = "proto-tftp")]
    pub tftp: TftpConfig,

    /// NTP configuration
    #[cfg(feature = "proto-ntp")]
    pub ntp: NtpConfig,

    /// EtherNet/IP configuration
    #[cfg(feature = "proto-enip")]
    pub enip: EnipConfig,

    /// RFB/VNC configuration
    #[cfg(feature = "proto-rfb")]
    pub rfb: RfbConfig,

    /// IKE configuration
    #[cfg(feature = "proto-ike")]
    pub ike: IkeConfig,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            #[cfg(feature = "proto-http")]
            http: HttpConfig::default(),
            #[cfg(feature = "proto-dns")]
            dns: DnsConfig::default(),
            #[cfg(feature = "proto-tls")]
            tls: TlsConfig::default(),
            #[cfg(feature = "proto-ssh")]
            ssh: SshConfig::default(),
            #[cfg(feature = "proto-smtp")]
            smtp: SmtpConfig::default(),
            #[cfg(feature = "proto-smb")]
            smb: SmbConfig::default(),
            #[cfg(feature = "proto-dcerpc")]
            dcerpc: DcerpcConfig::default(),
            #[cfg(feature = "proto-ftp")]
            ftp: FtpConfig::default(),
            #[cfg(feature = "proto-nfs")]
            nfs: NfsConfig::default(),
            #[cfg(feature = "proto-kerberos")]
            kerberos: KerberosConfig::default(),
            #[cfg(feature = "proto-rdp")]
            rdp: RdpConfig::default(),
            #[cfg(feature = "proto-dhcp")]
            dhcp: DhcpConfig::default(),
            #[cfg(feature = "proto-snmp")]
            snmp: SnmpConfig::default(),
            #[cfg(feature = "proto-sip")]
            sip: SipConfig::default(),
            #[cfg(feature = "proto-mqtt")]
            mqtt: MqttConfig::default(),
            #[cfg(feature = "proto-modbus")]
            modbus: ModbusConfig::default(),
            #[cfg(feature = "proto-dnp3")]
            dnp3: Dnp3Config::default(),
            #[cfg(feature = "proto-tftp")]
            tftp: TftpConfig::default(),
            #[cfg(feature = "proto-ntp")]
            ntp: NtpConfig::default(),
            #[cfg(feature = "proto-enip")]
            enip: EnipConfig::default(),
            #[cfg(feature = "proto-rfb")]
            rfb: RfbConfig::default(),
            #[cfg(feature = "proto-ike")]
            ike: IkeConfig::default(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Per-Protocol Configurations
// ═══════════════════════════════════════════════════════════════════════════════

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
    pub detect_spam: bool,
    pub detect_phishing: bool,
    pub detect_spoofing: bool,
    pub detect_open_relay: bool,
    pub local_domains: Vec<String>,
    pub detect_auth_brute_force: bool,
    pub auth_brute_force_threshold: u32,
    pub auth_brute_force_window_secs: u64,
    pub detect_malware_attachments: bool,
    pub detect_mass_mailer: bool,
    pub mass_mailer_threshold: u32,
    pub mass_mailer_recipient_threshold: u32,
    pub mass_mailer_window_secs: u64,
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

/// SMB analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_version: bool,
    pub detect_smb1: bool,
    pub max_transaction_size: usize,
    pub log_commands: bool,
    pub log_files: bool,
    pub detect_lateral_movement: bool,
    pub detect_ransomware: bool,
}

impl Default for SmbConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![445, 139],
            detect_version: true,
            detect_smb1: true,
            max_transaction_size: 16_777_216, // 16 MB
            log_commands: true,
            log_files: true,
            detect_lateral_movement: true,
            detect_ransomware: true,
        }
    }
}

/// DCERPC analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcerpcConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_exploits: bool,
    pub log_operations: bool,
}

impl Default for DcerpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![135, 593],
            detect_exploits: true,
            log_operations: true,
        }
    }
}

/// FTP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_bounce_attacks: bool,
    pub detect_brute_force: bool,
    pub log_commands: bool,
    pub log_transfers: bool,
}

impl Default for FtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![21, 20],
            detect_bounce_attacks: true,
            detect_brute_force: true,
            log_commands: true,
            log_transfers: true,
        }
    }
}

/// NFS analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfsConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub log_operations: bool,
}

impl Default for NfsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![2049, 111],
            log_operations: true,
        }
    }
}

/// Kerberos analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_kerberoasting: bool,
    pub detect_golden_ticket: bool,
    pub log_tickets: bool,
}

impl Default for KerberosConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![88],
            detect_kerberoasting: true,
            detect_golden_ticket: true,
            log_tickets: true,
        }
    }
}

/// RDP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_brute_force: bool,
    pub detect_bluekeep: bool,
    pub log_connections: bool,
}

impl Default for RdpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![3389],
            detect_brute_force: true,
            detect_bluekeep: true,
            log_connections: true,
        }
    }
}

/// DHCP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_rogue_server: bool,
    pub log_leases: bool,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![67, 68],
            detect_rogue_server: true,
            log_leases: true,
        }
    }
}

/// SNMP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_default_community: bool,
    pub log_queries: bool,
}

impl Default for SnmpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![161, 162],
            detect_default_community: true,
            log_queries: true,
        }
    }
}

/// SIP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_toll_fraud: bool,
    pub log_calls: bool,
}

impl Default for SipConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![5060, 5061],
            detect_toll_fraud: true,
            log_calls: true,
        }
    }
}

/// MQTT analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_anonymous: bool,
    pub log_messages: bool,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![1883, 8883],
            detect_anonymous: true,
            log_messages: true,
        }
    }
}

/// Modbus analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_unauthorized_write: bool,
    pub log_operations: bool,
}

impl Default for ModbusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![502],
            detect_unauthorized_write: true,
            log_operations: true,
        }
    }
}

/// DNP3 analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dnp3Config {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_unauthorized_control: bool,
    pub log_operations: bool,
}

impl Default for Dnp3Config {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![20000],
            detect_unauthorized_control: true,
            log_operations: true,
        }
    }
}

/// TFTP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TftpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub log_transfers: bool,
}

impl Default for TftpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![69],
            log_transfers: true,
        }
    }
}

/// NTP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_amplification: bool,
    pub detect_monlist: bool,
    pub log_queries: bool,
}

impl Default for NtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![123],
            detect_amplification: true,
            detect_monlist: true,
            log_queries: true,
        }
    }
}

/// EtherNet/IP analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnipConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_unauthorized_access: bool,
    pub log_operations: bool,
}

impl Default for EnipConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![44818, 2222],
            detect_unauthorized_access: true,
            log_operations: true,
        }
    }
}

/// RFB/VNC analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfbConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_brute_force: bool,
    pub detect_weak_auth: bool,
    pub log_connections: bool,
}

impl Default for RfbConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![5900, 5901, 5902, 5903],
            detect_brute_force: true,
            detect_weak_auth: true,
            log_connections: true,
        }
    }
}

/// IKE analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkeConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_weak_crypto: bool,
    pub log_negotiations: bool,
}

impl Default for IkeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![500, 4500],
            detect_weak_crypto: true,
            log_negotiations: true,
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

        #[cfg(feature = "proto-http")]
        assert!(config.http.enabled);

        #[cfg(feature = "proto-dns")]
        assert!(config.dns.enabled);

        #[cfg(feature = "proto-smb")]
        assert!(config.smb.enabled);
    }

    #[test]
    fn test_init_registry() {
        let registry = init_registry();
        // Registry should have protocols if features are enabled
        // Number depends on which features are compiled
        assert!(registry.len() >= 0);
    }
}

//! Configuration for probabilistic scan detection

use std::collections::HashSet;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Main configuration for scan detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetectConfig {
    /// Enable scan detection
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Score thresholds for classification
    #[serde(default)]
    pub thresholds: ScoreThresholds,

    /// Rule weights (can override defaults)
    #[serde(default)]
    pub weights: RuleWeights,

    /// Time window for tracking (seconds)
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,

    /// SYN completion timeout (seconds) - SYN must complete handshake within this time
    #[serde(default = "default_syn_timeout_secs")]
    pub syn_timeout_secs: u64,

    /// Cleanup interval for expired entries (seconds)
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,

    /// Enable specific rule categories
    #[serde(default)]
    pub categories: RuleCategoryConfig,

    /// Commonly targeted ports (get bonus score)
    #[serde(default = "default_targeted_ports")]
    pub targeted_ports: Vec<u16>,

    /// Disabled rules (by ID)
    #[serde(default)]
    pub disabled_rules: Vec<String>,
}

fn default_true() -> bool { true }
fn default_window_secs() -> u64 { 600 } // 10 minutes
fn default_syn_timeout_secs() -> u64 { 5 }
fn default_cleanup_interval() -> u64 { 30 }

fn default_targeted_ports() -> Vec<u16> {
    vec![
        21,    // FTP
        22,    // SSH
        23,    // Telnet
        25,    // SMTP
        53,    // DNS
        80,    // HTTP
        110,   // POP3
        111,   // RPC/Portmapper
        135,   // MSRPC
        139,   // NetBIOS Session
        143,   // IMAP
        161,   // SNMP
        179,   // BGP
        389,   // LDAP
        443,   // HTTPS
        445,   // SMB/CIFS
        465,   // SMTPS
        514,   // Syslog
        587,   // SMTP Submission
        636,   // LDAPS
        993,   // IMAPS
        995,   // POP3S
        1080,  // SOCKS Proxy
        1433,  // MSSQL
        1521,  // Oracle DB
        1723,  // PPTP VPN
        2049,  // NFS
        3306,  // MySQL
        3389,  // RDP
        5432,  // PostgreSQL
        5900,  // VNC
        6379,  // Redis
        8080,  // HTTP Proxy
        8443,  // HTTPS Alt
        9200,  // Elasticsearch
        11211, // Memcached
        27017, // MongoDB
    ]
}

impl Default for ScanDetectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            thresholds: ScoreThresholds::default(),
            weights: RuleWeights::default(),
            window_secs: default_window_secs(),
            syn_timeout_secs: default_syn_timeout_secs(),
            cleanup_interval_secs: default_cleanup_interval(),
            categories: RuleCategoryConfig::default(),
            targeted_ports: default_targeted_ports(),
            disabled_rules: Vec::new(),
        }
    }
}

impl ScanDetectConfig {
    /// Get window duration
    pub fn window_duration(&self) -> Duration {
        Duration::from_secs(self.window_secs)
    }

    /// Get SYN timeout duration
    pub fn syn_timeout(&self) -> Duration {
        Duration::from_secs(self.syn_timeout_secs)
    }

    /// Check if a rule is disabled
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules.iter().any(|r| r == rule_id)
    }

    /// Get targeted ports as HashSet for fast lookup
    pub fn targeted_ports_set(&self) -> HashSet<u16> {
        self.targeted_ports.iter().copied().collect()
    }
}

/// Score thresholds for classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreThresholds {
    /// Score to classify as SUSPICIOUS
    #[serde(default = "default_suspicious")]
    pub suspicious: f32,

    /// Score to classify as PROBABLE_SCAN
    #[serde(default = "default_probable_scan")]
    pub probable_scan: f32,

    /// Score to classify as LIKELY_ATTACK
    #[serde(default = "default_likely_attack")]
    pub likely_attack: f32,

    /// Score to classify as CONFIRMED_SCAN (immediate action)
    #[serde(default = "default_confirmed_scan")]
    pub confirmed_scan: f32,
}

fn default_suspicious() -> f32 { 3.0 }
fn default_probable_scan() -> f32 { 5.0 }
fn default_likely_attack() -> f32 { 8.0 }
fn default_confirmed_scan() -> f32 { 12.0 }

impl Default for ScoreThresholds {
    fn default() -> Self {
        Self {
            suspicious: default_suspicious(),
            probable_scan: default_probable_scan(),
            likely_attack: default_likely_attack(),
            confirmed_scan: default_confirmed_scan(),
        }
    }
}

/// Rule category enable/disable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCategoryConfig {
    #[serde(default = "default_true")]
    pub connection: bool,
    #[serde(default = "default_true")]
    pub geographic: bool,
    #[serde(default = "default_true")]
    pub temporal: bool,
    #[serde(default = "default_true")]
    pub protocol: bool,
    #[serde(default = "default_true")]
    pub reputation: bool,
    #[serde(default = "default_true")]
    pub custom: bool,
    #[serde(default = "default_true")]
    pub wasm: bool,
}

impl Default for RuleCategoryConfig {
    fn default() -> Self {
        Self {
            connection: true,
            geographic: true,
            temporal: true,
            protocol: true,
            reputation: true,
            custom: true,
            wasm: true,
        }
    }
}

/// Configurable rule weights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleWeights {
    // Connection rules (increase score)
    #[serde(default = "default_half_open_syn")]
    pub half_open_syn: f32,
    #[serde(default = "default_targeted_port_bonus")]
    pub targeted_port_bonus: f32,
    #[serde(default = "default_sequential_scan")]
    pub sequential_scan: f32,
    #[serde(default = "default_rapid_rate")]
    pub rapid_rate: f32,
    #[serde(default = "default_closed_port_rst")]
    pub closed_port_rst: f32,
    #[serde(default = "default_scanner_fingerprint")]
    pub scanner_fingerprint: f32,
    #[serde(default = "default_unusual_ttl")]
    pub unusual_ttl: f32,
    #[serde(default = "default_tcp_options_mismatch")]
    pub tcp_options_mismatch: f32,

    // Connection rules (decrease score)
    #[serde(default = "default_completed_handshake")]
    pub completed_handshake: f32,
    #[serde(default = "default_data_exchanged")]
    pub data_exchanged: f32,
    #[serde(default = "default_tls_completed")]
    pub tls_completed: f32,
    #[serde(default = "default_http_request")]
    pub http_request: f32,
    #[serde(default = "default_known_good_ip")]
    pub known_good_ip: f32,
    #[serde(default = "default_dns_match")]
    pub dns_match: f32,
    #[serde(default = "default_expected_service")]
    pub expected_service: f32,

    // Geographic rules
    #[serde(default = "default_high_risk_country")]
    pub high_risk_country: f32,
    #[serde(default = "default_bulletproof_asn")]
    pub bulletproof_asn: f32,
    #[serde(default = "default_residential_ip")]
    pub residential_ip: f32,
    #[serde(default = "default_residential_scan")]
    pub residential_scan: f32,
    #[serde(default = "default_cloud_provider")]
    pub cloud_provider: f32,
    #[serde(default = "default_datacenter_ip")]
    pub datacenter_ip: f32,
    #[serde(default = "default_tor_exit")]
    pub tor_exit: f32,
    #[serde(default = "default_vpn_provider")]
    pub vpn_provider: f32,
    #[serde(default = "default_vpn_asn")]
    pub vpn_asn: f32,
    #[serde(default = "default_same_country")]
    pub same_country: f32,
    #[serde(default = "default_same_network")]
    pub same_network: f32,
    #[serde(default = "default_known_scanner")]
    pub known_scanner: f32,
    #[serde(default = "default_geoip_failure")]
    pub geoip_failure: f32,

    // Temporal rules
    #[serde(default = "default_off_hours")]
    pub off_hours: f32,
    #[serde(default = "default_business_hours")]
    pub business_hours: f32,
    #[serde(default = "default_burst_after_silence")]
    pub burst_after_silence: f32,
    #[serde(default = "default_consistent_timing")]
    pub consistent_timing: f32,
    #[serde(default = "default_weekend_activity")]
    pub weekend_activity: f32,
    #[serde(default = "default_holiday_period")]
    pub holiday_period: f32,

    // Reputation rules
    #[serde(default = "default_abuseipdb_low")]
    pub abuseipdb_low: f32,
    #[serde(default = "default_abuseipdb_high")]
    pub abuseipdb_high: f32,
    #[serde(default = "default_spamhaus")]
    pub spamhaus: f32,
    #[serde(default = "default_emerging_threats")]
    pub emerging_threats: f32,
    #[serde(default = "default_honeypot")]
    pub honeypot: f32,
    #[serde(default = "default_previous_ban")]
    pub previous_ban: f32,
    #[serde(default = "default_whitelist")]
    pub whitelist: f32,
    #[serde(default = "default_partner_vendor")]
    pub partner_vendor: f32,
}

// Default weight functions
fn default_half_open_syn() -> f32 { 1.0 }
fn default_targeted_port_bonus() -> f32 { 0.5 }
fn default_sequential_scan() -> f32 { 2.0 }
fn default_rapid_rate() -> f32 { 3.0 }
fn default_closed_port_rst() -> f32 { 0.5 }
fn default_scanner_fingerprint() -> f32 { 5.0 }
fn default_unusual_ttl() -> f32 { 1.0 }
fn default_tcp_options_mismatch() -> f32 { 1.0 }

fn default_completed_handshake() -> f32 { -2.0 }
fn default_data_exchanged() -> f32 { -1.0 }
fn default_tls_completed() -> f32 { -2.0 }
fn default_http_request() -> f32 { -1.5 }
fn default_known_good_ip() -> f32 { -3.0 }
fn default_dns_match() -> f32 { -1.0 }
fn default_expected_service() -> f32 { -0.5 }

fn default_high_risk_country() -> f32 { 2.0 }
fn default_bulletproof_asn() -> f32 { 3.0 }
fn default_residential_ip() -> f32 { -0.5 }
fn default_residential_scan() -> f32 { 1.5 }
fn default_cloud_provider() -> f32 { 0.5 }
fn default_datacenter_ip() -> f32 { 0.5 }
fn default_tor_exit() -> f32 { 2.0 }
fn default_vpn_provider() -> f32 { 1.0 }
fn default_vpn_asn() -> f32 { 1.5 }
fn default_same_country() -> f32 { -0.5 }
fn default_same_network() -> f32 { -1.0 }
fn default_known_scanner() -> f32 { 5.0 }
fn default_geoip_failure() -> f32 { 1.5 }

fn default_off_hours() -> f32 { 1.0 }
fn default_business_hours() -> f32 { -0.5 }
fn default_burst_after_silence() -> f32 { 1.5 }
fn default_consistent_timing() -> f32 { 2.0 }
fn default_weekend_activity() -> f32 { 0.5 }
fn default_holiday_period() -> f32 { 1.0 }

fn default_abuseipdb_low() -> f32 { 3.0 }
fn default_abuseipdb_high() -> f32 { 5.0 }
fn default_spamhaus() -> f32 { 4.0 }
fn default_emerging_threats() -> f32 { 3.0 }
fn default_honeypot() -> f32 { 4.0 }
fn default_previous_ban() -> f32 { 2.0 }
fn default_whitelist() -> f32 { -5.0 }
fn default_partner_vendor() -> f32 { -3.0 }

impl Default for RuleWeights {
    fn default() -> Self {
        Self {
            half_open_syn: default_half_open_syn(),
            targeted_port_bonus: default_targeted_port_bonus(),
            sequential_scan: default_sequential_scan(),
            rapid_rate: default_rapid_rate(),
            closed_port_rst: default_closed_port_rst(),
            scanner_fingerprint: default_scanner_fingerprint(),
            unusual_ttl: default_unusual_ttl(),
            tcp_options_mismatch: default_tcp_options_mismatch(),

            completed_handshake: default_completed_handshake(),
            data_exchanged: default_data_exchanged(),
            tls_completed: default_tls_completed(),
            http_request: default_http_request(),
            known_good_ip: default_known_good_ip(),
            dns_match: default_dns_match(),
            expected_service: default_expected_service(),

            high_risk_country: default_high_risk_country(),
            bulletproof_asn: default_bulletproof_asn(),
            residential_ip: default_residential_ip(),
            residential_scan: default_residential_scan(),
            cloud_provider: default_cloud_provider(),
            datacenter_ip: default_datacenter_ip(),
            tor_exit: default_tor_exit(),
            vpn_provider: default_vpn_provider(),
            vpn_asn: default_vpn_asn(),
            same_country: default_same_country(),
            same_network: default_same_network(),
            known_scanner: default_known_scanner(),
            geoip_failure: default_geoip_failure(),

            off_hours: default_off_hours(),
            business_hours: default_business_hours(),
            burst_after_silence: default_burst_after_silence(),
            consistent_timing: default_consistent_timing(),
            weekend_activity: default_weekend_activity(),
            holiday_period: default_holiday_period(),

            abuseipdb_low: default_abuseipdb_low(),
            abuseipdb_high: default_abuseipdb_high(),
            spamhaus: default_spamhaus(),
            emerging_threats: default_emerging_threats(),
            honeypot: default_honeypot(),
            previous_ban: default_previous_ban(),
            whitelist: default_whitelist(),
            partner_vendor: default_partner_vendor(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScanDetectConfig::default();
        assert!(config.enabled);
        assert_eq!(config.thresholds.suspicious, 3.0);
        assert_eq!(config.thresholds.confirmed_scan, 12.0);
        assert_eq!(config.window_secs, 600);
    }

    #[test]
    fn test_targeted_ports() {
        let config = ScanDetectConfig::default();
        let ports = config.targeted_ports_set();
        assert!(ports.contains(&22));  // SSH
        assert!(ports.contains(&3389)); // RDP
        assert!(!ports.contains(&12345)); // Random
    }

    #[test]
    fn test_rule_disabled() {
        let mut config = ScanDetectConfig::default();
        config.disabled_rules = vec!["R1".to_string(), "G3".to_string()];
        assert!(config.is_rule_disabled("R1"));
        assert!(config.is_rule_disabled("G3"));
        assert!(!config.is_rule_disabled("R2"));
    }
}

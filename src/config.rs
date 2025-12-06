use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::ebpf::EbpfConfig;
use crate::shared_whitelist::SharedWhitelistConfig;
use crate::siem::SiemConfig;
use crate::zones::ZoneConfig;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub nftables: NftablesConfig,

    #[serde(default)]
    pub intel: IntelConfig,

    #[serde(default)]
    pub dbus: DbusConfig,

    #[serde(default)]
    pub siem: SiemConfig,

    #[serde(default)]
    pub zones: ZoneConfig,

    #[serde(default)]
    pub whitelist: SharedWhitelistConfig,

    #[serde(default)]
    pub ebpf: EbpfConfig,

    #[serde(default)]
    pub port_scan: PortScanConfig,

    #[serde(default)]
    pub dpi: DpiConfig,

    #[serde(default)]
    pub tls_proxy: TlsProxyConfig,

    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,
}

impl Default for Config {
    fn default() -> Self {
        let mut services = HashMap::new();

        // Default SSH monitoring
        services.insert(
            "ssh".to_string(),
            ServiceConfig {
                enabled: true,
                log_path: "/var/log/auth.log".to_string(),
                patterns: vec![
                    PatternConfig {
                        name: "failed_password".to_string(),
                        regex: r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
                        event_type: "failed_auth".to_string(),
                    },
                    PatternConfig {
                        name: "invalid_user".to_string(),
                        regex: r"Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
                        event_type: "invalid_user".to_string(),
                    },
                    PatternConfig {
                        name: "connection_closed".to_string(),
                        regex: r"Connection closed by (?P<ip>\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]"
                            .to_string(),
                        event_type: "failed_auth".to_string(),
                    },
                ],
                max_failures: 5,
                find_time: 600,
                ban_time: 3600,
            },
        );

        // Default nginx monitoring
        services.insert(
            "nginx".to_string(),
            ServiceConfig {
                enabled: false,
                log_path: "/var/log/nginx/error.log".to_string(),
                patterns: vec![PatternConfig {
                    name: "limit_req".to_string(),
                    regex: r"limiting requests, excess: .* by zone .*, client: (?P<ip>\d+\.\d+\.\d+\.\d+)"
                        .to_string(),
                    event_type: "rate_limit".to_string(),
                }],
                max_failures: 10,
                find_time: 60,
                ban_time: 600,
            },
        );

        Self {
            general: GeneralConfig::default(),
            nftables: NftablesConfig::default(),
            intel: IntelConfig::default(),
            dbus: DbusConfig::default(),
            siem: SiemConfig::default(),
            zones: ZoneConfig::default(),
            whitelist: SharedWhitelistConfig::default(),
            ebpf: EbpfConfig::default(),
            port_scan: PortScanConfig::default(),
            dpi: DpiConfig::default(),
            tls_proxy: TlsProxyConfig::default(),
            services,
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.as_ref().display()))?;

        Ok(config)
    }

    /// Load config from default locations or create default
    pub fn load_or_default() -> Result<Self> {
        let paths = [
            PathBuf::from("/etc/crmonban/config.toml"),
            dirs_next::config_dir()
                .map(|p| p.join("crmonban/config.toml"))
                .unwrap_or_default(),
            PathBuf::from("config.toml"),
        ];

        for path in &paths {
            if path.exists() {
                return Self::load(path);
            }
        }

        Ok(Self::default())
    }

    /// Save configuration to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    /// Get the database path
    pub fn db_path(&self) -> PathBuf {
        PathBuf::from(&self.general.db_path)
    }

    /// Get the PID file path
    pub fn pid_path(&self) -> PathBuf {
        PathBuf::from(&self.general.pid_file)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Path to SQLite database
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Path to PID file
    #[serde(default = "default_pid_file")]
    pub pid_file: String,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Whether to gather intel automatically on ban
    #[serde(default = "default_true")]
    pub auto_intel: bool,

    /// Default ban duration in seconds (0 = permanent)
    #[serde(default = "default_ban_duration")]
    pub default_ban_duration: i64,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            pid_file: default_pid_file(),
            log_level: default_log_level(),
            auto_intel: true,
            default_ban_duration: default_ban_duration(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftablesConfig {
    /// Table name to use
    #[serde(default = "default_table_name")]
    pub table_name: String,

    /// Chain name for input filtering
    #[serde(default = "default_chain_name")]
    pub chain_name: String,

    /// Set name for blocked IPv4 addresses
    #[serde(default = "default_set_v4")]
    pub set_v4: String,

    /// Set name for blocked IPv6 addresses
    #[serde(default = "default_set_v6")]
    pub set_v6: String,

    /// Priority for the chain (lower = earlier)
    #[serde(default = "default_priority")]
    pub priority: i32,
}

impl Default for NftablesConfig {
    fn default() -> Self {
        Self {
            table_name: default_table_name(),
            chain_name: default_chain_name(),
            set_v4: default_set_v4(),
            set_v6: default_set_v6(),
            priority: default_priority(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelConfig {
    /// Enable GeoIP lookups
    #[serde(default = "default_true")]
    pub geoip_enabled: bool,

    /// Enable reverse DNS lookups
    #[serde(default = "default_true")]
    pub rdns_enabled: bool,

    /// Enable WHOIS lookups
    #[serde(default = "default_true")]
    pub whois_enabled: bool,

    /// Shodan API key (optional)
    #[serde(default)]
    pub shodan_api_key: Option<String>,

    /// AbuseIPDB API key (optional)
    #[serde(default)]
    pub abuseipdb_api_key: Option<String>,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            geoip_enabled: true,
            rdns_enabled: true,
            whois_enabled: true,
            shodan_api_key: None,
            abuseipdb_api_key: None,
            timeout_secs: default_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbusConfig {
    /// Enable D-Bus interface
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Use system bus (true) or session bus (false)
    #[serde(default = "default_true")]
    pub system_bus: bool,
}

impl Default for DbusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            system_bus: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Whether this service is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Path to the log file to monitor
    pub log_path: String,

    /// Patterns to match in the log file
    pub patterns: Vec<PatternConfig>,

    /// Number of failures before ban
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,

    /// Time window to count failures (seconds)
    #[serde(default = "default_find_time")]
    pub find_time: u64,

    /// Ban duration for this service (seconds)
    #[serde(default = "default_service_ban_time")]
    pub ban_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternConfig {
    /// Name for this pattern
    pub name: String,

    /// Regex pattern (must have `ip` named capture group)
    pub regex: String,

    /// Event type for matches
    pub event_type: String,
}

// Default value functions
fn default_db_path() -> String {
    "/var/lib/crmonban/crmonban.db".to_string()
}

fn default_pid_file() -> String {
    "/var/run/crmonban.pid".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_ban_duration() -> i64 {
    3600 // 1 hour
}

fn default_table_name() -> String {
    "crmonban".to_string()
}

fn default_chain_name() -> String {
    "input".to_string()
}

fn default_set_v4() -> String {
    "blocked_v4".to_string()
}

fn default_set_v6() -> String {
    "blocked_v6".to_string()
}

fn default_priority() -> i32 {
    -100 // Before most other rules
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    10
}

fn default_max_failures() -> u32 {
    5
}

fn default_find_time() -> u64 {
    600 // 10 minutes
}

fn default_service_ban_time() -> i64 {
    3600 // 1 hour
}

fn default_port_scan_threshold() -> u32 {
    10 // ports
}

fn default_port_scan_window() -> u64 {
    60 // seconds
}

fn default_port_scan_ban_time() -> i64 {
    3600 // 1 hour
}

/// Port scan detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanConfig {
    /// Enable port scan detection via nftables
    #[serde(default)]
    pub enabled: bool,

    /// Number of unique ports that triggers a port scan detection
    #[serde(default = "default_port_scan_threshold")]
    pub threshold: u32,

    /// Time window in seconds to count unique port hits
    #[serde(default = "default_port_scan_window")]
    pub window_secs: u64,

    /// Ban duration in seconds for port scanners
    #[serde(default = "default_port_scan_ban_time")]
    pub ban_time: i64,

    /// Ports to monitor (empty = all ports)
    #[serde(default)]
    pub monitored_ports: Vec<u16>,

    /// Ports to exclude from monitoring (e.g., common services you expect traffic on)
    #[serde(default = "default_excluded_ports")]
    pub excluded_ports: Vec<u16>,

    /// Detect TCP SYN scans (half-open connections)
    #[serde(default = "default_true")]
    pub detect_syn_scan: bool,

    /// Detect TCP NULL scans (no flags set)
    #[serde(default = "default_true")]
    pub detect_null_scan: bool,

    /// Detect TCP XMAS scans (FIN+PSH+URG flags)
    #[serde(default = "default_true")]
    pub detect_xmas_scan: bool,

    /// Detect TCP FIN scans (only FIN flag)
    #[serde(default = "default_true")]
    pub detect_fin_scan: bool,

    /// Detect UDP scans
    #[serde(default = "default_true")]
    pub detect_udp_scan: bool,

    /// Log file path for nftables port scan logs (via nflog or /var/log/kern.log)
    #[serde(default = "default_port_scan_log")]
    pub log_path: String,

    /// Use nflog group for logging (more efficient than kernel log)
    #[serde(default)]
    pub nflog_group: Option<u32>,
}

fn default_excluded_ports() -> Vec<u16> {
    vec![22, 80, 443] // Common service ports
}

fn default_port_scan_log() -> String {
    "/var/log/kern.log".to_string()
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_port_scan_threshold(),
            window_secs: default_port_scan_window(),
            ban_time: default_port_scan_ban_time(),
            monitored_ports: vec![],
            excluded_ports: default_excluded_ports(),
            detect_syn_scan: true,
            detect_null_scan: true,
            detect_xmas_scan: true,
            detect_fin_scan: true,
            detect_udp_scan: true,
            log_path: default_port_scan_log(),
            nflog_group: None,
        }
    }
}

/// Deep packet inspection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiConfig {
    /// Enable deep packet inspection
    #[serde(default)]
    pub enabled: bool,

    /// NFQUEUE number for packet inspection
    #[serde(default = "default_dpi_queue")]
    pub queue_num: u16,

    /// Number of initial packets to inspect per connection
    #[serde(default = "default_dpi_packet_count")]
    pub packets_per_conn: u8,

    /// Maximum payload bytes to inspect per packet
    #[serde(default = "default_dpi_max_payload")]
    pub max_payload_bytes: usize,

    /// Ports to inspect (empty = all non-excluded ports)
    #[serde(default)]
    pub inspected_ports: Vec<u16>,

    /// Ports to exclude from inspection
    #[serde(default = "default_dpi_excluded_ports")]
    pub excluded_ports: Vec<u16>,

    /// Ban duration for detected threats (seconds)
    #[serde(default = "default_dpi_ban_time")]
    pub ban_time: i64,

    /// Enable SQL injection detection
    #[serde(default = "default_true")]
    pub detect_sqli: bool,

    /// Enable XSS detection
    #[serde(default = "default_true")]
    pub detect_xss: bool,

    /// Enable command injection detection
    #[serde(default = "default_true")]
    pub detect_cmdi: bool,

    /// Enable path traversal detection
    #[serde(default = "default_true")]
    pub detect_path_traversal: bool,

    /// Enable shellcode/exploit detection
    #[serde(default = "default_true")]
    pub detect_shellcode: bool,

    /// Enable protocol anomaly detection
    #[serde(default = "default_true")]
    pub detect_protocol_anomaly: bool,

    /// Custom patterns to match (regex)
    #[serde(default)]
    pub custom_patterns: Vec<DpiPattern>,

    /// Action on match: "ban", "log", "drop"
    #[serde(default = "default_dpi_action")]
    pub action: String,
}

/// Custom DPI pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiPattern {
    /// Pattern name
    pub name: String,
    /// Regex pattern to match in payload
    pub pattern: String,
    /// Severity: "low", "medium", "high", "critical"
    #[serde(default = "default_pattern_severity")]
    pub severity: String,
    /// Description of the threat
    #[serde(default)]
    pub description: String,
}

fn default_dpi_queue() -> u16 {
    100
}

fn default_dpi_packet_count() -> u8 {
    8 // Minimum needed to capture full TLS handshake
}

fn default_dpi_max_payload() -> usize {
    4096
}

fn default_dpi_excluded_ports() -> Vec<u16> {
    vec![] // Empty by default - inspect all ports including TLS handshakes
}

fn default_dpi_ban_time() -> i64 {
    7200 // 2 hours
}

fn default_dpi_action() -> String {
    "ban".to_string()
}

fn default_pattern_severity() -> String {
    "medium".to_string()
}

impl Default for DpiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            queue_num: default_dpi_queue(),
            packets_per_conn: default_dpi_packet_count(),
            max_payload_bytes: default_dpi_max_payload(),
            inspected_ports: vec![],
            excluded_ports: default_dpi_excluded_ports(),
            ban_time: default_dpi_ban_time(),
            detect_sqli: true,
            detect_xss: true,
            detect_cmdi: true,
            detect_path_traversal: true,
            detect_shellcode: true,
            detect_protocol_anomaly: true,
            custom_patterns: vec![],
            action: default_dpi_action(),
        }
    }
}

/// TLS interception proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProxyConfig {
    /// Enable TLS interception proxy
    #[serde(default)]
    pub enabled: bool,

    /// Listen address for the proxy
    #[serde(default = "default_tls_proxy_listen")]
    pub listen_addr: String,

    /// Listen port for the proxy
    #[serde(default = "default_tls_proxy_port")]
    pub listen_port: u16,

    /// Path to CA certificate file (PEM format)
    /// If not specified, will auto-generate and store in data_dir
    #[serde(default)]
    pub ca_cert_path: Option<String>,

    /// Path to CA private key file (PEM format)
    #[serde(default)]
    pub ca_key_path: Option<String>,

    /// Directory to cache generated certificates
    #[serde(default = "default_tls_cert_cache")]
    pub cert_cache_dir: String,

    /// Ports to intercept (redirect to proxy)
    #[serde(default = "default_tls_intercept_ports")]
    pub intercept_ports: Vec<u16>,

    /// Domains to bypass (no interception, passthrough)
    #[serde(default)]
    pub bypass_domains: Vec<String>,

    /// Enable certificate validation for upstream connections
    #[serde(default = "default_true")]
    pub verify_upstream: bool,

    /// Log decrypted traffic to file (for debugging)
    #[serde(default)]
    pub log_decrypted: bool,

    /// Path for decrypted traffic log
    #[serde(default)]
    pub decrypted_log_path: Option<String>,

    /// Maximum concurrent connections
    #[serde(default = "default_tls_max_connections")]
    pub max_connections: usize,

    /// Connection timeout in seconds
    #[serde(default = "default_tls_timeout")]
    pub timeout_secs: u64,

    /// Enable inspection of decrypted content via DPI
    #[serde(default = "default_true")]
    pub inspect_decrypted: bool,

    /// CA certificate validity in days
    #[serde(default = "default_ca_validity_days")]
    pub ca_validity_days: u32,

    /// Generated certificate validity in days
    #[serde(default = "default_cert_validity_days")]
    pub cert_validity_days: u32,

    /// CA common name
    #[serde(default = "default_ca_cn")]
    pub ca_common_name: String,

    /// CA organization
    #[serde(default = "default_ca_org")]
    pub ca_organization: String,
}

fn default_tls_proxy_listen() -> String {
    "127.0.0.1".to_string()
}

fn default_tls_proxy_port() -> u16 {
    8443
}

fn default_tls_cert_cache() -> String {
    "/var/lib/crmonban/certs".to_string()
}

fn default_tls_intercept_ports() -> Vec<u16> {
    vec![443, 8443, 993, 995, 465, 587] // HTTPS, IMAPS, POP3S, SMTPS
}

fn default_tls_max_connections() -> usize {
    1000
}

fn default_tls_timeout() -> u64 {
    30
}

fn default_ca_validity_days() -> u32 {
    3650 // 10 years
}

fn default_cert_validity_days() -> u32 {
    365 // 1 year
}

fn default_ca_cn() -> String {
    "crmonban Inspection CA".to_string()
}

fn default_ca_org() -> String {
    "crmonban Security".to_string()
}

impl Default for TlsProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_tls_proxy_listen(),
            listen_port: default_tls_proxy_port(),
            ca_cert_path: None,
            ca_key_path: None,
            cert_cache_dir: default_tls_cert_cache(),
            intercept_ports: default_tls_intercept_ports(),
            bypass_domains: vec![],
            verify_upstream: true,
            log_decrypted: false,
            decrypted_log_path: None,
            max_connections: default_tls_max_connections(),
            timeout_secs: default_tls_timeout(),
            inspect_decrypted: true,
            ca_validity_days: default_ca_validity_days(),
            cert_validity_days: default_cert_validity_days(),
            ca_common_name: default_ca_cn(),
            ca_organization: default_ca_org(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.services.contains_key("ssh"));
        assert_eq!(config.nftables.table_name, "crmonban");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.nftables.table_name, config.nftables.table_name);
    }
}

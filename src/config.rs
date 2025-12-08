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

    /// Deployment mode and network topology
    #[serde(default)]
    pub deployment: DeploymentConfig,

    /// Log forwarding to remote syslog/SIEM
    #[serde(default)]
    pub log_forward: LogForwardConfig,

    #[serde(default)]
    pub nftables: NftablesConfig,

    #[serde(default)]
    pub intel: IntelConfig,

    #[serde(default)]
    pub dbus: DbusConfig,

    #[serde(default)]
    pub display: DisplayConfig,

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
    pub port_rules: PortRulesConfig,

    #[serde(default)]
    pub ebpf_malware: EbpfMalwareConfig,

    #[serde(default)]
    pub dns_monitor: DnsMonitorConfig,

    #[serde(default)]
    pub port_hopping: PortHoppingConfig,

    /// Packet engine for live packet capture and NIDS processing
    #[serde(default)]
    pub packet_engine: PacketEngineConfig,

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
            deployment: DeploymentConfig::default(),
            log_forward: LogForwardConfig::default(),
            nftables: NftablesConfig::default(),
            intel: IntelConfig::default(),
            dbus: DbusConfig::default(),
            display: DisplayConfig::default(),
            siem: SiemConfig::default(),
            zones: ZoneConfig::default(),
            whitelist: SharedWhitelistConfig::default(),
            ebpf: EbpfConfig::default(),
            port_scan: PortScanConfig::default(),
            dpi: DpiConfig::default(),
            tls_proxy: TlsProxyConfig::default(),
            port_rules: PortRulesConfig::default(),
            ebpf_malware: EbpfMalwareConfig::default(),
            dns_monitor: DnsMonitorConfig::default(),
            port_hopping: PortHoppingConfig::default(),
            packet_engine: PacketEngineConfig::default(),
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

/// Deployment mode for crmonban
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// Protect this host only (INPUT chain)
    #[default]
    Host,
    /// Network gateway/firewall between internal and external networks (FORWARD chain)
    /// Use `protect_self` in DeploymentConfig to also protect the gateway host
    Gateway,
}

impl std::fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeploymentMode::Host => write!(f, "host"),
            DeploymentMode::Gateway => write!(f, "gateway"),
        }
    }
}

/// Deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Deployment mode: "host" or "gateway"
    #[serde(default)]
    pub mode: DeploymentMode,

    /// For gateway mode: also protect the gateway host itself (adds INPUT chain rules)
    #[serde(default = "default_true")]
    pub protect_self: bool,

    /// External/WAN interface(s) - traffic from these is untrusted
    #[serde(default)]
    pub external_interfaces: Vec<String>,

    /// Internal/LAN interface(s) - traffic to these is protected
    #[serde(default)]
    pub internal_interfaces: Vec<String>,

    /// Whether to track connection state for stateful filtering
    #[serde(default = "default_true")]
    pub stateful: bool,

    /// Whether to inspect outbound traffic for data exfiltration/C2
    #[serde(default)]
    pub inspect_outbound: bool,

    /// Rate limit for new connections per source IP (0 = disabled)
    #[serde(default)]
    pub conn_rate_limit: u32,

    /// NAT mode: none, snat, masquerade
    #[serde(default)]
    pub nat_mode: NatMode,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            mode: DeploymentMode::Host,
            protect_self: true,
            external_interfaces: Vec::new(),
            internal_interfaces: Vec::new(),
            stateful: true,
            inspect_outbound: false,
            conn_rate_limit: 0,
            nat_mode: NatMode::None,
        }
    }
}

impl DeploymentConfig {
    /// Whether this config protects the local host (INPUT chain)
    pub fn has_input_protection(&self) -> bool {
        match self.mode {
            DeploymentMode::Host => true,
            DeploymentMode::Gateway => self.protect_self,
        }
    }

    /// Whether this config inspects forwarded traffic (FORWARD chain)
    pub fn has_forward_protection(&self) -> bool {
        matches!(self.mode, DeploymentMode::Gateway)
    }
}

/// NAT mode for filter/edge deployments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NatMode {
    #[default]
    None,
    /// Source NAT with specific IP
    Snat,
    /// Masquerade (dynamic SNAT)
    Masquerade,
}

/// Log forwarding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogForwardConfig {
    /// Enable log forwarding
    #[serde(default)]
    pub enabled: bool,

    /// Syslog server address (host:port)
    #[serde(default)]
    pub syslog_server: Option<String>,

    /// Syslog protocol: udp, tcp, or tls
    #[serde(default = "default_syslog_protocol")]
    pub syslog_protocol: String,

    /// Syslog facility (0-23, default 1 = user)
    #[serde(default = "default_syslog_facility")]
    pub syslog_facility: u8,

    /// Forward security events
    #[serde(default = "default_true")]
    pub forward_events: bool,

    /// Forward ban/unban actions
    #[serde(default = "default_true")]
    pub forward_bans: bool,

    /// Forward statistics periodically
    #[serde(default)]
    pub forward_stats: bool,

    /// Stats forwarding interval in seconds
    #[serde(default = "default_stats_interval")]
    pub stats_interval: u64,

    /// JSON format for structured logging
    #[serde(default = "default_true")]
    pub json_format: bool,
}

impl Default for LogForwardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            syslog_server: None,
            syslog_protocol: default_syslog_protocol(),
            syslog_facility: default_syslog_facility(),
            forward_events: true,
            forward_bans: true,
            forward_stats: false,
            stats_interval: default_stats_interval(),
            json_format: true,
        }
    }
}

fn default_syslog_protocol() -> String {
    "udp".to_string()
}

fn default_syslog_facility() -> u8 {
    1 // user
}

fn default_stats_interval() -> u64 {
    60
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

/// Display server (dashboard) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayConfig {
    /// Enable the display server subprocess
    #[serde(default)]
    pub enabled: bool,

    /// HTTP port for the display server
    #[serde(default = "default_display_port")]
    pub port: u16,

    /// Path to display server binary (default: auto-detect)
    #[serde(default)]
    pub binary_path: Option<String>,

    /// Unix socket path for IPC (default: /run/crmonban/events.sock)
    #[serde(default)]
    pub socket_path: Option<String>,

    /// Auto-restart display server on crash
    #[serde(default = "default_true")]
    pub auto_restart: bool,
}

fn default_display_port() -> u16 {
    3001
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_display_port(),
            binary_path: None,
            socket_path: None,
            auto_restart: true,
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

/// eBPF malware detection configuration
/// Detects malicious eBPF programs like Symbiote and BPFDoor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfMalwareConfig {
    /// Enable eBPF malware detection
    #[serde(default)]
    pub enabled: bool,

    /// Monitor bpf() syscalls for unauthorized program loading
    #[serde(default = "default_true")]
    pub monitor_bpf_syscalls: bool,

    /// Monitor raw socket creation with SO_ATTACH_FILTER
    #[serde(default = "default_true")]
    pub monitor_socket_filters: bool,

    /// Alert on any eBPF program attachment
    #[serde(default = "default_true")]
    pub alert_on_attach: bool,

    /// Whitelist of processes allowed to load eBPF programs
    #[serde(default = "default_ebpf_whitelist")]
    pub whitelist_processes: Vec<String>,

    /// Known malicious port patterns (Symbiote-style port hopping)
    #[serde(default = "default_malicious_ports")]
    pub known_malicious_ports: Vec<u16>,

    /// Ban duration for detected eBPF malware C2 IPs
    #[serde(default = "default_ebpf_ban_time")]
    pub ban_time: i64,
}

fn default_ebpf_whitelist() -> Vec<String> {
    vec![
        "systemd".to_string(),
        "dockerd".to_string(),
        "containerd".to_string(),
        "cilium".to_string(),
        "bpftrace".to_string(),
        "tcpdump".to_string(),
        "wireshark".to_string(),
    ]
}

fn default_malicious_ports() -> Vec<u16> {
    // Known Symbiote port-hopping ports
    vec![54778, 58870, 59666, 54879, 57987, 64322, 45677, 63227]
}

fn default_ebpf_ban_time() -> i64 {
    86400 // 24 hours for malware C2
}

impl Default for EbpfMalwareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            monitor_bpf_syscalls: true,
            monitor_socket_filters: true,
            alert_on_attach: true,
            whitelist_processes: default_ebpf_whitelist(),
            known_malicious_ports: default_malicious_ports(),
            ban_time: default_ebpf_ban_time(),
        }
    }
}

/// DNS covert channel detection configuration
/// Detects DNS-based C2 channels like BPFDoor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMonitorConfig {
    /// Enable DNS monitoring
    #[serde(default)]
    pub enabled: bool,

    /// Detect potential covert channels in DNS traffic
    #[serde(default = "default_true")]
    pub detect_covert_channels: bool,

    /// Maximum allowed DNS query name length (longer may indicate tunneling)
    #[serde(default = "default_max_query_length")]
    pub max_query_length: usize,

    /// Minimum entropy threshold for detecting encoded data in queries
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Maximum queries per minute from single IP before flagging
    #[serde(default = "default_max_dns_rate")]
    pub max_queries_per_minute: u32,

    /// Detect TXT record abuse (common for data exfiltration)
    #[serde(default = "default_true")]
    pub detect_txt_abuse: bool,

    /// Maximum TXT record response size (bytes)
    #[serde(default = "default_max_txt_size")]
    pub max_txt_response_size: usize,

    /// Ban duration for DNS tunneling attempts
    #[serde(default = "default_dns_ban_time")]
    pub ban_time: i64,

    /// NFQUEUE number for DNS inspection
    #[serde(default = "default_dns_queue")]
    pub queue_num: u16,
}

fn default_max_query_length() -> usize {
    63 // Standard max label length
}

fn default_entropy_threshold() -> f64 {
    4.0 // High entropy indicates encoded/encrypted data
}

fn default_max_dns_rate() -> u32 {
    100 // queries per minute
}

fn default_max_txt_size() -> usize {
    512 // bytes
}

fn default_dns_ban_time() -> i64 {
    3600 // 1 hour
}

fn default_dns_queue() -> u16 {
    101 // Different from DPI queue
}

impl Default for DnsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            detect_covert_channels: true,
            max_query_length: default_max_query_length(),
            entropy_threshold: default_entropy_threshold(),
            max_queries_per_minute: default_max_dns_rate(),
            detect_txt_abuse: true,
            max_txt_response_size: default_max_txt_size(),
            ban_time: default_dns_ban_time(),
            queue_num: default_dns_queue(),
        }
    }
}

/// Port hopping detection configuration
/// Detects malware-style rapid port cycling (like Symbiote)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortHoppingConfig {
    /// Enable port hopping detection
    #[serde(default)]
    pub enabled: bool,

    /// Number of unique high ports that triggers detection
    #[serde(default = "default_hopping_threshold")]
    pub threshold: u32,

    /// Time window in seconds to count port accesses
    #[serde(default = "default_hopping_window")]
    pub window_secs: u64,

    /// Minimum port number to consider (ignore well-known ports)
    #[serde(default = "default_min_port")]
    pub min_port: u16,

    /// Ban duration for port hopping detection
    #[serde(default = "default_hopping_ban_time")]
    pub ban_time: i64,

    /// Protocols to monitor: tcp, udp, both
    #[serde(default = "default_hopping_protocols")]
    pub protocols: Vec<String>,
}

fn default_hopping_threshold() -> u32 {
    5 // 5 different high ports
}

fn default_hopping_window() -> u64 {
    30 // 30 seconds
}

fn default_min_port() -> u16 {
    1024 // Ignore well-known ports
}

fn default_hopping_ban_time() -> i64 {
    7200 // 2 hours
}

fn default_hopping_protocols() -> Vec<String> {
    vec!["tcp".to_string(), "udp".to_string()]
}

impl Default for PortHoppingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_hopping_threshold(),
            window_secs: default_hopping_window(),
            min_port: default_min_port(),
            ban_time: default_hopping_ban_time(),
            protocols: default_hopping_protocols(),
        }
    }
}

/// Port-based firewall rules configuration (like UFW)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRulesConfig {
    /// Enable port-based filtering (default deny policy)
    #[serde(default)]
    pub enabled: bool,

    /// Default policy for incoming traffic: "drop", "reject", or "accept"
    #[serde(default = "default_port_policy")]
    pub default_input_policy: String,

    /// Default policy for outgoing traffic: "drop", "reject", or "accept"
    #[serde(default = "default_accept_policy")]
    pub default_output_policy: String,

    /// Default policy for forwarded traffic: "drop", "reject", or "accept"
    #[serde(default = "default_port_policy")]
    pub default_forward_policy: String,

    /// Allow established/related connections (stateful firewall)
    #[serde(default = "default_true")]
    pub allow_established: bool,

    /// Allow loopback traffic
    #[serde(default = "default_true")]
    pub allow_loopback: bool,

    /// Allow ICMP (ping)
    #[serde(default = "default_true")]
    pub allow_icmp: bool,

    /// Port rules
    #[serde(default)]
    pub rules: Vec<PortRule>,
}

/// A single port rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRule {
    /// Rule number/priority (lower = evaluated first)
    #[serde(default)]
    pub priority: u32,

    /// Action: "allow", "deny", "reject", "log"
    pub action: PortAction,

    /// Direction: "in", "out", "both"
    #[serde(default = "default_direction")]
    pub direction: String,

    /// Protocol: "tcp", "udp", "any"
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Port number or range (e.g., "22", "80", "1000-2000")
    pub port: String,

    /// Source IP/CIDR (optional, empty = any)
    #[serde(default)]
    pub from: Option<String>,

    /// Destination IP/CIDR (optional, empty = any)
    #[serde(default)]
    pub to: Option<String>,

    /// Comment/description
    #[serde(default)]
    pub comment: String,

    /// Whether this rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Port rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortAction {
    Allow,
    Deny,
    Reject,
    Log,
}

impl std::fmt::Display for PortAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortAction::Allow => write!(f, "allow"),
            PortAction::Deny => write!(f, "deny"),
            PortAction::Reject => write!(f, "reject"),
            PortAction::Log => write!(f, "log"),
        }
    }
}

impl std::str::FromStr for PortAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "allow" => Ok(PortAction::Allow),
            "deny" | "drop" => Ok(PortAction::Deny),
            "reject" => Ok(PortAction::Reject),
            "log" => Ok(PortAction::Log),
            _ => Err(format!("Invalid action: {}", s)),
        }
    }
}

fn default_port_policy() -> String {
    "drop".to_string()
}

fn default_accept_policy() -> String {
    "accept".to_string()
}

fn default_direction() -> String {
    "in".to_string()
}

fn default_protocol() -> String {
    "tcp".to_string()
}

impl Default for PortRulesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_input_policy: default_port_policy(),
            default_output_policy: default_accept_policy(),
            default_forward_policy: default_port_policy(),
            allow_established: true,
            allow_loopback: true,
            allow_icmp: true,
            rules: vec![
                // Default allow SSH
                PortRule {
                    priority: 100,
                    action: PortAction::Allow,
                    direction: "in".to_string(),
                    protocol: "tcp".to_string(),
                    port: "22".to_string(),
                    from: None,
                    to: None,
                    comment: "Allow SSH".to_string(),
                    enabled: true,
                },
            ],
        }
    }
}

impl PortRule {
    /// Create a new allow rule
    pub fn allow(port: &str, protocol: &str) -> Self {
        Self {
            priority: 100,
            action: PortAction::Allow,
            direction: "in".to_string(),
            protocol: protocol.to_string(),
            port: port.to_string(),
            from: None,
            to: None,
            comment: String::new(),
            enabled: true,
        }
    }

    /// Create a new deny rule
    pub fn deny(port: &str, protocol: &str) -> Self {
        Self {
            priority: 100,
            action: PortAction::Deny,
            direction: "in".to_string(),
            protocol: protocol.to_string(),
            port: port.to_string(),
            from: None,
            to: None,
            comment: String::new(),
            enabled: true,
        }
    }

    /// Parse port string to get port number(s)
    pub fn parse_ports(&self) -> Result<Vec<u16>, String> {
        if self.port.contains('-') {
            // Port range
            let parts: Vec<&str> = self.port.split('-').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid port range: {}", self.port));
            }
            let start: u16 = parts[0].parse().map_err(|_| format!("Invalid port: {}", parts[0]))?;
            let end: u16 = parts[1].parse().map_err(|_| format!("Invalid port: {}", parts[1]))?;
            Ok((start..=end).collect())
        } else if self.port.contains(',') {
            // Multiple ports
            self.port
                .split(',')
                .map(|p| p.trim().parse::<u16>().map_err(|_| format!("Invalid port: {}", p)))
                .collect()
        } else {
            // Single port
            let port: u16 = self.port.parse().map_err(|_| format!("Invalid port: {}", self.port))?;
            Ok(vec![port])
        }
    }
}

/// Packet engine configuration for live packet capture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEngineConfig {
    /// Enable packet engine
    pub enabled: bool,
    /// Capture method: "af_packet", "nfqueue", or "pcap"
    pub capture_method: String,
    /// Interface to capture on (for af_packet mode)
    pub interface: Option<String>,
    /// NFQUEUE number (for nfqueue mode)
    pub nfqueue_num: u16,
    /// Enable promiscuous mode
    pub promiscuous: bool,
    /// Snapshot length (max bytes per packet)
    pub snaplen: u32,
    /// Read timeout in milliseconds
    pub timeout_ms: u32,
    /// Number of worker threads (0 = auto-detect)
    pub workers: usize,
    /// Enable signature matching
    pub signatures_enabled: bool,
    /// Path to rules directory
    pub rules_dir: Option<String>,
    /// Enable flow tracking
    pub flow_tracking: bool,
    /// Enable ML anomaly detection
    pub ml_detection: bool,
    /// Enable threat intel lookups
    pub threat_intel: bool,
    /// Ban duration for detected attacks (seconds)
    pub ban_duration: i64,
    /// Auto-ban on signature match
    pub auto_ban: bool,
}

impl Default for PacketEngineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capture_method: "af_packet".to_string(),
            interface: None,
            nfqueue_num: 100,
            promiscuous: true,
            snaplen: 65535,
            timeout_ms: 100,
            workers: 0,
            signatures_enabled: true,
            rules_dir: Some("/var/lib/crmonban/data/rules".to_string()),
            flow_tracking: true,
            ml_detection: false,
            threat_intel: false,
            ban_duration: 3600,
            auto_ban: false,
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

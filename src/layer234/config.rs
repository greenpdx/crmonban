//! Configuration file support for NetVec detector
//!
//! Supports loading configuration from TOML files.

use super::error::{NetVecError, Result};
use super::types::VECTOR_DIM;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Root configuration structure
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// General detector settings
    pub detector: DetectorSettings,

    /// Scan detection settings
    pub scan: ScanSettings,

    /// Brute force detection settings
    pub brute_force: BruteForceSettings,

    /// Anomaly detection settings
    pub anomaly: AnomalySettings,

    /// DoS attack detection settings
    pub dos: DosSettings,

    /// Performance and resource settings
    pub performance: PerformanceSettings,

    /// PostgreSQL database configuration (for future use)
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Pre-defined attack signatures
    #[serde(default)]
    pub signatures: Vec<SignatureConfig>,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Packet stream logging configuration
    #[serde(default)]
    pub packet_log: PacketLogConfig,

    /// Alerting configuration
    #[serde(default)]
    pub alerts: AlertsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            detector: DetectorSettings::default(),
            scan: ScanSettings::default(),
            brute_force: BruteForceSettings::default(),
            anomaly: AnomalySettings::default(),
            dos: DosSettings::default(),
            performance: PerformanceSettings::default(),
            database: DatabaseConfig::default(),
            signatures: default_signatures(),
            logging: LoggingConfig::default(),
            packet_log: PacketLogConfig::default(),
            alerts: AlertsConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            NetVecError::ConfigError(format!("Failed to read config file: {}", e))
        })?;
        let mut config = Self::from_str(&content)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Parse configuration from a TOML string
    pub fn from_str(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| NetVecError::ConfigError(format!("Failed to parse config: {}", e)))
    }

    /// Serialize configuration to a TOML string
    pub fn to_string(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| NetVecError::ConfigError(format!("Failed to serialize config: {}", e)))
    }

    /// Save configuration to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = self.to_string()?;
        std::fs::write(path.as_ref(), content).map_err(|e| {
            NetVecError::ConfigError(format!("Failed to write config file: {}", e))
        })
    }

    /// Generate default config file content with comments
    pub fn default_with_comments() -> &'static str {
        DEFAULT_CONFIG
    }

    /// Apply environment variable overrides to the configuration.
    /// Environment variables (including those loaded from .env) override config file values.
    ///
    /// Supported environment variables:
    /// - SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_TLS
    /// - L2D_ALERTS_ENABLED, L2D_ALERTS_EMAIL_ENABLED
    /// - L2D_ALERTS_EMAIL_RECIPIENTS (comma-separated)
    /// - L2D_LOGGING_ENABLED, L2D_LOGGING_LEVEL
    /// - L2D_LOGGING_JSON_PATH, L2D_PACKET_LOG_PATH
    pub fn apply_env_overrides(&mut self) {
        // SMTP settings
        if let Ok(v) = std::env::var("SMTP_HOST") {
            self.alerts.smtp.host = v;
        }
        if let Ok(v) = std::env::var("SMTP_PORT") {
            if let Ok(port) = v.parse() {
                self.alerts.smtp.port = port;
            }
        }
        if let Ok(v) = std::env::var("SMTP_USER") {
            self.alerts.smtp.username = Some(v);
        }
        if let Ok(v) = std::env::var("SMTP_PASS") {
            self.alerts.smtp.password = Some(v);
        }
        if let Ok(v) = std::env::var("SMTP_FROM") {
            self.alerts.smtp.from = v;
        }
        if let Ok(v) = std::env::var("SMTP_TLS") {
            self.alerts.smtp.tls = v;
        }

        // Alerts settings
        if let Ok(v) = std::env::var("L2D_ALERTS_ENABLED") {
            self.alerts.enabled = v.parse().unwrap_or(self.alerts.enabled);
        }
        if let Ok(v) = std::env::var("L2D_ALERTS_EMAIL_ENABLED") {
            self.alerts.email.enabled = v.parse().unwrap_or(self.alerts.email.enabled);
        }
        // Accept SMTP_TO or L2D_ALERTS_EMAIL_RECIPIENTS
        if let Ok(v) = std::env::var("SMTP_TO").or_else(|_| std::env::var("L2D_ALERTS_EMAIL_RECIPIENTS")) {
            self.alerts.email.recipients = v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("L2D_ALERTS_EMAIL_DIGEST_INTERVAL") {
            if let Ok(secs) = v.parse() {
                self.alerts.email.digest_interval_secs = secs;
            }
        }
        if let Ok(v) = std::env::var("L2D_ALERTS_EMAIL_MAX_PER_HOUR") {
            if let Ok(max) = v.parse() {
                self.alerts.email.max_emails_per_hour = max;
            }
        }

        // Command alert settings
        if let Ok(v) = std::env::var("L2D_ALERTS_COMMAND_ENABLED") {
            self.alerts.command.enabled = v.parse().unwrap_or(self.alerts.command.enabled);
        }
        if let Ok(v) = std::env::var("L2D_ALERTS_COMMAND") {
            self.alerts.command.command = v;
        }

        // Logging settings
        if let Ok(v) = std::env::var("L2D_LOGGING_ENABLED") {
            self.logging.enabled = v.parse().unwrap_or(self.logging.enabled);
        }
        if let Ok(v) = std::env::var("L2D_LOGGING_LEVEL") {
            self.logging.level = v;
        }
        if let Ok(v) = std::env::var("L2D_LOGGING_JSON_PATH") {
            self.logging.json.path = v;
        }
        if let Ok(v) = std::env::var("L2D_LOGGING_JSON_ENABLED") {
            self.logging.json.enabled = v.parse().unwrap_or(self.logging.json.enabled);
        }

        // Packet log settings
        if let Ok(v) = std::env::var("L2D_PACKET_LOG_ENABLED") {
            self.packet_log.enabled = v.parse().unwrap_or(self.packet_log.enabled);
        }
        if let Ok(v) = std::env::var("L2D_PACKET_LOG_PATH") {
            self.packet_log.path = v;
        }
        if let Ok(v) = std::env::var("L2D_PACKET_LOG_ALL_HTTP") {
            self.packet_log.log_all_http = v.parse().unwrap_or(self.packet_log.log_all_http);
        }

        // Detector settings
        if let Ok(v) = std::env::var("L2D_DETECTOR_SCAN") {
            self.detector.scan_detection = v.parse().unwrap_or(self.detector.scan_detection);
        }
        if let Ok(v) = std::env::var("L2D_DETECTOR_BRUTE_FORCE") {
            self.detector.brute_force_detection = v.parse().unwrap_or(self.detector.brute_force_detection);
        }
        if let Ok(v) = std::env::var("L2D_DETECTOR_ANOMALY") {
            self.detector.anomaly_detection = v.parse().unwrap_or(self.detector.anomaly_detection);
        }
        if let Ok(v) = std::env::var("L2D_DETECTOR_DOS") {
            self.detector.dos_detection = v.parse().unwrap_or(self.detector.dos_detection);
        }
        if let Ok(v) = std::env::var("L2D_DETECTOR_WINDOW_MS") {
            if let Ok(ms) = v.parse() {
                self.detector.window_size_ms = ms;
            }
        }

        // Performance/persistence settings
        if let Ok(v) = std::env::var("L2D_SIGNATURE_PATH") {
            self.performance.signature_path = Some(v);
        }
        if let Ok(v) = std::env::var("L2D_BASELINE_PATH") {
            self.performance.baseline_path = Some(v);
        }

        // Database settings
        if let Ok(v) = std::env::var("L2D_DATABASE_ENABLED") {
            self.database.enabled = v.parse().unwrap_or(self.database.enabled);
        }
        if let Ok(v) = std::env::var("L2D_DATABASE_HOST") {
            self.database.host = v;
        }
        if let Ok(v) = std::env::var("L2D_DATABASE_PORT") {
            if let Ok(port) = v.parse() {
                self.database.port = port;
            }
        }
        if let Ok(v) = std::env::var("L2D_DATABASE_NAME") {
            self.database.name = v;
        }
        if let Ok(v) = std::env::var("L2D_DATABASE_USER") {
            self.database.username = Some(v);
        }
        if let Ok(v) = std::env::var("L2D_DATABASE_PASS") {
            self.database.password = Some(v);
        }
        if let Ok(v) = std::env::var("L2D_DATABASE_SSL") {
            self.database.ssl_mode = v;
        }
        if let Ok(v) = std::env::var("L2D_DATABASE_POOL_MIN") {
            if let Ok(n) = v.parse() {
                self.database.pool_min = n;
            }
        }
        if let Ok(v) = std::env::var("L2D_DATABASE_POOL_MAX") {
            if let Ok(n) = v.parse() {
                self.database.pool_max = n;
            }
        }
        // Also support DATABASE_URL for full connection string override
        if let Ok(v) = std::env::var("DATABASE_URL") {
            // Parse DATABASE_URL and extract components
            // Format: postgres://user:pass@host:port/dbname?sslmode=mode
            if let Some(url) = parse_database_url(&v) {
                self.database.enabled = true;
                self.database.host = url.host;
                self.database.port = url.port;
                self.database.name = url.name;
                self.database.username = Some(url.user);
                if !url.password.is_empty() {
                    self.database.password = Some(url.password);
                }
                self.database.ssl_mode = url.ssl_mode;
            }
        }
    }
}

/// Parsed database URL components
struct ParsedDatabaseUrl {
    host: String,
    port: u16,
    name: String,
    user: String,
    password: String,
    ssl_mode: String,
}

/// Parse a PostgreSQL connection URL
fn parse_database_url(url: &str) -> Option<ParsedDatabaseUrl> {
    // postgres://user:pass@host:port/dbname?sslmode=mode
    let url = url.strip_prefix("postgres://")?;

    let (auth_host, rest) = if let Some(idx) = url.find('/') {
        (&url[..idx], &url[idx + 1..])
    } else {
        return None;
    };

    let (dbname, params) = if let Some(idx) = rest.find('?') {
        (&rest[..idx], &rest[idx + 1..])
    } else {
        (rest, "")
    };

    let (auth, host_port) = if let Some(idx) = auth_host.rfind('@') {
        (&auth_host[..idx], &auth_host[idx + 1..])
    } else {
        ("", auth_host)
    };

    let (user, password) = if let Some(idx) = auth.find(':') {
        (&auth[..idx], &auth[idx + 1..])
    } else {
        (auth, "")
    };

    let (host, port) = if let Some(idx) = host_port.rfind(':') {
        (&host_port[..idx], host_port[idx + 1..].parse().unwrap_or(5432))
    } else {
        (host_port, 5432u16)
    };

    let ssl_mode = params
        .split('&')
        .find(|p| p.starts_with("sslmode="))
        .map(|p| p.strip_prefix("sslmode=").unwrap_or("prefer"))
        .unwrap_or("prefer")
        .to_string();

    Some(ParsedDatabaseUrl {
        host: host.to_string(),
        port,
        name: dbname.to_string(),
        user: user.to_string(),
        password: password.to_string(),
        ssl_mode,
    })
}

/// General detector settings
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectorSettings {
    /// Enable scan detection (SYN, Connect, UDP, etc.)
    pub scan_detection: bool,

    /// Enable brute force detection
    pub brute_force_detection: bool,

    /// Enable anomaly-based detection
    pub anomaly_detection: bool,

    /// Enable DoS/DDoS attack detection
    pub dos_detection: bool,

    /// Time window size in milliseconds for aggregating packets
    pub window_size_ms: u64,

    /// Minimum packets required before analyzing a window
    pub min_packets: usize,
}

impl Default for DetectorSettings {
    fn default() -> Self {
        Self {
            scan_detection: true,
            brute_force_detection: true,
            anomaly_detection: true,
            dos_detection: true,
            window_size_ms: 60_000,
            min_packets: 10,
        }
    }
}

/// Scan detection settings
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanSettings {
    /// Signature matching threshold (0.0-1.0, higher = stricter)
    pub signature_threshold: f32,

    /// Minimum SYN ratio to consider as SYN scan
    pub syn_scan_threshold: f32,

    /// Minimum half-open connection ratio for SYN scan
    pub half_open_threshold: f32,

    /// Minimum unique ports ratio for port scan
    pub unique_ports_threshold: f32,

    /// Ports commonly scanned (used for signature weighting)
    pub common_scan_ports: Vec<u16>,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            signature_threshold: 0.85,
            syn_scan_threshold: 0.7,
            half_open_threshold: 0.5,
            unique_ports_threshold: 0.02,
            common_scan_ports: vec![
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306,
                3389, 5900, 8080,
            ],
        }
    }
}

/// Brute force detection settings
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct BruteForceSettings {
    /// Ports considered authentication services (brute force targets)
    pub auth_ports: Vec<u16>,

    /// Minimum auth port ratio to trigger brute force detection
    pub auth_port_threshold: f32,

    /// Minimum single port concentration for brute force
    pub single_port_threshold: f32,

    /// Minimum successful handshake ratio for brute force
    pub handshake_threshold: f32,

    /// Maximum unique port ratio (brute force targets single port)
    pub max_unique_port_ratio: f32,
}

impl Default for BruteForceSettings {
    fn default() -> Self {
        Self {
            auth_ports: vec![
                21,    // FTP
                22,    // SSH
                23,    // Telnet
                25,    // SMTP
                110,   // POP3
                143,   // IMAP
                389,   // LDAP
                445,   // SMB
                993,   // IMAPS
                995,   // POP3S
                1433,  // MSSQL
                3306,  // MySQL
                3389,  // RDP
                5432,  // PostgreSQL
                5900,  // VNC
                6379,  // Redis
                27017, // MongoDB
            ],
            auth_port_threshold: 0.5,
            single_port_threshold: 0.7,
            handshake_threshold: 0.3,
            max_unique_port_ratio: 0.1,
        }
    }
}

/// Anomaly detection settings
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AnomalySettings {
    /// Distance threshold for anomaly detection (0.0-1.0)
    /// Higher values = more permissive (fewer false positives)
    pub threshold: f32,

    /// Minimum baseline samples before enabling anomaly detection
    pub min_baseline_samples: usize,

    /// Enable automatic baseline learning from normal traffic
    pub auto_baseline: bool,
}

impl Default for AnomalySettings {
    fn default() -> Self {
        Self {
            threshold: 0.7,
            min_baseline_samples: 100,
            auto_baseline: false,
        }
    }
}

/// DoS (Denial of Service) attack detection settings
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DosSettings {
    /// Enable DoS detection
    pub enabled: bool,

    /// Minimum normalized packet rate to consider as potential DoS (0.0-1.0)
    /// 0.1 = 10,000 packets/sec, 0.5 = 50,000 packets/sec
    pub min_packet_rate: f32,

    /// Minimum normalized byte rate to consider as potential DoS (0.0-1.0)
    /// 0.1 = 12.5 MB/s, 0.5 = 62.5 MB/s
    pub min_byte_rate: f32,

    /// Minimum connection rate for connection exhaustion detection (0.0-1.0)
    /// 0.05 = 500 connections/sec
    pub min_connection_rate: f32,

    /// Half-open ratio threshold for SYN flood detection
    pub half_open_threshold: f32,
}

impl Default for DosSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            min_packet_rate: 0.1,
            min_byte_rate: 0.1,
            min_connection_rate: 0.05,
            half_open_threshold: 0.7,
        }
    }
}

/// Performance and resource settings
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceSettings {
    /// Maximum number of concurrent TCP sessions to track
    pub max_sessions: usize,

    /// Signature store capacity
    pub signature_capacity: usize,

    /// Baseline store capacity
    pub baseline_capacity: usize,

    /// Path for persistent signature storage (optional)
    pub signature_path: Option<String>,

    /// Path for persistent baseline storage (optional)
    pub baseline_path: Option<String>,
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            max_sessions: 100_000,
            signature_capacity: 10_000,
            baseline_capacity: 100_000,
            signature_path: None,
            baseline_path: None,
        }
    }
}

// =============================================================================
// Database Configuration
// =============================================================================

/// PostgreSQL database configuration (for future use)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Enable database storage
    pub enabled: bool,

    /// Database host
    pub host: String,

    /// Database port
    pub port: u16,

    /// Database name
    pub name: String,

    /// Database username (prefer L2D_DATABASE_USER env var)
    pub username: Option<String>,

    /// Database password (prefer L2D_DATABASE_PASS env var)
    pub password: Option<String>,

    /// Connection pool minimum size
    pub pool_min: u32,

    /// Connection pool maximum size
    pub pool_max: u32,

    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,

    /// SSL mode: "disable", "prefer", "require"
    pub ssl_mode: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "localhost".to_string(),
            port: 5432,
            name: "layer2detect".to_string(),
            username: None,
            password: None,
            pool_min: 1,
            pool_max: 10,
            connect_timeout_secs: 30,
            ssl_mode: "prefer".to_string(),
        }
    }
}

impl DatabaseConfig {
    /// Build a PostgreSQL connection URL
    pub fn connection_url(&self) -> String {
        let user = self.username.as_deref().unwrap_or("layer2detect");
        let pass = self.password.as_deref().unwrap_or("");

        if pass.is_empty() {
            format!(
                "postgres://{}@{}:{}/{}?sslmode={}",
                user, self.host, self.port, self.name, self.ssl_mode
            )
        } else {
            format!(
                "postgres://{}:{}@{}:{}/{}?sslmode={}",
                user, pass, self.host, self.port, self.name, self.ssl_mode
            )
        }
    }
}

// =============================================================================
// Logging Configuration
// =============================================================================

/// Logging configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Enable logging subsystem
    pub enabled: bool,

    /// Log level: "trace", "debug", "info", "warn", "error"
    pub level: String,

    /// JSON file logging configuration
    pub json: JsonLogConfig,

    /// Syslog configuration
    pub syslog: SyslogConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: "info".to_string(),
            json: JsonLogConfig::default(),
            syslog: SyslogConfig::default(),
        }
    }
}

/// JSON file logging configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct JsonLogConfig {
    /// Enable JSON file logging
    pub enabled: bool,

    /// Log file path
    pub path: String,

    /// Rotation strategy: "daily", "hourly", "size"
    pub rotation: String,

    /// Max file size in bytes (for size-based rotation)
    pub max_size_bytes: u64,

    /// Number of rotated files to keep
    pub max_files: usize,
}

impl Default for JsonLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "/var/log/layer2detect/alerts.jsonl".to_string(),
            rotation: "daily".to_string(),
            max_size_bytes: 104_857_600, // 100MB
            max_files: 7,
        }
    }
}

/// Syslog configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SyslogConfig {
    /// Enable syslog output
    pub enabled: bool,

    /// Syslog facility
    pub facility: String,

    /// Remote syslog server (optional)
    pub remote_host: Option<String>,

    /// Remote syslog port
    pub remote_port: Option<u16>,

    /// Protocol for remote syslog: "udp" or "tcp"
    pub remote_protocol: Option<String>,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            facility: "daemon".to_string(),
            remote_host: None,
            remote_port: None,
            remote_protocol: None,
        }
    }
}

// =============================================================================
// Packet Stream Logging Configuration
// =============================================================================

/// Packet stream logging configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PacketLogConfig {
    /// Enable packet stream logging
    pub enabled: bool,

    /// Log file path
    pub path: String,

    /// Log all HTTP/HTTPS URLs (even without alerts)
    pub log_all_http: bool,

    /// Minimum confidence to log packets for alerts
    pub min_confidence: f32,

    /// Include payload hex dump
    pub include_payload_hex: bool,

    /// Maximum payload bytes to capture
    pub max_payload_bytes: usize,
}

impl Default for PacketLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "/var/log/layer2detect/packets.jsonl".to_string(),
            log_all_http: true,
            min_confidence: 0.0,
            include_payload_hex: true,
            max_payload_bytes: 2048,
        }
    }
}

// =============================================================================
// Alerting Configuration
// =============================================================================

/// Alerting configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertsConfig {
    /// Enable alerting subsystem
    pub enabled: bool,

    /// Email alert configuration
    pub email: EmailAlertConfig,

    /// SMTP configuration
    pub smtp: SmtpConfig,

    /// Command execution configuration
    pub command: CommandAlertConfig,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            email: EmailAlertConfig::default(),
            smtp: SmtpConfig::default(),
            command: CommandAlertConfig::default(),
        }
    }
}

/// Email alert configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailAlertConfig {
    /// Enable email alerts
    pub enabled: bool,

    /// Enable immediate alerts for critical threats
    pub immediate_enabled: bool,

    /// Enable digest emails
    pub digest_enabled: bool,

    /// Digest interval in seconds
    pub digest_interval_secs: u64,

    /// Threat types that trigger immediate alerts
    pub immediate_threat_types: Vec<String>,

    /// Minimum confidence for immediate alerts
    pub immediate_min_confidence: f32,

    /// Minimum confidence for digest inclusion
    pub digest_min_confidence: f32,

    /// Maximum emails per hour (rate limiting)
    pub max_emails_per_hour: u32,

    /// Email recipients
    pub recipients: Vec<String>,
}

impl Default for EmailAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            immediate_enabled: false, // Disabled for testing
            digest_enabled: true,
            digest_interval_secs: 300, // 5 minutes
            immediate_threat_types: vec!["SynFlood".to_string()],
            immediate_min_confidence: 0.95,
            digest_min_confidence: 0.0, // Include all in digest for testing
            max_emails_per_hour: 10,
            recipients: Vec::new(),
        }
    }
}

/// SMTP configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SmtpConfig {
    /// SMTP server hostname
    pub host: String,

    /// SMTP server port
    pub port: u16,

    /// SMTP username (optional, prefer SMTP_USER env var)
    pub username: Option<String>,

    /// SMTP password (optional, prefer SMTP_PASS env var)
    pub password: Option<String>,

    /// From address
    pub from: String,

    /// TLS mode: "none", "starttls", "tls"
    pub tls: String,

    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: None,
            password: None,
            from: "layer2detect@example.com".to_string(),
            tls: "starttls".to_string(),
            timeout_secs: 30,
        }
    }
}

/// Command execution on alert configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandAlertConfig {
    /// Enable command execution
    pub enabled: bool,

    /// Command/script to execute
    pub command: String,

    /// Working directory
    pub workdir: Option<String>,

    /// Timeout in seconds
    pub timeout_secs: u64,

    /// Threat types that trigger command (empty = all)
    pub threat_types: Vec<String>,

    /// Minimum confidence to trigger
    pub min_confidence: f32,

    /// Additional environment variables
    pub env_vars: Option<std::collections::HashMap<String, String>>,
}

impl Default for CommandAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            command: "/usr/local/bin/on-alert.sh".to_string(),
            workdir: None,
            timeout_secs: 30,
            threat_types: Vec::new(),
            min_confidence: 0.5,
            env_vars: None,
        }
    }
}

/// Pre-defined signature configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Unique name for this signature
    pub name: String,

    /// Description of what this signature detects
    #[serde(default)]
    pub description: String,

    /// Feature vector values (sparse representation)
    /// Maps feature index to value
    pub features: Vec<FeatureValue>,

    /// Whether this signature is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// A single feature value in a signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureValue {
    /// Feature index (0-71)
    pub index: usize,
    /// Feature value (0.0-1.0)
    pub value: f32,
}

impl SignatureConfig {
    /// Convert to a full feature vector
    pub fn to_vector(&self) -> [f32; VECTOR_DIM] {
        let mut vec = [0.0f32; VECTOR_DIM];
        for fv in &self.features {
            if fv.index < VECTOR_DIM {
                vec[fv.index] = fv.value;
            }
        }
        vec
    }
}

/// Default attack signatures
fn default_signatures() -> Vec<SignatureConfig> {
    vec![
        // Scan signatures
        SignatureConfig {
            name: "syn_scan_large".to_string(),
            description: "TCP SYN scan targeting many ports".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.8 },   // Many unique ports
                FeatureValue { index: 12, value: 0.95 }, // High SYN ratio
                FeatureValue { index: 13, value: 0.02 }, // Low SYN-ACK ratio
                FeatureValue { index: 17, value: 0.9 },  // High half-open ratio
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "syn_scan_small".to_string(),
            description: "TCP SYN scan targeting fewer ports".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.1 },   // Fewer unique ports
                FeatureValue { index: 12, value: 0.98 }, // Very high SYN ratio
                FeatureValue { index: 13, value: 0.0 },  // No SYN-ACK
                FeatureValue { index: 17, value: 1.0 },  // All half-open
            ],
            enabled: true,
        },
        // Connect scan from ATTACKER perspective: SYN -> ACK -> RST per port
        // Attacker doesn't send SYN-ACK (target does), so synack_ratio=0
        SignatureConfig {
            name: "connect_scan_large".to_string(),
            description: "TCP Connect scan targeting many ports (100+)".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.15 },  // ~150 unique ports
                FeatureValue { index: 12, value: 0.33 }, // SYN is 1/3 of packets (SYN,ACK,RST)
                FeatureValue { index: 13, value: 0.0 },  // Attacker never sends SYN-ACK
                FeatureValue { index: 14, value: 0.33 }, // RST is 1/3 of packets
                FeatureValue { index: 19, value: 1.0 },  // RST after SYN (no SYN-ACK seen)
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "connect_scan_medium".to_string(),
            description: "TCP Connect scan targeting moderate ports (50-100)".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.07 },  // ~70 unique ports
                FeatureValue { index: 12, value: 0.33 }, // SYN ratio
                FeatureValue { index: 13, value: 0.0 },  // No SYN-ACK from attacker
                FeatureValue { index: 14, value: 0.33 }, // RST ratio
                FeatureValue { index: 19, value: 1.0 },  // RST after SYN
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "connect_scan_small".to_string(),
            description: "TCP Connect scan targeting fewer ports (20-50)".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.035 }, // ~35 unique ports
                FeatureValue { index: 12, value: 0.33 }, // SYN ratio
                FeatureValue { index: 13, value: 0.0 },  // No SYN-ACK
                FeatureValue { index: 14, value: 0.33 }, // RST ratio
                FeatureValue { index: 19, value: 1.0 },  // RST after SYN
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "udp_scan".to_string(),
            description: "UDP port scan".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.8 },  // Many unique ports
                FeatureValue { index: 24, value: 0.1 }, // Low response ratio
                FeatureValue { index: 25, value: 0.6 }, // ICMP unreachable responses
                FeatureValue { index: 27, value: 0.9 }, // Empty payloads
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "ping_sweep".to_string(),
            description: "ICMP ping sweep across hosts".to_string(),
            features: vec![
                FeatureValue { index: 8, value: 0.9 },  // Many unique IPs
                FeatureValue { index: 36, value: 0.95 }, // High echo request ratio
                FeatureValue { index: 40, value: 0.9 }, // Ping sweep score
                FeatureValue { index: 44, value: 0.8 }, // Regular timing
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "brute_force".to_string(),
            description: "Authentication brute force attack".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.02 },  // Single port
                FeatureValue { index: 12, value: 0.5 },  // Moderate SYN ratio
                FeatureValue { index: 13, value: 0.0 },  // Attacker doesn't see SYN-ACK
                FeatureValue { index: 20, value: 1.0 },  // All traffic to auth port
                FeatureValue { index: 21, value: 1.0 },  // Single port concentration
            ],
            enabled: true,
        },
        // DoS attack signatures
        SignatureConfig {
            name: "syn_flood".to_string(),
            description: "TCP SYN flood attack - high rate SYN packets without handshake completion".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.02 },  // Few unique ports (not a scan)
                FeatureValue { index: 12, value: 0.95 }, // Very high SYN ratio
                FeatureValue { index: 13, value: 0.02 }, // Almost no SYN-ACK
                FeatureValue { index: 64, value: 0.5 },  // High packet rate (50k pps)
                FeatureValue { index: 68, value: 0.8 },  // High TCP flood score
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "syn_flood_low_rate".to_string(),
            description: "Slowloris-style SYN flood at lower rate".to_string(),
            features: vec![
                FeatureValue { index: 1, value: 0.01 },  // Single port typically
                FeatureValue { index: 12, value: 0.9 },  // High SYN ratio
                FeatureValue { index: 64, value: 0.15 }, // Moderate packet rate (15k pps)
                FeatureValue { index: 66, value: 0.3 },  // High connection rate
                FeatureValue { index: 67, value: 0.8 },  // High half-open indicator
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "udp_flood".to_string(),
            description: "UDP flood attack - high rate UDP packets".to_string(),
            features: vec![
                FeatureValue { index: 31, value: 0.9 },  // High "other services" UDP ratio
                FeatureValue { index: 64, value: 0.5 },  // High packet rate
                FeatureValue { index: 65, value: 0.5 },  // High byte rate
                FeatureValue { index: 69, value: 0.8 },  // High UDP flood score
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "icmp_flood".to_string(),
            description: "ICMP echo flood (ping flood) to single target".to_string(),
            features: vec![
                FeatureValue { index: 8, value: 0.02 },  // Single/few destination IPs (not sweep)
                FeatureValue { index: 36, value: 0.95 }, // High ICMP echo request ratio
                FeatureValue { index: 64, value: 0.3 },  // High packet rate
                FeatureValue { index: 70, value: 0.8 },  // High ICMP flood score
            ],
            enabled: true,
        },
        SignatureConfig {
            name: "connection_exhaustion".to_string(),
            description: "Connection exhaustion attack - many half-open connections".to_string(),
            features: vec![
                FeatureValue { index: 12, value: 0.6 },  // Elevated SYN ratio
                FeatureValue { index: 17, value: 0.85 }, // Very high half-open ratio
                FeatureValue { index: 66, value: 0.4 },  // High connection rate
                FeatureValue { index: 71, value: 0.7 },  // Connection exhaustion score
            ],
            enabled: true,
        },
    ]
}

/// Default configuration file content with comments
const DEFAULT_CONFIG: &str = r#"# NetVec Detection Configuration
# ================================

[detector]
# Enable different detection modules
scan_detection = true
brute_force_detection = true
anomaly_detection = true
dos_detection = true

# Time window for packet aggregation (milliseconds)
window_size_ms = 60000

# Minimum packets before analyzing a window
min_packets = 10

[scan]
# Signature matching threshold (0.0-1.0)
# Higher = stricter matching, fewer false positives
signature_threshold = 0.85

# Thresholds for heuristic scan detection
syn_scan_threshold = 0.7
half_open_threshold = 0.5
unique_ports_threshold = 0.02

# Commonly scanned ports (for signature weighting)
common_scan_ports = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

[brute_force]
# Ports considered authentication services
# Traffic concentrated on these ports may indicate brute force
auth_ports = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    389,   # LDAP
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    27017, # MongoDB
]

# Detection thresholds
auth_port_threshold = 0.5      # Minimum ratio of traffic to auth ports
single_port_threshold = 0.7    # Minimum concentration on single port
handshake_threshold = 0.3      # Minimum successful handshakes
max_unique_port_ratio = 0.1    # Maximum unique ports (brute force = single port)

[anomaly]
# Distance threshold for anomaly detection (0.0-1.0)
# Higher = more permissive, fewer false positives
threshold = 0.7

# Minimum baseline samples before enabling detection
min_baseline_samples = 100

# Automatically learn baseline from normal traffic
auto_baseline = false

[dos]
# Enable DoS attack detection
enabled = true

# Minimum packet rate to consider as potential flood (normalized: 0-1)
# 0.1 = 10,000 pps, 0.5 = 50,000 pps
min_packet_rate = 0.1

# Minimum byte rate threshold (normalized: 0-1)
# 0.1 = 12.5 MB/s, 0.5 = 62.5 MB/s
min_byte_rate = 0.1

# Minimum connection rate for connection exhaustion (normalized: 0-1)
# 0.05 = 500 connections/sec
min_connection_rate = 0.05

# Half-open ratio threshold for SYN flood detection
half_open_threshold = 0.7

[performance]
# Maximum concurrent TCP sessions to track
max_sessions = 100000

# Vector store capacities
signature_capacity = 10000
baseline_capacity = 100000

# Optional persistence paths (uncomment to enable)
# signature_path = "/var/lib/netvec/signatures.db"
# baseline_path = "/var/lib/netvec/baseline.db"

# Pre-defined attack signatures
# =============================
# Each signature defines feature values that indicate an attack pattern.
# Feature indices correspond to the 72-dimensional feature vector:
#   0-11:  Protocol-agnostic (ports, timing, targets)
#   12-23: TCP-specific (flags, connections, behavior)
#   24-35: UDP-specific (patterns, services, amplification)
#   36-47: ICMP-specific (types, patterns, timing)
#   48-63: TLS-specific (probes, versions, behavior)
#   64-71: DoS-specific (packet rate, byte rate, flood scores)

[[signatures]]
name = "syn_scan_large"
description = "TCP SYN scan targeting many ports"
enabled = true
features = [
    { index = 1, value = 0.8 },   # Many unique ports
    { index = 12, value = 0.95 }, # High SYN ratio
    { index = 13, value = 0.02 }, # Low SYN-ACK ratio
    { index = 17, value = 0.9 },  # High half-open ratio
]

[[signatures]]
name = "syn_scan_small"
description = "TCP SYN scan targeting fewer ports"
enabled = true
features = [
    { index = 1, value = 0.1 },   # Fewer unique ports
    { index = 12, value = 0.98 }, # Very high SYN ratio
    { index = 13, value = 0.0 },  # No SYN-ACK
    { index = 17, value = 1.0 },  # All half-open
]

# Connect scan from ATTACKER perspective: SYN -> ACK -> RST per port
# Attacker doesn't send SYN-ACK (target does), so synack_ratio=0

[[signatures]]
name = "connect_scan_large"
description = "TCP Connect scan targeting many ports (100+)"
enabled = true
features = [
    { index = 1, value = 0.15 },  # ~150 unique ports
    { index = 12, value = 0.33 }, # SYN is 1/3 of packets (SYN,ACK,RST)
    { index = 13, value = 0.0 },  # Attacker never sends SYN-ACK
    { index = 14, value = 0.33 }, # RST is 1/3 of packets
    { index = 19, value = 1.0 },  # RST after SYN (no SYN-ACK seen)
]

[[signatures]]
name = "connect_scan_medium"
description = "TCP Connect scan targeting moderate ports (50-100)"
enabled = true
features = [
    { index = 1, value = 0.07 },  # ~70 unique ports
    { index = 12, value = 0.33 }, # SYN ratio
    { index = 13, value = 0.0 },  # No SYN-ACK from attacker
    { index = 14, value = 0.33 }, # RST ratio
    { index = 19, value = 1.0 },  # RST after SYN
]

[[signatures]]
name = "connect_scan_small"
description = "TCP Connect scan targeting fewer ports (20-50)"
enabled = true
features = [
    { index = 1, value = 0.035 }, # ~35 unique ports
    { index = 12, value = 0.33 }, # SYN ratio
    { index = 13, value = 0.0 },  # No SYN-ACK
    { index = 14, value = 0.33 }, # RST ratio
    { index = 19, value = 1.0 },  # RST after SYN
]

[[signatures]]
name = "udp_scan"
description = "UDP port scan"
enabled = true
features = [
    { index = 1, value = 0.8 },  # Many unique ports
    { index = 24, value = 0.1 }, # Low response ratio
    { index = 25, value = 0.6 }, # ICMP unreachable responses
    { index = 27, value = 0.9 }, # Empty payloads
]

[[signatures]]
name = "ping_sweep"
description = "ICMP ping sweep across hosts"
enabled = true
features = [
    { index = 8, value = 0.9 },   # Many unique IPs
    { index = 36, value = 0.95 }, # High echo request ratio
    { index = 40, value = 0.9 },  # Ping sweep score
    { index = 44, value = 0.8 },  # Regular timing
]

[[signatures]]
name = "brute_force"
description = "Authentication brute force attack"
enabled = true
features = [
    { index = 1, value = 0.02 },  # Single port
    { index = 12, value = 0.5 },  # Moderate SYN ratio
    { index = 13, value = 0.0 },  # Attacker doesn't see SYN-ACK
    { index = 20, value = 1.0 },  # All traffic to auth port
    { index = 21, value = 1.0 },  # Single port concentration
]

# DoS Attack Signatures
# =====================

[[signatures]]
name = "syn_flood"
description = "TCP SYN flood attack - high rate SYN packets without handshake completion"
enabled = true
features = [
    { index = 1, value = 0.02 },  # Few unique ports (not a scan)
    { index = 12, value = 0.95 }, # Very high SYN ratio
    { index = 13, value = 0.02 }, # Almost no SYN-ACK
    { index = 64, value = 0.5 },  # High packet rate (50k pps)
    { index = 68, value = 0.8 },  # High TCP flood score
]

[[signatures]]
name = "syn_flood_low_rate"
description = "Slowloris-style SYN flood at lower rate"
enabled = true
features = [
    { index = 1, value = 0.01 },  # Single port typically
    { index = 12, value = 0.9 },  # High SYN ratio
    { index = 64, value = 0.15 }, # Moderate packet rate (15k pps)
    { index = 66, value = 0.3 },  # High connection rate
    { index = 67, value = 0.8 },  # High half-open indicator
]

[[signatures]]
name = "udp_flood"
description = "UDP flood attack - high rate UDP packets"
enabled = true
features = [
    { index = 31, value = 0.9 },  # High "other services" UDP ratio
    { index = 64, value = 0.5 },  # High packet rate
    { index = 65, value = 0.5 },  # High byte rate
    { index = 69, value = 0.8 },  # High UDP flood score
]

[[signatures]]
name = "icmp_flood"
description = "ICMP echo flood (ping flood) to single target"
enabled = true
features = [
    { index = 8, value = 0.02 },  # Single/few destination IPs (not sweep)
    { index = 36, value = 0.95 }, # High ICMP echo request ratio
    { index = 64, value = 0.3 },  # High packet rate
    { index = 70, value = 0.8 },  # High ICMP flood score
]

[[signatures]]
name = "connection_exhaustion"
description = "Connection exhaustion attack - many half-open connections"
enabled = true
features = [
    { index = 12, value = 0.6 },  # Elevated SYN ratio
    { index = 17, value = 0.85 }, # Very high half-open ratio
    { index = 66, value = 0.4 },  # High connection rate
    { index = 71, value = 0.7 },  # Connection exhaustion score
]
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.detector.scan_detection);
        assert!(config.detector.brute_force_detection);
        assert!(!config.signatures.is_empty());
    }

    #[test]
    fn test_parse_config() {
        let config = Config::from_str(DEFAULT_CONFIG).unwrap();
        assert!(config.detector.scan_detection);
        assert_eq!(config.brute_force.auth_ports.len(), 17);
    }

    #[test]
    fn test_signature_to_vector() {
        let sig = SignatureConfig {
            name: "test".to_string(),
            description: "".to_string(),
            features: vec![
                FeatureValue { index: 0, value: 0.5 },
                FeatureValue { index: 12, value: 0.9 },
            ],
            enabled: true,
        };
        let vec = sig.to_vector();
        assert_eq!(vec[0], 0.5);
        assert_eq!(vec[12], 0.9);
        assert_eq!(vec[1], 0.0);
    }

    #[test]
    fn test_roundtrip() {
        let config = Config::default();
        let toml = config.to_string().unwrap();
        let parsed = Config::from_str(&toml).unwrap();
        assert_eq!(config.detector.window_size_ms, parsed.detector.window_size_ms);
    }

    // DoS configuration tests

    #[test]
    fn test_dos_settings_defaults() {
        let dos = DosSettings::default();
        assert!(dos.enabled);
        assert_eq!(dos.min_packet_rate, 0.1);
        assert_eq!(dos.min_byte_rate, 0.1);
        assert_eq!(dos.min_connection_rate, 0.05);
        assert_eq!(dos.half_open_threshold, 0.7);
    }

    #[test]
    fn test_dos_detection_in_detector_settings() {
        let detector = DetectorSettings::default();
        assert!(detector.dos_detection);
    }

    #[test]
    fn test_dos_config_parsing() {
        let config = Config::from_str(DEFAULT_CONFIG).unwrap();
        assert!(config.dos.enabled);
        assert_eq!(config.dos.min_packet_rate, 0.1);
        assert_eq!(config.dos.min_byte_rate, 0.1);
        assert_eq!(config.dos.min_connection_rate, 0.05);
        assert_eq!(config.dos.half_open_threshold, 0.7);
        assert!(config.detector.dos_detection);
    }

    #[test]
    fn test_dos_signatures_present() {
        let config = Config::default();
        let dos_signatures: Vec<_> = config.signatures.iter()
            .filter(|s| {
                s.name == "syn_flood" ||
                s.name == "syn_flood_low_rate" ||
                s.name == "udp_flood" ||
                s.name == "icmp_flood" ||
                s.name == "connection_exhaustion"
            })
            .collect();
        assert_eq!(dos_signatures.len(), 5, "Expected 5 DoS signatures");
    }

    #[test]
    fn test_syn_flood_signature_features() {
        let config = Config::default();
        let syn_flood = config.signatures.iter()
            .find(|s| s.name == "syn_flood")
            .expect("syn_flood signature not found");

        let vec = syn_flood.to_vector();
        // Should have high packet rate at index 64
        assert!(vec[64] > 0.0, "syn_flood should have packet rate feature at index 64");
        // Should have TCP flood score at index 68
        assert!(vec[68] > 0.0, "syn_flood should have TCP flood score at index 68");
        // Should have high SYN ratio at index 12
        assert!(vec[12] > 0.9, "syn_flood should have high SYN ratio");
    }

    #[test]
    fn test_udp_flood_signature_features() {
        let config = Config::default();
        let udp_flood = config.signatures.iter()
            .find(|s| s.name == "udp_flood")
            .expect("udp_flood signature not found");

        let vec = udp_flood.to_vector();
        // Should have packet rate at index 64
        assert!(vec[64] > 0.0, "udp_flood should have packet rate feature");
        // Should have byte rate at index 65
        assert!(vec[65] > 0.0, "udp_flood should have byte rate feature");
        // Should have UDP flood score at index 69
        assert!(vec[69] > 0.0, "udp_flood should have UDP flood score");
    }

    #[test]
    fn test_icmp_flood_signature_features() {
        let config = Config::default();
        let icmp_flood = config.signatures.iter()
            .find(|s| s.name == "icmp_flood")
            .expect("icmp_flood signature not found");

        let vec = icmp_flood.to_vector();
        // Should have low unique IPs at index 8 (single target)
        assert!(vec[8] < 0.1, "icmp_flood should target few IPs (not a sweep)");
        // Should have high echo request ratio at index 36
        assert!(vec[36] > 0.9, "icmp_flood should have high echo request ratio");
        // Should have ICMP flood score at index 70
        assert!(vec[70] > 0.0, "icmp_flood should have ICMP flood score");
    }

    #[test]
    fn test_connection_exhaustion_signature_features() {
        let config = Config::default();
        let conn_exhaust = config.signatures.iter()
            .find(|s| s.name == "connection_exhaustion")
            .expect("connection_exhaustion signature not found");

        let vec = conn_exhaust.to_vector();
        // Should have connection rate at index 66
        assert!(vec[66] > 0.0, "connection_exhaustion should have connection rate feature");
        // Should have high half-open ratio at index 17
        assert!(vec[17] > 0.8, "connection_exhaustion should have high half-open ratio");
        // Should have connection exhaustion score at index 71
        assert!(vec[71] > 0.0, "connection_exhaustion should have exhaustion score");
    }

    #[test]
    fn test_dos_config_roundtrip() {
        let config = Config::default();
        let toml = config.to_string().unwrap();
        let parsed = Config::from_str(&toml).unwrap();

        assert_eq!(config.dos.enabled, parsed.dos.enabled);
        assert_eq!(config.dos.min_packet_rate, parsed.dos.min_packet_rate);
        assert_eq!(config.dos.min_byte_rate, parsed.dos.min_byte_rate);
        assert_eq!(config.dos.min_connection_rate, parsed.dos.min_connection_rate);
        assert_eq!(config.dos.half_open_threshold, parsed.dos.half_open_threshold);
    }

    #[test]
    fn test_dos_custom_thresholds() {
        let toml = r#"
[detector]
dos_detection = true

[dos]
enabled = true
min_packet_rate = 0.2
min_byte_rate = 0.3
min_connection_rate = 0.1
half_open_threshold = 0.8
"#;
        let config = Config::from_str(toml).unwrap();
        assert!(config.dos.enabled);
        assert_eq!(config.dos.min_packet_rate, 0.2);
        assert_eq!(config.dos.min_byte_rate, 0.3);
        assert_eq!(config.dos.min_connection_rate, 0.1);
        assert_eq!(config.dos.half_open_threshold, 0.8);
    }

    #[test]
    fn test_dos_disabled_config() {
        let toml = r#"
[dos]
enabled = false
"#;
        let config = Config::from_str(toml).unwrap();
        assert!(!config.dos.enabled);
    }

    #[test]
    fn test_dos_signature_indices_in_valid_range() {
        let config = Config::default();
        let dos_sigs = ["syn_flood", "syn_flood_low_rate", "udp_flood", "icmp_flood", "connection_exhaustion"];

        for name in dos_sigs {
            let sig = config.signatures.iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("{} signature not found", name));

            for feature in &sig.features {
                assert!(feature.index < VECTOR_DIM,
                    "{}: feature index {} exceeds VECTOR_DIM {}", name, feature.index, VECTOR_DIM);
                assert!(feature.value >= 0.0 && feature.value <= 1.0,
                    "{}: feature value {} not in range [0, 1]", name, feature.value);
            }
        }
    }
}

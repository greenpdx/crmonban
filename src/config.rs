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

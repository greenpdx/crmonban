//! Zone support for crmonban
//!
//! Zone-based security model for network segmentation.
//! Zones allow categorizing network segments by trust level:
//! - Trusted (100): Loopback, management
//! - Internal (80): Corporate LAN
//! - VPN (70): VPN tunnels
//! - DMZ (50): Public-facing services
//! - Guest (30): Guest/IoT networks
//! - External (0): Untrusted internet

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::{debug, info};

/// Zone trust levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ZoneType {
    Trusted = 100,
    Internal = 80,
    VPN = 70,
    DMZ = 50,
    Guest = 30,
    External = 0,
}

impl ZoneType {
    pub fn trust_level(&self) -> u8 {
        *self as u8
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "trusted" => Some(ZoneType::Trusted),
            "internal" => Some(ZoneType::Internal),
            "vpn" => Some(ZoneType::VPN),
            "dmz" => Some(ZoneType::DMZ),
            "guest" => Some(ZoneType::Guest),
            "external" => Some(ZoneType::External),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ZoneType::Trusted => "trusted",
            ZoneType::Internal => "internal",
            ZoneType::VPN => "vpn",
            ZoneType::DMZ => "dmz",
            ZoneType::Guest => "guest",
            ZoneType::External => "external",
        }
    }
}

impl std::fmt::Display for ZoneType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Zone definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    /// Zone name
    pub name: String,

    /// Trust level (0-100)
    pub trust_level: u8,

    /// Network interfaces in this zone
    pub interfaces: Vec<String>,

    /// IP networks in this zone (CIDR notation)
    pub networks: Vec<String>,

    /// Description
    pub description: String,

    /// Whether IPs in this zone are implicitly whitelisted
    #[serde(default)]
    pub implicit_whitelist: bool,
}

impl Zone {
    /// Check if an IP belongs to this zone
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        for network in &self.networks {
            if let Ok(net) = network.parse::<ipnetwork::IpNetwork>() {
                if net.contains(*ip) {
                    return true;
                }
            }
        }
        false
    }
}

/// Zone configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZoneConfig {
    /// Enable zone support
    #[serde(default)]
    pub enabled: bool,

    /// Path to zone configuration file
    #[serde(default)]
    pub config_file: Option<PathBuf>,

    /// Zone definitions
    #[serde(default)]
    pub zones: Vec<Zone>,

    /// Default zone for unknown IPs
    #[serde(default = "default_zone")]
    pub default_zone: String,

    /// Trust level threshold for implicit whitelist
    /// IPs in zones with trust >= this value are not banned
    #[serde(default = "default_whitelist_threshold")]
    pub whitelist_threshold: u8,
}

fn default_zone() -> String {
    "external".to_string()
}

fn default_whitelist_threshold() -> u8 {
    80 // Internal and above
}

/// Zone manager
pub struct ZoneManager {
    config: ZoneConfig,
    /// Zone lookup by name
    zones_by_name: HashMap<String, Zone>,
}

impl ZoneManager {
    /// Create a new zone manager
    pub fn new(config: ZoneConfig) -> Self {
        let mut zones_by_name = HashMap::new();

        for zone in &config.zones {
            zones_by_name.insert(zone.name.clone(), zone.clone());
        }

        // Add default zones if not defined
        if !zones_by_name.contains_key("external") {
            zones_by_name.insert(
                "external".to_string(),
                Zone {
                    name: "external".to_string(),
                    trust_level: 0,
                    interfaces: vec![],
                    networks: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
                    description: "Untrusted external network".to_string(),
                    implicit_whitelist: false,
                },
            );
        }

        Self {
            config,
            zones_by_name,
        }
    }

    /// Load zones from external config file
    pub fn load_from_file(&mut self, path: &PathBuf) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;

        // Try YAML first
        if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
            #[derive(Deserialize)]
            struct FirewallConfig {
                zones: Option<Vec<Zone>>,
            }

            let config: FirewallConfig = serde_yaml::from_str(&content)?;
            if let Some(zones) = config.zones {
                for zone in zones {
                    info!("Loaded zone '{}' from {}", zone.name, path.display());
                    self.zones_by_name.insert(zone.name.clone(), zone);
                }
            }
        } else {
            // Try TOML
            #[derive(Deserialize)]
            struct TomlConfig {
                zones: Option<Vec<Zone>>,
            }

            let config: TomlConfig = toml::from_str(&content)?;
            if let Some(zones) = config.zones {
                for zone in zones {
                    info!("Loaded zone '{}' from {}", zone.name, path.display());
                    self.zones_by_name.insert(zone.name.clone(), zone);
                }
            }
        }

        Ok(())
    }

    /// Get zone for an IP address
    pub fn get_zone_for_ip(&self, ip: &IpAddr) -> Option<&Zone> {
        // Find the most specific zone that contains this IP
        let mut best_zone: Option<&Zone> = None;
        let mut best_prefix_len = 0;

        for zone in self.zones_by_name.values() {
            for network in &zone.networks {
                if let Ok(net) = network.parse::<ipnetwork::IpNetwork>() {
                    if net.contains(*ip) {
                        let prefix_len = net.prefix();
                        if prefix_len > best_prefix_len {
                            best_prefix_len = prefix_len;
                            best_zone = Some(zone);
                        }
                    }
                }
            }
        }

        best_zone
    }

    /// Get zone by name
    pub fn get_zone(&self, name: &str) -> Option<&Zone> {
        self.zones_by_name.get(name)
    }

    /// Check if an IP is in a trusted zone (should not be banned)
    pub fn is_trusted(&self, ip: &IpAddr) -> bool {
        if !self.config.enabled {
            return false;
        }

        if let Some(zone) = self.get_zone_for_ip(ip) {
            if zone.implicit_whitelist {
                debug!("IP {} is in implicitly whitelisted zone '{}'", ip, zone.name);
                return true;
            }

            if zone.trust_level >= self.config.whitelist_threshold {
                debug!(
                    "IP {} is in trusted zone '{}' (trust_level={} >= threshold={})",
                    ip, zone.name, zone.trust_level, self.config.whitelist_threshold
                );
                return true;
            }
        }

        false
    }

    /// Get zone name for an IP
    pub fn get_zone_name(&self, ip: &IpAddr) -> String {
        self.get_zone_for_ip(ip)
            .map(|z| z.name.clone())
            .unwrap_or_else(|| self.config.default_zone.clone())
    }

    /// List all zones
    pub fn list_zones(&self) -> Vec<&Zone> {
        self.zones_by_name.values().collect()
    }

    /// Add or update a zone
    pub fn add_zone(&mut self, zone: Zone) {
        info!("Adding zone: {} (trust_level={})", zone.name, zone.trust_level);
        self.zones_by_name.insert(zone.name.clone(), zone);
    }

    /// Remove a zone
    pub fn remove_zone(&mut self, name: &str) -> Option<Zone> {
        info!("Removing zone: {}", name);
        self.zones_by_name.remove(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_type() {
        assert_eq!(ZoneType::Trusted.trust_level(), 100);
        assert_eq!(ZoneType::External.trust_level(), 0);
        assert_eq!(ZoneType::from_name("internal"), Some(ZoneType::Internal));
        assert_eq!(ZoneType::from_name("unknown"), None);
    }

    #[test]
    fn test_zone_contains_ip() {
        let zone = Zone {
            name: "lan".to_string(),
            trust_level: 80,
            interfaces: vec![],
            networks: vec!["192.168.1.0/24".to_string()],
            description: "LAN".to_string(),
            implicit_whitelist: false,
        };

        assert!(zone.contains_ip(&"192.168.1.100".parse().unwrap()));
        assert!(!zone.contains_ip(&"192.168.2.100".parse().unwrap()));
    }

    #[test]
    fn test_zone_manager() {
        let config = ZoneConfig {
            enabled: true,
            zones: vec![
                Zone {
                    name: "internal".to_string(),
                    trust_level: 80,
                    interfaces: vec![],
                    networks: vec!["10.0.0.0/8".to_string()],
                    description: "Internal".to_string(),
                    implicit_whitelist: false,
                },
            ],
            whitelist_threshold: 70,
            ..Default::default()
        };

        let manager = ZoneManager::new(config);

        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(manager.is_trusted(&ip));

        let external_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!manager.is_trusted(&external_ip));
    }
}

//! IP Spoofing Detection
//!
//! Detects IP spoofing using bogon/martian address detection:
//! - Always-bogon addresses (0.0.0.0/8, 127.0.0.0/8, etc.)
//! - Configurable private ranges (10.x, 172.16.x, 192.168.x)
//! - Land attack (src == dst with same port)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use crate::layer234::ThreatType;

/// Bogon detection configuration
#[derive(Debug, Clone)]
pub struct BogonConfig {
    /// Allow RFC1918 private ranges (10.x, 172.16.x, 192.168.x) as source
    pub allow_private: bool,
    /// Allow link-local (169.254.x.x, fe80::/10)
    pub allow_link_local: bool,
    /// Allow loopback (127.x.x.x, ::1)
    pub allow_loopback: bool,
    /// Custom allowed ranges (for internal deployments)
    pub allowed_ranges: Vec<IpNetwork>,
}

impl Default for BogonConfig {
    fn default() -> Self {
        Self {
            // By default, allow private ranges (internal deployment)
            allow_private: true,
            allow_link_local: true,
            allow_loopback: false,
            allowed_ranges: Vec::new(),
        }
    }
}

impl BogonConfig {
    /// Create a strict config that flags all special-use addresses
    pub fn strict() -> Self {
        Self {
            allow_private: false,
            allow_link_local: false,
            allow_loopback: false,
            allowed_ranges: Vec::new(),
        }
    }

    /// Create a config for internal network monitoring
    pub fn internal() -> Self {
        Self {
            allow_private: true,
            allow_link_local: true,
            allow_loopback: true,
            allowed_ranges: Vec::new(),
        }
    }
}

/// RFC 5735 special-use IPv4 addresses (always flagged as bogon)
const ALWAYS_BOGON_V4: &[(&str, &str)] = &[
    ("0.0.0.0/8", "This network"),
    ("192.0.0.0/24", "IETF Protocol Assignments"),
    ("192.0.2.0/24", "TEST-NET-1 (Documentation)"),
    ("198.18.0.0/15", "Network Interconnect Device Benchmark"),
    ("198.51.100.0/24", "TEST-NET-2 (Documentation)"),
    ("203.0.113.0/24", "TEST-NET-3 (Documentation)"),
    ("224.0.0.0/4", "Multicast"),
    ("240.0.0.0/4", "Reserved for Future Use"),
    ("255.255.255.255/32", "Limited Broadcast"),
];

/// Configurable special-use IPv4 addresses (may be allowed)
const CONFIGURABLE_BOGON_V4: &[(&str, &str, BogonCategory)] = &[
    ("10.0.0.0/8", "Private (RFC1918)", BogonCategory::Private),
    ("172.16.0.0/12", "Private (RFC1918)", BogonCategory::Private),
    ("192.168.0.0/16", "Private (RFC1918)", BogonCategory::Private),
    ("169.254.0.0/16", "Link-Local", BogonCategory::LinkLocal),
    ("127.0.0.0/8", "Loopback", BogonCategory::Loopback),
];

/// IPv6 bogon ranges (always flagged)
const ALWAYS_BOGON_V6: &[(&str, &str)] = &[
    ("::/128", "Unspecified"),
    ("::ffff:0:0/96", "IPv4-mapped (deprecated)"),
    ("100::/64", "Discard-Only (RFC 6666)"),
    ("2001:db8::/32", "Documentation"),
    ("ff00::/8", "Multicast"),
];

/// Configurable IPv6 ranges
const CONFIGURABLE_BOGON_V6: &[(&str, &str, BogonCategory)] = &[
    ("::1/128", "Loopback", BogonCategory::Loopback),
    ("fe80::/10", "Link-Local", BogonCategory::LinkLocal),
    ("fc00::/7", "Unique Local (Private)", BogonCategory::Private),
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum BogonCategory {
    Private,
    LinkLocal,
    Loopback,
}

/// Parsed bogon network entry
#[derive(Debug, Clone)]
struct BogonEntry {
    network: IpNetwork,
    description: String,
    category: Option<BogonCategory>,
}

/// Bogon address checker with configurable allowed ranges
#[derive(Debug)]
pub struct BogonChecker {
    /// Configuration
    config: BogonConfig,
    /// Parsed always-bogon networks
    always_bogon: Vec<BogonEntry>,
    /// Parsed configurable bogon networks
    configurable_bogon: Vec<BogonEntry>,
    /// Statistics
    stats: BogonStats,
}

#[derive(Debug, Default, Clone)]
pub struct BogonStats {
    pub total_checked: u64,
    pub bogon_detected: u64,
    pub martian_detected: u64,
    pub land_attacks: u64,
}

impl BogonChecker {
    /// Create a new bogon checker with the given configuration
    pub fn new(config: BogonConfig) -> Self {
        let mut always_bogon = Vec::new();
        let mut configurable_bogon = Vec::new();

        // Parse always-bogon IPv4 ranges
        for (cidr, desc) in ALWAYS_BOGON_V4 {
            if let Ok(net) = cidr.parse::<Ipv4Network>() {
                always_bogon.push(BogonEntry {
                    network: IpNetwork::V4(net),
                    description: desc.to_string(),
                    category: None,
                });
            }
        }

        // Parse always-bogon IPv6 ranges
        for (cidr, desc) in ALWAYS_BOGON_V6 {
            if let Ok(net) = cidr.parse::<Ipv6Network>() {
                always_bogon.push(BogonEntry {
                    network: IpNetwork::V6(net),
                    description: desc.to_string(),
                    category: None,
                });
            }
        }

        // Parse configurable IPv4 ranges
        for (cidr, desc, cat) in CONFIGURABLE_BOGON_V4 {
            if let Ok(net) = cidr.parse::<Ipv4Network>() {
                configurable_bogon.push(BogonEntry {
                    network: IpNetwork::V4(net),
                    description: desc.to_string(),
                    category: Some(*cat),
                });
            }
        }

        // Parse configurable IPv6 ranges
        for (cidr, desc, cat) in CONFIGURABLE_BOGON_V6 {
            if let Ok(net) = cidr.parse::<Ipv6Network>() {
                configurable_bogon.push(BogonEntry {
                    network: IpNetwork::V6(net),
                    description: desc.to_string(),
                    category: Some(*cat),
                });
            }
        }

        Self {
            config,
            always_bogon,
            configurable_bogon,
            stats: BogonStats::default(),
        }
    }

    /// Check if an IP address is a bogon (spoofed) source
    pub fn check_source(&mut self, src_ip: IpAddr) -> Option<ThreatType> {
        self.stats.total_checked += 1;

        // Check custom allowed ranges first
        for allowed in &self.config.allowed_ranges {
            if allowed.contains(src_ip) {
                return None;
            }
        }

        // Check always-bogon ranges
        for entry in &self.always_bogon {
            if entry.network.contains(src_ip) {
                self.stats.bogon_detected += 1;
                return Some(ThreatType::IpSpoofBogon {
                    src_ip: src_ip.to_string(),
                    bogon_type: entry.description.clone(),
                });
            }
        }

        // Check configurable ranges based on config
        for entry in &self.configurable_bogon {
            if entry.network.contains(src_ip) {
                let is_allowed = match entry.category {
                    Some(BogonCategory::Private) => self.config.allow_private,
                    Some(BogonCategory::LinkLocal) => self.config.allow_link_local,
                    Some(BogonCategory::Loopback) => self.config.allow_loopback,
                    None => false,
                };

                if !is_allowed {
                    self.stats.bogon_detected += 1;
                    return Some(ThreatType::IpSpoofBogon {
                        src_ip: src_ip.to_string(),
                        bogon_type: entry.description.clone(),
                    });
                }
            }
        }

        // Check for martian addresses (source IP that should never be seen)
        if self.is_martian(src_ip) {
            self.stats.martian_detected += 1;
            return Some(ThreatType::IpSpoofMartian {
                src_ip: src_ip.to_string(),
            });
        }

        None
    }

    /// Check for Land attack (src == dst with same port)
    pub fn check_land_attack(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> Option<ThreatType> {
        if src_ip == dst_ip && src_port == dst_port && src_port != 0 {
            self.stats.land_attacks += 1;
            return Some(ThreatType::LandAttack {
                ip: src_ip.to_string(),
                port: src_port,
            });
        }
        None
    }

    /// Check if address is martian (impossible source)
    fn is_martian(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                // Source can never be broadcast
                if v4.is_broadcast() {
                    return true;
                }
                // Source can never be unspecified (0.0.0.0)
                if v4.is_unspecified() {
                    return true;
                }
                // Class E (240.0.0.0/4) is reserved
                if v4.octets()[0] >= 240 {
                    return true;
                }
                false
            }
            IpAddr::V6(v6) => {
                // Source can never be unspecified (::)
                if v6.is_unspecified() {
                    return true;
                }
                false
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &BogonStats {
        &self.stats
    }

    /// Get feature vector values
    pub fn get_features(&self, total_packets: u64) -> [f32; 4] {
        let total = total_packets.max(1) as f32;
        [
            // SPOOF_BOGON_RATIO
            self.stats.bogon_detected as f32 / total,
            // SPOOF_MARTIAN_RATIO
            self.stats.martian_detected as f32 / total,
            // SPOOF_TTL_ANOMALY (placeholder - would need TTL data)
            0.0,
            // SPOOF_LAND_DETECTED
            if self.stats.land_attacks > 0 { 1.0 } else { 0.0 },
        ]
    }

    /// Update configuration
    pub fn set_config(&mut self, config: BogonConfig) {
        self.config = config;
    }

    /// Add a custom allowed range
    pub fn add_allowed_range(&mut self, network: IpNetwork) {
        self.config.allowed_ranges.push(network);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_always_bogon() {
        let mut checker = BogonChecker::new(BogonConfig::default());

        // These should always be flagged
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))).is_some());
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))).is_some());
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))).is_some());
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).is_some());
    }

    #[test]
    fn test_private_allowed_by_default() {
        let mut checker = BogonChecker::new(BogonConfig::default());

        // Private ranges should be allowed by default
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))).is_none());
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_none());
    }

    #[test]
    fn test_private_flagged_strict() {
        let mut checker = BogonChecker::new(BogonConfig::strict());

        // Private ranges should be flagged in strict mode
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_some());
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))).is_some());
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_some());
    }

    #[test]
    fn test_public_ip_ok() {
        let mut checker = BogonChecker::new(BogonConfig::strict());

        // Public IPs should never be flagged
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_none());
        assert!(checker.check_source(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).is_none());
    }

    #[test]
    fn test_land_attack() {
        let mut checker = BogonChecker::new(BogonConfig::default());
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Same IP and port = Land attack
        assert!(checker.check_land_attack(ip, ip, 80, 80).is_some());

        // Different port = Not Land attack
        assert!(checker.check_land_attack(ip, ip, 80, 81).is_none());

        // Different IP = Not Land attack
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        assert!(checker.check_land_attack(ip, ip2, 80, 80).is_none());
    }

    #[test]
    fn test_custom_allowed_range() {
        let mut checker = BogonChecker::new(BogonConfig::strict());

        // This would normally be flagged
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(checker.check_source(ip).is_some());

        // Add custom allowed range
        checker.add_allowed_range("10.0.0.0/8".parse().unwrap());

        // Now it should be allowed
        let mut checker2 = BogonChecker::new(BogonConfig::strict());
        checker2.add_allowed_range("10.0.0.0/8".parse().unwrap());
        assert!(checker2.check_source(ip).is_none());
    }
}

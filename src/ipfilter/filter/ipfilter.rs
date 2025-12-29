//! IP Filter implementation
//!
//! Provides IP address filtering with blocked, watch, and clean statuses.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

/// Status of an IP address in the filter
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpStatus {
    /// IP is blocked (deny)
    Blocked {
        reason: String,
        added_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    },
    /// IP is on watch list (monitor)
    Watch {
        reason: String,
        added_at: DateTime<Utc>,
        hit_count: u64,
    },
    /// IP is clean (allow)
    Clean {
        added_at: DateTime<Utc>,
        verified: bool,
    },
    /// IP status is unknown (not in any list)
    Unknown,
}

/// Entry in the IP filter
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FilterEntry {
    status: IpStatus,
    last_seen: DateTime<Utc>,
}

/// IP network entry for CIDR-based filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkEntry {
    network: IpNetwork,
    status: IpStatus,
}

/// IP Filter managing blocked, watched, and clean IP addresses
#[derive(Debug)]
pub struct IpFilter {
    /// Individual IP entries
    entries: DashMap<IpAddr, FilterEntry>,
    /// CIDR network entries
    networks: DashMap<String, NetworkEntry>,
    /// Default status for unknown IPs
    default_status: IpStatus,
}

impl Default for IpFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl IpFilter {
    /// Create a new empty IP filter
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            networks: DashMap::new(),
            default_status: IpStatus::Unknown,
        }
    }

    /// Set the default status for unknown IPs
    pub fn with_default_status(mut self, status: IpStatus) -> Self {
        self.default_status = status;
        self
    }

    /// Check the status of an IP address
    pub fn check(&self, ip: &IpAddr) -> IpStatus {
        // First check individual IP entries
        if let Some(entry) = self.entries.get(ip) {
            // Check expiration for blocked IPs
            if let IpStatus::Blocked { expires_at: Some(expires), .. } = &entry.status {
                if Utc::now() > *expires {
                    // Expired, remove and return unknown
                    drop(entry);
                    self.entries.remove(ip);
                    return self.check_networks(ip);
                }
            }
            return entry.status.clone();
        }

        // Then check network ranges
        self.check_networks(ip)
    }

    fn check_networks(&self, ip: &IpAddr) -> IpStatus {
        for entry in self.networks.iter() {
            if entry.network.contains(*ip) {
                return entry.status.clone();
            }
        }
        self.default_status.clone()
    }

    /// Block an IP address
    pub fn block(&mut self, ip: IpAddr, reason: String) {
        self.block_with_expiry(ip, reason, None);
    }

    /// Block an IP address with an expiration time
    pub fn block_with_expiry(
        &mut self,
        ip: IpAddr,
        reason: String,
        expires_at: Option<DateTime<Utc>>,
    ) {
        let entry = FilterEntry {
            status: IpStatus::Blocked {
                reason,
                added_at: Utc::now(),
                expires_at,
            },
            last_seen: Utc::now(),
        };
        self.entries.insert(ip, entry);
    }

    /// Block a network (CIDR)
    pub fn block_network(&mut self, network: IpNetwork, reason: String) {
        let entry = NetworkEntry {
            network,
            status: IpStatus::Blocked {
                reason,
                added_at: Utc::now(),
                expires_at: None,
            },
        };
        self.networks.insert(network.to_string(), entry);
    }

    /// Add an IP to the watch list
    pub fn watch(&mut self, ip: IpAddr, reason: String) {
        let entry = FilterEntry {
            status: IpStatus::Watch {
                reason,
                added_at: Utc::now(),
                hit_count: 0,
            },
            last_seen: Utc::now(),
        };
        self.entries.insert(ip, entry);
    }

    /// Watch a network (CIDR)
    pub fn watch_network(&mut self, network: IpNetwork, reason: String) {
        let entry = NetworkEntry {
            network,
            status: IpStatus::Watch {
                reason,
                added_at: Utc::now(),
                hit_count: 0,
            },
        };
        self.networks.insert(network.to_string(), entry);
    }

    /// Mark an IP as clean (allowed)
    pub fn mark_clean(&mut self, ip: IpAddr, verified: bool) {
        let entry = FilterEntry {
            status: IpStatus::Clean {
                added_at: Utc::now(),
                verified,
            },
            last_seen: Utc::now(),
        };
        self.entries.insert(ip, entry);
    }

    /// Mark a network as clean
    pub fn mark_clean_network(&mut self, network: IpNetwork, verified: bool) {
        let entry = NetworkEntry {
            network,
            status: IpStatus::Clean {
                added_at: Utc::now(),
                verified,
            },
        };
        self.networks.insert(network.to_string(), entry);
    }

    /// Remove an IP from all lists
    pub fn remove(&mut self, ip: &IpAddr) -> Option<IpStatus> {
        self.entries.remove(ip).map(|(_, e)| e.status)
    }

    /// Remove a network from all lists
    pub fn remove_network(&mut self, network: &IpNetwork) -> Option<IpStatus> {
        self.networks.remove(&network.to_string()).map(|(_, e)| e.status)
    }

    /// Increment hit count for watched IPs
    pub fn record_hit(&self, ip: &IpAddr) {
        if let Some(mut entry) = self.entries.get_mut(ip) {
            if let IpStatus::Watch { hit_count, .. } = &mut entry.status {
                *hit_count += 1;
            }
            entry.last_seen = Utc::now();
        }
    }

    /// Get all blocked IPs
    pub fn get_blocked(&self) -> Vec<(IpAddr, IpStatus)> {
        self.entries
            .iter()
            .filter(|e| matches!(e.status, IpStatus::Blocked { .. }))
            .map(|e| (*e.key(), e.status.clone()))
            .collect()
    }

    /// Get all watched IPs
    pub fn get_watched(&self) -> Vec<(IpAddr, IpStatus)> {
        self.entries
            .iter()
            .filter(|e| matches!(e.status, IpStatus::Watch { .. }))
            .map(|e| (*e.key(), e.status.clone()))
            .collect()
    }

    /// Get all clean IPs
    pub fn get_clean(&self) -> Vec<(IpAddr, IpStatus)> {
        self.entries
            .iter()
            .filter(|e| matches!(e.status, IpStatus::Clean { .. }))
            .map(|e| (*e.key(), e.status.clone()))
            .collect()
    }

    /// Get count of entries by status
    pub fn stats(&self) -> FilterStats {
        let mut stats = FilterStats::default();
        for entry in self.entries.iter() {
            match &entry.status {
                IpStatus::Blocked { .. } => stats.blocked += 1,
                IpStatus::Watch { .. } => stats.watched += 1,
                IpStatus::Clean { .. } => stats.clean += 1,
                IpStatus::Unknown => stats.unknown += 1,
            }
        }
        stats.networks = self.networks.len();
        stats
    }

    /// Clear all expired blocks
    pub fn clear_expired(&self) -> usize {
        let now = Utc::now();
        let mut cleared = 0;

        self.entries.retain(|_, entry| {
            if let IpStatus::Blocked { expires_at: Some(expires), .. } = &entry.status {
                if now > *expires {
                    cleared += 1;
                    return false;
                }
            }
            true
        });

        cleared
    }

    /// Load blocked IPs from a list
    pub fn load_blocklist(&mut self, ips: Vec<(IpAddr, String)>) {
        for (ip, reason) in ips {
            self.block(ip, reason);
        }
    }

    /// Load network blocks from a list
    pub fn load_network_blocklist(&mut self, networks: Vec<(IpNetwork, String)>) {
        for (network, reason) in networks {
            self.block_network(network, reason);
        }
    }
}

/// Statistics about the filter
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FilterStats {
    pub blocked: usize,
    pub watched: usize,
    pub clean: usize,
    pub unknown: usize,
    pub networks: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_block_ip() {
        let mut filter = IpFilter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        filter.block(ip, "Malicious activity".to_string());

        match filter.check(&ip) {
            IpStatus::Blocked { reason, .. } => {
                assert_eq!(reason, "Malicious activity");
            }
            _ => panic!("Expected blocked status"),
        }
    }

    #[test]
    fn test_watch_ip() {
        let mut filter = IpFilter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));

        filter.watch(ip, "Suspicious".to_string());
        filter.record_hit(&ip);
        filter.record_hit(&ip);

        match filter.check(&ip) {
            IpStatus::Watch { hit_count, .. } => {
                assert_eq!(hit_count, 2);
            }
            _ => panic!("Expected watch status"),
        }
    }

    #[test]
    fn test_clean_ip() {
        let mut filter = IpFilter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        filter.mark_clean(ip, true);

        match filter.check(&ip) {
            IpStatus::Clean { verified, .. } => {
                assert!(verified);
            }
            _ => panic!("Expected clean status"),
        }
    }

    #[test]
    fn test_network_block() {
        let mut filter = IpFilter::new();
        let network: IpNetwork = "192.168.0.0/16".parse().unwrap();

        filter.block_network(network, "Internal network".to_string());

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 254, 254));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(matches!(filter.check(&ip1), IpStatus::Blocked { .. }));
        assert!(matches!(filter.check(&ip2), IpStatus::Blocked { .. }));
        assert!(matches!(filter.check(&ip3), IpStatus::Unknown));
    }

    #[test]
    fn test_unknown_ip() {
        let filter = IpFilter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(matches!(filter.check(&ip), IpStatus::Unknown));
    }

    #[test]
    fn test_stats() {
        let mut filter = IpFilter::new();

        filter.block(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "test".to_string());
        filter.block(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)), "test".to_string());
        filter.watch(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), "test".to_string());
        filter.mark_clean(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), true);

        let stats = filter.stats();
        assert_eq!(stats.blocked, 2);
        assert_eq!(stats.watched, 1);
        assert_eq!(stats.clean, 1);
    }
}
